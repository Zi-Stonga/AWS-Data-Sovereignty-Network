"""
Network topology validation for sovereign zone isolation.
Validates CIDR isolation, VPC attachment rules, and cross-zone peering proposals.
"""

import logging
from dataclasses import dataclass
from ipaddress import IPv4Network, ip_network

from src.config.enums import (
    DataClassification, SovereignZone,
    CROSS_ZONE_BLOCKED_CLASSIFICATIONS,
)
from src.config.settings import AppConfig, NetworkConfig

logger = logging.getLogger(__name__)


class NetworkValidationError(Exception):
    """Raised when a proposed network configuration violates sovereignty rules."""


@dataclass(frozen=True)
class VpcDefinition:
    """A VPC and its metadata used for topology validation."""

    name: str
    cidr: str
    zone: SovereignZone
    is_tgw_attached: bool
    is_vgw_only: bool
    allowed_data_classifications: frozenset[DataClassification]


@dataclass(frozen=True)
class PeeringProposal:
    """A proposed peering or attachment between two network endpoints."""

    source_vpc: VpcDefinition
    destination_vpc: VpcDefinition
    data_classifications: frozenset[DataClassification]
    uses_privatelink: bool


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of a topology validation check."""

    is_valid: bool
    violations: list[str]
    warnings: list[str]


def validate_cidr_isolation(config: NetworkConfig) -> ValidationResult:
    """Verify that zone CIDR blocks do not overlap.

    Args:
        config: Network configuration with all CIDR definitions.

    Returns:
        ValidationResult with any overlap violations.
    """
    cidrs = {
        "eu_gdpr": config.eu_gdpr_vpc_cidr,
        "eu_mifid": config.eu_mifid_vpc_cidr,
        "apac_mas": config.apac_mas_vpc_cidr,
        "us_banking": config.us_banking_vpc_cidr,
    }
    violations: list[str] = []
    networks = {name: ip_network(cidr, strict=False) for name, cidr in cidrs.items()}
    names = list(networks.keys())

    for i, name_a in enumerate(names):
        for name_b in names[i + 1:]:
            net_a: IPv4Network = networks[name_a]
            net_b: IPv4Network = networks[name_b]
            if net_a.overlaps(net_b):
                violations.append(
                    f"CIDR overlap detected: {name_a} ({net_a}) overlaps "
                    f"{name_b} ({net_b}). This creates a cross-zone routing risk."
                )

    if violations:
        logger.error("CIDR isolation failed: %s", violations)
    else:
        logger.info("CIDR isolation passed for %d networks", len(networks))

    return ValidationResult(is_valid=len(violations) == 0, violations=violations, warnings=[])


def validate_vpc_attachment_rules(vpcs: list[VpcDefinition]) -> ValidationResult:
    """Verify VPC attachment rules for EU sovereign VPCs.

    EU VPCs holding restricted data must use VGW, not TGW.

    Args:
        vpcs: List of VPC definitions to validate.

    Returns:
        ValidationResult with attachment rule violations.
    """
    violations: list[str] = []
    warnings: list[str] = []

    for vpc in vpcs:
        has_restricted = bool(
            vpc.allowed_data_classifications & CROSS_ZONE_BLOCKED_CLASSIFICATIONS
        )
        if vpc.zone == SovereignZone.EU and has_restricted:
            if vpc.is_tgw_attached and not vpc.is_vgw_only:
                violations.append(
                    f"VPC '{vpc.name}' in the EU zone holds restricted data "
                    f"but is attached to a TGW. Use VGW to prevent transitive routing."
                )
            if not vpc.is_vgw_only:
                warnings.append(
                    f"VPC '{vpc.name}': confirm VGW-only attachment at the DX private VIF level."
                )

    if violations:
        logger.error("VPC attachment validation failed: %s", violations)
    else:
        logger.info("VPC attachment passed for %d VPCs", len(vpcs))

    return ValidationResult(
        is_valid=len(violations) == 0, violations=violations, warnings=warnings
    )


def validate_peering_proposal(proposal: PeeringProposal) -> ValidationResult:
    """Validate whether a proposed cross-zone network connection is permitted.

    Args:
        proposal: The proposed peering to evaluate.

    Returns:
        ValidationResult with any policy violations.
    """
    violations: list[str] = []
    warnings: list[str] = []
    source_zone = proposal.source_vpc.zone
    dest_zone = proposal.destination_vpc.zone

    if source_zone == dest_zone:
        return ValidationResult(is_valid=True, violations=[], warnings=[])

    blocked = proposal.data_classifications & CROSS_ZONE_BLOCKED_CLASSIFICATIONS
    if blocked:
        violations.append(
            f"Cross-zone connection from {source_zone.value} to {dest_zone.value} "
            f"carries blocked data classifications: {[c.value for c in blocked]}."
        )

    if not proposal.uses_privatelink:
        violations.append(
            f"Cross-zone connection from {source_zone.value} to {dest_zone.value} "
            f"does not use PrivateLink. Direct CIDR routing between zones is prohibited."
        )

    if not blocked and proposal.uses_privatelink:
        warnings.append(
            f"Cross-zone PrivateLink from {source_zone.value} to {dest_zone.value}: "
            f"confirm the endpoint exposes only anonymised or aggregated data."
        )

    return ValidationResult(
        is_valid=len(violations) == 0, violations=violations, warnings=warnings
    )


def build_reference_vpcs(config: AppConfig) -> list[VpcDefinition]:
    """Construct the reference VPC definitions from the project specification.

    Args:
        config: Validated application configuration.

    Returns:
        List of VpcDefinition objects representing the full topology.
    """
    net = config.network
    return [
        VpcDefinition(
            name="eu-gdpr-vpc", cidr=net.eu_gdpr_vpc_cidr,
            zone=SovereignZone.EU, is_tgw_attached=False, is_vgw_only=True,
            allowed_data_classifications=frozenset([
                DataClassification.CUSTOMER_PII, DataClassification.KYC_DOCUMENT,
            ]),
        ),
        VpcDefinition(
            name="eu-mifid-vpc", cidr=net.eu_mifid_vpc_cidr,
            zone=SovereignZone.EU, is_tgw_attached=False, is_vgw_only=True,
            allowed_data_classifications=frozenset([
                DataClassification.TRADE_ORDER, DataClassification.ACCOUNT_NUMBER,
            ]),
        ),
        VpcDefinition(
            name="apac-mas-vpc", cidr=net.apac_mas_vpc_cidr,
            zone=SovereignZone.APAC, is_tgw_attached=True, is_vgw_only=False,
            allowed_data_classifications=frozenset([
                DataClassification.CUSTOMER_PII, DataClassification.ACCOUNT_NUMBER,
            ]),
        ),
        VpcDefinition(
            name="us-banking-vpc", cidr=net.us_banking_vpc_cidr,
            zone=SovereignZone.US, is_tgw_attached=True, is_vgw_only=False,
            allowed_data_classifications=frozenset([
                DataClassification.NON_PII_OPERATIONAL,
                DataClassification.AGGREGATED_RISK_METRIC,
            ]),
        ),
    ]
