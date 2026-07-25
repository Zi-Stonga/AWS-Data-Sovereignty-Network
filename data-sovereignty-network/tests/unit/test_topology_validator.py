"""Unit tests for src/network/topology_validator.py"""

from unittest.mock import MagicMock
import pytest
from src.config.enums import DataClassification, SovereignZone
from src.network.topology_validator import (
    PeeringProposal, ValidationResult, VpcDefinition,
    validate_cidr_isolation, validate_peering_proposal, validate_vpc_attachment_rules,
)

def _make_net(
    eu_gdpr="10.50.0.0/16", eu_mifid="10.51.0.0/16",
    apac_mas="10.60.0.0/16", us_banking="10.70.0.0/16",
) -> MagicMock:
    """MagicMock stands in for NetworkConfig to avoid loading real env vars."""
    m = MagicMock()
    m.eu_gdpr_vpc_cidr = eu_gdpr
    m.eu_mifid_vpc_cidr = eu_mifid
    m.apac_mas_vpc_cidr = apac_mas
    m.us_banking_vpc_cidr = us_banking
    return m

def _eu_gdpr_vpc(is_tgw_attached=False, is_vgw_only=True) -> VpcDefinition:
    return VpcDefinition(
        name="eu-gdpr-vpc", cidr="10.50.0.0/16", zone=SovereignZone.EU,
        is_tgw_attached=is_tgw_attached, is_vgw_only=is_vgw_only,
        allowed_data_classifications=frozenset([DataClassification.CUSTOMER_PII]),
    )

def _us_vpc() -> VpcDefinition:
    return VpcDefinition(
        name="us-banking-vpc", cidr="10.70.0.0/16", zone=SovereignZone.US,
        is_tgw_attached=True, is_vgw_only=False,
        allowed_data_classifications=frozenset([DataClassification.NON_PII_OPERATIONAL]),
    )

class TestValidateCidrIsolation:
    def test_non_overlapping_passes(self):
        assert validate_cidr_isolation(_make_net()).is_valid is True

    def test_overlapping_detected(self):
        result = validate_cidr_isolation(_make_net(eu_mifid="10.50.1.0/24"))
        assert result.is_valid is False
        assert any("eu_gdpr" in v for v in result.violations)

    def test_identical_cidrs_detected(self):
        assert validate_cidr_isolation(_make_net(us_banking="10.50.0.0/16")).is_valid is False

    def test_returns_validation_result(self):
        assert isinstance(validate_cidr_isolation(_make_net()), ValidationResult)

class TestValidateVpcAttachmentRules:
    def test_eu_vgw_only_passes(self):
        assert validate_vpc_attachment_rules([_eu_gdpr_vpc()]).is_valid is True

    def test_eu_tgw_with_restricted_data_fails(self):
        # Arrange
        bad_vpc = _eu_gdpr_vpc(is_tgw_attached=True, is_vgw_only=False)
        # Act
        result = validate_vpc_attachment_rules([bad_vpc])
        # Assert
        assert result.is_valid is False
        assert "eu-gdpr-vpc" in result.violations[0]

    def test_us_tgw_passes(self):
        assert validate_vpc_attachment_rules([_us_vpc()]).is_valid is True

    def test_multiple_vpcs_evaluated_independently(self):
        # Arrange
        bad = VpcDefinition(
            name="eu-bad-vpc", cidr="10.52.0.0/16", zone=SovereignZone.EU,
            is_tgw_attached=True, is_vgw_only=False,
            allowed_data_classifications=frozenset([DataClassification.TRADE_ORDER]),
        )
        # Act
        result = validate_vpc_attachment_rules([_eu_gdpr_vpc(), bad])
        # Assert
        assert result.is_valid is False
        assert len(result.violations) == 1

class TestValidatePeeringProposal:
    def test_intra_zone_permitted(self):
        eu_b = VpcDefinition(
            name="eu-mifid-vpc", cidr="10.51.0.0/16", zone=SovereignZone.EU,
            is_tgw_attached=False, is_vgw_only=True,
            allowed_data_classifications=frozenset([DataClassification.TRADE_ORDER]),
        )
        proposal = PeeringProposal(
            source_vpc=_eu_gdpr_vpc(), destination_vpc=eu_b,
            data_classifications=frozenset([DataClassification.CUSTOMER_PII]),
            uses_privatelink=False,
        )
        assert validate_peering_proposal(proposal).is_valid is True

    def test_cross_zone_pii_rejected(self):
        # Arrange
        proposal = PeeringProposal(
            source_vpc=_eu_gdpr_vpc(), destination_vpc=_us_vpc(),
            data_classifications=frozenset([DataClassification.CUSTOMER_PII]),
            uses_privatelink=True,
        )
        # Act
        result = validate_peering_proposal(proposal)
        # Assert
        assert result.is_valid is False
        assert any("customer_pii" in v for v in result.violations)

    def test_cross_zone_anonymised_via_privatelink_permitted(self):
        proposal = PeeringProposal(
            source_vpc=_eu_gdpr_vpc(), destination_vpc=_us_vpc(),
            data_classifications=frozenset([DataClassification.ANONYMIZED_ANALYTICS]),
            uses_privatelink=True,
        )
        assert validate_peering_proposal(proposal).is_valid is True

    def test_cross_zone_no_privatelink_rejected(self):
        # Arrange
        proposal = PeeringProposal(
            source_vpc=_eu_gdpr_vpc(), destination_vpc=_us_vpc(),
            data_classifications=frozenset([DataClassification.ANONYMIZED_ANALYTICS]),
            uses_privatelink=False,
        )
        # Act
        result = validate_peering_proposal(proposal)
        # Assert
        assert result.is_valid is False
        assert any("PrivateLink" in v for v in result.violations)

    def test_pii_and_no_privatelink_two_violations(self):
        proposal = PeeringProposal(
            source_vpc=_eu_gdpr_vpc(), destination_vpc=_us_vpc(),
            data_classifications=frozenset([DataClassification.CUSTOMER_PII]),
            uses_privatelink=False,
        )
        assert len(validate_peering_proposal(proposal).violations) >= 2

    def test_permitted_cross_zone_produces_warning(self):
        proposal = PeeringProposal(
            source_vpc=_eu_gdpr_vpc(), destination_vpc=_us_vpc(),
            data_classifications=frozenset([DataClassification.ANONYMIZED_ANALYTICS]),
            uses_privatelink=True,
        )
        result = validate_peering_proposal(proposal)
        assert result.is_valid is True
        assert len(result.warnings) > 0
