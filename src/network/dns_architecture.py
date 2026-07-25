"""
DNS architecture configuration for per-region sovereign zone isolation.
Builds Route 53 private hosted zone definitions, resolver rules, and DNS
firewall rules that prevent accidental cross-zone name resolution.
"""

import logging
from dataclasses import dataclass

from src.config.enums import AwsRegion, SovereignZone, ZONE_REGIONS

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class HostedZone:
    """A Route 53 private hosted zone definition."""

    name: str
    zone: SovereignZone
    regions: list[AwsRegion]
    description: str


@dataclass(frozen=True)
class ResolverRule:
    """A Route 53 Resolver forwarding rule."""

    name: str
    domain_name: str
    rule_type: str
    target_zone: SovereignZone
    is_forward: bool
    description: str


@dataclass(frozen=True)
class DnsFirewallRule:
    """A Route 53 DNS Firewall rule."""

    name: str
    domain_list: list[str]
    action: str
    priority: int
    description: str


def build_private_hosted_zones() -> list[HostedZone]:
    """Construct per-zone private hosted zone definitions.

    Returns:
        List of HostedZone definitions for all sovereign zones.
    """
    zones = [
        HostedZone(
            name="banking.eu.internal", zone=SovereignZone.EU,
            regions=ZONE_REGIONS[SovereignZone.EU],
            description="EU zone DNS. Resolves only within eu-west-1 and eu-central-1.",
        ),
        HostedZone(
            name="banking.apac.internal", zone=SovereignZone.APAC,
            regions=ZONE_REGIONS[SovereignZone.APAC],
            description="APAC zone DNS. Resolves only within ap-southeast-1.",
        ),
        HostedZone(
            name="banking.us.internal", zone=SovereignZone.US,
            regions=ZONE_REGIONS[SovereignZone.US],
            description="US zone DNS. Resolves only within us-east-1 and us-east-2.",
        ),
    ]
    logger.info("Built %d private hosted zones", len(zones))
    return zones


def build_resolver_rules() -> list[ResolverRule]:
    """Construct Route 53 Resolver rules enforcing DNS isolation.

    EU VPCs have no forwarding rule for .us.internal or .apac.internal.
    Queries to those domains return NXDOMAIN.

    Returns:
        List of ResolverRule definitions.
    """
    rules = [
        ResolverRule(
            name="eu-forward-eu-internal", domain_name="banking.eu.internal",
            rule_type="FORWARD", target_zone=SovereignZone.EU, is_forward=True,
            description="Forward .eu.internal to EU inbound resolver endpoints.",
        ),
        ResolverRule(
            name="eu-block-apac-internal", domain_name="banking.apac.internal",
            rule_type="SYSTEM", target_zone=SovereignZone.EU, is_forward=False,
            description=(
                "EU VPCs return NXDOMAIN for .apac.internal. "
                "Absence of forwarding rule is the enforcement mechanism."
            ),
        ),
        ResolverRule(
            name="eu-block-us-internal", domain_name="banking.us.internal",
            rule_type="SYSTEM", target_zone=SovereignZone.EU, is_forward=False,
            description="EU VPCs return NXDOMAIN for .us.internal.",
        ),
        ResolverRule(
            name="apac-forward-apac-internal", domain_name="banking.apac.internal",
            rule_type="FORWARD", target_zone=SovereignZone.APAC, is_forward=True,
            description="Forward .apac.internal to APAC inbound resolver endpoints.",
        ),
        ResolverRule(
            name="us-forward-us-internal", domain_name="banking.us.internal",
            rule_type="FORWARD", target_zone=SovereignZone.US, is_forward=True,
            description="Forward .us.internal to US inbound resolver endpoints.",
        ),
    ]
    logger.info("Built %d resolver rules", len(rules))
    return rules


def build_dns_firewall_rules() -> list[DnsFirewallRule]:
    """Construct DNS Firewall rules blocking non-approved external resolution.

    Returns:
        List of DnsFirewallRule definitions.
    """
    rules = [
        DnsFirewallRule(
            name="block-public-dns-resolvers",
            domain_list=[
                "8.8.8.8.in-addr.arpa", "8.8.4.4.in-addr.arpa", "1.1.1.1.in-addr.arpa",
            ],
            action="BLOCK", priority=10,
            description="Block public DNS resolver IPs to enforce DNS Firewall rules.",
        ),
        DnsFirewallRule(
            name="block-dynamic-dns-providers",
            domain_list=["*.dyn.com", "*.no-ip.com", "*.duckdns.org", "*.ngrok.io"],
            action="BLOCK", priority=20,
            description="Block dynamic DNS providers used for exfiltration tunnels.",
        ),
        DnsFirewallRule(
            name="allow-approved-external",
            domain_list=["*.amazonaws.com", "*.aws.com"],
            action="ALLOW", priority=100,
            description="Allow resolution of AWS service endpoints.",
        ),
    ]
    logger.info("Built %d DNS firewall rules", len(rules))
    return rules
