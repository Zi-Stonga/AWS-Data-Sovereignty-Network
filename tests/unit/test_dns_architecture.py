"""Unit tests for src/network/dns_architecture.py"""

from src.config.enums import SovereignZone
from src.network.dns_architecture import (
    DnsFirewallRule, HostedZone, ResolverRule,
    build_dns_firewall_rules, build_private_hosted_zones, build_resolver_rules,
)

class TestBuildPrivateHostedZones:
    def test_returns_three_zones(self):
        assert len(build_private_hosted_zones()) == 3

    def test_all_are_hosted_zone_type(self):
        for zone in build_private_hosted_zones():
            assert isinstance(zone, HostedZone)

    def test_eu_zone_present(self):
        zones = build_private_hosted_zones()
        names = [z.name for z in zones]
        assert "banking.eu.internal" in names

    def test_apac_zone_present(self):
        zones = build_private_hosted_zones()
        names = [z.name for z in zones]
        assert "banking.apac.internal" in names

    def test_us_zone_present(self):
        zones = build_private_hosted_zones()
        names = [z.name for z in zones]
        assert "banking.us.internal" in names

    def test_eu_zone_has_two_regions(self):
        zones = build_private_hosted_zones()
        eu = next(z for z in zones if z.zone == SovereignZone.EU)
        assert len(eu.regions) == 2

    def test_apac_zone_has_one_region(self):
        zones = build_private_hosted_zones()
        apac = next(z for z in zones if z.zone == SovereignZone.APAC)
        assert len(apac.regions) == 1

class TestBuildResolverRules:
    def test_returns_five_rules(self):
        assert len(build_resolver_rules()) == 5

    def test_all_are_resolver_rule_type(self):
        for rule in build_resolver_rules():
            assert isinstance(rule, ResolverRule)

    def test_eu_has_no_forward_for_apac(self):
        rules = build_resolver_rules()
        eu_apac_block = next(r for r in rules if r.name == "eu-block-apac-internal")
        assert eu_apac_block.is_forward is False

    def test_eu_has_no_forward_for_us(self):
        rules = build_resolver_rules()
        eu_us_block = next(r for r in rules if r.name == "eu-block-us-internal")
        assert eu_us_block.is_forward is False

    def test_eu_forward_rule_is_forward(self):
        rules = build_resolver_rules()
        eu_forward = next(r for r in rules if r.name == "eu-forward-eu-internal")
        assert eu_forward.is_forward is True

    def test_block_rules_have_system_type(self):
        rules = build_resolver_rules()
        block_rules = [r for r in rules if not r.is_forward]
        for rule in block_rules:
            assert rule.rule_type == "SYSTEM"

class TestBuildDnsFirewallRules:
    def test_returns_three_rules(self):
        assert len(build_dns_firewall_rules()) == 3

    def test_all_are_firewall_rule_type(self):
        for rule in build_dns_firewall_rules():
            assert isinstance(rule, DnsFirewallRule)

    def test_public_resolver_block_has_lowest_priority(self):
        rules = build_dns_firewall_rules()
        block = next(r for r in rules if r.name == "block-public-dns-resolvers")
        assert block.priority == 10

    def test_dynamic_dns_block_present(self):
        rules = build_dns_firewall_rules()
        names = [r.name for r in rules]
        assert "block-dynamic-dns-providers" in names

    def test_aws_endpoints_are_allowed(self):
        rules = build_dns_firewall_rules()
        allow = next(r for r in rules if r.name == "allow-approved-external")
        assert allow.action == "ALLOW"
        assert any("amazonaws.com" in d for d in allow.domain_list)

    def test_dynamic_dns_block_action_is_block(self):
        rules = build_dns_firewall_rules()
        block = next(r for r in rules if r.name == "block-dynamic-dns-providers")
        assert block.action == "BLOCK"
