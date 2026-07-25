"""Unit tests for src/iam/role_builder.py"""

from unittest.mock import MagicMock
import pytest
from src.config.enums import SovereignZone
from src.iam.role_builder import (
    IamRole, RoleError,
    build_compliance_scanner_role, build_dpo_read_role,
    build_flow_log_role, build_network_admin_role, serialise_role,
)

def _make_config(zone: SovereignZone = SovereignZone.EU) -> MagicMock:
    """MagicMock stands in for AppConfig to avoid loading real env vars."""
    m = MagicMock()
    m.aws.account_id_eu = "111111111111"
    m.aws.account_id_apac = "222222222222"
    m.aws.account_id_us = "333333333333"
    m.aws.management_account_id = "000000000000"
    m.monitoring.vpc_flow_log_group = "/vpc/flowlogs"
    m.monitoring.alert_sns_topic_arn = "arn:aws:sns:eu-west-1:111111111111:alerts"
    return m

class TestBuildFlowLogRole:
    def test_returns_iam_role(self):
        assert isinstance(build_flow_log_role(_make_config(), SovereignZone.EU), IamRole)

    def test_name_includes_zone(self):
        role = build_flow_log_role(_make_config(), SovereignZone.EU)
        assert "eu" in role.name

    def test_trust_principal_is_flow_logs_service(self):
        role = build_flow_log_role(_make_config(), SovereignZone.EU)
        principal = role.trust_policy["Statement"][0]["Principal"]["Service"]
        assert principal == "vpc-flow-logs.amazonaws.com"

    def test_inline_policy_scoped_to_log_group(self):
        role = build_flow_log_role(_make_config(), SovereignZone.EU)
        resources = role.inline_policies["FlowLogDelivery"]["Statement"][0]["Resource"]
        assert any("/vpc/flowlogs" in r for r in resources)

    def test_no_managed_policies(self):
        role = build_flow_log_role(_make_config(), SovereignZone.EU)
        assert role.managed_policy_arns == []

class TestBuildComplianceScannerRole:
    def test_returns_iam_role(self):
        assert isinstance(
            build_compliance_scanner_role(_make_config(), SovereignZone.EU), IamRole
        )

    def test_name_includes_zone(self):
        role = build_compliance_scanner_role(_make_config(), SovereignZone.APAC)
        assert "apac" in role.name

    def test_trust_principal_is_lambda(self):
        role = build_compliance_scanner_role(_make_config(), SovereignZone.EU)
        principal = role.trust_policy["Statement"][0]["Principal"]["Service"]
        assert principal == "lambda.amazonaws.com"

    def test_policy_includes_config_read(self):
        role = build_compliance_scanner_role(_make_config(), SovereignZone.EU)
        sids = [
            s["Sid"]
            for s in role.inline_policies["ComplianceScannerPolicy"]["Statement"]
        ]
        assert "ReadConfigFindings" in sids

    def test_policy_includes_sns_publish(self):
        role = build_compliance_scanner_role(_make_config(), SovereignZone.EU)
        sids = [
            s["Sid"]
            for s in role.inline_policies["ComplianceScannerPolicy"]["Statement"]
        ]
        assert "PublishFindingsToSNS" in sids

    def test_macie_read_scoped_to_zone_regions(self):
        role = build_compliance_scanner_role(_make_config(), SovereignZone.EU)
        stmts = role.inline_policies["ComplianceScannerPolicy"]["Statement"]
        macie = next(s for s in stmts if s["Sid"] == "ReadMacieFindings")
        regions = macie["Condition"]["StringEquals"]["aws:RequestedRegion"]
        assert "eu-west-1" in regions
        assert "eu-central-1" in regions

class TestBuildDpoReadRole:
    def test_returns_iam_role(self):
        assert isinstance(build_dpo_read_role(_make_config()), IamRole)

    def test_name_is_dpo_read_only(self):
        assert build_dpo_read_role(_make_config()).name == "dpo-read-only"

    def test_trust_requires_mfa(self):
        role = build_dpo_read_role(_make_config())
        condition = role.trust_policy["Statement"][0]["Condition"]
        assert condition["Bool"]["aws:MultiFactorAuthPresent"] == "true"

    def test_trust_requires_recent_mfa(self):
        role = build_dpo_read_role(_make_config())
        condition = role.trust_policy["Statement"][0]["Condition"]
        assert "NumericLessThan" in condition

    def test_session_duration_is_one_hour(self):
        assert build_dpo_read_role(_make_config()).max_session_duration_seconds == 3600

    def test_no_managed_policies(self):
        assert build_dpo_read_role(_make_config()).managed_policy_arns == []

class TestBuildNetworkAdminRole:
    def test_returns_iam_role(self):
        assert isinstance(
            build_network_admin_role(_make_config(), SovereignZone.EU), IamRole
        )

    def test_name_includes_zone(self):
        role = build_network_admin_role(_make_config(), SovereignZone.US)
        assert "us" in role.name

    def test_contains_tgw_peering_deny(self):
        role = build_network_admin_role(_make_config(), SovereignZone.EU)
        sids = [s["Sid"] for s in role.inline_policies["NetworkAdminPolicy"]["Statement"]]
        assert "DenyTGWPeeringCrossZone" in sids

    def test_vpc_management_scoped_to_zone_regions(self):
        role = build_network_admin_role(_make_config(), SovereignZone.EU)
        stmts = role.inline_policies["NetworkAdminPolicy"]["Statement"]
        vpc_stmt = next(s for s in stmts if s["Sid"] == "VPCManagementInZone")
        regions = vpc_stmt["Condition"]["StringEquals"]["aws:RequestedRegion"]
        assert "eu-west-1" in regions
        assert "eu-central-1" in regions

    def test_trust_requires_mfa(self):
        role = build_network_admin_role(_make_config(), SovereignZone.EU)
        condition = role.trust_policy["Statement"][0]["Condition"]
        assert condition["Bool"]["aws:MultiFactorAuthPresent"] == "true"

class TestSerialiseRole:
    def test_returns_dict(self):
        role = build_flow_log_role(_make_config(), SovereignZone.EU)
        result = serialise_role(role)
        assert isinstance(result, dict)

    def test_contains_role_name(self):
        role = build_flow_log_role(_make_config(), SovereignZone.EU)
        result = serialise_role(role)
        assert result["role_name"] == role.name

    def test_trust_policy_is_json_string(self):
        import json
        role = build_flow_log_role(_make_config(), SovereignZone.EU)
        result = serialise_role(role)
        parsed = json.loads(result["trust_policy"])
        assert "Version" in parsed
