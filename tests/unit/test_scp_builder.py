"""Unit tests for src/iam/scp_builder.py"""

import json
from unittest.mock import MagicMock
import pytest
from src.config.enums import AwsRegion, SovereignZone
from src.iam.scp_builder import (
    PolicyDocument, build_eu_scp, build_apac_scp, build_us_scp, serialise_policy,
)

def _make_config() -> MagicMock:
    """MagicMock stands in for AppConfig to avoid loading real env vars."""
    config = MagicMock()
    config.aws.org_id = "o-test123"
    return config

class TestBuildEuScp:
    def test_returns_policy_document(self):
        assert isinstance(build_eu_scp(_make_config()), PolicyDocument)

    def test_zone_is_eu(self):
        assert build_eu_scp(_make_config()).zone == SovereignZone.EU

    def test_contains_deny_non_eu_regions(self):
        result = build_eu_scp(_make_config())
        assert "DenyNonEURegionDataResources" in [s.sid for s in result.statements]

    def test_eu_regions_in_deny_condition(self):
        result = build_eu_scp(_make_config())
        deny = next(s for s in result.statements if s.sid == "DenyNonEURegionDataResources")
        allowed = deny.conditions["StringNotLike"]["aws:RequestedRegion"]
        assert AwsRegion.EU_WEST_1.value in allowed
        assert AwsRegion.EU_CENTRAL_1.value in allowed

    def test_non_eu_regions_not_in_deny_condition(self):
        result = build_eu_scp(_make_config())
        deny = next(s for s in result.statements if s.sid == "DenyNonEURegionDataResources")
        allowed = deny.conditions["StringNotLike"]["aws:RequestedRegion"]
        assert AwsRegion.US_EAST_1.value not in allowed
        assert AwsRegion.AP_SOUTHEAST_1.value not in allowed

    def test_contains_kms_restriction(self):
        sids = [s.sid for s in build_eu_scp(_make_config()).statements]
        assert "DenyKMSKeyCreationOutsideEU" in sids

    def test_contains_s3_public_access_block(self):
        sids = [s.sid for s in build_eu_scp(_make_config()).statements]
        assert "DenyS3PublicAccess" in sids

    def test_contains_cloudtrail_protection(self):
        sids = [s.sid for s in build_eu_scp(_make_config()).statements]
        assert "DenyDisableCloudTrail" in sids

    def test_all_statements_deny(self):
        assert all(s.effect == "Deny" for s in build_eu_scp(_make_config()).statements)

    def test_no_wildcard_only_actions(self):
        result = build_eu_scp(_make_config())
        for stmt in result.statements:
            assert stmt.actions != ["*"]

class TestBuildApacScp:
    def test_zone_is_apac(self):
        assert build_apac_scp(_make_config()).zone == SovereignZone.APAC

    def test_contains_tgw_peering_deny(self):
        sids = [s.sid for s in build_apac_scp(_make_config()).statements]
        assert "DenyTGWPeeringToNonAPAC" in sids

    def test_apac_region_in_deny_condition(self):
        result = build_apac_scp(_make_config())
        deny = next(s for s in result.statements if s.sid == "DenyNonAPACRegionDataResources")
        allowed = deny.conditions["StringNotLike"]["aws:RequestedRegion"]
        assert AwsRegion.AP_SOUTHEAST_1.value in allowed

class TestBuildUsScp:
    def test_zone_is_us(self):
        assert build_us_scp(_make_config()).zone == SovereignZone.US

    def test_blocks_eu_pii_buckets(self):
        result = build_us_scp(_make_config())
        deny = next(s for s in result.statements if s.sid == "DenyEUPIIBucketsFromUS")
        assert any("eu-pii" in r for r in deny.resources)
        assert any("eu-gdpr" in r for r in deny.resources)
        assert any("eu-mifid" in r for r in deny.resources)

class TestSerialisePolicy:
    def test_returns_valid_json(self):
        parsed = json.loads(serialise_policy(build_eu_scp(_make_config())))
        assert "Version" in parsed
        assert "Statement" in parsed

    def test_empty_condition_omitted(self):
        parsed = json.loads(serialise_policy(build_eu_scp(_make_config())))
        deny_leave = next(s for s in parsed["Statement"] if s["Sid"] == "DenyLeaveOrganization")
        assert "Condition" not in deny_leave
