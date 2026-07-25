"""Unit tests for src/monitoring/alarm_builder.py"""

from unittest.mock import MagicMock
import pytest
from src.config.enums import SovereignZone
from src.monitoring.alarm_builder import (
    AlarmSeverity, CloudWatchAlarm, ConfigRule, MonitoringStack,
    build_config_rules, build_cross_zone_traffic_alarm,
    build_macie_finding_alarm, build_monitoring_stack, build_scp_violation_alarm,
)

def _make_config() -> MagicMock:
    """MagicMock stands in for AppConfig to avoid loading real env vars."""
    m = MagicMock()
    m.compliance.scp_violation_alert_threshold = 1
    m.monitoring.alert_sns_topic_arn = "arn:aws:sns:eu-west-1:111111111111:alerts"
    m.monitoring.vpc_flow_log_group = "/vpc/flowlogs"
    m.monitoring.cloudtrail_log_group = "/cloudtrail/logs"
    return m

class TestBuildScpViolationAlarm:
    def test_returns_cloudwatch_alarm(self):
        assert isinstance(build_scp_violation_alarm(_make_config(), SovereignZone.EU), CloudWatchAlarm)

    def test_name_includes_zone(self):
        alarm = build_scp_violation_alarm(_make_config(), SovereignZone.EU)
        assert "eu" in alarm.name

    def test_severity_is_critical(self):
        alarm = build_scp_violation_alarm(_make_config(), SovereignZone.EU)
        assert alarm.severity == AlarmSeverity.CRITICAL

    def test_threshold_matches_config(self):
        alarm = build_scp_violation_alarm(_make_config(), SovereignZone.EU)
        assert alarm.threshold == 1.0

    def test_sns_topic_arn_from_config(self):
        alarm = build_scp_violation_alarm(_make_config(), SovereignZone.EU)
        assert alarm.sns_topic_arn == "arn:aws:sns:eu-west-1:111111111111:alerts"

class TestBuildCrossZoneTrafficAlarm:
    def test_returns_cloudwatch_alarm(self):
        assert isinstance(
            build_cross_zone_traffic_alarm(_make_config(), SovereignZone.APAC), CloudWatchAlarm
        )

    def test_severity_is_critical(self):
        alarm = build_cross_zone_traffic_alarm(_make_config(), SovereignZone.EU)
        assert alarm.severity == AlarmSeverity.CRITICAL

    def test_threshold_is_zero(self):
        alarm = build_cross_zone_traffic_alarm(_make_config(), SovereignZone.EU)
        assert alarm.threshold == 0.0

    def test_name_includes_zone(self):
        alarm = build_cross_zone_traffic_alarm(_make_config(), SovereignZone.US)
        assert "us" in alarm.name

class TestBuildMacieFindingAlarm:
    def test_returns_cloudwatch_alarm(self):
        assert isinstance(
            build_macie_finding_alarm(_make_config(), SovereignZone.EU), CloudWatchAlarm
        )

    def test_severity_is_high(self):
        alarm = build_macie_finding_alarm(_make_config(), SovereignZone.EU)
        assert alarm.severity == AlarmSeverity.HIGH

    def test_threshold_is_zero(self):
        alarm = build_macie_finding_alarm(_make_config(), SovereignZone.EU)
        assert alarm.threshold == 0.0

    def test_period_is_daily(self):
        alarm = build_macie_finding_alarm(_make_config(), SovereignZone.EU)
        assert alarm.period_seconds == 86400

class TestBuildConfigRules:
    def test_returns_six_rules(self):
        assert len(build_config_rules(SovereignZone.EU)) == 6

    def test_all_rules_are_config_rule_type(self):
        for rule in build_config_rules(SovereignZone.EU):
            assert isinstance(rule, ConfigRule)

    def test_rule_names_include_zone(self):
        for rule in build_config_rules(SovereignZone.APAC):
            assert "apac" in rule.name

    def test_s3_public_access_rule_has_remediation(self):
        rules = build_config_rules(SovereignZone.EU)
        s3_rule = next(r for r in rules if "s3-no-public-access" in r.name)
        assert s3_rule.remediation_action is not None

    def test_mfa_rule_has_no_remediation(self):
        rules = build_config_rules(SovereignZone.EU)
        mfa_rule = next(r for r in rules if "mfa-enabled" in r.name)
        assert mfa_rule.remediation_action is None

class TestBuildMonitoringStack:
    def test_returns_monitoring_stack(self):
        assert isinstance(
            build_monitoring_stack(_make_config(), SovereignZone.EU), MonitoringStack
        )

    def test_contains_three_alarms(self):
        stack = build_monitoring_stack(_make_config(), SovereignZone.EU)
        assert len(stack.alarms) == 3

    def test_contains_six_config_rules(self):
        stack = build_monitoring_stack(_make_config(), SovereignZone.EU)
        assert len(stack.config_rules) == 6

    def test_contains_three_log_groups(self):
        stack = build_monitoring_stack(_make_config(), SovereignZone.EU)
        assert len(stack.log_group_names) == 3

    def test_zone_matches(self):
        stack = build_monitoring_stack(_make_config(), SovereignZone.APAC)
        assert stack.zone == SovereignZone.APAC
