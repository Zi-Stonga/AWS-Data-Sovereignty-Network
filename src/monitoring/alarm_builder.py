"""
Monitoring and alerting configuration for sovereign zone compliance.
Builds CloudWatch alarm definitions and Config rule sets for each zone.
"""

import logging
from dataclasses import dataclass
from enum import Enum, unique

from src.config.enums import SovereignZone, ZONE_REGIONS
from src.config.settings import AppConfig

logger = logging.getLogger(__name__)


@unique
class AlarmSeverity(str, Enum):
    """Alert severity tiers mapped to response SLAs."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class CloudWatchAlarm:
    """A CloudWatch alarm definition for a sovereignty control."""

    name: str
    zone: SovereignZone
    metric_name: str
    namespace: str
    threshold: float
    comparison_operator: str
    evaluation_periods: int
    period_seconds: int
    severity: AlarmSeverity
    description: str
    sns_topic_arn: str


@dataclass(frozen=True)
class ConfigRule:
    """An AWS Config rule checking a compliance control."""

    name: str
    zone: SovereignZone
    source_identifier: str
    input_parameters: dict
    description: str
    remediation_action: str | None


@dataclass(frozen=True)
class MonitoringStack:
    """Complete monitoring configuration for a zone."""

    zone: SovereignZone
    alarms: list[CloudWatchAlarm]
    config_rules: list[ConfigRule]
    log_group_names: list[str]


def build_scp_violation_alarm(config: AppConfig, zone: SovereignZone) -> CloudWatchAlarm:
    """Build an alarm that fires on any SCP denial in the zone.

    Args:
        config: Validated application configuration.
        zone: The zone to monitor.

    Returns:
        CloudWatchAlarm for SCP violations.
    """
    return CloudWatchAlarm(
        name=f"scp-violation-{zone.value}", zone=zone,
        metric_name="SCPDenialCount",
        namespace=f"DataSovereignty/{zone.value.upper()}",
        threshold=float(config.compliance.scp_violation_alert_threshold),
        comparison_operator="GreaterThanOrEqualToThreshold",
        evaluation_periods=1, period_seconds=300,
        severity=AlarmSeverity.CRITICAL,
        description=(
            f"Fires when any SCP denial is recorded in the {zone.value.upper()} zone. "
            f"Investigate immediately for compliance breach."
        ),
        sns_topic_arn=config.monitoring.alert_sns_topic_arn,
    )


def build_cross_zone_traffic_alarm(config: AppConfig, zone: SovereignZone) -> CloudWatchAlarm:
    """Build an alarm monitoring for unexpected cross-zone traffic.

    Args:
        config: Validated application configuration.
        zone: The source zone to monitor.

    Returns:
        CloudWatchAlarm for cross-zone traffic anomalies.
    """
    return CloudWatchAlarm(
        name=f"cross-zone-traffic-{zone.value}", zone=zone,
        metric_name="CrossZoneFlowCount",
        namespace=f"DataSovereignty/{zone.value.upper()}",
        threshold=0.0, comparison_operator="GreaterThanThreshold",
        evaluation_periods=1, period_seconds=300,
        severity=AlarmSeverity.CRITICAL,
        description=(
            f"Fires when VPC Flow Logs detect traffic from {zone.value.upper()} "
            f"destined for a non-{zone.value.upper()} CIDR."
        ),
        sns_topic_arn=config.monitoring.alert_sns_topic_arn,
    )


def build_macie_finding_alarm(config: AppConfig, zone: SovereignZone) -> CloudWatchAlarm:
    """Build an alarm for Macie PII findings in non-compliant locations.

    Args:
        config: Validated application configuration.
        zone: The zone where Macie is scanning.

    Returns:
        CloudWatchAlarm for Macie findings.
    """
    return CloudWatchAlarm(
        name=f"macie-pii-finding-{zone.value}", zone=zone,
        metric_name="MaciePIIFindingCount",
        namespace=f"DataSovereignty/{zone.value.upper()}",
        threshold=0.0, comparison_operator="GreaterThanThreshold",
        evaluation_periods=1, period_seconds=86400,
        severity=AlarmSeverity.HIGH,
        description=(
            f"Fires when Macie discovers PII outside the {zone.value.upper()} zone. "
            f"Triggers DPO notification."
        ),
        sns_topic_arn=config.monitoring.alert_sns_topic_arn,
    )


def build_config_rules(zone: SovereignZone) -> list[ConfigRule]:
    """Build AWS Config rule definitions for a sovereign zone.

    Args:
        zone: The zone to build Config rules for.

    Returns:
        List of ConfigRule definitions.
    """
    rules = [
        ConfigRule(
            name=f"s3-no-public-access-{zone.value}", zone=zone,
            source_identifier="S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED",
            input_parameters={},
            description="Checks that no S3 bucket has public access enabled.",
            remediation_action="AWS-DisableS3BucketPublicReadWrite",
        ),
        ConfigRule(
            name=f"encrypted-volumes-{zone.value}", zone=zone,
            source_identifier="ENCRYPTED_VOLUMES", input_parameters={},
            description="Checks that all EBS volumes are encrypted at rest.",
            remediation_action=None,
        ),
        ConfigRule(
            name=f"cloudtrail-enabled-{zone.value}", zone=zone,
            source_identifier="CLOUD_TRAIL_ENABLED", input_parameters={},
            description="Checks that CloudTrail is active in all permitted regions.",
            remediation_action=None,
        ),
        ConfigRule(
            name=f"rds-storage-encrypted-{zone.value}", zone=zone,
            source_identifier="RDS_STORAGE_ENCRYPTED", input_parameters={},
            description="Checks that all RDS instances have storage encryption enabled.",
            remediation_action=None,
        ),
        ConfigRule(
            name=f"vpc-flow-logs-enabled-{zone.value}", zone=zone,
            source_identifier="VPC_FLOW_LOGS_ENABLED", input_parameters={},
            description="Checks that VPC Flow Logs are enabled. Required for residency verification.",
            remediation_action=None,
        ),
        ConfigRule(
            name=f"mfa-enabled-iam-console-{zone.value}", zone=zone,
            source_identifier="MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS", input_parameters={},
            description="Checks that MFA is enabled for all IAM console users.",
            remediation_action=None,
        ),
    ]
    logger.info("Built %d Config rules for zone=%s", len(rules), zone.value)
    return rules


def build_monitoring_stack(config: AppConfig, zone: SovereignZone) -> MonitoringStack:
    """Assemble the complete monitoring stack for a sovereign zone.

    Args:
        config: Validated application configuration.
        zone: The zone to build monitoring for.

    Returns:
        MonitoringStack with all alarms and Config rules.
    """
    alarms = [
        build_scp_violation_alarm(config, zone),
        build_cross_zone_traffic_alarm(config, zone),
        build_macie_finding_alarm(config, zone),
    ]
    log_groups = [
        config.monitoring.vpc_flow_log_group,
        config.monitoring.cloudtrail_log_group,
        f"/aws/lambda/compliance-scanner-{zone.value}",
    ]
    logger.info(
        "Built monitoring stack: zone=%s alarms=%d config_rules=%d",
        zone.value, len(alarms), len(build_config_rules(zone)),
    )
    return MonitoringStack(
        zone=zone, alarms=alarms,
        config_rules=build_config_rules(zone),
        log_group_names=log_groups,
    )
