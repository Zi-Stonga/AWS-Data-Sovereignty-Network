"""
Application configuration loaded once at startup from environment variables.
All config is centralised here. Callers receive a validated AppConfig instance
and must not call os.getenv() elsewhere in the codebase.
"""

import logging
import os
from dataclasses import dataclass

from src.config.enums import AwsRegion

logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Raised when required configuration is absent or invalid at startup."""


@dataclass(frozen=True)
class AwsConfig:
    """AWS SDK and account identifiers."""

    account_id_eu: str
    account_id_apac: str
    account_id_us: str
    org_id: str
    management_account_id: str
    default_region: AwsRegion = AwsRegion.EU_WEST_1


@dataclass(frozen=True)
class NetworkConfig:
    """CIDR allocations for each sovereign zone VPC."""

    eu_gdpr_vpc_cidr: str = "10.50.0.0/16"
    eu_mifid_vpc_cidr: str = "10.51.0.0/16"
    apac_mas_vpc_cidr: str = "10.60.0.0/16"
    us_banking_vpc_cidr: str = "10.70.0.0/16"
    dx_bandwidth_gbps: int = 10


@dataclass(frozen=True)
class ComplianceConfig:
    """Thresholds and retention periods required by regulation."""

    mifid_trade_record_retention_years: int = 5
    mifid_regulator_access_hours: int = 24
    gdpr_audit_log_retention_years: int = 7
    dora_resilience_test_interval_days: int = 90
    dora_tlpt_interval_years: int = 3
    macie_scan_interval_hours: int = 24
    scp_violation_alert_threshold: int = 1


@dataclass(frozen=True)
class MonitoringConfig:
    """Observability and alerting targets."""

    siem_endpoint: str
    dpo_portal_endpoint: str
    cloudtrail_log_group: str
    vpc_flow_log_group: str
    config_aggregator_name: str
    alert_sns_topic_arn: str


@dataclass(frozen=True)
class AppConfig:
    """Root configuration object passed through the application."""

    aws: AwsConfig
    network: NetworkConfig
    compliance: ComplianceConfig
    monitoring: MonitoringConfig
    log_level: str = "INFO"
    environment: str = "production"


def _require_env(key: str) -> str:
    """Return the value of an environment variable or raise ConfigurationError.

    Args:
        key: The environment variable name.

    Returns:
        The string value of the variable.

    Raises:
        ConfigurationError: When the variable is absent or empty.
    """
    value = os.getenv(key, "").strip()
    if not value:
        raise ConfigurationError(
            f"Required environment variable '{key}' is missing or empty. "
            f"Check .env.example for the full list of required variables."
        )
    return value


def load_config() -> AppConfig:
    """Build and validate the application configuration from environment variables.

    Returns:
        A fully validated AppConfig instance.

    Raises:
        ConfigurationError: When any required variable is absent.
    """
    logger.info("Loading application configuration from environment")

    aws = AwsConfig(
        account_id_eu=_require_env("AWS_ACCOUNT_ID_EU"),
        account_id_apac=_require_env("AWS_ACCOUNT_ID_APAC"),
        account_id_us=_require_env("AWS_ACCOUNT_ID_US"),
        org_id=_require_env("AWS_ORG_ID"),
        management_account_id=_require_env("AWS_MANAGEMENT_ACCOUNT_ID"),
    )
    monitoring = MonitoringConfig(
        siem_endpoint=_require_env("SIEM_ENDPOINT"),
        dpo_portal_endpoint=_require_env("DPO_PORTAL_ENDPOINT"),
        cloudtrail_log_group=_require_env("CLOUDTRAIL_LOG_GROUP"),
        vpc_flow_log_group=_require_env("VPC_FLOW_LOG_GROUP"),
        config_aggregator_name=_require_env("CONFIG_AGGREGATOR_NAME"),
        alert_sns_topic_arn=_require_env("ALERT_SNS_TOPIC_ARN"),
    )
    config = AppConfig(
        aws=aws,
        network=NetworkConfig(),
        compliance=ComplianceConfig(),
        monitoring=monitoring,
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        environment=os.getenv("ENVIRONMENT", "production"),
    )
    logger.info("Configuration loaded", extra={"environment": config.environment})
    return config
