"""
Enumeration types for sovereign zones, regions, and regulatory frameworks.
Used throughout the application as the authoritative type definitions for
data residency and compliance domain concepts.
"""

from enum import Enum, unique


@unique
class SovereignZone(str, Enum):
    """Top-level data sovereignty boundary. Each zone maps to one or more
    AWS regions and a distinct set of regulatory obligations."""

    EU = "eu"
    APAC = "apac"
    US = "us"


@unique
class AwsRegion(str, Enum):
    """AWS region identifiers in scope for this architecture."""

    EU_WEST_1 = "eu-west-1"
    EU_CENTRAL_1 = "eu-central-1"
    AP_SOUTHEAST_1 = "ap-southeast-1"
    US_EAST_1 = "us-east-1"
    US_EAST_2 = "us-east-2"


@unique
class RegulatoryFramework(str, Enum):
    """Compliance frameworks enforced by this infrastructure."""

    GDPR = "GDPR"
    MIFID_II = "MiFID_II"
    DORA = "DORA"
    MAS_TRM = "MAS_TRM"
    APRA_CPS234 = "APRA_CPS234"
    NYDFS_500 = "NYDFS_500"
    CCPA = "CCPA"


@unique
class DataClassification(str, Enum):
    """Data sensitivity tiers that govern cross-zone transfer eligibility."""

    CUSTOMER_PII = "customer_pii"
    TRADE_ORDER = "trade_order"
    ACCOUNT_NUMBER = "account_number"
    KYC_DOCUMENT = "kyc_document"
    ANONYMIZED_ANALYTICS = "anonymized_analytics"
    AGGREGATED_RISK_METRIC = "aggregated_risk_metric"
    NON_PII_OPERATIONAL = "non_pii_operational"
    SOC_SIEM_LOG = "soc_siem_log"


ZONE_REGIONS: dict[SovereignZone, list[AwsRegion]] = {
    SovereignZone.EU: [AwsRegion.EU_WEST_1, AwsRegion.EU_CENTRAL_1],
    SovereignZone.APAC: [AwsRegion.AP_SOUTHEAST_1],
    SovereignZone.US: [AwsRegion.US_EAST_1, AwsRegion.US_EAST_2],
}

ZONE_FRAMEWORKS: dict[SovereignZone, list[RegulatoryFramework]] = {
    SovereignZone.EU: [
        RegulatoryFramework.GDPR,
        RegulatoryFramework.MIFID_II,
        RegulatoryFramework.DORA,
    ],
    SovereignZone.APAC: [
        RegulatoryFramework.MAS_TRM,
        RegulatoryFramework.APRA_CPS234,
    ],
    SovereignZone.US: [
        RegulatoryFramework.NYDFS_500,
        RegulatoryFramework.CCPA,
    ],
}

CROSS_ZONE_ALLOWED_CLASSIFICATIONS: frozenset[DataClassification] = frozenset([
    DataClassification.ANONYMIZED_ANALYTICS,
    DataClassification.AGGREGATED_RISK_METRIC,
    DataClassification.NON_PII_OPERATIONAL,
    DataClassification.SOC_SIEM_LOG,
])

CROSS_ZONE_BLOCKED_CLASSIFICATIONS: frozenset[DataClassification] = frozenset([
    DataClassification.CUSTOMER_PII,
    DataClassification.TRADE_ORDER,
    DataClassification.ACCOUNT_NUMBER,
    DataClassification.KYC_DOCUMENT,
])
