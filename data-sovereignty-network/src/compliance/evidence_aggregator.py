"""
Compliance evidence aggregation for multi-framework regulatory audits.
Collects and structures evidence artefacts for GDPR, MiFID II, DORA, and MAS TRM.
"""

import logging
from dataclasses import dataclass
from datetime import date

from src.config.enums import RegulatoryFramework, SovereignZone
from src.config.settings import AppConfig

logger = logging.getLogger(__name__)


class EvidenceError(Exception):
    """Raised when required evidence is missing for audit submission."""


@dataclass(frozen=True)
class EvidenceArtefact:
    """A single piece of compliance evidence."""

    name: str
    framework: RegulatoryFramework
    zone: SovereignZone
    source: str
    storage_location: str
    retention_years: int
    is_immutable: bool
    is_automated: bool
    description: str
    last_generated: date | None


@dataclass(frozen=True)
class AuditPackage:
    """Assembled collection of evidence for a regulatory audit."""

    frameworks: list[RegulatoryFramework]
    zones: list[SovereignZone]
    artefacts: list[EvidenceArtefact]
    generated_date: date
    dpo_sign_off_required: bool


def build_eu_evidence_artefacts(config: AppConfig) -> list[EvidenceArtefact]:
    """Construct evidence artefacts for GDPR, MiFID II, and DORA.

    Args:
        config: Validated application configuration.

    Returns:
        List of EvidenceArtefact for the EU zone.
    """
    c = config.compliance
    return [
        EvidenceArtefact(
            name="Network Topology Diagram", framework=RegulatoryFramework.GDPR,
            zone=SovereignZone.EU, source="AWS Config Resource Graph",
            storage_location="s3://audit-logs-eu/topology/",
            retention_years=c.gdpr_audit_log_retention_years,
            is_immutable=True, is_automated=True,
            description="Auto-generated weekly from Config resource graph. Exported to DPO portal.",
            last_generated=date.today(),
        ),
        EvidenceArtefact(
            name="VPC Flow Log Data Residency Report", framework=RegulatoryFramework.GDPR,
            zone=SovereignZone.EU, source="VPC Flow Logs + Athena",
            storage_location="s3://audit-logs-eu/flow-log-reports/",
            retention_years=c.gdpr_audit_log_retention_years,
            is_immutable=True, is_automated=True,
            description=(
                f"Athena queries confirm no EU PII to non-EU CIDRs. "
                f"Run every {c.macie_scan_interval_hours} hours."
            ),
            last_generated=date.today(),
        ),
        EvidenceArtefact(
            name="SCP Violation Log", framework=RegulatoryFramework.GDPR,
            zone=SovereignZone.EU, source="CloudTrail + SIEM",
            storage_location="s3://audit-logs-eu/scp-violations/",
            retention_years=c.gdpr_audit_log_retention_years,
            is_immutable=True, is_automated=True,
            description=(
                f"CloudTrail records every SCP denial. Fed to SIEM. "
                f"Alert threshold: {c.scp_violation_alert_threshold} violation(s)."
            ),
            last_generated=date.today(),
        ),
        EvidenceArtefact(
            name="GDPR Audit Log WORM Confirmation", framework=RegulatoryFramework.GDPR,
            zone=SovereignZone.EU, source="S3 Object Lock + AWS Compliance Report",
            storage_location="s3://audit-logs-eu/worm-confirmation/",
            retention_years=c.gdpr_audit_log_retention_years,
            is_immutable=True, is_automated=False,
            description=(
                f"S3 Object Lock WORM for {c.gdpr_audit_log_retention_years} years. "
                f"Report downloadable from AWS Artifact."
            ),
            last_generated=date.today(),
        ),
        EvidenceArtefact(
            name="Macie PII Discovery Report", framework=RegulatoryFramework.GDPR,
            zone=SovereignZone.EU, source="AWS Macie",
            storage_location="s3://audit-logs-eu/macie-reports/",
            retention_years=c.gdpr_audit_log_retention_years,
            is_immutable=True, is_automated=True,
            description="Monthly Macie report confirming no PII in non-compliant buckets.",
            last_generated=date.today(),
        ),
        EvidenceArtefact(
            name="MiFID II Trade Record Retention Confirmation",
            framework=RegulatoryFramework.MIFID_II,
            zone=SovereignZone.EU, source="S3 Object Lock + RDS snapshot policy",
            storage_location="s3://audit-logs-eu/mifid-retention/",
            retention_years=c.mifid_trade_record_retention_years,
            is_immutable=True, is_automated=True,
            description=(
                f"Trade records stored in EU for {c.mifid_trade_record_retention_years} years. "
                f"Regulator access within {c.mifid_regulator_access_hours} hours."
            ),
            last_generated=date.today(),
        ),
        EvidenceArtefact(
            name="AWS Artifact Compliance Reports", framework=RegulatoryFramework.DORA,
            zone=SovereignZone.EU, source="AWS Artifact",
            storage_location="https://console.aws.amazon.com/artifact/",
            retention_years=c.gdpr_audit_log_retention_years,
            is_immutable=False, is_automated=False,
            description="SOC 2 Type II, ISO 27001, EU Data Protection Addendum.",
            last_generated=None,
        ),
    ]


def build_apac_evidence_artefacts(config: AppConfig) -> list[EvidenceArtefact]:
    """Construct evidence artefacts for MAS TRM.

    Args:
        config: Validated application configuration.

    Returns:
        List of EvidenceArtefact for the APAC zone.
    """
    return [
        EvidenceArtefact(
            name="MAS TRM Data Residency Confirmation", framework=RegulatoryFramework.MAS_TRM,
            zone=SovereignZone.APAC, source="AWS Config + VPC Flow Logs",
            storage_location="s3://audit-logs-apac/mas-trm/",
            retention_years=5, is_immutable=True, is_automated=True,
            description="Confirms customer data accessible from within ap-southeast-1.",
            last_generated=date.today(),
        ),
        EvidenceArtefact(
            name="APAC TGW Isolation Confirmation", framework=RegulatoryFramework.MAS_TRM,
            zone=SovereignZone.APAC, source="AWS Config + CloudTrail",
            storage_location="s3://audit-logs-apac/tgw-isolation/",
            retention_years=5, is_immutable=True, is_automated=True,
            description="Confirms APAC TGW has no inter-region peering to EU or US TGWs.",
            last_generated=date.today(),
        ),
    ]


def assemble_audit_package(
    config: AppConfig,
    target_frameworks: list[RegulatoryFramework],
) -> AuditPackage:
    """Assemble a complete audit package for the specified frameworks.

    Args:
        config: Validated application configuration.
        target_frameworks: The frameworks to include.

    Returns:
        AuditPackage ready for DPO review and regulatory submission.

    Raises:
        EvidenceError: When no artefacts are found for the requested frameworks.
    """
    all_artefacts = build_eu_evidence_artefacts(config) + build_apac_evidence_artefacts(config)
    relevant = [a for a in all_artefacts if a.framework in target_frameworks]

    if not relevant:
        raise EvidenceError(
            f"No evidence artefacts found for: {[f.value for f in target_frameworks]}. "
            f"Ensure evidence collection is configured for these frameworks."
        )

    requires_dpo = RegulatoryFramework.GDPR in target_frameworks
    logger.info(
        "Assembled audit package: frameworks=%s artefacts=%d",
        [f.value for f in target_frameworks], len(relevant),
    )
    return AuditPackage(
        frameworks=target_frameworks,
        zones=list({a.zone for a in relevant}),
        artefacts=relevant,
        generated_date=date.today(),
        dpo_sign_off_required=requires_dpo,
    )
