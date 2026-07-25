"""Unit tests for src/compliance/evidence_aggregator.py"""

from unittest.mock import MagicMock
import pytest
from src.config.enums import RegulatoryFramework, SovereignZone
from src.compliance.evidence_aggregator import (
    AuditPackage, EvidenceArtefact, EvidenceError,
    assemble_audit_package, build_apac_evidence_artefacts, build_eu_evidence_artefacts,
)

def _make_config() -> MagicMock:
    """MagicMock stands in for AppConfig to avoid loading real env vars."""
    m = MagicMock()
    m.compliance.gdpr_audit_log_retention_years = 7
    m.compliance.mifid_trade_record_retention_years = 5
    m.compliance.mifid_regulator_access_hours = 24
    m.compliance.macie_scan_interval_hours = 24
    m.compliance.scp_violation_alert_threshold = 1
    return m

class TestBuildEuEvidenceArtefacts:
    def test_returns_seven_artefacts(self):
        assert len(build_eu_evidence_artefacts(_make_config())) == 7

    def test_all_are_evidence_artefact_type(self):
        for a in build_eu_evidence_artefacts(_make_config()):
            assert isinstance(a, EvidenceArtefact)

    def test_all_artefacts_in_eu_zone(self):
        for a in build_eu_evidence_artefacts(_make_config()):
            assert a.zone == SovereignZone.EU

    def test_gdpr_artefacts_present(self):
        frameworks = [a.framework for a in build_eu_evidence_artefacts(_make_config())]
        assert RegulatoryFramework.GDPR in frameworks

    def test_mifid_artefact_present(self):
        frameworks = [a.framework for a in build_eu_evidence_artefacts(_make_config())]
        assert RegulatoryFramework.MIFID_II in frameworks

    def test_dora_artefact_present(self):
        frameworks = [a.framework for a in build_eu_evidence_artefacts(_make_config())]
        assert RegulatoryFramework.DORA in frameworks

    def test_gdpr_retention_from_config(self):
        artefacts = build_eu_evidence_artefacts(_make_config())
        gdpr = [a for a in artefacts if a.framework == RegulatoryFramework.GDPR]
        for a in gdpr:
            assert a.retention_years == 7

class TestBuildApacEvidenceArtefacts:
    def test_returns_two_artefacts(self):
        assert len(build_apac_evidence_artefacts(_make_config())) == 2

    def test_all_in_apac_zone(self):
        for a in build_apac_evidence_artefacts(_make_config()):
            assert a.zone == SovereignZone.APAC

    def test_all_mas_trm_framework(self):
        for a in build_apac_evidence_artefacts(_make_config()):
            assert a.framework == RegulatoryFramework.MAS_TRM

class TestAssembleAuditPackage:
    def test_returns_audit_package(self):
        result = assemble_audit_package(
            _make_config(), [RegulatoryFramework.GDPR]
        )
        assert isinstance(result, AuditPackage)

    def test_gdpr_package_requires_dpo_sign_off(self):
        result = assemble_audit_package(
            _make_config(), [RegulatoryFramework.GDPR]
        )
        assert result.dpo_sign_off_required is True

    def test_mas_trm_package_no_dpo_sign_off(self):
        result = assemble_audit_package(
            _make_config(), [RegulatoryFramework.MAS_TRM]
        )
        assert result.dpo_sign_off_required is False

    def test_artefacts_filtered_by_framework(self):
        result = assemble_audit_package(
            _make_config(), [RegulatoryFramework.MAS_TRM]
        )
        for a in result.artefacts:
            assert a.framework == RegulatoryFramework.MAS_TRM

    def test_unknown_framework_raises_evidence_error(self):
        with pytest.raises(EvidenceError):
            assemble_audit_package(
                _make_config(), [RegulatoryFramework.CCPA]
            )

    def test_multiple_frameworks_combined(self):
        result = assemble_audit_package(
            _make_config(),
            [RegulatoryFramework.GDPR, RegulatoryFramework.MIFID_II],
        )
        frameworks = {a.framework for a in result.artefacts}
        assert RegulatoryFramework.GDPR in frameworks
        assert RegulatoryFramework.MIFID_II in frameworks
