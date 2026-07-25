"""Unit tests for src/compliance/dora_schedule.py"""

from datetime import date, timedelta
from unittest.mock import MagicMock
import pytest
from src.compliance.dora_schedule import (
    DoraTestSchedule, ResilienceTest, TestStatus, TestType,
    build_dora_test_schedule, build_evidence_checklist, check_overdue_tests,
)

def _make_config() -> MagicMock:
    """MagicMock stands in for AppConfig to avoid loading real env vars."""
    m = MagicMock()
    m.compliance.dora_resilience_test_interval_days = 90
    m.compliance.dora_tlpt_interval_years = 3
    m.compliance.macie_scan_interval_hours = 24
    return m

class TestBuildDoraTestSchedule:
    def test_returns_dora_test_schedule(self):
        assert isinstance(build_dora_test_schedule(_make_config()), DoraTestSchedule)

    def test_contains_all_required_test_types(self):
        types = {t.test_type for t in build_dora_test_schedule(_make_config()).tests}
        assert TestType.DX_CONNECTION_FAILURE in types
        assert TestType.AZ_FAILURE_SIMULATION in types
        assert TestType.REGION_FAILOVER in types
        assert TestType.TLPT in types
        assert TestType.DATA_RESIDENCY_VERIFICATION in types

    def test_tlpt_frequency_uses_config(self):
        result = build_dora_test_schedule(_make_config())
        tlpt = next(t for t in result.tests if t.test_type == TestType.TLPT)
        assert tlpt.frequency_days == 3 * 365

    def test_dx_frequency_uses_config(self):
        result = build_dora_test_schedule(_make_config())
        dx = next(t for t in result.tests if t.test_type == TestType.DX_CONNECTION_FAILURE)
        assert dx.frequency_days == 90

    def test_all_tests_have_evidence_location(self):
        for test in build_dora_test_schedule(_make_config()).tests:
            assert test.evidence_location

    def test_all_tests_have_regulatory_reference(self):
        for test in build_dora_test_schedule(_make_config()).tests:
            assert "DORA" in test.regulatory_reference or "GDPR" in test.regulatory_reference

class TestCheckOverdueTests:
    def test_no_overdue_when_last_run_is_none(self):
        test = ResilienceTest(
            test_type=TestType.DX_CONNECTION_FAILURE, description="t", aws_tool="x",
            frequency_days=90, last_run_date=None, status=TestStatus.SCHEDULED,
            evidence_location="s3://b/", regulatory_reference="DORA Article 24",
        )
        schedule = DoraTestSchedule(
            tests=[test], programme_owner="CISO", next_review_date=date.today()
        )
        assert len(check_overdue_tests(schedule)) == 0

    def test_overdue_test_identified(self):
        # Arrange: last run 180 days ago with 90-day frequency
        test = ResilienceTest(
            test_type=TestType.DX_CONNECTION_FAILURE, description="t", aws_tool="x",
            frequency_days=90, last_run_date=date.today() - timedelta(days=180),
            status=TestStatus.SCHEDULED, evidence_location="s3://b/",
            regulatory_reference="DORA Article 24",
        )
        schedule = DoraTestSchedule(
            tests=[test], programme_owner="CISO", next_review_date=date.today()
        )
        overdue = check_overdue_tests(schedule)
        assert len(overdue) == 1
        assert overdue[0].test_type == TestType.DX_CONNECTION_FAILURE

    def test_in_progress_not_flagged(self):
        # Arrange: overdue on schedule but currently running
        test = ResilienceTest(
            test_type=TestType.AZ_FAILURE_SIMULATION, description="t", aws_tool="FIS",
            frequency_days=90, last_run_date=date.today() - timedelta(days=180),
            status=TestStatus.IN_PROGRESS, evidence_location="s3://b/",
            regulatory_reference="DORA Article 24",
        )
        schedule = DoraTestSchedule(
            tests=[test], programme_owner="CISO", next_review_date=date.today()
        )
        assert len(check_overdue_tests(schedule)) == 0

class TestBuildEvidenceChecklist:
    def test_returns_list_of_dicts(self):
        checklist = build_evidence_checklist(build_dora_test_schedule(_make_config()))
        assert isinstance(checklist, list)
        assert all(isinstance(i, dict) for i in checklist)

    def test_each_item_has_required_keys(self):
        required = {
            "test_type", "regulatory_reference", "evidence_location",
            "status", "last_run", "next_run", "aws_tool",
        }
        for item in build_evidence_checklist(build_dora_test_schedule(_make_config())):
            assert required <= item.keys()

    def test_length_matches_schedule(self):
        schedule = build_dora_test_schedule(_make_config())
        assert len(build_evidence_checklist(schedule)) == len(schedule.tests)
