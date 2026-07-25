"""
DORA Article 24 compliance testing schedule and evidence collection.
Models the resilience testing programme required by EU DORA (effective Jan 2025).
"""

import logging
from dataclasses import dataclass
from datetime import date, timedelta
from enum import Enum, unique

from src.config.settings import AppConfig

logger = logging.getLogger(__name__)


class DoraComplianceError(Exception):
    """Raised when a DORA compliance check fails or evidence is incomplete."""


@unique
class TestType(str, Enum):
    """DORA Article 24 test categories."""

    DX_CONNECTION_FAILURE = "dx_connection_failure"
    AZ_FAILURE_SIMULATION = "az_failure_simulation"
    REGION_FAILOVER = "region_failover"
    TLPT = "threat_led_penetration_test"
    DATA_RESIDENCY_VERIFICATION = "data_residency_verification"


@unique
class TestStatus(str, Enum):
    """Execution status of a scheduled test."""

    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    PASSED = "passed"
    FAILED = "failed"
    EVIDENCE_PENDING = "evidence_pending"


@dataclass(frozen=True)
class ResilienceTest:
    """A single DORA resilience test definition."""

    test_type: TestType
    description: str
    aws_tool: str
    frequency_days: int
    last_run_date: date | None
    status: TestStatus
    evidence_location: str
    regulatory_reference: str


@dataclass(frozen=True)
class DoraTestSchedule:
    """Full DORA testing programme for the organisation."""

    tests: list[ResilienceTest]
    programme_owner: str
    next_review_date: date


def _calculate_next_run(last_run: date | None, frequency_days: int) -> date:
    """Calculate the next scheduled run date.

    Args:
        last_run: Date of the most recent test run, or None if never run.
        frequency_days: How often the test should run in days.

    Returns:
        The date the next run is due.
    """
    if last_run is None:
        return date.today()
    return last_run + timedelta(days=frequency_days)


def build_dora_test_schedule(config: AppConfig) -> DoraTestSchedule:
    """Construct the full DORA Article 24 testing programme.

    Args:
        config: Validated application configuration.

    Returns:
        DoraTestSchedule covering all required test types.
    """
    c = config.compliance
    tests = [
        ResilienceTest(
            test_type=TestType.DX_CONNECTION_FAILURE,
            description=(
                "Simulate BGP failure on Direct Connect without physical disconnection. "
                "Verify failover to backup DX circuit within RTO."
            ),
            aws_tool="AWS Direct Connect Resiliency Toolkit",
            frequency_days=c.dora_resilience_test_interval_days,
            last_run_date=None, status=TestStatus.SCHEDULED,
            evidence_location="s3://audit-logs-eu/dora/dx-failure-tests/",
            regulatory_reference="DORA Article 24(1)(a)",
        ),
        ResilienceTest(
            test_type=TestType.AZ_FAILURE_SIMULATION,
            description=(
                "Inject AZ-level network partition using AWS FIS. "
                "Verify sovereignty controls remain enforced."
            ),
            aws_tool="AWS Fault Injection Simulator (FIS)",
            frequency_days=180, last_run_date=None, status=TestStatus.SCHEDULED,
            evidence_location="s3://audit-logs-eu/dora/az-failure-tests/",
            regulatory_reference="DORA Article 24(1)(b)",
        ),
        ResilienceTest(
            test_type=TestType.REGION_FAILOVER,
            description=(
                "Execute Route 53 manual failover. Verify EU failover stays within EU zone. "
                "Confirm no cross-zone migration."
            ),
            aws_tool="Route 53 Health Checks + Global Accelerator",
            frequency_days=365, last_run_date=None, status=TestStatus.SCHEDULED,
            evidence_location="s3://audit-logs-eu/dora/region-failover-tests/",
            regulatory_reference="DORA Article 24(1)(c)",
        ),
        ResilienceTest(
            test_type=TestType.TLPT,
            description=(
                "Threat-Led Penetration Test by qualified external red team. "
                "Scope covers all sovereign zone boundaries and cross-zone controls."
            ),
            aws_tool="AWS Detective + external red team",
            frequency_days=c.dora_tlpt_interval_years * 365,
            last_run_date=None, status=TestStatus.SCHEDULED,
            evidence_location="s3://audit-logs-eu/dora/tlpt-reports/",
            regulatory_reference="DORA Article 26 (TLPT)",
        ),
        ResilienceTest(
            test_type=TestType.DATA_RESIDENCY_VERIFICATION,
            description=(
                "Continuous automated scan using Config and Macie. "
                "Athena queries confirm no EU PII traffic destined for non-EU CIDRs."
            ),
            aws_tool="AWS Config + Macie + Athena + VPC Flow Logs",
            frequency_days=c.macie_scan_interval_hours // 24,
            last_run_date=date.today(), status=TestStatus.IN_PROGRESS,
            evidence_location="s3://audit-logs-eu/dora/residency-verification/",
            regulatory_reference="DORA Article 24(6) + GDPR Article 44",
        ),
    ]
    logger.info("Built DORA test schedule with %d test types", len(tests))
    return DoraTestSchedule(
        tests=tests,
        programme_owner="Chief Information Security Officer",
        next_review_date=date.today() + timedelta(days=90),
    )


def check_overdue_tests(schedule: DoraTestSchedule) -> list[ResilienceTest]:
    """Identify tests past their scheduled run date.

    Args:
        schedule: The full DORA test schedule.

    Returns:
        List of overdue tests requiring immediate scheduling.
    """
    today = date.today()
    overdue = []
    for test in schedule.tests:
        next_run = _calculate_next_run(test.last_run_date, test.frequency_days)
        if next_run < today and test.status == TestStatus.SCHEDULED:
            overdue.append(test)
            logger.warning(
                "Overdue DORA test: type=%s next_run=%s",
                test.test_type.value, next_run.isoformat(),
            )
    return overdue


def build_evidence_checklist(schedule: DoraTestSchedule) -> list[dict]:
    """Generate a regulatory audit evidence checklist.

    Args:
        schedule: The DORA test schedule.

    Returns:
        List of evidence items for audit submission.
    """
    return [
        {
            "test_type": test.test_type.value,
            "regulatory_reference": test.regulatory_reference,
            "evidence_location": test.evidence_location,
            "status": test.status.value,
            "last_run": (
                test.last_run_date.isoformat() if test.last_run_date else "never"
            ),
            "next_run": _calculate_next_run(
                test.last_run_date, test.frequency_days
            ).isoformat(),
            "aws_tool": test.aws_tool,
        }
        for test in schedule.tests
    ]
