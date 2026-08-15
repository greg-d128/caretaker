from __future__ import annotations

"""Shared acceptance criteria and calculations.

This module intentionally depends only on the Python standard library so it can be
used by adaptive instrumentation, repair policy, and FunctionSlot without creating
an import cycle through Guard/evidence instrumentation.
"""

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True, slots=True)
class AcceptanceCriteria:
    """Common short-term and long-term acceptance thresholds."""

    initial_successful_executions: int = 3
    long_term_successful_executions: int = 100
    long_term_minimum_duration_seconds: float = 3600.0
    probation_failure_budget: int = 0
    long_term_maximum_failures: int = 1
    long_term_failure_rate: float = 0.001


def short_term_accepted(
    *,
    successful_executions: int,
    failed_executions: int,
    criteria: AcceptanceCriteria,
) -> bool:
    return (
        successful_executions >= criteria.initial_successful_executions
        and failed_executions <= criteria.probation_failure_budget
    )


def long_term_accepted(
    *,
    successful_executions: int,
    failed_executions: int,
    started_at: datetime,
    criteria: AcceptanceCriteria,
    now: datetime | None = None,
) -> bool:
    if successful_executions < criteria.long_term_successful_executions:
        return False
    if failed_executions > criteria.long_term_maximum_failures:
        return False
    total = successful_executions + failed_executions
    failure_rate = failed_executions / max(1, total)
    if failure_rate > criteria.long_term_failure_rate:
        return False
    current = now or datetime.now(timezone.utc)
    return (current - started_at).total_seconds() >= criteria.long_term_minimum_duration_seconds
