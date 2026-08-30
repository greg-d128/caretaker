"""Fail-safe inspection of persisted Repair work after a process restart.

The current application-scoped recovery contract does not reactivate an in-memory
replacement. This module produces an explicit recovery plan for incomplete
attempts so an operator or future supervisor can reconcile them without treating
an interrupted transaction as successful work.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from .domain import RepairAttemptOutcome, RepairAttemptStage, utcnow


RECOVERY_PLAN_SCHEMA_VERSION = 1


def _field(record: Any, name: str, default: Any = None) -> Any:
    if isinstance(record, Mapping):
        return record.get(name, default)
    return getattr(record, name, default)


def _enum_name(value: Any) -> str:
    return str(getattr(value, "name", value or ""))


def _attempts(store: Any, target_id: str | None) -> tuple[Any, ...]:
    if target_id is not None:
        return tuple(store.attempts_for_target(target_id))
    if hasattr(store, "all_attempts"):
        return tuple(store.all_attempts())
    return ()


def build_repair_recovery_plan(
    store: Any,
    *,
    target_id: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a fail-safe plan for attempts interrupted by process loss.

    Completed attempts are omitted. An attempt with no completion timestamp or
    a pending outcome is an interrupted transaction, including a transaction
    whose last durable milestone was ``COMPLETE`` but whose final write was not
    durable. The plan is advisory and read-only: it never changes a store,
    activates a candidate, or assumes an approval survives restart.
    """
    observed_at = (now or utcnow()).isoformat()
    decisions: list[dict[str, Any]] = []
    for attempt in _attempts(store, target_id):
        completed_at = _field(attempt, "completed_at")
        outcome = _enum_name(_field(attempt, "outcome"))
        stage = _enum_name(_field(attempt, "stage"))
        if completed_at is not None and outcome != RepairAttemptOutcome.PENDING.name:
            continue
        decisions.append({
            "attempt_id": str(_field(attempt, "attempt_id", "")),
            "episode_id": str(_field(attempt, "episode_id", "")),
            "incident_id": str(_field(attempt, "incident_id", "")),
            "target_id": str(_field(attempt, "target_id", "")),
            "candidate_id": str(_field(attempt, "candidate_id", "")),
            "attempt_number": _field(attempt, "attempt_number"),
            "last_milestone": stage or RepairAttemptStage.CREATED.name,
            "persisted_outcome": outcome or RepairAttemptOutcome.PENDING.name,
            "transaction_state": "INTERRUPTED",
            "recovery_action": "ROLLBACK_TO_DEPLOYED_CODE",
            "authority_action": "REVALIDATE_BEFORE_ANY_CONTINUATION",
            "candidate_reactivation_allowed": False,
            "approval_survives_restart": False,
            "reason": (
                "Repair transaction did not durably complete; treat it as rolled back "
                "and do not reactivate an in-memory replacement"
            ),
        })
    return {
        "schema_version": RECOVERY_PLAN_SCHEMA_VERSION,
        "observed_at": observed_at,
        "target_id": target_id,
        "restart_policy": "DEPLOYED_CODE_ONLY",
        "read_only": True,
        "automatic_reactivation": False,
        "incomplete_attempt_count": len(decisions),
        "decisions": decisions,
    }
