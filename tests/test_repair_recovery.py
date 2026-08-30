from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from caretaker import (
    InMemoryRepairStore,
    SQLiteRepairStore,
    apply_repair_recovery_plan,
    build_repair_recovery_plan,
)
from caretaker.domain import RepairAttempt, RepairAttemptOutcome, RepairAttemptStage


def _attempt(*, target_id: str, completed: bool, outcome: RepairAttemptOutcome) -> RepairAttempt:
    return RepairAttempt(
        attempt_id=uuid4(),
        episode_id=uuid4(),
        incident_id=uuid4(),
        candidate_id=uuid4(),
        target_id=target_id,
        attempt_number=1,
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc) if completed else None,
        policy_snapshot_id=uuid4(),
        validation_profile_id="default",
        base_function_version=0,
        base_source_hash="base-hash",
        stage=RepairAttemptStage.COMPLETE if completed else RepairAttemptStage.VALIDATION,
        outcome=outcome,
    )


def test_recovery_plan_marks_incomplete_attempt_as_rollback_without_reactivation() -> None:
    store = InMemoryRepairStore()
    interrupted = _attempt(
        target_id="app:charge",
        completed=False,
        outcome=RepairAttemptOutcome.PENDING,
    )
    completed = _attempt(
        target_id="app:charge",
        completed=True,
        outcome=RepairAttemptOutcome.SUCCEEDED,
    )
    store.record_attempt(interrupted)
    store.record_attempt(completed)

    plan = build_repair_recovery_plan(store, target_id="app:charge")

    assert plan["read_only"] is True
    assert plan["restart_policy"] == "DEPLOYED_CODE_ONLY"
    assert plan["automatic_reactivation"] is False
    assert plan["incomplete_attempt_count"] == 1
    decision = plan["decisions"][0]
    assert decision["attempt_id"] == str(interrupted.attempt_id)
    assert decision["last_milestone"] == "VALIDATION"
    assert decision["recovery_action"] == "ROLLBACK_TO_DEPLOYED_CODE"
    assert decision["authority_action"] == "REVALIDATE_BEFORE_ANY_CONTINUATION"
    assert decision["candidate_reactivation_allowed"] is False
    assert decision["approval_survives_restart"] is False

    applied = apply_repair_recovery_plan(store, plan)
    repeated = apply_repair_recovery_plan(store, plan)
    assert applied["applied_count"] == 1
    assert repeated["applied_count"] == 0
    assert repeated["already_recorded_count"] == 1
    assert build_repair_recovery_plan(store, target_id="app:charge")["incomplete_attempt_count"] == 0


def test_sqlite_recovery_plan_and_acknowledgement_preserve_attempt_evidence(tmp_path: Path) -> None:
    store = SQLiteRepairStore(tmp_path / "caretaker.sqlite")
    interrupted = _attempt(
        target_id="app:charge",
        completed=False,
        outcome=RepairAttemptOutcome.PROVIDER_FAILED,
    )
    store.record_attempt(interrupted)

    plan = build_repair_recovery_plan(store)

    assert plan["incomplete_attempt_count"] == 1
    assert plan["decisions"][0]["persisted_outcome"] == "PROVIDER_FAILED"
    assert apply_repair_recovery_plan(store, plan)["applied_count"] == 1
    assert len(store.all_attempts()) == 1
    assert store.all_attempts()[0]["attempt_id"] == str(interrupted.attempt_id)
    recoveries = store.all_recoveries()
    assert len(recoveries) == 1
    assert recoveries[0]["attempt_id"] == str(interrupted.attempt_id)
    assert recoveries[0]["recovery_action"] == "ROLLBACK_TO_DEPLOYED_CODE"
