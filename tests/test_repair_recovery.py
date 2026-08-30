from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from caretaker import (
    InMemoryRepairStore,
    RecoveryAction,
    RepairRecoveryPolicy,
    SQLiteRepairStore,
    apply_repair_recovery_plan,
    build_repair_recovery_plan,
    create_recovery_authority_packet,
    validate_authority_expiry,
    validate_supervisor_time,
    verify_recovery_authority_packet,
)
from caretaker.domain import RepairAttempt, RepairAttemptOutcome, RepairAttemptStage
from caretaker.policy import PolicyConfigurationError, RepairPolicy, validate_policy


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
    assert decision["policy_requested_action"] == "ROLLBACK_TO_DEPLOYED_CODE"
    assert decision["policy_action_status"] == "PLANNED_ONLY"
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


def test_recovery_policy_surfaces_packet_skew_and_failure_actions() -> None:
    policy = RepairRecoveryPolicy(
        worker_failure_action=RecoveryAction.REPLACE_WORKER,
        approval_packet_ttl_seconds=1800,
        suggested_change_packet_ttl_seconds=30,
        clock_skew_tolerance_seconds=15.0,
    )
    plan = build_repair_recovery_plan(InMemoryRepairStore(), policy=policy)

    assert plan["policy"]["worker_failure_action"] == "REPLACE_WORKER"
    assert plan["policy"]["approval_packet_ttl_seconds"] == 1800
    assert plan["policy"]["suggested_change_packet_ttl_seconds"] == 30
    assert plan["policy"]["clock_skew_tolerance_seconds"] == 15.0

    with pytest.raises(ValueError, match="reactivation"):
        build_repair_recovery_plan(
            InMemoryRepairStore(),
            policy=RepairRecoveryPolicy(allow_candidate_reactivation_after_restart=True),
        )
    with pytest.raises(PolicyConfigurationError, match="reactivation"):
        validate_policy(
            RepairPolicy(
                recovery=RepairRecoveryPolicy(
                    allow_candidate_reactivation_after_restart=True,
                )
            )
        )


def test_supervisor_time_and_authority_expiry_fail_closed() -> None:
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    within = validate_supervisor_time(
        supervisor_time,
        supervisor_time.replace(second=20),
        tolerance_seconds=30,
    )
    outside = validate_supervisor_time(
        supervisor_time,
        supervisor_time.replace(second=31),
        tolerance_seconds=30,
    )
    assert within["valid"] is True
    assert outside["valid"] is False
    assert outside["failure"] == "CLOCK_SKEW_EXCEEDED"

    valid = validate_authority_expiry(
        supervisor_time.replace(minute=1),
        supervisor_time=supervisor_time,
    )
    expired = validate_authority_expiry(
        supervisor_time,
        supervisor_time=supervisor_time,
    )
    assert valid["valid"] is True
    assert expired["valid"] is False
    assert expired["failure"] == "AUTHORITY_EXPIRED"


def test_recovery_authority_packet_binds_state_and_never_grants_authority() -> None:
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    packet = create_recovery_authority_packet(
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        capabilities=("observe", "restart-worker"),
        policy_state={"recovery": "reviewed"},
        approvals={"incident": "approved"},
        supervisor_time=supervisor_time,
    )

    verified = verify_recovery_authority_packet(
        packet,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe", "restart-worker"},
    )
    assert verified["valid"] is True
    assert verified["authority_granted_by_packet"] is False

    mismatch = verify_recovery_authority_packet(
        packet,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-8",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe", "restart-worker"},
    )
    assert mismatch["valid"] is False
    assert "CONTEXT_MISMATCH:generation_id" in mismatch["failures"]

    tampered = replace(packet, approvals={"incident": "forged"})
    tampered_result = verify_recovery_authority_packet(
        tampered,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe", "restart-worker"},
    )
    assert tampered_result["valid"] is False
    assert "PACKET_CONTENT_HASH_MISMATCH" in tampered_result["failures"]

    expired = verify_recovery_authority_packet(
        packet,
        supervisor_time=supervisor_time + timedelta(seconds=3601),
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe", "restart-worker"},
    )
    assert expired["valid"] is False
    assert "AUTHORITY_EXPIRED" in expired["failures"]
