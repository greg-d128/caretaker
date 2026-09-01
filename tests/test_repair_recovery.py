from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from caretaker import (
    InMemoryRepairStore,
    RecoveryAction,
    RecoveryPlanStaleError,
    RepairRecoveryPolicy,
    SQLiteRepairStore,
    WorkerAcceptanceOverride,
    WorkerAcceptancePolicy,
    apply_repair_recovery_plan,
    build_repair_recovery_plan,
    create_recovery_authority_packet,
    dispatch_recovery_action,
    evaluate_worker_acceptance,
    validate_authority_expiry,
    validate_recovery_candidate_binding,
    validate_supervisor_time,
    verify_recovery_authority_packet,
    select_recovery_action,
    recover_candidate_observation_state,
)
from caretaker.domain import ObservationRecord, RepairAttempt, RepairAttemptOutcome, RepairAttemptStage
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


def _observation(
    *,
    target_id: str,
    candidate_id,
    call_id,
    occurred_at: datetime,
    success: bool,
) -> ObservationRecord:
    return ObservationRecord(
        observation_id=uuid4(),
        target_id=target_id,
        candidate_id=candidate_id,
        function_version=1,
        call_id=call_id,
        occurred_at=occurred_at,
        mode="repair-retry",
        original_outcome=None,
        candidate_outcome={"succeeded": success},
        comparison=None,
        counted_as_success=success,
        counted_as_failure=not success,
        decision_reason="test observation",
    )


def test_observation_recovery_is_durable_idempotent_and_read_only(tmp_path: Path) -> None:
    interrupted = _attempt(
        target_id="app:charge",
        completed=False,
        outcome=RepairAttemptOutcome.PENDING,
    )
    first = _observation(
        target_id=interrupted.target_id,
        candidate_id=interrupted.candidate_id,
        call_id=uuid4(),
        occurred_at=datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc),
        success=True,
    )
    second = _observation(
        target_id=interrupted.target_id,
        candidate_id=interrupted.candidate_id,
        call_id=uuid4(),
        occurred_at=datetime(2026, 8, 30, 12, 1, tzinfo=timezone.utc),
        success=False,
    )

    for store in (
        InMemoryRepairStore(),
        SQLiteRepairStore(tmp_path / "observations.sqlite"),
    ):
        store.record_observation(first)
        store.record_observation(first)
        store.record_observation(second)
        assert len(store.all_observations()) == 2
        with pytest.raises(ValueError, match="different evidence"):
            store.record_observation(
                replace(first, counted_as_success=False, counted_as_failure=True)
            )

        recovered = recover_candidate_observation_state(
            store,
            target_id=interrupted.target_id,
            candidate_id=str(interrupted.candidate_id),
        )
        assert recovered["read_only"] is True
        assert recovered["authority_granted"] is False
        assert recovered["state"] == "PERSISTED_EVIDENCE_READY"
        assert recovered["observation_count"] == 2
        assert recovered["successful_executions"] == 1
        assert recovered["failed_executions"] == 1
        assert recovered["duplicate_observation_count"] == 0
        assert recovered["double_count_protection"] == "OBSERVATION_ID_UNIQUENESS"


def test_recovery_plan_includes_persisted_candidate_observation_state() -> None:
    store = InMemoryRepairStore()
    interrupted = _attempt(
        target_id="app:charge",
        completed=False,
        outcome=RepairAttemptOutcome.PENDING,
    )
    store.record_attempt(interrupted)
    store.record_observation(
        _observation(
            target_id=interrupted.target_id,
            candidate_id=interrupted.candidate_id,
            call_id=uuid4(),
            occurred_at=datetime.now(timezone.utc),
            success=True,
        )
    )

    decision = build_repair_recovery_plan(store)["decisions"][0]

    assert decision["observation_recovery"]["observation_count"] == 1
    assert decision["observation_recovery"]["continuation_requires_live_revalidation"] is True


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
    assert decision["policy_action"]["selected_action"] == "ROLLBACK_TO_DEPLOYED_CODE"
    assert decision["policy_action"]["requires_application_orchestration"] is False
    assert decision["authority_action"] == "REVALIDATE_BEFORE_ANY_CONTINUATION"
    assert decision["candidate_reactivation_allowed"] is False
    assert decision["approval_survives_restart"] is False

    applied = apply_repair_recovery_plan(store, plan)
    repeated = apply_repair_recovery_plan(store, plan)
    assert applied["applied_count"] == 1
    assert applied["action_results"][0]["status"] == "FALLBACK_ONLY"
    assert repeated["applied_count"] == 0
    assert repeated["already_recorded_count"] == 1
    assert store.all_recoveries()[0].policy_action["selected_action"] == "ROLLBACK_TO_DEPLOYED_CODE"
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


def test_recovery_plan_rejects_tampered_or_completed_source() -> None:
    store = InMemoryRepairStore()
    interrupted = _attempt(
        target_id="app:charge",
        completed=False,
        outcome=RepairAttemptOutcome.PENDING,
    )
    store.record_attempt(interrupted)
    plan = build_repair_recovery_plan(store)

    tampered = {
        **plan,
        "decisions": [
            {**plan["decisions"][0], "target_id": "app:other"}
        ],
    }
    with pytest.raises(RecoveryPlanStaleError, match="target_id"):
        apply_repair_recovery_plan(store, tampered)
    assert store.all_recoveries() == ()

    store.record_attempt(
        replace(
            interrupted,
            completed_at=datetime.now(timezone.utc),
            stage=RepairAttemptStage.COMPLETE,
            outcome=RepairAttemptOutcome.SUCCEEDED,
        )
    )
    with pytest.raises(RecoveryPlanStaleError, match="completed"):
        apply_repair_recovery_plan(store, plan)
    assert store.all_recoveries() == ()


def test_recovery_plan_validates_all_decisions_before_writing() -> None:
    store = InMemoryRepairStore()
    first = _attempt(
        target_id="app:charge",
        completed=False,
        outcome=RepairAttemptOutcome.PENDING,
    )
    second = _attempt(
        target_id="app:refund",
        completed=False,
        outcome=RepairAttemptOutcome.PENDING,
    )
    store.record_attempt(first)
    store.record_attempt(second)
    plan = build_repair_recovery_plan(store)
    tampered = {
        **plan,
        "decisions": [
            plan["decisions"][0],
            {**plan["decisions"][1], "candidate_id": str(uuid4())},
        ],
    }

    with pytest.raises(RecoveryPlanStaleError, match="candidate_id"):
        apply_repair_recovery_plan(store, tampered)
    assert store.all_recoveries() == ()

    applied = apply_repair_recovery_plan(store, plan)
    assert applied["applied_count"] == 2
    assert {item.attempt_id for item in store.all_recoveries()} == {
        str(first.attempt_id),
        str(second.attempt_id),
    }


def test_recovery_plan_projects_linked_lifecycle_records_without_mutating_them() -> None:
    store = InMemoryRepairStore()
    interrupted = _attempt(
        target_id="app:charge",
        completed=False,
        outcome=RepairAttemptOutcome.PENDING,
    )
    generation_id = uuid4()
    now = datetime.now(timezone.utc)
    store.record_attempt(interrupted)
    store.episodes[interrupted.episode_id] = SimpleNamespace(
        episode_id=interrupted.episode_id,
        created_at=now,
        completed_at=None,
    )
    store.generations[generation_id] = SimpleNamespace(
        generation_id=generation_id,
        started_at=now,
        completed_at=None,
    )
    store.candidates[interrupted.candidate_id] = SimpleNamespace(
        candidate_id=interrupted.candidate_id,
        generation_id=generation_id,
        created_at=now,
    )

    plan = build_repair_recovery_plan(store)

    assert plan["incomplete_lifecycle_record_count"] == 5
    records = plan["decisions"][0]["incomplete_records"]
    assert {item["record_type"] for item in records} == {
        "attempt", "incident", "episode", "generation", "validation",
    }
    assert next(item for item in records if item["record_type"] == "incident")["state"] == "INCOMPLETE_REPAIR"
    assert next(item for item in records if item["record_type"] == "validation")["state"] == "INCOMPLETE"
    assert store.episodes[interrupted.episode_id].completed_at is None
    assert store.generations[generation_id].completed_at is None

    applied = apply_repair_recovery_plan(store, plan)

    assert applied["applied_count"] == 1
    assert applied["lifecycle_mark_count"] == 5
    recovery = store.all_recoveries()[0]
    assert len(recovery.incomplete_records) == 5
    marks = store.all_recovery_lifecycle_marks()
    assert len(marks) == 5
    assert {mark.record_type for mark in marks} == {
        "attempt", "incident", "episode", "generation", "validation",
    }
    assert all(mark.state in {"INCOMPLETE_REPAIR", "INCOMPLETE"} for mark in marks)


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_recovery_lifecycle_marks_are_durable_and_idempotent(
    tmp_path: Path,
    store_kind: str,
) -> None:
    path = tmp_path / "lifecycle.sqlite"
    store = (
        InMemoryRepairStore()
        if store_kind == "memory"
        else SQLiteRepairStore(path)
    )
    interrupted = _attempt(
        target_id="app:charge",
        completed=False,
        outcome=RepairAttemptOutcome.PENDING,
    )
    store.record_attempt(interrupted)
    plan = build_repair_recovery_plan(store)

    first = apply_repair_recovery_plan(store, plan)
    repeated = apply_repair_recovery_plan(store, plan)

    assert first["lifecycle_mark_count"] == 4
    assert repeated["lifecycle_mark_count"] == 0
    marks = store.all_recovery_lifecycle_marks()
    assert len(marks) == 4
    marker_ids = {
        mark["marker_id"] if isinstance(mark, dict) else str(mark.marker_id)
        for mark in marks
    }
    assert len(marker_ids) == 4
    assert all(
        len(mark["source_sha256"] if isinstance(mark, dict) else mark.source_sha256) == 64
        for mark in marks
    )

    if store_kind == "sqlite":
        reopened = SQLiteRepairStore(path)
        reopened_marks = reopened.all_recovery_lifecycle_marks()
        assert len(reopened_marks) == 4
        assert {
            mark["marker_id"] for mark in reopened_marks
        } == marker_ids


def test_recovery_candidate_binding_requires_live_context_and_rejects_mismatch() -> None:
    attempt = _attempt(
        target_id="app:charge",
        completed=False,
        outcome=RepairAttemptOutcome.PENDING,
    )
    candidate_source = "def candidate():\n    return 1\n"
    candidate_source_hash = hashlib.sha256(candidate_source.encode()).hexdigest()
    candidate = SimpleNamespace(
        candidate_id=attempt.candidate_id,
        episode_id=attempt.episode_id,
        incident_id=attempt.incident_id,
        target_id=attempt.target_id,
        base_source_hash=attempt.base_source_hash,
        authority_policy_generation=attempt.authority_policy_generation,
        authority_policy_fingerprint=attempt.authority_policy_fingerprint,
        artifact=SimpleNamespace(
            kind="FUNCTION_REPLACEMENT",
            files=(SimpleNamespace(
                content=candidate_source,
                content_hash=candidate_source_hash,
            ),),
            artifact_hash=candidate_source_hash,
        ),
    )

    persisted = validate_recovery_candidate_binding(
        attempt,
        candidate,
        persisted_policy_fingerprint="policy-hash",
    )
    assert persisted["persisted_binding_valid"] is True
    assert persisted["execution_valid"] is False
    assert set(persisted["missing_live_context"]) == {
        "target_id", "code_hash", "policy_fingerprint", "authority_policy_generation",
        "authority_policy_fingerprint",
    }
    assert persisted["policy_snapshot_revalidation_required"] is True
    assert persisted["authority_granted"] is False

    live = validate_recovery_candidate_binding(
        attempt,
        candidate,
        current_target_id=attempt.target_id,
        current_code_hash=attempt.base_source_hash,
        persisted_policy_fingerprint="policy-hash",
        current_policy_fingerprint="policy-hash",
        current_authority_policy_generation=attempt.authority_policy_generation,
        current_authority_policy_fingerprint=attempt.authority_policy_fingerprint,
    )
    assert live["execution_valid"] is True
    assert live["artifact_integrity"]["valid"] is True

    tampered = SimpleNamespace(
        **{
            **vars(candidate),
            "artifact": SimpleNamespace(
                kind="FUNCTION_REPLACEMENT",
                files=(SimpleNamespace(
                    content="def candidate():\n    return 2\n",
                    content_hash=candidate_source_hash,
                ),),
                artifact_hash=candidate_source_hash,
            ),
        }
    )
    tampered_result = validate_recovery_candidate_binding(
        attempt,
        tampered,
        current_target_id=attempt.target_id,
        current_code_hash=attempt.base_source_hash,
        persisted_policy_fingerprint="policy-hash",
        current_policy_fingerprint="policy-hash",
        current_authority_policy_generation=attempt.authority_policy_generation,
        current_authority_policy_fingerprint=attempt.authority_policy_fingerprint,
    )
    assert tampered_result["execution_valid"] is False
    assert "PERSISTED_ARTIFACT_CONTENT_HASH_MISMATCH:0" in tampered_result["failures"]

    mismatch = validate_recovery_candidate_binding(
        attempt,
        candidate,
        current_target_id="app:other",
        current_code_hash=attempt.base_source_hash,
        persisted_policy_fingerprint="policy-hash",
        current_policy_fingerprint="policy-hash",
        current_authority_policy_generation=attempt.authority_policy_generation,
        current_authority_policy_fingerprint=attempt.authority_policy_fingerprint,
    )
    assert mismatch["execution_valid"] is False
    assert "LIVE_CONTEXT_MISMATCH:target_id" in mismatch["failures"]


def test_recovery_plan_application_revalidates_live_binding_before_dispatch() -> None:
    store = InMemoryRepairStore()
    interrupted = _attempt(
        target_id="app:charge",
        completed=False,
        outcome=RepairAttemptOutcome.PENDING,
    )
    store.record_attempt(interrupted)
    candidate_source = "def candidate():\n    return 1\n"
    candidate_source_hash = hashlib.sha256(candidate_source.encode()).hexdigest()
    store.candidates[interrupted.candidate_id] = SimpleNamespace(
        candidate_id=interrupted.candidate_id,
        episode_id=interrupted.episode_id,
        incident_id=interrupted.incident_id,
        target_id=interrupted.target_id,
        created_at=interrupted.created_at,
        base_source_hash=interrupted.base_source_hash,
        authority_policy_generation=interrupted.authority_policy_generation,
        authority_policy_fingerprint=interrupted.authority_policy_fingerprint,
        artifact=SimpleNamespace(
            kind="FUNCTION_REPLACEMENT",
            files=(SimpleNamespace(
                content=candidate_source,
                content_hash=candidate_source_hash,
            ),),
            artifact_hash=candidate_source_hash,
        ),
    )
    store.policies[interrupted.policy_snapshot_id] = SimpleNamespace(
        policy_snapshot_id=interrupted.policy_snapshot_id,
        fingerprint="policy-hash",
        created_at=interrupted.created_at,
    )
    live_context = {
        "target_id": interrupted.target_id,
        "code_hash": interrupted.base_source_hash,
        "policy_fingerprint": "policy-hash",
        "authority_policy_generation": interrupted.authority_policy_generation,
        "authority_policy_fingerprint": interrupted.authority_policy_fingerprint,
    }
    plan = build_repair_recovery_plan(
        store,
        live_context_by_target={interrupted.target_id: live_context},
    )
    assert plan["decisions"][0]["candidate_binding"]["execution_valid"] is True

    calls: list[Mapping[str, object]] = []
    with pytest.raises(RecoveryPlanStaleError, match="live candidate"):
        apply_repair_recovery_plan(
            store,
            plan,
            live_context_by_target={
                interrupted.target_id: {
                    **live_context,
                    "code_hash": "changed-code-hash",
                }
            },
            handlers={
                "GENERATE_INCIDENT": lambda decision: calls.append(decision)
                or {"accepted": True, "incident_id": "incident-new"}
            },
        )

    assert calls == []
    assert store.all_recoveries() == ()
    assert store.all_recovery_lifecycle_marks() == ()


def test_recovery_plan_application_fails_closed_when_live_binding_is_unavailable() -> None:
    store = InMemoryRepairStore()
    interrupted = _attempt(
        target_id="app:charge",
        completed=False,
        outcome=RepairAttemptOutcome.PENDING,
    )
    store.record_attempt(interrupted)
    plan = build_repair_recovery_plan(store)
    calls: list[Mapping[str, object]] = []

    with pytest.raises(RecoveryPlanStaleError, match="binding is unavailable"):
        apply_repair_recovery_plan(
            store,
            plan,
            live_context_by_target={
                interrupted.target_id: {
                    "target_id": interrupted.target_id,
                    "code_hash": interrupted.base_source_hash,
                    "policy_fingerprint": "policy-hash",
                    "authority_policy_generation": interrupted.authority_policy_generation,
                    "authority_policy_fingerprint": interrupted.authority_policy_fingerprint,
                }
            },
            handlers={
                "GENERATE_INCIDENT": lambda decision: calls.append(decision)
                or {"accepted": True, "incident_id": "incident-new"}
            },
        )

    assert calls == []
    assert store.all_recoveries() == ()
    assert store.all_recovery_lifecycle_marks() == ()


def test_recovery_plan_marks_process_local_pending_approval_stale() -> None:
    store = InMemoryRepairStore()
    interrupted = _attempt(
        target_id="app:charge",
        completed=False,
        outcome=RepairAttemptOutcome.AWAITING_APPROVAL,
    )
    store.record_attempt(interrupted)
    store.episodes[interrupted.episode_id] = SimpleNamespace(
        episode_id=interrupted.episode_id,
        created_at=datetime.now(timezone.utc),
        completed_at=None,
        outcome="AWAITING_APPROVAL",
    )

    plan = build_repair_recovery_plan(store)

    decision = plan["decisions"][0]
    assert decision["approval_state"] == "STALE_AFTER_RESTART"
    assert decision["approval_survives_restart"] is False
    approval = next(
        item for item in decision["incomplete_records"]
        if item["record_type"] == "approval"
    )
    assert approval["state"] == "STALE_AFTER_RESTART"
    assert "new transaction" in approval["reason"]

    applied = apply_repair_recovery_plan(store, plan)
    assert applied["applied_count"] == 1
    assert any(
        item["record_type"] == "approval"
        and item["state"] == "STALE_AFTER_RESTART"
        for item in store.all_recoveries()[0].incomplete_records
    )
    approval_marks = [
        mark for mark in store.all_recovery_lifecycle_marks()
        if mark.record_type == "approval"
    ]
    assert len(approval_marks) == 1
    assert approval_marks[0].state == "STALE_AFTER_RESTART"


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
    assert plan["policy"]["worker_acceptance"]["probation_successful_executions"] == 1000
    assert plan["policy"]["worker_acceptance"]["acceptance_successful_executions"] == 1000

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


def test_recovery_action_selection_is_explicit_and_disabled_policy_fails_safe() -> None:
    planned = select_recovery_action(RecoveryAction.REPLACE_WORKER, enabled=True)
    assert planned["selected_action"] == "REPLACE_WORKER"
    assert planned["status"] == "PLANNED_ONLY"
    assert planned["requires_application_orchestration"] is True
    assert planned["authority_granted"] is False

    disabled = select_recovery_action(RecoveryAction.STOP_APPLICATION, enabled=False)
    assert disabled["selected_action"] is None
    assert disabled["status"] == "DISABLED_BY_POLICY"
    assert disabled["runtime_fallback"] == "ROLLBACK_TO_DEPLOYED_CODE"


def test_recovery_action_dispatch_requires_application_callback_acknowledgement() -> None:
    decision = {
        "policy_action": {
            "requested_action": "GENERATE_INCIDENT",
            "selected_action": "GENERATE_INCIDENT",
            "policy_enabled": True,
        },
    }
    missing = dispatch_recovery_action(decision)
    assert missing["status"] == "NOT_CONFIGURED"
    assert missing["authority_granted"] is False

    rejected = dispatch_recovery_action(
        decision,
        handlers={"GENERATE_INCIDENT": lambda _decision: {"accepted": False}},
    )
    assert rejected["status"] == "REJECTED_BY_HANDLER"

    received = []
    executed = dispatch_recovery_action(
        decision,
        handlers={
            "GENERATE_INCIDENT": lambda current: received.append(current) or {
                "accepted": True,
                "incident_id": "incident-1",
            }
        },
    )
    assert executed["status"] == "EXECUTED"
    assert executed["authority_granted"] is False
    assert received == [decision]


def test_deployed_code_rollback_dispatch_requires_explicit_application_gate() -> None:
    decision = {
        "target_id": "app:charge",
        "policy_action": {
            "requested_action": "ROLLBACK_TO_DEPLOYED_CODE",
            "selected_action": "ROLLBACK_TO_DEPLOYED_CODE",
            "policy_enabled": True,
        },
    }

    rejected = dispatch_recovery_action(
        decision,
        handlers={
            "ROLLBACK_TO_DEPLOYED_CODE": lambda _decision: {"accepted": True},
        },
    )
    assert rejected["status"] == "REJECTED_BY_HANDLER"
    assert rejected["authority_granted"] is False
    assert rejected["required_gates"] == ["rollback_applied"]

    executed = dispatch_recovery_action(
        decision,
        handlers={
            "ROLLBACK_TO_DEPLOYED_CODE": lambda _decision: {
                "accepted": True,
                "rollback_applied": True,
                "deployed_code_hash": "deployed-hash",
            },
        },
    )
    assert executed["status"] == "EXECUTED"
    assert executed["authority_granted"] is False
    assert executed["handler_result"]["deployed_code_hash"] == "deployed-hash"


def test_degraded_continuation_dispatch_requires_explicit_application_gate() -> None:
    decision = {
        "target_id": "app:charge",
        "policy_action": {
            "requested_action": "CONTINUE_DEGRADED",
            "selected_action": "CONTINUE_DEGRADED",
            "policy_enabled": True,
        },
    }

    rejected = dispatch_recovery_action(
        decision,
        handlers={
            "CONTINUE_DEGRADED": lambda _decision: {"accepted": True},
        },
    )
    assert rejected["status"] == "REJECTED_BY_HANDLER"
    assert rejected["required_gates"] == ["degraded_continuation"]

    executed = dispatch_recovery_action(
        decision,
        handlers={
            "CONTINUE_DEGRADED": lambda _decision: {
                "accepted": True,
                "degraded_continuation": True,
                "boundary": "application-callback",
            },
        },
    )
    assert executed["status"] == "EXECUTED"
    assert executed["authority_granted"] is False


def test_replacement_dispatch_requires_verified_packet_and_acceptance_state() -> None:
    decision = {
        "policy_action": {
            "requested_action": "REPLACE_WORKER",
            "selected_action": "REPLACE_WORKER",
            "policy_enabled": True,
        },
    }

    rejected = dispatch_recovery_action(
        decision,
        handlers={"REPLACE_WORKER": lambda _decision: {"accepted": True}},
    )
    assert rejected["status"] == "REJECTED_BY_HANDLER"
    assert "authority_packet_verified" in rejected["required_gates"]
    assert "acceptance_state:PROBATION_OR_ACCEPTED" in rejected["required_gates"]

    accepted = dispatch_recovery_action(
        decision,
        handlers={
            "REPLACE_WORKER": lambda _decision: {
                "accepted": True,
                "failed_worker_id": "worker-old",
                "replacement_worker_id": "worker-new",
                "authority_packet_id": "packet-1",
                "authority_packet_verified": True,
                "authority_packet_expires_at": "2030-01-01T00:00:00+00:00",
                "acceptance_state": "PROBATION",
            },
        },
    )
    assert accepted["status"] == "EXECUTED"
    assert accepted["authority_granted"] is False


def test_apply_recovery_plan_persists_callback_execution_result() -> None:
    store = InMemoryRepairStore()
    interrupted = _attempt(
        target_id="app:charge",
        completed=False,
        outcome=RepairAttemptOutcome.PENDING,
    )
    store.record_attempt(interrupted)
    plan = build_repair_recovery_plan(
        store,
        policy=RepairRecoveryPolicy(
            interrupted_transaction_action=RecoveryAction.GENERATE_INCIDENT,
        ),
    )
    seen = []

    applied = apply_repair_recovery_plan(
        store,
        plan,
        handlers={
            "GENERATE_INCIDENT": lambda decision: seen.append(decision["attempt_id"])
            or {
                "accepted": True,
                "incident_id": "incident-1",
                "incident_recorded": True,
            },
        },
    )

    assert applied["action_results"][0]["status"] == "EXECUTED"
    assert seen == [str(interrupted.attempt_id)]
    assert store.all_recoveries()[0].action_execution["status"] == "EXECUTED"


def test_worker_acceptance_uses_defaults_and_target_override_without_granting_authority() -> None:
    policy = WorkerAcceptancePolicy(
        per_target_overrides={
            "app:fast": WorkerAcceptanceOverride(
                probation_successful_executions=2,
                probation_failure_budget=1,
                acceptance_successful_executions=5,
                acceptance_failure_budget=1,
            )
        }
    )

    probation = evaluate_worker_acceptance(
        target_id="app:fast",
        successful_executions=2,
        failed_executions=1,
        policy=policy,
    )
    assert probation["probation_complete"] is True
    assert probation["accepted"] is False
    assert probation["uses_target_override"] is True
    assert probation["authority_granted"] is False

    accepted = evaluate_worker_acceptance(
        target_id="app:fast",
        successful_executions=5,
        failed_executions=1,
        policy=policy,
    )
    assert accepted["accepted"] is True
    assert accepted["thresholds"]["acceptance_successful_executions"] == 5

    default_target = evaluate_worker_acceptance(
        target_id="app:ordinary",
        successful_executions=999,
        failed_executions=0,
        policy=policy,
    )
    assert default_target["probation_complete"] is False
    assert default_target["uses_target_override"] is False


def test_worker_acceptance_rejects_invalid_override_ordering() -> None:
    policy = WorkerAcceptancePolicy(
        per_target_overrides={
            "app:invalid": WorkerAcceptanceOverride(
                probation_successful_executions=10,
                acceptance_successful_executions=9,
            )
        }
    )
    with pytest.raises(ValueError, match="lowers acceptance below probation"):
        evaluate_worker_acceptance(
            target_id="app:invalid",
            successful_executions=10,
            failed_executions=0,
            policy=policy,
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
