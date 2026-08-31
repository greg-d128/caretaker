from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from caretaker.logging import (
    CaretakerApplicationSupervisor,
    WorkerFailureAction,
    WorkerKind,
    WorkerRestartPolicy,
)
from caretaker import (
    InMemoryRepairStore,
    SQLiteRepairStore,
    RecoveryAction,
    RepairRecoveryPolicy,
    WorkerFailureRecoveryRecord,
    WorkerAcceptancePolicy,
    create_recovery_authority_packet,
    dispatch_recovery_action,
    create_worker_failure_record,
    create_worker_postmortem_packet,
    reconcile_worker_failure_records,
    reconcile_worker_postmortems,
    resolve_worker_failure_scope,
    worker_failure_recovery_status,
    verify_worker_postmortem_packet,
)


class FakeRuntime:
    def __init__(self) -> None:
        self.events = []
        self.audit = FakeAudit()

    def event(self, **kwargs):
        self.events.append(kwargs)

    def close(self):
        self.closed = True


class FakeAudit:
    def __init__(self) -> None:
        self.events = []

    def emit(self, event_type, **kwargs):
        self.events.append({"event_type": event_type, **kwargs})


def test_supervisor_lifecycle_emits_start_and_stop_audit_events() -> None:
    runtime = FakeRuntime()
    supervisor = CaretakerApplicationSupervisor(runtime)

    supervisor.start()
    supervisor.stop()

    assert [item["event_type"] for item in runtime.audit.events] == [
        "SUPERVISOR_STATE_CHANGED",
        "SUPERVISOR_STATE_CHANGED",
    ]
    assert runtime.audit.events[0]["outcome"]["state"] == "STARTED"
    assert runtime.audit.events[1]["outcome"]["state"] == "STOPPED"
    assert runtime.audit.events[0]["scope"]["worker_id"] == str(
        supervisor.supervisor_health.worker_id
    )


def test_worker_failure_records_incident_and_uses_callback_owned_restart() -> None:
    runtime = FakeRuntime()
    supervisor = CaretakerApplicationSupervisor(runtime)
    worker = supervisor.workers.register(WorkerKind.REPAIR_ANALYZER, 1234)
    failed = supervisor.workers.mark_failed(
        worker.worker_id,
        error_fingerprint="worker-crash",
    )
    incidents = []

    result = supervisor.handle_worker_failure(
        failed,
        policy=WorkerRestartPolicy(maximum_restarts=1),
        create_incident=lambda envelope: incidents.append(dict(envelope)),
        restart_worker=lambda current: {
            "started": True,
            "pid": 5678,
            "backoff_seconds": 0.5,
        },
    )

    assert result["action"] == "RESTARTED"
    assert result["incident_status"] == "RECORDED"
    assert incidents[0]["transaction_state"] == "ROLLED_BACK"
    assert incidents[0]["current_work_ids"] == []
    current = next(
        item for item in supervisor.workers.all() if item.worker_id == worker.worker_id
    )
    assert current.process_id == 5678
    assert current.restart_count == 1
    assert current.state.name == "STARTING"
    assert current.authority_packet_id is None
    assert result["restart"]["backoff_seconds"] == 0.5
    assert [item["event_type"] for item in runtime.audit.events] == [
        "WORKER_FAILED",
        "INCIDENT_CAPTURED",
        "WORKER_REPLACEMENT_REQUESTED",
        "WORKER_REPLACED",
    ]
    assert runtime.audit.events[0]["outcome"]["state"] == "ROLLED_BACK"
    assert runtime.audit.events[1]["outcome"]["state"] == "RECORDED"
    assert runtime.audit.events[2]["outcome"]["state"] == "REQUESTED"
    assert runtime.audit.events[3]["outcome"]["state"] == "RESTARTED"


def test_worker_failure_scope_uses_transaction_or_incident_and_does_not_use_target_alone() -> None:
    assert resolve_worker_failure_scope({"transaction_id": "txn-7"}) == "transaction:txn-7"
    assert resolve_worker_failure_scope({"incident_id": "incident-7"}) == "incident:incident-7"
    first = resolve_worker_failure_scope(
        {"worker_id": "worker-1", "target_id": "app:charge"},
        failure_id="failure-1",
    )
    second = resolve_worker_failure_scope(
        {"worker_id": "worker-2", "target_id": "app:charge"},
        failure_id="failure-2",
    )
    assert first == "worker-failure:failure-1"
    assert second == "worker-failure:failure-2"
    assert first != second


def test_worker_failure_incident_capsule_is_created_immediately_and_policy_bound(tmp_path) -> None:
    from caretaker.capsule import IncidentCapsulePolicy, IncidentCapsuleStore
    from caretaker.run import create_worker_failure_incident_capsule

    store = IncidentCapsuleStore(tmp_path / "enabled")
    result = create_worker_failure_incident_capsule(
        store,
        {
            "worker_id": "worker-1",
            "worker_kind": "SYSTEM_COLLECTOR",
            "transaction_state": "ROLLED_BACK",
            "detail_level": "STANDARD",
        },
        run_id=uuid4(),
        policy_fingerprint="policy-hash",
        authority_policy_generation=7,
        authority_policy_fingerprint="authority-hash",
    )

    assert result["accepted"] is True
    assert result["incident_recorded"] is True
    loaded = store.load(result["capsule_id"])
    assert loaded["capsule"]["incident_id"] == result["incident_id"]
    assert loaded["capsule"]["incident_state"]["transaction_state"] == "ROLLED_BACK"
    assert loaded["capsule"]["incident_state"]["worker_failure"]["worker_id"] == "worker-1"
    assert loaded["integrity"]["content_sha256"] == result["capsule_integrity"]

    disabled = IncidentCapsuleStore(
        tmp_path / "disabled",
        policy=IncidentCapsulePolicy(enabled=False),
    )
    with pytest.raises(ValueError, match="disabled by policy"):
        create_worker_failure_incident_capsule(disabled, {"worker_id": "worker-1"})


def test_worker_failure_applies_exhaustion_action_and_preserves_failure_evidence() -> None:
    runtime = FakeRuntime()
    supervisor = CaretakerApplicationSupervisor(runtime)
    worker = supervisor.workers.register(WorkerKind.WRITER, 1234)
    failed = supervisor.workers.mark_failed(
        worker.worker_id,
        error_fingerprint="writer-stopped",
    )
    disabled = []

    result = supervisor.handle_worker_failure(
        failed,
        policy=WorkerRestartPolicy(
            enabled=False,
            exhaustion_action=WorkerFailureAction.DISABLE_COMPONENT,
        ),
        create_incident=lambda envelope: None,
        disable_component=lambda current: disabled.append(current.worker_id),
    )

    assert result["action"] == "DISABLE_COMPONENT"
    assert disabled == [worker.worker_id]
    assert result["failure_envelope"]["last_error_fingerprint"] == "writer-stopped"
    assert result["failure_envelope"]["transaction_state"] == "ROLLED_BACK"
    assert runtime.events[-1]["fields"]["action"] == "DISABLE_COMPONENT"


def test_worker_failure_stop_action_is_selected_when_restart_is_exhausted() -> None:
    runtime = FakeRuntime()
    supervisor = CaretakerApplicationSupervisor(runtime)
    worker = supervisor.workers.register(WorkerKind.EVENT_SERVER, 1234)
    failed = supervisor.workers.mark_failed(worker.worker_id, error_fingerprint="event-stopped")

    result = supervisor.handle_worker_failure(
        failed,
        policy=WorkerRestartPolicy(
            enabled=False,
            exhaustion_action=WorkerFailureAction.STOP_APPLICATION,
        ),
    )

    assert result["action"] == "STOP_APPLICATION"
    assert result["action_result"]["boundary"] == "none"
    assert result["incident_status"] == "NOT_CONFIGURED"


def test_worker_failure_envelope_keeps_diagnostic_context_opt_in_and_bounded() -> None:
    runtime = FakeRuntime()
    supervisor = CaretakerApplicationSupervisor(runtime)
    worker = supervisor.workers.register(WorkerKind.REPAIR_ANALYZER, 1234)
    supervisor.workers.heartbeat(
        worker.worker_id,
        current_work_ids=(),
        queue_depth=3,
        diagnostic_context={
            "milestone": "VALIDATION",
            "partial_queue": ["item-1", "item-2"],
            "policy_state": {"repair": "reviewed"},
            "nested": {"a": {"b": {"c": {"d": "too deep"}}}},
            "large": "x" * 1000,
        },
    )
    failed = supervisor.workers.mark_failed(worker.worker_id, error_fingerprint="worker-crash")

    standard = supervisor.worker_failure_envelope(failed, diagnostic_debug=False)
    assert standard["detail_level"] == "STANDARD"
    assert "diagnostic_context" not in standard

    diagnostic = supervisor.worker_failure_envelope(failed, diagnostic_debug=True)
    assert diagnostic["detail_level"] == "DIAGNOSTIC"
    assert diagnostic["diagnostic_context"]["milestone"] == "VALIDATION"
    assert diagnostic["diagnostic_context"]["partial_queue"] == ["item-1", "item-2"]
    assert diagnostic["diagnostic_context"]["nested"]["a"]["b"]["c"] == "<depth-limit>"
    assert len(diagnostic["diagnostic_context"]["large"]) == 512


def test_worker_failure_envelope_uses_diagnostic_debug_environment(monkeypatch) -> None:
    runtime = FakeRuntime()
    supervisor = CaretakerApplicationSupervisor(runtime)
    worker = supervisor.workers.register(WorkerKind.REPAIR_ANALYZER, 1234)
    worker = supervisor.workers.mark_failed(
        worker.worker_id,
        diagnostic_context={"milestone": "ACTIVATION"},
    )

    monkeypatch.setenv("CARETAKER_DIAGNOSTIC_DEBUG", "1")
    envelope = supervisor.worker_failure_envelope(worker)

    assert envelope["detail_level"] == "DIAGNOSTIC"
    assert envelope["diagnostic_context"] == {"milestone": "ACTIVATION"}


def test_worker_failure_is_persisted_before_recovery_action_is_selected() -> None:
    runtime = FakeRuntime()
    store = InMemoryRepairStore()
    supervisor = CaretakerApplicationSupervisor(runtime, failure_store=store)
    worker = supervisor.workers.register(WorkerKind.REPAIR_ANALYZER, 1234)
    failed = supervisor.workers.mark_failed(worker.worker_id, error_fingerprint="worker-crash")

    result = supervisor.handle_worker_failure(
        failed,
        policy=WorkerRestartPolicy(enabled=False),
    )

    assert result["failure_persistence_status"] == "PERSISTED"
    records = store.all_worker_failures()
    assert len(records) == 1
    assert records[0].worker_id == str(worker.worker_id)
    assert records[0].transaction_state == "ROLLED_BACK"
    assert records[0].envelope["last_error_fingerprint"] == "worker-crash"


def test_sqlite_worker_failure_record_survives_store_reopen(tmp_path) -> None:
    path = tmp_path / "worker-failures.sqlite"
    first = SQLiteRepairStore(path)
    supervisor = CaretakerApplicationSupervisor(FakeRuntime(), failure_store=first)
    worker = supervisor.workers.register(WorkerKind.WRITER, 1234)
    failed = supervisor.workers.mark_failed(worker.worker_id, error_fingerprint="writer-stopped")

    result = supervisor.handle_worker_failure(
        failed,
        policy=WorkerRestartPolicy(enabled=False),
        diagnostic_debug=True,
    )

    assert result["failure_persistence_status"] == "PERSISTED"
    reopened = SQLiteRepairStore(path)
    records = reopened.all_worker_failures()
    assert len(records) == 1
    assert records[0]["worker_id"] == str(worker.worker_id)
    assert records[0]["detail_level"] == "DIAGNOSTIC"
    assert records[0]["envelope"]["transaction_state"] == "ROLLED_BACK"


def test_critical_worker_failure_requires_and_persists_complete_postmortem() -> None:
    runtime = FakeRuntime()
    store = InMemoryRepairStore()
    supervisor = CaretakerApplicationSupervisor(runtime, failure_store=store)
    worker = supervisor.workers.register(WorkerKind.REPAIR_ANALYZER, 1234)
    failed = supervisor.workers.mark_failed(worker.worker_id, error_fingerprint="worker-crash")
    evidence = {
        "milestone": "VALIDATION",
        "partial_queue": ["work-1", "work-2"],
        "policy_state": {"repair": "reviewed"},
    }

    result = supervisor.handle_worker_failure(
        failed,
        policy=WorkerRestartPolicy(enabled=False),
        critical_evidence=True,
        collect_postmortem=lambda current, envelope: {
            **evidence,
            "worker_id": str(current.worker_id),
            "transaction_state": envelope["transaction_state"],
        },
        require_complete_postmortem=True,
    )

    assert result["postmortem_status"] == "COMPLETE"
    record = store.all_worker_failures()[0]
    assert record.critical_evidence is True
    assert record.postmortem_status == "COMPLETE"
    assert record.postmortem_packet["evidence"]["partial_queue"] == ["work-1", "work-2"]
    assert record.postmortem_packet["content_sha256"]
    assert verify_worker_postmortem_packet(
        record.postmortem_packet,
        envelope=record.envelope,
    )["valid"] is True

    tampered = dict(record.postmortem_packet)
    tampered["evidence"] = {**tampered["evidence"], "policy_state": {"repair": "changed"}}
    assert verify_worker_postmortem_packet(tampered)["failures"] == [
        "PACKET_CONTENT_HASH_MISMATCH"
    ]


def test_critical_worker_failure_retains_incomplete_postmortem_status() -> None:
    envelope = {
        "worker_id": "worker-1",
        "worker_kind": "REPAIR_ANALYZER",
        "transaction_state": "ROLLED_BACK",
        "detail_level": "STANDARD",
    }
    record = create_worker_failure_record(
        envelope,
        critical_evidence=True,
        require_complete_postmortem=True,
    )

    assert record.postmortem_status == "INCOMPLETE"
    assert record.postmortem_packet == {}
    assert "complete worker post-mortem" in record.postmortem_errors[0]

    with pytest.raises(ValueError, match="missing required fields"):
        create_worker_postmortem_packet(
            envelope,
            evidence={"milestone": "VALIDATION"},
        )
    with pytest.raises(ValueError, match="ROLLED_BACK"):
        create_worker_postmortem_packet(
            {**envelope, "transaction_state": "ACTIVE"},
            evidence={
                "milestone": "VALIDATION",
                "partial_queue": [],
                "policy_state": {},
            },
        )


def test_worker_postmortem_reconciliation_deduplicates_and_combines_compatible_streams() -> None:
    observed_at = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)

    def record(worker_id: str, mean: float):
        return create_worker_failure_record(
            {
                "worker_id": worker_id,
                "worker_kind": "REPAIR_ANALYZER",
                "transaction_state": "ROLLED_BACK",
                "detail_level": "DIAGNOSTIC",
            },
            observed_at=observed_at,
            postmortem_evidence={
                "milestone": "VALIDATION",
                "partial_queue": [],
                "policy_state": {"repair": "reviewed"},
                "behavior_signature": {
                    "sample_count": 100,
                    "metrics": {
                        "duration_ms": {"mean": mean, "standard_deviation": 1.0},
                    },
                },
            },
        )

    first = record("worker-1", 10.0)
    second = record("worker-2", 10.2)
    result = reconcile_worker_postmortems(
        [first, first, second],
        scope="incident-1",
    )

    assert result["complete_record_count"] == 3
    assert result["unique_packet_count"] == 2
    assert result["duplicate_count"] == 1
    assert result["comparison"]["status"] == "COMBINED"
    assert result["comparison"]["metrics"]["duration_ms"]["sample_count"] == 200
    assert result["conflict"] is False


def test_worker_postmortem_reconciliation_retains_divergence_in_sqlite_conflict_report(tmp_path) -> None:
    def record(worker_id: str, mean: float):
        return create_worker_failure_record(
            {
                "worker_id": worker_id,
                "worker_kind": "REPAIR_ANALYZER",
                "transaction_state": "ROLLED_BACK",
                "detail_level": "DIAGNOSTIC",
            },
            postmortem_evidence={
                "milestone": "VALIDATION",
                "partial_queue": [worker_id],
                "policy_state": {"repair": "reviewed"},
                "behavior_signature": {
                    "sample_count": 100,
                    "metrics": {
                        "duration_ms": {"mean": mean, "standard_deviation": 1.0},
                    },
                },
            },
        )

    store = SQLiteRepairStore(tmp_path / "repair.sqlite")
    first = record("worker-1", 10.0)
    second = record("worker-2", 20.0)
    result = reconcile_worker_postmortems(
        [first, second],
        scope="incident-2",
        store=store,
    )

    assert result["comparison"]["status"] == "RETAINED_NOT_COMBINED"
    assert result["conflict"] is True
    assert len(result["conflict_report"].packets) == 2
    reports = store.all_worker_postmortem_conflicts()
    assert len(reports) == 1
    assert reports[0]["scope"] == "incident-2"
    assert len(reports[0]["packets"]) == 2
    assert reports[0]["reason"].startswith("worker post-mortem behavior signatures")
    repeated = reconcile_worker_postmortems(
        [first, second],
        scope="incident-2",
        store=store,
    )
    assert repeated["conflict_report"].report_id == result["conflict_report"].report_id
    assert len(store.all_worker_postmortem_conflicts()) == 1
    reopened = SQLiteRepairStore(tmp_path / "repair.sqlite")
    assert len(reopened.all_worker_postmortem_conflicts()) == 1


def test_worker_postmortem_reconciliation_never_combines_different_targets() -> None:
    def record(worker_id: str, target_id: str):
        return create_worker_failure_record(
            {
                "worker_id": worker_id,
                "worker_kind": "REPAIR_ANALYZER",
                "target_id": target_id,
                "transaction_id": "txn-mixed-targets",
                "transaction_state": "ROLLED_BACK",
            },
            postmortem_evidence={
                "milestone": "VALIDATION",
                "partial_queue": [],
                "policy_state": {},
                "behavior_signature": {
                    "sample_count": 100,
                    "metrics": {
                        "duration_ms": {"mean": 10.0, "standard_deviation": 1.0},
                    },
                },
            },
        )

    result = reconcile_worker_postmortems(
        [record("worker-1", "app:charge"), record("worker-2", "app:refund")],
        scope="transaction:txn-mixed-targets",
    )

    assert result["comparison"]["status"] == "RETAINED_NOT_COMBINED"
    assert result["conflict"] is True
    assert result["conflict_report"].reason.startswith(
        "worker post-mortem records have different"
    )


def test_worker_failure_reconciliation_groups_persisted_records_and_retains_incomplete_evidence() -> None:
    store = InMemoryRepairStore()
    complete = create_worker_failure_record(
        {
            "worker_id": "worker-1",
            "worker_kind": "REPAIR_ANALYZER",
            "transaction_id": "txn-1",
            "transaction_state": "ROLLED_BACK",
        },
        postmortem_evidence={
            "milestone": "VALIDATION",
            "partial_queue": [],
            "policy_state": {},
        },
    )
    incomplete = create_worker_failure_record(
        {
            "worker_id": "worker-2",
            "worker_kind": "REPAIR_ANALYZER",
            "transaction_id": "txn-1",
            "transaction_state": "ROLLED_BACK",
        },
        critical_evidence=True,
        require_complete_postmortem=True,
    )
    unrelated = create_worker_failure_record(
        {
            "worker_id": "worker-3",
            "worker_kind": "REPAIR_ANALYZER",
            "target_id": "app:charge",
            "transaction_state": "ROLLED_BACK",
        },
    )
    for record in (complete, incomplete, unrelated):
        store.record_worker_failure(record)

    result = reconcile_worker_failure_records(store)

    assert result["group_count"] == 2
    assert result["record_count"] == 3
    transaction = next(
        item for item in result["reconciliations"] if item["scope"] == "transaction:txn-1"
    )
    assert transaction["input_count"] == 2
    assert transaction["comparison"]["status"] == "INCOMPLETE_EVIDENCE"
    assert transaction["conflict"] is True
    assert transaction["conflict_report"].incomplete_records[0]["record_id"] == str(
        incomplete.failure_id
    )
    assert len(store.all_worker_postmortem_conflicts()) == 1

    filtered = reconcile_worker_failure_records(store, scope="transaction:txn-1")
    assert filtered["group_count"] == 1
    assert filtered["record_count"] == 2


def test_supervisor_reconciliation_selects_critical_action_and_requires_handler_ack() -> None:
    runtime = FakeRuntime()
    store = InMemoryRepairStore()
    supervisor = CaretakerApplicationSupervisor(runtime, failure_store=store)
    record = create_worker_failure_record(
        {
            "worker_id": "worker-critical",
            "worker_kind": "REPAIR_ANALYZER",
            "transaction_id": "txn-critical",
            "transaction_state": "ROLLED_BACK",
        },
        critical_evidence=True,
        require_complete_postmortem=True,
    )
    store.record_worker_failure(record)

    calls = []
    result = supervisor.reconcile_worker_failures(
        recovery_policy=RepairRecoveryPolicy(
            worker_failure_action=RecoveryAction.CONTINUE_DEGRADED,
            critical_evidence_action=RecoveryAction.GENERATE_INCIDENT,
        ),
        recovery_handlers={
            "GENERATE_INCIDENT": lambda decision: calls.append(decision["scope"]) or {
                "accepted": True,
                "incident_id": f"incident-for-{decision['scope']}",
            },
        },
    )

    decision = result["recovery_decisions"][0]
    assert decision["critical_evidence_conflict"] is True
    assert decision["policy_action"]["selected_action"] == "GENERATE_INCIDENT"
    assert decision["action_execution"]["status"] == "EXECUTED"
    assert decision["authority_granted"] is False
    assert len(store.all_worker_failure_recoveries()) == 1
    assert calls == ["transaction:txn-critical"]

    repeated = supervisor.reconcile_worker_failures(
        recovery_policy=RepairRecoveryPolicy(
            worker_failure_action=RecoveryAction.CONTINUE_DEGRADED,
            critical_evidence_action=RecoveryAction.GENERATE_INCIDENT,
        ),
        recovery_handlers={
            "GENERATE_INCIDENT": lambda _decision: calls.append("unexpected") or {
                "accepted": True,
                "incident_id": "unexpected",
            },
        },
    )
    assert repeated["recovery_decisions"][0]["action_execution"]["status"] == "EXECUTED"
    assert calls == ["transaction:txn-critical"]


def test_worker_failure_recovery_checkpoint_survives_sqlite_reopen(tmp_path) -> None:
    store = SQLiteRepairStore(tmp_path / "repair.sqlite")
    record = create_worker_failure_record(
        {
            "worker_id": "worker-sqlite",
            "worker_kind": "WRITER",
            "incident_id": "incident-sqlite",
            "transaction_state": "ROLLED_BACK",
        },
        critical_evidence=True,
        require_complete_postmortem=True,
    )
    store.record_worker_failure(record)
    supervisor = CaretakerApplicationSupervisor(FakeRuntime(), failure_store=store)
    calls = []

    result = supervisor.reconcile_worker_failures(
        recovery_policy=RepairRecoveryPolicy(
            critical_evidence_action=RecoveryAction.GENERATE_INCIDENT,
        ),
        recovery_handlers={
            "GENERATE_INCIDENT": lambda _decision: calls.append("called") or {
                "accepted": True,
                "incident_id": "incident-sqlite-recovery",
            },
        },
    )

    assert result["recovery_decisions"][0]["action_execution"]["status"] == "EXECUTED"
    assert calls == ["called"]
    reopened = SQLiteRepairStore(tmp_path / "repair.sqlite")
    persisted = reopened.all_worker_failure_recoveries()
    assert len(persisted) == 1
    assert persisted[0]["action"] == "GENERATE_INCIDENT"
    assert persisted[0]["action_execution"]["handler_result"]["incident_id"] == (
        "incident-sqlite-recovery"
    )


def test_worker_failure_recovery_status_is_bounded_and_read_only() -> None:
    store = InMemoryRepairStore()
    failure = create_worker_failure_record(
        {
            "worker_id": "worker-status",
            "worker_kind": "WRITER",
            "target_id": "app:status",
            "transaction_id": "txn-status",
            "transaction_state": "ROLLED_BACK",
            "sensitive_diagnostic": "must not cross the summary boundary",
        },
        critical_evidence=True,
        postmortem_error="post-mortem collection was incomplete",
        require_complete_postmortem=True,
    )
    store.record_worker_failure(failure)
    recovery = WorkerFailureRecoveryRecord(
        recovery_id=uuid4(),
        scope="transaction:txn-status",
        target_id="app:status",
        observed_at=failure.observed_at,
        action="GENERATE_INCIDENT",
        critical_evidence_conflict=True,
        policy_action={
            "selected_action": "GENERATE_INCIDENT",
            "status": "PLANNED_ONLY",
            "requires_application_orchestration": True,
        },
        reconciliation_summary={
            "input_count": 1,
            "comparison_status": "INCOMPLETE_EVIDENCE",
        },
        action_execution={"status": "PENDING", "accepted": False},
    )
    store.record_worker_failure_recovery(recovery)
    status = worker_failure_recovery_status(store)

    assert status["read_only"] is True
    assert status["authority_granted"] is False
    assert status["bounded"] is True
    assert status["failure_count"] == 1
    assert status["recovery_count"] == 1
    assert status["failures"][0]["worker_id"] == "worker-status"
    assert status["failures"][0]["postmortem_status"] == "INCOMPLETE"
    assert status["failures"][0]["postmortem_error"] == (
        "post-mortem collection was incomplete"
    )
    assert "envelope" not in status["failures"][0]
    assert "postmortem_packet" not in status["failures"][0]
    assert "sensitive_diagnostic" not in str(status)
    assert status["recoveries"][0]["action_execution"]["status"] == "PENDING"
    assert status["recoveries"][0]["policy_action"]["selected_action"] == (
        "GENERATE_INCIDENT"
    )


def test_worker_failure_recovery_status_summarizes_sqlite_conflicts(tmp_path) -> None:
    store = SQLiteRepairStore(tmp_path / "worker-status.sqlite")
    record = create_worker_failure_record(
        {
            "worker_id": "worker-conflict",
            "worker_kind": "EVENT_SERVER",
            "incident_id": "incident-status",
            "target_id": "app:status",
            "transaction_state": "ROLLED_BACK",
        },
        critical_evidence=True,
        require_complete_postmortem=True,
    )
    store.record_worker_failure(record)
    reconcile_worker_failure_records(store)

    status = worker_failure_recovery_status(store, limit=1)

    assert status["failure_count"] == 1
    assert status["conflict_count"] == 1
    assert status["conflicts"][0]["scope"] == record.reconciliation_scope
    assert status["conflicts"][0]["incomplete_records"][0]["record_id"] == str(
        record.failure_id
    )


def test_worker_failure_recovery_status_rejects_unbounded_limits() -> None:
    store = InMemoryRepairStore()
    with pytest.raises(ValueError, match="between 1 and 500"):
        worker_failure_recovery_status(store, limit=501)

def test_replacement_action_handler_uses_packet_admission_and_acceptance() -> None:
    runtime = FakeRuntime()
    supervisor = CaretakerApplicationSupervisor(runtime)
    original = supervisor.workers.register(WorkerKind.REPAIR_ANALYZER, 1234)
    supervisor.workers.mark_failed(original.worker_id, error_fingerprint="worker-crash")
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    packet = create_recovery_authority_packet(
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        capabilities=("observe",),
        supervisor_time=supervisor_time,
    )
    spawned = []
    handler = supervisor.build_replacement_action_handler(
        failed_worker_id=original.worker_id,
        packet=packet,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
        policy=RepairRecoveryPolicy(
            worker_acceptance=WorkerAcceptancePolicy(
                probation_successful_executions=2,
                acceptance_successful_executions=3,
            )
        ),
        acceptance_policy=WorkerAcceptancePolicy(
            probation_successful_executions=2,
            acceptance_successful_executions=3,
        ),
        spawn_worker=lambda request: spawned.append(request) or {"started": True, "pid": 5678},
    )

    result = dispatch_recovery_action(
        {
            "target_id": "app:charge",
            "policy_action": {
                "requested_action": "REPLACE_WORKER",
                "selected_action": "REPLACE_WORKER",
                "policy_enabled": True,
            },
        },
        handlers={"REPLACE_WORKER": handler},
    )

    assert result["status"] == "EXECUTED"
    assert result["handler_result"]["authority_packet_verified"] is True
    assert result["handler_result"]["acceptance_state"] == "PROBATION"
    assert len(spawned) == 1


def test_incident_action_handler_requires_application_acknowledgement() -> None:
    decision = {
        "target_id": "app:charge",
        "policy_action": {
            "requested_action": "GENERATE_INCIDENT",
            "selected_action": "GENERATE_INCIDENT",
            "policy_enabled": True,
        },
    }
    received = []
    handler = CaretakerApplicationSupervisor.build_incident_action_handler(
        lambda current: received.append(current) or {
            "accepted": True,
            "incident_id": "incident-42",
            "incident_recorded": True,
        }
    )

    result = dispatch_recovery_action(
        decision,
        handlers={"GENERATE_INCIDENT": handler},
    )

    assert result["status"] == "EXECUTED"
    assert received == [decision]
    assert result["handler_result"]["incident_id"] == "incident-42"

    rejected = CaretakerApplicationSupervisor.build_incident_action_handler(
        lambda _current: None
    )
    rejected_result = dispatch_recovery_action(
        decision,
        handlers={"GENERATE_INCIDENT": rejected},
    )
    assert rejected_result["status"] == "REJECTED_BY_HANDLER"
    assert "acknowledgement mapping" in rejected_result["handler_result"]["reason"]


def test_shutdown_action_handler_requires_application_boundary_acknowledgement() -> None:
    runtime = FakeRuntime()
    supervisor = CaretakerApplicationSupervisor(runtime)
    decision = {
        "target_id": "app:charge",
        "policy_action": {
            "requested_action": "STOP_APPLICATION",
            "selected_action": "STOP_APPLICATION",
            "policy_enabled": True,
        },
    }
    received = []
    handler = supervisor.build_shutdown_action_handler(
        lambda current: received.append(current) or {
            "accepted": True,
            "shutdown_requested": True,
            "boundary": "application-callback",
        }
    )

    result = dispatch_recovery_action(
        decision,
        handlers={"STOP_APPLICATION": handler},
    )

    assert result["status"] == "EXECUTED"
    assert received == [decision]
    assert result["handler_result"]["shutdown_requested"] is True

    no_boundary = dispatch_recovery_action(
        decision,
        handlers={"STOP_APPLICATION": supervisor.build_shutdown_action_handler()},
    )
    assert no_boundary["status"] == "REJECTED_BY_HANDLER"
    assert "no application boundary" in no_boundary["handler_result"]["reason"]


def test_replacement_action_handler_rejects_expired_packet() -> None:
    runtime = FakeRuntime()
    supervisor = CaretakerApplicationSupervisor(runtime)
    original = supervisor.workers.register(WorkerKind.REPAIR_ANALYZER, 1234)
    supervisor.workers.mark_failed(original.worker_id, error_fingerprint="worker-crash")
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    packet = create_recovery_authority_packet(
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        supervisor_time=supervisor_time,
        policy=RepairRecoveryPolicy(approval_packet_ttl_seconds=1),
    )
    handler = supervisor.build_replacement_action_handler(
        failed_worker_id=original.worker_id,
        packet=packet,
        supervisor_time=packet.expires_at,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        spawn_worker=lambda _request: {"started": True, "pid": 5678},
    )

    result = handler({"target_id": "app:charge"})

    assert result["accepted"] is False
    assert "AUTHORITY_EXPIRED" in result["reason"]
