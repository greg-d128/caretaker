from __future__ import annotations

from caretaker.logging import (
    CaretakerApplicationSupervisor,
    WorkerFailureAction,
    WorkerKind,
    WorkerRestartPolicy,
)
from caretaker import InMemoryRepairStore, SQLiteRepairStore


class FakeRuntime:
    def __init__(self) -> None:
        self.events = []

    def event(self, **kwargs):
        self.events.append(kwargs)


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
