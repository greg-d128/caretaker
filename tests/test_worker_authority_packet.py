from __future__ import annotations

import json
import os
import queue
import threading
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from caretaker import (
    create_recovery_authority_packet,
    deserialize_recovery_authority_packet,
    deserialize_worker_replacement_request,
    QueueWorkerAuthorityPacketTransport,
    QueueWorkerReplacementRequestTransport,
    serialize_recovery_authority_packet,
    serialize_worker_replacement_request,
    verify_recovery_authority_packet,
)
from caretaker import WorkerAcceptancePolicy
from caretaker.logging import (
    ControlSocketServer,
    WorkerAcceptanceState,
    WorkerKind,
    WorkerRegistry,
    WorkerState,
    submit_worker_authority_packet,
    submit_worker_replacement_request,
)
import caretaker.logging.supervisor as supervisor_module


def _packet(*, supervisor_time: datetime):
    return create_recovery_authority_packet(
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        capabilities=("observe",),
        supervisor_time=supervisor_time,
    )


def test_authority_packet_transport_round_trip_still_requires_live_context() -> None:
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    packet = _packet(supervisor_time=supervisor_time)

    encoded = serialize_recovery_authority_packet(packet)
    decoded = deserialize_recovery_authority_packet(encoded)

    assert decoded == packet
    verification = verify_recovery_authority_packet(
        decoded,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )
    assert verification["valid"] is True
    assert verification["authority_granted_by_packet"] is False


def test_authority_packet_transport_rejects_tampering_and_non_json_state() -> None:
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    packet = _packet(supervisor_time=supervisor_time)
    envelope = json.loads(serialize_recovery_authority_packet(packet))
    envelope["packet"]["target_id"] = "app:other"

    with pytest.raises(ValueError, match="content hash is invalid"):
        deserialize_recovery_authority_packet(envelope)

    non_json = create_recovery_authority_packet(
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        policy_state={"not_json": object()},
        supervisor_time=supervisor_time,
    )
    with pytest.raises(ValueError, match="JSON transport data"):
        serialize_recovery_authority_packet(non_json)


def test_authority_packet_transport_is_bounded() -> None:
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    packet = create_recovery_authority_packet(
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        policy_state={"large": "x" * 70_000},
        supervisor_time=supervisor_time,
    )

    with pytest.raises(ValueError, match="exceeds 65536 bytes"):
        serialize_recovery_authority_packet(packet)


def test_queue_worker_authority_transport_round_trips_without_admitting_worker() -> None:
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    packet = _packet(supervisor_time=supervisor_time)
    transport = QueueWorkerAuthorityPacketTransport(queue.Queue())

    delivery = transport.send(
        packet,
        operation="register",
        handoff_id=uuid4(),
        worker_kind=WorkerKind.REPAIR_ANALYZER.name,
    )
    handoff = transport.receive()

    assert delivery["message_type"] == "worker-authority-packet"
    assert handoff is not None
    assert handoff["packet"] == packet
    assert handoff["worker_kind"] == WorkerKind.REPAIR_ANALYZER.name
    assert handoff["transport_sender_pid"] == os.getpid()
    assert "worker_id" not in handoff


def test_queue_worker_replacement_transport_round_trips_request() -> None:
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    registry = WorkerRegistry()
    original = registry.register(WorkerKind.REPAIR_ANALYZER, 4321)
    registry.mark_failed(original.worker_id, error_fingerprint="worker-crash")
    packet = _packet(supervisor_time=supervisor_time)
    request = registry.prepare_replacement(
        original.worker_id,
        packet,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )
    transport = QueueWorkerReplacementRequestTransport(queue.Queue())

    delivery = transport.send(request)
    handoff = transport.receive()

    assert delivery["message_type"] == "worker-replacement-request"
    assert handoff is not None
    assert handoff["request"] == request
    assert handoff["request"].failed_worker_id == original.worker_id
    assert handoff["transport_sender_pid"] == os.getpid()


def test_supervisor_admits_authority_queue_handoff_with_application_bound_pid() -> None:
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    supervisor = supervisor_module.CaretakerApplicationSupervisor(object())
    packet = _packet(supervisor_time=supervisor_time)
    transport = QueueWorkerAuthorityPacketTransport(queue.Queue())
    transport.send(
        packet,
        operation="register",
        handoff_id=uuid4(),
        worker_kind=WorkerKind.REPAIR_ANALYZER.name,
    )
    handoff = transport.receive()
    assert handoff is not None
    handoff["transport_sender_pid"] = os.getpid() + 1

    response = supervisor.handle_worker_authority_queue_handoff(
        handoff,
        authoritative_worker_pid=4321,
        allowed_worker_kinds={WorkerKind.REPAIR_ANALYZER},
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )

    assert response["ok"] is True
    assert response["process_id"] == 4321
    assert response["authoritative_worker_pid"] == 4321
    assert response["transport_sender_pid"] == os.getpid() + 1
    worker = supervisor.workers.get(UUID(response["worker_id"]))
    assert worker.process_id == 4321
    assert worker.authority_packet_id == packet.packet_id

    refreshed_time = supervisor_time + timedelta(seconds=60)
    refreshed_packet = create_recovery_authority_packet(
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-9",
        authority_policy_fingerprint="authority-hash-new",
        capabilities=("observe",),
        supervisor_time=refreshed_time,
    )
    transport.send(
        refreshed_packet,
        operation="refresh",
        handoff_id=uuid4(),
        worker_kind=WorkerKind.REPAIR_ANALYZER.name,
        worker_id=worker.worker_id,
        process_start_id=worker.process_start_id,
    )
    refresh_handoff = transport.receive()
    assert refresh_handoff is not None
    refresh_response = supervisor.handle_worker_authority_queue_handoff(
        refresh_handoff,
        authoritative_worker_pid=4321,
        allowed_worker_kinds={WorkerKind.REPAIR_ANALYZER},
        supervisor_time=refreshed_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-9",
        authority_policy_fingerprint="authority-hash-new",
        allowed_capabilities={"observe"},
    )

    assert refresh_response["ok"] is True
    assert refresh_response["operation"] == "refresh"
    assert refresh_response["worker_id"] == str(worker.worker_id)
    assert supervisor.workers.get(worker.worker_id).authority_packet_id == refreshed_packet.packet_id


def test_supervisor_admits_replacement_queue_handoff_with_application_bound_pid() -> None:
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    supervisor = supervisor_module.CaretakerApplicationSupervisor(object())
    original = supervisor.workers.register(WorkerKind.REPAIR_ANALYZER, 4321)
    supervisor.workers.mark_failed(original.worker_id, error_fingerprint="worker-crash")
    request = supervisor.workers.prepare_replacement(
        original.worker_id,
        _packet(supervisor_time=supervisor_time),
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )
    transport = QueueWorkerReplacementRequestTransport(queue.Queue())
    transport.send(request)
    handoff = transport.receive()
    assert handoff is not None
    handoff["transport_sender_pid"] = os.getpid() + 1

    response = supervisor.handle_worker_replacement_queue_handoff(
        handoff,
        authoritative_worker_pid=8765,
        allowed_worker_kinds={WorkerKind.REPAIR_ANALYZER},
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )

    assert response["ok"] is True
    assert response["process_id"] == 8765
    assert response["authoritative_worker_pid"] == 8765
    assert response["transport_sender_pid"] == os.getpid() + 1
    replacement = supervisor.workers.get(UUID(response["worker_id"]))
    assert replacement.process_id == 8765
    assert replacement.replaced_worker_id == original.worker_id

    with pytest.raises(PermissionError, match="already been consumed"):
        supervisor.handle_worker_replacement_queue_handoff(
            handoff,
            authoritative_worker_pid=9999,
            allowed_worker_kinds={WorkerKind.REPAIR_ANALYZER},
            supervisor_time=supervisor_time,
            target_id="app:charge",
            generation_id="generation-7",
            code_hash="code-hash",
            policy_fingerprint="policy-hash",
            authority_policy_generation="authority-8",
            authority_policy_fingerprint="authority-hash",
            allowed_capabilities={"observe"},
        )


def test_transported_authority_admission_binds_peer_and_rejects_replay() -> None:
    registry = WorkerRegistry()
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    packet = _packet(supervisor_time=supervisor_time)
    handoff_id = uuid4()

    worker = registry.register_transported_authorized(
        WorkerKind.REPAIR_ANALYZER,
        4321,
        serialize_recovery_authority_packet(packet),
        handoff_id=handoff_id,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )
    assert worker.process_id == 4321
    assert worker.authority_packet_id == packet.packet_id

    with pytest.raises(PermissionError, match="already been consumed"):
        registry.register_transported_authorized(
            WorkerKind.REPAIR_ANALYZER,
            9876,
            serialize_recovery_authority_packet(packet),
            handoff_id=handoff_id,
            supervisor_time=supervisor_time,
            target_id="app:charge",
            generation_id="generation-7",
            code_hash="code-hash",
            policy_fingerprint="policy-hash",
            authority_policy_generation="authority-8",
            authority_policy_fingerprint="authority-hash",
            allowed_capabilities={"observe"},
        )


def test_local_authority_packet_socket_binds_peer_and_refreshes_identity(tmp_path) -> None:
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    supervisor = supervisor_module.CaretakerApplicationSupervisor(object())
    socket_path = tmp_path / "supervisor.sock"
    context = {
        "target_id": "app:charge",
        "generation_id": "generation-7",
        "code_hash": "code-hash",
        "policy_fingerprint": "policy-hash",
        "authority_policy_generation": "authority-8",
        "authority_policy_fingerprint": "authority-hash",
        "allowed_capabilities": {"observe"},
    }

    def handler(request, credentials):
        return supervisor.handle_worker_authority_packet(
            request,
            credentials,
            allowed_worker_kinds={WorkerKind.REPAIR_ANALYZER},
            supervisor_time=supervisor_time,
            **context,
        )

    server = ControlSocketServer(
        socket_path,
        handler,
        allowed_uids={os.getuid()},
    )
    server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for _ in range(50):
            if socket_path.exists():
                break
            time.sleep(0.01)
        packet = _packet(supervisor_time=supervisor_time)
        response = submit_worker_authority_packet(
            socket_path,
            packet=packet,
            handoff_id=uuid4(),
            worker_kind=WorkerKind.REPAIR_ANALYZER.name,
        )
        assert response["ok"] is True
        assert response["process_id"] == os.getpid()
        worker = supervisor.workers.get(UUID(response["worker_id"]))
        assert response["process_start_id"] == str(worker.process_start_id)

        refreshed_time = supervisor_time + timedelta(seconds=60)
        refreshed_packet = create_recovery_authority_packet(
            target_id="app:charge",
            generation_id="generation-7",
            code_hash="code-hash",
            policy_fingerprint="policy-hash",
            authority_policy_generation="authority-9",
            authority_policy_fingerprint="authority-hash-new",
            capabilities=("observe",),
            supervisor_time=refreshed_time,
        )
        supervisor_context = context.copy()
        supervisor_context.update({
            "authority_policy_generation": "authority-9",
            "authority_policy_fingerprint": "authority-hash-new",
        })
        server.handler = lambda request, credentials: supervisor.handle_worker_authority_packet(
            request,
            credentials,
            allowed_worker_kinds={WorkerKind.REPAIR_ANALYZER},
            supervisor_time=refreshed_time,
            **supervisor_context,
        )
        refresh_handoff_id = uuid4()
        refreshed = submit_worker_authority_packet(
            socket_path,
            packet=refreshed_packet,
            handoff_id=refresh_handoff_id,
            worker_kind=WorkerKind.REPAIR_ANALYZER.name,
            operation="refresh",
            worker_id=worker.worker_id,
            process_start_id=worker.process_start_id,
        )
        assert refreshed["ok"] is True
        assert refreshed["worker_id"] == str(worker.worker_id)
        assert refreshed["process_id"] == os.getpid()

        replay = submit_worker_authority_packet(
            socket_path,
            packet=refreshed_packet,
            handoff_id=refresh_handoff_id,
            worker_kind=WorkerKind.REPAIR_ANALYZER.name,
            operation="refresh",
            worker_id=worker.worker_id,
            process_start_id=worker.process_start_id,
        )
        assert replay["ok"] is False
        assert "handoff" in replay["error"]

        with pytest.raises(PermissionError, match="process identity"):
            supervisor.handle_worker_authority_packet(
                {
                    "command": "worker-authority-packet",
                    "operation": "refresh",
                    "handoff_id": str(uuid4()),
                    "worker_kind": WorkerKind.REPAIR_ANALYZER.name,
                    "worker_id": str(worker.worker_id),
                    "process_start_id": str(worker.process_start_id),
                    "packet": json.loads(serialize_recovery_authority_packet(refreshed_packet)),
                },
                (os.getpid() + 1, os.getuid(), os.getgid()),
                allowed_worker_kinds={WorkerKind.REPAIR_ANALYZER},
                supervisor_time=refreshed_time,
                **supervisor_context,
            )
    finally:
        server.stop()
        thread.join(timeout=2)


def test_replacement_request_transport_round_trip_and_tamper_rejection() -> None:
    registry = WorkerRegistry()
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    original = registry.register(WorkerKind.REPAIR_ANALYZER, 1234)
    registry.mark_failed(original.worker_id, error_fingerprint="worker-crash")
    request = registry.prepare_replacement(
        original.worker_id,
        _packet(supervisor_time=supervisor_time),
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
        reason="replace after crash",
    )

    encoded = serialize_worker_replacement_request(request)
    assert deserialize_worker_replacement_request(encoded) == request
    envelope = json.loads(encoded)
    envelope["request"]["reason"] = "tampered"
    with pytest.raises(ValueError, match="content hash is invalid"):
        deserialize_worker_replacement_request(envelope)


def test_local_replacement_packet_socket_is_single_use_and_peer_bound(tmp_path) -> None:
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    supervisor = supervisor_module.CaretakerApplicationSupervisor(object())
    original = supervisor.workers.register(WorkerKind.REPAIR_ANALYZER, os.getpid())
    supervisor.workers.mark_failed(original.worker_id, error_fingerprint="worker-crash")
    request = supervisor.workers.prepare_replacement(
        original.worker_id,
        _packet(supervisor_time=supervisor_time),
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )
    socket_path = tmp_path / "supervisor.sock"
    context = {
        "target_id": "app:charge",
        "generation_id": "generation-7",
        "code_hash": "code-hash",
        "policy_fingerprint": "policy-hash",
        "authority_policy_generation": "authority-8",
        "authority_policy_fingerprint": "authority-hash",
        "allowed_capabilities": {"observe"},
    }
    server = ControlSocketServer(
        socket_path,
        lambda request, credentials: supervisor.handle_worker_replacement_packet(
            request,
            credentials,
            allowed_worker_kinds={WorkerKind.REPAIR_ANALYZER},
            supervisor_time=supervisor_time,
            **context,
        ),
        allowed_uids={os.getuid()},
    )
    server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for _ in range(50):
            if socket_path.exists():
                break
            time.sleep(0.01)
        response = submit_worker_replacement_request(socket_path, request=request)
        assert response["ok"] is True
        assert response["process_id"] == os.getpid()
        assert response["replaced_worker_id"] == str(original.worker_id)

        replay = submit_worker_replacement_request(socket_path, request=request)
        assert replay["ok"] is False
        assert "consumed" in replay["error"]
    finally:
        server.stop()
        thread.join(timeout=2)


def test_worker_registry_requires_exact_authority_packet_context() -> None:
    registry = WorkerRegistry()
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    packet = _packet(supervisor_time=supervisor_time)

    worker = registry.register_authorized(
        WorkerKind.REPAIR_ANALYZER,
        1234,
        packet,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )
    assert worker.authority_packet_id == packet.packet_id
    assert worker.authority_packet_expires_at == packet.expires_at

    with pytest.raises(PermissionError, match="CONTEXT_MISMATCH:generation_id"):
        registry.register_authorized(
            WorkerKind.REPAIR_ANALYZER,
            5678,
            packet,
            supervisor_time=supervisor_time,
            target_id="app:charge",
            generation_id="generation-8",
            code_hash="code-hash",
            policy_fingerprint="policy-hash",
            authority_policy_generation="authority-8",
            authority_policy_fingerprint="authority-hash",
            allowed_capabilities={"observe"},
        )
    assert len(registry.all()) == 1


def test_worker_authority_lifecycle_emits_bounded_audit_events() -> None:
    events = []
    registry = WorkerRegistry(
        audit_event=lambda event_type, **fields: events.append(
            {"event_type": event_type, **fields}
        )
    )
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    packet = _packet(supervisor_time=supervisor_time)
    worker = registry.register_authorized(
        WorkerKind.REPAIR_ANALYZER,
        1234,
        packet,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )
    refresh_time = supervisor_time + timedelta(seconds=60)
    refreshed_packet = create_recovery_authority_packet(
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-9",
        authority_policy_fingerprint="authority-hash-new",
        capabilities=("observe",),
        supervisor_time=refresh_time,
    )
    registry.refresh_authorized(
        worker.worker_id,
        refreshed_packet,
        supervisor_time=refresh_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-9",
        authority_policy_fingerprint="authority-hash-new",
        allowed_capabilities={"observe"},
    )
    registry.heartbeat(worker.worker_id, supervisor_time=refreshed_packet.expires_at)

    assert [event["event_type"] for event in events] == [
        "WORKER_AUTHORITY_ISSUED",
        "WORKER_AUTHORITY_REFRESHED",
        "WORKER_AUTHORITY_EXPIRED",
    ]
    assert events[0]["outcome"]["state"] == "ISSUED"
    assert events[1]["details"]["prior_authority_packet_id"] == str(packet.packet_id)
    assert events[2]["outcome"]["state"] == "EXPIRED"
    assert "capabilities" not in events[0]["details"]


def test_expired_worker_becomes_unauthorized_and_restart_clears_packet() -> None:
    registry = WorkerRegistry()
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    packet = _packet(supervisor_time=supervisor_time)
    worker = registry.register_authorized(
        WorkerKind.REPAIR_ANALYZER,
        1234,
        packet,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )

    expired = registry.heartbeat(
        worker.worker_id,
        supervisor_time=packet.expires_at,
    )
    assert expired.state is WorkerState.UNAUTHORIZED
    assert expired.last_error_fingerprint == "authority-expired"
    assert worker.worker_id in {item.worker_id for item in registry.unhealthy()}

    restarted = registry.record_restart(worker.worker_id, pid=5678)
    assert restarted.state is WorkerState.STARTING
    assert restarted.authority_packet_id is None
    assert restarted.authority_packet_expires_at is None


def test_supervisor_cycle_reconciles_silent_worker_authority_expiry_once() -> None:
    events = []
    registry = WorkerRegistry(audit_event=lambda event_type, **fields: events.append((event_type, fields)))
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    packet = _packet(supervisor_time=supervisor_time)
    worker = registry.register_authorized(
        WorkerKind.REPAIR_ANALYZER,
        1234,
        packet,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )

    expired = registry.reconcile_authority_expiry(packet.expires_at)
    repeated = registry.reconcile_authority_expiry(packet.expires_at)

    assert [item.worker_id for item in expired] == [worker.worker_id]
    assert expired[0].state is WorkerState.UNAUTHORIZED
    assert repeated == ()
    assert [event_type for event_type, _ in events] == [
        "WORKER_AUTHORITY_ISSUED",
        "WORKER_AUTHORITY_EXPIRED",
    ]


def test_supervisor_cycle_rejects_naive_authority_expiry_time() -> None:
    registry = WorkerRegistry()

    with pytest.raises(ValueError, match="timezone-aware"):
        registry.reconcile_authority_expiry(datetime(2026, 8, 30, 12, 0))


def test_supervisor_control_cycle_invokes_application_hook_with_authoritative_time() -> None:
    supervisor = supervisor_module.CaretakerApplicationSupervisor(object())
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    observed = []

    result = supervisor.run_control_cycle(
        supervisor_time=supervisor_time,
        on_cycle=lambda current_time: observed.append(current_time) or {"drained": 2},
    )

    assert result["ok"] is True
    assert result["authority_granted"] is False
    assert result["supervisor_time"] == supervisor_time.isoformat()
    assert observed == [supervisor_time]
    assert result["cycle_callback"] == {
        "status": "COMPLETED",
        "result": {"drained": 2},
        "authority_granted": False,
    }


def test_supervisor_control_cycle_retains_callback_failure_as_bounded_evidence() -> None:
    supervisor = supervisor_module.CaretakerApplicationSupervisor(object())
    result = supervisor.run_control_cycle(
        supervisor_time=datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc),
        on_cycle=lambda _current_time: (_ for _ in ()).throw(RuntimeError("cycle failed")),
    )

    assert result["ok"] is False
    assert result["cycle_callback"]["status"] == "FAILED"
    assert result["cycle_callback"]["error"] == "RuntimeError: cycle failed"
    assert result["cycle_callback"]["authority_granted"] is False


def test_live_worker_can_refresh_packet_without_resetting_acceptance_state() -> None:
    registry = WorkerRegistry()
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    acceptance_policy = WorkerAcceptancePolicy(
        probation_successful_executions=2,
        acceptance_successful_executions=3,
    )
    packet = _packet(supervisor_time=supervisor_time)
    worker = registry.register_authorized(
        WorkerKind.REPAIR_ANALYZER,
        1234,
        packet,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
        acceptance_policy=acceptance_policy,
    )
    worker = registry.record_acceptance_observation(
        worker.worker_id,
        success=True,
        policy=acceptance_policy,
    )
    before_refresh = worker
    refresh_time = supervisor_time + timedelta(seconds=60)
    refreshed_packet = create_recovery_authority_packet(
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-9",
        authority_policy_fingerprint="authority-hash-new",
        capabilities=("observe",),
        supervisor_time=refresh_time,
    )

    refreshed = registry.refresh_authorized(
        worker.worker_id,
        refreshed_packet,
        supervisor_time=refresh_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-9",
        authority_policy_fingerprint="authority-hash-new",
        allowed_capabilities={"observe"},
    )

    assert refreshed.worker_id == before_refresh.worker_id
    assert refreshed.process_id == before_refresh.process_id
    assert refreshed.process_start_id == before_refresh.process_start_id
    assert refreshed.authority_packet_id == refreshed_packet.packet_id
    assert refreshed.authority_packet_expires_at == refreshed_packet.expires_at
    assert refreshed.acceptance_state is before_refresh.acceptance_state
    assert refreshed.acceptance_successful_executions == 1
    assert refreshed.acceptance_failed_executions == 0


def test_packet_refresh_rejects_expired_or_failed_worker() -> None:
    registry = WorkerRegistry()
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    packet = _packet(supervisor_time=supervisor_time)
    worker = registry.register_authorized(
        WorkerKind.REPAIR_ANALYZER,
        1234,
        packet,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )
    replacement_packet = _packet(
        supervisor_time=supervisor_time + timedelta(seconds=1),
    )

    with pytest.raises(PermissionError, match="expired; re-admission"):
        registry.refresh_authorized(
            worker.worker_id,
            replacement_packet,
            supervisor_time=packet.expires_at,
            target_id="app:charge",
            generation_id="generation-7",
            code_hash="code-hash",
            policy_fingerprint="policy-hash",
            authority_policy_generation="authority-8",
            authority_policy_fingerprint="authority-hash",
            allowed_capabilities={"observe"},
        )

    registry.mark_failed(worker.worker_id, error_fingerprint="worker-crash")
    with pytest.raises(PermissionError, match="live authorized worker"):
        registry.refresh_authorized(
            worker.worker_id,
            replacement_packet,
            supervisor_time=supervisor_time + timedelta(seconds=1),
            target_id="app:charge",
            generation_id="generation-7",
            code_hash="code-hash",
            policy_fingerprint="policy-hash",
            authority_policy_generation="authority-8",
            authority_policy_fingerprint="authority-hash",
            allowed_capabilities={"observe"},
        )


def test_stale_packet_refresh_cannot_overwrite_newer_refresh(monkeypatch) -> None:
    registry = WorkerRegistry()
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    packet = _packet(supervisor_time=supervisor_time)
    worker = registry.register_authorized(
        WorkerKind.REPAIR_ANALYZER,
        1234,
        packet,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )
    newer_time = supervisor_time + timedelta(seconds=60)
    newer_packet = create_recovery_authority_packet(
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-9",
        authority_policy_fingerprint="authority-hash-new",
        capabilities=("observe",),
        supervisor_time=newer_time,
    )
    stale_time = supervisor_time + timedelta(seconds=30)
    stale_packet = create_recovery_authority_packet(
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        capabilities=("observe",),
        supervisor_time=stale_time,
    )
    original_verify = supervisor_module.verify_recovery_authority_packet
    refreshed = False

    def verify_and_refresh(candidate, **kwargs):
        nonlocal refreshed
        if candidate.packet_id == stale_packet.packet_id and not refreshed:
            refreshed = True
            registry.refresh_authorized(
                worker.worker_id,
                newer_packet,
                supervisor_time=newer_time,
                target_id="app:charge",
                generation_id="generation-7",
                code_hash="code-hash",
                policy_fingerprint="policy-hash",
                authority_policy_generation="authority-9",
                authority_policy_fingerprint="authority-hash-new",
                allowed_capabilities={"observe"},
            )
        return original_verify(candidate, **kwargs)

    monkeypatch.setattr(
        supervisor_module,
        "verify_recovery_authority_packet",
        verify_and_refresh,
    )
    with pytest.raises(PermissionError, match="changed during refresh"):
        registry.refresh_authorized(
            worker.worker_id,
            stale_packet,
            supervisor_time=stale_time,
            target_id="app:charge",
            generation_id="generation-7",
            code_hash="code-hash",
            policy_fingerprint="policy-hash",
            authority_policy_generation="authority-8",
            authority_policy_fingerprint="authority-hash",
            allowed_capabilities={"observe"},
        )
    assert registry.get(worker.worker_id).authority_packet_id == newer_packet.packet_id


def test_replacement_handoff_requires_packet_and_records_provenance() -> None:
    registry = WorkerRegistry()
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    original = registry.register(WorkerKind.REPAIR_ANALYZER, 1234)
    registry.mark_failed(original.worker_id, error_fingerprint="worker-crash")
    packet = _packet(supervisor_time=supervisor_time)

    request = registry.prepare_replacement(
        original.worker_id,
        packet,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
        reason="replace after crash" + ("!" * 400),
    )
    assert request.summary()["failed_worker_id"] == str(original.worker_id)
    assert len(request.reason) == 256

    replacement = registry.register_replacement(
        request,
        WorkerKind.REPAIR_ANALYZER,
        5678,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
        acceptance_policy=WorkerAcceptancePolicy(
            probation_successful_executions=2,
            acceptance_successful_executions=3,
        ),
    )
    assert replacement.authority_packet_id == packet.packet_id
    assert replacement.replaced_worker_id == original.worker_id
    assert replacement.state is WorkerState.STARTING
    assert replacement.target_id == "app:charge"
    assert replacement.acceptance_state is WorkerAcceptanceState.PROBATION

    replacement = registry.record_acceptance_observation(
        replacement.worker_id,
        success=True,
        policy=WorkerAcceptancePolicy(
            probation_successful_executions=2,
            acceptance_successful_executions=3,
        ),
    )
    replacement = registry.record_acceptance_observation(
        replacement.worker_id,
        success=True,
        policy=WorkerAcceptancePolicy(
            probation_successful_executions=2,
            acceptance_successful_executions=3,
        ),
    )
    assert replacement.acceptance_state is WorkerAcceptanceState.PROBATION
    replacement = registry.record_acceptance_observation(
        replacement.worker_id,
        success=True,
        policy=WorkerAcceptancePolicy(
            probation_successful_executions=2,
            acceptance_successful_executions=3,
        ),
    )
    assert replacement.acceptance_state is WorkerAcceptanceState.ACCEPTED
    assert replacement.acceptance_successful_executions == 3

    with pytest.raises(PermissionError, match="already been consumed"):
        registry.register_replacement(
            request,
            WorkerKind.REPAIR_ANALYZER,
            5679,
            supervisor_time=supervisor_time,
            target_id="app:charge",
            generation_id="generation-7",
            code_hash="code-hash",
            policy_fingerprint="policy-hash",
            authority_policy_generation="authority-8",
            authority_policy_fingerprint="authority-hash",
            allowed_capabilities={"observe"},
        )


def test_replacement_handoff_rejects_expired_packet_without_registering_worker() -> None:
    registry = WorkerRegistry()
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    original = registry.register(WorkerKind.REPAIR_ANALYZER, 1234)
    registry.mark_failed(original.worker_id, error_fingerprint="worker-crash")
    packet = _packet(supervisor_time=supervisor_time)
    request = registry.prepare_replacement(
        original.worker_id,
        packet,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )

    with pytest.raises(PermissionError, match="AUTHORITY_EXPIRED"):
        registry.register_replacement(
            request,
            WorkerKind.REPAIR_ANALYZER,
            5678,
            supervisor_time=packet.expires_at,
            target_id="app:charge",
            generation_id="generation-7",
            code_hash="code-hash",
            policy_fingerprint="policy-hash",
            authority_policy_generation="authority-8",
            authority_policy_fingerprint="authority-hash",
            allowed_capabilities={"observe"},
        )
    assert len(registry.all()) == 1


def test_worker_acceptance_budget_failure_marks_worker_failed() -> None:
    registry = WorkerRegistry()
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    original = registry.register(WorkerKind.REPAIR_ANALYZER, 1234)
    registry.mark_failed(original.worker_id, error_fingerprint="worker-crash")
    packet = _packet(supervisor_time=supervisor_time)
    request = registry.prepare_replacement(
        original.worker_id,
        packet,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )
    replacement = registry.register_replacement(
        request,
        WorkerKind.REPAIR_ANALYZER,
        5678,
        supervisor_time=supervisor_time,
        target_id="app:charge",
        generation_id="generation-7",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
        acceptance_policy=WorkerAcceptancePolicy(
            probation_successful_executions=2,
            acceptance_successful_executions=2,
            probation_failure_budget=0,
        ),
    )

    failed = registry.record_acceptance_observation(
        replacement.worker_id,
        success=False,
        policy=WorkerAcceptancePolicy(
            probation_successful_executions=2,
            acceptance_successful_executions=2,
            probation_failure_budget=0,
        ),
    )
    assert failed.acceptance_state is WorkerAcceptanceState.FAILED
    assert failed.state is WorkerState.FAILED
    assert failed.last_error_fingerprint == "worker-acceptance-failed"
    assert failed.authority_packet_id == packet.packet_id

    with pytest.raises(PermissionError, match="failed or unauthorized"):
        registry.record_acceptance_observation(
            replacement.worker_id,
            success=True,
            policy=WorkerAcceptancePolicy(
                probation_successful_executions=2,
                acceptance_successful_executions=2,
            ),
        )
