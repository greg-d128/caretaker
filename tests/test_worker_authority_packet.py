from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from caretaker import (
    create_recovery_authority_packet,
    deserialize_recovery_authority_packet,
    serialize_recovery_authority_packet,
    verify_recovery_authority_packet,
)
from caretaker import WorkerAcceptancePolicy
from caretaker.logging import WorkerAcceptanceState, WorkerKind, WorkerRegistry, WorkerState
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
