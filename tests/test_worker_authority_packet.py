from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from caretaker import create_recovery_authority_packet
from caretaker.logging import WorkerKind, WorkerRegistry, WorkerState


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
    )
    assert replacement.authority_packet_id == packet.packet_id
    assert replacement.replaced_worker_id == original.worker_id
    assert replacement.state is WorkerState.STARTING

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
