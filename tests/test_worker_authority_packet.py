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
