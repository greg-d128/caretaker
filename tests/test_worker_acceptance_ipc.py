from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone

import pytest

from caretaker import (
    RepairRecoveryPolicy,
    WorkerAcceptancePolicy,
    WorkerAcceptanceStore,
    create_recovery_authority_packet,
)
from caretaker.logging import (
    CaretakerApplicationSupervisor,
    ControlSocketServer,
    WorkerAcceptanceState,
    WorkerKind,
    submit_worker_acceptance_observation,
)


def _registered_supervisor(tmp_path):
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    context = {
        "target_id": "app:charge",
        "generation_id": "generation-7",
        "code_hash": "code-hash",
        "policy_fingerprint": "policy-hash",
    }
    recovery_policy = RepairRecoveryPolicy(
        worker_acceptance=WorkerAcceptancePolicy(
            probation_successful_executions=1,
            acceptance_successful_executions=2,
        )
    )
    packet = create_recovery_authority_packet(
        **context,
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        capabilities=("observe",),
        supervisor_time=supervisor_time,
    )
    supervisor = CaretakerApplicationSupervisor(
        object(),
        acceptance_store=WorkerAcceptanceStore(tmp_path / "worker-acceptance.sqlite"),
    )
    worker = supervisor.workers.register_authorized(
        WorkerKind.REPAIR_ANALYZER,
        os.getpid(),
        packet,
        supervisor_time=supervisor_time,
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
        policy=recovery_policy,
        **context,
    )
    return supervisor, worker


def _request(worker, *, observation_id: str = "observation-1", **overrides):
    request = {
        "worker_id": str(worker.worker_id),
        "process_start_id": str(worker.process_start_id),
        "authority_packet_id": str(worker.authority_packet_id),
        "observation_id": observation_id,
        "success": True,
    }
    request.update(overrides)
    return request


def test_worker_acceptance_observation_binds_to_registered_process_and_packet(tmp_path) -> None:
    supervisor, worker = _registered_supervisor(tmp_path)
    credentials = (os.getpid(), os.getuid(), os.getgid())
    supervisor.workers.heartbeat(worker.worker_id)

    result = supervisor.handle_worker_acceptance_observation(
        _request(
            worker,
            target_id="attacker-target",
            generation_id="attacker-generation",
            code_hash="attacker-code",
            policy_fingerprint="attacker-policy",
        ),
        credentials,
    )

    assert result["ok"] is True
    assert result["target_id"] == "app:charge"
    assert result["acceptance_state"] == WorkerAcceptanceState.PROBATION.name
    assert result["acceptance_successful_executions"] == 1
    assert result["authority_granted"] is False

    for field, value, message in (
        ("credentials", (os.getpid() + 1, os.getuid(), os.getgid()), "process identity"),
        ("process_start_id", "stale-process", "process start identity"),
        ("authority_packet_id", "stale-packet", "authority packet identity"),
    ):
        request = _request(worker)
        actual_credentials = credentials
        if field == "credentials":
            actual_credentials = value
        else:
            request[field] = value
        with pytest.raises(PermissionError, match=message):
            supervisor.handle_worker_acceptance_observation(request, actual_credentials)


def test_worker_acceptance_observation_uses_control_socket(tmp_path) -> None:
    supervisor, worker = _registered_supervisor(tmp_path)
    socket_path = tmp_path / "supervisor.sock"
    server = ControlSocketServer(
        socket_path,
        supervisor.handle_worker_acceptance_observation,
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
        response = submit_worker_acceptance_observation(
            socket_path,
            worker_id=worker.worker_id,
            process_start_id=worker.process_start_id,
            authority_packet_id=worker.authority_packet_id,
            observation_id="socket-observation-1",
            success=True,
        )
        assert response["ok"] is True
        assert response["acceptance_successful_executions"] == 1
    finally:
        server.stop()
        thread.join(timeout=2)
