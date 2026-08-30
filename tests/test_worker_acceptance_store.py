from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest

from caretaker import (
    RepairRecoveryPolicy,
    WorkerAcceptancePolicy,
    WorkerAcceptanceStore,
    WorkerAcceptanceStoreError,
    create_recovery_authority_packet,
)
from caretaker.logging import WorkerAcceptanceState, WorkerKind, WorkerRegistry


def _context() -> dict[str, str]:
    return {
        "target_id": "app:charge",
        "generation_id": "generation-7",
        "code_hash": "code-hash",
        "policy_fingerprint": "policy-hash",
    }


def test_store_is_idempotent_and_rejects_conflicting_observation_reuse(tmp_path) -> None:
    store = WorkerAcceptanceStore(tmp_path / "worker-acceptance.sqlite")
    context = _context()

    first = store.record(
        **context,
        observation_id="observation-1",
        worker_id="worker-1",
        success=True,
    )
    duplicate = store.record(
        **context,
        observation_id="observation-1",
        worker_id="worker-1",
        success=True,
    )
    assert first["observation_count"] == 1
    assert duplicate["duplicate"] is True
    assert duplicate["successful_executions"] == 1

    with pytest.raises(WorkerAcceptanceStoreError, match="different worker evidence"):
        store.record(
            **context,
            observation_id="observation-1",
            worker_id="worker-2",
            success=False,
        )

    second = store.record(
        **context,
        observation_id="observation-2",
        worker_id="worker-2",
        success=False,
    )
    assert second["observation_count"] == 2
    assert second["successful_executions"] == 1
    assert second["failed_executions"] == 1
    assert store.load(**context)["content_sha256"] == second["content_sha256"]


def test_registry_restores_only_exact_acceptance_context_after_restart(tmp_path) -> None:
    store = WorkerAcceptanceStore(tmp_path / "worker-acceptance.sqlite")
    supervisor_time = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    context = _context()
    packet = create_recovery_authority_packet(
        **context,
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        capabilities=("observe",),
        supervisor_time=supervisor_time,
    )
    recovery_policy = RepairRecoveryPolicy(
        worker_acceptance=WorkerAcceptancePolicy(
            probation_successful_executions=2,
            acceptance_successful_executions=3,
        )
    )

    first_registry = WorkerRegistry(acceptance_store=store)
    first = first_registry.register_authorized(
        WorkerKind.REPAIR_ANALYZER,
        1234,
        packet,
        supervisor_time=supervisor_time,
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
        policy=recovery_policy,
        **context,
    )
    first_registry.record_acceptance_observation(
        first.worker_id,
        success=True,
        observation_id="observation-1",
        policy=recovery_policy.worker_acceptance,
    )

    restarted_registry = WorkerRegistry(acceptance_store=store)
    restarted = restarted_registry.register_authorized(
        WorkerKind.REPAIR_ANALYZER,
        5678,
        packet,
        supervisor_time=supervisor_time,
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
        policy=recovery_policy,
        **context,
    )
    assert restarted.acceptance_successful_executions == 1
    assert restarted.acceptance_failed_executions == 0
    assert restarted.acceptance_state is WorkerAcceptanceState.PROBATION

    different_context = dict(context, code_hash="new-code-hash")
    different_packet = create_recovery_authority_packet(
        **different_context,
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        capabilities=("observe",),
        supervisor_time=supervisor_time,
    )
    different = restarted_registry.register_authorized(
        WorkerKind.REPAIR_ANALYZER,
        6789,
        different_packet,
        supervisor_time=supervisor_time,
        authority_policy_generation="authority-8",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
        policy=recovery_policy,
        **different_context,
    )
    assert different.acceptance_successful_executions == 0
    assert different.acceptance_state is WorkerAcceptanceState.PROBATION


def test_store_rejects_tampered_checkpoint(tmp_path) -> None:
    path = tmp_path / "worker-acceptance.sqlite"
    store = WorkerAcceptanceStore(path)
    store.record(
        **_context(),
        observation_id="observation-1",
        worker_id="worker-1",
        success=True,
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE worker_acceptance_progress SET content_sha256 = ?",
            ("tampered",),
        )

    with pytest.raises(WorkerAcceptanceStoreError, match="checkpoint hash is invalid"):
        WorkerAcceptanceStore(path).load(**_context())
