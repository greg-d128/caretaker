from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from caretaker import (
    IsolatedReplayCoordinator,
    RegressionFixturePolicy,
    RegressionFixtureStore,
    ReplayExecutionError,
    ReplayExecutionResult,
    ValidationIsolationLevel,
)
from caretaker.validation import ValidationBackendCapabilities


SOURCE = "def charge(value):\n    return value + 1\n"


def _store(tmp_path: Path) -> tuple[RegressionFixtureStore, str]:
    policy = RegressionFixturePolicy(enabled=True, replay_enabled=True)
    store = RegressionFixtureStore(tmp_path, policy=policy)
    envelope = store.record(
        target_id="app:charge",
        name="case",
        args=(1,),
        kwargs={},
        expected=2,
        incident_id=None,
        candidate_id=None,
        source_function_version=2,
        source_function_hash=hashlib.sha256(SOURCE.encode()).hexdigest(),
        replay_safety="PURE",
    )
    assert envelope is not None
    return store, envelope["fixture_id"]


class FakeVMReplayBackend:
    def __init__(self) -> None:
        self.requests = []

    def capabilities(self) -> ValidationBackendCapabilities:
        return ValidationBackendCapabilities(
            name="fake-vm",
            isolation_level=ValidationIsolationLevel.VM,
            separate_kernel=True,
            ephemeral_workspace=True,
        )

    def available(self) -> tuple[bool, str | None]:
        return True, None

    def execute(self, request):
        self.requests.append(request)
        return ReplayExecutionResult(
            fixture_id=request.fixture_id,
            target_id=request.target_id,
            outcome="PASSED",
            backend_name="fake-vm",
            isolation_level=ValidationIsolationLevel.VM,
            output=2,
        )


def test_replay_requires_explicit_policy_and_matching_source(tmp_path: Path) -> None:
    store, fixture_id = _store(tmp_path)
    disabled = IsolatedReplayCoordinator(
        store,
        policy=RegressionFixturePolicy(enabled=True, replay_enabled=False),
    )
    with pytest.raises(ReplayExecutionError, match="disabled"):
        disabled.prepare(fixture_id, entrypoint="charge", source=SOURCE)

    enabled = IsolatedReplayCoordinator(
        store,
        policy=RegressionFixturePolicy(enabled=True, replay_enabled=True),
    )
    with pytest.raises(ReplayExecutionError, match="source hash"):
        enabled.prepare(fixture_id, entrypoint="charge", source=SOURCE + "\n")


def test_replay_rejects_process_backend_and_dispatches_only_to_isolated_backend(tmp_path: Path) -> None:
    store, fixture_id = _store(tmp_path)
    coordinator = IsolatedReplayCoordinator(
        store,
        policy=RegressionFixturePolicy(enabled=True, replay_enabled=True),
    )

    class ProcessBackend(FakeVMReplayBackend):
        def capabilities(self):
            return ValidationBackendCapabilities(
                name="process",
                isolation_level=ValidationIsolationLevel.PROCESS,
            )

    with pytest.raises(ReplayExecutionError, match="requires at least VM"):
        coordinator.execute(
            fixture_id,
            entrypoint="charge",
            source=SOURCE,
            backend=ProcessBackend(),
        )

    backend = FakeVMReplayBackend()
    result = coordinator.execute(
        fixture_id,
        entrypoint="charge",
        source=SOURCE,
        backend=backend,
    )
    assert result.outcome == "PASSED"
    assert backend.requests[0].fixture["replay_status"] == "DATA_ONLY_NOT_EXECUTABLE"
    assert backend.requests[0].fixture["args"] == [1]
    assert backend.requests[0].historical_source_hash != ""
    assert backend.requests[0].subject_source_hash == hashlib.sha256(SOURCE.encode()).hexdigest()


def test_replay_rejects_backend_result_identity_mismatch(tmp_path: Path) -> None:
    store, fixture_id = _store(tmp_path)
    coordinator = IsolatedReplayCoordinator(
        store,
        policy=RegressionFixturePolicy(enabled=True, replay_enabled=True),
    )
    backend = FakeVMReplayBackend()
    backend.execute = lambda request: ReplayExecutionResult(
        fixture_id="wrong",
        target_id=request.target_id,
        outcome="PASSED",
        backend_name="fake-vm",
        isolation_level=ValidationIsolationLevel.VM,
    )
    with pytest.raises(ReplayExecutionError, match="identity"):
        coordinator.execute(
            fixture_id,
            entrypoint="charge",
            source=SOURCE,
            backend=backend,
        )
