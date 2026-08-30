from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from caretaker import (
    IncidentCapsuleStore,
    IsolatedReplayCoordinator,
    RegressionFixturePolicy,
    RegressionFixtureStore,
    ReplayExecutionError,
    ReplayExecutionResult,
    RootlessPodmanReplayBackend,
    ValidationIsolationLevel,
    execute_capsule_replay,
    execute_historical_capsule_replays,
)
from caretaker.validation import ValidationBackendCapabilities
from caretaker.replay_worker import run_payload


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


class FakeContainerReplayBackend(FakeVMReplayBackend):
    def capabilities(self):
        return ValidationBackendCapabilities(
            name="fake-container",
            isolation_level=ValidationIsolationLevel.CONTAINER,
            ephemeral_workspace=True,
        )

    def execute(self, request):
        self.requests.append(request)
        return ReplayExecutionResult(
            fixture_id=request.fixture_id,
            target_id=request.target_id,
            outcome="PASSED",
            backend_name="fake-container",
            isolation_level=ValidationIsolationLevel.CONTAINER,
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


def test_replay_registry_selects_backend_that_meets_policy(tmp_path: Path) -> None:
    store, fixture_id = _store(tmp_path)
    policy = RegressionFixturePolicy(
        enabled=True,
        replay_enabled=True,
        replay_minimum_isolation=ValidationIsolationLevel.CONTAINER,
    )
    container = FakeContainerReplayBackend()
    vm = FakeVMReplayBackend()
    coordinator = IsolatedReplayCoordinator(
        store,
        policy=policy,
        backends=(vm, container),
    )

    result = coordinator.execute(
        fixture_id,
        entrypoint="charge",
        source=SOURCE,
    )

    assert result.backend_name == "fake-container"
    assert len(container.requests) == 1
    assert not vm.requests


def test_replay_without_configured_backend_fails_closed(tmp_path: Path) -> None:
    store, fixture_id = _store(tmp_path)
    coordinator = IsolatedReplayCoordinator(
        store,
        policy=RegressionFixturePolicy(enabled=True, replay_enabled=True),
    )

    with pytest.raises(ReplayExecutionError, match="no replay execution backend"):
        coordinator.execute(fixture_id, entrypoint="charge", source=SOURCE)


def test_capsule_replay_requires_incident_link_and_does_not_modify_capsule(tmp_path: Path) -> None:
    regression_policy = RegressionFixturePolicy(enabled=True, replay_enabled=True)
    store = RegressionFixtureStore(tmp_path, policy=regression_policy)
    incident_id = "00000000-0000-0000-0000-000000000001"
    capsule_store = IncidentCapsuleStore(tmp_path)
    capsule_envelope = capsule_store.create_placeholder(
        incident_id,
        incident_state={"trigger": "exception"},
    )
    fixture = store.record(
        target_id="app:charge",
        name="incident-case",
        args=(1,),
        kwargs={},
        expected=2,
        incident_id=incident_id,
        candidate_id=None,
        source_function_version=2,
        source_function_hash=hashlib.sha256(SOURCE.encode()).hexdigest(),
        replay_safety="PURE",
    )
    assert fixture is not None
    coordinator = IsolatedReplayCoordinator(
        store,
        policy=regression_policy,
        backend=FakeVMReplayBackend(),
    )
    capsule_id = str(capsule_envelope["capsule"]["capsule_id"])
    before = capsule_store.load(capsule_id)
    result = execute_capsule_replay(
        coordinator,
        capsule_store,
        capsule_id=capsule_id,
        fixture_id=str(fixture["fixture_id"]),
        entrypoint="charge",
        source=SOURCE,
    )
    after = capsule_store.load(capsule_id)
    assert result["outcome"] == "PASSED"
    assert result["capsule_modified"] is False
    assert result["integrity_verified"] is True
    assert before == after


def test_capsule_replay_rejects_fixture_from_another_incident(tmp_path: Path) -> None:
    regression_policy = RegressionFixturePolicy(enabled=True, replay_enabled=True)
    store = RegressionFixtureStore(tmp_path, policy=regression_policy)
    capsule_store = IncidentCapsuleStore(tmp_path)
    capsule_envelope = capsule_store.create_placeholder(
        "00000000-0000-0000-0000-000000000001",
    )
    fixture = store.record(
        target_id="app:charge",
        name="other-incident-case",
        args=(1,),
        kwargs={},
        expected=2,
        incident_id="00000000-0000-0000-0000-000000000002",
        candidate_id=None,
        source_function_version=2,
        source_function_hash=hashlib.sha256(SOURCE.encode()).hexdigest(),
        replay_safety="PURE",
    )
    assert fixture is not None
    coordinator = IsolatedReplayCoordinator(
        store,
        policy=regression_policy,
        backend=FakeVMReplayBackend(),
    )
    with pytest.raises(ReplayExecutionError, match="not owned"):
        execute_capsule_replay(
            coordinator,
            capsule_store,
            capsule_id=str(capsule_envelope["capsule"]["capsule_id"]),
            fixture_id=str(fixture["fixture_id"]),
            entrypoint="charge",
            source=SOURCE,
        )


def test_historical_capsule_replay_isolates_each_fixture_and_skips_missing_capsules(
    tmp_path: Path,
) -> None:
    regression_policy = RegressionFixturePolicy(enabled=True, replay_enabled=True)
    store = RegressionFixtureStore(tmp_path, policy=regression_policy)
    capsule_store = IncidentCapsuleStore(tmp_path)
    first_incident = "00000000-0000-0000-0000-000000000001"
    second_incident = "00000000-0000-0000-0000-000000000002"
    capsule_store.create_placeholder(first_incident)
    for incident_id in (first_incident, second_incident):
        fixture = store.record(
            target_id="app:charge",
            name=f"incident-{incident_id[-1]}",
            args=(1,),
            kwargs={},
            expected=2,
            incident_id=incident_id,
            candidate_id=None,
            source_function_version=2,
            source_function_hash=hashlib.sha256(SOURCE.encode()).hexdigest(),
            replay_safety="PURE",
        )
        assert fixture is not None
    backend = FakeVMReplayBackend()
    coordinator = IsolatedReplayCoordinator(
        store,
        policy=regression_policy,
        backend=backend,
    )

    result = execute_historical_capsule_replays(
        coordinator,
        capsule_store,
        store.list_summaries(limit=10),
        entrypoint="charge",
        source=SOURCE,
    )

    statuses = {item["source_incident_id"]: item["status"] for item in result["results"]}
    assert statuses[first_incident] == "COMPLETED"
    assert statuses[second_incident] == "SKIPPED_NO_CAPSULE"
    assert result["fixture_count"] == 2
    assert result["completed_count"] == 1
    assert result["dispatched_count"] == 1
    assert result["capsule_modified"] is False
    assert len(backend.requests) == 1


def test_replay_backend_registry_rejects_conflicting_configuration(tmp_path: Path) -> None:
    store, _fixture_id = _store(tmp_path)
    backend = FakeVMReplayBackend()

    with pytest.raises(ValueError, match="backend or backends"):
        IsolatedReplayCoordinator(
            store,
            policy=RegressionFixturePolicy(enabled=True, replay_enabled=True),
            backend=backend,
            backends=(backend,),
        )


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


def test_replay_worker_executes_only_exact_json_values() -> None:
    result = run_payload({
        "source": SOURCE,
        "entrypoint": "charge",
        "args": [1],
        "kwargs": {},
        "expected": 2,
    })
    assert result == {"outcome": "PASSED", "output": 2, "expected": 2}

    rejected = run_payload({
        "source": SOURCE,
        "entrypoint": "charge",
        "args": [{"type": "builtins.str", "value": "<redacted>", "redacted": True}],
        "kwargs": {},
        "expected": 2,
    })
    assert rejected["outcome"] == "ERROR"


def test_rootless_podman_replay_command_has_no_host_workspace_or_network(monkeypatch, tmp_path: Path) -> None:
    backend = RootlessPodmanReplayBackend("caretaker-replay:test", workspace=tmp_path)
    captured = {}

    def fake_run(command, *, output_path, timeout_seconds, cwd, env):
        captured["command"] = command
        return {"outcome": "PASSED", "output": 2}

    monkeypatch.setattr("caretaker.replay._run_worker_command", fake_run)
    request = type("Request", (), {
        "fixture_id": "fixture",
        "target_id": "app:charge",
        "entrypoint": "charge",
        "source": SOURCE,
        "fixture": {"args": [1], "kwargs": {}, "expected": 2},
    })()
    result = backend.execute(request)
    assert result.outcome == "PASSED"
    command = captured["command"]
    assert command[:3] == ["podman", "--cgroup-manager=cgroupfs", "run"]
    assert "--network=none" in command
    assert "--read-only" in command
    assert all("/workspace" not in item and "/opt/caretaker-src" not in item for item in command)
    assert all(item != "PYTHONPATH=/opt/caretaker-src" for item in command)
    assert "caretaker.replay_worker" in command
    assert backend.capabilities().details["caretaker_code_source"] == "installed-image-wheel"
    assert backend.capabilities().details["application_workspace_mount"] == "none"
