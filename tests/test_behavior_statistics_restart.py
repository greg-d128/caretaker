from __future__ import annotations

import os
import threading
from pathlib import Path
from uuid import uuid4

from caretaker.behavior import BehaviorSnapshotStore, BehaviorStatisticsRepository
from caretaker.evidence import (
    BehaviorEvent,
    BehaviorEventKind,
    EventOutcome,
    ResourceIdentity,
    identify_function,
)
from caretaker.guard import GuardEngine
from caretaker.guard.models import BaselineState
from caretaker.guard.policy import (
    AggregationPolicy,
    BaselinePolicy,
    BehaviorSnapshotPolicy,
    GuardBinding,
    GuardPolicy,
    SamplingPolicy,
)
from caretaker.logging import (
    RuntimeArtifactSigningService,
    RuntimeRecordIntegrityMode,
    RuntimeSigningPolicy,
)
from tests.guard_targets import failing


def _completed(target_id: str, duration: float, *, stage: str = "LIGHTWEIGHT") -> BehaviorEvent:
    return BehaviorEvent.create(
        event_kind=BehaviorEventKind.FUNCTION_CALL,
        operation="function.call.completed",
        code_identity=identify_function(failing),
        run_id=uuid4(),
        call_id=uuid4(),
        target_id=target_id,
        process_id=os.getpid(),
        thread_id=threading.get_ident(),
        duration_seconds=duration,
        attributes={"observation_stage": stage},
        outcome=EventOutcome.SUCCEEDED,
    )


def _network(target_id: str, destination: str) -> BehaviorEvent:
    return BehaviorEvent.create(
        event_kind=BehaviorEventKind.NETWORK_CONNECT,
        operation="socket.connect",
        code_identity=identify_function(failing),
        run_id=uuid4(),
        call_id=uuid4(),
        target_id=target_id,
        process_id=os.getpid(),
        thread_id=threading.get_ident(),
        resource=ResourceIdentity("network", destination),
        outcome=EventOutcome.SUCCEEDED,
    )


def test_online_behavior_statistics_are_bounded_and_include_quantiles(tmp_path: Path) -> None:
    repository = BehaviorStatisticsRepository(
        tmp_path,
        statistics_target=20,
        materialize_after_samples=10_000,
        automatic_materialization=False,
    )
    target_id = "stats.target"
    configuration = {"sampling": {"lightweight_every_calls": 100}}
    for value in range(1, 101):
        repository.observe_event(
            _completed(target_id, float(value), stage="LIGHTWEIGHT"),
            monitoring_configuration=configuration,
        )

    capture = repository.current_capture(target_id)
    assert capture is not None
    statistics = capture["profile"]["statistics"]["duration_seconds"]
    assert statistics["count"] == 100
    assert statistics["minimum"] == 1.0
    assert statistics["maximum"] == 100.0
    assert statistics["average"] == 50.5
    assert statistics["reservoir_size"] == 20
    assert statistics["p10"] <= statistics["p50"] <= statistics["p90"] <= statistics["p95"] <= statistics["p99"]
    assert len(statistics["histogram_bounds"]) == 9
    assert statistics["histogram_bounds"] == sorted(statistics["histogram_bounds"])
    provenance = capture["profile"]["sampling_provenance"]
    assert provenance["strata"]["LIGHTWEIGHT"]["sample_count"] == 100


def test_monitoring_configuration_change_seals_old_generation_but_stage_change_does_not(tmp_path: Path) -> None:
    repository = BehaviorStatisticsRepository(
        tmp_path,
        materialize_after_samples=10_000,
        automatic_materialization=False,
        checkpoint_every_samples=1,
    )
    target_id = "generation.target"
    first_configuration = {"sampling": {"every": 1000}}
    repository.observe_event(
        _completed(target_id, 0.1, stage="LIGHTWEIGHT"),
        monitoring_configuration=first_configuration,
    )
    first = repository.current_capture(target_id)
    assert first is not None

    repository.observe_event(
        _completed(target_id, 0.2, stage="BEHAVIOR"),
        monitoring_configuration=first_configuration,
    )
    same_generation = repository.current_capture(target_id)
    assert same_generation is not None
    assert same_generation["generation_id"] == first["generation_id"]
    assert repository.pending_count() == 0

    repository.observe_event(
        _completed(target_id, 0.3, stage="BEHAVIOR"),
        monitoring_configuration={"sampling": {"every": 10}},
    )
    changed = repository.current_capture(target_id)
    assert changed is not None
    assert changed["generation_id"] != first["generation_id"]
    assert repository.pending_count() == 1


def test_supervisor_materialization_signs_queued_statistical_snapshot(tmp_path: Path) -> None:
    repository = BehaviorStatisticsRepository(
        tmp_path,
        materialize_after_samples=1,
        automatic_materialization=True,
    )
    repository.observe_event(
        _completed("signed.target", 0.1),
        monitoring_configuration={"sampling": {"every": 1}},
    )
    assert repository.pending_count() == 1

    signer = RuntimeArtifactSigningService(
        policy=RuntimeSigningPolicy(
            mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
            run_signer_in_separate_process=False,
        ),
        application_id="tests",
        run_id=uuid4(),
        process_start_id=uuid4(),
        root=tmp_path,
    )
    store = BehaviorSnapshotStore(tmp_path, artifact_signer=signer)
    materialized = repository.materialize_pending(store)
    assert len(materialized) == 1
    assert materialized[0]["integrity"]["signature_state"] == "EPHEMERAL_SIGNED"
    signer.close()


def _guard_policy(*, sample_rate: float = 1.0) -> GuardPolicy:
    return GuardPolicy(
        aggregation=AggregationPolicy(
            close_after_events=1,
            close_after_calls=1,
            close_after_seconds=999,
        ),
        baseline=BaselinePolicy(minimum_windows=1),
        snapshots=BehaviorSnapshotPolicy(
            enabled=True,
            automatic_materialization=False,
            materialize_after_samples=1000,
        ),
        sampling=SamplingPolicy(event_sample_rate=sample_rate),
    )


def test_guard_restores_signed_snapshot_baseline_after_restart(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CARETAKER_DATA_DIR", str(tmp_path))
    target_id = "tests.restart:failing"
    binding = GuardBinding(enabled=True, observe_network=True)
    policy = _guard_policy()

    first = GuardEngine(policy=policy)
    first.register_target(target_id, failing, binding)
    first.record_event(_completed(target_id, 0.25, stage="BEHAVIOR"))
    first.record_event(_network(target_id, "api.example:443"))
    accepted = first.accept_baseline(target_id)
    assert accepted.state is BaselineState.ACCEPTED
    assert first.behavior_statistics is not None

    signer = RuntimeArtifactSigningService(
        policy=RuntimeSigningPolicy(
            mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
            run_signer_in_separate_process=False,
        ),
        application_id="tests",
        run_id=uuid4(),
        process_start_id=uuid4(),
        root=tmp_path,
    )
    store = BehaviorSnapshotStore(tmp_path, artifact_signer=signer)
    materialized = first.behavior_statistics.materialize_pending(store)
    assert materialized
    accepted_snapshot = next(
        envelope
        for envelope in materialized
        if envelope["snapshot"].get("seal_reason") == "guard-baseline-accepted"
    )
    duration = accepted_snapshot["snapshot"]["profile"]["statistics"]["duration_seconds"]
    assert duration["p50"] == 0.25
    assert accepted_snapshot["snapshot"]["profile"]["sampling_provenance"]["strata"]["BEHAVIOR"]["sample_count"] == 1
    signer.close()

    restarted = GuardEngine(policy=policy)
    restarted.register_target(target_id, failing, binding)
    restored = restarted.baselines.get(identify_function(failing))
    assert restored is not None
    assert restored.state is BaselineState.ACCEPTED
    assert restored.baseline_id == accepted.baseline_id
    assert "api.example:443" in restored.profile.network_destinations
    assert restored.profile.statistics["duration_seconds"]["p50"] == 0.25
    assert restored.profile.sampling_provenance["strata"]["BEHAVIOR"]["sample_count"] == 1

    # A monitoring-policy change creates a different behavior generation and the
    # old accepted baseline is deliberately not restored.
    changed = GuardEngine(policy=_guard_policy(sample_rate=0.5))
    changed.register_target(target_id, failing, binding)
    assert changed.baselines.get(identify_function(failing)) is None
