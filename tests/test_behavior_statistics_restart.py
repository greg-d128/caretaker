from __future__ import annotations

import os
import threading
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from caretaker.behavior import (
    BehaviorSnapshotStore,
    BehaviorStatisticsRepository,
    observed_return_category,
)
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


def _completed(
    target_id: str,
    duration: float,
    *,
    stage: str = "LIGHTWEIGHT",
    return_category: str | None = None,
) -> BehaviorEvent:
    attributes = {"observation_stage": stage}
    if return_category is not None:
        attributes["return_category"] = return_category
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
        attributes=attributes,
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


def test_return_category_observation_is_type_only_and_does_not_consume_iterators() -> None:
    values = [
        None,
        True,
        1,
        1.5,
        "text",
        [1, 2],
        {"key": "value"},
    ]
    categories = [observed_return_category(value) for value in values]
    iterator = iter((1, 2))
    iterator_category = observed_return_category(iterator)

    assert categories[0].startswith("none:")
    assert categories[1].startswith("boolean:")
    assert categories[2].startswith("integer:")
    assert categories[3].startswith("float:")
    assert categories[4].startswith("text:")
    assert categories[5].startswith("list:")
    assert categories[6].startswith("mapping:")
    assert iterator_category.startswith("iterator:")
    assert next(iterator) == 1


def test_return_categories_are_bounded_and_restart_safe(tmp_path: Path) -> None:
    repository = BehaviorStatisticsRepository(
        tmp_path,
        maximum_return_categories=2,
        materialize_after_samples=10_000,
        checkpoint_every_samples=1,
        automatic_materialization=False,
    )
    target_id = "return.target"
    configuration = {"sampling": {"every": 1}}
    categories = (
        observed_return_category(None),
        observed_return_category(1),
        observed_return_category("overflow"),
    )
    for category in categories:
        repository.observe_event(
            _completed(target_id, 0.1, return_category=category),
            monitoring_configuration=configuration,
        )

    capture = repository.current_capture(target_id)
    assert capture is not None
    profile = capture["profile"]
    assert profile["return_categories"] == {categories[0]: 1, categories[1]: 1}
    assert profile["return_category_coverage_complete"] is False
    assert profile["return_category_overflow_count"] == 1
    assert sum(profile["return_categories"].values()) == 2

    restarted = BehaviorStatisticsRepository(
        tmp_path,
        maximum_return_categories=2,
        materialize_after_samples=10_000,
        checkpoint_every_samples=1,
        automatic_materialization=False,
    )
    restarted.observe_event(
        _completed(target_id, 0.1, return_category=categories[0]),
        monitoring_configuration=configuration,
    )
    restarted_capture = restarted.current_capture(target_id)
    assert restarted_capture is not None
    assert restarted_capture["profile"]["return_categories"][categories[0]] == 2
    assert restarted_capture["profile"]["return_category_overflow_count"] == 1


def test_failed_call_does_not_create_a_return_category_observation(tmp_path: Path) -> None:
    repository = BehaviorStatisticsRepository(
        tmp_path,
        materialize_after_samples=10_000,
        automatic_materialization=False,
    )
    target_id = "failed-return.target"
    event = replace(
        _completed(
            target_id,
            0.1,
            return_category=observed_return_category("not-a-return"),
        ),
        outcome=EventOutcome.FAILED,
    )
    repository.observe_event(event, monitoring_configuration={"sampling": {"every": 1}})
    capture = repository.current_capture(target_id)
    assert capture is not None
    assert capture["profile"]["return_categories"] == {}


def test_attributed_resource_identity_does_not_reset_function_generation(tmp_path: Path) -> None:
    repository = BehaviorStatisticsRepository(
        tmp_path,
        materialize_after_samples=100,
        checkpoint_every_samples=1,
    )
    target_id = "audit.target"
    configuration = {"sampling": {"every": 1}}

    for number in range(100):
        repository.observe_event(
            _completed(target_id, 0.001), monitoring_configuration=configuration
        )
        resource_event = replace(
            _network(target_id, f"127.0.0.1:{8000 + number % 2}"),
            code_identity=identify_function(_network),
        )
        repository.observe_event(resource_event, monitoring_configuration=configuration)

    store = BehaviorSnapshotStore(tmp_path)
    repository.materialize_pending(store, maximum=100)
    summaries = store.list_summaries()

    assert len(summaries) == 1
    assert summaries[0]["profile"]["coverage_call_count"] == 100
    assert summaries[0]["profile"]["coverage_snapshot_count"] == 1


def test_manual_capture_atomically_cuts_disjoint_generation_epochs(tmp_path: Path) -> None:
    repository = BehaviorStatisticsRepository(
        tmp_path,
        materialize_after_samples=10_000,
        automatic_materialization=False,
        checkpoint_every_samples=1,
    )
    target_id = "epoch.target"
    configuration = {"sampling": {"every": 1}}
    for duration in (0.1, 0.2):
        repository.observe_event(
            _completed(target_id, duration), monitoring_configuration=configuration
        )

    first = repository.cut_capture(target_id)
    assert first is not None
    assert first["complete_epoch"] is True
    assert first["epoch_sequence"] == 1
    assert (first["first_sample_sequence"], first["last_sample_sequence"]) == (1, 2)

    repository.observe_event(
        _completed(target_id, 0.3), monitoring_configuration=configuration
    )
    second = repository.cut_capture(target_id)
    assert second is not None
    assert second["epoch_sequence"] == 2
    assert (second["first_sample_sequence"], second["last_sample_sequence"]) == (3, 3)
    active = repository.current_capture(target_id)
    assert active is not None
    assert active["epoch_sequence"] == 3
    assert active["first_sample_sequence"] == 4
    assert active["profile"]["call_count"] == 0

    restarted = BehaviorStatisticsRepository(
        tmp_path,
        materialize_after_samples=10_000,
        automatic_materialization=False,
        checkpoint_every_samples=1,
    )
    restarted.observe_event(
        _completed(target_id, 0.4), monitoring_configuration=configuration
    )
    third = restarted.cut_capture(target_id)
    assert third is not None
    assert third["epoch_sequence"] == 3
    assert (third["first_sample_sequence"], third["last_sample_sequence"]) == (4, 4)

    store = BehaviorSnapshotStore(tmp_path)
    store.create(first)
    store.create(second)
    store.create(third)
    summary = store.list_summaries()[0]
    assert summary["profile"]["coverage_kind"] == "generation"
    assert summary["profile"]["coverage_call_count"] == 4
    assert summary["profile"]["coverage_snapshot_count"] == 3


def test_pending_epochs_materialize_in_subject_generation_sequence(tmp_path: Path) -> None:
    repository = BehaviorStatisticsRepository(
        tmp_path,
        materialize_after_samples=1,
        checkpoint_every_samples=1,
    )
    target_id = "ordered.target"
    for duration in (0.1, 0.2, 0.3, 0.4):
        repository.observe_event(
            _completed(target_id, duration), monitoring_configuration={"sampling": {"every": 1}}
        )

    store = BehaviorSnapshotStore(tmp_path)
    envelopes = repository.materialize_pending(store, maximum=100)

    assert [item["snapshot"]["epoch_sequence"] for item in envelopes] == [1, 2, 3, 4]
    summary = store.list_summaries()[0]
    assert summary["profile"]["coverage_call_count"] == 4


def test_randomized_epoch_boundaries_are_bounded_provenance_and_disjoint(tmp_path: Path) -> None:
    repository = BehaviorStatisticsRepository(
        tmp_path,
        materialize_after_samples=10_000,
        checkpoint_every_samples=1,
        randomized_epoch_boundaries=True,
        randomized_epoch_min_samples=2,
        randomized_epoch_max_samples=4,
        randomized_epoch_seed=17,
    )
    target_id = "randomized.target"
    configuration = {"sampling": {"every": 1}}

    repository.observe_event(_completed(target_id, 0.1), monitoring_configuration=configuration)
    first_active = repository.current_capture(target_id)
    assert first_active is not None
    first_boundary = first_active["profile"]["sampling_provenance"]["epoch_boundary"]
    assert first_boundary["algorithm"] == "uniform-integer-v1"
    assert first_boundary["randomized"] is True
    assert 2 <= first_boundary["target_samples"] <= 4
    assert len(first_boundary["seed_commitment"]) == 64

    for _ in range(first_boundary["target_samples"] - 1):
        repository.observe_event(_completed(target_id, 0.1), monitoring_configuration=configuration)
    assert repository.pending_count() == 1

    store = BehaviorSnapshotStore(tmp_path)
    first_envelope = repository.materialize_pending(store)[0]
    first_snapshot = first_envelope["snapshot"]
    assert first_snapshot["seal_reason"] == "randomized-epoch-boundary-reached"
    assert first_snapshot["first_sample_sequence"] == 1
    assert first_snapshot["last_sample_sequence"] == first_boundary["target_samples"]

    second_active = repository.current_capture(target_id)
    assert second_active is not None
    second_boundary = second_active["profile"]["sampling_provenance"]["epoch_boundary"]
    assert 2 <= second_boundary["target_samples"] <= 4
    for _ in range(second_boundary["target_samples"]):
        repository.observe_event(_completed(target_id, 0.1), monitoring_configuration=configuration)
    second_envelope = repository.materialize_pending(store)[0]
    second_snapshot = second_envelope["snapshot"]
    assert second_snapshot["first_sample_sequence"] == first_snapshot["last_sample_sequence"] + 1
    assert second_snapshot["last_sample_sequence"] == (
        second_snapshot["first_sample_sequence"] + second_boundary["target_samples"] - 1
    )

    replay = BehaviorStatisticsRepository(
        tmp_path / "replay",
        materialize_after_samples=10_000,
        checkpoint_every_samples=1,
        randomized_epoch_boundaries=True,
        randomized_epoch_min_samples=2,
        randomized_epoch_max_samples=4,
        randomized_epoch_seed=17,
    )
    replay.observe_event(_completed(target_id, 0.1), monitoring_configuration=configuration)
    replay_first = replay.current_capture(target_id)
    assert replay_first is not None
    replay_boundary = replay_first["profile"]["sampling_provenance"]["epoch_boundary"]
    assert replay_boundary["target_samples"] == first_boundary["target_samples"]
    assert replay_boundary["seed_commitment"] == first_boundary["seed_commitment"]
    for _ in range(first_boundary["target_samples"] - 1):
        replay.observe_event(_completed(target_id, 0.1), monitoring_configuration=configuration)
    replay.materialize_pending(BehaviorSnapshotStore(tmp_path / "replay"))
    replay_second = replay.current_capture(target_id)
    assert replay_second is not None
    replay_second_boundary = replay_second["profile"]["sampling_provenance"]["epoch_boundary"]
    assert replay_second_boundary["target_samples"] == second_boundary["target_samples"]
    assert replay_second_boundary["seed_commitment"] == second_boundary["seed_commitment"]


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
