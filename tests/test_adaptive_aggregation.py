from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from caretaker.adaptive_aggregation import (
    AdaptiveAggregationError,
    AdaptiveObservationBatcher,
    SupervisorAdaptiveAggregationStore,
)
from caretaker.adaptive import (
    AdaptiveAggregationPolicy,
    BehaviorSamplingPolicy,
    InstrumentationDemotionPolicy,
    InstrumentationLevel,
    LightweightPolicy,
    lightweight,
)
from caretaker.authority import get_authority_runtime_context


def _batch(*, batch_id: str, worker_id: str = "worker-a", generation_id: str = "generation-a"):
    now = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    return {
        "batch_id": batch_id,
        "worker_id": worker_id,
        "worker_pid": 101,
        "target_id": "example.target",
        "generation_id": generation_id,
        "code_hash": "code-a",
        "monitoring_fingerprint": "monitoring-a",
        "policy_fingerprint": "policy-a",
        "authority_policy_generation": "7",
        "authority_policy_fingerprint": "authority-a",
        "created_at": now.isoformat(),
        "first_observed_at": now.isoformat(),
        "last_observed_at": (now + timedelta(seconds=1)).isoformat(),
        "sequence_start": 1,
        "sequence_end": 2,
        "observation_count": 2,
        "exception_count": 1,
        "timing_breach_count": 1,
        "behavior_observation_calls": 2,
        "behavior_samples": 1,
        "repair_evidence_samples": 1,
        "problem_reproductions": 1,
        "successful_executions": 1,
        "failed_executions": 1,
        "exception_events": [now.isoformat()],
        "timing_events": [(now + timedelta(seconds=1)).isoformat()],
    }


def _context():
    return {
        "current_generations": {"example.target": "generation-a"},
        "policy_fingerprint": "policy-a",
        "authority_policy_generation": "7",
        "authority_policy_fingerprint": "authority-a",
    }


def test_supervisor_aggregation_merges_batches_and_retains_worker_provenance(tmp_path: Path):
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    first = _batch(batch_id="00000000-0000-0000-0000-000000000001")
    second = _batch(
        batch_id="00000000-0000-0000-0000-000000000002",
        worker_id="worker-b",
    )

    assert store.submit(first)["status"] == "QUEUED"
    assert store.submit(second)["status"] == "QUEUED"
    result = store.reconcile(**_context())

    assert result["merged"] == 2
    assert result["pending"] == 0
    aggregates = store.list_aggregates()
    assert len(aggregates) == 1
    aggregate = aggregates[0]
    assert aggregate["total_batches"] == 2
    assert aggregate["exception_count"] == 2
    assert aggregate["behavior_observation_calls"] == 4
    assert aggregate["total_observations"] == 4
    assert sorted(aggregate["workers"]) == ["worker-a", "worker-b"]
    assert aggregate["worker_overflow_count"] == 0
    assert aggregate["processed_batch_count"] == 2


def test_supervisor_aggregation_is_idempotent_for_resubmitted_batch(tmp_path: Path):
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    batch = _batch(batch_id="00000000-0000-0000-0000-000000000003")
    store.submit(batch)
    assert store.reconcile(**_context())["merged"] == 1

    assert store.submit(batch)["status"] == "DUPLICATE"
    assert store.status()["pending"] == 0
    assert store.list_aggregates()[0]["total_batches"] == 1


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("generation_id", "generation-old", "STALE_GENERATION"),
        ("policy_fingerprint", "policy-old", "STALE_POLICY"),
        ("authority_policy_generation", "6", "STALE_AUTHORITY_GENERATION"),
        ("authority_policy_fingerprint", "authority-old", "STALE_AUTHORITY_FINGERPRINT"),
    ),
)
def test_supervisor_aggregation_rejects_stale_worker_context(
    tmp_path: Path, field: str, value: str, reason: str
):
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    batch = _batch(batch_id="00000000-0000-0000-0000-000000000004")
    batch[field] = value
    store.submit(batch)

    result = store.reconcile(**_context())

    assert result["merged"] == 0
    assert result["rejected"] == 1
    assert store.status()["aggregates"] == 0
    rejected = list(store.rejected_directory.glob("*.json"))
    assert len(rejected) == 1
    assert reason in rejected[0].read_text(encoding="utf-8")


def test_supervisor_aggregation_requires_current_generation_context(tmp_path: Path):
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    batch = _batch(batch_id="00000000-0000-0000-0000-000000000005")
    store.submit(batch)

    result = store.reconcile(
        current_generations={},
        policy_fingerprint="policy-a",
        authority_policy_generation="7",
        authority_policy_fingerprint="authority-a",
    )

    assert result["rejected"] == 1
    assert "GENERATION_CONTEXT_UNAVAILABLE" in next(
        store.rejected_directory.glob("*.json")
    ).read_text(encoding="utf-8")


def test_supervisor_aggregation_rejects_malformed_batch_without_merging(tmp_path: Path):
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    batch = _batch(batch_id="00000000-0000-0000-0000-000000000006")
    batch["exception_count"] = -1
    with pytest.raises(AdaptiveAggregationError):
        store.submit(batch)
    assert store.status()["pending"] == 0


def test_supervisor_aggregation_requires_explicit_batch_id(tmp_path: Path):
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    batch = _batch(batch_id="00000000-0000-0000-0000-000000000007")
    batch.pop("batch_id")

    with pytest.raises(AdaptiveAggregationError, match="batch_id"):
        store.submit(batch)
    assert store.status()["pending"] == 0


def test_worker_batcher_flushes_bounded_records_with_sequence_provenance(tmp_path: Path):
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    batcher = AdaptiveObservationBatcher(
        store,
        worker_id="worker-a",
        worker_pid=101,
        target_id="example.target",
        generation_id="generation-a",
        code_hash="code-a",
        monitoring_fingerprint="monitoring-a",
        policy_fingerprint="policy-a",
        authority_policy_generation="7",
        authority_policy_fingerprint="authority-a",
        flush_after_observations=2,
        flush_interval_seconds=0,
    )

    assert batcher.record(behavior_observation_calls=1) is None
    result = batcher.record(behavior_samples=1)

    assert result is not None
    assert result["status"] == "QUEUED"
    assert result["batch_id"]
    assert batcher.status()["pending_records"] == 0
    assert store.reconcile(**_context())["merged"] == 1
    aggregate = store.list_aggregates()[0]
    assert aggregate["total_observations"] == 2
    assert aggregate["workers"]["worker-a"]["first_sequence"] == 1
    assert aggregate["workers"]["worker-a"]["last_sequence"] == 2


def test_enabled_adaptive_policy_emits_live_controller_counters(tmp_path: Path):
    policy = LightweightPolicy(
        initial_level=InstrumentationLevel.BEHAVIOR,
        sampling=BehaviorSamplingPolicy(
            enabled=True,
            lightweight_every_calls=0,
            behavior_every_calls=1,
            randomize_initial_offset=False,
        ),
        demotion=InstrumentationDemotionPolicy(enabled=False),
        aggregation=AdaptiveAggregationPolicy(
            enabled=True,
            flush_after_observations=1,
            flush_interval_seconds=0,
        ),
    )

    @lightweight(policy=policy, target_id="aggregation.live", state_directory=tmp_path / "adaptive")
    def observed(value: int) -> int:
        return value + 1

    assert observed(1) == 2
    controller = observed.__caretaker_adaptive__
    assert controller._aggregation_batcher is not None
    controller._aggregation_batcher.flush()
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    context = dict(_context())
    context["current_generations"] = {"aggregation.live": controller.code_hash}
    context["policy_fingerprint"] = controller._policy_fingerprint
    context["authority_policy_generation"] = str(
        get_authority_runtime_context().effective.generation
    )
    context["authority_policy_fingerprint"] = controller._authority_fingerprint
    assert store.reconcile(**context)["merged"] == 2
    aggregate = store.list_aggregates()[0]
    assert aggregate["behavior_observation_calls"] == 1
    assert aggregate["successful_executions"] == 1
