from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from caretaker.adaptive_aggregation import (
    AdaptiveAggregationBackpressureAction,
    AdaptiveAggregationError,
    AdaptiveObservationBatcher,
    SupervisorAdaptiveAggregationStore,
    extended_aggregation_target_id,
)
from caretaker.adaptive import (
    AdaptiveAggregationPolicy,
    BehaviorSamplingPolicy,
    ExceptionPromotionPolicy,
    InstrumentationDemotionPolicy,
    InstrumentationLevel,
    LightweightPolicy,
    lightweight,
    validate_lightweight_policy,
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
    assert store.acknowledgement(str(first["batch_id"]))["status"] == "ACCEPTED"
    assert store.acknowledgement(str(second["batch_id"]))["status"] == "ACCEPTED"
    assert store.status()["acknowledgements"] == 2


def test_optional_aggregation_scope_requires_extended_context_and_keeps_populations_separate(
    tmp_path: Path,
):
    scoped = _batch(batch_id="00000000-0000-0000-0000-00000000000c")
    scoped["aggregation_scope"] = "cluster:blue"
    extended = extended_aggregation_target_id(
        scoped["target_id"], scoped["aggregation_scope"]
    )

    rejected_store = SupervisorAdaptiveAggregationStore(tmp_path / "rejected")
    rejected_store.submit(scoped)
    rejected = rejected_store.reconcile(**_context())
    assert rejected["rejected"] == 1
    assert "GENERATION_CONTEXT_UNAVAILABLE" in next(
        rejected_store.rejected_directory.glob("*.json")
    ).read_text(encoding="utf-8")

    store = SupervisorAdaptiveAggregationStore(tmp_path / "accepted")
    store.submit(scoped)
    unscoped = _batch(batch_id="00000000-0000-0000-0000-00000000000d")
    store.submit(unscoped)
    context = _context()
    context["current_generations"] = {
        "example.target": "generation-a",
        extended: "generation-a",
    }
    context["policy_fingerprints"] = {
        "example.target": "policy-a",
        extended: "policy-a",
    }
    context.pop("policy_fingerprint", None)

    result = store.reconcile(**context)

    assert result["merged"] == 2
    aggregates = store.list_aggregates()
    assert len(aggregates) == 2
    assert {
        (item["target_id"], item["aggregation_scope"])
        for item in aggregates
    } == {
        ("example.target", None),
        ("example.target", "cluster:blue"),
    }
    assert next(
        item for item in aggregates if item["aggregation_scope"] == "cluster:blue"
    )["aggregation_target_id"] == extended


def test_transition_deadline_expires_and_rejects_late_acknowledgement(
    tmp_path: Path, monkeypatch
):
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    batch = _batch(batch_id="00000000-0000-0000-0000-00000000000e")
    batch.update(
        observation_count=1,
        sequence_end=1,
        exception_count=1,
        exception_events=["2026-08-30T12:00:00+00:00"],
    )
    store.submit(batch)
    context = _context()
    assert store.reconcile(**context)["merged"] == 1
    fixed_now = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(
        "caretaker.adaptive_aggregation._utcnow_iso",
        lambda: fixed_now.isoformat(),
    )
    policy = {
        "exception": {
            "enabled": True,
            "occurrences": 1,
            "window_seconds": 3600,
            "promote_to": "BEHAVIOR",
        },
        "soft_timing": {
            "enabled": False,
            "occurrences": 1,
            "window_seconds": 3600,
            "promote_to": "BEHAVIOR",
        },
        "repair_evidence": {"enabled": False},
        "transition_timeout_seconds": 30,
    }
    assert store.evaluate_promotions(
        **context,
        promotion_policies={"example.target": policy},
    )["created"] == 1
    request = store.list_transition_requests()[0]
    assert request["transition_timeout_seconds"] == 30.0
    assert request["expires_at"] == "2026-08-30T12:00:30+00:00"

    visible = store.list_transition_requests(
        now=fixed_now + timedelta(seconds=31),
    )[0]
    assert visible["status"] == "EXPIRED"
    assert visible["deadline_status"] == "EXPIRED"
    assert visible["stale_worker_ids"] == ["worker-a"]
    assert visible["remaining_seconds"] == 0.0
    with pytest.raises(PermissionError, match="expired"):
        store.acknowledge_transition(
            {"request_id": request["request_id"], "worker_id": "worker-a"},
            peer_pid=101,
        )


def test_adaptive_transition_timeout_policy_is_bounded() -> None:
    with pytest.raises(ValueError, match="transition_timeout_seconds"):
        validate_lightweight_policy(
            LightweightPolicy(
                aggregation=AdaptiveAggregationPolicy(
                    transition_timeout_seconds=0,
                )
            )
        )


class _BackpressureStore:
    def __init__(self, *, fail_count: int = 0) -> None:
        self.fail_count = fail_count
        self.batches: list[dict[str, object]] = []

    def submit(self, batch):
        if self.fail_count:
            self.fail_count -= 1
            raise RuntimeError("aggregation queue is full")
        self.batches.append(dict(batch))
        return {"status": "QUEUED", "batch_id": batch["batch_id"]}


def _backpressure_batcher(store, action: AdaptiveAggregationBackpressureAction):
    return AdaptiveObservationBatcher(
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
        flush_after_observations=1,
        flush_interval_seconds=0,
        backpressure_action=action,
    )


def test_adaptive_backpressure_retain_preserves_pending_evidence() -> None:
    batcher = _backpressure_batcher(
        _BackpressureStore(fail_count=1),
        AdaptiveAggregationBackpressureAction.RETAIN,
    )

    result = batcher.record(behavior_samples=1)

    assert result is not None
    assert result["status"] == "DEFERRED"
    assert batcher.status()["pending_records"] == 1
    assert batcher.status()["dropped_records"] == 0


def test_adaptive_backpressure_drop_discards_only_the_failed_batch() -> None:
    batcher = _backpressure_batcher(
        _BackpressureStore(fail_count=1),
        AdaptiveAggregationBackpressureAction.DROP,
    )

    result = batcher.record(behavior_samples=1)

    assert result is not None
    assert result["status"] == "DROPPED"
    assert result["dropped_records"] == 1
    assert batcher.status()["pending_records"] == 0
    assert batcher.status()["dropped_records"] == 1


def test_adaptive_backpressure_reduce_retries_without_detail_samples() -> None:
    store = _BackpressureStore(fail_count=1)
    batcher = _backpressure_batcher(
        store,
        AdaptiveAggregationBackpressureAction.REDUCE,
    )

    result = batcher.record(
        event_kind="timing",
        duration_seconds=2.5,
        resource_values={"cpu_seconds": 0.5},
        timing_breach_count=1,
        behavior_samples=1,
    )

    assert result is not None
    assert result["status"] == "REDUCED"
    assert result["dropped_detail"] is True
    assert len(store.batches) == 1
    reduced = store.batches[0]
    assert reduced["timing_breach_count"] == 1
    assert reduced["timing_events"] == []
    assert reduced["duration_samples"] == []
    assert reduced["duration_samples_truncated"] is True
    assert reduced["resource_samples"] == {}
    assert batcher.status()["pending_records"] == 0


def test_lightweight_policy_rejects_unknown_adaptive_backpressure_action() -> None:
    with pytest.raises(ValueError, match="backpressure_action"):
        validate_lightweight_policy(
            LightweightPolicy(
                aggregation=AdaptiveAggregationPolicy(backpressure_action="INVALID")
            )
        )


def test_supervisor_records_delayed_threshold_proposal_without_applying_policy(
    tmp_path: Path,
):
    store = SupervisorAdaptiveAggregationStore(tmp_path)

    proposal = store.create_threshold_proposal(
        target_id="example.target",
        generation_id="generation-a",
        code_hash="code-a",
        monitoring_fingerprint="monitoring-a",
        policy_fingerprint="policy-a",
        authority_policy_generation="7",
        authority_policy_fingerprint="authority-a",
        changes={
            "exception.occurrences": 4,
            "exception.window_seconds": 900,
        },
        requested_by="operator:test",
        reason="reduce false positives after reviewed evidence",
        effective_after_seconds=60,
    )

    assert proposal["status"] == "PROPOSAL_ONLY"
    assert proposal["proposal_only"] is True
    assert proposal["changes"] == {
        "exception.occurrences": 4,
        "exception.window_seconds": 900.0,
    }
    assert proposal["effective_at"] != proposal["created_at"]
    context = {
        "current_generations": {"example.target": "generation-a"},
        "policy_fingerprints": {"example.target": "policy-a"},
        "authority_policy_generation": "7",
        "authority_policy_fingerprint": "authority-a",
    }
    listed = store.list_transition_requests(**context)
    assert listed[0]["request_kind"] == "ADAPTIVE_THRESHOLD_PROPOSAL"
    assert listed[0]["status"] == "PROPOSAL_ONLY"
    assert listed[0]["context_status"] == "CURRENT"

    stale = store.list_transition_requests(
        **{
            **context,
            "policy_fingerprints": {"example.target": "policy-b"},
        }
    )
    assert stale[0]["context_status"] == "STALE_POLICY"
    with pytest.raises(PermissionError, match="Behavior promotion"):
        store.acknowledge_transition(
            {"request_id": proposal["request_id"], "worker_id": "worker-a"},
            peer_pid=101,
        )


def test_threshold_proposal_review_is_context_bound_idempotent_and_non_mutating(
    tmp_path: Path,
):
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    proposal = store.create_threshold_proposal(
        target_id="example.target",
        generation_id="generation-a",
        code_hash="code-a",
        monitoring_fingerprint="monitoring-a",
        policy_fingerprint="policy-a",
        authority_policy_generation="7",
        authority_policy_fingerprint="authority-a",
        changes={"exception.occurrences": 4},
        requested_by="operator:test",
        reason="review threshold evidence",
        expires_in_seconds=3600,
    )
    created = datetime.fromisoformat(proposal["created_at"])
    context = {
        "current_generations": {"example.target": "generation-a"},
        "policy_fingerprints": {"example.target": "policy-a"},
        "authority_policy_generation": "7",
        "authority_policy_fingerprint": "authority-a",
    }

    reviewed = store.review_threshold_proposal(
        proposal["request_id"],
        decision="approve",
        reviewed_by="uid:1001",
        reason="evidence is sufficient for staged review",
        now=created + timedelta(seconds=1),
        **context,
    )

    assert reviewed["status"] == "RECORDED"
    assert reviewed["review_status"] == "APPROVED_FOR_STAGED_POLICY_REVIEW"
    assert reviewed["policy_applied"] is False
    assert reviewed["authority_granted"] is False
    listed = store.list_transition_requests(**context)
    assert listed[0]["status"] == "PROPOSAL_ONLY"
    assert listed[0]["review_status"] == "APPROVED_FOR_STAGED_POLICY_REVIEW"
    assert listed[0]["review"]["reviewed_by"] == "uid:1001"

    duplicate = store.review_threshold_proposal(
        proposal["request_id"],
        decision="APPROVE",
        reviewed_by="uid:1001",
        reason="evidence is sufficient for staged review",
        now=created + timedelta(seconds=2),
        **context,
    )
    assert duplicate["status"] == "DUPLICATE"
    assert store.status()["proposal_reviews"] == 1

    with pytest.raises(AdaptiveAggregationError, match="conflicting"):
        store.review_threshold_proposal(
            proposal["request_id"],
            decision="REJECT",
            reviewed_by="uid:1001",
            reason="different decision",
            now=created + timedelta(seconds=3),
            **context,
        )

    with pytest.raises(PermissionError, match="STALE_POLICY"):
        store.review_threshold_proposal(
            proposal["request_id"],
            decision="REJECT",
            reviewed_by="uid:1002",
            reason="stale context must fail closed",
            now=created + timedelta(seconds=4),
            **{
                **context,
                "policy_fingerprints": {"example.target": "policy-b"},
            },
        )


def test_threshold_proposal_rejects_non_threshold_fields(tmp_path: Path) -> None:
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    with pytest.raises(AdaptiveAggregationError, match="unsupported adaptive threshold"):
        store.create_threshold_proposal(
            target_id="example.target",
            generation_id="generation-a",
            code_hash="code-a",
            monitoring_fingerprint="monitoring-a",
            policy_fingerprint="policy-a",
            authority_policy_generation="7",
            authority_policy_fingerprint="authority-a",
            changes={"exception.promote_to": "REPAIR"},
            requested_by="operator:test",
            reason="not a threshold change",
        )


def test_supervisor_records_worker_distribution_conflict_without_discarding_evidence(
    tmp_path: Path,
):
    store = SupervisorAdaptiveAggregationStore(
        tmp_path,
        distribution_minimum_observations=2,
    )
    first = _batch(batch_id="00000000-0000-0000-0000-00000000000a")
    first.update(
        observation_count=100,
        sequence_end=100,
        exception_count=0,
        timing_breach_count=0,
        behavior_observation_calls=100,
        behavior_samples=100,
        repair_evidence_samples=0,
        problem_reproductions=0,
        exception_events=[],
        timing_events=[],
    )
    second = _batch(
        batch_id="00000000-0000-0000-0000-00000000000b",
        worker_id="worker-b",
    )
    second.update(
        observation_count=100,
        sequence_end=100,
        exception_count=100,
        timing_breach_count=0,
        behavior_observation_calls=100,
        behavior_samples=100,
        repair_evidence_samples=0,
        problem_reproductions=0,
        exception_events=[],
        timing_events=[],
    )
    store.submit(first)
    store.submit(second)

    result = store.reconcile(**_context())

    assert result["merged"] == 2
    assert result["conflicts"] == 2
    assert result["conflict_reports"] == 2
    aggregate = store.list_aggregates()[0]
    assert aggregate["exception_count"] == 100
    assert len(aggregate["distribution_conflicts"]) == 2
    assert all(item["z_score"] > 3 for item in aggregate["distribution_conflicts"])
    reports = sorted(store.conflict_directory.glob("*.json"))
    assert len(reports) == 2
    assert all(
        json.loads(path.read_text(encoding="utf-8"))["evidence_retained"] is True
        for path in reports
    )


def test_supervisor_reconciles_bounded_timing_duration_distributions(
    tmp_path: Path,
):
    store = SupervisorAdaptiveAggregationStore(
        tmp_path,
        distribution_minimum_observations=2,
    )
    first = _batch(batch_id="00000000-0000-0000-0000-00000000000f")
    first.update(
        timing_breach_count=2,
        timing_events=[
            "2026-08-30T12:00:00+00:00",
            "2026-08-30T12:00:01+00:00",
        ],
        duration_samples=[1.0, 1.0],
    )
    second = _batch(
        batch_id="00000000-0000-0000-0000-000000000010",
        worker_id="worker-b",
    )
    second.update(
        timing_breach_count=2,
        timing_events=[
            "2026-08-30T12:00:00+00:00",
            "2026-08-30T12:00:01+00:00",
        ],
        duration_samples=[10.0, 10.0],
    )
    store.submit(first)
    store.submit(second)

    result = store.reconcile(**_context())

    assert result["merged"] == 2
    assert result["conflicts"] == 2
    assert result["conflict_reports"] == 2
    aggregate = store.list_aggregates()[0]
    duration = aggregate["timing_duration_statistics"]
    assert duration["count"] == 4
    assert duration["mean"] == 5.5
    assert duration["minimum"] == 1.0
    assert duration["maximum"] == 10.0
    assert {
        item["metric"] for item in aggregate["distribution_conflicts"]
    } == {"timing_duration_seconds"}
    assert all(item["z_score"] > 3 for item in aggregate["distribution_conflicts"])


def test_supervisor_reconciles_bounded_resource_distributions(tmp_path: Path):
    store = SupervisorAdaptiveAggregationStore(
        tmp_path,
        distribution_minimum_observations=2,
    )
    first = _batch(batch_id="00000000-0000-0000-0000-000000000011")
    first.update(
        observation_count=30,
        sequence_end=30,
        timing_breach_count=0,
        exception_count=0,
        behavior_observation_calls=30,
        behavior_samples=30,
        repair_evidence_samples=0,
        problem_reproductions=0,
        successful_executions=30,
        failed_executions=0,
        exception_events=[],
        timing_events=[],
        resource_samples={"cpu_seconds": [1.0] * 30},
        resource_samples_truncated={"cpu_seconds": False},
    )
    second = _batch(
        batch_id="00000000-0000-0000-0000-000000000012",
        worker_id="worker-b",
    )
    second.update(
        observation_count=30,
        sequence_end=30,
        timing_breach_count=0,
        exception_count=0,
        behavior_observation_calls=30,
        behavior_samples=30,
        repair_evidence_samples=0,
        problem_reproductions=0,
        successful_executions=30,
        failed_executions=0,
        exception_events=[],
        timing_events=[],
        resource_samples={"cpu_seconds": [10.0] * 30},
        resource_samples_truncated={"cpu_seconds": False},
    )
    store.submit(first)
    store.submit(second)

    result = store.reconcile(**_context())

    assert result["merged"] == 2
    assert result["conflicts"] == 2
    aggregate = store.list_aggregates()[0]
    resource = aggregate["resource_statistics"]["cpu_seconds"]
    assert resource["count"] == 60
    assert resource["mean"] == 5.5
    assert resource["minimum"] == 1.0
    assert resource["maximum"] == 10.0
    assert {
        item["metric"] for item in aggregate["distribution_conflicts"]
    } == {"resource:cpu_seconds"}
    assert all(item["z_score"] > 3 for item in aggregate["distribution_conflicts"])


def test_supervisor_aggregation_is_idempotent_for_resubmitted_batch(tmp_path: Path):
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    batch = _batch(batch_id="00000000-0000-0000-0000-000000000003")
    store.submit(batch)
    assert store.reconcile(**_context())["merged"] == 1

    assert store.submit(batch)["status"] == "DUPLICATE"
    assert store.status()["pending"] == 0
    assert store.list_aggregates()[0]["total_batches"] == 1


def test_supervisor_creates_context_bound_promotion_and_tracks_worker_acknowledgements(
    tmp_path: Path,
):
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    first = _batch(batch_id="00000000-0000-0000-0000-000000000008")
    second = _batch(
        batch_id="00000000-0000-0000-0000-000000000009",
        worker_id="worker-b",
    )
    store.submit(first)
    store.submit(second)
    context = _context()
    assert store.reconcile(**context)["merged"] == 2

    promotion_policy = {
        "exception": {
            "enabled": True,
            "occurrences": 2,
            "window_seconds": 3600,
            "promote_to": "REPAIR",
        },
        "soft_timing": {
            "enabled": False,
            "occurrences": 2,
            "window_seconds": 3600,
            "promote_to": "BEHAVIOR",
        },
        "repair_evidence": {
            "enabled": True,
            "minimum_behavior_samples": 1,
            "minimum_observation_calls": 1,
            "minimum_duration_seconds": 0,
            "require_problem_reproduction": True,
        },
    }
    evaluated = store.evaluate_promotions(
        **context,
        promotion_policies={"example.target": promotion_policy},
    )
    assert evaluated["created"] == 1
    request = store.list_transition_requests()[0]
    assert request["requested_level"] == "BEHAVIOR"
    assert request["signal_level"] == "REPAIR"
    assert request["status"] == "PENDING"
    assert [item["worker_id"] for item in request["required_workers"]] == [
        "worker-a",
        "worker-b",
    ]

    assert store.evaluate_promotions(
        **context,
        promotion_policies={"example.target": promotion_policy},
    )["created"] == 0
    assert store.list_transition_requests()[0]["status"] == "PENDING"

    ack = {
        "request_id": request["request_id"],
        "worker_id": "worker-a",
        "target_id": request["target_id"],
        "generation_id": request["generation_id"],
        "code_hash": request["code_hash"],
        "monitoring_fingerprint": request["monitoring_fingerprint"],
        "policy_fingerprint": request["policy_fingerprint"],
        "authority_policy_generation": request["authority_policy_generation"],
        "authority_policy_fingerprint": request["authority_policy_fingerprint"],
        "applied": True,
        "observed_level": "BEHAVIOR",
    }
    assert store.acknowledge_transition(ack, peer_pid=101)["transition_status"] == "PARTIAL"
    assert store.acknowledge_transition(
        {**ack, "worker_id": "worker-b"},
        peer_pid=101,
    )["transition_status"] == "APPLIED"
    assert store.list_transition_requests()[0]["status"] == "APPLIED"
    assert store.acknowledge_transition(ack, peer_pid=101)["status"] == "DUPLICATE"

    with pytest.raises(PermissionError, match="peer process"):
        store.acknowledge_transition(
            {**ack, "request_id": request["request_id"]},
            peer_pid=202,
        )

    evaluated = store.evaluate_promotions(
        **context,
        promotion_policies={"example.target": promotion_policy},
    )
    assert evaluated["proposals_created"] == 1
    proposal = next(
        item
        for item in store.list_transition_requests()
        if item["request_kind"] == "ADAPTIVE_REPAIR_PROPOSAL"
    )
    assert proposal["status"] == "PROPOSAL_ONLY"
    assert proposal["requested_level"] == "REPAIR"
    with pytest.raises(PermissionError, match="Behavior promotion"):
        store.acknowledge_transition(ack | {"request_id": proposal["request_id"]}, peer_pid=101)


def test_aggregated_exception_threshold_waits_for_supervisor_request(tmp_path: Path):
    policy = LightweightPolicy(
        exception=ExceptionPromotionPolicy(
            enabled=True,
            occurrences=1,
            window_seconds=3600,
            promote_to=InstrumentationLevel.BEHAVIOR,
        ),
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

    @lightweight(policy=policy, target_id="aggregation.supervised", state_directory=tmp_path / "adaptive")
    def observed() -> None:
        raise RuntimeError("expected test signal")

    with pytest.raises(RuntimeError, match="expected test signal"):
        observed()
    controller = observed.__caretaker_adaptive__
    assert controller.state.level is InstrumentationLevel.LIGHTWEIGHT
    status = controller.aggregation_status()
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    context = {
        "current_generations": {"aggregation.supervised": controller.code_hash},
        "policy_fingerprints": {"aggregation.supervised": status["policy_fingerprint"]},
        "authority_policy_generation": status["authority_policy_generation"],
        "authority_policy_fingerprint": status["authority_policy_fingerprint"],
    }
    assert store.reconcile(**context)["merged"] == 1
    evaluated = store.evaluate_promotions(
        **context,
        promotion_policies={"aggregation.supervised": status["promotion_policy"]},
    )
    assert evaluated["created"] == 1
    request = store.list_transition_requests()[0]
    with pytest.raises(PermissionError, match="Behavior only"):
        controller.apply_supervisor_transition({**request, "requested_level": "REPAIR"})
    verified_context = {
        "current_generations": {"aggregation.supervised": controller.code_hash},
        "policy_fingerprints": {
            "aggregation.supervised": status["policy_fingerprint"]
        },
        "authority_policy_generation": status["authority_policy_generation"],
        "authority_policy_fingerprint": status["authority_policy_fingerprint"],
    }
    assert store.list_transition_requests(**verified_context)[0]["context_status"] == "CURRENT"
    stale_context = {
        **verified_context,
        "policy_fingerprints": {"aggregation.supervised": "policy-changed"},
    }
    assert store.list_transition_requests(**stale_context)[0]["context_status"] == "STALE_POLICY"
    with pytest.raises(PermissionError, match="stale: STALE_POLICY"):
        store.acknowledge_transition(
            {
                **request,
                "worker_id": "worker-a",
                "applied": True,
                "observed_level": "BEHAVIOR",
            },
            peer_pid=101,
            **stale_context,
        )
    applied = controller.apply_supervisor_transition(request)
    assert applied["applied"] is True
    assert applied["changed"] is True
    assert controller.state.level is InstrumentationLevel.BEHAVIOR


def test_adaptive_transition_helpers_keep_context_explicit(monkeypatch):
    from caretaker.logging import ipc

    captured: list[tuple[object, dict[str, object], float]] = []

    def fake_control_request(path, request, *, timeout):
        captured.append((path, request, timeout))
        return {"ok": True}

    monkeypatch.setattr(ipc, "control_request", fake_control_request)
    ipc.list_adaptive_transition_requests(
        "/run/caretaker/control.sock",
        worker_id="worker-a",
        target_id="example.target",
        limit=3,
    )
    ipc.acknowledge_adaptive_transition(
        "/run/caretaker/control.sock",
        request_id="request-1",
        worker_id="worker-a",
        target_id="example.target",
        generation_id="generation-a",
        code_hash="code-a",
        monitoring_fingerprint="monitoring-a",
        policy_fingerprint="policy-a",
        authority_policy_generation="7",
        authority_policy_fingerprint="authority-a",
        applied=True,
        observed_level="BEHAVIOR",
    )

    assert captured[0][1] == {
        "command": "adaptive-transition-list",
        "worker_id": "worker-a",
        "target_id": "example.target",
        "limit": 3,
    }
    assert captured[1][1]["command"] == "adaptive-transition-ack"
    assert "requested_level" not in captured[1][1]


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
    assert store.acknowledgement(str(batch["batch_id"]))["status"] == "REJECTED"


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

    assert batcher.record(
        behavior_observation_calls=1,
        resource_values={"cpu_seconds": 0.25},
    ) is None
    result = batcher.record(
        behavior_samples=1,
        resource_values={"cpu_seconds": 0.75},
    )

    assert result is not None
    assert result["status"] == "QUEUED"
    assert result["batch_id"]
    assert batcher.status()["pending_records"] == 0
    assert store.reconcile(**_context())["merged"] == 1
    aggregate = store.list_aggregates()[0]
    assert aggregate["total_observations"] == 2
    assert aggregate["workers"]["worker-a"]["first_sequence"] == 1
    assert aggregate["workers"]["worker-a"]["last_sequence"] == 2
    resource = aggregate["workers"]["worker-a"]["resource_statistics"]["cpu_seconds"]
    assert resource["count"] == 2
    assert resource["mean"] == 0.5


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
