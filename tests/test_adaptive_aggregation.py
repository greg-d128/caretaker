from __future__ import annotations

import json
import multiprocessing
import queue
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from caretaker.adaptive_aggregation import (
    AdaptiveAggregationBackpressureAction,
    AdaptiveAggregationError,
    AdaptiveObservationBatcher,
    QueueAdaptiveAggregationStore,
    RemoteAdaptiveAggregationStore,
    SupervisorAdaptiveAggregationStore,
    compare_adaptive_populations,
    extended_aggregation_target_id,
    normalize_adaptive_observation_batch,
    verify_adaptive_population_comparison_report,
)
from caretaker.run import (
    _emit_adaptive_aggregation_audit,
    _adaptive_threshold_policy_settings,
    _handle_adaptive_observation_submission,
)
from caretaker.adaptive import (
    AdaptiveAggregationPolicy,
    AdaptiveAggregationTransport,
    BehaviorSamplingPolicy,
    ExceptionPromotionPolicy,
    InstrumentationDemotionPolicy,
    InstrumentationLevel,
    LightweightPolicy,
    lightweight,
    validate_lightweight_policy,
)
from caretaker.authority import get_authority_runtime_context
from caretaker.logging import (
    CaretakerApplicationSupervisor,
    RemoteIncidentCapture,
    WorkerKind,
)


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


def _repair_proposal(store: SupervisorAdaptiveAggregationStore) -> tuple[dict[str, object], dict[str, str]]:
    """Create a complete supervisor Repair-evidence proposal for handoff tests."""
    first = _batch(batch_id="00000000-0000-0000-0000-000000000101")
    second = _batch(
        batch_id="00000000-0000-0000-0000-000000000102",
        worker_id="worker-b",
    )
    store.submit(first)
    store.submit(second)
    reconcile_context = _context()
    store.reconcile(**reconcile_context)
    context = {
        "current_generations": {"example.target": "generation-a"},
        "policy_fingerprints": {"example.target": "policy-a"},
        "authority_policy_generation": "7",
        "authority_policy_fingerprint": "authority-a",
    }
    policy = {
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
    store.evaluate_promotions(
        **reconcile_context,
        promotion_policies={"example.target": policy},
    )
    transition = next(
        item
        for item in store.list_transition_requests()
        if item["request_kind"] == "ADAPTIVE_PROMOTION"
    )
    ack = {
        "request_id": transition["request_id"],
        "worker_id": "worker-a",
        "target_id": transition["target_id"],
        "generation_id": transition["generation_id"],
        "code_hash": transition["code_hash"],
        "monitoring_fingerprint": transition["monitoring_fingerprint"],
        "policy_fingerprint": transition["policy_fingerprint"],
        "authority_policy_generation": transition["authority_policy_generation"],
        "authority_policy_fingerprint": transition["authority_policy_fingerprint"],
        "applied": True,
        "observed_level": "BEHAVIOR",
    }
    store.acknowledge_transition(ack, peer_pid=101, **context)
    store.acknowledge_transition({**ack, "worker_id": "worker-b"}, peer_pid=101, **context)
    store.evaluate_promotions(
        **reconcile_context,
        promotion_policies={"example.target": policy},
    )
    proposal = next(
        item
        for item in store.list_transition_requests()
        if item["request_kind"] == "ADAPTIVE_REPAIR_PROPOSAL"
    )
    return proposal, context


def test_fixed_scoped_threshold_activation_targets_only_that_population():
    settings = _adaptive_threshold_policy_settings(
        {"exception.occurrences": 2},
        target_id="example.target",
        aggregation_scope="cluster:blue",
        scope_resolution="FIXED",
    )
    assert len(settings) == 1
    assert settings[0].target == extended_aggregation_target_id(
        "example.target", "cluster:blue"
    )


def test_resolver_scoped_exception_threshold_targets_that_population():
    settings = _adaptive_threshold_policy_settings(
        {"exception.occurrences": 2},
        target_id="example.target",
        aggregation_scope="cluster:blue",
        scope_resolution="RESOLVER",
    )
    assert len(settings) == 1
    assert settings[0].target == extended_aggregation_target_id(
        "example.target", "cluster:blue"
    )


def test_resolver_scoped_repair_evidence_threshold_remains_fail_closed():
    with pytest.raises(ValueError, match="only exception and soft-timing thresholds"):
        _adaptive_threshold_policy_settings(
            {"repair_evidence.minimum_behavior_samples": 2},
            target_id="example.target",
            aggregation_scope="cluster:blue",
            scope_resolution="RESOLVER",
        )

    settings = _adaptive_threshold_policy_settings(
        {"exception.occurrences": 2},
        target_id="example.target",
    )
    assert len(settings) == 1
    assert settings[0].target == "example.target"


def _population_aggregate(
    scope: str,
    *,
    total_observations: int = 40,
    exception_count: int = 4,
    code_hash: str = "code-a",
) -> dict[str, object]:
    target_id = "example.target"
    aggregation_target_id = extended_aggregation_target_id(target_id, scope)
    return {
        "schema_version": 1,
        "aggregate_key": aggregation_target_id,
        "target_id": target_id,
        "aggregation_scope": scope,
        "aggregation_target_id": aggregation_target_id,
        "generation_id": "generation-a",
        "code_hash": code_hash,
        "monitoring_fingerprint": "monitoring-a",
        "policy_fingerprint": "policy-a",
        "authority_policy_generation": "7",
        "authority_policy_fingerprint": "authority-a",
        "first_observed_at": "2026-08-30T12:00:00+00:00",
        "last_observed_at": "2026-08-30T12:01:00+00:00",
        "total_observations": total_observations,
        "exception_count": exception_count,
        "timing_breach_count": 2,
        "behavior_observation_calls": total_observations,
        "behavior_samples": 20,
        "repair_evidence_samples": 10,
        "problem_reproductions": 2,
        "successful_executions": total_observations - 2,
        "failed_executions": 2,
        "timing_duration_statistics": {
            "count": total_observations,
            "mean": 1.0,
            "m2": 4.0,
            "minimum": 0.5,
            "maximum": 1.5,
        },
        "workers": {"worker-a": {"observations": total_observations}},
    }


def test_cross_population_comparison_retains_scopes_and_is_evidence_only() -> None:
    left = _population_aggregate("cluster:blue")
    right = _population_aggregate("cluster:red")

    report = compare_adaptive_populations([left, right])

    assert report["status"] == "COMPARABLE"
    assert report["authority_granted"] is False
    assert report["evidence_only"] is True
    assert {item["aggregation_scope"] for item in report["populations"]} == {
        "cluster:blue",
        "cluster:red",
    }
    assert report["conflict_count"] == 0
    assert report["content_sha256"]
    assert verify_adaptive_population_comparison_report(report)["valid"] is True
    assert left["aggregation_scope"] == "cluster:blue"
    assert right["aggregation_scope"] == "cluster:red"


def test_cross_population_comparison_reports_three_sigma_conflict() -> None:
    left = _population_aggregate("cluster:blue", exception_count=0)
    right = _population_aggregate("cluster:red", exception_count=40)

    report = compare_adaptive_populations([left, right])

    assert report["status"] == "DISTRIBUTION_CONFLICT"
    exception_conflicts = [
        item for item in report["comparisons"]
        if item["metric"] == "exception_rate" and item["conflict"]
    ]
    assert exception_conflicts
    assert exception_conflicts[0]["z_score"] > 3.0
    assert report["authority_granted"] is False


def test_cross_population_comparison_fails_closed_for_insufficient_evidence() -> None:
    report = compare_adaptive_populations([
        _population_aggregate("cluster:blue", total_observations=2, exception_count=0),
        _population_aggregate("cluster:red", total_observations=2, exception_count=1),
    ])

    assert report["status"] == "INCOMPLETE_EVIDENCE"
    assert report["comparisons"] == []
    assert report["incomplete_metrics"]
    assert report["authority_granted"] is False


def test_cross_population_comparison_rejects_mixed_contexts() -> None:
    left = _population_aggregate("cluster:blue")
    right = _population_aggregate("cluster:red", code_hash="code-b")

    report = compare_adaptive_populations([left, right])

    assert report["status"] == "INCOMPLETE_EVIDENCE"
    assert report["comparisons"] == []
    assert "selected populations have different comparison contexts" in report["reasons"]
    assert report["comparison_context"] is None


def test_cross_population_comparison_hash_detects_tampering() -> None:
    report = compare_adaptive_populations([
        _population_aggregate("cluster:blue"),
        _population_aggregate("cluster:red"),
    ])
    tampered = dict(report)
    tampered["status"] = "DISTRIBUTION_CONFLICT"

    verification = verify_adaptive_population_comparison_report(tampered)

    assert verification["valid"] is False
    assert verification["status"] == "INVALID"


def test_remote_adaptive_store_submits_bounded_batch_to_supervisor(monkeypatch):
    batch = _batch(batch_id="00000000-0000-0000-0000-0000000000aa")
    calls = []

    def fake_control_request(path, request, *, timeout):
        calls.append((path, request, timeout))
        return {"ok": True, "result": {"status": "QUEUED", "batch_id": batch["batch_id"]}}

    monkeypatch.setattr("caretaker.logging.ipc.control_request", fake_control_request)
    result = RemoteAdaptiveAggregationStore("/run/caretaker/control.sock").submit(batch)

    assert result == {"status": "QUEUED", "batch_id": batch["batch_id"]}
    assert calls[0][1]["command"] == "adaptive-observation-submit"
    assert calls[0][1]["batch"]["schema_version"] == 1
    assert calls[0][1]["batch"]["batch_id"] == batch["batch_id"]


def test_supervisor_adaptive_intake_binds_batch_worker_pid_to_peer():
    batch = _batch(batch_id="00000000-0000-0000-0000-0000000000ab")
    submitted = []

    class Store:
        def submit(self, value):
            submitted.append(value)
            return {"status": "QUEUED", "batch_id": value["batch_id"]}

    response = _handle_adaptive_observation_submission(
        Store(),
        {"command": "adaptive-observation-submit", "batch": batch},
        (101, 1000, 1000),
        type("Child", (), {"pid": 101, "poll": lambda self: None})(),
    )
    assert response["ok"] is True
    assert response["transport_peer_pid"] == 101
    assert submitted[0]["worker_pid"] == 101

    with pytest.raises(PermissionError, match="worker_pid"):
        altered = dict(batch)
        altered["worker_pid"] = 202
        _handle_adaptive_observation_submission(
            Store(),
            {"command": "adaptive-observation-submit", "batch": altered},
            (101, 1000, 1000),
            type("Child", (), {"pid": 101, "poll": lambda self: None})(),
        )


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


def test_supervisor_control_cycle_drains_bound_adaptive_worker_queues(tmp_path: Path):
    supervisor = CaretakerApplicationSupervisor(object())
    worker = supervisor.workers.register(WorkerKind.REPAIR_ANALYZER, 4321)
    queue_store = QueueAdaptiveAggregationStore(queue.Queue())
    batch = _batch(
        batch_id="00000000-0000-0000-0000-000000000003",
        worker_id="untrusted-worker-id",
    )
    queue_store.submit(batch)
    store = SupervisorAdaptiveAggregationStore(tmp_path)

    result = supervisor.reconcile_adaptive_aggregation_queues(
        {worker.worker_id: queue_store},
        aggregation_store=store,
        current_generations={"example.target": "generation-a"},
        policy_fingerprint="policy-a",
        authority_policy_generation="7",
        authority_policy_fingerprint="authority-a",
    )

    assert result["ok"] is True
    assert result["authority_granted"] is False
    assert result["drained"] == 1
    assert result["reconciliation"]["merged"] == 1
    aggregate = store.list_aggregates()[0]
    assert list(aggregate["workers"]) == [str(worker.worker_id)]
    assert aggregate["workers"][str(worker.worker_id)]["worker_pid"] == 4321


def test_supervisor_control_cycle_does_not_drain_failed_worker_queue(tmp_path: Path):
    supervisor = CaretakerApplicationSupervisor(object())
    worker = supervisor.workers.register(WorkerKind.REPAIR_ANALYZER, 4321)
    supervisor.workers.mark_failed(worker.worker_id, error_fingerprint="worker-crash")
    queue_store = QueueAdaptiveAggregationStore(queue.Queue())
    queue_store.submit(_batch(batch_id="00000000-0000-0000-0000-000000000004"))
    store = SupervisorAdaptiveAggregationStore(tmp_path)

    with pytest.raises(PermissionError, match="failed or unauthorized"):
        supervisor.reconcile_adaptive_aggregation_queues(
            {worker.worker_id: queue_store},
            aggregation_store=store,
            current_generations={"example.target": "generation-a"},
            policy_fingerprint="policy-a",
            authority_policy_generation="7",
            authority_policy_fingerprint="authority-a",
        )

    assert queue_store.receive() is not None


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


def test_adaptive_rebind_retain_preserves_pending_old_context() -> None:
    store = _BackpressureStore(fail_count=1)
    batcher = _backpressure_batcher(
        store,
        AdaptiveAggregationBackpressureAction.RETAIN,
    )
    batcher.flush_after_observations = 10

    batcher.record(behavior_samples=1)
    result = batcher.rebind(
        target_id="example.target",
        aggregation_scope="cluster:blue",
        generation_id="generation-a",
        code_hash="code-a",
        monitoring_fingerprint="monitoring-a",
        policy_fingerprint="policy-a",
        authority_policy_generation="7",
        authority_policy_fingerprint="authority-a",
    )

    assert result is not None
    assert result["status"] == "DEFERRED"
    assert batcher.status()["pending_records"] == 1
    assert batcher.status()["aggregation_scope"] is None

    result = batcher.rebind(
        target_id="example.target",
        aggregation_scope="cluster:blue",
        generation_id="generation-a",
        code_hash="code-a",
        monitoring_fingerprint="monitoring-a",
        policy_fingerprint="policy-a",
        authority_policy_generation="7",
        authority_policy_fingerprint="authority-a",
    )

    assert result is not None
    assert result["status"] == "QUEUED"
    assert batcher.status()["pending_records"] == 0
    assert batcher.status()["aggregation_scope"] == "cluster:blue"


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


def test_adaptive_backpressure_incident_notifies_once_and_retains_evidence() -> None:
    store = _BackpressureStore(fail_count=2)
    notifications: list[dict[str, object]] = []
    audit_events: list[tuple[str, dict[str, object]]] = []

    def notify(payload):
        notifications.append(dict(payload))
        return {"accepted": True, "incident_id": "incident-123"}

    def audit(event_type, **fields):
        audit_events.append((event_type, dict(fields)))

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
        flush_after_observations=1,
        flush_interval_seconds=0,
        backpressure_action=AdaptiveAggregationBackpressureAction.INCIDENT,
        backpressure_incident_callback=notify,
        backpressure_audit_callback=audit,
    )

    first = batcher.record(
        event_kind="timing",
        duration_seconds=2.5,
        resource_values={"cpu_seconds": 0.5},
        timing_breach_count=1,
    )
    assert first is not None
    assert first["status"] == "INCIDENT_RECORDED"
    assert first["incident_id"] == "incident-123"
    assert batcher.status()["pending_records"] == 1
    assert batcher.status()["backpressure_incident_id"] == "incident-123"
    assert len(notifications) == 1
    assert notifications[0]["batch_id"]
    assert notifications[0]["pending_records"] == 1
    assert "timing_events" not in notifications[0]
    assert "duration_samples" not in notifications[0]
    assert "resource_samples" not in notifications[0]
    assert len(audit_events) == 1
    assert audit_events[0][0] == "ADAPTIVE_AGGREGATION_BACKPRESSURE"
    assert audit_events[0][1]["outcome"]["state"] == "INCIDENT_RECORDED"
    assert audit_events[0][1]["outcome"]["authority_granted"] is False
    assert audit_events[0][1]["scope"]["target_id"] == "example.target"

    second = batcher.flush()
    assert second is not None
    assert second["status"] == "INCIDENT_ALREADY_RECORDED"
    assert len(notifications) == 1
    assert len(audit_events) == 1
    assert batcher.status()["pending_records"] == 1

    queued = batcher.flush()
    assert queued is not None
    assert queued["status"] == "QUEUED"
    assert batcher.status()["pending_records"] == 0
    assert batcher.status()["backpressure_incident_id"] is None


def test_adaptive_backpressure_incident_without_callback_is_explicit_and_retained() -> None:
    batcher = _backpressure_batcher(
        _BackpressureStore(fail_count=1),
        AdaptiveAggregationBackpressureAction.INCIDENT,
    )

    result = batcher.record(behavior_samples=1)

    assert result is not None
    assert result["status"] == "INCIDENT_UNAVAILABLE"
    assert result["accepted"] is False
    assert batcher.status()["pending_records"] == 1
    assert batcher.status()["backpressure_incident_recorded"] is False


@pytest.mark.parametrize("callback", [
    lambda _payload: {"accepted": False},
    lambda _payload: {"accepted": True},
    lambda _payload: (_ for _ in ()).throw(RuntimeError("incident sink failed")),
])
def test_adaptive_backpressure_incident_callback_failure_retains_evidence(callback) -> None:
    batcher = AdaptiveObservationBatcher(
        _BackpressureStore(fail_count=1),
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
        backpressure_action=AdaptiveAggregationBackpressureAction.INCIDENT,
        backpressure_incident_callback=callback,
    )

    result = batcher.record(behavior_samples=1)

    assert result is not None
    assert result["status"] in {"INCIDENT_REJECTED", "INCIDENT_FAILED"}
    assert result["accepted"] is False
    assert batcher.status()["pending_records"] == 1


def test_adaptive_backpressure_audit_callback_failure_is_explicit_and_non_authoritative() -> None:
    def notify(_payload):
        return {"accepted": True, "incident_id": "incident-123"}

    def audit(_event_type, **_fields):
        raise RuntimeError("audit sink unavailable")

    batcher = AdaptiveObservationBatcher(
        _BackpressureStore(fail_count=1),
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
        backpressure_action=AdaptiveAggregationBackpressureAction.INCIDENT,
        backpressure_incident_callback=notify,
        backpressure_audit_callback=audit,
    )

    result = batcher.record(behavior_samples=1)

    assert result is not None
    assert result["status"] == "INCIDENT_RECORDED"
    assert result["audit_status"] == "FAILED"
    assert batcher.status()["pending_records"] == 1
    assert batcher.status()["last_audit_error"] == (
        "RuntimeError: audit sink unavailable"
    )


def test_lightweight_policy_accepts_adaptive_incident_backpressure_action() -> None:
    validate_lightweight_policy(
        LightweightPolicy(
            aggregation=AdaptiveAggregationPolicy(
                backpressure_action=AdaptiveAggregationBackpressureAction.INCIDENT
            )
        )
    )


def test_lightweight_forwards_adaptive_backpressure_incident_callback(tmp_path: Path) -> None:
    def notify(_payload):
        return {"accepted": True, "incident_id": "incident-123"}

    audit_events: list[tuple[str, dict[str, object]]] = []

    def audit(event_type, **fields):
        audit_events.append((event_type, dict(fields)))

    @lightweight(
        policy=LightweightPolicy(
            aggregation=AdaptiveAggregationPolicy(
                enabled=True,
                backpressure_action=AdaptiveAggregationBackpressureAction.INCIDENT,
            )
        ),
        target_id="example.adaptive.callback",
        state_directory=tmp_path,
        backpressure_incident_callback=notify,
        backpressure_audit_callback=audit,
    )
    def sample() -> str:
        return "ok"

    batcher = sample.__caretaker_adaptive__._aggregation_batcher
    assert batcher is not None
    assert batcher.backpressure_incident_callback is notify
    assert batcher.backpressure_audit_callback is audit


def test_lightweight_uses_active_logging_audit_by_default(
    monkeypatch, tmp_path: Path
) -> None:
    audit_events: list[tuple[str, dict[str, object]]] = []

    def audit(event_type, **fields):
        audit_events.append((event_type, dict(fields)))

    class _Audit:
        enabled = True

        emit = staticmethod(audit)

    monkeypatch.setattr(
        "caretaker.logging.handler.get_runtime",
        lambda: type("_Runtime", (), {"audit": _Audit()})(),
    )
    wrapped = lightweight(
        policy=LightweightPolicy(
            aggregation=AdaptiveAggregationPolicy(
                enabled=True,
                backpressure_action=AdaptiveAggregationBackpressureAction.INCIDENT,
            )
        ),
        target_id="example.adaptive.default-audit",
        state_directory=tmp_path,
    )(lambda: "ok")

    batcher = wrapped.__caretaker_adaptive__._aggregation_batcher
    assert batcher is not None
    assert batcher.backpressure_audit_callback is audit


def test_lightweight_uses_supervised_incident_capture_by_default(
    monkeypatch, tmp_path: Path
) -> None:
    capture = RemoteIncidentCapture("/tmp/caretaker-control.sock")
    monkeypatch.setattr(
        "caretaker.logging.handler.get_runtime",
        lambda: type("_Runtime", (), {"incident_capture": capture})(),
    )
    wrapped = lightweight(
        policy=LightweightPolicy(
            aggregation=AdaptiveAggregationPolicy(
                enabled=True,
                backpressure_action=AdaptiveAggregationBackpressureAction.INCIDENT,
            )
        ),
        target_id="example.adaptive.default-incident",
        state_directory=tmp_path,
    )(lambda: "ok")

    batcher = wrapped.__caretaker_adaptive__._aggregation_batcher
    assert batcher is not None
    assert batcher.backpressure_incident_callback is capture


def test_lightweight_explicit_backpressure_incident_callback_wins(
    monkeypatch, tmp_path: Path
) -> None:
    explicit = lambda *_args, **_kwargs: None
    active = RemoteIncidentCapture("/tmp/caretaker-control.sock")
    monkeypatch.setattr(
        "caretaker.logging.handler.get_runtime",
        lambda: type("_Runtime", (), {"incident_capture": active})(),
    )
    wrapped = lightweight(
        policy=LightweightPolicy(
            aggregation=AdaptiveAggregationPolicy(
                enabled=True,
                backpressure_action=AdaptiveAggregationBackpressureAction.INCIDENT,
            )
        ),
        target_id="example.adaptive.explicit-incident",
        state_directory=tmp_path,
        backpressure_incident_callback=explicit,
    )(lambda: "ok")

    batcher = wrapped.__caretaker_adaptive__._aggregation_batcher
    assert batcher is not None
    assert batcher.backpressure_incident_callback is explicit


def test_lightweight_does_not_enable_incident_capture_without_supervisor(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "caretaker.logging.handler.get_runtime",
        lambda: type(
            "_Runtime", (), {"incident_capture": RemoteIncidentCapture(None)}
        )(),
    )
    wrapped = lightweight(
        policy=LightweightPolicy(
            aggregation=AdaptiveAggregationPolicy(
                enabled=True,
                backpressure_action=AdaptiveAggregationBackpressureAction.INCIDENT,
            )
        ),
        target_id="example.adaptive.no-incident-capture",
        state_directory=tmp_path,
    )(lambda: "ok")

    batcher = wrapped.__caretaker_adaptive__._aggregation_batcher
    assert batcher is not None
    assert batcher.backpressure_incident_callback is None


def test_lightweight_explicit_backpressure_audit_callback_wins(
    monkeypatch, tmp_path: Path
) -> None:
    explicit = lambda *_args, **_kwargs: None
    active = lambda *_args, **_kwargs: None
    monkeypatch.setattr(
        "caretaker.logging.handler.get_runtime",
        lambda: type(
            "_Runtime",
            (),
            {"audit": type("_Audit", (), {"enabled": True, "emit": active})()},
        )(),
    )
    wrapped = lightweight(
        policy=LightweightPolicy(
            aggregation=AdaptiveAggregationPolicy(enabled=True)
        ),
        target_id="example.adaptive.explicit-audit",
        state_directory=tmp_path,
        backpressure_audit_callback=explicit,
    )(lambda: "ok")

    batcher = wrapped.__caretaker_adaptive__._aggregation_batcher
    assert batcher is not None
    assert batcher.backpressure_audit_callback is explicit


def test_lightweight_does_not_enable_unconfigured_remote_audit_callback(
    monkeypatch, tmp_path: Path
) -> None:
    active = lambda *_args, **_kwargs: None
    monkeypatch.setattr(
        "caretaker.logging.handler.get_runtime",
        lambda: type(
            "_Runtime",
            (),
            {
                "audit": type(
                    "_Audit", (), {"socket_path": None, "emit": active}
                )()
            },
        )(),
    )
    wrapped = lightweight(
        policy=LightweightPolicy(
            aggregation=AdaptiveAggregationPolicy(enabled=True)
        ),
        target_id="example.adaptive.no-remote-audit",
        state_directory=tmp_path,
    )(lambda: "ok")

    batcher = wrapped.__caretaker_adaptive__._aggregation_batcher
    assert batcher is not None
    assert batcher.backpressure_audit_callback is None


def test_lightweight_policy_rejects_unknown_adaptive_backpressure_action() -> None:
    with pytest.raises(ValueError, match="backpressure_action"):
        validate_lightweight_policy(
            LightweightPolicy(
                aggregation=AdaptiveAggregationPolicy(backpressure_action="INVALID")
            )
        )


def test_lightweight_policy_rejects_non_boolean_persistent_acceptance() -> None:
    with pytest.raises(ValueError, match="allow_persistent_acceptance"):
        validate_lightweight_policy(
            LightweightPolicy(
                aggregation=AdaptiveAggregationPolicy(
                    allow_persistent_acceptance="yes"
                )
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


def test_approved_threshold_change_records_post_policy_worker_transition(
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
    review_context = {
        "current_generations": {"example.target": "generation-a"},
        "policy_fingerprints": {"example.target": "policy-a"},
        "authority_policy_generation": "7",
        "authority_policy_fingerprint": "authority-a",
    }
    store.review_threshold_proposal(
        proposal["request_id"],
        decision="APPROVE",
        reviewed_by="uid:1001",
        reason="ready for staged policy handling",
        now=created + timedelta(seconds=1),
        **review_context,
    )

    transition = store.create_threshold_policy_transition(
        proposal["request_id"],
        applied_policy_fingerprint="policy-b",
        current_generations={"example.target": "generation-a"},
        current_policy_fingerprints={"example.target": "policy-b"},
        authority_policy_generation="8",
        authority_policy_fingerprint="authority-b",
        required_workers=[{"worker_id": "worker-a", "worker_pid": 101}],
        applied_by="uid:1001",
        reason="authority workflow applied reviewed threshold",
        authority_lease_id="00000000-0000-0000-0000-000000000008",
        now=created + timedelta(seconds=2),
    )

    assert transition["request_kind"] == "ADAPTIVE_POLICY_TRANSITION"
    assert transition["status"] == "PENDING"
    assert transition["previous_policy_fingerprint"] == "policy-a"
    assert transition["policy_fingerprint"] == "policy-b"
    assert transition["requested_level"] == "POLICY"
    assert transition["policy_applied"] is True
    assert transition["authority_granted"] is False
    assert transition["authority_lease_id"] == "00000000-0000-0000-0000-000000000008"

    acknowledgement = store.acknowledge_transition(
        {
            **transition,
            "worker_id": "worker-a",
            "applied": True,
            "observed_level": "POLICY",
        },
        peer_pid=101,
        current_generations={"example.target": "generation-a"},
        policy_fingerprints={"example.target": "policy-b"},
        authority_policy_generation="8",
        authority_policy_fingerprint="authority-b",
    )
    assert acknowledgement["transition_status"] == "APPLIED"
    listed = store.list_transition_requests(
        current_generations={"example.target": "generation-a"},
        policy_fingerprints={"example.target": "policy-b"},
        authority_policy_generation="8",
        authority_policy_fingerprint="authority-b",
    )
    policy_transitions = [
        item for item in listed
        if item.get("request_kind") == "ADAPTIVE_POLICY_TRANSITION"
    ]
    assert len(policy_transitions) == 1
    assert policy_transitions[0]["status"] == "APPLIED"


def test_adaptive_policy_transition_rollback_is_idempotent_and_pre_acceptance_only(
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
    review_context = {
        "current_generations": {"example.target": "generation-a"},
        "policy_fingerprints": {"example.target": "policy-a"},
        "authority_policy_generation": "7",
        "authority_policy_fingerprint": "authority-a",
    }
    store.review_threshold_proposal(
        proposal["request_id"],
        decision="APPROVE",
        reviewed_by="uid:1001",
        reason="ready for staged policy handling",
        now=created + timedelta(seconds=1),
        **review_context,
    )
    transition = store.create_threshold_policy_transition(
        proposal["request_id"],
        applied_policy_fingerprint="policy-b",
        current_generations={"example.target": "generation-a"},
        current_policy_fingerprints={"example.target": "policy-b"},
        authority_policy_generation="8",
        authority_policy_fingerprint="authority-b",
        required_workers=[{"worker_id": "worker-a", "worker_pid": 101}],
        applied_by="uid:1001",
        reason="apply reviewed threshold",
        authority_lease_id="00000000-0000-0000-0000-000000000008",
        now=created + timedelta(seconds=2),
    )

    rollback = store.record_transition_rollback(
        transition["request_id"],
        rolled_back_by="uid:1001",
        reason="worker verification did not complete",
        authority_lease_id=transition["authority_lease_id"],
        now=created + timedelta(seconds=3),
    )
    assert rollback["status"] == "ROLLED_BACK"
    assert rollback["policy_applied"] is False
    duplicate = store.record_transition_rollback(
        transition["request_id"],
        rolled_back_by="uid:1001",
        reason="worker verification did not complete",
        authority_lease_id=transition["authority_lease_id"],
        now=created + timedelta(seconds=4),
    )
    assert duplicate["duplicate"] is True
    listed = store.list_transition_requests(
        current_generations={"example.target": "generation-a"},
        policy_fingerprints={"example.target": "policy-b"},
        authority_policy_generation="8",
        authority_policy_fingerprint="authority-b",
    )
    transition_view = next(
        item for item in listed if item["request_kind"] == "ADAPTIVE_POLICY_TRANSITION"
    )
    assert transition_view["status"] == "ROLLED_BACK"
    assert transition_view["rollback_status"] == "ROLLED_BACK"
    with pytest.raises(PermissionError, match="rolled back"):
        store.acknowledge_transition(
            {
                **transition,
                "worker_id": "worker-a",
                "applied": True,
                "observed_level": "POLICY",
            },
            peer_pid=101,
            current_generations={"example.target": "generation-a"},
            policy_fingerprints={"example.target": "policy-b"},
            authority_policy_generation="8",
            authority_policy_fingerprint="authority-b",
        )

    applied_proposal = store.create_threshold_proposal(
        target_id="example.other",
        generation_id="generation-a",
        code_hash="code-a",
        monitoring_fingerprint="monitoring-a",
        policy_fingerprint="policy-a",
        authority_policy_generation="7",
        authority_policy_fingerprint="authority-a",
        changes={"exception.occurrences": 4},
        requested_by="operator:test",
        reason="review another threshold",
        expires_in_seconds=3600,
    )
    applied_created = datetime.fromisoformat(applied_proposal["created_at"])
    store.review_threshold_proposal(
        applied_proposal["request_id"],
        decision="APPROVE",
        reviewed_by="uid:1001",
        reason="ready",
        now=applied_created + timedelta(seconds=1),
        current_generations={"example.other": "generation-a"},
        policy_fingerprints={"example.other": "policy-a"},
        authority_policy_generation="7",
        authority_policy_fingerprint="authority-a",
    )
    accepted = store.create_threshold_policy_transition(
        applied_proposal["request_id"],
        applied_policy_fingerprint="policy-b",
        current_generations={"example.other": "generation-a"},
        current_policy_fingerprints={"example.other": "policy-b"},
        authority_policy_generation="8",
        authority_policy_fingerprint="authority-b",
        required_workers=[{"worker_id": "worker-b", "worker_pid": 102}],
        applied_by="uid:1001",
        reason="apply reviewed threshold",
        now=applied_created + timedelta(seconds=2),
    )
    store.acknowledge_transition(
        {
            **accepted,
            "worker_id": "worker-b",
            "applied": True,
            "observed_level": "POLICY",
        },
        peer_pid=102,
        current_generations={"example.other": "generation-a"},
        policy_fingerprints={"example.other": "policy-b"},
        authority_policy_generation="8",
        authority_policy_fingerprint="authority-b",
    )
    with pytest.raises(PermissionError, match="new incident"):
        store.record_transition_rollback(
            accepted["request_id"],
            rolled_back_by="uid:1001",
            reason="too late",
            now=applied_created + timedelta(seconds=3),
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


def test_archived_batch_revalidation_is_durable_and_does_not_modify_aggregate(
    tmp_path: Path,
) -> None:
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    batch = _batch(batch_id="00000000-0000-0000-0000-000000000013")
    store.submit(batch)
    assert store.reconcile(**_context())["merged"] == 1
    archive_path = next(store.archive_directory.glob("*.json"))
    original_archive = archive_path.read_bytes()
    original_aggregate = store.list_aggregates()[0]

    def validate_against_new_policy(
        archived: dict[str, object], requested_policy: str
    ) -> dict[str, object]:
        return {
            "valid": archived["policy_fingerprint"] == "policy-a"
            and requested_policy == "policy-b",
            "reason": "historical policy transition was reviewed",
            "checks": {"source_policy": archived["policy_fingerprint"]},
        }

    result = store.revalidate_archived_batches(
        policy_fingerprint="policy-b",
        validator=validate_against_new_policy,
        validator_id="operator-review-v1",
    )
    assert result["status"] == "COMPLETED"
    assert result["checked_count"] == 1
    report = result["reports"][0]
    assert report["status"] == "VALIDATED"
    assert report["source_policy_fingerprint"] == "policy-a"
    assert report["requested_policy_fingerprint"] == "policy-b"
    assert report["authority_granted"] is False
    assert report["aggregate_modified"] is False
    assert archive_path.read_bytes() == original_archive
    assert store.list_aggregates()[0] == original_aggregate
    assert store.status()["revalidations"] == 1

    repeated = store.revalidate_archived_batches(
        policy_fingerprint="policy-b",
        validator=validate_against_new_policy,
        validator_id="operator-review-v1",
    )
    assert repeated["reports"][0]["duplicate"] is True
    assert len(store.list_batch_revalidations()) == 1


def test_archived_batch_revalidation_without_validator_marks_different_policy_unchecked(
    tmp_path: Path,
) -> None:
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    batch = _batch(batch_id="00000000-0000-0000-0000-000000000014")
    store.submit(batch)
    store.reconcile(**_context())

    result = store.revalidate_archived_batches(policy_fingerprint="policy-b")

    assert result["reports"][0]["status"] == "REVALIDATION_REQUIRED"
    assert result["reports"][0]["validator_id"] == "identity-only"
    assert result["authority_granted"] is False
    assert result["aggregate_modified"] is False


def test_archived_batch_revalidation_emits_output_only_audit_event(
    tmp_path: Path,
) -> None:
    events: list[dict[str, object]] = []

    def audit_event(event_type: str, **fields: object) -> None:
        events.append({"event_type": event_type, **fields})

    store = SupervisorAdaptiveAggregationStore(tmp_path, audit_event=audit_event)
    batch = _batch(batch_id="00000000-0000-0000-0000-000000000015")
    store.submit(batch)
    store.reconcile(**_context())
    store.revalidate_archived_batches(policy_fingerprint="policy-a")

    event = next(item for item in events if item["event_type"] == "ADAPTIVE_BATCH_REVALIDATED")
    assert event["scope"]["batch_id"] == batch["batch_id"]
    assert event["outcome"]["state"] == "MATCHED_POLICY"
    assert event["outcome"]["authority_granted"] is False
    assert event["details"]["aggregate_modified"] is False


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


def test_adaptive_repair_proposal_review_and_handoff_are_context_bound(tmp_path: Path):
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    proposal, context = _repair_proposal(store)

    review = store.review_repair_proposal(
        str(proposal["request_id"]),
        decision="APPROVE",
        reviewed_by="uid:1001",
        reason="operator reviewed the retained application-wide evidence",
        **context,
    )
    assert review["review_status"] == "APPROVED_FOR_REPAIR_HANDOFF"
    assert review["policy_mutated"] is False
    assert review["authority_granted"] is False

    dispatched: list[dict[str, object]] = []

    def dispatch(handoff):
        dispatched.append(dict(handoff))
        return {"accepted": True, "queued": True}

    handoff = store.create_adaptive_repair_handoff(
        str(proposal["request_id"]),
        promoted_by="uid:1001",
        reason="begin ordinary Repair evaluation under operator authority",
        dispatch_callback=dispatch,
        **context,
    )
    assert handoff["status"] == "DISPATCHED"
    assert handoff["outcome"]["accepted"] is True
    assert handoff["policy_mutated"] is False
    assert handoff["authority_granted"] is False
    assert len(dispatched) == 1

    duplicate = store.create_adaptive_repair_handoff(
        str(proposal["request_id"]),
        promoted_by="uid:1001",
        reason="retry must not dispatch twice",
        dispatch_callback=lambda _: pytest.fail("duplicate handoff was dispatched"),
        **context,
    )
    assert duplicate["duplicate"] is True
    assert duplicate["status"] == "DISPATCHED"
    listed = store.list_transition_requests(**context)
    listed_proposal = next(
        item
        for item in listed
        if item["request_kind"] == "ADAPTIVE_REPAIR_PROPOSAL"
    )
    assert listed_proposal["review_status"] == "APPROVED_FOR_REPAIR_HANDOFF"
    assert listed_proposal["handoff_status"] == "DISPATCHED"

    with pytest.raises(PermissionError, match="STALE_POLICY"):
        store.create_adaptive_repair_handoff(
            str(proposal["request_id"]),
            promoted_by="uid:1001",
            reason="stale context must fail closed",
            current_generations=context["current_generations"],
            policy_fingerprints={"example.target": "policy-b"},
            authority_policy_generation=context["authority_policy_generation"],
            authority_policy_fingerprint=context["authority_policy_fingerprint"],
        )


def test_adaptive_repair_proposal_rejects_handoff_without_review(tmp_path: Path):
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    proposal, context = _repair_proposal(store)
    with pytest.raises(PermissionError, match="approved operator review"):
        store.create_adaptive_repair_handoff(
            str(proposal["request_id"]),
            promoted_by="uid:1001",
            reason="must review first",
            **context,
        )


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


def test_application_scope_resolver_keeps_population_batches_separate(tmp_path: Path):
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

    @lightweight(
        policy=policy,
        target_id="aggregation.scoped",
        state_directory=tmp_path / "adaptive",
        aggregation_scope_resolver=lambda args, kwargs: f"cluster:{args[0]}",
    )
    def observed(cluster: str) -> str:
        return cluster

    assert observed("blue") == "blue"
    assert observed("red") == "red"
    controller = observed.__caretaker_adaptive__
    controller._aggregation_batcher.flush()
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    status = controller.aggregation_status()
    context = {
        "current_generations": {
            extended_aggregation_target_id("aggregation.scoped", "cluster:blue"):
            controller.code_hash,
            extended_aggregation_target_id("aggregation.scoped", "cluster:red"):
            controller.code_hash,
        },
        "policy_fingerprints": {
            extended_aggregation_target_id("aggregation.scoped", "cluster:blue"):
            status["policy_fingerprint"],
            extended_aggregation_target_id("aggregation.scoped", "cluster:red"):
            status["policy_fingerprint"],
        },
        "authority_policy_generation": status["authority_policy_generation"],
        "authority_policy_fingerprint": status["authority_policy_fingerprint"],
    }

    assert store.reconcile(**context)["merged"] == 4
    aggregates = store.list_aggregates()
    assert {
        (item["target_id"], item["aggregation_scope"])
        for item in aggregates
    } == {
        ("aggregation.scoped", "cluster:blue"),
        ("aggregation.scoped", "cluster:red"),
    }


def test_application_scope_resolver_keeps_threshold_windows_separate_and_persistent(
    tmp_path: Path,
):
    policy = LightweightPolicy(
        exception=ExceptionPromotionPolicy(
            enabled=True,
            occurrences=2,
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
    )

    @lightweight(
        policy=policy,
        target_id="aggregation.scoped-thresholds",
        state_directory=tmp_path / "adaptive",
        aggregation_scope_resolver=lambda args, kwargs: f"cluster:{args[0]}",
    )
    def observed(cluster: str) -> None:
        raise RuntimeError(cluster)

    for cluster in ("blue", "red"):
        with pytest.raises(RuntimeError, match=cluster):
            observed(cluster)

    controller = observed.__caretaker_adaptive__
    assert controller.state.level is InstrumentationLevel.LIGHTWEIGHT
    assert len(controller._scope_exception_events["cluster:blue"]) == 1
    assert len(controller._scope_exception_events["cluster:red"]) == 1

    assert controller._state_path is not None
    persisted = json.loads(controller._state_path.read_text(encoding="utf-8"))
    assert set(persisted["resolved_scopes"]) == {"cluster:blue", "cluster:red"}
    assert set(persisted["scope_exception_events"]) == {
        "cluster:blue",
        "cluster:red",
    }
    assert {
        (
            item["aggregation_scope"],
            item["aggregation_scope_mode"],
            item["aggregation_target_id"],
        )
        for item in controller.aggregation_status()["scope_contexts"]
    } == {
        (
            "cluster:blue",
            "RESOLVER",
            extended_aggregation_target_id(
                "aggregation.scoped-thresholds", "cluster:blue"
            ),
        ),
        (
            "cluster:red",
            "RESOLVER",
            extended_aggregation_target_id(
                "aggregation.scoped-thresholds", "cluster:red"
            ),
        ),
    }

    with pytest.raises(RuntimeError, match="blue"):
        observed("blue")
    assert controller.state.level is InstrumentationLevel.BEHAVIOR


def test_application_scope_resolver_failure_suppresses_only_scope_evidence(
    tmp_path: Path,
):
    policy = LightweightPolicy(
        initial_level=InstrumentationLevel.BEHAVIOR,
        aggregation=AdaptiveAggregationPolicy(
            enabled=True,
            flush_after_observations=1,
            flush_interval_seconds=0,
        ),
    )

    def failing_scope(args, kwargs):
        raise RuntimeError("scope unavailable")

    @lightweight(
        policy=policy,
        target_id="aggregation.scope-failure",
        state_directory=tmp_path / "adaptive",
        aggregation_scope_resolver=failing_scope,
    )
    def observed(value: int) -> int:
        return value + 1

    assert observed(1) == 2
    controller = observed.__caretaker_adaptive__
    assert controller.state.recent_diagnostics[-1]["kind"] == (
        "aggregation-scope-unavailable"
    )
    assert controller._aggregation_batcher.status()["pending_records"] == 0


def test_adaptive_aggregation_audit_projection_is_bounded_and_non_authoritative():
    class Audit:
        def __init__(self) -> None:
            self.events = []

        def emit(self, event_type, **fields):
            self.events.append((event_type, fields))

    class Runtime:
        def __init__(self) -> None:
            self.audit = Audit()
            self.effective = type("Effective", (), {
                "generation": 4,
                "fingerprint": "policy-fingerprint",
            })()

    runtime = Runtime()
    _emit_adaptive_aggregation_audit(
        runtime,
        {
            "merged": 2,
            "duplicates": 1,
            "rejected": 0,
            "conflicts": 1,
            "conflict_reports": 1,
            "errors": [],
            "pending": 3,
            "promotions": {"created": 1, "proposals_created": 1},
        },
        actor_type="operator",
        actor_id="uid:1001",
    )

    assert len(runtime.audit.events) == 2
    event_type, fields = runtime.audit.events[0]
    assert event_type == "ADAPTIVE_AGGREGATION_RECONCILED"
    assert fields["actor"] == {"type": "operator", "id": "uid:1001"}
    assert fields["scope"] == {"aggregation_scope": "application"}
    assert fields["outcome"] == {
        "state": "RECONCILED",
        "authority_granted": False,
    }
    assert fields["details"]["merged"] == 2
    assert fields["details"]["promotion_requests_created"] == 1
    proposal_type, proposal_fields = runtime.audit.events[1]
    assert proposal_type == "ADAPTIVE_REPAIR_PROPOSAL"
    assert proposal_fields["actor"] == {"type": "operator", "id": "uid:1001"}
    assert proposal_fields["scope"] == {"aggregation_scope": "application"}
    assert proposal_fields["outcome"] == {
        "state": "PROPOSAL_ONLY",
        "authority_granted": False,
    }
    assert proposal_fields["details"] == {
        "proposal_count": 1,
        "promotion_requests_created": 1,
        "authority_granted": False,
    }


def test_application_queue_transport_round_trips_and_hashes_messages() -> None:
    from caretaker.transport import (
        ApplicationLocalQueueTransport,
        ApplicationTransportError,
    )

    channel = queue.Queue(maxsize=1)
    transport = ApplicationLocalQueueTransport(channel)
    sent = transport.send("evidence", {"value": 3})
    message = transport.receive()

    assert message is not None
    assert message["message_id"] == sent["message_id"]
    assert message["payload"] == {"value": 3}
    assert message["content_sha256"] == sent["content_sha256"]

    transport.send("evidence", {"value": 4})
    with pytest.raises(ApplicationTransportError, match="queue is full"):
        transport.send("evidence", {"value": 5})


def test_application_queue_transport_rejects_tampered_or_non_bytes_messages() -> None:
    from caretaker.transport import ApplicationLocalQueueTransport, ApplicationTransportError

    channel = queue.Queue()
    transport = ApplicationLocalQueueTransport(channel)
    transport.send("evidence", {"value": 3})
    raw = channel.get_nowait()
    envelope = json.loads(raw)
    envelope["payload"]["value"] = 4
    channel.put_nowait(json.dumps(envelope).encode())
    with pytest.raises(ApplicationTransportError, match="payload hash is invalid"):
        transport.receive()

    channel.put_nowait({"not": "bytes"})
    with pytest.raises(ApplicationTransportError, match="message must be bytes"):
        transport.receive()


def test_application_queue_transport_supports_application_multiprocessing_queue() -> None:
    from caretaker.transport import ApplicationLocalQueueTransport

    channel = multiprocessing.Queue(maxsize=1)
    try:
        transport = ApplicationLocalQueueTransport(channel)
        transport.send("evidence", {"value": 3})
        message = transport.receive(timeout=1.0)
        assert message is not None
        assert message["payload"] == {"value": 3}
    finally:
        channel.close()
        channel.join_thread()


def test_queue_adaptive_store_preserves_batch_integrity_and_supervisor_ownership(tmp_path: Path) -> None:
    channel = queue.Queue()
    queued = QueueAdaptiveAggregationStore(channel)
    batch = _batch(batch_id="00000000-0000-0000-0000-0000000000f1")

    result = queued.submit(batch)
    received = queued.receive()

    assert result["status"] == "QUEUED"
    assert result["transport"] == "QUEUE"
    assert received == normalize_adaptive_observation_batch(batch)

    supervisor_store = SupervisorAdaptiveAggregationStore(tmp_path)
    queued.submit(batch)
    drained = queued.drain_to(
        supervisor_store,
        worker_id="bound-worker",
        worker_pid=404,
    )
    assert drained == ({"status": "QUEUED", "batch_id": batch["batch_id"]},)
    assert supervisor_store.status()["pending"] == 1
    pending = next((tmp_path / "adaptive" / "aggregation" / "pending").glob("*.json"))
    stored = json.loads(pending.read_text())
    assert stored["batch"]["worker_id"] == "bound-worker"
    assert stored["batch"]["worker_pid"] == 404

    queued.submit(batch)
    with pytest.raises(ValueError, match="authoritative worker_id and worker_pid"):
        queued.drain_to(supervisor_store)


def test_queue_transport_is_selected_only_when_policy_allows_it(tmp_path: Path) -> None:
    channel = queue.Queue()
    policy = LightweightPolicy(
        aggregation=AdaptiveAggregationPolicy(
            enabled=True,
            transport=AdaptiveAggregationTransport.QUEUE,
        )
    )

    @lightweight(
        policy=policy,
        target_id="aggregation.queue-policy",
        state_directory=tmp_path / "adaptive",
        aggregation_transport=channel,
    )
    def observed(value: int) -> int:
        return value + 1

    controller = observed.__caretaker_adaptive__
    assert controller.aggregation_status()["transport"] == "QUEUE"
    assert controller.aggregation_status()["enabled"] is True

    invalid = LightweightPolicy(
        aggregation=AdaptiveAggregationPolicy(enabled=True, transport="QUEUE")
    )
    with pytest.raises(ValueError, match="aggregation.transport"):
        validate_lightweight_policy(invalid)

    missing_binding = LightweightPolicy(
        aggregation=AdaptiveAggregationPolicy(
            enabled=True,
            transport=AdaptiveAggregationTransport.QUEUE,
        )
    )
    with pytest.raises(ValueError, match="requires an application-owned queue"):
        lightweight(
            policy=missing_binding,
            target_id="aggregation.queue-policy-missing",
            state_directory=tmp_path / "adaptive-missing",
        )(observed.__wrapped__)
