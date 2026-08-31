from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from caretaker.behavior import (
    BehaviorCollectionBudgetExceeded,
    BehaviorCollectionQueueFull,
    BehaviorCollectionScheduler,
)
from caretaker.guard.engine import GuardEngine
from caretaker.guard.policy import BehaviorSnapshotPolicy, GuardBinding, GuardPolicy
from caretaker.operator import OperatorRuntimeRegistry
from caretaker import LightweightPolicy, lightweight


def test_scheduler_orders_operator_requests_by_priority_then_deadline(tmp_path: Path) -> None:
    now = datetime(2026, 8, 30, tzinfo=timezone.utc)
    scheduler = BehaviorCollectionScheduler(
        tmp_path,
        maximum_pending=3,
        clock=lambda: now,
    )
    low = scheduler.enqueue(
        scope="function",
        subject="low",
        requested_calls=10,
        requested_by="uid:1001",
        reason="routine refresh",
        priority=1,
        deadline=(now + timedelta(hours=2)).isoformat(),
    )
    high = scheduler.enqueue(
        scope="function",
        subject="high",
        requested_calls=10,
        requested_by="uid:1001",
        reason="incident follow-up",
        priority=10,
        deadline=(now + timedelta(hours=4)).isoformat(),
    )

    claimed = scheduler.claim_next()

    assert claimed is not None
    assert claimed["request_id"] == high["request_id"]
    scheduler.complete(claimed["request_id"], outcome="CAPTURED", observed_calls=10)
    assert scheduler.claim_next()["request_id"] == low["request_id"]


def test_scheduler_applies_queue_backpressure_and_supports_cancellation(tmp_path: Path) -> None:
    scheduler = BehaviorCollectionScheduler(tmp_path, maximum_pending=1)
    first = scheduler.enqueue(
        scope="module",
        subject="example",
        requested_calls=1,
        requested_by="uid:1001",
        reason="audit",
    )

    with pytest.raises(BehaviorCollectionQueueFull):
        scheduler.enqueue(
            scope="function",
            subject="another",
            requested_calls=1,
            requested_by="uid:1001",
            reason="audit",
        )

    cancelled = scheduler.cancel(first["request_id"], reason="no longer needed")
    assert cancelled["status"] == "CANCELLED"
    replacement = scheduler.enqueue(
        scope="function",
        subject="another",
        requested_calls=1,
        requested_by="uid:1001",
        reason="audit",
    )
    assert replacement["status"] == "QUEUED"


def test_scheduler_recovers_active_request_after_restart(tmp_path: Path) -> None:
    scheduler = BehaviorCollectionScheduler(tmp_path)
    request = scheduler.enqueue(
        scope="function",
        subject="example.target",
        requested_calls=25,
        requested_by="uid:1001",
        reason="incident evidence",
    )
    claimed = scheduler.claim_next(request_id=request["request_id"])
    assert claimed is not None
    assert claimed["status"] == "ACTIVE"

    restarted = BehaviorCollectionScheduler(tmp_path)
    recovered = restarted.list_requests()[0]

    assert recovered["status"] == "QUEUED"
    assert recovered["recovered_after_restart"] is True
    assert restarted.status()["queued"] == 1


def test_scheduler_round_robin_cursor_prevents_automatic_subject_starvation(
    tmp_path: Path,
) -> None:
    scheduler = BehaviorCollectionScheduler(tmp_path)

    first = scheduler.select_fair_automatic_subjects(
        ("target-a", "target-b", "target-c"),
        limit=2,
    )
    assert first == ("target-a", "target-b")

    restarted = BehaviorCollectionScheduler(tmp_path)
    second = restarted.select_fair_automatic_subjects(
        ("target-a", "target-b", "target-c"),
        limit=2,
    )
    assert second == ("target-c", "target-a")
    assert restarted.status()["automatic_fairness"] == "PERSISTED_ROUND_ROBIN"
    assert restarted.status()["automatic_last_subject"] == "target-a"


def test_scheduler_fair_selection_handles_subjects_added_or_removed(tmp_path: Path) -> None:
    scheduler = BehaviorCollectionScheduler(tmp_path)
    assert scheduler.select_fair_automatic_subjects(("target-a", "target-b"), limit=1) == (
        "target-a",
    )
    assert scheduler.select_fair_automatic_subjects(("target-b", "target-c"), limit=1) == (
        "target-b",
    )


def test_scheduler_enforces_observed_duration_budget_and_preserves_queued_work(
    tmp_path: Path,
) -> None:
    scheduler = BehaviorCollectionScheduler(
        tmp_path,
        soft_budget_seconds_per_minute=5.0,
        hard_budget_seconds_per_minute=10.0,
    )
    first = scheduler.enqueue(
        scope="function",
        subject="target-a",
        requested_calls=1,
        requested_by="uid:1001",
        reason="budget test",
    )
    claimed = scheduler.claim_next(request_id=first["request_id"])
    assert claimed is not None
    scheduler.complete(
        claimed["request_id"],
        outcome="CAPTURED",
        duration_seconds=10.0,
    )
    assert scheduler.status()["resource_budget"]["state"] == "HARD_LIMIT"

    second = scheduler.enqueue(
        scope="function",
        subject="target-b",
        requested_calls=1,
        requested_by="uid:1001",
        reason="budget test",
    )
    assert scheduler.claim_next(request_id=second["request_id"]) is None
    with pytest.raises(BehaviorCollectionBudgetExceeded):
        scheduler.execute(
            scope="function",
            subject="target-c",
            requested_calls=1,
            requested_by="uid:1001",
            reason="budget test",
            operation=lambda: {"profile": {"call_count": 1}},
        )
    requests = {
        item["request_id"]: item
        for item in scheduler.list_requests(limit=10)
    }
    assert requests[second["request_id"]]["status"] == "QUEUED"


def test_scheduler_duration_budget_expires_with_time_window(tmp_path: Path) -> None:
    now = [datetime(2026, 8, 30, tzinfo=timezone.utc)]
    scheduler = BehaviorCollectionScheduler(
        tmp_path,
        hard_budget_seconds_per_minute=1.0,
        clock=lambda: now[0],
    )
    request = scheduler.enqueue(
        scope="function",
        subject="target-a",
        requested_calls=1,
        requested_by="uid:1001",
        reason="budget window test",
    )
    claimed = scheduler.claim_next(request_id=request["request_id"])
    assert claimed is not None
    scheduler.complete(
        claimed["request_id"],
        outcome="CAPTURED",
        duration_seconds=1.0,
    )
    now[0] += timedelta(seconds=61)
    assert scheduler.status()["resource_budget"]["state"] == "NORMAL"


def test_scheduler_reports_sampling_density_and_enforces_call_budget(
    tmp_path: Path,
) -> None:
    scheduler = BehaviorCollectionScheduler(
        tmp_path,
        soft_budget_calls_per_minute=5,
        hard_budget_calls_per_minute=10,
    )
    request = scheduler.enqueue(
        scope="function",
        subject="target-a",
        requested_calls=20,
        requested_by="uid:1001",
        reason="call budget test",
    )
    claimed = scheduler.claim_next(request_id=request["request_id"])
    assert claimed is not None
    scheduler.complete(
        claimed["request_id"],
        outcome="CAPTURED",
        observed_calls=10,
    )

    budget = scheduler.status()["resource_budget"]
    assert budget["state"] == "HARD_LIMIT"
    assert budget["hard_limit_reasons"] == ["call_volume"]
    assert budget["recent_observed_calls"] == 10
    assert budget["recent_requested_calls"] == 20
    assert budget["recent_call_rate_per_minute"] == 10
    assert budget["sampling_density"] == 0.5

    queued = scheduler.enqueue(
        scope="function",
        subject="target-b",
        requested_calls=1,
        requested_by="uid:1001",
        reason="call budget test",
    )
    assert scheduler.claim_next(request_id=queued["request_id"]) is None
    requests = {
        item["request_id"]: item
        for item in scheduler.list_requests(limit=10)
    }
    assert requests[queued["request_id"]]["status"] == "QUEUED"


def test_scheduler_call_budget_expires_with_time_window(tmp_path: Path) -> None:
    now = [datetime(2026, 8, 30, tzinfo=timezone.utc)]
    scheduler = BehaviorCollectionScheduler(
        tmp_path,
        hard_budget_calls_per_minute=1,
        clock=lambda: now[0],
    )
    request = scheduler.enqueue(
        scope="function",
        subject="target-a",
        requested_calls=1,
        requested_by="uid:1001",
        reason="call budget window test",
    )
    claimed = scheduler.claim_next(request_id=request["request_id"])
    assert claimed is not None
    scheduler.complete(claimed["request_id"], outcome="CAPTURED", observed_calls=1)
    now[0] += timedelta(seconds=61)
    assert scheduler.status()["resource_budget"]["state"] == "NORMAL"


def test_scheduler_reports_queue_pressure_and_available_slots(tmp_path: Path) -> None:
    scheduler = BehaviorCollectionScheduler(tmp_path, maximum_pending=2)
    first = scheduler.enqueue(
        scope="function",
        subject="target-a",
        requested_calls=1,
        requested_by="uid:1001",
        reason="queue pressure test",
    )
    scheduler.enqueue(
        scope="function",
        subject="target-b",
        requested_calls=1,
        requested_by="uid:1001",
        reason="queue pressure test",
    )

    pressure = scheduler.status()["queue_pressure"]
    assert pressure == {
        "state": "FULL",
        "pending": 2,
        "queued": 2,
        "active": 0,
        "maximum_pending": 2,
        "available_slots": 0,
        "utilization": 1.0,
    }
    with pytest.raises(BehaviorCollectionQueueFull):
        scheduler.enqueue(
            scope="function",
            subject="target-c",
            requested_calls=1,
            requested_by="uid:1001",
            reason="queue pressure test",
        )
    assert scheduler.cancel(first["request_id"], reason="free queue slot")["status"] == "CANCELLED"
    assert scheduler.status()["queue_pressure"]["available_slots"] == 1


def test_scheduler_enforces_process_memory_budget_and_fails_closed_when_unavailable(
    tmp_path: Path,
) -> None:
    scheduler = BehaviorCollectionScheduler(
        tmp_path,
        hard_budget_process_memory_bytes=100,
        process_memory_probe=lambda: 101,
    )
    budget = scheduler.status()["resource_budget"]
    assert budget["state"] == "HARD_LIMIT"
    assert budget["hard_limit_reasons"] == ["process_memory"]
    assert budget["process_memory_bytes"] == 101
    assert budget["process_memory_measurement_available"] is True
    request = scheduler.enqueue(
        scope="function",
        subject="target-a",
        requested_calls=1,
        requested_by="uid:1001",
        reason="process memory budget test",
    )
    assert scheduler.claim_next(request_id=request["request_id"]) is None

    unavailable = BehaviorCollectionScheduler(
        tmp_path / "unavailable",
        hard_budget_process_memory_bytes=100,
        process_memory_probe=lambda: None,
    )
    unavailable_budget = unavailable.status()["resource_budget"]
    assert unavailable_budget["state"] == "HARD_LIMIT"
    assert unavailable_budget["hard_limit_reasons"] == ["process_memory_unavailable"]
    assert unavailable_budget["process_memory_measurement_available"] is False


def test_scheduler_expires_deadline_without_claiming_request(tmp_path: Path) -> None:
    now = [datetime(2026, 8, 30, tzinfo=timezone.utc)]
    scheduler = BehaviorCollectionScheduler(tmp_path, clock=lambda: now[0])
    request = scheduler.enqueue(
        scope="function",
        subject="example.target",
        requested_calls=1,
        requested_by="uid:1001",
        reason="deadline test",
        deadline=(now[0] + timedelta(minutes=1)).isoformat(),
    )
    now[0] += timedelta(minutes=2)

    assert scheduler.claim_next() is None
    expired = scheduler.list_requests()[0]
    assert expired["request_id"] == request["request_id"]
    assert expired["status"] == "EXPIRED"


def test_scheduler_execute_persists_bounded_provenance(tmp_path: Path) -> None:
    scheduler = BehaviorCollectionScheduler(tmp_path, maximum_calls=20)
    capture, request = scheduler.execute(
        scope="function",
        subject="example.target",
        requested_calls=20,
        requested_by="uid:1001",
        reason="operator investigation",
        priority=50,
        operation=lambda: {
            "generation_id": "generation-1",
            "profile": {"call_count": 999},
        },
    )

    assert capture["collection_request"]["request_id"] == request["request_id"]
    assert capture["collection_request"]["status"] == "CAPTURED"
    assert capture["collection_request"]["observed_calls"] == 20
    assert capture["collection_request"]["observed_generation"] == "generation-1"
    assert scheduler.status()["pending"] == 0


def test_guard_uses_policy_limits_and_authority_bound_scheduler(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CARETAKER_DATA_DIR", str(tmp_path))
    guard = GuardEngine(
        policy=GuardPolicy(
            snapshots=BehaviorSnapshotPolicy(
                collection_max_active=1,
                collection_max_pending=2,
                collection_max_calls=4,
            )
        )
    )

    capture = guard.schedule_behavior_collection(
        scope="function",
        subject="example.target",
        calls=4,
        requested_by="uid:1001",
        reason="operator investigation",
        operation=lambda: {"generation_id": "generation-1", "profile": {"call_count": 4}},
    )

    assert capture["collection_request"]["authority_policy_fingerprint"]
    assert capture["collection_request"]["status"] == "CAPTURED"
    assert guard.behavior_collection_status()["maximum_pending"] == 2


def test_operator_function_capture_uses_scheduler_provenance(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CARETAKER_DATA_DIR", str(tmp_path))
    guard = GuardEngine(policy=GuardPolicy())

    def sample(value: int) -> int:
        return value

    guard.register_target(
        "example.sample",
        sample,
        GuardBinding(enabled=True),
        periodic=False,
    )
    registry = OperatorRuntimeRegistry()
    registry.register_guard_engine(guard)

    result = registry.handle_request(
        {
            "command": "behavior-capture",
            "scope": "function",
            "subject": "example.sample",
            "calls": 3,
            "reason": "operator verification",
        },
        (1234, 1001, 1001),
    )

    assert result["ok"] is True
    request = result["capture"]["collection_request"]
    assert request["requested_by"] == "uid:1001"
    assert request["reason"] == "operator verification"
    assert request["status"] == "CAPTURED"


def test_operator_can_cancel_queued_collection_request(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CARETAKER_DATA_DIR", str(tmp_path))
    guard = GuardEngine(policy=GuardPolicy())
    request = guard.behavior_collection_scheduler.enqueue(
        scope="function",
        subject="example.target",
        requested_calls=1,
        requested_by="uid:1001",
        reason="queued work",
    )
    registry = OperatorRuntimeRegistry()
    registry.register_guard_engine(guard)

    result = registry.handle_request(
        {
            "command": "behavior-collection-cancel",
            "request_id": request["request_id"],
            "reason": "operator no longer needs it",
        },
        (1234, 1001, 1001),
    )

    assert result["ok"] is True
    assert result["request"]["status"] == "CANCELLED"


def test_operator_can_promote_registered_adaptive_target_to_behavior(tmp_path: Path) -> None:
    guard = GuardEngine()

    def sample(value: int) -> int:
        return value

    wrapped = lightweight(
        policy=LightweightPolicy(),
        engine=type("Engine", (), {"guard": guard})(),
        behavior_binding=GuardBinding(enabled=True),
        target_id="example.operator-promotion",
        state_directory=tmp_path,
    )(sample)
    wrapped.__caretaker_adaptive__.prepare_guard_registration()

    registry = OperatorRuntimeRegistry()
    registry.register_guard_engine(guard)
    result = registry.handle_request(
        {
            "command": "behavior-collection-promote",
            "target": "example.operator-promotion",
            "reason": "incident investigation",
        },
        (1234, 1001, 1001),
    )

    assert result["ok"] is True
    promotion = result["promotion"]
    assert promotion["promoted"] is True
    assert promotion["requested_by"] == "uid:1001"
    assert promotion["state"]["level"] == "BEHAVIOR"
    assert promotion["state"]["stage"] == "pre-repair-behavior"


def test_operator_promotion_rejects_non_adaptive_guard_target() -> None:
    guard = GuardEngine()

    def sample(value: int) -> int:
        return value

    guard.register_target("example.not-adaptive", sample, GuardBinding(enabled=True), periodic=False)
    registry = OperatorRuntimeRegistry()
    registry.register_guard_engine(guard)

    with pytest.raises(KeyError, match="No eligible Guard target"):
        registry.handle_request(
            {
                "command": "behavior-collection-promote",
                "target": "example.not-adaptive",
                "reason": "incident investigation",
            },
            (1234, 1001, 1001),
        )


def test_automatic_collection_cycle_promotes_one_adaptive_backlog_target(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("CARETAKER_DATA_DIR", str(tmp_path))
    guard = GuardEngine(
        policy=GuardPolicy(
            snapshots=BehaviorSnapshotPolicy(
                collection_auto_promote=True,
                collection_auto_max_promoted=1,
            )
        )
    )

    def sample(value: int) -> int:
        return value

    wrapped = lightweight(
        policy=LightweightPolicy(),
        engine=type("Engine", (), {"guard": guard})(),
        behavior_binding=GuardBinding(enabled=True),
        target_id="example.automatic-promotion",
        state_directory=tmp_path / "adaptive",
    )(sample)
    wrapped.__caretaker_adaptive__.prepare_guard_registration()

    registry = OperatorRuntimeRegistry()
    registry.register_guard_engine(guard)
    first = registry.handle_request(
        {"command": "behavior-collection-auto-cycle"},
        (1234, 1001, 1001),
    )["cycles"][0]
    assert first["enabled"] is True
    assert [item["target_id"] for item in first["promoted"]] == [
        "example.automatic-promotion"
    ]
    assert first["active_automatic"] == 1
    assert first["promoted"][0]["state"]["level"] == "BEHAVIOR"
    assert first["promoted"][0]["state"]["promotion_requested_by"] == "caretaker:auto"
    assert first["promoted"][0]["state"]["promotion_authority_generation"] == "0"

    second = guard.automatic_behavior_collection_cycle()
    assert second["promoted"] == []
    assert second["active_automatic"] == 1

    monkeypatch.setattr(
        guard,
        "behavior_collection_backlog",
        lambda **_: {
            "enabled": True,
            "items": [{
                "target_id": "example.automatic-promotion",
                "generation_id": first["promoted"][0]["generation_id"],
                "status": "sufficiently_covered",
                "snapshot_id": "snapshot-automatic",
            }],
            "counts": {"sufficiently_covered": 1},
        },
    )
    reconciled = guard.automatic_behavior_collection_cycle()
    assert reconciled["promoted"] == []
    assert reconciled["outcomes"][0]["outcome"] == "CAPTURED"
    assert reconciled["outcomes"][0]["snapshot_id"] == "snapshot-automatic"
    assert reconciled["active_automatic"] == 0
    assert wrapped.__caretaker_adaptive__.state.promotion_outcome == "CAPTURED"


def test_automatic_collection_allows_bounded_waiting_targets_without_blocking_collectors(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("CARETAKER_DATA_DIR", str(tmp_path))
    guard = GuardEngine(
        policy=GuardPolicy(
            snapshots=BehaviorSnapshotPolicy(
                collection_auto_promote=True,
                collection_auto_max_promoted=1,
                collection_auto_max_waiting=2,
            )
        )
    )

    def sample(value: int) -> int:
        return value

    wrapped = []
    for target_id in (
        "example.automatic-waiting-a",
        "example.automatic-waiting-b",
        "example.automatic-waiting-c",
    ):
        current = lightweight(
            policy=LightweightPolicy(),
            engine=type("Engine", (), {"guard": guard})(),
            behavior_binding=GuardBinding(enabled=True),
            target_id=target_id,
            state_directory=tmp_path / "adaptive",
        )(sample)
        current.__caretaker_adaptive__.prepare_guard_registration()
        wrapped.append(current)

    first = guard.automatic_behavior_collection_cycle()
    assert len(first["promoted"]) == 2
    assert first["active_automatic"] == 2
    assert first["collecting_automatic"] == 0
    assert first["waiting_automatic"] == 2

    wrapped[0](1)
    second = guard.automatic_behavior_collection_cycle()
    assert len(second["promoted"]) == 1
    assert second["collecting_automatic"] == 1
    assert second["waiting_automatic"] == 2


def test_guard_backlog_reports_waiting_and_queued_current_generations(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("CARETAKER_DATA_DIR", str(tmp_path))
    guard = GuardEngine(policy=GuardPolicy())

    def sample(value: int) -> int:
        return value

    guard.register_target(
        "example.backlog",
        sample,
        GuardBinding(enabled=True),
        periodic=False,
    )
    waiting = guard.behavior_collection_backlog()
    assert waiting["counts"] == {"armed_waiting": 1}
    request = guard.behavior_collection_scheduler.enqueue(
        scope="function",
        subject="example.backlog",
        requested_calls=1,
        requested_by="uid:1001",
        reason="coverage request",
    )

    queued = guard.behavior_collection_backlog()
    assert queued["counts"] == {"queued": 1}
    assert queued["items"][0]["request_id"] == request["request_id"]
