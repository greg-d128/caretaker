from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from caretaker.behavior import (
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

    second = guard.automatic_behavior_collection_cycle()
    assert second["promoted"] == []
    assert second["active_automatic"] == 1


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
