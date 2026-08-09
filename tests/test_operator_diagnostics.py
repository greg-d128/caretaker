from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from caretaker.authority import AuthorityPolicyError
from caretaker.domain import RepairEvent
from caretaker.operator import OperatorRuntimeRegistry, control_failure_response


class _Store:
    def __init__(self, events):
        self.events = tuple(events)

    def recent_events(self, target_id, limit=50):
        values = [
            event
            for event in self.events
            if target_id is None or event.target_id == target_id
        ]
        return tuple(values[-limit:])


class _Registry:
    def find(self, target_id):
        return None


class _Engine:
    def __init__(self, events):
        self.store = _Store(events)
        self.registry = _Registry()

    def pending_approvals(self):
        return ()


def test_repair_events_are_sorted_by_timestamp():
    now = datetime.now(timezone.utc)
    earlier = RepairEvent(
        event_id=uuid4(),
        timestamp=now,
        event_type="first",
        target_id="lab.divide",
    )
    later = RepairEvent(
        event_id=uuid4(),
        timestamp=now + timedelta(seconds=1),
        event_type="second",
        target_id="lab.divide",
    )
    registry = OperatorRuntimeRegistry()
    engine = _Engine((later, earlier))
    registry.register_repair_engine(engine)

    response = registry.handle_request(
        {"command": "repair-events", "limit": 10},
        (123, 1000, 1000),
    )

    assert response["ok"] is True
    assert [item["event_type"] for item in response["events"]] == [
        "first",
        "second",
    ]


def test_unexpected_control_failure_is_structured_internal_error():
    response = control_failure_response(
        {"command": "repair-events", "target": "lab.divide"},
        (123, 1000, 1000),
        AttributeError("'RepairEvent' object has no attribute 'created_at'"),
    )
    error = response["error"]

    assert response["ok"] is False
    assert error["event"] == "caretaker.internal.operation.failed"
    assert error["failure_domain"] == "CARETAKER_INTERNAL"
    assert error["failure_kind"] == "internal-exception"
    assert error["exception_type"] == "AttributeError"
    assert error["target_id"] == "lab.divide"
    assert error["operation"] == "repair-events"
    assert error["severity"] == 40
    assert "debug" not in error


def test_control_failure_debug_detail_is_explicit_and_bounded():
    try:
        raise RuntimeError("synthetic control failure")
    except RuntimeError as exc:
        response = control_failure_response(
            {"command": "repair-events", "target": "lab.divide"},
            (123, 1000, 1000),
            exc,
            include_debug=True,
        )

    debug = response["error"]["debug"]
    assert "synthetic control failure" in debug["traceback"]
    assert len(debug["traceback"]) <= 8192
    assert debug["request_keys"] == ["command", "target"]


def test_authority_rejection_is_not_reported_as_internal_defect():
    response = control_failure_response(
        {"command": "policy-authority-update"},
        (123, 1000, 1000),
        AuthorityPolicyError("synthetic policy rejection"),
    )
    error = response["error"]

    assert error["failure_domain"] == "POLICY"
    assert error["failure_kind"] == "policy-rejection"
    assert error["decision"] == "rejected"
    assert error["severity"] == 30


def test_invalid_control_request_is_distinguished_from_internal_failure():
    response = control_failure_response(
        {"command": "target-state"},
        (123, 1000, 1000),
        ValueError("target-state requires target"),
    )
    error = response["error"]

    assert error["failure_domain"] == "CONTROL_PLANE"
    assert error["failure_kind"] == "request-rejected"
    assert error["severity"] == 30
