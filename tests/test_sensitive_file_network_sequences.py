from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from caretaker.evidence import (
    BehaviorEvent,
    BehaviorEventKind,
    EventOutcome,
    ResourceIdentity,
    identify_function,
)
from caretaker.guard import GuardBinding, GuardEngine
from caretaker.guard.analytics import sensitive_file_network_sequences
from caretaker.operator import OperatorRuntimeRegistry


def _events_for(sample, target_id: str):
    run_id = uuid4()
    call_id = uuid4()
    start = datetime(2026, 8, 31, tzinfo=timezone.utc)

    def event(kind, operation, resource, *, call=call_id, seconds=0):
        created = BehaviorEvent.create(
            event_kind=kind,
            operation=operation,
            code_identity=identify_function(sample),
            run_id=run_id,
            call_id=call,
            target_id=target_id,
            process_id=101,
            thread_id=202,
            resource=resource,
            outcome=EventOutcome.SUCCEEDED,
        )
        return replace(created, occurred_at=start + timedelta(seconds=seconds))

    sensitive_file = event(
        BehaviorEventKind.FILE_READ,
        "open",
        ResourceIdentity("file", "/etc/caretaker/secret", "open", True),
    )
    outbound = event(
        BehaviorEventKind.NETWORK_SEND,
        "socket.sendto",
        ResourceIdentity("network", "api.example:443", "send"),
        seconds=2,
    )
    unrelated_call = event(
        BehaviorEventKind.NETWORK_SEND,
        "socket.sendto",
        ResourceIdentity("network", "other.example:443", "send"),
        call=uuid4(),
        seconds=1,
    )
    ordinary_file = event(
        BehaviorEventKind.FILE_READ,
        "open",
        ResourceIdentity("file", "/tmp/ordinary", "open", False),
        seconds=3,
    )
    return sensitive_file, outbound, unrelated_call, ordinary_file


def test_sensitive_file_network_sequence_requires_shared_execution_context():
    def sample(value):
        return value

    sensitive_file, outbound, unrelated_call, ordinary_file = _events_for(
        sample, "example.sequence"
    )

    sequences = sensitive_file_network_sequences(
        (outbound, ordinary_file, unrelated_call, sensitive_file),
        maximum=10,
        window_seconds=5,
    )

    assert len(sequences) == 1
    sequence = sequences[0]
    assert sequence["file_event_kind"] == "FILE_READ"
    assert sequence["network_event_kind"] == "NETWORK_SEND"
    assert sequence["network_destination"] == "api.example:443"
    assert sequence["delay_seconds"] == 2.0
    assert sequence["coverage"] == "bounded_sample"
    assert sequence["absence_claim"] is False


def test_guard_and_operator_expose_sequence_evidence():
    def sample(value):
        return value

    target_id = "example.sequence.control"
    sensitive_file, outbound, _unrelated_call, _ordinary_file = _events_for(
        sample, target_id
    )
    guard = GuardEngine()
    guard.register_target(
        target_id,
        sample,
        GuardBinding(enabled=True, observe_network=True, observe_filesystem=True),
        periodic=False,
    )
    guard.record_event(sensitive_file)
    guard.record_event(outbound)

    direct = guard.sensitive_file_network_sequences(target_id, window_seconds=5)
    assert len(direct) == 1

    registry = OperatorRuntimeRegistry()
    registry.register_guard_engine(guard)
    response = registry.handle_request(
        {
            "command": "guard-sensitive-file-network-sequences",
            "target": target_id,
            "window_seconds": 5,
        },
        (1234, 1001, 1001),
    )
    assert response["ok"] is True
    assert len(response["sequences"]) == 1
    assert response["evidence_only"] is True
    assert response["absence_claim"] is False
