from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from caretaker.capsule import IncidentCapsuleStore
from caretaker.logging import (
    AuditStreamError,
    EvidencePriority,
    RemoteAuditStream,
    RemoteIncidentCapture,
)
from caretaker.console_identity import ConsoleIdentityStore
from caretaker.run import (
    _handle_console_invocation_event,
    _handle_console_identity_request,
    _emit_behavior_collection_audit,
    _handle_adaptive_backpressure_audit_submission,
    _handle_adaptive_backpressure_incident_submission,
    _handle_validation_audit_submission,
)


def _request() -> dict[str, object]:
    return {
        "command": "audit-validation-decision",
        "scope": {
            "target_id": "demo.target",
            "incident_id": str(uuid4()),
            "episode_id": str(uuid4()),
            "candidate_id": str(uuid4()),
            "attempt_id": str(uuid4()),
        },
        "policy": {
            "policy_id": str(uuid4()),
            "fingerprint": "sha256:validation-policy",
            "authority_policy_generation": 4,
            "authority_policy_fingerprint": "sha256:authority",
        },
        "outcome": {
            "state": "ELIGIBLE",
            "eligible": True,
            "requires_operator_approval": False,
            "proposal_only": False,
            "total_score": 91.25,
        },
        "details": {
            "validation_backend": "process",
            "validation_isolation": "PROCESS",
            "backend_available": True,
            "check_count": 5,
            "passed_check_count": 5,
            "failed_check_count": 0,
            "risk_finding_count": 0,
            "hard_disqualification_count": 0,
            "review_required_finding_count": 0,
        },
    }


def _backpressure_request() -> dict[str, object]:
    return {
        "command": "audit-adaptive-backpressure",
        "scope": {
            "target_id": "demo.target",
            "aggregation_scope": "checkout:premium",
            "generation_id": "generation-1",
            "batch_id": str(uuid4()),
        },
        "policy": {
            "fingerprint": "sha256:worker-policy",
            "authority_generation": 4,
            "authority_fingerprint": "sha256:worker-authority",
        },
        "outcome": {
            "state": "INCIDENT_RECORDED",
            "incident_recorded": True,
            "authority_granted": False,
        },
        "details": {
            "action": "INCIDENT",
            "pending_records": 4,
            "sequence_start": 10,
            "sequence_end": 13,
            "incident_id": "incident-1",
            "error": "queue full",
            "authority_granted": False,
        },
    }


class _Audit:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def emit(self, event_type: str, **kwargs):
        self.calls.append({"event_type": event_type, **kwargs})
        return {"event_id": "event-1", "stream_sequence": 8}


def _runtime(audit: _Audit):
    return SimpleNamespace(
        audit=audit,
        run_id=uuid4(),
        snapshot=SimpleNamespace(snapshot_id=uuid4(), content_hash="sha256:audit-policy"),
        effective=SimpleNamespace(generation=9),
    )


def test_supervisor_binds_validation_audit_to_application_peer_and_rewrites_actor():
    audit = _Audit()
    runtime = _runtime(audit)
    response = _handle_validation_audit_submission(
        runtime,
        _request(),
        (4321, 1000, 1000),
        SimpleNamespace(pid=4321, poll=lambda: None),
    )

    assert response == {
        "ok": True,
        "recorded": True,
        "event_id": "event-1",
        "stream_sequence": 8,
    }
    call = audit.calls[0]
    assert call["event_type"] == "VALIDATION_DECISION"
    assert call["actor"] == {"type": "worker", "id": "pid:4321", "uid": 1000}
    assert call["policy"] == {
        "policy_id": str(runtime.snapshot.snapshot_id),
        "fingerprint": "sha256:audit-policy",
        "authority_generation": 9,
    }
    assert call["details"]["reported_policy_fingerprint"] == "sha256:validation-policy"
    assert call["details"]["worker_pid"] == 4321
    assert call["priority"] is EvidencePriority.IMPORTANT


def test_supervisor_rejects_non_application_peer_for_validation_audit():
    with pytest.raises(PermissionError, match="not from the application worker"):
        _handle_validation_audit_submission(
            _runtime(_Audit()),
            _request(),
            (9999, 1000, 1000),
            SimpleNamespace(pid=4321, poll=lambda: None),
        )


def test_supervisor_rejects_nested_or_unknown_worker_audit_fields():
    request = _request()
    request["details"] = {"raw_evidence": {"secret": "do not persist"}}
    with pytest.raises(ValueError, match="unsupported fields"):
        _handle_validation_audit_submission(
            _runtime(_Audit()),
            request,
            (4321, 1000, 1000),
            SimpleNamespace(pid=4321, poll=lambda: None),
        )


def test_supervisor_binds_backpressure_audit_and_forces_critical_priority():
    audit = _Audit()
    runtime = _runtime(audit)
    response = _handle_adaptive_backpressure_audit_submission(
        runtime,
        _backpressure_request(),
        (4321, 1000, 1000),
        SimpleNamespace(pid=4321, poll=lambda: None),
    )

    assert response == {
        "ok": True,
        "recorded": True,
        "event_id": "event-1",
        "stream_sequence": 8,
    }
    call = audit.calls[0]
    assert call["event_type"] == "ADAPTIVE_AGGREGATION_BACKPRESSURE"
    assert call["actor"] == {"type": "worker", "id": "pid:4321", "uid": 1000}
    assert call["policy"] == {
        "policy_id": str(runtime.snapshot.snapshot_id),
        "fingerprint": "sha256:audit-policy",
        "authority_generation": 9,
    }
    assert call["scope"]["target_id"] == "demo.target"
    assert call["details"]["reported_policy_fingerprint"] == "sha256:worker-policy"
    assert call["details"]["reported_authority_generation"] == 4
    assert call["details"]["worker_pid"] == 4321
    assert call["priority"] is EvidencePriority.CRITICAL


def test_supervisor_rejects_unauthorized_backpressure_audit_claims():
    request = _backpressure_request()
    request["outcome"] = {
        "state": "INCIDENT_RECORDED",
        "incident_recorded": True,
        "authority_granted": True,
    }
    with pytest.raises(ValueError, match="cannot grant authority"):
        _handle_adaptive_backpressure_audit_submission(
            _runtime(_Audit()),
            request,
            (4321, 1000, 1000),
            SimpleNamespace(pid=4321, poll=lambda: None),
        )


def test_supervisor_rejects_invalid_backpressure_audit_shape():
    request = _backpressure_request()
    request["details"] = {
        "action": "INCIDENT",
        "pending_records": {"secret": "do not persist"},
        "sequence_start": 1,
        "sequence_end": 1,
    }
    with pytest.raises(ValueError, match="must be a scalar"):
        _handle_adaptive_backpressure_audit_submission(
            _runtime(_Audit()),
            request,
            (4321, 1000, 1000),
            SimpleNamespace(pid=4321, poll=lambda: None),
        )


def test_supervisor_rejects_non_application_peer_for_backpressure_audit():
    with pytest.raises(PermissionError, match="not from the application worker"):
        _handle_adaptive_backpressure_audit_submission(
            _runtime(_Audit()),
            _backpressure_request(),
            (9999, 1000, 1000),
            SimpleNamespace(pid=4321, poll=lambda: None),
        )


def test_supervisor_captures_backpressure_incident_and_deduplicates_retry(tmp_path):
    audit = _Audit()
    runtime = _runtime(audit)
    capsule_store = IncidentCapsuleStore(tmp_path)
    incident_by_batch: dict[str, dict[str, str]] = {}
    request = {
        "command": "adaptive-backpressure-incident",
        "context": {
            "event": "adaptive-aggregation-backpressure",
            "action": "INCIDENT",
            "batch_id": "batch-1",
            "target_id": "demo.target",
            "aggregation_scope": None,
            "generation_id": "generation-1",
            "policy_fingerprint": "sha256:worker-policy",
            "authority_policy_generation": 4,
            "authority_policy_fingerprint": "sha256:worker-authority",
            "pending_records": 4,
            "sequence_start": 10,
            "sequence_end": 13,
            "error": None,
        },
    }
    peer = SimpleNamespace(pid=4321, poll=lambda: None)

    first = _handle_adaptive_backpressure_incident_submission(
        runtime, capsule_store, incident_by_batch, request, (4321, 1000, 1000), peer
    )
    second = _handle_adaptive_backpressure_incident_submission(
        runtime, capsule_store, incident_by_batch, request, (4321, 1000, 1000), peer
    )

    assert first["accepted"] is True
    assert first["incident_recorded"] is True
    assert first["idempotent"] is False
    assert second["incident_id"] == first["incident_id"]
    assert second["capsule_id"] == first["capsule_id"]
    assert second["idempotent"] is True
    assert len(capsule_store.list_summaries()) == 1
    envelope = capsule_store.load(first["capsule_id"])
    assert envelope["capsule"]["incident_state"]["trigger"] == (
        "adaptive_aggregation_backpressure"
    )
    assert [call["event_type"] for call in audit.calls] == [
        "INCIDENT_CAPTURED"
    ]
    assert audit.calls[0]["outcome"]["authority_granted"] is False


def test_supervisor_rejects_backpressure_incident_context_reuse():
    incident_by_batch = {
        "batch-1": {
            "incident_id": "incident-1",
            "capsule_id": "capsule-1",
            "target_id": "demo.target",
            "generation_id": "generation-1",
            "policy_fingerprint": "sha256:worker-policy",
        }
    }
    request = {
        "context": {
            "event": "adaptive-aggregation-backpressure",
            "action": "INCIDENT",
            "batch_id": "batch-1",
            "target_id": "other.target",
            "generation_id": "generation-1",
            "policy_fingerprint": "sha256:worker-policy",
            "pending_records": 1,
            "sequence_start": 1,
            "sequence_end": 1,
        }
    }
    with pytest.raises(ValueError, match="reused"):
        _handle_adaptive_backpressure_incident_submission(
            _runtime(_Audit()),
            IncidentCapsuleStore("/tmp/caretaker-test-no-write"),
            incident_by_batch,
            request,
            (4321, 1000, 1000),
            SimpleNamespace(pid=4321, poll=lambda: None),
        )


def test_behavior_collection_audit_is_bounded_and_authority_free():
    audit = _Audit()
    runtime = _runtime(audit)
    request = {
        "scope": "function",
        "subject": "demo.target",
        "calls": 50,
        "reason": "r" * 1000,
    }
    _emit_behavior_collection_audit(
        runtime,
        request=request,
        capture={
            "collection_request": {
                "request_id": str(uuid4()),
                "scope": "function",
                "subject": "demo.target",
                "requested_by": "uid:1000",
                "reason": "operator capture",
                "requested_calls": 50,
                "observed_calls": 48,
                "status": "CAPTURED",
                "outcome": "CAPTURED",
                "duration_seconds": 0.125,
                "observed_generation": "generation-1",
            }
        },
        actor_id="uid:1000",
    )

    call = audit.calls[0]
    assert call["event_type"] == "BEHAVIOR_COLLECTION_OUTCOME"
    assert call["actor"] == {"type": "operator", "id": "uid:1000"}
    assert call["scope"]["subject"] == "demo.target"
    assert call["details"]["duration_seconds"] == 0.125
    assert call["details"]["reason"] == "operator capture"
    assert call["outcome"]["state"] == "CAPTURED"
    assert call["outcome"]["authority_granted"] is False

    _emit_behavior_collection_audit(
        runtime,
        request={"scope": "function", "subject": "demo.target"},
        capture={
            "collection_request": {
                "scope": "function",
                "subject": "demo.target",
                "outcome": "FAILED",
                "snapshot_id": str(uuid4()),
            }
        },
        actor_id="application-supervisor",
        actor_type="supervisor",
    )
    automatic_call = audit.calls[-1]
    assert automatic_call["actor"] == {
        "type": "supervisor",
        "id": "application-supervisor",
    }
    assert automatic_call["details"]["snapshot_id"]


def test_remote_audit_stream_only_allows_allow_listed_worker_events(monkeypatch):
    calls = []

    def fake_control_request(path, request, *, timeout):
        calls.append((path, request, timeout))
        return {
            "ok": True,
            "recorded": True,
            "event_id": "event-1",
            "stream_sequence": 2,
        }

    monkeypatch.setattr("caretaker.logging.ipc.control_request", fake_control_request)
    stream = RemoteAuditStream("/tmp/caretaker-control.sock")
    assert stream.emit(
        "VALIDATION_DECISION",
        actor={"type": "forged"},
        scope={"target_id": "demo.target"},
        policy={"policy_id": "policy-1", "fingerprint": "sha256:policy"},
        outcome={"state": "ELIGIBLE", "eligible": True},
        details={},
    ) == {"event_id": "event-1", "stream_sequence": 2}
    assert calls[0][1]["command"] == "audit-validation-decision"
    assert "actor" not in calls[0][1]
    assert stream.emit(
        "ADAPTIVE_AGGREGATION_BACKPRESSURE",
        scope={"target_id": "demo.target", "batch_id": "batch-1"},
        policy={"fingerprint": "sha256:worker"},
        outcome={"state": "RETAINED", "authority_granted": False},
        details={"action": "RETAIN", "pending_records": 1, "sequence_start": 1, "sequence_end": 1},
        priority=EvidencePriority.IMPORTANT,
    ) == {"event_id": "event-1", "stream_sequence": 2}
    assert calls[1][1]["command"] == "audit-adaptive-backpressure"
    assert calls[1][1]["priority"] == EvidencePriority.CRITICAL.name
    with pytest.raises(AuditStreamError, match="only VALIDATION_DECISION or ADAPTIVE_AGGREGATION_BACKPRESSURE"):
        stream.emit("POLICY_APPLIED", priority=EvidencePriority.CRITICAL)


def test_remote_incident_capture_is_output_only_and_bounded(monkeypatch):
    calls = []

    def fake_control_request(path, request, *, timeout):
        calls.append((path, request, timeout))
        return {
            "ok": True,
            "accepted": True,
            "incident_id": "incident-1",
            "capsule_id": "capsule-1",
        }

    monkeypatch.setattr("caretaker.logging.ipc.control_request", fake_control_request)
    capture = RemoteIncidentCapture("/tmp/caretaker-control.sock")
    assert capture({"event": "adaptive-aggregation-backpressure"}) == {
        "accepted": True,
        "incident_id": "incident-1",
        "capsule_id": "capsule-1",
    }
    assert calls[0][1] == {
        "command": "adaptive-backpressure-incident",
        "context": {"event": "adaptive-aggregation-backpressure"},
    }


def test_remote_incident_capture_without_socket_is_disabled():
    assert RemoteIncidentCapture(None)({"event": "adaptive-aggregation-backpressure"}) is None


def test_console_invocation_events_are_process_owned_and_authority_free():
    audit = _Audit()
    runtime = _runtime(audit)
    invocations: dict[str, int] = {}
    invocation_id = str(uuid4())

    started = _handle_console_invocation_event(
        runtime,
        {
            "command": "console-invocation-start",
            "invocation_id": invocation_id,
        },
        (5678, 1000, 1001),
        invocations,
    )
    ended = _handle_console_invocation_event(
        runtime,
        {
            "command": "console-invocation-end",
            "invocation_id": invocation_id,
            "reason": "operator_exit",
        },
        (5678, 1000, 1001),
        invocations,
    )

    assert started["recorded"] is True
    assert ended["recorded"] is True
    assert invocations == {}
    assert [call["event_type"] for call in audit.calls[-2:]] == [
        "CONSOLE_INVOCATION_STARTED",
        "CONSOLE_INVOCATION_ENDED",
    ]
    assert audit.calls[-2]["actor"] == {"type": "operator", "id": "uid:1000"}
    assert audit.calls[-2]["details"]["authority_granted"] is False


def test_console_invocation_end_cannot_be_replayed_by_another_process():
    audit = _Audit()
    runtime = _runtime(audit)
    invocations: dict[str, int] = {}
    invocation_id = str(uuid4())
    _handle_console_invocation_event(
        runtime,
        {"command": "console-invocation-start", "invocation_id": invocation_id},
        (5678, 1000, 1001),
        invocations,
    )
    with pytest.raises(PermissionError, match="not owned"):
        _handle_console_invocation_event(
            runtime,
            {"command": "console-invocation-end", "invocation_id": invocation_id},
            (8765, 1000, 1001),
            invocations,
        )


def test_console_public_identity_is_audited_and_stored_without_authority(tmp_path):
    import base64
    import hashlib

    audit = _Audit()
    runtime = _runtime(audit)
    store = ConsoleIdentityStore(tmp_path)
    public_key = b"c" * 32
    identity = {
        "identity_id": str(uuid4()),
        "algorithm": "ed25519",
        "encoding": "base64",
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "public_key_fingerprint": hashlib.sha256(public_key).hexdigest(),
    }
    invocation_id = str(uuid4())

    _handle_console_invocation_event(
        runtime,
        {
            "command": "console-invocation-start",
            "invocation_id": invocation_id,
            "console_identity": identity,
        },
        (5678, 1000, 1001),
        {},
        store,
    )

    details = audit.calls[-1]["details"]
    assert details["authority_granted"] is False
    assert details["console_identity"]["public_key"] == identity["public_key"]
    stored = store.get(invocation_id)
    assert stored["public_key_fingerprint"] == identity["public_key_fingerprint"]
    assert "private_key" not in stored
    retrieved = _handle_console_identity_request(
        store,
        {"command": "console-invocation-identity", "invocation_id": invocation_id},
    )
    assert retrieved["authority_granted"] is False
    assert retrieved["identity"]["public_key"] == identity["public_key"]
    assert "private_key" not in retrieved["identity"]


def test_console_cli_registers_and_closes_one_invocation(monkeypatch, tmp_path):
    import caretaker.console as console_module

    requests: list[dict[str, object]] = []

    def fake_control_request(path, request, *, timeout):
        requests.append(dict(request))
        return {"ok": True}

    class FakeConsole:
        def __init__(self, socket_path, data_directory):
            self.socket_path = socket_path
            self.data_directory = data_directory

        def run(self):
            return None

    monkeypatch.setattr(console_module, "control_request", fake_control_request)
    monkeypatch.setattr(console_module, "CaretakerConsoleApp", FakeConsole)

    assert console_module.main(
        ["--socket", str(tmp_path / "control.sock"), "--data-directory", str(tmp_path)]
    ) == 0
    assert [item["command"] for item in requests] == [
        "console-invocation-start",
        "console-invocation-end",
    ]
    assert requests[0]["invocation_id"] == requests[1]["invocation_id"]
