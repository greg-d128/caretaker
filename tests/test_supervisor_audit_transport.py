from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from caretaker.logging import AuditStreamError, EvidencePriority, RemoteAuditStream
from caretaker.run import _handle_validation_audit_submission


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


class _Audit:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def emit(self, event_type: str, **kwargs):
        self.calls.append({"event_type": event_type, **kwargs})
        return {"event_id": "event-1", "stream_sequence": 8}


def _runtime(audit: _Audit):
    return SimpleNamespace(
        audit=audit,
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


def test_remote_audit_stream_only_allows_validation_decisions(monkeypatch):
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
    with pytest.raises(AuditStreamError, match="only VALIDATION_DECISION"):
        stream.emit("POLICY_APPLIED", priority=EvidencePriority.CRITICAL)
