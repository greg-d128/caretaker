from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from caretaker.logging import (
    AUDIT_EVENT_REGISTRY,
    AuditStreamError,
    AuditStreamPolicy,
    AuditStreamWriter,
    EvidencePriority,
)


def _writer(path: Path, **changes):
    policy = AuditStreamPolicy(**changes)
    return AuditStreamWriter(policy, directory=path, run_id=uuid4(), process_start_id=uuid4())


def test_audit_stream_is_hash_chained_and_recovers_across_restart(tmp_path: Path) -> None:
    run_id = uuid4()
    process_start_id = uuid4()
    policy = AuditStreamPolicy()
    writer = AuditStreamWriter(policy, directory=tmp_path, run_id=run_id, process_start_id=process_start_id)
    first = writer.emit(
        "POLICY_APPLIED",
        actor={"type": "operator"},
        policy={"policy_id": "policy-1", "fingerprint": "sha256:policy-1"},
        outcome={"state": "APPLIED"},
        priority=EvidencePriority.CRITICAL,
    )
    assert first is not None
    writer.close()

    second_start = uuid4()
    restarted = AuditStreamWriter(policy, directory=tmp_path, run_id=uuid4(), process_start_id=second_start)
    second = restarted.emit("WORKER_FAILED", priority=EvidencePriority.CRITICAL)
    restarted.close()

    rows = [json.loads(line) for line in (tmp_path / "caretaker_audit.log").read_text().splitlines()]
    assert [row["stream_sequence"] for row in rows] == [1, 2]
    assert rows[1]["integrity"]["previous_event_hash"] == rows[0]["integrity"]["content_sha256"]
    assert second["stream_sequence"] == 2


def test_audit_stream_discards_only_an_incomplete_final_line(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    writer.emit("INCIDENT_CAPTURED")
    writer.close()
    path = tmp_path / "caretaker_audit.log"
    with path.open("ab") as stream:
        stream.write(b'{"incomplete":')
    restarted = _writer(tmp_path)
    event = restarted.emit("RECOVERY_DECISION", priority=EvidencePriority.CRITICAL)
    restarted.close()
    assert event["stream_sequence"] == 2
    assert len(path.read_text().splitlines()) == 2


def test_audit_stream_rejects_tampered_existing_record(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    writer.emit(
        "POLICY_APPLIED",
        policy={"policy_id": "policy-1", "fingerprint": "sha256:policy-1"},
        outcome={"state": "APPLIED"},
        priority=EvidencePriority.CRITICAL,
    )
    writer.close()
    path = tmp_path / "caretaker_audit.log"
    row = json.loads(path.read_text())
    row["outcome"] = {"state": "FORGED"}
    path.write_text(json.dumps(row) + "\n")
    with pytest.raises(AuditStreamError, match="content hash"):
        _writer(tmp_path)


def test_audit_stream_can_be_disabled(tmp_path: Path) -> None:
    writer = _writer(tmp_path, enabled=False)
    assert writer.emit("AUDIT_STREAM_STARTED") is None
    writer.close()
    assert not (tmp_path / "caretaker_audit.log").exists()


def test_audit_registry_is_complete_and_exposes_redaction_contract() -> None:
    expected = {
        "AUDIT_STREAM_STARTED", "AUDIT_STREAM_ROTATED", "AUDIT_DELIVERY_STATUS",
        "AUDIT_DATA_LOSS", "CONSOLE_INVOCATION_STARTED", "CONSOLE_INVOCATION_ENDED",
        "POLICY_PROPOSED", "POLICY_REVIEWED", "POLICY_APPLIED", "POLICY_REJECTED",
        "POLICY_ROLLED_BACK", "POLICY_SUPERSEDED", "AUTHORITY_SNAPSHOT_CHANGED",
        "WORKER_AUTHORITY_ISSUED", "WORKER_AUTHORITY_REFRESHED",
        "WORKER_AUTHORITY_EXPIRED", "WORKER_FAILED", "WORKER_REPLACEMENT_REQUESTED",
        "WORKER_REPLACED", "SUPERVISOR_STATE_CHANGED", "INCIDENT_CAPTURED",
        "VALIDATION_DECISION", "RECOVERY_DECISION",
    }
    assert set(AUDIT_EVENT_REGISTRY) == expected
    for definition in AUDIT_EVENT_REGISTRY.values():
        assert definition["description"]
        assert isinstance(definition["required_fields"], tuple)
        assert isinstance(definition["redaction_rules"], tuple)
        assert definition["example"]


def test_registered_audit_events_enforce_priority_and_required_fields(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    with pytest.raises(AuditStreamError, match="required fields"):
        writer.emit("POLICY_APPLIED", priority=EvidencePriority.CRITICAL)
    with pytest.raises(AuditStreamError, match="CRITICAL priority"):
        writer.emit(
            "POLICY_APPLIED",
            policy={"policy_id": "policy-1", "fingerprint": "sha256:policy-1"},
            outcome={"state": "APPLIED"},
            priority=EvidencePriority.IMPORTANT,
        )
    event = writer.emit(
        "POLICY_APPLIED",
        policy={"policy_id": "policy-1", "fingerprint": "sha256:policy-1"},
        outcome={"state": "APPLIED"},
        priority=EvidencePriority.CRITICAL,
    )
    writer.close()
    assert event["event_type"] == "POLICY_APPLIED"


def test_audit_policy_rejects_paths_outside_logging_directory() -> None:
    from caretaker.logging.policy import LoggingPolicyConfigurationError, OperatorLoggingPolicy

    with pytest.raises(LoggingPolicyConfigurationError, match="file_name"):
        from caretaker.logging.policy import validate_operator_logging_policy

        validate_operator_logging_policy(
            OperatorLoggingPolicy(audit=AuditStreamPolicy(file_name="../audit.log"))
        )


def test_logging_runtime_emits_separate_audit_stream(tmp_path: Path) -> None:
    from caretaker.logging.handler import LoggingRuntime
    from caretaker.logging.policy import CompressionPolicy, OperatorLoggingPolicy

    policy = OperatorLoggingPolicy(
        directory=str(tmp_path),
        compression=CompressionPolicy(enabled=False),
    )
    runtime = LoggingRuntime(policy, supervised=True)
    try:
        runtime.flush()
    finally:
        runtime.close()
    rows = [json.loads(line) for line in (tmp_path / "caretaker_audit.log").read_text().splitlines()]
    assert rows[0]["event_type"] == "AUDIT_STREAM_STARTED"
    assert all("control" not in row["event_type"].lower() for row in rows)


def test_policy_reload_audit_binds_prior_and_resulting_snapshots(tmp_path: Path) -> None:
    from caretaker.logging.handler import LoggingRuntime
    from caretaker.logging.policy import CompressionPolicy, OperatorLoggingPolicy, policy_snapshot

    policy = OperatorLoggingPolicy(
        directory=str(tmp_path),
        compression=CompressionPolicy(enabled=False),
    )
    runtime = LoggingRuntime(policy, supervised=True)
    try:
        old_snapshot_id = runtime.snapshot.snapshot_id
        new_policy = OperatorLoggingPolicy(
            directory=str(tmp_path),
            application_id="reloaded",
            compression=CompressionPolicy(enabled=False),
        )
        runtime._on_policy_reload(new_policy, policy_snapshot(new_policy))
    finally:
        runtime.close()
    rows = [json.loads(line) for line in (tmp_path / "caretaker_audit.log").read_text().splitlines()]
    applied = [row for row in rows if row["event_type"] == "POLICY_APPLIED"][-1]
    assert applied["policy"]["prior_policy_id"] == str(old_snapshot_id)
    assert applied["policy"]["policy_id"] != str(old_snapshot_id)
