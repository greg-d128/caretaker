from __future__ import annotations

import hashlib
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
    verify_audit_stream,
)
from caretaker.logging.policy import RedactionPolicy


class RecordingAuditSink:
    sink_id = "monitoring-test"

    def __init__(self) -> None:
        self.records: list[bytes] = []
        self.flushes = 0

    def deliver(self, record: bytes) -> None:
        self.records.append(bytes(record))

    def flush(self) -> None:
        self.flushes += 1


class FailingAuditSink:
    sink_id = "monitoring-failing"

    def deliver(self, record: bytes) -> None:
        raise OSError("sink unavailable")

    def flush(self) -> None:
        raise OSError("sink unavailable")


class AcknowledgingAuditSink(RecordingAuditSink):
    def deliver(self, record: bytes) -> dict[str, object]:
        self.records.append(bytes(record))
        return {
            "acknowledged": True,
            "record_sha256": hashlib.sha256(record).hexdigest(),
        }


class MismatchedAcknowledgementSink(RecordingAuditSink):
    def deliver(self, record: bytes) -> dict[str, object]:
        self.records.append(bytes(record))
        return {"acknowledged": True, "record_sha256": "0" * 64}


class ToggleAuditSink(RecordingAuditSink):
    def __init__(self) -> None:
        super().__init__()
        self.available = False

    def deliver(self, record: bytes) -> None:
        if not self.available:
            raise OSError("sink unavailable")
        super().deliver(record)


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


def test_audit_writer_redacts_event_values_before_hashing(tmp_path: Path) -> None:
    writer = AuditStreamWriter(
        AuditStreamPolicy(),
        directory=tmp_path,
        run_id=uuid4(),
        process_start_id=uuid4(),
        redaction_policy=RedactionPolicy(),
    )
    event = writer.emit(
        "INCIDENT_CAPTURED",
        actor={"type": "operator", "token": "private-token"},
        details={
            "nested": {"password": "private-password"},
            "message": "authorization=private-authorization",
        },
    )
    writer.close()

    assert event["actor"]["token"] == "<redacted>"
    assert event["details"] == {
        "nested": {"password": "<redacted>"},
        "message": "authorization=<redacted>",
    }
    raw = (tmp_path / "caretaker_audit.log").read_text()
    assert "private-token" not in raw
    assert "private-password" not in raw
    assert "private-authorization" not in raw
    assert verify_audit_stream(tmp_path / "caretaker_audit.log")["valid"] is True


def test_logging_runtime_passes_active_redaction_policy_to_audit_writer(tmp_path: Path) -> None:
    from caretaker.logging.handler import LoggingRuntime
    from caretaker.logging.policy import CompressionPolicy, OperatorLoggingPolicy

    policy = OperatorLoggingPolicy(
        directory=str(tmp_path),
        compression=CompressionPolicy(enabled=False),
        redaction=RedactionPolicy(
            secret_field_names=("customer_secret",),
            replacement="<masked>",
        ),
    )
    runtime = LoggingRuntime(policy, supervised=True)
    try:
        runtime.audit.emit(
            "INCIDENT_CAPTURED",
            details={"customer_secret": "sensitive-value"},
        )
    finally:
        runtime.close()

    rows = [
        json.loads(line)
        for line in (tmp_path / "caretaker_audit.log").read_text().splitlines()
    ]
    event = rows[-1]
    assert event["details"] == {"customer_secret": "<masked>"}
    assert "sensitive-value" not in (tmp_path / "caretaker_audit.log").read_text()


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


def test_logging_runtime_audits_recovered_incomplete_tail(tmp_path: Path) -> None:
    from caretaker.logging.handler import LoggingRuntime
    from caretaker.logging.policy import CompressionPolicy, OperatorLoggingPolicy

    policy = OperatorLoggingPolicy(
        directory=str(tmp_path),
        compression=CompressionPolicy(enabled=False),
    )
    writer = AuditStreamWriter(
        policy.audit,
        directory=tmp_path,
        run_id=uuid4(),
        process_start_id=uuid4(),
    )
    writer.emit("INCIDENT_CAPTURED")
    writer.close()
    audit_path = tmp_path / "caretaker_audit.log"
    incomplete = b'{"incomplete":'
    with audit_path.open("ab") as stream:
        stream.write(incomplete)

    runtime = LoggingRuntime(policy, supervised=True)
    try:
        assert runtime.audit.recovered_truncated_bytes == len(incomplete)
    finally:
        runtime.close()
    rows = [json.loads(line) for line in audit_path.read_text().splitlines()]
    loss = [row for row in rows if row["event_type"] == "AUDIT_DATA_LOSS"][-1]
    assert loss["outcome"]["state"] == "RECOVERED_INCOMPLETE_TAIL"
    assert loss["details"] == {
        "bytes": len(incomplete),
        "category": "audit_stream",
        "reason": "incomplete_final_record",
        "records_preserved": True,
    }


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


def test_signed_audit_events_verify_across_restart(tmp_path: Path) -> None:
    from caretaker.logging import RuntimeArtifactSigningService, RuntimeRecordIntegrityMode, RuntimeSigningPolicy

    signing_policy = RuntimeSigningPolicy(
        mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
        run_signer_in_separate_process=False,
    )
    audit_policy = AuditStreamPolicy(sign_events=True)
    first_run_id = uuid4()
    first_process_start_id = uuid4()
    first_signer = RuntimeArtifactSigningService(
        policy=signing_policy,
        application_id="demo",
        run_id=first_run_id,
        process_start_id=first_process_start_id,
        root=tmp_path,
    )
    first = AuditStreamWriter(
        audit_policy,
        directory=tmp_path,
        run_id=first_run_id,
        process_start_id=first_process_start_id,
        artifact_signer=first_signer,
    )
    first_event = first.emit("INCIDENT_CAPTURED")
    first.close()
    first_signer.close()

    second_run_id = uuid4()
    second_process_start_id = uuid4()
    second_signer = RuntimeArtifactSigningService(
        policy=signing_policy,
        application_id="demo",
        run_id=second_run_id,
        process_start_id=second_process_start_id,
        root=tmp_path,
    )
    restarted = AuditStreamWriter(
        audit_policy,
        directory=tmp_path,
        run_id=second_run_id,
        process_start_id=second_process_start_id,
        artifact_signer=second_signer,
    )
    second_event = restarted.emit("RECOVERY_DECISION", priority=EvidencePriority.CRITICAL)
    restarted.close()
    second_signer.close()

    assert first_event["integrity"]["signature_state"] == "EPHEMERAL_SIGNED"
    assert second_event["integrity"]["signature_state"] == "EPHEMERAL_SIGNED"
    rows = [json.loads(line) for line in (tmp_path / "caretaker_audit.log").read_text().splitlines()]
    assert all("artifact_signature" in row["integrity"] for row in rows)


def test_signed_audit_events_reject_tampered_signature(tmp_path: Path) -> None:
    from caretaker.logging import RuntimeArtifactSigningService, RuntimeRecordIntegrityMode, RuntimeSigningPolicy

    run_id = uuid4()
    process_start_id = uuid4()
    signer = RuntimeArtifactSigningService(
        policy=RuntimeSigningPolicy(
            mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
            run_signer_in_separate_process=False,
        ),
        application_id="demo",
        run_id=run_id,
        process_start_id=process_start_id,
        root=tmp_path,
    )
    writer = AuditStreamWriter(
        AuditStreamPolicy(sign_events=True),
        directory=tmp_path,
        run_id=run_id,
        process_start_id=process_start_id,
        artifact_signer=signer,
    )
    writer.emit("INCIDENT_CAPTURED")
    writer.close()
    signer.close()
    path = tmp_path / "caretaker_audit.log"
    row = json.loads(path.read_text())
    row["integrity"]["artifact_signature"]["signature"] = "AA=="
    path.write_text(json.dumps(row) + "\n")

    verifier = RuntimeArtifactSigningService(
        policy=RuntimeSigningPolicy(
            mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
            run_signer_in_separate_process=False,
        ),
        application_id="demo",
        run_id=uuid4(),
        process_start_id=uuid4(),
        root=tmp_path,
    )
    with pytest.raises(AuditStreamError, match="signature"):
        AuditStreamWriter(
            AuditStreamPolicy(sign_events=True),
            directory=tmp_path,
            run_id=uuid4(),
            process_start_id=uuid4(),
            artifact_signer=verifier,
        )
    verifier.close()


def test_signed_audit_events_require_a_signer(tmp_path: Path) -> None:
    with pytest.raises(AuditStreamError, match="no runtime artifact signer"):
        AuditStreamWriter(
            AuditStreamPolicy(sign_events=True),
            directory=tmp_path,
            run_id=uuid4(),
            process_start_id=uuid4(),
        )


def test_read_only_audit_verifier_validates_hash_chain(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    writer.emit("INCIDENT_CAPTURED")
    writer.close()

    report = verify_audit_stream(tmp_path / "caretaker_audit.log")

    assert report["valid"] is True
    assert report["hash_chain_valid"] is True
    assert report["event_count"] == 1
    assert report["unsigned_event_count"] == 1


def test_read_only_audit_verifier_validates_signed_events_with_public_key(tmp_path: Path) -> None:
    from caretaker.logging import RuntimeArtifactSigningService, RuntimeRecordIntegrityMode, RuntimeSigningPolicy

    run_id = uuid4()
    process_start_id = uuid4()
    signer = RuntimeArtifactSigningService(
        policy=RuntimeSigningPolicy(
            mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
            run_signer_in_separate_process=False,
        ),
        application_id="demo",
        run_id=run_id,
        process_start_id=process_start_id,
        root=tmp_path,
    )
    writer = AuditStreamWriter(
        AuditStreamPolicy(sign_events=True),
        directory=tmp_path,
        run_id=run_id,
        process_start_id=process_start_id,
        artifact_signer=signer,
    )
    writer.emit("INCIDENT_CAPTURED")
    writer.close()
    identity = signer.identity
    report = verify_audit_stream(
        tmp_path / "caretaker_audit.log",
        require_signatures=True,
        identity_public_keys={identity.public_key_fingerprint: identity.public_key},
    )
    signer.close()

    assert report["valid"] is True
    assert report["signature_verification"] == "VERIFIED"
    assert report["unverified_signature_count"] == 0


def test_read_only_audit_verifier_reports_unavailable_signature_key(tmp_path: Path) -> None:
    from caretaker.logging import RuntimeArtifactSigningService, RuntimeRecordIntegrityMode, RuntimeSigningPolicy

    run_id = uuid4()
    process_start_id = uuid4()
    signer = RuntimeArtifactSigningService(
        policy=RuntimeSigningPolicy(
            mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
            run_signer_in_separate_process=False,
        ),
        application_id="demo",
        run_id=run_id,
        process_start_id=process_start_id,
        root=tmp_path,
    )
    writer = AuditStreamWriter(
        AuditStreamPolicy(sign_events=True),
        directory=tmp_path,
        run_id=run_id,
        process_start_id=process_start_id,
        artifact_signer=signer,
    )
    writer.emit("INCIDENT_CAPTURED")
    writer.close()
    signer.close()

    optional = verify_audit_stream(tmp_path / "caretaker_audit.log")
    required = verify_audit_stream(
        tmp_path / "caretaker_audit.log", require_signatures=True
    )

    assert optional["valid"] is True
    assert optional["signature_verification"] == "UNAVAILABLE"
    assert optional["unverified_signature_count"] == 1
    assert required["valid"] is False
    assert required["signature_verification"] == "FAILED"


def test_read_only_audit_verifier_rejects_incomplete_tail(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    writer.emit("INCIDENT_CAPTURED")
    writer.close()
    with (tmp_path / "caretaker_audit.log").open("ab") as stream:
        stream.write(b'{"incomplete":')

    report = verify_audit_stream(tmp_path / "caretaker_audit.log")

    assert report["valid"] is False
    assert report["hash_chain_valid"] is False
    assert any("incomplete final" in error for error in report["errors"])


def test_signed_audit_events_reject_a_cross_runtime_signer(tmp_path: Path) -> None:
    from caretaker.logging import RuntimeArtifactSigningService, RuntimeRecordIntegrityMode, RuntimeSigningPolicy

    signer = RuntimeArtifactSigningService(
        policy=RuntimeSigningPolicy(
            mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
            run_signer_in_separate_process=False,
        ),
        application_id="demo",
        run_id=uuid4(),
        process_start_id=uuid4(),
        root=tmp_path,
    )
    writer = AuditStreamWriter(
        AuditStreamPolicy(sign_events=True),
        directory=tmp_path,
        run_id=uuid4(),
        process_start_id=uuid4(),
        artifact_signer=signer,
    )
    with pytest.raises(AuditStreamError, match="does not match"):
        writer.emit("INCIDENT_CAPTURED")
    writer.close()
    signer.close()


def test_audit_registry_is_complete_and_exposes_redaction_contract() -> None:
    expected = {
        "AUDIT_STREAM_STARTED", "AUDIT_STREAM_ROTATED", "AUDIT_DELIVERY_STATUS",
        "AUDIT_DATA_LOSS", "CONSOLE_INVOCATION_STARTED", "CONSOLE_INVOCATION_ENDED",
            "POLICY_PROPOSED", "POLICY_REVIEWED", "POLICY_APPLIED", "POLICY_REJECTED",
            "POLICY_ACCEPTED", "POLICY_ROLLED_BACK", "POLICY_SUPERSEDED", "AUTHORITY_SNAPSHOT_CHANGED",
        "WORKER_AUTHORITY_ISSUED", "WORKER_AUTHORITY_REFRESHED",
        "WORKER_AUTHORITY_EXPIRED", "WORKER_FAILED", "WORKER_REPLACEMENT_REQUESTED",
            "WORKER_REPLACED", "SUPERVISOR_STATE_CHANGED", "INCIDENT_CAPTURED",
            "WORKER_COMPARISON_ASSIGNMENT", "WORKER_COMPARISON_RESULT",
            "WORKER_COMPARISON_RECONCILED",
            "VALIDATION_DECISION", "RECOVERY_DECISION", "REPAIR_ROLLOUT_TRANSITION",
        "SHADOW_EXECUTION_DECISION", "REPAIR_ROLLOUT_ROUTING_DECISION",
        "REPAIR_ROLLOUT_EXECUTION_OUTCOME",
        "REPAIR_CANDIDATE_OBSERVATION",
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


def test_audit_policy_sampling_records_loss_before_next_retained_event(tmp_path: Path) -> None:
    writer = _writer(
        tmp_path,
        always_preserve_priorities=frozenset({
            EvidencePriority.IMPORTANT,
            EvidencePriority.CRITICAL,
        }),
        debug_rate=0.0,
        ordinary_rate=0.0,
    )
    assert writer.emit("LOW_PRIORITY_EVENT", priority=EvidencePriority.DEBUG) is None
    assert writer.emit("LOW_PRIORITY_EVENT", priority=EvidencePriority.ORDINARY) is None
    assert writer.pending_loss_count == 2

    retained = writer.emit("INCIDENT_CAPTURED")
    writer.close()

    assert retained["stream_sequence"] == 2
    rows = [
        json.loads(line)
        for line in (tmp_path / "caretaker_audit.log").read_text().splitlines()
    ]
    assert [row["event_type"] for row in rows] == [
        "AUDIT_DATA_LOSS",
        "INCIDENT_CAPTURED",
    ]
    assert rows[0]["priority"] == "CRITICAL"
    assert rows[0]["details"] == {
        "category": "audit_events",
        "count": 2,
        "priority_counts": {"DEBUG": 1, "ORDINARY": 1},
        "reason": "sampling_policy",
        "loss_record_preserved": True,
    }
    assert verify_audit_stream(tmp_path / "caretaker_audit.log")["valid"] is True


def test_audit_policy_flushes_pending_loss_without_a_following_event(tmp_path: Path) -> None:
    writer = _writer(tmp_path, debug_rate=0.0)
    assert writer.emit("LOW_PRIORITY_EVENT", priority=EvidencePriority.DEBUG) is None
    writer.flush()
    assert writer.pending_loss_count == 0
    writer.close()

    rows = [
        json.loads(line)
        for line in (tmp_path / "caretaker_audit.log").read_text().splitlines()
    ]
    assert len(rows) == 1
    assert rows[0]["event_type"] == "AUDIT_DATA_LOSS"
    assert verify_audit_stream(tmp_path / "caretaker_audit.log")["valid"] is True


def test_audit_policy_rejects_sampling_critical_events(tmp_path: Path) -> None:
    from caretaker.logging.policy import LoggingPolicyConfigurationError, OperatorLoggingPolicy, validate_operator_logging_policy

    with pytest.raises(LoggingPolicyConfigurationError, match="critical_rate"):
        validate_operator_logging_policy(
            OperatorLoggingPolicy(
                audit=AuditStreamPolicy(critical_rate=0.0),
            )
        )
    with pytest.raises(AuditStreamError, match="include CRITICAL"):
        AuditStreamWriter(
            AuditStreamPolicy(
                always_preserve_priorities=frozenset({EvidencePriority.IMPORTANT}),
            ),
            directory=tmp_path,
            run_id=uuid4(),
            process_start_id=uuid4(),
        )


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
    delivery = [row for row in rows if row["event_type"] == "AUDIT_DELIVERY_STATUS"][-1]
    assert delivery["outcome"]["state"] == "LOCAL_ONLY"
    assert delivery["details"] == {
        "acknowledgement_required": False,
        "external_delivery": False,
        "sink_id": "local-file",
        "state": "ACTIVE",
    }
    assert all("control" not in row["event_type"].lower() for row in rows)


def test_audit_writer_delivers_exact_local_record_to_output_only_sink(tmp_path: Path) -> None:
    sink = RecordingAuditSink()
    writer = AuditStreamWriter(
        AuditStreamPolicy(),
        directory=tmp_path,
        run_id=uuid4(),
        process_start_id=uuid4(),
        external_sink=sink,
    )
    writer.emit("INCIDENT_CAPTURED", details={"token": "redacted-by-policy"})
    writer.close()

    local_record = (tmp_path / "caretaker_audit.log").read_bytes()
    assert sink.records == [local_record]
    assert sink.flushes == 1
    assert writer.delivery_status() == {
        "state": "ACTIVE",
        "required": False,
        "acknowledgement_required": False,
        "sink_id": "monitoring-test",
        "delivered_events": 1,
        "failed_events": 0,
        "last_error_type": None,
        "pending_records": 0,
        "pending_bytes": 0,
    }


def test_logging_runtime_can_use_external_audit_sink(tmp_path: Path) -> None:
    from caretaker.logging.handler import LoggingRuntime
    from caretaker.logging.policy import CompressionPolicy, OperatorLoggingPolicy

    sink = RecordingAuditSink()
    runtime = LoggingRuntime(
        OperatorLoggingPolicy(
            directory=str(tmp_path),
            compression=CompressionPolicy(enabled=False),
        ),
        supervised=True,
        external_audit_sink=sink,
    )
    try:
        runtime.flush()
        assert runtime.audit.delivery_status()["state"] == "ACTIVE"
    finally:
        runtime.close()
    assert len(sink.records) >= 2


def test_required_external_audit_delivery_fails_closed_after_local_persistence(
    tmp_path: Path,
) -> None:
    writer = AuditStreamWriter(
        AuditStreamPolicy(external_delivery_required=True),
        directory=tmp_path,
        run_id=uuid4(),
        process_start_id=uuid4(),
        external_sink=FailingAuditSink(),
    )
    with pytest.raises(AuditStreamError, match="required external audit delivery"):
        writer.emit("INCIDENT_CAPTURED")

    assert writer.delivery_status()["state"] == "DEGRADED"
    assert writer.delivery_status()["failed_events"] == 1
    assert verify_audit_stream(tmp_path / "caretaker_audit.log")["valid"] is True
    with pytest.raises(AuditStreamError, match="required external audit delivery"):
        writer.close()


def test_required_external_audit_sink_must_be_present(tmp_path: Path) -> None:
    with pytest.raises(AuditStreamError, match="no output-only sink"):
        AuditStreamWriter(
            AuditStreamPolicy(external_delivery_required=True),
            directory=tmp_path,
            run_id=uuid4(),
            process_start_id=uuid4(),
        )


def test_required_external_audit_delivery_accepts_matching_record_acknowledgement(
    tmp_path: Path,
) -> None:
    sink = AcknowledgingAuditSink()
    writer = AuditStreamWriter(
        AuditStreamPolicy(
            external_delivery_required=True,
            external_delivery_require_ack=True,
        ),
        directory=tmp_path,
        run_id=uuid4(),
        process_start_id=uuid4(),
        external_sink=sink,
    )
    writer.emit("INCIDENT_CAPTURED")
    writer.close()

    assert writer.delivery_status()["delivered_events"] == 1
    assert writer.delivery_status()["pending_records"] == 0
    assert writer.delivery_status()["acknowledgement_required"] is True


def test_required_external_audit_delivery_queues_unverified_acknowledgement(
    tmp_path: Path,
) -> None:
    writer = AuditStreamWriter(
        AuditStreamPolicy(
            external_delivery_required=True,
            external_delivery_require_ack=True,
        ),
        directory=tmp_path,
        run_id=uuid4(),
        process_start_id=uuid4(),
        external_sink=MismatchedAcknowledgementSink(),
    )
    with pytest.raises(AuditStreamError, match="required external audit delivery"):
        writer.emit("INCIDENT_CAPTURED")

    assert writer.delivery_status()["pending_records"] == 2
    assert writer.delivery_status()["failed_events"] == 1
    with pytest.raises(AuditStreamError, match="required external audit delivery"):
        writer.close()


def test_audit_policy_validates_external_delivery_requirement() -> None:
    from caretaker.logging.policy import (
        LoggingPolicyConfigurationError,
        OperatorLoggingPolicy,
        validate_operator_logging_policy,
    )

    with pytest.raises(LoggingPolicyConfigurationError, match="external_delivery_required"):
        validate_operator_logging_policy(
            OperatorLoggingPolicy(
                audit=AuditStreamPolicy(external_delivery_required="yes"),
            )
        )
    with pytest.raises(LoggingPolicyConfigurationError, match="external_delivery_require_ack"):
        validate_operator_logging_policy(
            OperatorLoggingPolicy(
                audit=AuditStreamPolicy(external_delivery_require_ack="yes"),
            )
        )
    with pytest.raises(LoggingPolicyConfigurationError, match="max_pending_records"):
        validate_operator_logging_policy(
            OperatorLoggingPolicy(
                audit=AuditStreamPolicy(external_delivery_max_pending_records=0),
            )
        )
    with pytest.raises(LoggingPolicyConfigurationError, match="max_pending_bytes"):
        validate_operator_logging_policy(
            OperatorLoggingPolicy(
                audit=AuditStreamPolicy(external_delivery_max_pending_bytes=0),
            )
        )
    with pytest.raises(LoggingPolicyConfigurationError, match="max_pending_records"):
        validate_operator_logging_policy(
            OperatorLoggingPolicy(
                audit=AuditStreamPolicy(external_delivery_max_pending_records="many"),
            )
        )


def test_audit_delivery_queue_retries_in_order_after_restart(tmp_path: Path) -> None:
    failing = FailingAuditSink()
    first = AuditStreamWriter(
        AuditStreamPolicy(),
        directory=tmp_path,
        run_id=uuid4(),
        process_start_id=uuid4(),
        external_sink=failing,
    )
    first.emit("INCIDENT_CAPTURED")
    first.close()
    # The delivery-state transition is queued after the original record.
    assert first.delivery_status()["pending_records"] == 2

    recovered = RecordingAuditSink()
    second = AuditStreamWriter(
        AuditStreamPolicy(),
        directory=tmp_path,
        run_id=uuid4(),
        process_start_id=uuid4(),
        external_sink=recovered,
    )
    assert second.delivery_status()["pending_records"] == 0
    second.emit("RECOVERY_DECISION", priority=EvidencePriority.CRITICAL)
    second.close()

    local_records = (tmp_path / "caretaker_audit.log").read_bytes().splitlines(keepends=True)
    assert recovered.records == [local_records[0], local_records[1], local_records[2]]
    assert verify_audit_stream(tmp_path / "caretaker_audit.log")["valid"] is True


def test_audit_delivery_state_transitions_are_recorded_without_failure_recursion(
    tmp_path: Path,
) -> None:
    sink = ToggleAuditSink()
    writer = AuditStreamWriter(
        AuditStreamPolicy(),
        directory=tmp_path,
        run_id=uuid4(),
        process_start_id=uuid4(),
        external_sink=sink,
    )

    writer.emit("INCIDENT_CAPTURED")
    assert writer.delivery_status()["state"] == "DEGRADED"
    sink.available = True
    writer.emit("RECOVERY_DECISION", priority=EvidencePriority.CRITICAL)
    writer.close()

    rows = [
        json.loads(line)
        for line in (tmp_path / "caretaker_audit.log").read_text().splitlines()
    ]
    assert [row["event_type"] for row in rows] == [
        "INCIDENT_CAPTURED",
        "AUDIT_DELIVERY_STATUS",
        "RECOVERY_DECISION",
        "AUDIT_DELIVERY_STATUS",
    ]
    assert [
        row["outcome"]["state"]
        for row in rows
        if row["event_type"] == "AUDIT_DELIVERY_STATUS"
    ] == ["DEGRADED", "ACTIVE"]
    assert writer.delivery_status()["state"] == "ACTIVE"
    assert writer.delivery_status()["failed_events"] == 1
    assert verify_audit_stream(tmp_path / "caretaker_audit.log")["valid"] is True


def test_audit_delivery_recovery_during_flush_is_recorded(tmp_path: Path) -> None:
    sink = ToggleAuditSink()
    writer = AuditStreamWriter(
        AuditStreamPolicy(),
        directory=tmp_path,
        run_id=uuid4(),
        process_start_id=uuid4(),
        external_sink=sink,
    )

    writer.emit("INCIDENT_CAPTURED")
    sink.available = True
    writer.flush()
    writer.close()

    rows = [
        json.loads(line)
        for line in (tmp_path / "caretaker_audit.log").read_text().splitlines()
    ]
    assert [row["event_type"] for row in rows] == [
        "INCIDENT_CAPTURED",
        "AUDIT_DELIVERY_STATUS",
        "AUDIT_DELIVERY_STATUS",
    ]
    assert [
        row["outcome"]["state"]
        for row in rows
        if row["event_type"] == "AUDIT_DELIVERY_STATUS"
    ] == ["DEGRADED", "ACTIVE"]
    assert verify_audit_stream(tmp_path / "caretaker_audit.log")["valid"] is True


def test_audit_delivery_queue_is_bounded_without_dropping_local_records(
    tmp_path: Path,
) -> None:
    writer = AuditStreamWriter(
        AuditStreamPolicy(external_delivery_max_pending_records=1),
        directory=tmp_path,
        run_id=uuid4(),
        process_start_id=uuid4(),
        external_sink=FailingAuditSink(),
    )
    writer.emit("INCIDENT_CAPTURED")
    with pytest.raises(AuditStreamError, match="delivery queue is full"):
        writer.emit("RECOVERY_DECISION", priority=EvidencePriority.CRITICAL)

    assert writer.delivery_status()["pending_records"] == 1
    # The failed delivery transition remains locally durable even when the
    # bounded retry queue cannot retain another record.
    assert len((tmp_path / "caretaker_audit.log").read_bytes().splitlines()) == 3
    assert verify_audit_stream(tmp_path / "caretaker_audit.log")["valid"] is True
    writer.close()


def test_logging_runtime_can_sign_audit_stream_with_runtime_identity(tmp_path: Path) -> None:
    from caretaker.logging import RuntimeRecordIntegrityMode, RuntimeSigningPolicy
    from caretaker.logging.handler import LoggingRuntime
    from caretaker.logging.policy import CompressionPolicy, OperatorLoggingPolicy

    policy = OperatorLoggingPolicy(
        directory=str(tmp_path),
        compression=CompressionPolicy(enabled=False),
        signing=RuntimeSigningPolicy(
            mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
            run_signer_in_separate_process=False,
        ),
        audit=AuditStreamPolicy(sign_events=True),
    )
    runtime = LoggingRuntime(policy, supervised=True)
    try:
        runtime.flush()
    finally:
        runtime.close()
    rows = [json.loads(line) for line in (tmp_path / "caretaker_audit.log").read_text().splitlines()]
    assert rows
    assert all(row["integrity"]["signature_state"] == "EPHEMERAL_SIGNED" for row in rows)


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
    superseded = [row for row in rows if row["event_type"] == "POLICY_SUPERSEDED"][-1]
    assert superseded["details"]["superseded_policy_id"] == str(old_snapshot_id)
    assert superseded["details"]["replacement_policy_id"] == applied["policy"]["policy_id"]


def test_rejected_policy_reload_is_audited_without_raw_error_text(tmp_path: Path) -> None:
    from caretaker.logging.handler import LoggingRuntime
    from caretaker.logging.policy import CompressionPolicy, OperatorLoggingPolicy

    policy = OperatorLoggingPolicy(
        directory=str(tmp_path),
        compression=CompressionPolicy(enabled=False),
    )
    runtime = LoggingRuntime(policy, supervised=True)
    try:
        runtime._on_policy_reload_error(
            ValueError("secret-token=should-not-be-written")
        )
    finally:
        runtime.close()
    rows = [
        json.loads(line)
        for line in (tmp_path / "caretaker_audit.log").read_text().splitlines()
    ]
    rejected = [row for row in rows if row["event_type"] == "POLICY_REJECTED"][-1]
    assert rejected["outcome"] == {"state": "REJECTED"}
    assert rejected["details"]["error_type"] == "ValueError"
    assert rejected["details"]["prior_policy_retained"] is True
    assert "secret-token" not in json.dumps(rejected)
