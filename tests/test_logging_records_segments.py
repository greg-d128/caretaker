from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from caretaker.logging import (
    LogChannel,
    LogEnvelope,
    OperatorLoggingPolicy,
    RecordFormatError,
    RuntimeRecordIntegrityMode,
    RuntimeSigningPolicy,
    SegmentWriter,
    TLVLogCodec,
    read_segment,
)
from caretaker.logging.policy import CompressionPolicy, RotationPolicy


def envelope(sequence: int, *, message: str = "hello") -> LogEnvelope:
    return LogEnvelope(
        schema_version=1,
        writer_version="0.5.0a1",
        record_id=uuid4(),
        occurred_at=datetime.now(timezone.utc),
        monotonic_ns=123,
        process_start_id=uuid4(),
        sequence_number=sequence,
        channel=LogChannel.APPLICATION,
        severity=20,
        logger_name="demo",
        message_template="hello %s",
        formatted_message=message,
        fields={"value": 1},
        process_id=10,
        thread_id=20,
        task_id=None,
        run_id=uuid4(),
        call_id=uuid4(),
        target_id="demo:fn",
        function_version=1,
        incident_id=None,
    )


def test_tlv_record_round_trip_and_unknown_fields_are_skipped():
    codec = TLVLogCodec()
    original = envelope(1)
    encoded = codec.encode(original, extra_fields=((65000, 7, b"future-data"),))
    assert len(encoded) <= 4096
    decoded = codec.decode(encoded)
    assert decoded.record_id == original.record_id
    assert decoded.fields == original.fields


def test_record_larger_than_4k_requires_attachment():
    codec = TLVLogCodec()
    with pytest.raises(RecordFormatError, match="attachment stream"):
        codec.encode(envelope(1, message="x" * 5000))


def test_segment_is_source_of_truth_and_truncated_tail_is_recoverable(tmp_path):
    policy = OperatorLoggingPolicy(
        directory=str(tmp_path),
        compression=CompressionPolicy(enabled=False),
        rotation=RotationPolicy(maximum_segment_bytes=1024 * 1024, maximum_segment_seconds=3600),
    )
    writer = SegmentWriter(policy, run_id=uuid4(), process_start_id=uuid4())
    writer.write(envelope(1))
    writer.write(envelope(2))
    manifest = writer.close()
    assert manifest is not None
    path = Path(manifest.path)
    with path.open("ab") as stream:
        stream.write(b"CTLG\x00")
    records = read_segment(path)
    assert [item.sequence_number for item in records] == [1, 2]


def test_segment_hash_chain_across_rotations(tmp_path):
    policy = OperatorLoggingPolicy(
        directory=str(tmp_path),
        compression=CompressionPolicy(enabled=False),
        rotation=RotationPolicy(maximum_segment_bytes=900, maximum_segment_seconds=3600),
    )
    writer = SegmentWriter(policy, run_id=uuid4(), process_start_id=uuid4())
    writer.write(envelope(1, message="a" * 200))
    writer.write(envelope(2, message="b" * 200))
    final = writer.close()
    manifests = sorted((tmp_path / "application" / "manifests").glob("*.json"))
    assert len(manifests) >= 2
    import json
    values = [json.loads(path.read_text()) for path in manifests if not path.name.endswith("signature.json")]
    values.sort(key=lambda item: item["created_at"])
    assert values[1]["previous_segment_hash"] == values[0]["content_hash"]


def test_event_rotation_binds_attachment_checkpoint_to_signed_manifest(tmp_path):
    checkpoints: list[str] = []
    checkpoint_hash = "a" * 64

    def checkpoint() -> str:
        checkpoints.append(checkpoint_hash)
        return checkpoint_hash

    policy = OperatorLoggingPolicy(
        directory=str(tmp_path),
        compression=CompressionPolicy(enabled=False),
        rotation=RotationPolicy(maximum_segment_bytes=900, maximum_segment_seconds=3600),
        signing=RuntimeSigningPolicy(
            mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
            run_signer_in_separate_process=False,
        ),
    )
    writer = SegmentWriter(
        policy,
        run_id=uuid4(),
        process_start_id=uuid4(),
        attachment_checkpoint=checkpoint,
    )
    writer.write(envelope(1, message="a" * 200))
    writer.write(envelope(2, message="b" * 200))
    writer.close()

    assert checkpoints == [checkpoint_hash]
    signed_manifests = sorted(
        (tmp_path / "application" / "manifests").glob("*.signature.json")
    )
    assert signed_manifests
    values = [json.loads(path.read_text()) for path in signed_manifests]
    assert any(
        value["manifest"]["attachment_manifest_hash"] == checkpoint_hash
        for value in values
    )
