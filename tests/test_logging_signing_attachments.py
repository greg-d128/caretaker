from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from caretaker.logging import (
    AttachmentPolicy,
    AttachmentSamplingDecision,
    AttachmentStore,
    EvidencePriority,
    KeyEvolutionSigner,
    RuntimeRecordIntegrityMode,
    RuntimeSigningPolicy,
)


def test_ephemeral_signer_rotates_and_old_key_signs_transition():
    policy = RuntimeSigningPolicy(
        mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
        run_signer_in_separate_process=False,
        key_epoch_maximum_seconds=1,
    )
    signer = KeyEvolutionSigner(
        application_id="demo",
        run_id=uuid4(),
        process_start_id=uuid4(),
        policy=policy,
    )
    first_identity = signer.identity
    transition = signer.rotate_if_due(
        next_event_sequence=10,
        now=signer.identity.generated_at + timedelta(seconds=2),
    )
    assert transition is not None
    assert signer.identity.key_epoch == 2
    assert signer.identity.public_key_fingerprint != first_identity.public_key_fingerprint
    manifest = signer.sign_manifest(
        segment_id=uuid4(), segment_hash="a" * 64, previous_segment_hash=None,
        first_event_sequence=10, last_event_sequence=20, event_count=11,
    )
    assert manifest.key_epoch == 2
    assert KeyEvolutionSigner.verify_manifest(
        manifest,
        signer.identity.public_key,
        context={
            "application_id": "demo",
            "run_id": signer.run_id,
            "process_start_id": signer.process_start_id,
        },
    )
    signer.close()


def test_attachment_stream_compresses_and_references_event(tmp_path):
    store = AttachmentStore(tmp_path, AttachmentPolicy(maximum_rate_per_minute=None))
    event_id = uuid4()
    reference = store.store(
        event_id=event_id,
        event_sequence=42,
        content_type="application/json",
        payload=b"{" + b"x" * 10000 + b"}",
        priority=EvidencePriority.IMPORTANT,
    )
    assert reference.stored
    assert reference.event_id == event_id
    assert reference.event_sequence == 42
    assert reference.compressed_bytes < reference.uncompressed_bytes
    manifest = store.close()
    assert manifest["attachment_count"] == 1


def test_attachment_rate_policy_can_sample(monkeypatch, tmp_path):
    policy = AttachmentPolicy(
        maximum_rate_per_minute=1,
        minimum_sampling_probability=0.01,
    )
    store = AttachmentStore(tmp_path, policy)
    monkeypatch.setattr("caretaker.logging.attachments.random.random", lambda: 0.99)
    first = store.store(event_id=uuid4(), event_sequence=1, content_type="text/plain", payload=b"first")
    second = store.store(event_id=uuid4(), event_sequence=2, content_type="text/plain", payload=b"second")
    assert first.stored
    assert second.sampling_decision is AttachmentSamplingDecision.SAMPLED_OUT
    store.close()
