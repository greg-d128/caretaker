from __future__ import annotations

import hashlib
from uuid import uuid4

import pytest

from caretaker.behavior import BehaviorSnapshotStore
from caretaker.logging import (
    RuntimeArtifactSigningService,
    RuntimeRecordIntegrityMode,
    RuntimeSigningPolicy,
    SigningUnavailable,
)


def _capture() -> dict[str, object]:
    return {
        "scope": "function",
        "subject_key": "function:demo.target",
        "subject": {
            "target_id": "demo.target",
            "module_name": "demo",
            "qualified_name": "target",
        },
        "code_hash": "a" * 64,
        "code_hash_kind": "function-source-sha256",
        "profile": {"call_count": 10, "event_count": 2},
        "children": [],
    }


def test_ephemeral_runtime_signer_signs_behavior_snapshot_and_journals_public_key(tmp_path):
    policy = RuntimeSigningPolicy(
        mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
        run_signer_in_separate_process=False,
    )
    service = RuntimeArtifactSigningService(
        policy=policy,
        application_id="demo",
        run_id=uuid4(),
        process_start_id=uuid4(),
        root=tmp_path,
    )
    store = BehaviorSnapshotStore(tmp_path, artifact_signer=service)
    envelope = store.create(_capture())

    assert envelope["integrity"]["signature_state"] == "EPHEMERAL_SIGNED"
    assert store.load(envelope["snapshot"]["snapshot_id"])["snapshot"]["snapshot_id"] == envelope["snapshot"]["snapshot_id"]
    records = service.journal.records()
    assert any(row["record_type"] == "IDENTITY_CREATED" for row in records)
    identity = service.identity
    assert service.journal.public_key(identity.public_key_fingerprint) == identity.public_key
    service.close()


def test_external_signed_mode_never_silently_falls_back(tmp_path):
    policy = RuntimeSigningPolicy(mode=RuntimeRecordIntegrityMode.EXTERNAL_SIGNED)
    with pytest.raises(SigningUnavailable, match="will not silently fall back"):
        RuntimeArtifactSigningService(
            policy=policy,
            application_id="demo",
            run_id=uuid4(),
            process_start_id=uuid4(),
            root=tmp_path,
        )


def test_external_ed25519_signer_is_used_for_snapshots(tmp_path):
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    private = crypto.Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    class External:
        def public_identity(self):
            return {
                "identity_id": "deployment-signer",
                "algorithm": "ed25519",
                "public_key": public,
                "public_key_fingerprint": hashlib.sha256(public).hexdigest(),
            }

        def sign_artifact(self, payload: bytes) -> bytes:
            return private.sign(payload)

    service = RuntimeArtifactSigningService(
        policy=RuntimeSigningPolicy(mode=RuntimeRecordIntegrityMode.EXTERNAL_SIGNED),
        application_id="demo",
        run_id=uuid4(),
        process_start_id=uuid4(),
        root=tmp_path,
        external_signer=External(),
    )
    store = BehaviorSnapshotStore(tmp_path, artifact_signer=service)
    envelope = store.create(_capture())
    assert envelope["integrity"]["signature_state"] == "EXTERNAL_SIGNED"
    assert store.load(envelope["snapshot"]["snapshot_id"])["integrity"]["signer"] == "deployment-signer"
    service.close()


def test_behavior_archive_contains_signing_identity_records(tmp_path):
    service = RuntimeArtifactSigningService(
        policy=RuntimeSigningPolicy(
            mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
            run_signer_in_separate_process=False,
        ),
        application_id="demo",
        run_id=uuid4(),
        process_start_id=uuid4(),
        root=tmp_path,
    )
    store = BehaviorSnapshotStore(tmp_path, artifact_signer=service)
    envelope = store.create(_capture())
    archive_path = store.archive([envelope["snapshot"]["snapshot_id"]], remove=False)

    import tarfile
    with tarfile.open(archive_path, "r:gz") as archive:
        assert "signing-identities.json" in archive.getnames()
    service.close()
