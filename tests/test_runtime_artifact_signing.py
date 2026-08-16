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


def test_ephemeral_identity_journal_verifies_key_transition_sequence(tmp_path):
    service = RuntimeArtifactSigningService(
        policy=RuntimeSigningPolicy(
            mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
            run_signer_in_separate_process=False,
            key_epoch_maximum_seconds=0,
        ),
        application_id="demo",
        run_id=uuid4(),
        process_start_id=uuid4(),
        root=tmp_path,
    )
    store = BehaviorSnapshotStore(tmp_path, artifact_signer=service)
    first = store.create(_capture())
    second_capture = _capture()
    second_capture["profile"] = {"call_count": 20, "event_count": 3}
    second = store.create(second_capture)

    assert store.load(first["snapshot"]["snapshot_id"])["snapshot"]["snapshot_id"] == first["snapshot"]["snapshot_id"]
    assert store.load(second["snapshot"]["snapshot_id"])["snapshot"]["snapshot_id"] == second["snapshot"]["snapshot_id"]
    current = service.identity
    valid, error = service.journal.verify_identity(current.public_key_fingerprint)
    assert valid is True
    assert error is None
    transition_records = [
        row for row in service.journal.records() if row["record_type"] == "KEY_TRANSITION"
    ]
    assert transition_records
    assert all("next_event_sequence" in row["record"] for row in transition_records)
    service.close()


def test_signed_behavior_archive_verifies_and_restores_without_local_journal(tmp_path):
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
    snapshot_id = envelope["snapshot"]["snapshot_id"]
    archive_path = store.archive([snapshot_id], remove=True)

    report = store.verify_archive(archive_path)
    assert report["verified"] is True
    assert report["signed"] is True
    assert report["verified_snapshots"] == 1
    assert not (store.snapshot_directory / f"{snapshot_id}.json").exists()

    restored = store.restore_archive(archive_path)
    assert restored == (snapshot_id,)
    assert store.load(snapshot_id)["snapshot"]["snapshot_id"] == snapshot_id
    service.close()


def test_archive_restore_refuses_snapshot_id_collision(tmp_path):
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
    snapshot_id = envelope["snapshot"]["snapshot_id"]
    archive_path = store.archive([snapshot_id], remove=False)
    target = store.snapshot_directory / f"{snapshot_id}.json"
    target.write_text('{"different":true}', encoding="utf-8")

    with pytest.raises(ValueError, match="already exists with different content"):
        store.restore_archive(archive_path)
    service.close()


def test_signed_snapshot_cannot_be_downgraded_to_hash_only(tmp_path):
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
    path = store.snapshot_directory / f"{envelope['snapshot']['snapshot_id']}.json"
    import json
    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["integrity"].pop("artifact_signature", None)
    tampered["integrity"]["signature_state"] = "UNSIGNED"
    path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ValueError, match="requires EPHEMERAL_SIGNED"):
        store.load(envelope["snapshot"]["snapshot_id"])
    service.close()


def test_external_integrity_requirement_rejects_ephemeral_signature(tmp_path):
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
    writer = BehaviorSnapshotStore(tmp_path, artifact_signer=service)
    envelope = writer.create(_capture())
    reader = BehaviorSnapshotStore(
        tmp_path,
        minimum_integrity=RuntimeRecordIntegrityMode.EXTERNAL_SIGNED,
    )
    with pytest.raises(ValueError, match="required external authority"):
        reader.load(envelope["snapshot"]["snapshot_id"])
    service.close()


def test_unimplemented_signing_algorithm_is_rejected(tmp_path):
    with pytest.raises(SigningUnavailable, match="only ed25519 is implemented"):
        RuntimeArtifactSigningService(
            policy=RuntimeSigningPolicy(algorithm="rsa"),
            application_id="demo",
            run_id=uuid4(),
            process_start_id=uuid4(),
            root=tmp_path,
        )
