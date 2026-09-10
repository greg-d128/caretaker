from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from caretaker.capsule import (
    IncidentCapsuleError,
    IncidentCapsuleIntegrityError,
    IncidentCapsuleLevel,
    IncidentCapsulePolicy,
    IncidentCapsuleStore,
    content_hash,
)
from caretaker import ExceptionTrigger, RepairEngine, RepairMode, RepairPolicy, repair


def test_capsule_is_bounded_data_only_and_communications_are_revisioned(tmp_path: Path) -> None:
    incident_id = uuid4()
    run_id = uuid4()
    policy = IncidentCapsulePolicy(
        level=IncidentCapsuleLevel.STANDARD,
        maximum_text_characters=40,
        maximum_collection_items=2,
    )
    store = IncidentCapsuleStore(tmp_path, policy=policy)

    first = store.create_placeholder(
        incident_id,
        run_id=run_id,
        incident_state={
            "incident_id": incident_id,
            "message": "password=do-not-retain",
            "items": [1, 2, 3],
        },
        policy_fingerprint="policy-hash",
        policy=policy,
    )
    artifact_result = store.attach_artifact(
        incident_id,
        kind="operator-view",
        content={"view": "token=secret-value", "long": "x" * 100},
        source="caretaker-console",
        operator_identity="uid:1000",
        metadata={"tab_id": "investigate"},
        policy=policy,
    )
    second = store.record_communication(
        incident_id,
        direction="outbound",
        channel="reviewable-export",
        audience_profile_id="operators-v1",
        status="drafted",
        content_sha256="c" * 64,
        source="future-communications",
        policy=policy,
    )

    first_payload = first["capsule"]
    second_payload = second["capsule"]
    assert first_payload["revision"] == 1
    assert second_payload["revision"] == 3
    assert second_payload["previous_revision_sha256"] == artifact_result["capsule"]["integrity"]["content_sha256"]
    assert len(second_payload["communications"]) == 1
    assert len(second_payload["artifacts"]) == 1

    artifact = json.loads(
        (tmp_path / "incident-capsules" / "artifacts" / f"{artifact_result['artifact']['artifact']['artifact_id']}.json").read_text()
    )
    assert artifact["artifact"]["content"]["view"] == "token=<redacted>"
    assert artifact["artifact"]["content"]["long"].endswith("…")
    assert store.verify(second) == (True, None)
    summaries = store.list_summaries()
    assert summaries[0]["integrity_status"] == "VERIFIED"
    assert summaries[0]["revision"] == 3
    assert store.load(second["capsule"]["capsule_id"], revision=1)["capsule"]["revision"] == 1
    loaded_artifact = store.load_artifact(artifact_result["artifact"]["artifact"]["artifact_id"])
    assert loaded_artifact["artifact"]["artifact_id"] == artifact_result["artifact"]["artifact"]["artifact_id"]


def test_capsule_tampering_is_detected_and_disabled_policy_fails_closed(tmp_path: Path) -> None:
    incident_id = uuid4()
    store = IncidentCapsuleStore(tmp_path)
    envelope = store.create_placeholder(incident_id)
    path = tmp_path / "incident-capsules" / f"{envelope['capsule']['capsule_id']}.r1.json"
    value = json.loads(path.read_text())
    value["capsule"]["incident_state"]["changed"] = True
    path.write_text(json.dumps(value))

    with pytest.raises(IncidentCapsuleIntegrityError, match="content hash is invalid"):
        store.load(envelope["capsule"]["capsule_id"])
    assert store.list_summaries()[0]["integrity_status"] == "INVALID"

    disabled = IncidentCapsuleStore(
        tmp_path / "disabled",
        policy=IncidentCapsulePolicy(enabled=False),
    )
    with pytest.raises(IncidentCapsuleError, match="disabled by policy"):
        disabled.create_placeholder(uuid4())


def test_repair_incident_creates_capsule_when_store_is_configured(tmp_path: Path) -> None:
    store = IncidentCapsuleStore(tmp_path)
    engine = RepairEngine(capsule_store=store)

    def failing(value: int) -> int:
        raise ValueError(f"bad value {value}")

    wrapped = repair(
        engine=engine,
        policy=RepairPolicy(
            triggers=(ExceptionTrigger(),),
            mode=RepairMode.OBSERVE,
        ),
        target_id="test.failing",
    )(failing)

    with pytest.raises(ValueError, match="bad value"):
        wrapped(7)

    incident_id = next(iter(engine.store.incidents))
    capsule = store.latest_for_incident(incident_id)
    assert capsule is not None
    assert capsule["capsule"]["incident_id"] == str(incident_id)


def test_capsule_and_artifact_loads_reject_symlinks_and_oversized_content(tmp_path: Path) -> None:
    store = IncidentCapsuleStore(tmp_path)
    incident_id = uuid4()
    capsule = store.create_placeholder(incident_id)
    capsule_path = tmp_path / "incident-capsules" / f"{capsule['capsule']['capsule_id']}.r1.json"
    capsule_bytes = capsule_path.read_bytes()
    capsule_path.unlink()
    capsule_path.symlink_to(tmp_path / "outside-capsule.json")
    (tmp_path / "outside-capsule.json").write_bytes(capsule_bytes)
    with pytest.raises(IncidentCapsuleIntegrityError, match="stored capsule content is invalid"):
        store.load(capsule["capsule"]["capsule_id"])

    artifact_result = store.attach_artifact(
        incident_id,
        kind="evidence",
        content={"value": "small"},
        source="test",
    )
    artifact_id = artifact_result["artifact"]["artifact"]["artifact_id"]
    artifact_path = tmp_path / "incident-capsules" / "artifacts" / f"{artifact_id}.json"
    artifact_path.unlink()
    artifact_path.symlink_to(tmp_path / "outside-artifact.json")
    (tmp_path / "outside-artifact.json").write_bytes(artifact_result["artifact"]["artifact"].__str__().encode())
    with pytest.raises(IncidentCapsuleIntegrityError, match="stored capsule content is invalid"):
        store.load_artifact(artifact_id)

    # A real file is also bounded before JSON parsing, so a valid prefix plus
    # oversized trailing content cannot be accepted as a stored artifact.
    artifact_path.unlink()
    artifact_path.write_bytes(b"{" + b"x" * (store.policy.maximum_artifact_bytes + 1))
    with pytest.raises(IncidentCapsuleIntegrityError, match="stored capsule content is invalid"):
        store.load_artifact(artifact_id)


def test_artifact_identity_must_match_its_verified_capsule_reference(tmp_path: Path) -> None:
    store = IncidentCapsuleStore(tmp_path)
    result = store.attach_artifact(
        uuid4(),
        kind="evidence",
        content={"value": "small"},
        source="test",
    )
    artifact = result["artifact"]
    artifact_id = artifact["artifact"]["artifact_id"]
    path = tmp_path / "incident-capsules" / "artifacts" / f"{artifact_id}.json"
    value = json.loads(path.read_text())
    value["artifact"]["incident_id"] = str(uuid4())
    value["integrity"]["content_sha256"] = content_hash(value["artifact"])
    path.write_text(json.dumps(value))
    with pytest.raises(IncidentCapsuleIntegrityError, match="incident identity"):
        store.load_artifact(artifact_id)
