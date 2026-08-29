from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from caretaker.capsule import IncidentCapsuleStore
from caretaker.communications import (
    CommunicationAudiencePolicy,
    CommunicationPolicyError,
    IncidentCommunicationPolicy,
    build_communication_draft,
    generate_communication_draft,
)
from caretaker.logging.policy import load_operator_policy


def test_draft_is_bounded_redacted_provenanced_and_audience_filtered(tmp_path: Path) -> None:
    store = IncidentCapsuleStore(tmp_path)
    envelope = store.create_placeholder(
        uuid4(),
        incident_state={
            "occurred_at": "2026-08-29T12:00:00+00:00",
            "trigger": "exception",
            "target": "payments.charge",
            "failure": "authorization=super-secret",
            "impact": "checkout requests failed",
            "scope": "payments",
            "hypotheses": ["dependency timeout"],
            "operator_note": "token=must-not-appear",
        },
        policy_fingerprint="incident-policy-hash",
    )
    policy = IncidentCommunicationPolicy(
        audiences=(
            CommunicationAudiencePolicy(
                profile_id="public-v1",
                display_name="Public status readers",
                allowed_sections=(
                    "identity",
                    "confirmed_observations",
                    "impact",
                    "scope",
                    "mitigation",
                    "next_update",
                    "unknowns",
                    "provenance",
                ),
            ),
        )
    )

    result = build_communication_draft(
        envelope,
        audience_profile_id="public-v1",
        policy=policy,
        effective_policy_fingerprint="effective-logging-policy-hash",
    )
    draft = result["draft"]
    assert draft["status"] == "DRAFT"
    assert draft["review_required"] is True
    assert draft["delivery_authorized"] is False
    assert draft["sections"]["confirmed_observations"]["failure"] == "authorization=<redacted>"
    assert "hypotheses" not in draft["sections"]
    assert draft["sections"]["mitigation"]["status"] == "UNKNOWN"
    assert draft["sections"]["provenance"][0]["capsule_content_sha256"] == (
        envelope["integrity"]["content_sha256"]
    )
    assert "token=must-not-appear" not in result["draft"]["body"]
    assert "operator_note" not in result["draft"]["body"]


def test_generate_records_draft_metadata_once_without_rewriting_capsule_state(tmp_path: Path) -> None:
    store = IncidentCapsuleStore(tmp_path)
    incident_id = uuid4()
    envelope = store.create_placeholder(
        incident_id,
        incident_state={"trigger": "timeout", "target": "worker.run"},
    )
    policy = IncidentCommunicationPolicy()
    first = generate_communication_draft(
        store,
        envelope,
        audience_profile_id="operators-v1",
        policy=policy,
        capsule_policy=store.policy,
        effective_policy_fingerprint="logging-policy-hash",
    )
    latest = store.latest_for_incident(incident_id)
    assert latest is not None
    assert first["recording"]["status"] == "RECORDED"
    assert latest["capsule"]["revision"] == 2
    assert latest["capsule"]["incident_state"]["trigger"] == "timeout"
    assert len(latest["capsule"]["communications"]) == 1

    second = generate_communication_draft(
        store,
        latest,
        audience_profile_id="operators-v1",
        policy=policy,
        capsule_policy=store.policy,
        effective_policy_fingerprint="logging-policy-hash",
    )
    newest = store.latest_for_incident(incident_id)
    assert second["recording"]["status"] == "ALREADY_RECORDED"
    assert newest is not None
    assert newest["capsule"]["revision"] == 2
    assert len(newest["capsule"]["communications"]) == 1


def test_draft_policy_rejects_unknown_audience_and_oversized_output(tmp_path: Path) -> None:
    store = IncidentCapsuleStore(tmp_path)
    envelope = store.create_placeholder(uuid4(), incident_state={"failure": "x"})
    with pytest.raises(CommunicationPolicyError, match="not permitted"):
        build_communication_draft(
            envelope,
            audience_profile_id="missing-v1",
            policy=IncidentCommunicationPolicy(),
        )
    tiny = IncidentCommunicationPolicy(maximum_draft_bytes=1)
    with pytest.raises(CommunicationPolicyError, match="maximum_draft_bytes"):
        build_communication_draft(
            envelope,
            audience_profile_id="operators-v1",
            policy=tiny,
        )


def test_communication_audiences_load_from_logging_policy(tmp_path: Path) -> None:
    policy_file = tmp_path / "caretaker.toml"
    policy_file.write_text(
        """
[logging]
directory = "./data"

[logging.communications]
maximum_draft_bytes = 8192

[[logging.communications.audiences]]
profile_id = "public-v1"
display_name = "Public"
allowed_sections = ["identity", "confirmed_observations", "unknowns", "provenance"]
require_review = true
""",
        encoding="utf-8",
    )
    policy, _snapshot = load_operator_policy(policy_file)
    assert policy.communications.maximum_draft_bytes == 8192
    assert policy.communications.audiences[0].profile_id == "public-v1"
    assert policy.communications.audiences[0].allowed_sections == (
        "identity",
        "confirmed_observations",
        "unknowns",
        "provenance",
    )


def test_cli_exports_a_new_reviewable_draft_without_overwriting(tmp_path: Path) -> None:
    from caretaker.communication_cli import main

    store = IncidentCapsuleStore(tmp_path)
    envelope = store.create_placeholder(uuid4(), incident_state={"trigger": "exception"})
    output = tmp_path / "draft.json"
    assert main([
        "--data-directory", str(tmp_path),
        "--capsule-id", envelope["capsule"]["capsule_id"],
        "--audience-profile", "operators-v1",
        "--output", str(output),
    ]) == 0
    assert output.stat().st_mode & 0o777 == 0o600
    assert '"delivery_authorized": false' in output.read_text(encoding="utf-8")
    assert len(store.load(envelope["capsule"]["capsule_id"])["capsule"]["communications"]) == 1
