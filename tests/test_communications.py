from __future__ import annotations

import json
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
    review_communication_draft,
    tailor_communication_draft,
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
llm_tailoring_enabled = true

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
    assert policy.communications.llm_tailoring_enabled is True
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


def test_cli_can_request_policy_enabled_advisory_tailoring(tmp_path: Path, monkeypatch, capsys) -> None:
    from caretaker.communication_cli import main

    policy_file = tmp_path / "caretaker.toml"
    policy_file.write_text(
        """
[logging]
directory = "./data"

[logging.communications]
llm_tailoring_enabled = true
""",
        encoding="utf-8",
    )
    store = IncidentCapsuleStore(tmp_path)
    envelope = store.create_placeholder(uuid4(), incident_state={"trigger": "exception"})
    monkeypatch.setattr(
        "caretaker.communications.CommunicationDraftAssistant._chat",
        lambda _assistant, _prompt: json.dumps({
            "body": (
                "Incident wording suggestion\n"
                "Status: DRAFT — review required\n"
                "Delivery: not authorized; this is a reviewable draft only."
            )
        }),
    )
    assert main([
        "--data-directory", str(tmp_path),
        "--policy", str(policy_file),
        "--capsule-id", envelope["capsule"]["capsule_id"],
        "--audience-profile", "operators-v1",
        "--no-record",
        "--tailor-model", "local-model",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["tailoring"]["advisory_only"] is True
    assert result["tailoring"]["delivery_authorized"] is False
    assert result["recording"]["capsule_mutated"] is False


def test_review_records_explicit_decision_once_without_authorizing_delivery(tmp_path: Path) -> None:
    store = IncidentCapsuleStore(tmp_path)
    incident_id = uuid4()
    envelope = store.create_placeholder(incident_id, incident_state={"trigger": "exception"})
    draft = generate_communication_draft(
        store,
        envelope,
        audience_profile_id="operators-v1",
        policy=IncidentCommunicationPolicy(),
        capsule_policy=store.policy,
    )
    draft_id = draft["draft"]["draft_id"]
    latest = store.latest_for_incident(incident_id)
    assert latest is not None
    reviewed = review_communication_draft(
        store,
        latest,
        draft_id=draft_id,
        decision="approved",
        reason="Operator verified the facts",
        capsule_policy=store.policy,
        reviewer_identity="uid:1000",
    )
    assert reviewed["status"] == "RECORDED"
    assert reviewed["delivery_authorized"] is False
    after_review = store.latest_for_incident(incident_id)
    assert after_review is not None
    assert after_review["capsule"]["revision"] == 3
    assert len(after_review["capsule"]["communications"]) == 2
    review_record = after_review["capsule"]["communications"][1]
    assert review_record["status"] == "approved"
    assert review_record["metadata"]["review_decision"] == "approved"
    assert review_record["metadata"]["delivery_authorized"] is False

    repeated = review_communication_draft(
        store,
        after_review,
        draft_id=draft_id,
        decision="rejected",
        reason="A different later decision cannot rewrite history",
        capsule_policy=store.policy,
        reviewer_identity="uid:1000",
    )
    assert repeated["status"] == "ALREADY_REVIEWED"
    assert store.latest_for_incident(incident_id)["capsule"]["revision"] == 3


def test_review_requires_recorded_draft_and_reason(tmp_path: Path) -> None:
    store = IncidentCapsuleStore(tmp_path)
    envelope = store.create_placeholder(uuid4())
    with pytest.raises(CommunicationPolicyError, match="not recorded"):
        review_communication_draft(
            store,
            envelope,
            draft_id=str(uuid4()),
            decision="approved",
            reason="review",
            capsule_policy=store.policy,
            reviewer_identity="uid:1000",
        )


def test_llm_tailoring_is_disabled_by_default_and_preserves_canonical_draft(tmp_path: Path, monkeypatch) -> None:
    store = IncidentCapsuleStore(tmp_path)
    envelope = store.create_placeholder(
        uuid4(),
        incident_state={"trigger": "exception", "impact": "unknown"},
    )
    draft = generate_communication_draft(
        store,
        envelope,
        audience_profile_id="operators-v1",
        policy=IncidentCommunicationPolicy(),
        capsule_policy=store.policy,
        record=False,
    )
    with pytest.raises(CommunicationPolicyError, match="disabled by policy"):
        tailor_communication_draft(
            draft,
            policy=IncidentCommunicationPolicy(),
            model="local-model",
        )

    policy = IncidentCommunicationPolicy(llm_tailoring_enabled=True)
    draft = generate_communication_draft(
        store,
        envelope,
        audience_profile_id="operators-v1",
        policy=policy,
        capsule_policy=store.policy,
        record=False,
    )
    prompts: list[str] = []

    def fake_chat(_assistant, prompt: str) -> str:
        prompts.append(prompt)
        return json.dumps({
            "body": (
                "Incident rewritten for clarity\n"
                "Status: DRAFT — review required\n"
                "Impact remains unknown.\n"
                "token=must-not-pass\n"
                "Delivery: not authorized; this is a reviewable draft only."
            )
        })

    monkeypatch.setattr(
        "caretaker.communications.CommunicationDraftAssistant._chat",
        fake_chat,
    )
    canonical_body = draft["draft"]["body"]
    result = tailor_communication_draft(
        draft,
        policy=policy,
        model="local-model",
    )
    assert result["canonical_body"] == canonical_body
    assert result["suggested_body"] != canonical_body
    assert "token=must-not-pass" not in result["suggested_body"]
    assert "token=<redacted>" in result["suggested_body"]
    assert result["advisory_only"] is True
    assert result["draft_mutated"] is False
    assert result["delivery_authorized"] is False
    assert draft["draft"]["body"] == canonical_body
    assert prompts and "DRAFT_DATA" in prompts[0]


def test_llm_tailoring_rejects_tampering_and_removed_safety_caveats(tmp_path: Path, monkeypatch) -> None:
    store = IncidentCapsuleStore(tmp_path)
    envelope = store.create_placeholder(uuid4(), incident_state={"trigger": "timeout"})
    policy = IncidentCommunicationPolicy(llm_tailoring_enabled=True)
    draft = generate_communication_draft(
        store,
        envelope,
        audience_profile_id="operators-v1",
        policy=policy,
        capsule_policy=store.policy,
        record=False,
    )
    tampered = {**draft, "draft": {**draft["draft"], "body": "tampered"}}
    with pytest.raises(CommunicationPolicyError, match="content hash is invalid"):
        tailor_communication_draft(tampered, policy=policy, model="local-model")

    monkeypatch.setattr(
        "caretaker.communications.CommunicationDraftAssistant._chat",
        lambda _assistant, _prompt: json.dumps({"body": "Status: DRAFT only"}),
    )
    with pytest.raises(CommunicationPolicyError, match="safety caveats"):
        tailor_communication_draft(draft, policy=policy, model="local-model")


def test_review_cli_records_decision_and_does_not_claim_delivery(tmp_path: Path, capsys) -> None:
    from caretaker.communication_cli import main as draft_main
    from caretaker.communication_review_cli import main as review_main

    store = IncidentCapsuleStore(tmp_path)
    envelope = store.create_placeholder(uuid4(), incident_state={"trigger": "timeout"})
    draft_main([
        "--data-directory", str(tmp_path),
        "--capsule-id", envelope["capsule"]["capsule_id"],
        "--audience-profile", "operators-v1",
    ])
    draft_output = capsys.readouterr().out
    draft_id = json.loads(draft_output)["draft"]["draft_id"]
    assert review_main([
        "--data-directory", str(tmp_path),
        "--capsule-id", envelope["capsule"]["capsule_id"],
        "--draft-id", draft_id,
        "--decision", "rejected",
        "--reason", "Missing customer impact confirmation",
    ]) == 0
    review_output = json.loads(capsys.readouterr().out)
    assert review_output["delivery_authorized"] is False
    assert review_output["status"] == "RECORDED"
