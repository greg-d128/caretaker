from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from caretaker.capsule import IncidentCapsuleStore
from caretaker.capsule_assistance import IncidentCapsuleAssistant, assist_capsules


def test_assistance_runs_independently_per_capsule_without_mutation(tmp_path: Path, monkeypatch) -> None:
    store = IncidentCapsuleStore(tmp_path)
    first = store.create_placeholder(uuid4(), incident_state={"message": "first"})
    second = store.create_placeholder(uuid4(), incident_state={"message": "second"})
    before = sorted(path.name for path in store.directory.glob("*.json"))
    prompts: list[str] = []

    def fake_chat(self: IncidentCapsuleAssistant, prompt: str) -> str:
        prompts.append(prompt)
        return '{"summary":"advisory result","findings":["review evidence"],"uncertainties":[],"recommended_checks":[]}'

    monkeypatch.setattr(IncidentCapsuleAssistant, "_chat", fake_chat)
    result = assist_capsules(
        store,
        store.list_summaries(limit=10),
        query="Which historical incidents share a likely contributing condition?",
        model="local-test-model",
    )

    assert result["advisory_only"] is True
    assert result["capsule_mutated"] is False
    assert result["result_count"] == 2
    assert [item["status"] for item in result["results"]] == ["COMPLETED", "COMPLETED"]
    assert len(prompts) == 2
    assert sorted(path.name for path in store.directory.glob("*.json")) == before
    assert store.load(first["capsule"]["capsule_id"])["capsule"]["revision"] == 1
    assert store.load(second["capsule"]["capsule_id"])["capsule"]["revision"] == 1


def test_assistance_skips_invalid_capsules_and_preserves_result_per_incident(tmp_path: Path, monkeypatch) -> None:
    store = IncidentCapsuleStore(tmp_path)
    valid = store.create_placeholder(uuid4())
    invalid = store.create_placeholder(uuid4())
    invalid_path = store.directory / f"{invalid['capsule']['capsule_id']}.r1.json"
    invalid_path.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        IncidentCapsuleAssistant,
        "_chat",
        lambda self, prompt: '{"summary":"ok","findings":[],"uncertainties":[],"recommended_checks":[]}',
    )
    result = assist_capsules(
        store,
        store.list_summaries(limit=10),
        query="Summarize this incident",
        model="local-test-model",
    )

    statuses = {item["capsule_id"]: item["status"] for item in result["results"]}
    assert statuses[valid["capsule"]["capsule_id"]] == "COMPLETED"
    assert statuses[invalid["capsule"]["capsule_id"]] == "SKIPPED_INVALID_CAPSULE"


def test_assistance_rejects_remote_provider_endpoint() -> None:
    with pytest.raises(ValueError, match="remote provider endpoints"):
        IncidentCapsuleAssistant(model="local-test-model", endpoint="http://example.invalid/api/generate")


def test_assistance_rejects_authority_shaped_provider_fields(tmp_path: Path, monkeypatch) -> None:
    store = IncidentCapsuleStore(tmp_path)
    created = store.create_placeholder(uuid4())
    envelope = store.load(created["capsule"]["capsule_id"])
    monkeypatch.setattr(
        IncidentCapsuleAssistant,
        "_chat",
        lambda self, prompt: '{"summary":"ok","findings":[],"uncertainties":[],"recommended_checks":[],"repair":{"enabled":true}}',
    )

    with pytest.raises(ValueError, match="response fields are invalid"):
        IncidentCapsuleAssistant(model="local-test-model").assist(
            envelope,
            query="Summarize this incident",
        )


def test_noninteractive_cli_submits_batch_query_to_control_plane(tmp_path: Path, monkeypatch, capsys) -> None:
    from caretaker import capsule_cli

    socket_path = tmp_path / "control.sock"
    captured = {}

    monkeypatch.setattr(capsule_cli, "discover_control_socket", lambda directory: socket_path)

    def fake_control_request(path, request, timeout):
        captured.update({"path": path, "request": request, "timeout": timeout})
        return {"ok": True, "scope": "all", "result_count": 2, "results": []}

    monkeypatch.setattr(capsule_cli, "control_request", fake_control_request)
    assert capsule_cli.main([
        "--data-directory", str(tmp_path),
        "--query", "Compare historical failure patterns",
        "--model", "local-test-model",
        "--scope", "all",
    ]) == 0

    output = capsys.readouterr().out
    assert '"result_count": 2' in output
    assert captured["path"] == socket_path
    assert captured["request"]["command"] == "incident-capsule-assist"
    assert captured["request"]["query"] == "Compare historical failure patterns"
    assert captured["timeout"] == 360.0


def test_noninteractive_replay_cli_submits_historical_batch_to_control_plane(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    from caretaker import capsule_replay_cli

    socket_path = tmp_path / "control.sock"
    captured = {}
    monkeypatch.setattr(capsule_replay_cli, "discover_control_socket", lambda directory: socket_path)

    def fake_control_request(path, request, timeout):
        captured.update({"path": path, "request": request, "timeout": timeout})
        return {"ok": True, "scope": "all", "fixture_count": 0, "results": []}

    monkeypatch.setattr(capsule_replay_cli, "control_request", fake_control_request)
    assert capsule_replay_cli.main([
        "--data-directory", str(tmp_path),
        "--entrypoint", "charge",
        "--source", "def charge(value):\n    return value + 1\n",
        "--scope", "all",
        "--target-id", "app:charge",
        "--limit", "10",
    ]) == 0

    output = capsys.readouterr().out
    assert '"fixture_count": 0' in output
    assert captured["path"] == socket_path
    assert captured["request"]["command"] == "incident-capsule-replay-batch"
    assert captured["request"]["scope"] == "all"
    assert captured["request"]["target_id"] == "app:charge"
    assert captured["request"]["limit"] == 10
    assert captured["timeout"] == 360.0


def test_replay_audit_projection_is_bounded_and_advisory() -> None:
    from caretaker.run import _emit_incident_replay_audit

    class Audit:
        def __init__(self) -> None:
            self.events = []

        def emit(self, event_type, **fields):
            self.events.append((event_type, fields))

    class Runtime:
        def __init__(self) -> None:
            self.audit = Audit()

    runtime = Runtime()
    _emit_incident_replay_audit(
        runtime,
        replay_scope="all",
        actor_id="uid:1001",
        request={"incident_id": "incident-1"},
        result={
            "fixture_count": 2,
            "completed_count": 1,
            "dispatched_count": 1,
            "results": [
                {"status": "COMPLETED"},
                {"status": "FAILED"},
            ],
        },
    )
    _emit_incident_replay_audit(
        runtime,
        replay_scope="selected",
        actor_id="uid:1001",
        request={"fixture_id": "fixture-1"},
        error="fixture rejected",
    )

    assert [event[0] for event in runtime.audit.events] == [
        "INCIDENT_REPLAY_OUTCOME",
        "INCIDENT_REPLAY_OUTCOME",
    ]
    batch = runtime.audit.events[0][1]
    assert batch["scope"]["replay_scope"] == "all"
    assert batch["outcome"] == {
        "state": "PARTIAL",
        "capsule_modified": False,
        "authority_granted": False,
        "integrity_verified": True,
    }
    rejected = runtime.audit.events[1][1]
    assert rejected["outcome"]["state"] == "REJECTED"
    assert rejected["outcome"]["authority_granted"] is False
    assert rejected["details"]["error"] == "fixture rejected"
