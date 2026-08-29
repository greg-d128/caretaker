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
        return '{"summary":"advisory result","findings":["review evidence"]}'

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
        lambda self, prompt: '{"summary":"ok"}',
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
