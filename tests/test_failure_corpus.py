from __future__ import annotations

import json
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

from caretaker.failure_corpus import (
    FailureCorpus,
    FailureCorpusError,
    FailureCorpusExecutionPolicy,
    FailureCorpusHarness,
    FailureCorpusObservationStore,
    FailureCorpusPodmanRunner,
    FailureCorpusMultipassRunner,
    FailureCorpusProcessRunner,
    MAX_CORPUS_BYTES,
)
from caretaker.failure_corpus_cli import main as failure_corpus_report_main


ROOT = Path(__file__).resolve().parents[1]


def test_repository_failure_corpus_is_bounded_metadata_only() -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")

    assert corpus.corpus_id == "caretaker-default-failure-corpus-v1"
    assert len(corpus.scenarios) == 10
    assert {item.category for item in corpus.scenarios} == {
        "exception", "timeout", "invalid-output", "dependency", "configuration",
        "resource", "worker", "repair", "malicious-evidence", "llm",
    }
    assert all(item.summary()["executable"] is False for item in corpus.scenarios)
    assert all("stimulus" in item.summary() for item in corpus.scenarios)


def test_failure_corpus_is_read_only_and_bounded(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "corpus_id": "test-corpus",
        "description": "test",
        "scenarios": [{
            "scenario_id": "exception.test",
            "category": "exception",
            "description": "test",
            "stimulus": "test input",
            "expected": {
                "signal": "EXCEPTION",
                "caretaker_action": "CAPTURE_INCIDENT",
                "authority_effect": "NO_AUTHORITY_CHANGE",
                "minimum_isolation": "PROCESS",
            },
            "tags": [],
        }],
    }))
    corpus = FailureCorpus.load(path)

    assert corpus.get("exception.test").minimum_isolation == "PROCESS"
    assert corpus.list_summaries(limit=1)[0]["executable"] is False
    with pytest.raises(KeyError):
        corpus.get("exception.missing")
    with pytest.raises(FailureCorpusError, match="byte limit"):
        FailureCorpus.load(path, maximum_bytes=1)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("scenario_id", "not valid", "identifier"),
        ("category", "unknown", "unknown category"),
        ("expected_signal", "NOT_A_SIGNAL", "unknown expected signal"),
    ),
)
def test_failure_corpus_rejects_unsafe_or_unknown_values(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    manifest = {
        "schema_version": 1,
        "corpus_id": "test-corpus",
        "description": "test",
        "scenarios": [{
            "scenario_id": "exception.test",
            "category": "exception",
            "description": "test",
            "stimulus": "test input",
            "expected": {
                "signal": "EXCEPTION",
                "caretaker_action": "CAPTURE_INCIDENT",
                "authority_effect": "NO_AUTHORITY_CHANGE",
                "minimum_isolation": "PROCESS",
            },
            "tags": [],
        }],
    }
    if field == "expected_signal":
        manifest["scenarios"][0]["expected"]["signal"] = value
    else:
        manifest["scenarios"][0][field] = value
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))

    with pytest.raises(FailureCorpusError, match=message):
        FailureCorpus.load(path)


def test_failure_corpus_rejects_executable_manifest_fields(tmp_path: Path) -> None:
    manifest = {
        "schema_version": 1,
        "corpus_id": "test-corpus",
        "description": "test",
        "scenarios": [],
        "command": "python -c malicious",
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))

    with pytest.raises(FailureCorpusError, match="manifest fields"):
        FailureCorpus.load(path)


def test_trusted_harness_records_observed_result_separately() -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    harness = FailureCorpusHarness(
        corpus,
        runners={
            "exception.unhandled": lambda _scenario: {
                "signal": "EXCEPTION",
                "caretaker_action": "CAPTURE_INCIDENT",
                "authority_effect": "NO_AUTHORITY_CHANGE",
            },
        },
    )

    observation = harness.run("exception.unhandled")

    assert observation.status == "MATCHED"
    assert observation.executed is True
    assert observation.summary()["expected"]["signal"] == "EXCEPTION"
    assert observation.summary()["observed"]["signal"] == "EXCEPTION"


def test_trusted_harness_refuses_runner_below_declared_isolation() -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    called = False

    def runner(_scenario):
        nonlocal called
        called = True
        return {
            "signal": "DEPENDENCY_FAILURE",
            "caretaker_action": "CAPTURE_INCIDENT",
            "authority_effect": "NO_AUTHORITY_CHANGE",
        }

    harness = FailureCorpusHarness(
        corpus,
        runners={"dependency.changed": runner},
        isolation="PROCESS",
    )

    observation = harness.run("dependency.changed")

    assert observation.status == "ISOLATION_UNAVAILABLE"
    assert observation.executed is False
    assert called is False


def test_trusted_harness_applies_policy_minimum_and_disabled_state() -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    called = False

    def runner(_scenario):
        nonlocal called
        called = True
        return {
            "signal": "EXCEPTION",
            "caretaker_action": "CAPTURE_INCIDENT",
            "authority_effect": "NO_AUTHORITY_CHANGE",
        }

    strict = FailureCorpusHarness(
        corpus,
        runners={"exception.unhandled": runner},
        policy=FailureCorpusExecutionPolicy(minimum_isolation="CONTAINER"),
    )
    unavailable = strict.run("exception.unhandled")
    assert unavailable.status == "ISOLATION_UNAVAILABLE"
    assert unavailable.required_isolation == "CONTAINER"
    assert called is False

    disabled = FailureCorpusHarness(
        corpus,
        runners={"exception.unhandled": runner},
        policy=FailureCorpusExecutionPolicy(enabled=False),
    ).run("exception.unhandled")
    assert disabled.status == "POLICY_DISABLED"
    assert disabled.executed is False
    assert called is False


def test_process_runner_uses_explicit_json_command_and_cleans_workspace(tmp_path: Path) -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    command = [
        sys.executable,
        "-c",
        (
            "import json,sys; json.load(sys.stdin); "
            "print(json.dumps({'signal':'EXCEPTION','caretaker_action':'CAPTURE_INCIDENT',"
            "'authority_effect':'NO_AUTHORITY_CHANGE'}))"
        ),
    ]
    runner = FailureCorpusProcessRunner(
        corpus,
        {"exception.unhandled": command},
        workspace_root=tmp_path,
    )

    observation = runner.run("exception.unhandled")

    assert observation.status == "MATCHED"
    assert observation.executed is True
    assert tuple(tmp_path.iterdir()) == ()


def test_process_runner_fails_closed_when_policy_requires_stronger_isolation() -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    runner = FailureCorpusProcessRunner(
        corpus,
        {"exception.unhandled": [sys.executable, "-c", "raise SystemExit(99)"]},
        policy=FailureCorpusExecutionPolicy(minimum_isolation="CONTAINER"),
    )

    observation = runner.run("exception.unhandled")

    assert observation.status == "ISOLATION_UNAVAILABLE"
    assert observation.executed is False


def test_process_runner_records_command_failure_and_kills_timeout_process_group(tmp_path: Path) -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    failed = FailureCorpusProcessRunner(
        corpus,
        {"exception.unhandled": [sys.executable, "-c", "raise SystemExit(7)"]},
        workspace_root=tmp_path,
    ).run("exception.unhandled")
    timed_out = FailureCorpusProcessRunner(
        corpus,
        {"exception.unhandled": [sys.executable, "-c", "import time; time.sleep(10)"]},
        timeout_seconds=0.05,
        workspace_root=tmp_path,
    ).run("exception.unhandled")

    assert failed.status == "ERROR"
    assert "status 7" in (failed.error or "")
    assert timed_out.status == "ERROR"
    assert "timeout" in (timed_out.error or "")
    assert tuple(tmp_path.iterdir()) == ()


def test_podman_runner_verifies_rootless_image_and_hardening_flags(monkeypatch) -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    calls: list[list[str]] = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        if command[1:4] == ["info", "--format", "json"]:
            return SimpleNamespace(
                returncode=0,
                stdout='{"host":{"security":{"rootless":true}}}',
                stderr="",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    class FakeProcess:
        pid = 1234
        returncode = 0

        def communicate(self, *, input, timeout):
            assert '"scenario_id":"exception.unhandled"' in input
            assert timeout == 5.0
            return (
                '{"signal":"EXCEPTION","caretaker_action":"CAPTURE_INCIDENT",'
                '"authority_effect":"NO_AUTHORITY_CHANGE"}',
                "",
            )

    launched: list[list[str]] = []
    monkeypatch.setattr("caretaker.failure_corpus.shutil.which", lambda _name: "/usr/bin/podman")
    monkeypatch.setattr("caretaker.failure_corpus.subprocess.run", fake_run)
    monkeypatch.setattr(
        "caretaker.failure_corpus.subprocess.Popen",
        lambda command, **_kwargs: launched.append(command) or FakeProcess(),
    )
    runner = FailureCorpusPodmanRunner(
        corpus,
        "localhost/caretaker-replay-base:0.6.1",
        {"exception.unhandled": ["trusted-runner", "--json"]},
        policy=FailureCorpusExecutionPolicy(minimum_isolation="CONTAINER"),
        timeout_seconds=5,
        environment={"RUNNER_MODE": "test"},
    )

    observation = runner.run("exception.unhandled")

    assert observation.status == "MATCHED"
    assert len(calls) == 2
    assert launched
    assert "--network=none" in launched[0]
    assert "--read-only" in launched[0]
    assert "--cap-drop=ALL" in launched[0]
    assert "--security-opt=no-new-privileges" in launched[0]
    assert "--userns=keep-id" in launched[0]
    assert "--mount" not in launched[0]
    assert launched[0][-3:] == ["localhost/caretaker-replay-base:0.6.1", "trusted-runner", "--json"]


def test_podman_runner_fails_closed_when_rootless_or_image_preflight_fails(monkeypatch) -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    monkeypatch.setattr("caretaker.failure_corpus.shutil.which", lambda _name: "/usr/bin/podman")
    monkeypatch.setattr(
        "caretaker.failure_corpus.subprocess.run",
        lambda _command, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout='{"host":{"security":{"rootless":false}}}',
            stderr="",
        ),
    )
    runner = FailureCorpusPodmanRunner(
        corpus,
        "localhost/caretaker-replay-base:0.6.1",
        {"exception.unhandled": ["trusted-runner"]},
    )

    observation = runner.run("exception.unhandled")

    assert observation.status == "ISOLATION_UNAVAILABLE"
    assert observation.executed is False


def test_multipass_runner_transfers_request_and_cleans_disposable_clone(monkeypatch, tmp_path: Path) -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    host_calls: list[list[str]] = []
    guest_calls: list[list[str]] = []
    runner = FailureCorpusMultipassRunner(
        corpus,
        {"exception.unhandled": ["/opt/trusted-runner", "--json"]},
        policy=FailureCorpusExecutionPolicy(minimum_isolation="VM"),
        instance_name="caretaker-template",
        clean_snapshot=None,
        disposable_clone=True,
        require_network_isolation=False,
        timeout_seconds=5,
    )
    monkeypatch.setattr(runner, "available", lambda: (True, None))
    monkeypatch.setattr(
        runner,
        "_create_disposable_clone",
        lambda: ("caretaker-clone", None),
    )
    monkeypatch.setattr(runner, "_verify_guest_prerequisites", lambda _instance: (True, None))
    monkeypatch.setattr(runner, "_destroy_disposable_clone", lambda instance: host_calls.append(["delete", instance]))

    def fake_host(command, timeout=None):
        host_calls.append(list(command))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def fake_guest(instance, command, timeout=None):
        guest_calls.append([instance, *command])
        if command[0] == "/opt/trusted-runner":
            assert command[-1].startswith("/tmp/caretaker-failure-corpus-")
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    '{"signal":"EXCEPTION","caretaker_action":"CAPTURE_INCIDENT",'
                    '"authority_effect":"NO_AUTHORITY_CHANGE"}'
                ),
                stderr="",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(runner, "_host_command", fake_host)
    monkeypatch.setattr(runner, "_guest_command", fake_guest)

    observation = runner.run("exception.unhandled")

    assert observation.status == "MATCHED"
    assert host_calls[0][0:2] == ["multipass", "transfer"]
    assert host_calls[-1] == ["delete", "caretaker-clone"]
    assert guest_calls[0][0] == "caretaker-clone"
    assert guest_calls[-1][1:3] == ["rm", "-f"]
    assert not any("mount" in call for call in host_calls)


def test_multipass_runner_fails_closed_when_vm_preflight_is_unavailable(monkeypatch) -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    runner = FailureCorpusMultipassRunner(
        corpus,
        {"exception.unhandled": ["/opt/trusted-runner"]},
        policy=FailureCorpusExecutionPolicy(minimum_isolation="VM"),
        require_network_isolation=False,
    )
    monkeypatch.setattr(runner, "available", lambda: (False, "validator guest is unavailable"))

    observation = runner.run("exception.unhandled")

    assert observation.status == "ISOLATION_UNAVAILABLE"
    assert observation.executed is False


def test_trusted_harness_distinguishes_mismatched_and_invalid_results() -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    harness = FailureCorpusHarness(
        corpus,
        runners={
            "exception.unhandled": lambda _scenario: {
                "signal": "TIMEOUT",
                "caretaker_action": "RECORD_EVIDENCE",
                "authority_effect": "NO_AUTHORITY_CHANGE",
            },
            "worker.failed": lambda _scenario: {"signal": "WORKER_FAILURE"},
        },
    )

    mismatched = harness.run("exception.unhandled")
    invalid = harness.run("worker.failed")

    assert mismatched.status == "MISMATCHED"
    assert invalid.status == "INVALID_RESULT"


def test_trusted_harness_rejects_unsupported_observed_fields() -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    harness = FailureCorpusHarness(
        corpus,
        runners={
            "exception.unhandled": lambda _scenario: {
                "signal": "EXCEPTION",
                "caretaker_action": "CAPTURE_INCIDENT",
                "authority_effect": "NO_AUTHORITY_CHANGE",
                "command": "must not be persisted",
            },
        },
    )

    observation = harness.run("exception.unhandled")

    assert observation.status == "INVALID_RESULT"
    assert "unsupported fields" in (observation.error or "")


def test_observation_store_round_trip_and_filters(tmp_path: Path) -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    observation = FailureCorpusHarness(
        corpus,
        runners={
            "exception.unhandled": lambda _scenario: {
                "signal": "EXCEPTION",
                "caretaker_action": "CAPTURE_INCIDENT",
                "authority_effect": "NO_AUTHORITY_CHANGE",
                "details": {"source": "trusted-test"},
            },
        },
    ).run("exception.unhandled")
    store = FailureCorpusObservationStore(tmp_path)

    record = store.record(
        observation,
        corpus_id=corpus.corpus_id,
        environment_id="process-linux",
        incident_id="incident-123",
    )
    loaded = store.load(record["observation_id"])
    summaries = store.list_summaries(scenario_id="exception.unhandled", status="MATCHED")

    assert loaded == record
    assert len(record["content_sha256"]) == 64
    assert loaded["environment_id"] == "process-linux"
    assert loaded["incident_id"] == "incident-123"
    assert summaries[0]["observation"]["observed"]["details"]["source"] == "trusted-test"


def test_observation_store_rejects_corrupt_records_and_skips_them_in_listing(tmp_path: Path) -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    observation = FailureCorpusHarness(corpus, runners={}).run("exception.unhandled")
    store = FailureCorpusObservationStore(tmp_path)
    record = store.record(observation, corpus_id=corpus.corpus_id)
    path = store.directory / f"{record['observation_id']}.json"
    path.write_text(path.read_text(encoding="utf-8").replace("NOT_MAPPED", "MATCHED"), encoding="utf-8")

    with pytest.raises(FailureCorpusError, match="content hash"):
        store.load(record["observation_id"])
    assert store.list_summaries() == ()


def test_observation_store_enforces_serialized_size_limit(tmp_path: Path) -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    observation = FailureCorpusHarness(corpus, runners={}).run("exception.unhandled")
    store = FailureCorpusObservationStore(tmp_path, maximum_observation_bytes=64)

    with pytest.raises(FailureCorpusError, match="byte limit"):
        store.record(observation, corpus_id=corpus.corpus_id)


def test_observation_store_builds_bounded_deterministic_outcome_report(tmp_path: Path) -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    harness = FailureCorpusHarness(
        corpus,
        runners={
            "exception.unhandled": lambda _scenario: {
                "signal": "EXCEPTION",
                "caretaker_action": "CAPTURE_INCIDENT",
                "authority_effect": "NO_AUTHORITY_CHANGE",
            },
            "worker.failed": lambda _scenario: {
                "signal": "WORKER_FAILURE",
                "caretaker_action": "REPLACE_WORKER",
                "authority_effect": "NO_AUTHORITY_CHANGE",
            },
        },
    )
    store = FailureCorpusObservationStore(tmp_path)
    first = store.record(
        harness.run("exception.unhandled"),
        corpus_id=corpus.corpus_id,
        environment_id="process-linux",
    )
    second = store.record(
        harness.run("worker.failed"),
        corpus_id=corpus.corpus_id,
        environment_id="process-linux",
    )

    report = store.build_outcome_report(corpus_id=corpus.corpus_id, limit=1)
    same_report = store.build_outcome_report(corpus_id=corpus.corpus_id, limit=1)

    assert report == same_report
    assert report["records_available"] == 2
    assert report["records_included"] == 1
    assert report["truncated"] is True
    assert report["status_counts"] == {"MATCHED": 1}
    assert list(report["scenario_counts"]) in [["exception.unhandled"], ["worker.failed"]]
    assert report["provenance"][0]["observation_id"] in {
        first["observation_id"], second["observation_id"]
    }
    assert len(report["content_sha256"]) == 64


def test_observation_store_outcome_report_counts_corrupt_records(tmp_path: Path) -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    store = FailureCorpusObservationStore(tmp_path)
    record = store.record(
        FailureCorpusHarness(corpus, runners={}).run("exception.unhandled"),
        corpus_id=corpus.corpus_id,
    )
    path = store.directory / f"{record['observation_id']}.json"
    path.write_text(path.read_text(encoding="utf-8").replace("NOT_MAPPED", "MATCHED"), encoding="utf-8")

    report = store.build_outcome_report(corpus_id=corpus.corpus_id)

    assert report["records_available"] == 0
    assert report["corrupt_records"] == 1
    assert report["provenance"] == []


def test_observation_store_persists_and_verifies_content_addressed_report(tmp_path: Path) -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    store = FailureCorpusObservationStore(tmp_path)
    store.record(
        FailureCorpusHarness(corpus, runners={}).run("exception.unhandled"),
        corpus_id=corpus.corpus_id,
    )
    report = store.build_outcome_report(corpus_id=corpus.corpus_id)

    persisted = store.persist_outcome_report(report)
    loaded = store.load_outcome_report(report["content_sha256"])
    persisted_again = store.persist_outcome_report(report)

    assert loaded == report
    assert persisted == report
    assert persisted_again == report
    assert len(tuple(store.report_directory.glob("*.json"))) == 1

    path = store.report_directory / f"{report['content_sha256']}.json"
    path.write_text(path.read_text(encoding="utf-8").replace("NOT_MAPPED", "MATCHED"), encoding="utf-8")
    with pytest.raises(FailureCorpusError, match="content hash"):
        store.load_outcome_report(report["content_sha256"])


def test_failure_corpus_report_cli_is_read_only_and_can_persist(tmp_path: Path, capsys) -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    store = FailureCorpusObservationStore(tmp_path)
    store.record(
        FailureCorpusHarness(corpus, runners={}).run("exception.unhandled"),
        corpus_id=corpus.corpus_id,
    )

    assert failure_corpus_report_main([
        "--data-directory", str(tmp_path),
        "--corpus-id", corpus.corpus_id,
        "--persist",
    ]) == 0
    output = json.loads(capsys.readouterr().out)

    assert output["records_available"] == 1
    assert output["status_counts"] == {"NOT_MAPPED": 1}
    assert len(tuple((tmp_path / "failure-corpus-reports").glob("*.json"))) == 1


def test_trusted_harness_run_all_is_bounded_and_preserves_unmapped_scenarios() -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")
    harness = FailureCorpusHarness(corpus, runners={})

    observations = harness.run_all(limit=2)

    assert len(observations) == 2
    assert all(item.status == "NOT_MAPPED" for item in observations)
