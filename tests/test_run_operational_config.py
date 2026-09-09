from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

import pytest
import caretaker.run as run_module

from caretaker.run import (
    _adaptive_threshold_policy_settings,
    _behavior_materialization_log,
    _logging_policy_fingerprint,
    _load_external_signer,
    main,
)


def test_logging_policy_fingerprint_uses_snapshot_content_hash():
    runtime = SimpleNamespace(
        snapshot=SimpleNamespace(content_hash="snapshot-content-hash"),
        effective=SimpleNamespace(generation=7),
    )

    assert _logging_policy_fingerprint(runtime) == "snapshot-content-hash"


def test_external_signer_provider_can_be_loaded_from_module_attribute(monkeypatch):
    module = ModuleType("caretaker_test_signer")

    class Signer:
        def public_identity(self):
            return {"identity_id": "test"}

        def sign_artifact(self, payload: bytes) -> bytes:
            return b"signed:" + payload[:4]

    module.Signer = Signer
    monkeypatch.setitem(sys.modules, module.__name__, module)

    signer = _load_external_signer(f"{module.__name__}:Signer")
    assert signer.public_identity()["identity_id"] == "test"
    assert signer.sign_artifact(b"abcdef").startswith(b"signed:")


def test_adaptive_threshold_changes_become_target_scoped_authority_settings():
    settings = _adaptive_threshold_policy_settings(
        {
            "exception.occurrences": 4,
            "repair_evidence.require_problem_reproduction": False,
            "transition_timeout_seconds": 90,
        },
        target_id="example.target",
    )

    assert [(item.path, item.value, item.target) for item in settings] == [
        ("lightweight.exception.occurrences", 4, "example.target"),
        (
            "lightweight.repair_evidence.require_problem_reproduction",
            False,
            "example.target",
        ),
        ("lightweight.aggregation.transition_timeout_seconds", 90, "example.target"),
    ]


def test_adaptive_threshold_settings_reject_unknown_fields():
    with pytest.raises(ValueError, match="unsupported adaptive threshold field"):
        _adaptive_threshold_policy_settings(
            {"sampling.behavior_every_calls": 1},
            target_id="example.target",
        )


def test_external_signer_provider_requires_contract(monkeypatch):
    module = ModuleType("caretaker_bad_signer")
    module.value = object()
    monkeypatch.setitem(sys.modules, module.__name__, module)

    with pytest.raises(TypeError, match="public_identity"):
        _load_external_signer(f"{module.__name__}:value")


@pytest.mark.parametrize("specification", ("invalid-reference", ":Signer", "module:"))
def test_main_reports_malformed_external_signer_without_traceback(specification, capsys):
    with pytest.raises(SystemExit) as raised:
        main(["--external-signer", specification, "not_a_real_application"])

    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert "caretaker-run: error: external signer configuration is invalid:" in captured.err
    assert "Traceback (most recent call last)" not in captured.err


def test_main_reports_external_signer_import_failure_without_launching_application(monkeypatch, capsys):
    launched = False

    def fail_import(_name):
        raise ImportError("signer dependency is unavailable")

    def unexpected_launch(*_args, **_kwargs):
        nonlocal launched
        launched = True
        raise AssertionError("application should not launch")

    monkeypatch.setattr(run_module.importlib, "import_module", fail_import)
    monkeypatch.setattr(run_module, "LoggingRuntime", unexpected_launch)

    with pytest.raises(SystemExit) as raised:
        main(["--external-signer", "signer:provider", "not_a_real_application"])

    assert raised.value.code == 2
    assert launched is False
    captured = capsys.readouterr()
    assert "signer dependency is unavailable" in captured.err
    assert "Traceback (most recent call last)" not in captured.err


@pytest.mark.parametrize(
    ("module_name", "attribute", "value", "message"),
    (
        ("caretaker_bad_signer_object", "value", object(), "public_identity"),
        (
            "caretaker_bad_signer_methods",
            "value",
            type("PublicOnly", (), {"public_identity": lambda self: {}})(),
            "sign_artifact() or sign_manifest()",
        ),
    ),
)
def test_main_reports_external_signer_contract_failures_without_traceback(
    module_name, attribute, value, message, monkeypatch, capsys
):
    module = ModuleType(module_name)
    setattr(module, attribute, value)
    monkeypatch.setitem(sys.modules, module_name, module)

    with pytest.raises(SystemExit) as raised:
        main(["--external-signer", f"{module_name}:{attribute}", "not_a_real_application"])

    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert message in captured.err
    assert "Traceback (most recent call last)" not in captured.err


def test_main_reports_external_signer_constructor_failure_without_traceback(monkeypatch, capsys):
    module = ModuleType("caretaker_constructor_failure")

    class FailingSigner:
        def __init__(self):
            raise ValueError("signer configuration is incomplete")

    module.FailingSigner = FailingSigner
    monkeypatch.setitem(sys.modules, module.__name__, module)

    with pytest.raises(SystemExit) as raised:
        main(["--external-signer", f"{module.__name__}:FailingSigner", "not_a_real_application"])

    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert "signer configuration is incomplete" in captured.err
    assert "Traceback (most recent call last)" not in captured.err


def test_main_does_not_mislabel_unexpected_signer_failure(monkeypatch):
    def fail_import(_name):
        raise RuntimeError("unexpected signer loader failure")

    monkeypatch.setattr(run_module.importlib, "import_module", fail_import)

    with pytest.raises(RuntimeError, match="unexpected signer loader failure"):
        main(["--external-signer", "signer:provider", "not_a_real_application"])


def test_behavior_materialization_log_consolidates_artifacts_by_cycle():
    message, fields = _behavior_materialization_log((
        {
            "snapshot": {
                "snapshot_id": "snapshot-a",
                "subject_key": "function:lab.behavior_probe",
                "seal_reason": "sample-target-reached",
            },
            "integrity": {"signature_state": "HASH_CHAINED"},
        },
        {
            "snapshot": {
                "snapshot_id": "snapshot-b",
                "subject_key": "function:lab.dependency.json.dumps",
                "seal_reason": "sample-target-reached",
            },
            "integrity": {"signature_state": "HASH_CHAINED"},
        },
    ))

    assert message == (
        "Materialized 2 behavior snapshots for "
        "function:lab.behavior_probe, function:lab.dependency.json.dumps"
    )
    assert fields["snapshot_count"] == 2
    assert fields["snapshot_ids"] == ["snapshot-a", "snapshot-b"]
    assert fields["signature_states"] == ["HASH_CHAINED"]
