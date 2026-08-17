from __future__ import annotations

import sys
from types import ModuleType

import pytest

from caretaker.run import _behavior_materialization_log, _load_external_signer


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


def test_external_signer_provider_requires_contract(monkeypatch):
    module = ModuleType("caretaker_bad_signer")
    module.value = object()
    monkeypatch.setitem(sys.modules, module.__name__, module)

    with pytest.raises(TypeError, match="public_identity"):
        _load_external_signer(f"{module.__name__}:value")


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
