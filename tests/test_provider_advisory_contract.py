from __future__ import annotations

import json

import pytest

from caretaker.guard.provider import _parse_assessment_response
from caretaker.logging.interrogation import _parse_root_cause_response
from caretaker.provider import _parse_candidate_response
from caretaker.provider_security import (
    ProviderResponseError,
    provider_json_response,
    validate_provider_endpoint,
)


def test_provider_endpoint_rejects_credentials() -> None:
    with pytest.raises(ValueError, match="credentials"):
        validate_provider_endpoint("http://user:pass@127.0.0.1:11434", allow_remote_endpoint=False)


def test_provider_transport_rejects_oversize_and_nonfinite_response(monkeypatch) -> None:
    class Response:
        def __init__(self, value: bytes) -> None:
            self.value = value

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit: int) -> bytes:
            return self.value

    class Opener:
        def __init__(self, value: bytes) -> None:
            self.value = value

        def open(self, _request, timeout):
            assert timeout == 3
            return Response(self.value)

    monkeypatch.setattr(
        "caretaker.provider_security.urllib.request.build_opener",
        lambda _handler: Opener(b"{}"),
    )
    request = __import__("urllib.request", fromlist=["Request"]).Request("http://127.0.0.1")
    assert provider_json_response(request, allow_remote_endpoint=False, timeout_seconds=3) == ({}, "{}")

    monkeypatch.setattr(
        "caretaker.provider_security.urllib.request.build_opener",
        lambda _handler: Opener(b"x" * 5),
    )
    with pytest.raises(ProviderResponseError, match="byte limit"):
        provider_json_response(request, allow_remote_endpoint=False, timeout_seconds=3, maximum_bytes=4)

    monkeypatch.setattr(
        "caretaker.provider_security.urllib.request.build_opener",
        lambda _handler: Opener(b"NaN"),
    )
    with pytest.raises(ProviderResponseError, match="strict JSON"):
        provider_json_response(request, allow_remote_endpoint=False, timeout_seconds=3)


def test_repair_provider_schema_rejects_authority_shaped_fields_and_wrong_lists() -> None:
    with pytest.raises(ValueError, match="unsupported fields"):
        _parse_candidate_response(json.dumps({"candidates": [{"source": "def f(): pass", "approval": True}]}))
    with pytest.raises(ValueError, match="list of strings"):
        _parse_candidate_response(json.dumps({"candidates": [{"source": "def f(): pass", "assumptions": "no"}]}))


def test_guard_and_root_cause_parsers_are_strict_and_advisory_only() -> None:
    guard = {
        "severity": "HIGH",
        "confidence": 0.75,
        "significant_changes": [],
        "suspicious_patterns": [],
        "plausible_benign_explanations": [],
        "recommended_actions": ["review"],
        "requested_additional_evidence": [],
    }
    assert _parse_assessment_response(json.dumps(guard))["severity"] == "HIGH"
    guard["severity"] = "UNKNOWN"
    with pytest.raises(ValueError, match="severity"):
        _parse_assessment_response(json.dumps(guard))
    guard["severity"] = "HIGH"
    guard["confidence"] = float("nan")
    with pytest.raises(ValueError, match="strict JSON"):
        _parse_assessment_response(json.dumps(guard))

    root = {
        "primary_hypothesis": "evidence suggests a change",
        "confidence": 0.5,
        "alternatives": [],
        "missing_evidence": [],
        "recommended_actions": ["inspect"],
    }
    assert _parse_root_cause_response(json.dumps(root))["recommended_actions"] == ["inspect"]
    root["permission"] = "grant"
    with pytest.raises(ValueError, match="fields"):
        _parse_root_cause_response(json.dumps(root))
