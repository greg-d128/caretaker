from __future__ import annotations

import hashlib
import math
import subprocess
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

import caretaker
from caretaker import (
    CandidateProposal,
    ExceptionTrigger,
    ObservationPolicy,
    RepairEngine,
    RepairPolicy,
    ReplaySafety,
    RetryPolicy,
    StatePolicy,
    StaticRepairProvider,
    ValidationIsolationLevel,
    ValidationPolicy,
    repair,
)
from caretaker.domain import (
    ArtifactFile,
    CandidateGeneratorKind,
    RepairArtifact,
    RepairArtifactKind,
    RepairCandidate,
    utcnow,
)
from caretaker.guard.policy import BaselinePolicy, GuardPolicy, validate_guard_policy
from caretaker.validation import (
    Ed25519ValidationResultAuthenticator,
    MultipassValidationBackend,
    sign_validation_result,
    SubprocessValidationBackend,
    ValidationBackendCapabilities,
)
from tests.sample_targets import broken_divide


def _candidate_source() -> str:
    return """\
def broken_divide(total: float, count: int) -> float:
    if count == 0:
        return 0.0
    return total / count
"""


def _proposal() -> CandidateProposal:
    return CandidateProposal(
        source=_candidate_source(),
        explanation="local security-assurance regression candidate",
    )


def _automatic_policy() -> RepairPolicy:
    return RepairPolicy.automatic(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
        observation=ObservationPolicy(
            initial_successful_executions=1,
            long_term_successful_executions=1,
            long_term_minimum_duration_seconds=0,
        ),
    )


def _repair_candidate(target) -> RepairCandidate:
    source = _candidate_source()
    source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    return RepairCandidate(
        candidate_id=uuid4(),
        generation_id=uuid4(),
        episode_id=uuid4(),
        incident_id=uuid4(),
        target_id=target.target_id,
        created_at=utcnow(),
        base_function_version=target.slot.load().number,
        base_source_hash=target.slot.load().source_hash,
        artifact=RepairArtifact(
            kind=RepairArtifactKind.FUNCTION_REPLACEMENT,
            files=(
                ArtifactFile(
                    relative_path="__candidate__.py",
                    operation="replace-function",
                    content=source,
                    content_hash=source_hash,
                ),
            ),
            entrypoint="broken_divide",
            artifact_hash=source_hash,
        ),
        explanation="local security-assurance regression candidate",
        generator_kind=CandidateGeneratorKind.DETERMINISTIC,
        generator_name="test",
    )


def _successful_worker_result(**extra):
    checks = [
        {"kind": "AST_PARSE", "outcome": "PASSED", "summary": "parsed"},
        {"kind": "RESPONSE_STRUCTURE", "outcome": "PASSED", "summary": "structured"},
        {"kind": "FUNCTION_NAME", "outcome": "PASSED", "summary": "name"},
        {"kind": "CALLABLE_KIND", "outcome": "PASSED", "summary": "kind"},
        {"kind": "COMPILE", "outcome": "PASSED", "summary": "compiled"},
        {"kind": "SIGNATURE", "outcome": "PASSED", "summary": "signature"},
        {"kind": "REGISTERED_TESTS", "outcome": "SKIPPED", "summary": "no cases"},
        {"kind": "GENERATED_TESTS", "outcome": "SKIPPED", "summary": "no tests"},
        {"kind": "PERFORMANCE", "outcome": "PASSED", "summary": "timing"},
    ]
    result = {
        "eligible": True,
        "checks": checks,
        "measurements": {
            "candidate_median_seconds": 0.001,
            "original_median_seconds": 0.001,
            "candidate_max_seconds": 0.001,
            "source_lines": 4.0,
            "generated_tests_passed": 0.0,
            "generated_tests_total": 0.0,
        },
        "risk_findings": [],
        "hard_disqualifications": [],
        "review_required_findings": [],
    }
    result.update(extra)
    return result


def test_validation_result_rejects_candidate_identity_mismatch() -> None:
    class MismatchedResultBackend(SubprocessValidationBackend):
        def _run_worker(self, payload, *, timeout_seconds):
            return _successful_worker_result(
                candidate_artifact_hash="0" * 64,
                base_source_hash="1" * 64,
                authority_policy_fingerprint="2" * 64,
                validation_transaction_id="mismatched-local-test-transaction",
            )

    engine = RepairEngine(provider=StaticRepairProvider([]))
    wrapped = repair(policy=RepairPolicy.automatic(), engine=engine)(broken_divide)
    target = wrapped.__caretaker_target__
    report = MismatchedResultBackend().validate_candidate(
        _repair_candidate(target),
        target,
        timeout_seconds=1.0,
    )

    assert report.eligible is False


def _bound_successful_result(payload):
    result = _successful_worker_result()
    result.update(
        {
            field: payload[field]
            for field in (
                "protocol_version",
                "validation_transaction_id",
                "candidate_artifact_hash",
                "base_source_hash",
                "target_id",
                "entrypoint",
                "module_name",
                "qualified_name",
                "signature_text",
                "callable_kind",
                "policy_fingerprint",
                "authority_policy_generation",
                "authority_policy_fingerprint",
                "requested_isolation",
                "backend_name",
                "mandatory_checks",
            )
        }
    )
    return result


def test_required_external_validation_result_authentication_verifies() -> None:
    cryptography = pytest.importorskip("cryptography")
    del cryptography
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    private_key = Ed25519PrivateKey.generate()
    authenticator = Ed25519ValidationResultAuthenticator(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ),
        "validator-1",
    )

    class AuthenticatedBackend(SubprocessValidationBackend):
        def __init__(self):
            super().__init__(
                result_authenticator=authenticator,
                require_result_authentication=True,
            )

        def _run_worker(self, payload, *, timeout_seconds):
            result = _bound_successful_result(payload)
            result["result_authentication"] = sign_validation_result(
                result,
                private_key=private_key,
                key_id="validator-1",
            )
            return result

    engine = RepairEngine(provider=StaticRepairProvider([]))
    wrapped = repair(policy=RepairPolicy.automatic(), engine=engine)(broken_divide)
    target = wrapped.__caretaker_target__
    report = AuthenticatedBackend().validate_candidate(
        _repair_candidate(target),
        target,
        timeout_seconds=1.0,
    )

    assert report.eligible is True
    assert report.result_authentication_status == "VERIFIED"


def test_required_external_validation_result_authentication_rejects_tampering() -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    private_key = Ed25519PrivateKey.generate()
    authenticator = Ed25519ValidationResultAuthenticator(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ),
        "validator-1",
    )

    class TamperedBackend(SubprocessValidationBackend):
        def __init__(self):
            super().__init__(
                result_authenticator=authenticator,
                require_result_authentication=True,
            )

        def _run_worker(self, payload, *, timeout_seconds):
            result = _bound_successful_result(payload)
            result["result_authentication"] = sign_validation_result(
                result,
                private_key=private_key,
                key_id="validator-1",
            )
            result["eligible"] = False
            return result

    engine = RepairEngine(provider=StaticRepairProvider([]))
    wrapped = repair(policy=RepairPolicy.automatic(), engine=engine)(broken_divide)
    target = wrapped.__caretaker_target__
    report = TamperedBackend().validate_candidate(
        _repair_candidate(target),
        target,
        timeout_seconds=1.0,
    )

    assert report.eligible is False
    assert report.result_authentication_status == "INVALID"
    assert any("authentication failed" in finding for finding in report.hard_disqualifications)


def test_required_external_validation_result_authentication_rejects_missing_envelope() -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    private_key = Ed25519PrivateKey.generate()
    authenticator = Ed25519ValidationResultAuthenticator(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ),
        "validator-1",
    )

    class UnsignedBackend(SubprocessValidationBackend):
        def __init__(self):
            super().__init__(
                result_authenticator=authenticator,
                require_result_authentication=True,
            )

        def _run_worker(self, payload, *, timeout_seconds):
            return _bound_successful_result(payload)

    engine = RepairEngine(provider=StaticRepairProvider([]))
    wrapped = repair(policy=RepairPolicy.automatic(), engine=engine)(broken_divide)
    target = wrapped.__caretaker_target__
    report = UnsignedBackend().validate_candidate(
        _repair_candidate(target),
        target,
        timeout_seconds=1.0,
    )

    assert report.eligible is False
    assert report.result_authentication_status == "MISSING"
    assert any("required result authentication" in finding for finding in report.hard_disqualifications)


def test_validation_protocol_rejects_non_finite_numeric_evidence() -> None:
    class NonFiniteResultBackend(SubprocessValidationBackend):
        def _run_worker(self, payload, *, timeout_seconds):
            result = _successful_worker_result()
            result["measurements"] = dict(result["measurements"])
            result["measurements"]["candidate_median_seconds"] = "nan"
            return result

    engine = RepairEngine(provider=StaticRepairProvider([]))
    wrapped = repair(policy=RepairPolicy.automatic(), engine=engine)(broken_divide)
    target = wrapped.__caretaker_target__
    report = NonFiniteResultBackend().validate_candidate(
        _repair_candidate(target),
        target,
        timeout_seconds=1.0,
    )

    assert report.eligible is False
    assert all(math.isfinite(value) for value in report.measurements.values())


def test_persisted_repair_attempt_records_validation_backend_identity() -> None:
    class LocalFakeVMBackend(SubprocessValidationBackend):
        def capabilities(self):
            return ValidationBackendCapabilities(
                name="local-fake-vm",
                isolation_level=ValidationIsolationLevel.VM,
                separate_kernel=True,
                network_control=True,
                resource_control=True,
                ephemeral_workspace=True,
                details={"validator_identity": "local-test-vm"},
            )

        def _run_worker(self, payload, *, timeout_seconds):
            result = _successful_worker_result()
            result.update(
                {
                    field: payload[field]
                    for field in (
                        "protocol_version",
                        "validation_transaction_id",
                        "candidate_artifact_hash",
                        "base_source_hash",
                        "target_id",
                        "entrypoint",
                        "module_name",
                        "qualified_name",
                        "signature_text",
                        "callable_kind",
                        "policy_fingerprint",
                        "authority_policy_generation",
                        "authority_policy_fingerprint",
                        "requested_isolation",
                        "backend_name",
                        "mandatory_checks",
                    )
                }
            )
            return result

    engine = RepairEngine(
        provider=StaticRepairProvider([_proposal()]),
        validation_backends=(LocalFakeVMBackend(),),
    )
    wrapped = repair(policy=_automatic_policy(), engine=engine)(broken_divide)
    assert wrapped(10.0, 0) == 0.0

    attempts = (
        tuple(engine.store.all_attempts())
        if hasattr(engine.store, "all_attempts")
        else tuple(engine.store.attempts.values())
    )
    assert attempts
    attempt = attempts[-1]
    assert attempt.validation_backend_name == "local-fake-vm"
    assert attempt.validation_isolation_level is ValidationIsolationLevel.VM
    assert attempt.validation_backend_details["validator_identity"] == "local-test-vm"


def test_restore_for_validation_has_a_runtime_enforcement_consumer() -> None:
    package_root = Path(caretaker.__file__).resolve().parent
    consumers = []
    for path in package_root.rglob("*.py"):
        if path.name in {"policy.py", "policy_semantics.py"}:
            continue
        if "restore_for_validation" in path.read_text(encoding="utf-8"):
            consumers.append(path)

    assert consumers, (
        "restore_for_validation is accepted as an assurance requirement but is only "
        "referenced by policy declaration/validation code"
    )


def test_multipass_network_isolation_is_verified_not_only_marked() -> None:
    class MarkerOnlyBackend(MultipassValidationBackend):
        def _guest_command(self, instance, command, *, timeout=None):
            if command and command[0] == "stat":
                return subprocess.CompletedProcess(command, 0, "0 644\n", "")
            if command[:3] == ["id", "-u", self.subject_user]:
                return subprocess.CompletedProcess(command, 0, "1000\n", "")
            if command and command[0] == "test":
                return subprocess.CompletedProcess(command, 0, "", "")
            # Any actual network-state inspection should see that this simulated
            # guest still has a default route and therefore fail the prerequisite.
            return subprocess.CompletedProcess(
                command,
                0,
                "default via 10.0.2.2 dev enp0s1\n",
                "",
            )

    backend = MarkerOnlyBackend(
        instance_name="local-test-validator",
        require_network_isolation=True,
    )
    ready, _reason = backend._verify_guest_prerequisites("local-test-validator")

    assert ready is False


def test_multipass_does_not_claim_ephemeral_workspace_without_reset_boundary() -> None:
    backend = MultipassValidationBackend(
        instance_name="local-test-validator",
        clean_snapshot=None,
        restore_before_validation=False,
        disposable_clone=False,
        require_network_isolation=False,
    )

    assert backend.capabilities().ephemeral_workspace is False


@pytest.mark.repository
def test_guard_security_documentation_matches_automatic_acceptance_policy() -> None:
    policy = GuardPolicy(
        baseline=replace(BaselinePolicy(), automatic_acceptance=True),
    )
    validate_guard_policy(policy)

    project_root = Path(caretaker.__file__).resolve().parents[2]
    security_text = (project_root / "docs" / "GUARD_SECURITY.md").read_text(
        encoding="utf-8"
    ).lower()
    assert "no automatic baseline acceptance" not in security_text
