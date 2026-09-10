from __future__ import annotations

from .adaptive import lightweight_dependency
import ast
import base64
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from .domain import (
    CheckOutcome,
    RepairArtifactKind,
    RepairCandidate,
    RegisteredCase,
    ValidationCheckKind,
    ValidationCheckResult,
    ValidationBackendUnavailableAction,
    ValidationIsolationLevel,
    utcnow,
)
from .registry import RepairTarget
from .validation_primitives import finite_number, integer


@dataclass(frozen=True, slots=True)
class StaticAssessment:
    hard_disqualifications: tuple[str, ...]
    review_required_findings: tuple[str, ...]
    risk_findings: tuple[str, ...]


VALIDATION_RESULT_AUTHENTICATION_VERSION = 1
_VALIDATION_RESULT_AUTHENTICATION_KEY = "result_authentication"


class ValidationResultAuthenticator(Protocol):
    """Verify provenance attached to a validation result.

    Authenticity is evidence about the validator, not authority to activate a
    candidate.  The parent still validates the result protocol and applies all
    policy and authority gates after authentication succeeds.
    """

    def verify(
        self,
        result: Mapping[str, Any],
        authentication: Mapping[str, Any],
    ) -> tuple[bool, str | None]: ...


class ExternalValidationClient(Protocol):
    """Caller-owned transport for a remote/disposable validation service."""

    def validate(
        self,
        request: Mapping[str, Any],
        *,
        timeout_seconds: float,
    ) -> Mapping[str, Any]: ...


def _canonical_validation_value(value: Any) -> Any:
    """Return the strict JSON vocabulary used for result signatures."""

    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("validation result signatures do not accept non-finite floats")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("validation result signatures require string mapping keys")
            normalized[key] = _canonical_validation_value(item)
        return {key: normalized[key] for key in sorted(normalized)}
    if isinstance(value, (tuple, list)):
        return [_canonical_validation_value(item) for item in value]
    raise TypeError(
        "validation result signatures reject unsupported values: "
        f"{type(value).__module__}.{type(value).__qualname__}"
    )


def validation_result_signing_payload(result: Mapping[str, Any]) -> bytes:
    """Canonical bytes an external validator must sign.

    The authentication field is deliberately excluded so the signature binds
    the complete result body, including the supervisor-provided transaction
    binding, without recursively signing itself.
    """

    unsigned = {
        key: value
        for key, value in result.items()
        if key != _VALIDATION_RESULT_AUTHENTICATION_KEY
    }
    payload = {
        "protocol_version": VALIDATION_RESULT_AUTHENTICATION_VERSION,
        "result": _canonical_validation_value(unsigned),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )


def _ed25519():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Ed25519 validation-result authentication requires the optional "
            "'cryptography' package; install Caretaker[signing]"
        ) from exc
    return Ed25519PrivateKey, Ed25519PublicKey, serialization


@dataclass(frozen=True, slots=True)
class Ed25519ValidationResultAuthenticator:
    """Pin one external validator identity for result verification."""

    public_key: bytes
    key_id: str

    def __post_init__(self) -> None:
        if len(self.public_key) != 32:
            raise ValueError("Ed25519 validation public keys must contain 32 bytes")
        if not self.key_id.strip():
            raise ValueError("validation authenticator key_id cannot be empty")

    @property
    def public_key_fingerprint(self) -> str:
        return hashlib.sha256(self.public_key).hexdigest()

    def verify(
        self,
        result: Mapping[str, Any],
        authentication: Mapping[str, Any],
    ) -> tuple[bool, str | None]:
        required = {
            "version",
            "scheme",
            "key_id",
            "public_key_fingerprint",
            "signature",
        }
        if set(authentication) != required:
            return False, "validation result authentication fields are incomplete or unexpected"
        if authentication.get("version") != VALIDATION_RESULT_AUTHENTICATION_VERSION:
            return False, "unsupported validation result authentication version"
        if authentication.get("scheme") != "Ed25519":
            return False, "unsupported validation result authentication scheme"
        if authentication.get("key_id") != self.key_id:
            return False, "validation result was signed by an unexpected key ID"
        if authentication.get("public_key_fingerprint") != self.public_key_fingerprint:
            return False, "validation result public-key fingerprint does not match the pinned key"
        encoded_signature = authentication.get("signature")
        if not isinstance(encoded_signature, str):
            return False, "validation result signature must be base64 text"
        try:
            signature = base64.b64decode(encoded_signature, validate=True)
            _Ed25519PrivateKey, Ed25519PublicKey, _serialization = _ed25519()
            Ed25519PublicKey.from_public_bytes(self.public_key).verify(
                signature,
                validation_result_signing_payload(result),
            )
        except Exception:
            return False, "validation result signature verification failed"
        return True, None


def sign_validation_result(
    result: Mapping[str, Any],
    *,
    private_key: Any,
    key_id: str,
) -> dict[str, Any]:
    """Create the authentication object for an external validator result.

    This helper is intended for the separately managed validator process. It
    accepts an Ed25519 private-key object or raw 32-byte private-key material;
    Caretaker does not persist or distribute that private material.
    """

    if not key_id.strip():
        raise ValueError("validation signer key_id cannot be empty")
    Ed25519PrivateKey, _Ed25519PublicKey, serialization = _ed25519()
    if isinstance(private_key, (bytes, bytearray)):
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(private_key))
    if not hasattr(private_key, "sign") or not hasattr(private_key, "public_key"):
        raise TypeError("private_key must be an Ed25519 private-key object or 32 bytes")
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(validation_result_signing_payload(result))
    return {
        "version": VALIDATION_RESULT_AUTHENTICATION_VERSION,
        "scheme": "Ed25519",
        "key_id": key_id,
        "public_key_fingerprint": hashlib.sha256(public_key).hexdigest(),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


@dataclass(frozen=True, slots=True)
class ValidationReport:
    candidate_id: object
    eligible: bool
    checks: tuple[ValidationCheckResult, ...]
    measurements: dict[str, float]
    risk_findings: tuple[str, ...]
    hard_disqualifications: tuple[str, ...] = ()
    review_required_findings: tuple[str, ...] = ()
    worker_stdout: str = ""
    worker_stderr: str = ""
    backend_name: str = "process"
    isolation_level: ValidationIsolationLevel = ValidationIsolationLevel.PROCESS
    backend_available: bool = True
    backend_details: dict[str, Any] = field(default_factory=dict)
    requires_operator_approval: bool = False
    proposal_only: bool = False
    result_authentication_status: str = "NOT_REQUIRED"


@dataclass(frozen=True, slots=True)
class ValidationBackendCapabilities:
    name: str
    isolation_level: ValidationIsolationLevel
    separate_kernel: bool = False
    rootless: bool | None = None
    network_control: bool = False
    resource_control: bool = False
    ephemeral_workspace: bool = True
    details: dict[str, Any] | None = None


class ValidationBackend(Protocol):
    def capabilities(self) -> ValidationBackendCapabilities: ...
    def available(self) -> tuple[bool, str | None]: ...
    def validate_candidate(
        self, candidate: RepairCandidate, target: RepairTarget, *, timeout_seconds: float,
        regression_cases: tuple[Any, ...] = (),
    ) -> ValidationReport: ...


class ValidationBackendRegistry:
    """Capability-based validation backend selector.

    The lowest available backend satisfying the policy minimum is preferred so
    ordinary repairs do not pay for VM isolation unnecessarily. If no sufficient
    backend is available, the strongest configured backend is returned so its
    normal fail-closed unavailable report can explain the unmet requirement.
    """

    def __init__(self, backends: tuple[ValidationBackend, ...]) -> None:
        if not backends:
            raise ValueError("at least one validation backend is required")
        self.backends = tuple(backends)

    def select(self, minimum: ValidationIsolationLevel) -> ValidationBackend:
        ordered = sorted(
            self.backends,
            key=lambda item: int(item.capabilities().isolation_level),
        )
        sufficient = [
            item for item in ordered
            if item.capabilities().isolation_level >= minimum
        ]
        for item in sufficient:
            available, _reason = item.available()
            if available:
                return item
        if sufficient:
            return sufficient[0]
        # No configured backend can satisfy the policy. Use the strongest one so
        # validation emits the existing explicit insufficient-isolation report.
        return ordered[-1]

    def capabilities(self) -> tuple[ValidationBackendCapabilities, ...]:
        return tuple(item.capabilities() for item in self.backends)


_FUNCTION_VALIDATION_CHECKS = frozenset({
    ValidationCheckKind.RESPONSE_STRUCTURE,
    ValidationCheckKind.AST_PARSE,
    ValidationCheckKind.FUNCTION_NAME,
    ValidationCheckKind.SIGNATURE,
    ValidationCheckKind.CALLABLE_KIND,
    ValidationCheckKind.COMPILE,
    ValidationCheckKind.REGISTERED_TESTS,
    ValidationCheckKind.GENERATED_TESTS,
    ValidationCheckKind.PERFORMANCE,
})

# The supervisor owns these values.  The worker may echo them, but it must not
# choose or reinterpret them.  Keeping the binding fields explicit makes the
# process/container/VM worker protocol auditable and lets the parent fail
# closed when a result belongs to a different validation transaction.
VALIDATION_PROTOCOL_VERSION = 1
_VALIDATION_BINDING_FIELDS = (
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


class SubprocessValidationBackend:
    def __init__(
        self,
        python_executable: str | None = None,
        *,
        result_authenticator: ValidationResultAuthenticator | None = None,
        require_result_authentication: bool = False,
    ) -> None:
        self.python_executable = python_executable or sys.executable
        if require_result_authentication and result_authenticator is None:
            raise ValueError(
                "require_result_authentication requires a result_authenticator"
            )
        self.result_authenticator = result_authenticator
        self.require_result_authentication = bool(require_result_authentication)

    def capabilities(self) -> ValidationBackendCapabilities:
        return ValidationBackendCapabilities(
            name="process",
            isolation_level=ValidationIsolationLevel.PROCESS,
            separate_kernel=False,
            rootless=None,
            network_control=False,
            resource_control=True,
            ephemeral_workspace=True,
            details={"python_executable": self.python_executable},
        )

    def available(self) -> tuple[bool, str | None]:
        return True, None

    def _backend_unavailable_report(
        self,
        candidate: RepairCandidate,
        target: RepairTarget,
        *,
        reason: str,
        assessment: StaticAssessment,
    ) -> ValidationReport:
        capabilities = self.capabilities()
        required = target.policy.validation.minimum_isolation
        action = target.policy.validation.backend_unavailable_action
        now = utcnow()
        summary = (
            f"Validation backend {capabilities.name!r} cannot satisfy required isolation "
            f"{required.name}: {reason}"
        )
        check = ValidationCheckResult(
            kind=ValidationCheckKind.STATIC_POLICY,
            outcome=CheckOutcome.FAILED,
            started_at=now,
            finished_at=now,
            summary=summary,
            details={
                "backend": capabilities.name,
                "backend_isolation": capabilities.isolation_level.name,
                "required_isolation": required.name,
                "unavailable_action": action.name,
            },
        )
        hard = list(assessment.hard_disqualifications)
        review = list(assessment.review_required_findings)
        requires_approval = False
        proposal_only = False
        if action is ValidationBackendUnavailableAction.FAIL_REPAIR:
            hard.append(summary)
        elif action is ValidationBackendUnavailableAction.PROPOSE_ONLY:
            proposal_only = True
            review.append(summary + "; candidate retained as proposal only")
        elif action is ValidationBackendUnavailableAction.REQUIRE_OPERATOR_APPROVAL:
            requires_approval = not hard
            review.append(summary + "; explicit operator approval is required to proceed without this backend")
        return ValidationReport(
            candidate_id=candidate.candidate_id,
            eligible=False,
            checks=(check,),
            measurements={},
            risk_findings=assessment.risk_findings + (summary,),
            hard_disqualifications=tuple(dict.fromkeys(hard)),
            review_required_findings=tuple(dict.fromkeys(review)),
            backend_name=capabilities.name,
            isolation_level=capabilities.isolation_level,
            backend_available=False,
            backend_details=dict(capabilities.details or {}),
            requires_operator_approval=requires_approval,
            proposal_only=proposal_only,
        )

    def validate_candidate(
        self,
        candidate: RepairCandidate,
        target: RepairTarget,
        *,
        timeout_seconds: float,
        regression_cases: tuple[Any, ...] = (),
    ) -> ValidationReport:
        if candidate.artifact.kind is not RepairArtifactKind.FUNCTION_REPLACEMENT:
            now = utcnow()
            check = ValidationCheckResult(
                kind=ValidationCheckKind.RESPONSE_STRUCTURE,
                outcome=CheckOutcome.FAILED,
                started_at=now,
                finished_at=now,
                summary=f"Unsupported repair artifact kind: {candidate.artifact.kind.name}",
            )
            return ValidationReport(
                candidate_id=candidate.candidate_id,
                eligible=False,
                checks=(check,),
                measurements={},
                risk_findings=(),
                hard_disqualifications=(check.summary,),
                backend_name=self.capabilities().name,
                isolation_level=self.capabilities().isolation_level,
                backend_details=dict(self.capabilities().details or {}),
            )

        source = candidate.artifact.files[0].content
        assessment = assess_candidate_source(source)
        capabilities = self.capabilities()
        available, unavailable_reason = self.available()
        if not available:
            return self._backend_unavailable_report(
                candidate, target, reason=unavailable_reason or "backend is unavailable", assessment=assessment
            )
        if capabilities.isolation_level < target.policy.validation.minimum_isolation:
            return self._backend_unavailable_report(
                candidate,
                target,
                reason=(
                    f"backend provides {capabilities.isolation_level.name}, "
                    f"policy requires at least {target.policy.validation.minimum_isolation.name}"
                ),
                assessment=assessment,
            )
        registered_cases = (
            target.registered_cases + tuple(regression_cases)
            if target.policy.validation.run_registered_tests
            else ()
        )
        generated_tests = (
            tuple(test.source for test in candidate.generated_tests)
            if target.policy.validation.run_generated_tests
            else ()
        )
        policy_fingerprint = target.policy.snapshot().fingerprint
        validation_binding = {
            "protocol_version": VALIDATION_PROTOCOL_VERSION,
            "validation_transaction_id": str(uuid4()),
            "candidate_artifact_hash": candidate.artifact.artifact_hash,
            "base_source_hash": candidate.base_source_hash,
            "target_id": target.target_id,
            "entrypoint": candidate.artifact.entrypoint,
            "module_name": target.source.module_name,
            "qualified_name": target.source.qualified_name,
            "signature_text": target.contract.signature_text,
            "callable_kind": target.contract.kind.name,
            "policy_fingerprint": policy_fingerprint,
            "authority_policy_generation": candidate.authority_policy_generation,
            "authority_policy_fingerprint": candidate.authority_policy_fingerprint,
            "requested_isolation": target.policy.validation.minimum_isolation.name,
            "backend_name": capabilities.name,
            "mandatory_checks": sorted(kind.name for kind in _FUNCTION_VALIDATION_CHECKS),
        }
        payload = {
            "mode": "function",
            "source": source,
            "entrypoint": candidate.artifact.entrypoint,
            "module_name": target.source.module_name,
            "qualified_name": target.source.qualified_name,
            "signature_text": target.contract.signature_text,
            "callable_kind": target.contract.kind.name,
            "allow_imports": target.policy.validation.allow_imports,
            "allow_network": target.policy.validation.allow_network,
            "allow_subprocesses": target.policy.validation.allow_subprocesses,
            "allow_filesystem_writes": target.policy.validation.allow_filesystem_writes,
            "registered_cases": registered_cases,
            "generated_tests": generated_tests,
            "run_registered_tests": target.policy.validation.run_registered_tests,
            "run_generated_tests": target.policy.validation.run_generated_tests,
            **validation_binding,
        }
        result = dict(self._run_worker(payload, timeout_seconds=timeout_seconds))
        protocol_findings: list[str] = []
        result_authentication = result.pop(_VALIDATION_RESULT_AUTHENTICATION_KEY, None)
        result_authentication_status = "NOT_REQUIRED"
        authentication_required = (
            self.require_result_authentication
            or target.policy.validation.require_result_authentication
        )

        def add_risk_finding(finding: str) -> None:
            existing = result.get("risk_findings", ())
            if isinstance(existing, (list, tuple)):
                result["risk_findings"] = [*existing, finding]
            else:
                result["risk_findings"] = [finding]

        if result_authentication is None:
            if authentication_required:
                result_authentication_status = "MISSING"
                if self.result_authenticator is None:
                    protocol_findings.append(
                        "validation result authentication is required but no verifier is configured"
                    )
                else:
                    protocol_findings.append(
                        "validation worker omitted required result authentication"
                    )
            elif self.result_authenticator is not None:
                result_authentication_status = "MISSING"
                add_risk_finding("validation result authentication was not provided")
        elif self.result_authenticator is None:
            result_authentication_status = "UNVERIFIED"
            if authentication_required:
                protocol_findings.append(
                    "validation result authentication cannot be verified"
                )
            else:
                add_risk_finding("validation result authentication could not be verified")
        elif not isinstance(result_authentication, Mapping):
            result_authentication_status = "INVALID"
            protocol_findings.append(
                "validation worker returned a malformed result authentication object"
            )
        else:
            try:
                authenticated, reason = self.result_authenticator.verify(
                    result,
                    result_authentication,
                )
            except Exception as exc:
                authenticated, reason = False, f"authenticator raised {type(exc).__name__}"
            if not authenticated:
                result_authentication_status = "INVALID"
                protocol_findings.append(
                    "validation result authentication failed"
                    + (f": {reason}" if reason else "")
                )
            else:
                result_authentication_status = "VERIFIED"
        for field in _VALIDATION_BINDING_FIELDS:
            if field not in result:
                protocol_findings.append(
                    f"validation worker omitted binding field {field!r}"
                )
            elif result[field] != validation_binding[field]:
                protocol_findings.append(
                    f"validation worker binding mismatch for {field!r}"
                )
        raw_checks = result.get("checks", [])
        checks_list: list[ValidationCheckResult] = []
        if not isinstance(raw_checks, (list, tuple)):
            protocol_findings.append("validation worker checks must be a list")
            raw_checks = []
        for item in raw_checks:
            if not isinstance(item, dict):
                protocol_findings.append("validation worker returned a malformed check")
                continue
            try:
                checks_list.append(_check_from_dict(item))
            except (KeyError, TypeError, ValueError):
                protocol_findings.append("validation worker returned an unknown or malformed check")
        checks = tuple(checks_list)
        check_kinds = [check.kind for check in checks]
        duplicate_kinds = sorted(
            {kind.name for kind in check_kinds if check_kinds.count(kind) > 1}
        )
        if duplicate_kinds:
            protocol_findings.append(
                "validation worker returned duplicate checks: " + ", ".join(duplicate_kinds)
            )
        missing_kinds = sorted(
            (kind.name for kind in _FUNCTION_VALIDATION_CHECKS if kind not in check_kinds),
        )
        if missing_kinds:
            protocol_findings.append(
                "validation worker omitted mandatory checks: " + ", ".join(missing_kinds)
            )
        mandatory_failures = [
            check
            for check in checks
            if check.outcome in {CheckOutcome.FAILED, CheckOutcome.ERROR}
            and check.kind not in {
                ValidationCheckKind.PERFORMANCE,
                ValidationCheckKind.GENERATED_TESTS,
            }
        ]
        hard = tuple(
            dict.fromkeys(
                assessment.hard_disqualifications
                + tuple(result.get("hard_disqualifications", ()))
            )
        )
        review = tuple(
            dict.fromkeys(
                assessment.review_required_findings
                + tuple(result.get("review_required_findings", ()))
            )
        )
        raw_measurements = result.get("measurements", {})
        measurements: dict[str, float] = {}
        if not isinstance(raw_measurements, dict):
            protocol_findings.append("validation worker measurements must be an object")
        else:
            for key, value in raw_measurements.items():
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    protocol_findings.append(
                        f"validation worker measurement {key!r} is not a finite number"
                    )
                    continue
                number = float(value)
                if not math.isfinite(number):
                    protocol_findings.append(
                        f"validation worker measurement {key!r} is not a finite number"
                    )
                    continue
                measurements[str(key)] = number
        if protocol_findings:
            protocol_summary = "; ".join(dict.fromkeys(protocol_findings))
            hard = tuple(dict.fromkeys(hard + (protocol_summary,)))
        eligible = bool(result.get("eligible", False)) and not mandatory_failures and not hard and not review
        return ValidationReport(
            candidate_id=candidate.candidate_id,
            eligible=eligible,
            checks=checks,
            measurements=measurements,
            risk_findings=tuple(
                dict.fromkeys(
                    assessment.risk_findings
                    + tuple(result.get("risk_findings", ()))
                )
            ),
            hard_disqualifications=hard,
            review_required_findings=review,
            worker_stdout=result.get("worker_stdout", ""),
            worker_stderr=result.get("worker_stderr", ""),
            backend_name=capabilities.name,
            isolation_level=capabilities.isolation_level,
            backend_available=True,
            backend_details=dict(capabilities.details or {}),
            result_authentication_status=result_authentication_status,
        )

    def validate_auxiliary(
        self,
        *,
        source: str,
        entrypoint: str,
        valid_examples: tuple[Any, ...],
        invalid_examples: tuple[Any, ...],
        timeout_seconds: float,
        maximum_runtime_seconds: float,
    ) -> dict[str, Any]:
        payload = {
            "mode": "auxiliary_validator",
            "source": source,
            "entrypoint": entrypoint,
            "valid_examples": valid_examples,
            "invalid_examples": invalid_examples,
            "maximum_runtime_seconds": maximum_runtime_seconds,
        }
        return self._run_worker(payload, timeout_seconds=timeout_seconds)

    @lightweight_dependency(target_id="caretaker.dependency.subprocess.validation-worker")
    def _run_worker(self, payload: dict[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="caretaker-validation-") as temporary:
            temp = Path(temporary)
            input_path, output_path = _write_worker_request(temp, payload)
            environment = {
                "PYTHONPATH": os.pathsep.join(
                    (os.getcwd() if item == "" else item)
                    for item in sys.path
                    if isinstance(item, str)
                ),
                "PATH": os.environ.get("PATH", ""),
                "PYTHONIOENCODING": "utf-8",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            command = [
                self.python_executable,
                "-m",
                "caretaker.validation_worker",
                str(input_path),
                str(output_path),
            ]
            return _run_worker_command(
                command,
                output_path=output_path,
                timeout_seconds=timeout_seconds,
                cwd=temporary,
                env=environment,
            )


class ExternalValidationBackend(SubprocessValidationBackend):
    """Use a caller-owned transport for an independently managed validator.

    The client receives a strict, encoded request envelope and must return the
    corresponding encoded result envelope.  No network client, retry policy, or
    credential store is built into Caretaker; those remain deployment concerns.
    Authenticated results are required by default because an external backend
    is selected specifically to create an independent trust boundary.
    """

    def __init__(
        self,
        client: ExternalValidationClient,
        *,
        result_authenticator: ValidationResultAuthenticator | None,
        require_result_authentication: bool = True,
        validator_identity: str | None = None,
    ) -> None:
        super().__init__(
            python_executable="external",
            result_authenticator=result_authenticator,
            require_result_authentication=require_result_authentication,
        )
        if not hasattr(client, "validate"):
            raise TypeError("external validation client must provide validate()")
        self.client = client
        self.validator_identity = validator_identity

    def capabilities(self) -> ValidationBackendCapabilities:
        return ValidationBackendCapabilities(
            name="external",
            isolation_level=ValidationIsolationLevel.EXTERNAL,
            # Caretaker cannot independently attest the remote service's
            # kernel or resource boundary through a caller-owned transport.
            separate_kernel=False,
            rootless=None,
            network_control=False,
            resource_control=False,
            ephemeral_workspace=True,
            details={
                "transport": "caller-owned",
                "validator_identity": self.validator_identity,
                "authenticated_results_required": self.require_result_authentication,
                "isolation_attestation": "caller-supplied",
            },
        )

    def available(self) -> tuple[bool, str | None]:
        probe = getattr(self.client, "available", None)
        if probe is None:
            return True, None
        try:
            result = probe()
        except Exception as exc:
            return False, f"external validation availability check failed: {exc}"
        if (
            not isinstance(result, tuple)
            or len(result) != 2
            or not isinstance(result[0], bool)
            or (result[1] is not None and not isinstance(result[1], str))
        ):
            return False, "external validation availability check returned an invalid result"
        return result

    def _run_worker(
        self,
        payload: dict[str, Any],
        *,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        try:
            request = {
                "protocol_version": VALIDATION_PROTOCOL_VERSION,
                "payload": _encode_validation_data(payload),
            }
            envelope = self.client.validate(
                request,
                timeout_seconds=timeout_seconds,
            )
            if not isinstance(envelope, Mapping):
                raise ValueError("external validator response must be an object")
            if envelope.get("protocol_version") != VALIDATION_PROTOCOL_VERSION:
                raise ValueError("external validator returned an unsupported protocol version")
            result = _decode_validation_data(envelope["result"])
            if not isinstance(result, dict):
                raise ValueError("external validator result must be an object")
            authentication = envelope.get("authentication")
            if authentication is not None:
                if not isinstance(authentication, Mapping):
                    raise ValueError("external validator authentication must be an object")
                if _VALIDATION_RESULT_AUTHENTICATION_KEY in result:
                    raise ValueError("external validator returned duplicate authentication")
                result[_VALIDATION_RESULT_AUTHENTICATION_KEY] = dict(authentication)
            return result
        except Exception as exc:
            return _worker_backend_error(
                f"external validation transport or protocol failed: {type(exc).__name__}: {exc}"
            )


def _structured_bind_mount(
    source: Path,
    destination: str,
    *,
    read_only: bool,
    docker: bool = False,
) -> str:
    """Encode bind-source paths so commas cannot become mount options."""
    source = _validated_mount_source(source, require_existing=False)
    encoded_source = str(source).replace("\\", "\\\\").replace(",", "\\,")
    options = f"type=bind,src={encoded_source},dst={destination}"
    if docker:
        options += ",readonly" if read_only else ",rw"
    else:
        options += ",ro=true" if read_only else ",rw=true"
    return options


def _validated_mount_source(source: str | Path, *, require_existing: bool = True) -> Path:
    """Require an existing directory with no symlinked path component."""
    candidate = Path(source).expanduser()
    if not candidate.is_absolute():
        candidate = Path(os.path.abspath(candidate))
    current = Path(candidate.anchor)
    for component in candidate.parts[1:]:
        current /= component
        try:
            if current.is_symlink():
                raise ValueError(f"validation mount source cannot contain a symlink: {source}")
        except OSError as exc:
            raise ValueError(f"validation mount source is unavailable: {source}") from exc
    if require_existing and not candidate.is_dir():
        raise ValueError(f"validation mount source must be an existing directory: {source}")
    return candidate


def _validated_resource_size(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*[kKmMgGtT]?", value):
        raise ValueError(f"{name} must be a positive byte size such as 64m")
    return value


class RootlessPodmanValidationBackend(SubprocessValidationBackend):
    """Run a validation worker in a constrained rootless Podman container.

    The backend never pulls images.  The operator must provision a trusted image
    containing Python and any application dependencies that are not provided by
    the read-only workspace/source mounts.
    """

    def __init__(
        self,
        image: str,
        *,
        podman_executable: str = "podman",
        cgroup_manager: str = "cgroupfs",
        workspace: str | Path | None = None,
        additional_read_only_paths: tuple[str | Path, ...] = (),
        memory: str = "512m",
        cpus: float = 1.0,
        pids_limit: int = 64,
        tmpfs_size: str = "64m",
    ) -> None:
        super().__init__(python_executable="python")
        if not image.strip():
            raise ValueError("A pre-provisioned Podman validation image is required")
        try:
            cpus = float(finite_number(cpus, name="cpus", minimum=0.0))
            pids_limit = integer(pids_limit, name="pids_limit", minimum=1)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        if cpus <= 0:
            raise ValueError("cpus must be > 0")
        if cgroup_manager not in {"cgroupfs", "systemd"}:
            raise ValueError("cgroup_manager must be 'cgroupfs' or 'systemd'")
        self.image = image
        self.podman_executable = podman_executable
        self.cgroup_manager = cgroup_manager
        self.workspace = _validated_mount_source(workspace or os.getcwd())
        self.additional_read_only_paths = tuple(
            _validated_mount_source(item) for item in additional_read_only_paths
        )
        self.memory = _validated_resource_size(memory, name="memory")
        self.cpus = cpus
        self.pids_limit = pids_limit
        self.tmpfs_size = _validated_resource_size(tmpfs_size, name="tmpfs_size")
        self._availability_details: dict[str, Any] = {}

    def capabilities(self) -> ValidationBackendCapabilities:
        details = {
            "image": self.image,
            "workspace": str(self.workspace),
            "cgroup_manager": self.cgroup_manager,
            "network": "none",
            "read_only_root": True,
            "capabilities_dropped": "ALL",
            **self._availability_details,
        }
        return ValidationBackendCapabilities(
            name="podman-rootless",
            isolation_level=ValidationIsolationLevel.CONTAINER,
            separate_kernel=False,
            rootless=True,
            network_control=True,
            resource_control=True,
            ephemeral_workspace=True,
            details=details,
        )

    def available(self) -> tuple[bool, str | None]:
        executable = shutil.which(self.podman_executable)
        if executable is None and not Path(self.podman_executable).is_file():
            return False, f"Podman executable {self.podman_executable!r} was not found"
        try:
            info = subprocess.run(
                [self.podman_executable, "info", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                close_fds=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"Podman information query failed: {exc}"
        if info.returncode != 0:
            return False, f"Podman information query failed: {info.stderr[-1000:]}"
        try:
            payload = json.loads(info.stdout or "{}")
        except json.JSONDecodeError as exc:
            return False, f"Podman returned invalid JSON: {exc}"
        rootless = _find_json_boolean(payload, "rootless")
        if rootless is not True:
            return False, "Podman validation requires rootless mode"
        image = subprocess.run(
            [self.podman_executable, "image", "exists", self.image],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            close_fds=True,
        )
        if image.returncode != 0:
            return False, f"Podman validation image {self.image!r} is not present locally"
        digest = subprocess.run(
            [
                self.podman_executable,
                "image",
                "inspect",
                self.image,
                "--format",
                "{{.Digest}}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            close_fds=True,
        )
        if digest.returncode == 0 and digest.stdout.strip():
            self._availability_details["image_digest"] = digest.stdout.strip()
        self._availability_details["rootless_verified"] = True
        return True, None

    def _build_command(self, host_workdir: Path) -> list[str]:
        source_root = Path(__file__).resolve().parents[1]
        mounts: list[tuple[Path, str, bool]] = [
            (host_workdir, "/work", False),
            (source_root, "/opt/caretaker-src", True),
        ]
        python_paths = ["/opt/caretaker-src"]
        if self.workspace != source_root:
            mounts.append((self.workspace, "/workspace", True))
            python_paths.append("/workspace")
        for index, path in enumerate(self.additional_read_only_paths):
            destination = f"/inputs/{index}"
            mounts.append((path, destination, True))
            python_paths.append(destination)

        command = [
            self.podman_executable,
            f"--cgroup-manager={self.cgroup_manager}",
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            f"--pids-limit={self.pids_limit}",
            f"--memory={self.memory}",
            f"--cpus={self.cpus:g}",
            "--userns=keep-id",
            f"--tmpfs=/tmp:rw,nosuid,nodev,noexec,size={self.tmpfs_size}",
        ]
        for source, destination, read_only in mounts:
            command.extend(("--mount", _structured_bind_mount(source, destination, read_only=read_only)))
        command.extend(
            (
                "--workdir=/work",
                "--env",
                f"PYTHONPATH={':'.join(python_paths)}",
                "--env",
                "PYTHONIOENCODING=utf-8",
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                self.image,
                "python",
                "-m",
                "caretaker.validation_worker",
                "/work/request.json",
                "/work/result.json",
            )
        )
        return command

    @lightweight_dependency(target_id="caretaker.dependency.podman.validation-worker")
    def _run_worker(self, payload: dict[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="caretaker-podman-validation-") as temporary:
            temp = Path(temporary)
            _, output_path = _write_worker_request(temp, payload)
            command = self._build_command(temp)
            host_environment = {
                key: os.environ[key]
                for key in (
                    "PATH",
                    "HOME",
                    "XDG_RUNTIME_DIR",
                    "DBUS_SESSION_BUS_ADDRESS",
                    "CONTAINERS_CONF",
                    "CONTAINERS_STORAGE_CONF",
                    "REGISTRY_AUTH_FILE",
                )
                if key in os.environ
            }
            return _run_worker_command(
                command,
                output_path=output_path,
                timeout_seconds=timeout_seconds,
                cwd=temporary,
                env=host_environment,
            )


class RootlessDockerValidationBackend(RootlessPodmanValidationBackend):
    """Run a validation worker through a rootless Docker-compatible runtime.

    Docker's CLI and rootless capability reporting differ from Podman's, so the
    availability and command construction are explicit rather than relying on
    Podman flags.  The backend never pulls images and requires the daemon to
    advertise rootless mode.
    """

    def __init__(
        self,
        image: str,
        *,
        docker_executable: str = "docker",
        workspace: str | Path | None = None,
        additional_read_only_paths: tuple[str | Path, ...] = (),
        memory: str = "512m",
        cpus: float = 1.0,
        pids_limit: int = 64,
        tmpfs_size: str = "64m",
    ) -> None:
        super().__init__(
            image,
            podman_executable=docker_executable,
            cgroup_manager="cgroupfs",
            workspace=workspace,
            additional_read_only_paths=additional_read_only_paths,
            memory=memory,
            cpus=cpus,
            pids_limit=pids_limit,
            tmpfs_size=tmpfs_size,
        )
        self.docker_executable = docker_executable

    def capabilities(self) -> ValidationBackendCapabilities:
        details = {
            "image": self.image,
            "workspace": str(self.workspace),
            "network": "none",
            "read_only_root": True,
            "capabilities_dropped": "ALL",
            "runtime": "docker-rootless",
            **self._availability_details,
        }
        return ValidationBackendCapabilities(
            name="docker-rootless",
            isolation_level=ValidationIsolationLevel.CONTAINER,
            separate_kernel=False,
            rootless=True,
            network_control=True,
            resource_control=True,
            ephemeral_workspace=True,
            details=details,
        )

    def available(self) -> tuple[bool, str | None]:
        executable = shutil.which(self.docker_executable)
        if executable is None and not Path(self.docker_executable).is_file():
            return False, f"Docker executable {self.docker_executable!r} was not found"
        try:
            info = subprocess.run(
                [self.docker_executable, "info", "--format", "{{json .}}"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                close_fds=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"Docker information query failed: {exc}"
        if info.returncode != 0:
            return False, f"Docker information query failed: {info.stderr[-1000:]}"
        try:
            payload = json.loads(info.stdout or "{}")
        except json.JSONDecodeError as exc:
            return False, f"Docker returned invalid JSON: {exc}"
        rootless = payload.get("Rootless")
        if not isinstance(rootless, bool):
            options = payload.get("SecurityOptions")
            rootless = (
                isinstance(options, list)
                and any("rootless" in str(option).lower() for option in options)
            )
        if rootless is not True:
            return False, "Docker validation requires rootless mode"
        image = subprocess.run(
            [self.docker_executable, "image", "inspect", self.image],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            close_fds=True,
        )
        if image.returncode != 0:
            return False, f"Docker validation image {self.image!r} is not present locally"
        digest = subprocess.run(
            [
                self.docker_executable,
                "image",
                "inspect",
                self.image,
                "--format",
                "{{json .RepoDigests}}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            close_fds=True,
        )
        if digest.returncode == 0 and digest.stdout.strip():
            try:
                digests = json.loads(digest.stdout)
            except json.JSONDecodeError:
                digests = ()
            if isinstance(digests, list) and digests:
                self._availability_details["image_digest"] = str(digests[0])
        self._availability_details["rootless_verified"] = True
        return True, None

    def _build_command(self, host_workdir: Path) -> list[str]:
        source_root = Path(__file__).resolve().parents[1]
        mounts: list[tuple[Path, str, bool]] = [
            (host_workdir, "/work", False),
            (source_root, "/opt/caretaker-src", True),
        ]
        python_paths = ["/opt/caretaker-src"]
        if self.workspace != source_root:
            mounts.append((self.workspace, "/workspace", True))
            python_paths.append("/workspace")
        for index, path in enumerate(self.additional_read_only_paths):
            destination = f"/inputs/{index}"
            mounts.append((path, destination, True))
            python_paths.append(destination)

        command = [
            self.docker_executable,
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            f"--pids-limit={self.pids_limit}",
            f"--memory={self.memory}",
            f"--cpus={self.cpus:g}",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--tmpfs",
            f"/tmp:rw,nosuid,nodev,noexec,size={self.tmpfs_size}",
        ]
        for source, destination, read_only in mounts:
            command.extend(("--mount", _structured_bind_mount(source, destination, read_only=read_only, docker=True)))
        command.extend(
            (
                "--workdir=/work",
                "--env",
                f"PYTHONPATH={':'.join(python_paths)}",
                "--env",
                "PYTHONIOENCODING=utf-8",
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                self.image,
                "python",
                "-m",
                "caretaker.validation_worker",
                "/work/request.json",
                "/work/result.json",
            )
        )
        return command


class MultipassValidationBackend(SubprocessValidationBackend):
    """Run validation in a pre-provisioned Multipass VM.

    The validator VM is expected to contain Caretaker, the target application,
    and its dependencies.  Host paths are copied with ``multipass transfer``;
    host-directory mounts are treated as an availability failure.
    """

    def __init__(
        self,
        *,
        instance_name: str = "caretaker-validator",
        multipass_executable: str = "multipass",
        python_executable: str = "/opt/caretaker/venv/bin/python",
        subject_user: str = "caretaker-subject",
        clean_snapshot: str | None = "caretaker-clean",
        restore_before_validation: bool = True,
        disposable_clone: bool = False,
        require_network_isolation: bool = True,
        network_policy_marker: str = "/etc/caretaker/validation-network-isolated",
        operation_timeout_seconds: float = 60.0,
    ) -> None:
        super().__init__(python_executable=python_executable)
        if not instance_name.strip():
            raise ValueError("instance_name cannot be empty")
        if operation_timeout_seconds <= 0:
            raise ValueError("operation_timeout_seconds must be > 0")
        self.instance_name = instance_name
        self.multipass_executable = multipass_executable
        self.subject_user = subject_user
        self.clean_snapshot = clean_snapshot
        self.restore_before_validation = bool(restore_before_validation)
        self.disposable_clone = bool(disposable_clone)
        self.require_network_isolation = bool(require_network_isolation)
        self.network_policy_marker = network_policy_marker
        self.operation_timeout_seconds = float(operation_timeout_seconds)
        self._lock = threading.RLock()
        self._availability_details: dict[str, Any] = {}

    @staticmethod
    def _attest_network_ruleset(output: str, subject_uid: str) -> tuple[bool, str | None, str | None]:
        """Check the documented nftables egress contract without executing guest data."""

        normalized = " ".join(output.split())
        required = (
            "table inet caretaker",
            "chain output",
        )
        if any(fragment not in normalized for fragment in required):
            return False, None, "guest nftables ruleset does not prove the required egress policy"

        lines = [line.strip() for line in output.splitlines() if line.strip()]
        chain_start = next(
            (index for index, line in enumerate(lines) if line.startswith("chain output")),
            None,
        )
        if chain_start is None:
            return False, None, "guest nftables output has no output chain"
        depth = 0
        chain_lines: list[str] = []
        for line in lines[chain_start:]:
            depth += line.count("{") - line.count("}")
            chain_lines.append(line)
            if depth == 0:
                break
        chain_text = " ".join(chain_lines)
        if not chain_text.startswith("chain output") or depth != 0:
            return False, None, "guest nftables output has an incomplete output chain"

        chain_required = (
            "type filter hook output priority 0",
            "policy accept",
            f"meta skuid {subject_uid} ip daddr 127.0.0.0/8 accept",
            f"meta skuid {subject_uid} ip6 daddr ::1 accept",
            f"meta skuid {subject_uid} reject",
        )
        if any(fragment not in chain_text for fragment in chain_required):
            return False, None, "guest nftables ruleset does not prove the required egress policy"

        allowed_accepts = (
            f"meta skuid {subject_uid} ip daddr 127.0.0.0/8 accept",
            f"meta skuid {subject_uid} ip6 daddr ::1 accept",
        )
        unexpected_accept = next(
            (
                line
                for line in chain_lines
                if re.search(r"\baccept\b", line)
                and "policy accept" not in line
                and not any(fragment in line for fragment in allowed_accepts)
            ),
            None,
        )
        if unexpected_accept is not None:
            return False, None, "guest output chain contains an unapproved accept rule"
        subject_rules = [line for line in chain_lines if f"meta skuid {subject_uid}" in line]
        if not subject_rules or "reject" not in subject_rules[-1]:
            return False, None, "guest output chain does not end subject traffic with reject"
        return True, hashlib.sha256(output.encode("utf-8")).hexdigest(), None

    def capabilities(self) -> ValidationBackendCapabilities:
        details = {
            "instance": self.instance_name,
            "clean_snapshot": self.clean_snapshot,
            "restore_before_validation": self.restore_before_validation,
            "disposable_clone": self.disposable_clone,
            "host_mounts_allowed": False,
            "subject_user": self.subject_user,
            "network_policy_marker": (
                self.network_policy_marker if self.require_network_isolation else None
            ),
            "network_firewall_attestation": (
                "required-and-verified-at-availability"
                if self._availability_details.get("network_firewall_ruleset_hash")
                else "not-yet-verified"
            ) if self.require_network_isolation else None,
            "reset_boundary": (
                "disposable_clone"
                if self.disposable_clone
                else "clean_snapshot"
                if self.clean_snapshot and self.restore_before_validation
                else None
            ),
            **self._availability_details,
        }
        return ValidationBackendCapabilities(
            name="multipass",
            isolation_level=ValidationIsolationLevel.VM,
            separate_kernel=True,
            rootless=None,
            network_control=self.require_network_isolation,
            resource_control=True,
            ephemeral_workspace=(
                self.disposable_clone
                or (self.clean_snapshot is not None and self.restore_before_validation)
            ),
            details=details,
        )

    def _host_command(
        self,
        command: list[str],
        *,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout or self.operation_timeout_seconds,
            check=False,
            close_fds=True,
        )

    def available(self) -> tuple[bool, str | None]:
        executable = shutil.which(self.multipass_executable)
        if executable is None and not Path(self.multipass_executable).is_file():
            return False, f"Multipass executable {self.multipass_executable!r} was not found"
        info = self._host_command(
            [self.multipass_executable, "info", "--format", "json", self.instance_name]
        )
        if info.returncode != 0:
            return False, f"Multipass validator instance {self.instance_name!r} is unavailable: {info.stderr[-1000:]}"
        try:
            payload = json.loads(info.stdout or "{}")
        except json.JSONDecodeError as exc:
            return False, f"Multipass returned invalid JSON: {exc}"
        instance = _find_multipass_instance(payload, self.instance_name)
        if instance is None:
            return False, f"Multipass did not report validator instance {self.instance_name!r}"
        mounts = instance.get("mounts")
        if mounts:
            return False, "Multipass validation refuses instances with host-directory mounts"
        self._availability_details = {
            "image_hash": instance.get("image_hash") or instance.get("image_release"),
            "state": instance.get("state"),
        }
        state = str(instance.get("state", "")).upper()
        if self.disposable_clone:
            if state not in {"STOPPED", "OFF"}:
                return False, "Multipass disposable-clone mode requires a stopped template instance"
        elif state in {"RUNNING", "STARTED"}:
            ready, reason = self._verify_guest_prerequisites(self.instance_name)
            if not ready:
                return False, reason
        if self.clean_snapshot and self.restore_before_validation and not self.disposable_clone:
            snapshot = self._host_command(
                [
                    self.multipass_executable,
                    "info",
                    f"{self.instance_name}.{self.clean_snapshot}",
                ]
            )
            if snapshot.returncode != 0:
                return False, (
                    f"Required Multipass snapshot {self.instance_name}.{self.clean_snapshot} is unavailable"
                )
        return True, None

    def _verify_guest_prerequisites(self, instance: str) -> tuple[bool, str | None]:
        ready = self._guest_command(instance, ["test", "-x", self.python_executable])
        if ready.returncode != 0:
            return False, f"Validation Python {self.python_executable!r} is unavailable in Multipass guest"
        user = self._guest_command(instance, ["id", "-u", self.subject_user])
        if user.returncode != 0:
            return False, f"Validation subject user {self.subject_user!r} is unavailable in Multipass guest"
        subject_uid = user.stdout.strip()
        if not subject_uid.isdigit():
            return False, "Multipass validation could not determine the numeric subject UID"
        if self.require_network_isolation:
            marker = self._guest_command(
                instance,
                ["stat", "-c", "%u %a", self.network_policy_marker],
            )
            if marker.returncode != 0:
                return False, (
                    "Multipass validation requires the root-owned network-isolation marker "
                    f"{self.network_policy_marker!r}"
                )
            fields = marker.stdout.strip().split()
            if len(fields) != 2 or fields[0] != "0":
                return False, "Multipass network-isolation marker must be owned by root"
            try:
                permissions = int(fields[1], 8)
            except ValueError:
                return False, "Multipass network-isolation marker has invalid permissions"
            if permissions & 0o022:
                return False, "Multipass network-isolation marker must not be group/world writable"
            firewall = self._guest_command(
                instance,
                ["nft", "-a", "list", "table", "inet", "caretaker"],
            )
            if firewall.returncode != 0:
                return False, (
                    "Multipass validation could not inspect the guest nftables egress policy: "
                    + firewall.stderr[-500:]
                )
            attested, ruleset_hash, reason = self._attest_network_ruleset(
                firewall.stdout,
                subject_uid,
            )
            if not attested:
                return False, reason or "Multipass guest firewall policy attestation failed"
            self._availability_details["network_firewall_ruleset_hash"] = ruleset_hash
            self._availability_details["network_firewall_subject_uid"] = int(subject_uid)
            for route_command in (
                ["ip", "-4", "route", "show", "default"],
                ["ip", "-6", "route", "show", "default"],
            ):
                routes = self._guest_command(instance, route_command)
                if routes.returncode != 0:
                    return False, (
                        "Multipass validation could not verify guest default routes: "
                        + " ".join(route_command)
                    )
                if routes.stdout.strip():
                    return False, (
                        "Multipass guest retains a default route despite the required "
                        "network-isolation policy"
                    )
        return True, None

    def _restore_clean_instance(self, instance: str) -> tuple[bool, str | None]:
        if not self.clean_snapshot or not self.restore_before_validation:
            return True, None
        commands = (
            [self.multipass_executable, "stop", instance],
            [
                self.multipass_executable,
                "restore",
                "--destructive",
                f"{instance}.{self.clean_snapshot}",
            ],
            [self.multipass_executable, "start", instance],
            [self.multipass_executable, "wait-ready", instance],
        )
        for command in commands:
            completed = self._host_command(command)
            if completed.returncode != 0:
                return False, f"Multipass preparation failed: {' '.join(command)}: {completed.stderr[-1000:]}"
        return True, None

    def _create_disposable_clone(self) -> tuple[str | None, str | None]:
        name = f"caretaker-val-{uuid4().hex[:12]}"
        clone = self._host_command(
            [
                self.multipass_executable,
                "clone",
                self.instance_name,
                "--name",
                name,
            ]
        )
        if clone.returncode != 0:
            return None, f"Multipass clone failed: {clone.stderr[-1000:]}"
        for command in (
            [self.multipass_executable, "start", name],
            [self.multipass_executable, "wait-ready", name],
        ):
            completed = self._host_command(command)
            if completed.returncode != 0:
                self._destroy_disposable_clone(name)
                return None, f"Multipass clone preparation failed: {completed.stderr[-1000:]}"
        return name, None

    def _destroy_disposable_clone(self, instance: str) -> None:
        self._host_command([self.multipass_executable, "delete", "--purge", instance])

    def _guest_command(
        self,
        instance: str,
        command: list[str],
        *,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self._host_command(
            [self.multipass_executable, "exec", instance, "--", *command],
            timeout=timeout,
        )

    def _run_in_instance(
        self,
        instance: str,
        payload: dict[str, Any],
        *,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        token = uuid4().hex
        guest_directory = f"/var/lib/caretaker/validation/{token}"
        guest_input = f"{guest_directory}/request.json"
        guest_output = f"{guest_directory}/result.json"
        guest_transfer = f"/tmp/caretaker-validation-{token}.json"
        with tempfile.TemporaryDirectory(prefix="caretaker-multipass-validation-") as temporary:
            temp = Path(temporary)
            input_path, output_path = _write_worker_request(temp, payload)
            setup = self._guest_command(
                instance,
                [
                    "sudo",
                    "install",
                    "-d",
                    "-o",
                    self.subject_user,
                    "-g",
                    self.subject_user,
                    "-m",
                    "0700",
                    guest_directory,
                ],
            )
            if setup.returncode != 0:
                return _worker_transport_error("Multipass guest workspace creation failed", setup)
            try:
                transfer = self._host_command(
                    [
                        self.multipass_executable,
                        "transfer",
                        str(input_path),
                        f"{instance}:{guest_transfer}",
                    ]
                )
                if transfer.returncode != 0:
                    return _worker_transport_error("Multipass request transfer failed", transfer)
                install = self._guest_command(
                    instance,
                    [
                        "sudo",
                        "install",
                        "-o",
                        self.subject_user,
                        "-g",
                        self.subject_user,
                        "-m",
                        "0600",
                        guest_transfer,
                        guest_input,
                    ],
                )
                if install.returncode != 0:
                    return _worker_transport_error("Multipass request installation failed", install)
                self._guest_command(instance, ["sudo", "rm", "-f", guest_transfer])
                command = [
                    "sudo",
                    "-u",
                    self.subject_user,
                    "--",
                    "env",
                    "HOME=/var/lib/caretaker",
                    "PYTHONIOENCODING=utf-8",
                    "PYTHONDONTWRITEBYTECODE=1",
                    self.python_executable,
                    "-m",
                    "caretaker.validation_worker",
                    guest_input,
                    guest_output,
                ]
                try:
                    completed = self._guest_command(
                        instance,
                        command,
                        timeout=timeout_seconds,
                    )
                except subprocess.TimeoutExpired as exc:
                    return _worker_timeout_result(timeout_seconds, exc)
                transfer_result = self._host_command(
                    [
                        self.multipass_executable,
                        "transfer",
                        f"{instance}:{guest_output}",
                        str(output_path),
                    ]
                )
                if transfer_result.returncode != 0 and not output_path.exists():
                    return _worker_protocol_error(
                        completed,
                        summary="Multipass validation worker did not produce a transferable result.",
                    )
                return _load_worker_result(output_path, completed)
            finally:
                self._guest_command(instance, ["sudo", "rm", "-rf", guest_directory])
                self._guest_command(instance, ["sudo", "rm", "-f", guest_transfer])

    @lightweight_dependency(target_id="caretaker.dependency.multipass.validation-worker")
    def _run_worker(self, payload: dict[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
        with self._lock:
            instance = self.instance_name
            disposable = False
            if self.disposable_clone:
                instance, reason = self._create_disposable_clone()
                if instance is None:
                    return _worker_backend_error(reason or "Multipass disposable clone could not be created")
                disposable = True
            else:
                restored, reason = self._restore_clean_instance(instance)
                if not restored:
                    return _worker_backend_error(reason or "Multipass validator could not be restored")
            try:
                ready, reason = self._verify_guest_prerequisites(instance)
                if not ready:
                    return _worker_backend_error(reason or "Multipass guest prerequisites are unavailable")
                return self._run_in_instance(
                    instance,
                    payload,
                    timeout_seconds=timeout_seconds,
                )
            finally:
                if disposable:
                    self._destroy_disposable_clone(instance)


def _write_worker_request(temp: Path, payload: dict[str, Any]) -> tuple[Path, Path]:
    input_path = temp / "request.json"
    output_path = temp / "result.json"
    envelope = {
        "protocol_version": VALIDATION_PROTOCOL_VERSION,
        "payload": _encode_validation_data(payload),
    }
    input_path.write_text(
        json.dumps(envelope, sort_keys=True, separators=(",", ":"), allow_nan=False),
        encoding="utf-8",
    )
    return input_path, output_path


_VALIDATION_DATA_TAG = "__caretaker_validation_data__"


def _encode_validation_data(value: Any) -> Any:
    """Encode the small, explicit data vocabulary used by worker IPC.

    This is deliberately separate from the repository's general JSON helpers:
    validation inputs are executable-test inputs and must never silently turn
    arbitrary application objects into reprs or importable type names.
    """
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("validation protocol does not accept non-finite floats")
        return value
    if isinstance(value, RegisteredCase):
        return {
            _VALIDATION_DATA_TAG: "registered_case",
            "name": _encode_validation_data(value.name),
            "args": _encode_validation_data(value.args),
            "kwargs": _encode_validation_data(dict(value.kwargs)),
            "expected": _encode_validation_data(value.expected),
            "expected_exception": _encode_validation_data(value.expected_exception),
            "repeat": _encode_validation_data(value.repeat),
        }
    if isinstance(value, tuple):
        return {
            _VALIDATION_DATA_TAG: "tuple",
            "items": [_encode_validation_data(item) for item in value],
        }
    if isinstance(value, list):
        return [_encode_validation_data(item) for item in value]
    if isinstance(value, Mapping):
        items: list[list[Any]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("validation protocol mappings require string keys")
            items.append([key, _encode_validation_data(item)])
        return {
            _VALIDATION_DATA_TAG: "mapping",
            "items": items,
        }
    raise TypeError(
        "validation protocol rejects unsupported application object: "
        f"{type(value).__module__}.{type(value).__qualname__}"
    )


def _decode_validation_data(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("validation protocol contains a non-finite float")
        return value
    if isinstance(value, list):
        return [_decode_validation_data(item) for item in value]
    if not isinstance(value, dict):
        raise ValueError("validation protocol contains an unsupported JSON value")
    tag = value.get(_VALIDATION_DATA_TAG)
    if tag == "tuple":
        if set(value) != {_VALIDATION_DATA_TAG, "items"} or not isinstance(value["items"], list):
            raise ValueError("malformed validation tuple")
        return tuple(_decode_validation_data(item) for item in value["items"])
    if tag == "mapping":
        if set(value) != {_VALIDATION_DATA_TAG, "items"} or not isinstance(value["items"], list):
            raise ValueError("malformed validation mapping")
        result: dict[str, Any] = {}
        for item in value["items"]:
            if not isinstance(item, list) or len(item) != 2 or not isinstance(item[0], str):
                raise ValueError("malformed validation mapping item")
            if item[0] in result:
                raise ValueError("duplicate validation mapping key")
            result[item[0]] = _decode_validation_data(item[1])
        return result
    if tag == "registered_case":
        required = {
            _VALIDATION_DATA_TAG,
            "name",
            "args",
            "kwargs",
            "expected",
            "expected_exception",
            "repeat",
        }
        if set(value) != required:
            raise ValueError("malformed registered validation case")
        args = _decode_validation_data(value["args"])
        kwargs = _decode_validation_data(value["kwargs"])
        if not isinstance(args, tuple) or not isinstance(kwargs, dict):
            raise ValueError("registered validation case has invalid arguments")
        return RegisteredCase(
            name=_decode_validation_data(value["name"]),
            args=args,
            kwargs=kwargs,
            expected=_decode_validation_data(value["expected"]),
            expected_exception=_decode_validation_data(value["expected_exception"]),
            repeat=_decode_validation_data(value["repeat"]),
        )
    raise ValueError("validation protocol contains an unknown data tag")


def _worker_timeout_result(timeout_seconds: float, exc: subprocess.TimeoutExpired) -> dict[str, Any]:
    now = utcnow()
    timeout_check = ValidationCheckResult(
        kind=ValidationCheckKind.PERFORMANCE,
        outcome=CheckOutcome.FAILED,
        started_at=now - timedelta(seconds=timeout_seconds),
        finished_at=now,
        summary=f"Validation worker exceeded {timeout_seconds:g}s timeout.",
        error_type="TimeoutExpired",
        error_message=str(exc),
    )
    return {
        "eligible": False,
        "checks": [_check_to_dict(timeout_check)],
        "measurements": {},
        "risk_findings": ["validation worker timed out"],
        "hard_disqualifications": [],
        "review_required_findings": [],
        "worker_stdout": _bounded_stream(exc.stdout),
        "worker_stderr": _bounded_stream(exc.stderr),
    }


def _worker_protocol_error(
    completed: subprocess.CompletedProcess[str],
    *,
    summary: str = "Validation worker did not produce a result.",
) -> dict[str, Any]:
    now = utcnow()
    return {
        "eligible": False,
        "checks": [
            _check_to_dict(
                ValidationCheckResult(
                    kind=ValidationCheckKind.COMPILE,
                    outcome=CheckOutcome.ERROR,
                    started_at=now,
                    finished_at=now,
                    summary=summary,
                    details={"returncode": completed.returncode},
                    error_type="WorkerProtocolError",
                    error_message=_bounded_stream(completed.stderr, 2000),
                )
            )
        ],
        "measurements": {},
        "risk_findings": ["validation worker crashed or corrupted its protocol"],
        "hard_disqualifications": [],
        "review_required_findings": [],
        "worker_stdout": _bounded_stream(completed.stdout),
        "worker_stderr": _bounded_stream(completed.stderr),
    }


def _worker_transport_error(summary: str, completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    result = _worker_protocol_error(completed, summary=summary)
    result.setdefault("risk_findings", []).append("validation isolation transport failed")
    return result


def _worker_backend_error(summary: str) -> dict[str, Any]:
    now = utcnow()
    return {
        "eligible": False,
        "checks": [
            _check_to_dict(
                ValidationCheckResult(
                    kind=ValidationCheckKind.STATIC_POLICY,
                    outcome=CheckOutcome.ERROR,
                    started_at=now,
                    finished_at=now,
                    summary=summary,
                    error_type="ValidationBackendError",
                    error_message=summary,
                )
            )
        ],
        "measurements": {},
        "risk_findings": [summary],
        "hard_disqualifications": [summary],
        "review_required_findings": [],
        "worker_stdout": "",
        "worker_stderr": "",
    }


def _load_worker_result(
    output_path: Path,
    completed: subprocess.CompletedProcess[str],
) -> dict[str, Any]:
    if not output_path.exists():
        return _worker_protocol_error(completed)
    try:
        envelope = json.loads(output_path.read_text(encoding="utf-8"))
        if not isinstance(envelope, dict) or envelope.get("protocol_version") != VALIDATION_PROTOCOL_VERSION:
            raise ValueError("validation worker returned an unsupported protocol version")
        result = _decode_validation_data(envelope["result"])
        if not isinstance(result, dict):
            raise ValueError("validation worker result must be an object")
        authentication = envelope.get("authentication")
        if authentication is not None:
            if not isinstance(authentication, dict):
                raise ValueError("validation worker authentication must be an object")
            if _VALIDATION_RESULT_AUTHENTICATION_KEY in result:
                raise ValueError("validation worker returned duplicate result authentication")
            result[_VALIDATION_RESULT_AUTHENTICATION_KEY] = dict(authentication)
    except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        result = _worker_protocol_error(
            completed,
            summary=f"Validation worker produced an invalid result: {exc}",
        )
        return result
    result["worker_stdout"] = _bounded_stream(completed.stdout)
    result["worker_stderr"] = _bounded_stream(completed.stderr)
    if completed.returncode != 0:
        result["eligible"] = False
        result.setdefault("risk_findings", []).append(
            f"validation worker exited with status {completed.returncode}"
        )
    return result


def _run_worker_command(
    command: list[str],
    *,
    output_path: Path,
    timeout_seconds: float,
    cwd: str | Path | None,
    env: dict[str, str] | None,
) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            close_fds=True,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired as exc:
        return _worker_timeout_result(timeout_seconds, exc)
    return _load_worker_result(output_path, completed)


def _bounded_stream(value: Any, limit: int = 20_000) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value)[-limit:]


def _find_json_boolean(payload: Any, key: str) -> bool | None:
    if isinstance(payload, dict):
        for current_key, value in payload.items():
            if str(current_key).lower() == key.lower() and isinstance(value, bool):
                return value
            found = _find_json_boolean(value, key)
            if found is not None:
                return found
    elif isinstance(payload, list):
        for value in payload:
            found = _find_json_boolean(value, key)
            if found is not None:
                return found
    return None


def _find_multipass_instance(payload: Any, instance_name: str) -> dict[str, Any] | None:
    if isinstance(payload, dict):
        info = payload.get("info")
        if isinstance(info, dict):
            direct = info.get(instance_name)
            if isinstance(direct, dict):
                return direct
        direct = payload.get(instance_name)
        if isinstance(direct, dict):
            return direct
        if payload.get("name") == instance_name:
            return payload
        for value in payload.values():
            found = _find_multipass_instance(value, instance_name)
            if found is not None:
                return found
    elif isinstance(payload, list):
        for value in payload:
            found = _find_multipass_instance(value, instance_name)
            if found is not None:
                return found
    return None


# Explicit name for new code; keep SubprocessValidationBackend for compatibility.
ProcessValidationBackend = SubprocessValidationBackend


_DANGEROUS_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "system",
    "popen",
    "fork",
    "spawn",
    "Popen",
    "run",
    "call",
    "check_call",
    "check_output",
}
_CONCURRENCY_PARTS = {"threading", "multiprocessing", "concurrent", "asyncio", "Thread", "Process"}
_DYNAMIC_ATTRIBUTE_CALLS = {"getattr", "setattr", "delattr"}


def assess_candidate_source(source: str) -> StaticAssessment:
    hard: list[str] = []
    review: list[str] = []
    risks: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return StaticAssessment((), (), ())
    definitions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            review.append("candidate introduces imports; manual approval is required")
            risks.append("candidate introduces imports")
        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            leaf = name.split(".")[-1]
            if leaf in _DANGEROUS_CALLS:
                hard.append(f"candidate calls prohibited operation {name}")
            if any(part in _CONCURRENCY_PARTS for part in name.split(".")):
                review.append(f"candidate introduces concurrency through {name}")
                risks.append(f"candidate introduces concurrency through {name}")
            if leaf in _DYNAMIC_ATTRIBUTE_CALLS and len(node.args) >= 2:
                attribute_name = _static_string_value(node.args[1])
                if attribute_name is None:
                    hard.append(
                        f"candidate uses a dynamically constructed attribute name through {name}"
                    )
                elif attribute_name.startswith("__"):
                    hard.append(
                        f"candidate accesses prohibited dunder attribute {attribute_name}"
                    )
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            hard.append("candidate declares global or nonlocal state")
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            hard.append(f"candidate accesses prohibited dunder attribute {node.attr}")
    for definition in definitions:
        defaults = tuple(definition.args.defaults) + tuple(
            item for item in definition.args.kw_defaults if item is not None
        )
        for default in defaults:
            if not _is_safe_literal(default):
                hard.append("candidate contains executable or non-literal default arguments")
        annotations: list[ast.expr] = []
        annotations.extend(
            arg.annotation
            for arg in (
                list(definition.args.posonlyargs)
                + list(definition.args.args)
                + list(definition.args.kwonlyargs)
            )
            if arg.annotation is not None
        )
        if definition.args.vararg and definition.args.vararg.annotation:
            annotations.append(definition.args.vararg.annotation)
        if definition.args.kwarg and definition.args.kwarg.annotation:
            annotations.append(definition.args.kwarg.annotation)
        if definition.returns is not None:
            annotations.append(definition.returns)
        for annotation in annotations:
            if not _is_safe_annotation(annotation):
                hard.append("candidate contains executable or unsupported annotation expressions")
    return StaticAssessment(
        hard_disqualifications=tuple(dict.fromkeys(hard)),
        review_required_findings=tuple(dict.fromkeys(review)),
        risk_findings=tuple(dict.fromkeys(risks)),
    )


def sanitized_function_tree(source: str) -> ast.Module:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            node.returns = None
            for arg in (
                list(node.args.posonlyargs)
                + list(node.args.args)
                + list(node.args.kwonlyargs)
            ):
                arg.annotation = None
            if node.args.vararg:
                node.args.vararg.annotation = None
            if node.args.kwarg:
                node.args.kwarg.annotation = None
    return ast.fix_missing_locations(tree)


def _is_safe_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_is_safe_literal(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            key is not None and _is_safe_literal(key) and _is_safe_literal(value)
            for key, value in zip(node.keys, node.values)
        )
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        return _is_safe_literal(node.operand)
    return False


def _static_string_value(node: ast.AST) -> str | None:
    """Return a string that can be proven from syntax alone, if any."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_string_value(node.left)
        right = _static_string_value(node.right)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                return None
            parts.append(value.value)
        return "".join(parts)
    return None


def _is_safe_annotation(node: ast.AST) -> bool:
    if isinstance(node, (ast.Name, ast.Constant)):
        return True
    if isinstance(node, ast.Attribute):
        return not node.attr.startswith("__") and _is_safe_annotation(node.value)
    if isinstance(node, ast.Subscript):
        return _is_safe_annotation(node.value) and _is_safe_annotation(node.slice)
    if isinstance(node, ast.Tuple):
        return all(_is_safe_annotation(item) for item in node.elts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_safe_annotation(node.left) and _is_safe_annotation(node.right)
    return False


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return "<dynamic>"


def _check_from_dict(payload: dict[str, Any]) -> ValidationCheckResult:
    return ValidationCheckResult(
        kind=ValidationCheckKind[payload["kind"]],
        outcome=CheckOutcome[payload["outcome"]],
        started_at=utcnow(),
        finished_at=utcnow(),
        summary=payload.get("summary", ""),
        details=payload.get("details", {}),
        error_type=payload.get("error_type"),
        error_message=payload.get("error_message"),
    )


def _check_to_dict(check: ValidationCheckResult) -> dict[str, Any]:
    return {
        "kind": check.kind.name,
        "outcome": check.outcome.name,
        "summary": check.summary,
        "details": dict(check.details),
        "error_type": check.error_type,
        "error_message": check.error_message,
    }
