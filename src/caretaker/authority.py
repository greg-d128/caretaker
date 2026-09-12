from __future__ import annotations

import dataclasses
import fnmatch
import hashlib
import json
import os
import tomllib
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any, Mapping, Sequence
from uuid import UUID, uuid4

from .integrity.canonical import assert_canonical_json, canonical_json_bytes, load_json_object, write_canonical_json
from .integrity.gpg import GPGUnavailableError, GPGVerifier
from .integrity.manifest import load_root
from .integrity.models import SignatureVerificationMode
from .validation_primitives import bounded_text, exact_bool, finite_number, integer


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuthorityKind(Enum):
    FRAMEWORK = "framework"
    APPLICATION = "application"
    DEPLOYMENT = "deployment"
    RUNTIME = "runtime"


_AUTHORITY_ORDER = {
    AuthorityKind.FRAMEWORK: 0,
    AuthorityKind.APPLICATION: 1,
    AuthorityKind.DEPLOYMENT: 2,
    AuthorityKind.RUNTIME: 3,
}


_AUTHORITY_SIGNING_ROLES = {
    AuthorityKind.FRAMEWORK: frozenset({"protected", "policy-framework"}),
    AuthorityKind.APPLICATION: frozenset({"policy-application"}),
    AuthorityKind.DEPLOYMENT: frozenset({"policy-deployment"}),
    AuthorityKind.RUNTIME: frozenset({"policy-runtime"}),
}


SUPPORTED_POLICY_PREFIXES = frozenset({"authority", "repair", "guard", "logging", "system", "lightweight"})
RUNTIME_RESTART_BOUND_PREFIXES = (
    "system.",
    "logging.application_id",
    "logging.directory",
    "logging.codec",
    "logging.indexing",
    "logging.signing",
    "logging.buffering.queue_capacity",
    "guard.targets",
    "guard.retention",
)


class ConstraintOperator(Enum):
    EXACT = "exact"
    ALLOWED_VALUES = "allowed-values"
    PROHIBITED_VALUES = "prohibited-values"
    MINIMUM = "minimum"
    MAXIMUM = "maximum"
    REQUIRED_TRUE = "required-true"
    REQUIRED_FALSE = "required-false"


class SignatureState(Enum):
    VERIFIED = "verified"
    UNSIGNED = "unsigned"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"
    SKIPPED = "skipped"


class GuaranteeState(Enum):
    SATISFIED = "satisfied"
    VIOLATED = "violated"
    UNSIGNED = "unsigned"
    INVALID = "invalid"
    SKIPPED = "skipped"


class AuthorityPolicyError(RuntimeError):
    pass


class AuthorityPolicyConflictError(AuthorityPolicyError):
    def __init__(self, violations: Sequence["ConstraintViolation"]) -> None:
        self.violations = tuple(violations)
        rendered = "; ".join(
            f"{item.authority_id}:{item.path} expected {item.operator.value} "
            f"{item.expected!r}, observed {item.observed!r}"
            for item in self.violations
        )
        super().__init__(
            "Authority policy conflicts require an explicit lower-authority override: " + rendered
        )


@dataclass(frozen=True, slots=True)
class PolicySetting:
    path: str
    value: Any
    target: str | None = None
    override_constraints: bool = False
    reason: str | None = None

    def __post_init__(self) -> None:
        _validate_policy_path(self.path, target=self.target)
        if self.override_constraints and not (self.reason or "").strip():
            raise AuthorityPolicyError(
                "Explicit authority-constraint overrides require a reason"
            )


@dataclass(frozen=True, slots=True)
class PolicyConstraint:
    path: str
    operator: ConstraintOperator
    value: Any = None
    target: str | None = None

    def __post_init__(self) -> None:
        _validate_policy_path(self.path, target=self.target)


@dataclass(frozen=True, slots=True)
class PolicyAuthorityLayer:
    schema_version: int
    authority_id: str
    kind: AuthorityKind
    generation: int
    created_at: str
    settings: tuple[PolicySetting, ...] = ()
    constraints: tuple[PolicyConstraint, ...] = ()
    parents: Mapping[str, str] = field(default_factory=dict)
    expires_at: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "authority_id": self.authority_id,
            "kind": self.kind.value,
            "generation": self.generation,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "parents": dict(self.parents),
            "metadata": dict(self.metadata),
            "settings": [
                {
                    "path": item.path,
                    "value": item.value,
                    "target": item.target,
                    "override_constraints": item.override_constraints,
                    "reason": item.reason,
                }
                for item in self.settings
            ],
            "constraints": [
                {
                    "path": item.path,
                    "operator": item.operator.value,
                    "value": item.value,
                    "target": item.target,
                }
                for item in self.constraints
            ],
        }

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.canonical_dict())).hexdigest()

    @property
    def expired(self) -> bool:
        if not self.expires_at:
            return False
        return _parse_time(self.expires_at) <= utcnow()


@dataclass(frozen=True, slots=True)
class AuthorityLayerVerification:
    authority_id: str
    kind: AuthorityKind
    fingerprint: str
    signature_state: SignatureState
    role_name: str | None = None
    valid_primary_fingerprints: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    source_path: str | None = None

    @property
    def verified(self) -> bool:
        return self.signature_state is SignatureState.VERIFIED


@dataclass(frozen=True, slots=True)
class ConstraintViolation:
    authority_id: str
    authority_kind: AuthorityKind
    path: str
    target: str | None
    operator: ConstraintOperator
    expected: Any
    observed: Any
    overridden_by: str | None = None
    override_reason: str | None = None


@dataclass(frozen=True, slots=True)
class AuthorityRuntimeLease:
    lease_id: UUID
    authority_id: str
    requested_by: str
    reason: str
    created_at: datetime
    expires_at: datetime
    settings: tuple[PolicySetting, ...]
    signature_state: SignatureState = SignatureState.UNSIGNED
    source_layer_fingerprint: str | None = None

    @property
    def expired(self) -> bool:
        return self.expires_at <= utcnow()

    @property
    def fingerprint(self) -> str:
        payload = {
            "lease_id": str(self.lease_id),
            "authority_id": self.authority_id,
            "requested_by": self.requested_by,
            "reason": self.reason,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "settings": [_setting_dict(item) for item in self.settings],
            "signature_state": self.signature_state.value,
            "source_layer_fingerprint": self.source_layer_fingerprint,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class EffectiveAuthorityPolicy:
    generation: int
    fingerprint: str
    layers: tuple[PolicyAuthorityLayer, ...]
    verifications: tuple[AuthorityLayerVerification, ...]
    runtime_leases: tuple[AuthorityRuntimeLease, ...]
    violations: tuple[ConstraintViolation, ...]
    created_at: datetime = field(default_factory=utcnow)

    def layer_status(self) -> list[dict[str, Any]]:
        verification_by_id = {item.authority_id: item for item in self.verifications}
        violations_by_id: dict[str, list[ConstraintViolation]] = {}
        for item in self.violations:
            violations_by_id.setdefault(item.authority_id, []).append(item)
        rows: list[dict[str, Any]] = []
        for kind in (AuthorityKind.FRAMEWORK, AuthorityKind.APPLICATION, AuthorityKind.DEPLOYMENT):
            matching = [item for item in self.layers if item.kind is kind]
            if not matching:
                rows.append({
                    "kind": kind.value,
                    "authority_id": None,
                    "signature": SignatureState.SKIPPED.value,
                    "guarantee": GuaranteeState.SKIPPED.value,
                    "fingerprint": None,
                    "violations": 0,
                })
                continue
            for layer in matching:
                verification = verification_by_id.get(layer.authority_id)
                signature = verification.signature_state if verification else SignatureState.UNSIGNED
                violations = violations_by_id.get(layer.authority_id, [])
                if layer.expired or signature in {SignatureState.INVALID, SignatureState.UNAVAILABLE}:
                    guarantee = GuaranteeState.INVALID
                elif violations:
                    guarantee = GuaranteeState.VIOLATED
                elif signature is SignatureState.UNSIGNED:
                    guarantee = GuaranteeState.UNSIGNED
                else:
                    guarantee = GuaranteeState.SATISFIED
                rows.append({
                    "kind": kind.value,
                    "authority_id": layer.authority_id,
                    "signature": signature.value,
                    "guarantee": guarantee.value,
                    "fingerprint": layer.fingerprint,
                    "violations": len(violations),
                    "generation": layer.generation,
                    "created_at": layer.created_at,
                    "expires_at": layer.expires_at,
                    "expired": layer.expired,
                    "role": verification.role_name if verification else None,
                    "source_path": verification.source_path if verification else None,
                })
        for lease in self.runtime_leases:
            lease_violations = [
                item for item in self.violations
                if item.overridden_by == lease.authority_id
            ]
            rows.append({
                "kind": AuthorityKind.RUNTIME.value,
                "authority_id": lease.authority_id,
                "signature": lease.signature_state.value,
                "guarantee": (
                    GuaranteeState.SATISFIED.value
                    if lease.signature_state is SignatureState.VERIFIED
                    else GuaranteeState.UNSIGNED.value
                ),
                "fingerprint": lease.fingerprint,
                "source_layer_fingerprint": lease.source_layer_fingerprint,
                "violations": len(lease_violations),
                "lease_id": str(lease.lease_id),
                "expires_at": lease.expires_at.isoformat(),
            })
        return rows

    @property
    def overall_assurance(self) -> str:
        rows = self.layer_status()
        if any(item["guarantee"] == GuaranteeState.INVALID.value for item in rows):
            return "INVALID_AUTHORITY_CHAIN"
        if self.violations:
            return "GUARANTEE_VIOLATED"
        configured = [item for item in rows if item["kind"] != AuthorityKind.RUNTIME.value and item["guarantee"] != GuaranteeState.SKIPPED.value]
        if not configured:
            return "UNCONFIGURED"
        if any(item["signature"] == SignatureState.UNSIGNED.value for item in configured):
            return "PARTIAL_OR_UNSIGNED"
        if any(
            lease.signature_state is not SignatureState.VERIFIED
            for lease in self.runtime_leases
        ):
            return "UNSIGNED_RUNTIME_OVERRIDE"
        return "VERIFIED_AUTHORITY_CHAIN"

    def require_signed_runtime_leases(self) -> bool:
        value = self.setting("authority.runtime.require_signed_leases")
        return bool(value) if value is not None else False

    def setting(self, path: str, *, target_id: str | None = None) -> Any:
        value = None
        found = False
        for layer in self.layers:
            for item in layer.settings:
                if item.path == path and _target_matches(item.target, target_id):
                    value = item.value
                    found = True
        for lease in self.runtime_leases:
            if lease.expired:
                continue
            for item in lease.settings:
                if item.path == path and _target_matches(item.target, target_id):
                    value = item.value
                    found = True
        return value if found else None

    def apply_dataclass(self, value: Any, *, prefix: str, target_id: str | None = None) -> Any:
        result = value
        provenance: dict[str, tuple[str, bool, str | None]] = {}
        for layer in self.layers:
            for setting in layer.settings:
                if not _target_matches(setting.target, target_id):
                    continue
                relative = _relative_path(setting.path, prefix)
                if relative is None:
                    continue
                result = _replace_path(result, relative.split("."), setting.value)
                provenance[setting.path] = (
                    layer.authority_id,
                    setting.override_constraints,
                    setting.reason,
                )
        for lease in self.runtime_leases:
            if lease.expired:
                continue
            for setting in lease.settings:
                if not _target_matches(setting.target, target_id):
                    continue
                relative = _relative_path(setting.path, prefix)
                if relative is None:
                    continue
                result = _replace_path(result, relative.split("."), setting.value)
                provenance[setting.path] = (
                    lease.authority_id,
                    setting.override_constraints,
                    setting.reason,
                )

        flattened = _flatten_dataclass(result, prefix)
        unresolved: list[ConstraintViolation] = []
        for layer in self.layers:
            for constraint in layer.constraints:
                if not _target_matches(constraint.target, target_id):
                    continue
                if constraint.path not in flattened:
                    continue
                observed = flattened[constraint.path]
                if _constraint_satisfied(constraint, observed):
                    continue
                setter = provenance.get(constraint.path)
                overridden = setter is not None and setter[1] and _authority_is_lower(
                    setter[0], layer.authority_id, self.layers, self.runtime_leases
                )
                violation = ConstraintViolation(
                    authority_id=layer.authority_id,
                    authority_kind=layer.kind,
                    path=constraint.path,
                    target=target_id,
                    operator=constraint.operator,
                    expected=constraint.value,
                    observed=observed,
                    overridden_by=setter[0] if overridden and setter else None,
                    override_reason=setter[2] if overridden and setter else None,
                )
                if not overridden:
                    unresolved.append(violation)
        if unresolved:
            raise AuthorityPolicyConflictError(unresolved)
        return result

    def snapshot_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "generation": self.generation,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at.isoformat(),
            "overall_assurance": self.overall_assurance,
            "layers": [
                {
                    **layer.canonical_dict(),
                    "fingerprint": layer.fingerprint,
                }
                for layer in self.layers
            ],
            "verifications": [
                {
                    "authority_id": item.authority_id,
                    "kind": item.kind.value,
                    "fingerprint": item.fingerprint,
                    "signature_state": item.signature_state.value,
                    "role_name": item.role_name,
                    "valid_primary_fingerprints": list(item.valid_primary_fingerprints),
                    "errors": list(item.errors),
                    "source_path": item.source_path,
                }
                for item in self.verifications
            ],
            "runtime_leases": [
                {
                    "lease_id": str(item.lease_id),
                    "authority_id": item.authority_id,
                    "requested_by": item.requested_by,
                    "reason": item.reason,
                    "created_at": item.created_at.isoformat(),
                    "expires_at": item.expires_at.isoformat(),
                    "signature_state": item.signature_state.value,
                    "source_layer_fingerprint": item.source_layer_fingerprint,
                    "fingerprint": item.fingerprint,
                    "settings": [_setting_dict(setting) for setting in item.settings],
                }
                for item in self.runtime_leases
            ],
            "violations": [_violation_dict(item) for item in self.violations],
            "layer_status": self.layer_status(),
        }


@dataclass(frozen=True, slots=True)
class AuthorityLayerSource:
    kind: AuthorityKind
    path: Path
    role: str | None = None
    signatures: tuple[Path, ...] = ()
    root: Path | None = None
    public_keys: tuple[Path, ...] = ()
    verification_mode: SignatureVerificationMode = SignatureVerificationMode.AUTHORIZATION_THRESHOLD
    require_signature: bool = False


@dataclass(frozen=True, slots=True)
class AuthorityStackConfig:
    path: Path
    layers: tuple[AuthorityLayerSource, ...]
    default_root: Path | None = None
    default_public_keys: tuple[Path, ...] = ()


class PolicyAuthoritySupervisor:
    """Supervisor-owned authority stack and effective-policy generation.

    Application processes receive an immutable serialized snapshot. Runtime leases
    create a new generation; they never edit the signed source layers in place.
    """

    def __init__(
        self,
        layers: Sequence[PolicyAuthorityLayer] = (),
        verifications: Sequence[AuthorityLayerVerification] = (),
        *,
        snapshot_path: str | Path | None = None,
    ) -> None:
        self._layers = tuple(sorted(layers, key=lambda item: (_AUTHORITY_ORDER[item.kind], item.authority_id)))
        self._verifications = tuple(verifications)
        self._leases: dict[UUID, AuthorityRuntimeLease] = {}
        self._generation = 0
        self._lock = RLock()
        self._layer_expiry_state = tuple(layer.expired for layer in self._layers)
        self.snapshot_path = Path(snapshot_path).resolve() if snapshot_path else None
        self._validate_parent_chain()
        self._effective = self._reconcile()
        self._persist()

    @classmethod
    def from_stack_file(
        cls,
        path: str | Path,
        *,
        snapshot_path: str | Path | None = None,
    ) -> "PolicyAuthoritySupervisor":
        config = load_authority_stack_config(path)
        layers: list[PolicyAuthorityLayer] = []
        verifications: list[AuthorityLayerVerification] = []
        for source in config.layers:
            if source.kind is AuthorityKind.RUNTIME:
                raise AuthorityPolicyError(
                    "Runtime authority layers are temporary leases and cannot be loaded "
                    "as static stack layers; use a signed runtime-lease descriptor instead"
                )
            layer = load_policy_authority_layer(source.path, require_canonical=True)
            if layer.kind is not source.kind:
                raise AuthorityPolicyError(
                    f"Authority layer {source.path} declares kind {layer.kind.value}, "
                    f"but stack config expects {source.kind.value}"
                )
            verification = verify_authority_layer(
                layer,
                source,
                default_root=config.default_root,
                default_public_keys=config.default_public_keys,
            )
            if verification.signature_state in {SignatureState.INVALID, SignatureState.UNAVAILABLE}:
                raise AuthorityPolicyError(
                    f"Authority layer {layer.authority_id!r} failed signature verification: "
                    + "; ".join(verification.errors)
                )
            if source.require_signature and verification.signature_state is not SignatureState.VERIFIED:
                raise AuthorityPolicyError(
                    f"Authority layer {layer.authority_id!r} requires a valid signature"
                )
            if layer.expired:
                raise AuthorityPolicyError(f"Authority layer {layer.authority_id!r} is expired")
            if (
                layer.kind is AuthorityKind.FRAMEWORK
                and layer.metadata.get("caretaker.profile.lineage")
            ):
                # Named profiles are ordinary framework authority layers. Runtime
                # validation checks signed metadata and policy-surface coverage;
                # exact profile selection remains bound by lower-layer parent hashes.
                from .profiles import validate_runtime_profile

                validate_runtime_profile(layer, source_role=source.role)
            layers.append(layer)
            verifications.append(verification)
        return cls(layers, verifications, snapshot_path=snapshot_path)

    @property
    def effective(self) -> EffectiveAuthorityPolicy:
        with self._lock:
            self._expire_leases_locked()
            self._refresh_layer_expiry_locked()
            return self._effective

    def set_snapshot_path(self, path: str | Path) -> None:
        with self._lock:
            self.snapshot_path = Path(path).expanduser().resolve()
            self._persist()

    def acquire_runtime_lease(
        self,
        *,
        settings: Sequence[PolicySetting],
        requested_by: str,
        reason: str,
        duration_seconds: int,
        authority_id: str | None = None,
        signature_state: SignatureState = SignatureState.UNSIGNED,
        source_layer_fingerprint: str | None = None,
    ) -> AuthorityRuntimeLease:
        integer(
            duration_seconds,
            name="Runtime authority lease duration",
            minimum=1,
        )
        bounded_text(requested_by, name="Runtime authority lease requested_by", maximum=256)
        bounded_text(reason, name="Runtime authority lease reason", maximum=1024)
        settings = tuple(settings)
        if not settings:
            raise AuthorityPolicyError("Runtime authority lease requires at least one setting")
        for setting in settings:
            if setting.path.startswith(("repair.", "lightweight.")) and not setting.target:
                raise AuthorityPolicyError(
                    "Temporary repair.* and lightweight.* authority leases require an explicit target id or glob"
                )
            if runtime_lease_requires_restart(setting.path):
                raise AuthorityPolicyError(
                    f"{setting.path!r} is restart-bound and cannot be changed by a temporary "
                    "runtime lease; put the value in a deployment layer and restart Caretaker"
                )
        with self._lock:
            self._expire_leases_locked()
            if self._effective.require_signed_runtime_leases() and signature_state is not SignatureState.VERIFIED:
                raise AuthorityPolicyError(
                    "The effective authority policy requires signed runtime leases; "
                    "an unsigned temporary escalation cannot be applied"
                )
            now = utcnow()
            lease = AuthorityRuntimeLease(
                lease_id=uuid4(),
                authority_id=authority_id or f"runtime:{requested_by}",
                requested_by=requested_by,
                reason=reason,
                created_at=now,
                expires_at=now + timedelta(seconds=duration_seconds),
                settings=settings,
                signature_state=signature_state,
                source_layer_fingerprint=source_layer_fingerprint,
            )
            self._leases[lease.lease_id] = lease
            try:
                self._effective = self._reconcile()
            except Exception:
                self._leases.pop(lease.lease_id, None)
                raise
            self._persist()
            return lease

    def release_runtime_lease(self, lease_id: UUID) -> EffectiveAuthorityPolicy:
        with self._lock:
            if lease_id not in self._leases:
                raise KeyError(f"No authority runtime lease {lease_id}")
            self._leases.pop(lease_id)
            self._effective = self._reconcile()
            self._persist()
            return self._effective

    def load_signed_runtime_lease(
        self,
        source: AuthorityLayerSource,
        *,
        default_root: Path | None = None,
        default_public_keys: Sequence[Path] = (),
        requested_by: str,
        reason: str | None = None,
    ) -> AuthorityRuntimeLease:
        layer = load_policy_authority_layer(source.path, require_canonical=True)
        if layer.kind is not AuthorityKind.RUNTIME:
            raise AuthorityPolicyError("Signed runtime lease layer must declare kind 'runtime'")
        if layer.constraints:
            raise AuthorityPolicyError(
                "Runtime leases may change values but cannot introduce new authority constraints"
            )
        verification = verify_authority_layer(
            layer,
            source,
            default_root=default_root,
            default_public_keys=tuple(default_public_keys),
        )
        if verification.signature_state is not SignatureState.VERIFIED:
            raise AuthorityPolicyError(
                "Signed runtime lease failed verification: " + "; ".join(verification.errors)
            )
        self._validate_runtime_lease_parent_chain(layer)
        if layer.expires_at is None:
            raise AuthorityPolicyError("Signed runtime lease requires expires_at")
        remaining = int((_parse_time(layer.expires_at) - utcnow()).total_seconds())
        if remaining <= 0:
            raise AuthorityPolicyError("Signed runtime lease is already expired")
        return self.acquire_runtime_lease(
            settings=layer.settings,
            requested_by=requested_by,
            reason=reason or str(layer.metadata.get("reason") or "signed runtime authority lease"),
            duration_seconds=remaining,
            authority_id=layer.authority_id,
            signature_state=SignatureState.VERIFIED,
            source_layer_fingerprint=layer.fingerprint,
        )

    def load_signed_runtime_lease_from_stack_file(
        self,
        path: str | Path,
        *,
        requested_by: str,
        reason: str | None = None,
    ) -> AuthorityRuntimeLease:
        """Verify and apply one signed runtime lease described by a stack TOML file."""
        config = load_authority_stack_config(path)
        runtime_sources = [item for item in config.layers if item.kind is AuthorityKind.RUNTIME]
        non_runtime = [item for item in config.layers if item.kind is not AuthorityKind.RUNTIME]
        if non_runtime or len(runtime_sources) != 1:
            raise AuthorityPolicyError(
                "A signed runtime-lease descriptor must contain exactly one runtime layer"
            )
        source = runtime_sources[0]
        return self.load_signed_runtime_lease(
            source,
            default_root=config.default_root,
            default_public_keys=config.default_public_keys,
            requested_by=requested_by,
            reason=reason,
        )

    def _validate_parent_chain(self) -> None:
        previous: list[PolicyAuthorityLayer] = []
        for layer in self._layers:
            if layer.kind is AuthorityKind.FRAMEWORK and layer.parents:
                raise AuthorityPolicyError(
                    "Framework authority layer cannot declare a lower-level parent"
                )
            expected = {item.kind.value: item.fingerprint for item in previous}
            missing = [kind for kind in expected if kind not in layer.parents]
            if missing:
                raise AuthorityPolicyError(
                    f"Authority layer {layer.authority_id!r} must reference the exact upstream "
                    "policy fingerprints for: " + ", ".join(missing)
                )
            for parent_kind, expected_hash in expected.items():
                observed = str(layer.parents[parent_kind]).lower()
                if observed != expected_hash:
                    raise AuthorityPolicyError(
                        f"Authority layer {layer.authority_id!r} was created against {parent_kind} "
                        f"policy {observed}, but the loaded parent is {expected_hash}"
                    )
            unknown = set(layer.parents) - set(expected)
            if unknown:
                raise AuthorityPolicyError(
                    f"Authority layer {layer.authority_id!r} declares unavailable parent(s): "
                    + ", ".join(sorted(unknown))
                )
            previous.append(layer)

    def _validate_runtime_lease_parent_chain(self, layer: PolicyAuthorityLayer) -> None:
        expected = {item.kind.value: item.fingerprint for item in self._layers}
        missing = [kind for kind in expected if kind not in layer.parents]
        if missing:
            raise AuthorityPolicyError(
                "Signed runtime lease must reference the exact active upstream policies for: "
                + ", ".join(missing)
            )
        for parent_kind, expected_hash in expected.items():
            observed = str(layer.parents[parent_kind]).lower()
            if observed != expected_hash:
                raise AuthorityPolicyError(
                    f"Signed runtime lease was created against {parent_kind} policy {observed}, "
                    f"but the active parent is {expected_hash}"
                )
        unknown = set(layer.parents) - set(expected)
        if unknown:
            raise AuthorityPolicyError(
                "Signed runtime lease declares unavailable parent(s): "
                + ", ".join(sorted(unknown))
            )

    def _refresh_layer_expiry_locked(self) -> None:
        current = tuple(layer.expired for layer in self._layers)
        if current == self._layer_expiry_state:
            return
        self._layer_expiry_state = current
        self._effective = self._reconcile()
        self._persist()

    def _expire_leases_locked(self) -> None:
        expired = [key for key, lease in self._leases.items() if lease.expired]
        if not expired:
            return
        for key in expired:
            self._leases.pop(key, None)
        self._effective = self._reconcile()
        self._persist()

    def _reconcile(self) -> EffectiveAuthorityPolicy:
        self._generation += 1
        leases = tuple(sorted(self._leases.values(), key=lambda item: item.created_at))
        violations = _declared_setting_violations(self._layers, leases)
        unresolved = [item for item in violations if item.overridden_by is None]
        if unresolved:
            raise AuthorityPolicyConflictError(unresolved)
        payload = {
            "generation": self._generation,
            "layers": [layer.fingerprint for layer in self._layers],
            "runtime_leases": [
                {
                    "lease_id": str(lease.lease_id),
                    "authority_id": lease.authority_id,
                    "expires_at": lease.expires_at.isoformat(),
                    "settings": [_setting_dict(item) for item in lease.settings],
                }
                for lease in leases
            ],
            "violations": [_violation_dict(item) for item in violations],
        }
        fingerprint = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
        return EffectiveAuthorityPolicy(
            generation=self._generation,
            fingerprint=fingerprint,
            layers=self._layers,
            verifications=self._verifications,
            runtime_leases=leases,
            violations=tuple(violations),
        )

    def _persist(self) -> None:
        if self.snapshot_path is None:
            return
        write_canonical_json(self.snapshot_path, _canonical_snapshot(self._effective.snapshot_dict()))
        try:
            os.chmod(self.snapshot_path, 0o600)
        except OSError:
            pass


class AuthorityRuntimeContext:
    """Process-local view of the supervisor-owned effective authority policy."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._effective = EffectiveAuthorityPolicy(
            generation=0,
            fingerprint="unconfigured",
            layers=(),
            verifications=(),
            runtime_leases=(),
            violations=(),
        )

    @property
    def effective(self) -> EffectiveAuthorityPolicy:
        with self._lock:
            return self._effective

    def load_snapshot(self, path: str | Path) -> EffectiveAuthorityPolicy:
        value = load_json_object(path)
        return self.update_from_snapshot(value)

    def update_from_snapshot(self, value: Mapping[str, Any]) -> EffectiveAuthorityPolicy:
        effective = effective_policy_from_snapshot(value)
        with self._lock:
            self._effective = effective
        return effective

    def apply(self, value: Any, *, prefix: str, target_id: str | None = None) -> Any:
        return self.effective.apply_dataclass(value, prefix=prefix, target_id=target_id)


_RUNTIME_CONTEXT = AuthorityRuntimeContext()


def get_authority_runtime_context() -> AuthorityRuntimeContext:
    return _RUNTIME_CONTEXT


def load_authority_runtime_from_environment() -> EffectiveAuthorityPolicy:
    path = os.environ.get("CARETAKER_AUTHORITY_POLICY")
    if not path:
        return _RUNTIME_CONTEXT.effective
    return _RUNTIME_CONTEXT.load_snapshot(path)


def load_policy_authority_layer(
    path: str | Path,
    *,
    require_canonical: bool = True,
) -> PolicyAuthorityLayer:
    value = assert_canonical_json(path) if require_canonical else load_json_object(path)
    settings = tuple(
        PolicySetting(
            path=str(item["path"]),
            value=item.get("value"),
            target=str(item["target"]) if item.get("target") else None,
            override_constraints=exact_bool(
                item.get("override_constraints", False),
                name="authority setting override_constraints",
            ),
            reason=str(item["reason"]) if item.get("reason") else None,
        )
        for item in value.get("settings", ())
    )
    constraints = tuple(
        PolicyConstraint(
            path=str(item["path"]),
            operator=ConstraintOperator(str(item["operator"]).lower()),
            value=item.get("value"),
            target=str(item["target"]) if item.get("target") else None,
        )
        for item in value.get("constraints", ())
    )
    layer = PolicyAuthorityLayer(
        schema_version=integer(value.get("schema_version", 1), name="authority schema_version", minimum=1),
        authority_id=str(value["authority_id"]),
        kind=AuthorityKind(str(value["kind"]).lower()),
        generation=integer(value.get("generation", 1), name="authority generation", minimum=1),
        created_at=str(value.get("created_at") or utcnow().isoformat()),
        settings=settings,
        constraints=constraints,
        parents={str(key): str(item).lower() for key, item in dict(value.get("parents", {})).items()},
        expires_at=str(value["expires_at"]) if value.get("expires_at") else None,
        metadata={str(key): str(item) for key, item in dict(value.get("metadata", {})).items()},
    )
    if layer.schema_version != 1:
        raise AuthorityPolicyError(f"Unsupported authority policy schema {layer.schema_version}")
    if layer.generation < 1:
        raise AuthorityPolicyError("Authority policy generation must be positive")
    _parse_time(layer.created_at)
    if layer.expires_at:
        _parse_time(layer.expires_at)
    return layer


def write_policy_authority_layer(path: str | Path, layer: PolicyAuthorityLayer) -> None:
    write_canonical_json(path, layer.canonical_dict())


def load_authority_stack_config(path: str | Path) -> AuthorityStackConfig:
    source = Path(path).resolve()
    raw = tomllib.loads(source.read_text(encoding="utf-8"))
    if integer(raw.get("schema_version", 1), name="authority stack schema_version", minimum=1) != 1:
        raise AuthorityPolicyError("Unsupported authority stack schema")
    base = source.parent
    trust = dict(raw.get("trust", {}))
    default_root = _resolve_optional(base, trust.get("root"))
    default_public_keys = tuple(_resolve_required(base, item) for item in trust.get("public_keys", ()))
    layers: list[AuthorityLayerSource] = []
    for item in raw.get("layers", ()):
        layer = dict(item)
        mode = SignatureVerificationMode(
            str(layer.get("verification_mode", "authorization-threshold")).lower()
        )
        if mode is SignatureVerificationMode.RANDOMIZED_RUNTIME:
            raise AuthorityPolicyError(
                "Policy authority layers do not support randomized signature verification; "
                "use authorization-threshold or full-publication"
            )
        layers.append(
            AuthorityLayerSource(
                kind=AuthorityKind(str(layer["kind"]).lower()),
                path=_resolve_required(base, layer["path"]),
                role=str(layer["role"]) if layer.get("role") else None,
                signatures=tuple(_resolve_required(base, value) for value in layer.get("signatures", ())),
                root=_resolve_optional(base, layer.get("root")),
                public_keys=tuple(_resolve_required(base, value) for value in layer.get("public_keys", ())),
                verification_mode=mode,
                require_signature=exact_bool(
                    layer.get("require_signature", False),
                    name="authority layer require_signature",
                ),
            )
        )
    duplicate_kinds = [
        kind.value for kind in AuthorityKind
        if kind is not AuthorityKind.RUNTIME and sum(1 for item in layers if item.kind is kind) > 1
    ]
    if duplicate_kinds:
        raise AuthorityPolicyError(
            "Only one non-runtime layer per authority kind is supported in V1: " + ", ".join(duplicate_kinds)
        )
    return AuthorityStackConfig(
        path=source,
        layers=tuple(layers),
        default_root=default_root,
        default_public_keys=default_public_keys,
    )


def verify_authority_layer(
    layer: PolicyAuthorityLayer,
    source: AuthorityLayerSource,
    *,
    default_root: Path | None,
    default_public_keys: Sequence[Path],
) -> AuthorityLayerVerification:
    def invalid_role(error: str) -> AuthorityLayerVerification:
        return AuthorityLayerVerification(
            authority_id=layer.authority_id,
            kind=layer.kind,
            fingerprint=layer.fingerprint,
            signature_state=SignatureState.INVALID,
            role_name=source.role,
            errors=(error,),
            source_path=str(source.path),
        )

    if source.kind is not layer.kind:
        return invalid_role(
            f"Authority source kind {source.kind.value!r} does not match "
            f"layer kind {layer.kind.value!r}"
        )
    permitted_roles = _AUTHORITY_SIGNING_ROLES[layer.kind]
    if source.role is not None and source.role not in permitted_roles:
        return invalid_role(
            f"Authority layer kind {layer.kind.value!r} cannot use signing role "
            f"{source.role!r}; permitted role(s): {', '.join(sorted(permitted_roles))}"
        )
    if not source.signatures:
        return AuthorityLayerVerification(
            authority_id=layer.authority_id,
            kind=layer.kind,
            fingerprint=layer.fingerprint,
            signature_state=SignatureState.UNSIGNED,
            role_name=source.role,
            source_path=str(source.path),
        )
    root_path = source.root or default_root
    public_keys = source.public_keys or tuple(default_public_keys)
    if source.role is None:
        return invalid_role(
            f"Signed authority layer kind {layer.kind.value!r} requires one of these "
            f"signing roles: {', '.join(sorted(permitted_roles))}"
        )
    if root_path is None or not public_keys:
        return AuthorityLayerVerification(
            authority_id=layer.authority_id,
            kind=layer.kind,
            fingerprint=layer.fingerprint,
            signature_state=SignatureState.INVALID,
            role_name=source.role,
            errors=("Signed authority layer requires a trust root, role, and public keys",),
            source_path=str(source.path),
        )
    root = load_root(root_path)
    if source.role not in root.roles:
        return AuthorityLayerVerification(
            authority_id=layer.authority_id,
            kind=layer.kind,
            fingerprint=layer.fingerprint,
            signature_state=SignatureState.INVALID,
            role_name=source.role,
            errors=(f"Trust root does not define authority role {source.role!r}",),
            source_path=str(source.path),
        )
    try:
        verifier = GPGVerifier()
        result = verifier.verify_threshold(
            signed_path=source.path,
            signature_paths=source.signatures,
            public_key_paths=public_keys,
            role=root.roles[source.role],
            mode=source.verification_mode,
        )
    except GPGUnavailableError as exc:
        return AuthorityLayerVerification(
            authority_id=layer.authority_id,
            kind=layer.kind,
            fingerprint=layer.fingerprint,
            signature_state=SignatureState.UNAVAILABLE,
            role_name=source.role,
            errors=(str(exc),),
            source_path=str(source.path),
        )
    return AuthorityLayerVerification(
        authority_id=layer.authority_id,
        kind=layer.kind,
        fingerprint=layer.fingerprint,
        signature_state=SignatureState.VERIFIED if result.satisfied else SignatureState.INVALID,
        role_name=source.role,
        valid_primary_fingerprints=result.valid_primary_fingerprints,
        errors=result.errors,
        source_path=str(source.path),
    )


def effective_policy_from_snapshot(value: Mapping[str, Any]) -> EffectiveAuthorityPolicy:
    if not isinstance(value, Mapping):
        raise AuthorityPolicyError("authority runtime snapshot must be an object")
    if integer(value.get("schema_version", 1), name="authority snapshot schema_version", minimum=1) != 1:
        raise AuthorityPolicyError("Unsupported authority runtime snapshot schema")
    layers = tuple(_layer_from_snapshot(item) for item in value.get("layers", ()))
    verifications = tuple(
        AuthorityLayerVerification(
            authority_id=str(item["authority_id"]),
            kind=AuthorityKind(str(item["kind"])),
            fingerprint=str(item["fingerprint"]),
            signature_state=SignatureState(str(item["signature_state"])),
            role_name=item.get("role_name"),
            valid_primary_fingerprints=tuple(item.get("valid_primary_fingerprints", ())),
            errors=tuple(item.get("errors", ())),
            source_path=item.get("source_path"),
        )
        for item in value.get("verifications", ())
    )
    leases = tuple(
        AuthorityRuntimeLease(
            lease_id=UUID(str(item["lease_id"])),
            authority_id=str(item["authority_id"]),
            requested_by=str(item.get("requested_by", "unknown")),
            reason=str(item.get("reason", "runtime authority lease")),
            created_at=_parse_time(str(item["created_at"])),
            expires_at=_parse_time(str(item["expires_at"])),
            settings=tuple(_setting_from_dict(setting) for setting in item.get("settings", ())),
            signature_state=SignatureState(str(item.get("signature_state", "unsigned"))),
            source_layer_fingerprint=item.get("source_layer_fingerprint"),
        )
        for item in value.get("runtime_leases", ())
    )
    violations = tuple(
        ConstraintViolation(
            authority_id=str(item["authority_id"]),
            authority_kind=AuthorityKind(str(item["authority_kind"])),
            path=str(item["path"]),
            target=item.get("target"),
            operator=ConstraintOperator(str(item["operator"])),
            expected=item.get("expected"),
            observed=item.get("observed"),
            overridden_by=item.get("overridden_by"),
            override_reason=item.get("override_reason"),
        )
        for item in value.get("violations", ())
    )
    return EffectiveAuthorityPolicy(
        generation=integer(value.get("generation", 0), name="authority snapshot generation", minimum=0),
        fingerprint=str(value.get("fingerprint", "unconfigured")),
        layers=layers,
        verifications=verifications,
        runtime_leases=leases,
        violations=violations,
        created_at=_parse_time(str(value.get("created_at", utcnow().isoformat()))),
    )


def _layer_from_snapshot(value: Mapping[str, Any]) -> PolicyAuthorityLayer:
    return PolicyAuthorityLayer(
        schema_version=integer(value.get("schema_version", 1), name="authority layer schema_version", minimum=1),
        authority_id=str(value["authority_id"]),
        kind=AuthorityKind(str(value["kind"])),
        generation=integer(value.get("generation", 1), name="authority layer generation", minimum=1),
        created_at=str(value["created_at"]),
        settings=tuple(_setting_from_dict(item) for item in value.get("settings", ())),
        constraints=tuple(
            PolicyConstraint(
                path=str(item["path"]),
                operator=ConstraintOperator(str(item["operator"])),
                value=item.get("value"),
                target=item.get("target"),
            )
            for item in value.get("constraints", ())
        ),
        parents=dict(value.get("parents", {})),
        expires_at=value.get("expires_at"),
        metadata=dict(value.get("metadata", {})),
    )


def _declared_setting_violations(
    layers: Sequence[PolicyAuthorityLayer],
    leases: Sequence[AuthorityRuntimeLease],
) -> list[ConstraintViolation]:
    constraints: list[tuple[PolicyAuthorityLayer, PolicyConstraint]] = []
    violations: list[ConstraintViolation] = []
    settings: list[tuple[str, AuthorityKind, PolicySetting]] = []
    for layer in layers:
        for setting in layer.settings:
            settings.append((layer.authority_id, layer.kind, setting))
        for constraint in layer.constraints:
            constraints.append((layer, constraint))
    for lease in leases:
        for setting in lease.settings:
            settings.append((lease.authority_id, AuthorityKind.RUNTIME, setting))

    for setter_id, setter_kind, setting in settings:
        for owner, constraint in constraints:
            if _AUTHORITY_ORDER[setter_kind] <= _AUTHORITY_ORDER[owner.kind]:
                continue
            if constraint.path != setting.path:
                continue
            if not _patterns_overlap(constraint.target, setting.target):
                continue
            if _constraint_satisfied(constraint, setting.value):
                continue
            overridden = setting.override_constraints
            violations.append(
                ConstraintViolation(
                    authority_id=owner.authority_id,
                    authority_kind=owner.kind,
                    path=constraint.path,
                    target=setting.target,
                    operator=constraint.operator,
                    expected=constraint.value,
                    observed=setting.value,
                    overridden_by=setter_id if overridden else None,
                    override_reason=setting.reason if overridden else None,
                )
            )
    return violations


def _constraint_satisfied(constraint: PolicyConstraint, observed: Any) -> bool:
    observed_value = _canonical_scalar(observed)
    expected = constraint.value
    if constraint.operator is ConstraintOperator.EXACT:
        return observed_value == _canonical_scalar(expected)
    if constraint.operator is ConstraintOperator.ALLOWED_VALUES:
        return observed_value in {_canonical_scalar(item) for item in (expected or ())}
    if constraint.operator is ConstraintOperator.PROHIBITED_VALUES:
        return observed_value not in {_canonical_scalar(item) for item in (expected or ())}
    if constraint.operator is ConstraintOperator.REQUIRED_TRUE:
        return observed_value is True
    if constraint.operator is ConstraintOperator.REQUIRED_FALSE:
        return observed_value is False
    if constraint.operator is ConstraintOperator.MINIMUM:
        try:
            return observed_value >= expected
        except TypeError:
            return False
    if constraint.operator is ConstraintOperator.MAXIMUM:
        try:
            return observed_value <= expected
        except TypeError:
            return False
    return False


def _authority_is_lower(
    setter_id: str,
    owner_id: str,
    layers: Sequence[PolicyAuthorityLayer],
    leases: Sequence[AuthorityRuntimeLease],
) -> bool:
    kinds = {item.authority_id: item.kind for item in layers}
    kinds.update({item.authority_id: AuthorityKind.RUNTIME for item in leases})
    setter_kind = kinds.get(setter_id)
    owner_kind = kinds.get(owner_id)
    return bool(
        setter_kind is not None
        and owner_kind is not None
        and _AUTHORITY_ORDER[setter_kind] > _AUTHORITY_ORDER[owner_kind]
    )


def _validate_policy_path(path: str, *, target: str | None = None) -> None:
    normalized = str(path).strip()
    if not normalized or "." not in normalized:
        raise AuthorityPolicyError(
            "Authority policy paths must include a supported policy prefix and field name"
        )
    prefix = normalized.split(".", 1)[0]
    if prefix not in SUPPORTED_POLICY_PREFIXES:
        raise AuthorityPolicyError(
            f"Unsupported authority policy prefix {prefix!r}; supported prefixes are "
            + ", ".join(sorted(SUPPORTED_POLICY_PREFIXES))
        )
    if target is not None and prefix not in {"repair", "lightweight"}:
        raise AuthorityPolicyError(
            "Target-scoped authority settings are currently supported only for repair.* "
            "and lightweight.* paths; Guard target bindings are configured through repair.guard.*"
        )


def runtime_lease_requires_restart(path: str) -> bool:
    return path == "system" or any(
        path == prefix.rstrip(".") or path.startswith(prefix)
        for prefix in RUNTIME_RESTART_BOUND_PREFIXES
    )


def _target_matches(pattern: str | None, target_id: str | None) -> bool:
    if pattern is None:
        return True
    if target_id is None:
        return False
    return fnmatch.fnmatchcase(target_id, pattern)


def _patterns_overlap(first: str | None, second: str | None) -> bool:
    if first is None or second is None:
        return True
    if first == second:
        return True
    # Exact names and ordinary glob patterns cover the practical V1 case.
    return fnmatch.fnmatchcase(first, second) or fnmatch.fnmatchcase(second, first)


def _relative_path(path: str, prefix: str) -> str | None:
    prefix = prefix.rstrip(".")
    if path == prefix:
        return ""
    marker = prefix + "."
    if not path.startswith(marker):
        return None
    return path[len(marker):]


def _replace_path(value: Any, parts: list[str], raw: Any) -> Any:
    if not parts or parts == [""]:
        return _coerce_value(value, raw)
    if not dataclasses.is_dataclass(value):
        raise AuthorityPolicyError(
            f"Cannot apply authority setting through non-dataclass value at {'.'.join(parts)}"
        )
    name = parts[0]
    fields = {item.name for item in dataclasses.fields(value)}
    if name not in fields:
        raise AuthorityPolicyError(
            f"Authority setting references unknown policy field {name!r} on {type(value).__name__}"
        )
    current = getattr(value, name)
    replacement = _replace_path(current, parts[1:], raw)
    return replace(value, **{name: replacement})


def _coerce_value(current: Any, raw: Any) -> Any:
    if isinstance(current, Enum):
        enum_type = type(current)
        text = str(raw)
        try:
            return enum_type[text.upper()]
        except (KeyError, TypeError, ValueError):
            try:
                return enum_type(raw)
            except (KeyError, TypeError, ValueError) as exc:
                raise AuthorityPolicyError(
                    f"authority enum setting must be a {enum_type.__name__} value"
                ) from exc
    if isinstance(current, bool):
        try:
            return exact_bool(raw, name="authority boolean setting")
        except ValueError as exc:
            raise AuthorityPolicyError(str(exc)) from exc
    if isinstance(current, int) and not isinstance(current, bool):
        try:
            return integer(raw, name="authority integer setting")
        except ValueError as exc:
            raise AuthorityPolicyError(str(exc)) from exc
    if isinstance(current, float):
        try:
            return float(finite_number(raw, name="authority numeric setting"))
        except ValueError as exc:
            raise AuthorityPolicyError(str(exc)) from exc
    if isinstance(current, str):
        if not isinstance(raw, str):
            raise AuthorityPolicyError("authority text setting must be a string")
        return raw
    if current is None:
        return raw
    if isinstance(current, tuple):
        if not isinstance(raw, (list, tuple)):
            raise AuthorityPolicyError("Tuple policy settings require a JSON array")
        if current and isinstance(current[0], Enum):
            enum_type = type(current[0])
            return tuple(enum_type[str(item).upper()] for item in raw)
        return tuple(raw)
    if isinstance(current, frozenset):
        if not isinstance(raw, (list, tuple, set, frozenset)):
            raise AuthorityPolicyError("Set policy settings require a JSON array")
        if current:
            sample = next(iter(current))
            if isinstance(sample, Enum):
                enum_type = type(sample)
                try:
                    return frozenset(enum_type[str(item).upper()] for item in raw)
                except (KeyError, TypeError, ValueError) as exc:
                    raise AuthorityPolicyError(
                        f"authority set setting must contain {enum_type.__name__} values"
                    ) from exc
        return frozenset(raw)
    return raw


def _flatten_dataclass(value: Any, prefix: str) -> dict[str, Any]:
    result: dict[str, Any] = {}

    def visit(item: Any, path: str) -> None:
        if dataclasses.is_dataclass(item):
            for field_value in dataclasses.fields(item):
                child = getattr(item, field_value.name)
                visit(child, f"{path}.{field_value.name}" if path else field_value.name)
            return
        result[path] = _canonical_scalar(item)

    visit(value, prefix.rstrip("."))
    return result


def _canonical_scalar(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (tuple, list, set, frozenset)):
        return tuple(_canonical_scalar(item) for item in value)
    return value


def _setting_dict(item: PolicySetting) -> dict[str, Any]:
    return {
        "path": item.path,
        "value": item.value,
        "target": item.target,
        "override_constraints": item.override_constraints,
        "reason": item.reason,
    }


def _setting_from_dict(item: Mapping[str, Any]) -> PolicySetting:
    try:
        override_constraints = exact_bool(
            item.get("override_constraints", False),
            name="authority setting override_constraints",
        )
    except ValueError as exc:
        raise AuthorityPolicyError(str(exc)) from exc
    return PolicySetting(
        path=str(item["path"]),
        value=item.get("value"),
        target=item.get("target"),
        override_constraints=override_constraints,
        reason=item.get("reason"),
    )


def _violation_dict(item: ConstraintViolation) -> dict[str, Any]:
    return {
        "authority_id": item.authority_id,
        "authority_kind": item.authority_kind.value,
        "path": item.path,
        "target": item.target,
        "operator": item.operator.value,
        "expected": item.expected,
        "observed": item.observed,
        "overridden_by": item.overridden_by,
        "override_reason": item.override_reason,
    }


def _canonical_snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    """Make runtime snapshot compatible with Caretaker canonical JSON.

    Policy layer files themselves reject floats. Runtime snapshots may contain
    values from application policy dataclasses, so floats are rendered as strings
    rather than weakening the canonical metadata format.
    """
    def convert(item: Any) -> Any:
        if isinstance(item, float):
            return format(item, ".17g")
        if isinstance(item, Mapping):
            return {str(key): convert(child) for key, child in item.items()}
        if isinstance(item, (tuple, list)):
            return [convert(child) for child in item]
        return item

    return convert(dict(value))


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _resolve_optional(base: Path, value: Any) -> Path | None:
    return None if value is None else _resolve_required(base, value)


def _resolve_required(base: Path, value: Any) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = base / path
    return path.resolve()
