from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Mapping
from uuid import UUID, uuid4


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IntegrityClass(Enum):
    ORDINARY = "ordinary"
    PROTECTED = "protected"
    SEALED = "sealed"


class ManifestType(Enum):
    RELEASE = "release"
    PROTECTED = "protected"
    ROOT = "root"


class SignatureVerificationMode(Enum):
    """How many authorized OpenPGP identities are verified.

    AUTHORIZATION_THRESHOLD verifies the role's minimum authorization threshold.
    FULL_PUBLICATION verifies the expected publication signature set, normally all
    three Caretaker identities. RANDOMIZED_RUNTIME chooses an unpredictable subset
    whose size is encoded in the authenticated root metadata.
    """

    AUTHORIZATION_THRESHOLD = "authorization-threshold"
    FULL_PUBLICATION = "full-publication"
    RANDOMIZED_RUNTIME = "randomized-runtime"


class IntegrityFailureKind(Enum):
    HASH_MISMATCH = auto()
    MISSING_ARTIFACT = auto()
    UNSIGNED_ARTIFACT = auto()
    INSUFFICIENT_SIGNATURES = auto()
    INVALID_SIGNATURE = auto()
    UNKNOWN_SIGNER = auto()
    DUPLICATE_SIGNER = auto()
    EXPIRED_OR_REVOKED_SIGNER = auto()
    ROOT_ROLLBACK = auto()
    MANIFEST_ROLLBACK = auto()
    ROOT_CHAIN_BROKEN = auto()
    MANIFEST_INVALID = auto()
    RUNTIME_CODE_CHANGED = auto()
    GPG_UNAVAILABLE = auto()
    GPG_ERROR = auto()


class IntegrityAction(Enum):
    RECORD_ONLY = auto()
    ALERT = auto()
    REFUSE_IMPORT = auto()
    DISABLE_REPAIR_ENGINE = auto()
    TERMINATE_STARTUP = auto()


@dataclass(frozen=True, slots=True)
class RolePolicy:
    name: str
    authorized_primary_fingerprints: tuple[str, ...]
    threshold: int
    publication_threshold: int | None = None
    runtime_sample_size: int | None = None

    def __post_init__(self) -> None:
        normalized = tuple(normalize_fingerprint(item) for item in self.authorized_primary_fingerprints)
        if len(set(normalized)) != len(normalized):
            raise ValueError(f"Role {self.name!r} contains duplicate fingerprints")
        if self.threshold < 1:
            raise ValueError("Signature threshold must be at least one")
        if self.threshold > len(normalized):
            raise ValueError("Signature threshold exceeds the number of authorized signers")

        publication_threshold = self.publication_threshold
        if publication_threshold is None:
            publication_threshold = len(normalized)
        if publication_threshold < self.threshold or publication_threshold > len(normalized):
            raise ValueError(
                "Publication signature threshold must be at least the authorization threshold "
                "and no greater than the authorized signer count"
            )

        runtime_sample_size = self.runtime_sample_size
        if runtime_sample_size is None:
            runtime_sample_size = self.threshold
        if runtime_sample_size < 1 or runtime_sample_size > publication_threshold:
            raise ValueError("Runtime sample size must be within the publication signature set")
        if self.name in {"protected", "root"} and runtime_sample_size < self.threshold:
            raise ValueError("Protected and root randomized verification cannot weaken the 2-of-3 threshold")

        object.__setattr__(self, "authorized_primary_fingerprints", normalized)
        object.__setattr__(self, "publication_threshold", publication_threshold)
        object.__setattr__(self, "runtime_sample_size", runtime_sample_size)

    def threshold_for(self, mode: SignatureVerificationMode) -> int:
        if mode is SignatureVerificationMode.FULL_PUBLICATION:
            assert self.publication_threshold is not None
            return self.publication_threshold
        if mode is SignatureVerificationMode.RANDOMIZED_RUNTIME:
            assert self.runtime_sample_size is not None
            return self.runtime_sample_size
        return self.threshold


@dataclass(frozen=True, slots=True)
class KeyRotationPolicy:
    """Rolling key schedule encoded in signed root metadata.

    A rotation occurs every ``interval_days``. With the default A/B/C sequence,
    each slot is replaced once during a six-year cycle. The schedule is advisory
    by default; emergency rotation remains possible through a valid root transition.
    """

    epoch: str
    interval_days: int = 730
    sequence: tuple[str, ...] = ("A", "B", "C")
    generation: int = 0
    warning_days: int = 90

    def __post_init__(self) -> None:
        _parse_timestamp(self.epoch, "rotation epoch")
        if self.interval_days < 1:
            raise ValueError("Rotation interval must be positive")
        if not self.sequence or len(set(self.sequence)) != len(self.sequence):
            raise ValueError("Rotation sequence must contain distinct key-slot names")
        if self.generation < 0:
            raise ValueError("Rotation generation cannot be negative")
        if self.warning_days < 0:
            raise ValueError("Rotation warning window cannot be negative")

    @property
    def full_cycle_days(self) -> int:
        return self.interval_days * len(self.sequence)

    @property
    def next_slot(self) -> str:
        return self.sequence[self.generation % len(self.sequence)]

    @property
    def next_due_at(self) -> datetime:
        epoch = _parse_timestamp(self.epoch, "rotation epoch")
        return epoch + timedelta(days=self.interval_days * (self.generation + 1))


@dataclass(frozen=True, slots=True)
class RotationStatus:
    generation: int
    next_slot: str
    next_due_at: datetime
    days_remaining: int
    warning: bool
    overdue: bool
    full_cycle_days: int


@dataclass(frozen=True, slots=True)
class RootMetadata:
    schema_version: int
    project: str
    root_version: int
    roles: Mapping[str, RolePolicy]
    protected_paths: tuple[str, ...] = ()
    sealed_paths: tuple[str, ...] = ()
    key_slots: Mapping[str, str] = field(default_factory=dict)
    rotation_policy: KeyRotationPolicy | None = None
    created_at: str | None = None
    expires_at: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version not in {1, 2}:
            raise ValueError(f"Unsupported root schema version: {self.schema_version}")
        if not self.project or self.root_version < 1:
            raise ValueError("Root metadata requires a project and positive version")
        required = {"release", "protected", "root"}
        missing = required - set(self.roles)
        if missing:
            raise ValueError("Root metadata is missing roles: " + ", ".join(sorted(missing)))
        release = self.roles["release"]
        protected = self.roles["protected"]
        root = self.roles["root"]
        signer_sets = {
            frozenset(release.authorized_primary_fingerprints),
            frozenset(protected.authorized_primary_fingerprints),
            frozenset(root.authorized_primary_fingerprints),
        }
        if len(signer_sets) != 1 or len(next(iter(signer_sets))) != 3:
            raise ValueError("Caretaker roots require the same three primary identities for all roles")
        if release.threshold != 1 or protected.threshold != 2 or root.threshold != 2:
            raise ValueError("Caretaker roots require release=1, protected=2, and root=2 authorization thresholds")

        if self.schema_version == 2:
            if any(role.publication_threshold != 3 for role in (release, protected, root)):
                raise ValueError("Caretaker root V2 requires all three signatures on published manifests")
            if release.runtime_sample_size != 1:
                raise ValueError("Caretaker root V2 release runtime sampling must select one key")
            if protected.runtime_sample_size != 2 or root.runtime_sample_size != 2:
                raise ValueError("Caretaker root V2 protected/root runtime sampling must select two keys")
            normalized_slots = {
                str(name): normalize_fingerprint(fingerprint)
                for name, fingerprint in self.key_slots.items()
            }
            if set(normalized_slots) != {"A", "B", "C"}:
                raise ValueError("Caretaker root V2 requires key slots A, B, and C")
            if set(normalized_slots.values()) != set(release.authorized_primary_fingerprints):
                raise ValueError("Key-slot fingerprints must exactly match the authorized signer identities")
            if self.rotation_policy is None:
                raise ValueError("Caretaker root V2 requires a signed rotation policy")
            if set(self.rotation_policy.sequence) != set(normalized_slots):
                raise ValueError("Rotation sequence must reference exactly the signed key slots")
            object.__setattr__(self, "key_slots", normalized_slots)
        elif self.key_slots:
            object.__setattr__(
                self,
                "key_slots",
                {str(name): normalize_fingerprint(value) for name, value in self.key_slots.items()},
            )

    def role(self, name: str) -> RolePolicy:
        try:
            return self.roles[name]
        except KeyError as exc:
            raise ValueError(f"Root metadata does not define role {name!r}") from exc

    def rotation_status(self, now: datetime | None = None) -> RotationStatus | None:
        if self.rotation_policy is None:
            return None
        current = now or utcnow()
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        due = self.rotation_policy.next_due_at
        seconds = (due - current.astimezone(timezone.utc)).total_seconds()
        days_remaining = int(seconds // 86400)
        overdue = seconds < 0
        warning = overdue or seconds <= self.rotation_policy.warning_days * 86400
        return RotationStatus(
            generation=self.rotation_policy.generation,
            next_slot=self.rotation_policy.next_slot,
            next_due_at=due,
            days_remaining=days_remaining,
            warning=warning,
            overdue=overdue,
            full_cycle_days=self.rotation_policy.full_cycle_days,
        )


@dataclass(frozen=True, slots=True)
class ArtifactDigest:
    path: str
    sha256: str
    size_bytes: int
    integrity_class: IntegrityClass = IntegrityClass.ORDINARY
    function_hashes: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if (
            not self.path
            or Path(self.path).is_absolute()
            or ".." in Path(self.path).parts
            or "\\" in self.path
            or any(ord(character) < 32 for character in self.path)
        ):
            raise ValueError(f"Invalid relative artifact path: {self.path!r}")
        digest = self.sha256.lower()
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError(f"Invalid SHA-256 digest for {self.path!r}")
        if self.size_bytes < 0:
            raise ValueError("Artifact size cannot be negative")
        object.__setattr__(self, "sha256", digest)


@dataclass(frozen=True, slots=True)
class IntegrityManifest:
    schema_version: int
    project: str
    manifest_type: ManifestType
    manifest_version: int
    root_version: int
    package_version: str
    created_at: str
    artifacts: tuple[ArtifactDigest, ...]
    coverage_patterns: tuple[str, ...] = ()
    excluded_patterns: tuple[str, ...] = ()
    previous_manifest_sha256: str | None = None
    minimum_caretaker_version: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError(f"Unsupported manifest schema version: {self.schema_version}")
        if not self.project or self.manifest_version < 1 or self.root_version < 1:
            raise ValueError("Manifest requires a project and positive versions")
        paths = [item.path for item in self.artifacts]
        if not paths or len(paths) != len(set(paths)):
            raise ValueError("Manifest must contain at least one artifact with no duplicate paths")
        if paths != sorted(paths):
            raise ValueError("Manifest artifacts must be sorted by path")


@dataclass(frozen=True, slots=True)
class SignatureVerification:
    signature_path: str
    valid: bool
    signing_fingerprint: str | None
    primary_fingerprint: str | None
    status_codes: tuple[str, ...]
    public_key_algorithm_id: int | None = None
    hash_algorithm_id: int | None = None
    signature_class: str | None = None
    stderr: str = ""
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ThresholdVerification:
    role_name: str
    required_threshold: int
    authorized_primary_fingerprints: tuple[str, ...]
    valid_primary_fingerprints: tuple[str, ...]
    signature_results: tuple[SignatureVerification, ...]
    satisfied: bool
    errors: tuple[str, ...] = ()
    verification_mode: SignatureVerificationMode = SignatureVerificationMode.AUTHORIZATION_THRESHOLD
    selected_primary_fingerprints: tuple[str, ...] = ()
    expected_publication_signatures: int | None = None


@dataclass(frozen=True, slots=True)
class ArtifactVerification:
    path: str
    expected_sha256: str
    observed_sha256: str | None
    expected_size_bytes: int
    observed_size_bytes: int | None
    valid: bool
    error: str | None = None


@dataclass(frozen=True, slots=True)
class IntegrityVerification:
    verification_id: UUID
    occurred_at: datetime
    project: str
    root_version: int
    manifest_version: int
    manifest_type: ManifestType
    manifest_path: str
    manifest_sha256: str
    signature_verification: ThresholdVerification
    artifact_results: tuple[ArtifactVerification, ...]
    root_anchored: bool
    trusted: bool
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @classmethod
    def create(
        cls,
        *,
        project: str,
        root_version: int,
        manifest_version: int,
        manifest_type: ManifestType,
        manifest_path: str | Path,
        manifest_sha256: str,
        signature_verification: ThresholdVerification,
        artifact_results: tuple[ArtifactVerification, ...],
        root_anchored: bool,
        errors: tuple[str, ...] = (),
        warnings: tuple[str, ...] = (),
    ) -> "IntegrityVerification":
        trusted = (
            root_anchored
            and signature_verification.satisfied
            and all(item.valid for item in artifact_results)
            and not errors
        )
        return cls(
            verification_id=uuid4(),
            occurred_at=utcnow(),
            project=project,
            root_version=root_version,
            manifest_version=manifest_version,
            manifest_type=manifest_type,
            manifest_path=str(manifest_path),
            manifest_sha256=manifest_sha256,
            signature_verification=signature_verification,
            artifact_results=artifact_results,
            root_anchored=root_anchored,
            trusted=trusted,
            errors=errors,
            warnings=warnings,
        )


@dataclass(frozen=True, slots=True)
class IntegrityIncident:
    incident_id: UUID
    occurred_at: datetime
    failure_kind: IntegrityFailureKind
    action: IntegrityAction
    message: str
    artifact_path: str | None = None
    expected_hash: str | None = None
    observed_hash: str | None = None
    required_threshold: int | None = None
    valid_key_ids: tuple[str, ...] = ()
    invalid_key_ids: tuple[str, ...] = ()
    root_version: int | None = None
    manifest_version: int | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        failure_kind: IntegrityFailureKind,
        action: IntegrityAction,
        message: str,
        **kwargs: Any,
    ) -> "IntegrityIncident":
        return cls(
            incident_id=uuid4(),
            occurred_at=utcnow(),
            failure_kind=failure_kind,
            action=action,
            message=message,
            **kwargs,
        )


@dataclass(frozen=True, slots=True)
class TrustedVersionState:
    project: str
    highest_root_version: int = 0
    highest_release_manifest_version: int = 0
    highest_protected_manifest_version: int = 0
    accepted_manifest_hashes: Mapping[str, str] = field(default_factory=dict)
    updated_at: str | None = None


def normalize_fingerprint(value: str) -> str:
    normalized = "".join(character for character in value.upper() if character not in " \t\r\n:")
    if len(normalized) < 16 or any(character not in "0123456789ABCDEF" for character in normalized):
        raise ValueError(f"Invalid OpenPGP fingerprint: {value!r}")
    return normalized


def _parse_timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid {label}: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
