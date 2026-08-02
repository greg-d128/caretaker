from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Mapping, Sequence
from typing import Protocol

from .gpg import GPGVerifier
from .manifest import (
    load_manifest,
    load_root,
    manifest_sha256,
    sha256_file,
    validate_manifest_scope,
    verify_artifacts,
)
from .models import (
    IntegrityAction,
    IntegrityFailureKind,
    IntegrityIncident,
    IntegrityVerification,
    ManifestType,
    RootMetadata,
    RolePolicy,
    SignatureVerificationMode,
    ThresholdVerification,
    normalize_fingerprint,
)
from .state import IntegrityRollbackError, IntegrityStateStore


logger = logging.getLogger(__name__)


class IntegrityRecordStore(Protocol):
    def record_integrity_verification(self, record: IntegrityVerification) -> None: ...
    def record_integrity_incident(self, record: IntegrityIncident) -> None: ...


class IntegrityVerificationError(RuntimeError):
    def __init__(self, message: str, verification: IntegrityVerification | None = None) -> None:
        super().__init__(message)
        self.verification = verification


class IntegrityVerifier:
    def __init__(
        self,
        *,
        gpg: GPGVerifier | None = None,
        store: IntegrityRecordStore | None = None,
        state_store: IntegrityStateStore | None = None,
    ) -> None:
        self.gpg = gpg or GPGVerifier()
        self.store = store
        self.state_store = state_store

    def verify_manifest(
        self,
        *,
        root_path: str | Path,
        manifest_path: str | Path,
        signature_paths: Sequence[str | Path] | Mapping[str, str | Path],
        public_key_paths: Sequence[str | Path],
        artifact_root: str | Path,
        accept_state: bool = False,
        root_trusted: bool = False,
        verification_mode: SignatureVerificationMode = SignatureVerificationMode.AUTHORIZATION_THRESHOLD,
    ) -> IntegrityVerification:
        root = load_root(root_path)
        manifest = load_manifest(manifest_path)
        errors: list[str] = []
        warnings: list[str] = []
        expiry_error = _root_expiry_error(root)
        if expiry_error:
            errors.append(expiry_error)
        if manifest.project != root.project:
            errors.append("Manifest project does not match root metadata")
        if manifest.root_version != root.root_version:
            errors.append(
                f"Manifest requires root version {manifest.root_version}, but root metadata is version {root.root_version}"
            )

        role_name = _manifest_role(manifest.manifest_type)
        role = root.role(role_name)
        signature_result = self.gpg.verify_threshold(
            signed_path=manifest_path,
            signature_paths=signature_paths,
            public_key_paths=public_key_paths,
            role=role,
            mode=verification_mode,
        )
        errors.extend(validate_manifest_scope(root, manifest, artifact_root))
        artifact_results = verify_artifacts(artifact_root, manifest)
        digest = manifest_sha256(manifest_path)
        root_digest = sha256_file(root_path)
        root_anchored = root_trusted

        if self.state_store is not None:
            state = self.state_store.load(root.project)
            accepted_root_hash = state.accepted_manifest_hashes.get("root")
            if state.highest_root_version == root.root_version and accepted_root_hash == root_digest:
                root_anchored = True
            elif state.highest_root_version == root.root_version and accepted_root_hash:
                errors.append("Root metadata hash differs from the accepted root at the same version")
            try:
                self.state_store.assert_not_rollback(
                    state=state,
                    root_version=root.root_version,
                    manifest_type=manifest.manifest_type,
                    manifest_version=manifest.manifest_version,
                )
            except IntegrityRollbackError as exc:
                errors.append(str(exc))

        if not root_anchored:
            errors.append(
                "Root metadata is not externally anchored or present in accepted trusted state"
            )

        rotation = root.rotation_status()
        if rotation is not None and rotation.warning:
            if rotation.overdue:
                warnings.append(
                    f"Scheduled rotation for key slot {rotation.next_slot} is overdue; "
                    f"due at {rotation.next_due_at.isoformat()}"
                )
            else:
                warnings.append(
                    f"Scheduled rotation for key slot {rotation.next_slot} is due at "
                    f"{rotation.next_due_at.isoformat()}"
                )

        verification = IntegrityVerification.create(
            project=root.project,
            root_version=root.root_version,
            manifest_version=manifest.manifest_version,
            manifest_type=manifest.manifest_type,
            manifest_path=manifest_path,
            manifest_sha256=digest,
            signature_verification=signature_result,
            artifact_results=artifact_results,
            root_anchored=root_anchored,
            errors=tuple(errors),
            warnings=tuple(warnings),
        )
        self._record_verification(verification)

        if verification.trusted and accept_state and self.state_store is not None:
            state = self.state_store.load(root.project)
            self.state_store.accept(
                state=state,
                root_version=root.root_version,
                manifest_type=manifest.manifest_type,
                manifest_version=manifest.manifest_version,
                manifest_hash=digest,
            )
        if not verification.trusted:
            self._record_failure(verification)
        return verification

    def verify_initial_root(
        self,
        *,
        root_path: str | Path,
        signature_paths: Sequence[str | Path] | Mapping[str, str | Path],
        public_key_paths: Sequence[str | Path],
        trusted_primary_fingerprints: Sequence[str],
        threshold: int = 2,
    ) -> ThresholdVerification:
        root = load_root(root_path)
        expiry_error = _root_expiry_error(root)
        if expiry_error:
            raise IntegrityVerificationError(expiry_error)
        trusted_set = {normalize_fingerprint(item) for item in trusted_primary_fingerprints}
        root_set = set(root.role("root").authorized_primary_fingerprints)
        if trusted_set != root_set:
            raise IntegrityVerificationError(
                "Externally trusted fingerprints do not exactly match the root role identities"
            )
        bootstrap_role = RolePolicy(
            name="bootstrap-root",
            authorized_primary_fingerprints=tuple(trusted_primary_fingerprints),
            threshold=threshold,
        )
        result = self.gpg.verify_threshold(
            signed_path=root_path,
            signature_paths=signature_paths,
            public_key_paths=public_key_paths,
            role=bootstrap_role,
        )
        if not result.satisfied:
            self._record_integrity_incident(
                IntegrityIncident.create(
                    failure_kind=IntegrityFailureKind.ROOT_CHAIN_BROKEN,
                    action=IntegrityAction.TERMINATE_STARTUP,
                    message="Initial root metadata did not satisfy the externally trusted threshold",
                    required_threshold=threshold,
                    valid_key_ids=result.valid_primary_fingerprints,
                    root_version=root.root_version,
                    details={"errors": list(result.errors)},
                )
            )
        return result

    def verify_root_transition(
        self,
        *,
        old_root_path: str | Path,
        new_root_path: str | Path,
        new_root_signature_paths: Sequence[str | Path] | Mapping[str, str | Path],
        public_key_paths: Sequence[str | Path],
    ) -> tuple[ThresholdVerification, ThresholdVerification]:
        old_root = load_root(old_root_path)
        new_root = load_root(new_root_path)
        for candidate in (old_root, new_root):
            expiry_error = _root_expiry_error(candidate)
            if expiry_error:
                raise IntegrityVerificationError(expiry_error)
        if old_root.project != new_root.project:
            raise IntegrityVerificationError("Root transition changes project identity")
        if new_root.root_version != old_root.root_version + 1:
            raise IntegrityVerificationError(
                f"Root transition must be sequential: {old_root.root_version} -> {new_root.root_version}"
            )
        old_result = self.gpg.verify_threshold(
            signed_path=new_root_path,
            signature_paths=new_root_signature_paths,
            public_key_paths=public_key_paths,
            role=old_root.role("root"),
        )
        new_result = self.gpg.verify_threshold(
            signed_path=new_root_path,
            signature_paths=new_root_signature_paths,
            public_key_paths=public_key_paths,
            role=new_root.role("root"),
        )
        if not old_result.satisfied or not new_result.satisfied:
            self._record_integrity_incident(
                IntegrityIncident.create(
                    failure_kind=IntegrityFailureKind.ROOT_CHAIN_BROKEN,
                    action=IntegrityAction.TERMINATE_STARTUP,
                    message="Proposed root did not satisfy both old-root and new-root thresholds",
                    required_threshold=max(old_result.required_threshold, new_result.required_threshold),
                    valid_key_ids=tuple(
                        sorted(set(old_result.valid_primary_fingerprints) | set(new_result.valid_primary_fingerprints))
                    ),
                    root_version=new_root.root_version,
                    details={
                        "old_errors": list(old_result.errors),
                        "new_errors": list(new_result.errors),
                    },
                )
            )
        return old_result, new_result

    def accept_root(self, root_path: str | Path) -> None:
        if self.state_store is None:
            raise ValueError("No integrity state store is configured")
        root = load_root(root_path)
        state = self.state_store.load(root.project)
        self.state_store.accept(
            state=state,
            root_version=root.root_version,
            manifest_type=ManifestType.ROOT,
            manifest_version=root.root_version,
            manifest_hash=sha256_file(root_path),
        )

    def require_trusted(self, verification: IntegrityVerification) -> None:
        if not verification.trusted:
            raise IntegrityVerificationError(
                "Caretaker integrity verification failed; see the attached verification record",
                verification=verification,
            )

    def _record_verification(self, verification: IntegrityVerification) -> None:
        if self.store is not None:
            try:
                self.store.record_integrity_verification(verification)
            except Exception:
                logger.exception("Failed to persist integrity verification")

    def _record_integrity_incident(self, incident: IntegrityIncident) -> None:
        if self.store is not None:
            try:
                self.store.record_integrity_incident(incident)
            except Exception:
                logger.exception("Failed to persist integrity incident")

    def _record_failure(self, verification: IntegrityVerification) -> None:
        invalid_artifacts = [item for item in verification.artifact_results if not item.valid]
        if not verification.root_anchored:
            incident = IntegrityIncident.create(
                failure_kind=IntegrityFailureKind.ROOT_CHAIN_BROKEN,
                action=_failure_action(verification.manifest_type),
                message="Manifest was evaluated against an unanchored root",
                required_threshold=verification.signature_verification.required_threshold,
                valid_key_ids=verification.signature_verification.valid_primary_fingerprints,
                root_version=verification.root_version,
                manifest_version=verification.manifest_version,
                details={"errors": list(verification.errors)},
            )
        elif invalid_artifacts:
            first = invalid_artifacts[0]
            incident = IntegrityIncident.create(
                failure_kind=IntegrityFailureKind.HASH_MISMATCH,
                action=_failure_action(verification.manifest_type),
                message=f"Artifact integrity check failed for {first.path}",
                artifact_path=first.path,
                expected_hash=first.expected_sha256,
                observed_hash=first.observed_sha256,
                required_threshold=verification.signature_verification.required_threshold,
                valid_key_ids=verification.signature_verification.valid_primary_fingerprints,
                root_version=verification.root_version,
                manifest_version=verification.manifest_version,
            )
        elif any("older than trusted" in error for error in verification.errors):
            incident = IntegrityIncident.create(
                failure_kind=IntegrityFailureKind.MANIFEST_ROLLBACK,
                action=_failure_action(verification.manifest_type),
                message="Manifest or root rollback was rejected",
                required_threshold=verification.signature_verification.required_threshold,
                valid_key_ids=verification.signature_verification.valid_primary_fingerprints,
                root_version=verification.root_version,
                manifest_version=verification.manifest_version,
                details={"errors": list(verification.errors)},
            )
        else:
            incident = IntegrityIncident.create(
                failure_kind=IntegrityFailureKind.INSUFFICIENT_SIGNATURES,
                action=_failure_action(verification.manifest_type),
                message="Manifest signature threshold or integrity policy was not satisfied",
                required_threshold=verification.signature_verification.required_threshold,
                valid_key_ids=verification.signature_verification.valid_primary_fingerprints,
                root_version=verification.root_version,
                manifest_version=verification.manifest_version,
                details={"errors": list(verification.signature_verification.errors) + list(verification.errors)},
            )
        self._record_integrity_incident(incident)


def _manifest_role(manifest_type: ManifestType) -> str:
    if manifest_type is ManifestType.RELEASE:
        return "release"
    if manifest_type is ManifestType.PROTECTED:
        return "protected"
    return "root"


def _failure_action(manifest_type: ManifestType) -> IntegrityAction:
    if manifest_type in {ManifestType.PROTECTED, ManifestType.ROOT}:
        return IntegrityAction.TERMINATE_STARTUP
    return IntegrityAction.REFUSE_IMPORT


def _root_expiry_error(root: RootMetadata) -> str | None:
    if not root.expires_at:
        return None
    try:
        expires = datetime.fromisoformat(root.expires_at.replace("Z", "+00:00"))
    except ValueError:
        return "Root metadata contains an invalid expires_at timestamp"
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) >= expires.astimezone(timezone.utc):
        return f"Root metadata version {root.root_version} expired at {root.expires_at}"
    return None
