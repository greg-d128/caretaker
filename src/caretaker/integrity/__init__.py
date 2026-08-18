"""Public-key-only integrity verification for Caretaker releases.

This package intentionally contains no private-key handling or signing API.
Release signatures are produced by a separate offline signing procedure.
"""

from .gpg import GPGUnavailableError, GPGVerifier
from .instructions import render_gpg_verification_commands
from .manifest import (
    build_manifest,
    load_manifest,
    load_root,
    manifest_sha256,
    sha256_file,
    sha256sum_lines,
    validate_manifest_scope,
    verify_artifacts,
    write_manifest,
    write_root,
)
from .models import (
    ArtifactDigest,
    ArtifactVerification,
    IntegrityAction,
    IntegrityClass,
    IntegrityFailureKind,
    IntegrityIncident,
    IntegrityManifest,
    IntegrityVerification,
    KeyRotationPolicy,
    ManifestType,
    RotationStatus,
    RolePolicy,
    RootMetadata,
    SignatureVerification,
    SignatureVerificationMode,
    ThresholdVerification,
    TrustedVersionState,
    normalize_fingerprint,
)
from .runtime import (
    RuntimeIntegrityMonitor,
    bootstrap_integrity,
    fingerprint_function,
    verify_release_publication,
)
from .state import IntegrityRollbackError, IntegrityStateStore
from .verifier import IntegrityVerificationError, IntegrityVerifier

__all__ = [
    "ArtifactDigest",
    "ArtifactVerification",
    "GPGUnavailableError",
    "GPGVerifier",
    "IntegrityAction",
    "IntegrityClass",
    "IntegrityFailureKind",
    "IntegrityIncident",
    "IntegrityManifest",
    "IntegrityRollbackError",
    "IntegrityStateStore",
    "IntegrityVerification",
    "IntegrityVerificationError",
    "IntegrityVerifier",
    "KeyRotationPolicy",
    "ManifestType",
    "RotationStatus",
    "RolePolicy",
    "RootMetadata",
    "RuntimeIntegrityMonitor",
    "SignatureVerification",
    "SignatureVerificationMode",
    "ThresholdVerification",
    "TrustedVersionState",
    "bootstrap_integrity",
    "build_manifest",
    "fingerprint_function",
    "verify_release_publication",
    "load_manifest",
    "load_root",
    "manifest_sha256",
    "normalize_fingerprint",
    "render_gpg_verification_commands",
    "sha256_file",
    "sha256sum_lines",
    "validate_manifest_scope",
    "verify_artifacts",
    "write_manifest",
    "write_root",
]
