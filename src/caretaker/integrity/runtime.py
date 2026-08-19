from __future__ import annotations

import hashlib
import importlib
import inspect
import marshal
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from collections.abc import Mapping, Sequence
from typing import Callable

from .gpg import GPGVerifier
from .manifest import load_manifest, load_root, manifest_sha256, sha256_file
from .models import IntegrityClass, IntegrityManifest
from .models import IntegrityVerification, SignatureVerificationMode
from .verifier import IntegrityVerifier


@dataclass(frozen=True, slots=True)
class RuntimeFunctionFingerprint:
    module_name: str
    qualified_name: str
    source_sha256: str | None
    code_sha256: str


class RuntimeIntegrityMonitor:
    """Verify signed files and detect later in-memory implementation changes.

    This is a tamper-evidence mechanism, not a security boundary against a
    privileged attacker capable of replacing the interpreter or monitor.
    """

    def __init__(self, manifest: IntegrityManifest, artifact_root: str | Path) -> None:
        self.manifest = manifest
        self.artifact_root = Path(artifact_root).resolve()
        self._accepted_functions: dict[tuple[str, str], RuntimeFunctionFingerprint] = {}

    def verify_loaded_module(self, module: ModuleType) -> bool:
        file_name = getattr(module, "__file__", None)
        if not file_name:
            return False
        path = Path(file_name).resolve()
        try:
            relative = path.relative_to(self.artifact_root).as_posix()
        except ValueError:
            return False
        artifact = next((item for item in self.manifest.artifacts if item.path == relative), None)
        if artifact is None or not path.is_file():
            return False
        return path.stat().st_size == artifact.size_bytes and sha256_file(path) == artifact.sha256

    def accept_function(self, function: Callable[..., object]) -> RuntimeFunctionFingerprint:
        fingerprint = fingerprint_function(function)
        self._accepted_functions[(fingerprint.module_name, fingerprint.qualified_name)] = fingerprint
        return fingerprint

    def verify_function(self, function: Callable[..., object]) -> bool:
        current = fingerprint_function(function)
        expected = self._accepted_functions.get((current.module_name, current.qualified_name))
        return expected == current


def verify_release_publication(
    publication_directory: str | Path,
    *,
    trusted_primary_fingerprints: Sequence[str],
    artifact_root: str | Path | None = None,
    verification_mode: SignatureVerificationMode = SignatureVerificationMode.FULL_PUBLICATION,
) -> dict[str, object]:
    """Verify the conventional root and both release manifests for runtime status."""

    directory = Path(publication_directory).resolve()
    root_path = directory / "root.json"
    root = load_root(root_path)
    trusted = tuple(str(item).upper() for item in trusted_primary_fingerprints)
    if not trusted:
        raise ValueError("Runtime release verification requires independently trusted fingerprints")
    key_directory = directory / "release-keys"
    if not key_directory.is_dir():
        key_directory = directory
    slots = tuple(sorted(root.key_slots))
    if slots != ("A", "B", "C"):
        raise ValueError("Runtime publication verification requires root key slots A, B, and C")
    public_keys = [key_directory / f"caretaker-key-{slot.lower()}.asc" for slot in slots]
    root_signatures = [directory / f"root.json.key-{slot.lower()}.asc" for slot in slots]
    verifier = IntegrityVerifier(gpg=GPGVerifier())
    root_result = verifier.verify_initial_root(
        root_path=root_path,
        signature_paths=root_signatures,
        public_key_paths=public_keys,
        trusted_primary_fingerprints=trusted,
        threshold=root.roles["root"].threshold,
    )
    manifests: dict[str, object] = {}
    all_trusted = root_result.satisfied
    for name in ("release-manifest.json", "protected-manifest.json"):
        manifest_path = directory / name
        result = verifier.verify_manifest(
            root_path=root_path,
            manifest_path=manifest_path,
            signature_paths=[directory / f"{name}.key-{slot.lower()}.asc" for slot in slots],
            public_key_paths=public_keys,
            artifact_root=artifact_root or directory,
            root_trusted=root_result.satisfied,
            verification_mode=verification_mode,
        )
        invalid_artifacts = sum(not item.valid for item in result.artifact_results)
        manifests[name] = {
            "trusted": result.trusted,
            "manifest_sha256": manifest_sha256(manifest_path),
            "valid_signers": len(result.signature_verification.valid_primary_fingerprints),
            "required_signers": result.signature_verification.required_threshold,
            "invalid_artifacts": invalid_artifacts,
            "errors": list(result.errors),
            "warnings": list(result.warnings),
        }
        all_trusted &= result.trusted
    return {
        "status": "TRUSTED" if all_trusted else "FAILED",
        "configured": True,
        "root_anchored": root_result.satisfied,
        "root_errors": list(root_result.errors),
        "root_version": root.root_version,
        "verification_mode": verification_mode.value,
        "publication_directory": str(directory),
        "artifact_root": str(Path(artifact_root or directory).resolve()),
        "manifests": manifests,
    }


def verify_installed_publication(
    *,
    trusted_primary_fingerprints: Sequence[str] | None = None,
    package_root: str | Path | None = None,
    publication_directory: str | Path | None = None,
    verification_mode: SignatureVerificationMode = SignatureVerificationMode.FULL_PUBLICATION,
) -> dict[str, object]:
    """Verify the signed manifests shipped with an installed Caretaker wheel.

    Repository-local fingerprints are a convenience default, not an independent
    initial trust channel. High-assurance callers should supply fingerprints
    obtained outside the installed distribution.
    """

    if package_root is None:
        import caretaker

        package = Path(caretaker.__file__).resolve().parent
    else:
        package = Path(package_root).resolve()
    publication = (
        Path(publication_directory).resolve()
        if publication_directory is not None
        else package / "_publication"
    )
    root = load_root(publication / "root.json")
    trusted = tuple(trusted_primary_fingerprints or root.key_slots.values())
    if not trusted:
        raise ValueError("Installed verification requires trusted primary fingerprints")
    slots = tuple(sorted(root.key_slots))
    keys = [publication / "release-keys" / f"caretaker-key-{slot.lower()}.asc" for slot in slots]
    verifier = IntegrityVerifier(gpg=GPGVerifier())
    root_result = verifier.verify_initial_root(
        root_path=publication / "root.json",
        signature_paths=[publication / f"root.json.key-{slot.lower()}.asc" for slot in slots],
        public_key_paths=keys,
        trusted_primary_fingerprints=trusted,
        threshold=root.roles["root"].threshold,
    )
    manifests: dict[str, object] = {}
    all_trusted = root_result.satisfied
    for filename in ("wheel-release-manifest.json", "wheel-protected-manifest.json"):
        manifest = load_manifest(publication / filename)
        version_errors: list[str] = []
        try:
            import caretaker

            installed_version = caretaker.__version__
        except (ImportError, AttributeError):
            installed_version = None
        if installed_version and manifest.package_version != installed_version:
            version_errors.append(
                f"Manifest package version {manifest.package_version!r} does not match "
                f"installed Caretaker {installed_version!r}"
            )
        result = verifier.verify_manifest(
            root_path=publication / "root.json",
            manifest_path=publication / filename,
            signature_paths=[publication / f"{filename}.key-{slot.lower()}.asc" for slot in slots],
            public_key_paths=keys,
            artifact_root=package.parent,
            root_trusted=root_result.satisfied,
            verification_mode=verification_mode,
        )
        manifest_trusted = result.trusted and not version_errors
        manifests[filename] = {
            "trusted": manifest_trusted,
            "manifest_sha256": result.manifest_sha256,
            "valid_signers": len(result.signature_verification.valid_primary_fingerprints),
            "required_signers": result.signature_verification.required_threshold,
            "invalid_artifacts": sum(not item.valid for item in result.artifact_results),
            "errors": [*result.errors, *version_errors],
            "warnings": list(result.warnings),
        }
        all_trusted &= manifest_trusted
    return {
        "status": "TRUSTED" if all_trusted else "FAILED",
        "configured": True,
        "root_anchored": root_result.satisfied,
        "root_errors": list(root_result.errors),
        "root_version": root.root_version,
        "verification_mode": verification_mode.value,
        "publication_directory": str(publication),
        "artifact_root": str(package.parent),
        "used_embedded_fingerprint_defaults": trusted_primary_fingerprints is None,
        "manifests": manifests,
    }


def bootstrap_integrity(
    *,
    verifier: IntegrityVerifier,
    root_path: str | Path,
    root_signature_paths: Sequence[str | Path] | Mapping[str, str | Path],
    trusted_primary_fingerprints: Sequence[str],
    manifest_path: str | Path,
    signature_paths: Sequence[str | Path] | Mapping[str, str | Path],
    public_key_paths: Sequence[str | Path],
    artifact_root: str | Path,
    root_threshold: int = 2,
    accept_state: bool = False,
    verification_mode: SignatureVerificationMode = SignatureVerificationMode.AUTHORIZATION_THRESHOLD,
) -> IntegrityVerification:
    """Verify the configured Caretaker installation before enabling repair.

    Applications should call this before constructing or installing the repair
    engine. The bootstrap verifier itself must still be anchored externally by
    trusted public-key fingerprints or a previously accepted root.
    """

    root_result = verifier.verify_initial_root(
        root_path=root_path,
        signature_paths=root_signature_paths,
        public_key_paths=public_key_paths,
        trusted_primary_fingerprints=trusted_primary_fingerprints,
        threshold=root_threshold,
    )
    if not root_result.satisfied:
        raise RuntimeError("Caretaker root metadata did not satisfy the external trust threshold")
    if accept_state and verifier.state_store is not None:
        verifier.accept_root(root_path)

    result = verifier.verify_manifest(
        root_path=root_path,
        manifest_path=manifest_path,
        signature_paths=signature_paths,
        public_key_paths=public_key_paths,
        artifact_root=artifact_root,
        accept_state=accept_state,
        root_trusted=True,
        verification_mode=verification_mode,
    )
    verifier.require_trusted(result)
    return result


def fingerprint_function(function: Callable[..., object]) -> RuntimeFunctionFingerprint:
    try:
        source = inspect.getsource(function).encode("utf-8")
    except (OSError, TypeError):
        source_hash = None
    else:
        source_hash = hashlib.sha256(source).hexdigest()
    code_hash = hashlib.sha256(marshal.dumps(function.__code__)).hexdigest()
    return RuntimeFunctionFingerprint(
        module_name=function.__module__,
        qualified_name=function.__qualname__,
        source_sha256=source_hash,
        code_sha256=code_hash,
    )
