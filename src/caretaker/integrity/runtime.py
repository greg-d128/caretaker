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

from .manifest import load_manifest, sha256_file
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
    verification_mode: SignatureVerificationMode = SignatureVerificationMode.RANDOMIZED_RUNTIME,
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
