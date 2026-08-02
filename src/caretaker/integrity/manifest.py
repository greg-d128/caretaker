from __future__ import annotations

import fnmatch
import hashlib
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from .canonical import assert_canonical_json, canonical_json_bytes, load_json_object, write_canonical_json
from .models import (
    ArtifactDigest,
    ArtifactVerification,
    IntegrityClass,
    IntegrityManifest,
    ManifestType,
    KeyRotationPolicy,
    RolePolicy,
    RootMetadata,
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_sha256(path: str | Path) -> str:
    return sha256_file(path)


def build_manifest(
    *,
    root_dir: str | Path,
    project: str,
    package_version: str,
    manifest_type: ManifestType,
    manifest_version: int,
    root_version: int,
    include: Sequence[str] = ("**/*.py",),
    exclude: Sequence[str] = (),
    integrity_class: IntegrityClass | None = None,
    path_classes: Mapping[str, IntegrityClass] | None = None,
    previous_manifest_sha256: str | None = None,
    minimum_caretaker_version: str | None = None,
    metadata: Mapping[str, str] | None = None,
) -> IntegrityManifest:
    root = Path(root_dir).resolve()
    if manifest_version < 1 or root_version < 1:
        raise ValueError("Manifest and root versions must be positive integers")

    default_class = integrity_class or (
        IntegrityClass.PROTECTED if manifest_type is ManifestType.PROTECTED else IntegrityClass.ORDINARY
    )
    path_classes = path_classes or {}
    artifacts: list[ArtifactDigest] = []

    for path in _selected_files(root, include, exclude):
        relative = path.relative_to(root).as_posix()
        artifact_class = _resolve_integrity_class(relative, path_classes, default_class)
        stat = path.stat()
        artifacts.append(
            ArtifactDigest(
                path=relative,
                sha256=sha256_file(path),
                size_bytes=stat.st_size,
                integrity_class=artifact_class,
            )
        )

    if not artifacts:
        raise ValueError("Manifest would contain no artifacts")

    return IntegrityManifest(
        schema_version=1,
        project=project,
        manifest_type=manifest_type,
        manifest_version=manifest_version,
        root_version=root_version,
        package_version=package_version,
        created_at=datetime.now(timezone.utc).isoformat(),
        artifacts=tuple(artifacts),
        coverage_patterns=tuple(include),
        excluded_patterns=tuple(exclude),
        previous_manifest_sha256=previous_manifest_sha256,
        minimum_caretaker_version=minimum_caretaker_version,
        metadata=dict(metadata or {}),
    )


def write_manifest(path: str | Path, manifest: IntegrityManifest) -> None:
    write_canonical_json(path, manifest_to_dict(manifest))


def load_manifest(path: str | Path, *, require_canonical: bool = True) -> IntegrityManifest:
    value = assert_canonical_json(path) if require_canonical else load_json_object(path)
    artifacts = tuple(
        ArtifactDigest(
            path=str(item["path"]),
            sha256=str(item["sha256"]).lower(),
            size_bytes=int(item["size_bytes"]),
            integrity_class=IntegrityClass(str(item.get("integrity_class", "ordinary"))),
            function_hashes=dict(item.get("function_hashes", {})),
        )
        for item in value.get("artifacts", [])
    )
    return IntegrityManifest(
        schema_version=int(value["schema_version"]),
        project=str(value["project"]),
        manifest_type=ManifestType(str(value["manifest_type"])),
        manifest_version=int(value["manifest_version"]),
        root_version=int(value["root_version"]),
        package_version=str(value["package_version"]),
        created_at=str(value["created_at"]),
        artifacts=artifacts,
        coverage_patterns=tuple(value.get("coverage_patterns", ())),
        excluded_patterns=tuple(value.get("excluded_patterns", ())),
        previous_manifest_sha256=value.get("previous_manifest_sha256"),
        minimum_caretaker_version=value.get("minimum_caretaker_version"),
        metadata=dict(value.get("metadata", {})),
    )


def manifest_to_dict(manifest: IntegrityManifest) -> dict[str, object]:
    return {
        "schema_version": manifest.schema_version,
        "project": manifest.project,
        "manifest_type": manifest.manifest_type.value,
        "manifest_version": manifest.manifest_version,
        "root_version": manifest.root_version,
        "package_version": manifest.package_version,
        "created_at": manifest.created_at,
        "previous_manifest_sha256": manifest.previous_manifest_sha256,
        "minimum_caretaker_version": manifest.minimum_caretaker_version,
        "metadata": dict(manifest.metadata),
        "coverage_patterns": list(manifest.coverage_patterns),
        "excluded_patterns": list(manifest.excluded_patterns),
        "artifacts": [
            {
                "path": item.path,
                "sha256": item.sha256,
                "size_bytes": item.size_bytes,
                "integrity_class": item.integrity_class.value,
                "function_hashes": dict(item.function_hashes),
            }
            for item in manifest.artifacts
        ],
    }


def load_root(path: str | Path, *, require_canonical: bool = True) -> RootMetadata:
    value = assert_canonical_json(path) if require_canonical else load_json_object(path)
    roles = {
        str(name): RolePolicy(
            name=str(name),
            authorized_primary_fingerprints=tuple(role["authorized_primary_fingerprints"]),
            threshold=int(role["threshold"]),
            publication_threshold=(
                int(role["publication_threshold"])
                if role.get("publication_threshold") is not None
                else None
            ),
            runtime_sample_size=(
                int(role["runtime_sample_size"])
                if role.get("runtime_sample_size") is not None
                else None
            ),
        )
        for name, role in dict(value["roles"]).items()
    }
    rotation_value = value.get("rotation_policy")
    rotation_policy = None
    if rotation_value is not None:
        rotation_policy = KeyRotationPolicy(
            epoch=str(rotation_value["epoch"]),
            interval_days=int(rotation_value.get("interval_days", 730)),
            sequence=tuple(rotation_value.get("sequence", ("A", "B", "C"))),
            generation=int(rotation_value.get("generation", 0)),
            warning_days=int(rotation_value.get("warning_days", 90)),
        )
    return RootMetadata(
        schema_version=int(value["schema_version"]),
        project=str(value["project"]),
        root_version=int(value["root_version"]),
        roles=roles,
        protected_paths=tuple(value.get("protected_paths", ())),
        sealed_paths=tuple(value.get("sealed_paths", ())),
        key_slots=dict(value.get("key_slots", {})),
        rotation_policy=rotation_policy,
        created_at=value.get("created_at"),
        expires_at=value.get("expires_at"),
        metadata=dict(value.get("metadata", {})),
    )


def write_root(path: str | Path, root: RootMetadata) -> None:
    write_canonical_json(
        path,
        {
            "schema_version": root.schema_version,
            "project": root.project,
            "root_version": root.root_version,
            "created_at": root.created_at,
            "expires_at": root.expires_at,
            "metadata": dict(root.metadata),
            "protected_paths": list(root.protected_paths),
            "sealed_paths": list(root.sealed_paths),
            "key_slots": dict(root.key_slots),
            "rotation_policy": (
                {
                    "epoch": root.rotation_policy.epoch,
                    "interval_days": root.rotation_policy.interval_days,
                    "sequence": list(root.rotation_policy.sequence),
                    "generation": root.rotation_policy.generation,
                    "warning_days": root.rotation_policy.warning_days,
                }
                if root.rotation_policy is not None
                else None
            ),
            "roles": {
                name: {
                    "authorized_primary_fingerprints": list(role.authorized_primary_fingerprints),
                    "threshold": role.threshold,
                    "publication_threshold": role.publication_threshold,
                    "runtime_sample_size": role.runtime_sample_size,
                }
                for name, role in sorted(root.roles.items())
            },
        },
    )


def verify_artifacts(root_dir: str | Path, manifest: IntegrityManifest) -> tuple[ArtifactVerification, ...]:
    root = Path(root_dir).resolve()
    results: list[ArtifactVerification] = []
    for artifact in manifest.artifacts:
        try:
            path = _safe_artifact_path(root, artifact.path)
        except ValueError as exc:
            results.append(
                ArtifactVerification(
                    path=artifact.path,
                    expected_sha256=artifact.sha256,
                    observed_sha256=None,
                    expected_size_bytes=artifact.size_bytes,
                    observed_size_bytes=None,
                    valid=False,
                    error=str(exc),
                )
            )
            continue
        if not path.is_file():
            results.append(
                ArtifactVerification(
                    path=artifact.path,
                    expected_sha256=artifact.sha256,
                    observed_sha256=None,
                    expected_size_bytes=artifact.size_bytes,
                    observed_size_bytes=None,
                    valid=False,
                    error="artifact does not exist or is not a regular file",
                )
            )
            continue
        observed_size = path.stat().st_size
        observed_hash = sha256_file(path)
        valid = observed_size == artifact.size_bytes and observed_hash == artifact.sha256
        results.append(
            ArtifactVerification(
                path=artifact.path,
                expected_sha256=artifact.sha256,
                observed_sha256=observed_hash,
                expected_size_bytes=artifact.size_bytes,
                observed_size_bytes=observed_size,
                valid=valid,
                error=None if valid else "artifact size or SHA-256 digest differs",
            )
        )
    return tuple(results)


def sha256sum_lines(manifest: IntegrityManifest) -> str:
    """Return GNU sha256sum-compatible lines for independent verification."""
    for artifact in manifest.artifacts:
        if "\n" in artifact.path or "\r" in artifact.path:
            raise ValueError("Artifact paths containing newlines cannot be exported to sha256sum format")
    return "".join(f"{artifact.sha256}  {artifact.path}\n" for artifact in manifest.artifacts)


def expected_integrity_class(root: RootMetadata, relative_path: str) -> IntegrityClass:
    selected = IntegrityClass.ORDINARY
    if any(fnmatch.fnmatch(relative_path, pattern) for pattern in root.protected_paths):
        selected = IntegrityClass.PROTECTED
    if any(fnmatch.fnmatch(relative_path, pattern) for pattern in root.sealed_paths):
        selected = IntegrityClass.SEALED
    return selected


def validate_manifest_scope(
    root: RootMetadata,
    manifest: IntegrityManifest,
    artifact_root: str | Path,
) -> tuple[str, ...]:
    """Enforce root-authorized protected/sealed classification and coverage."""

    errors: list[str] = []
    observed_paths = {artifact.path for artifact in manifest.artifacts}
    for artifact in manifest.artifacts:
        expected = expected_integrity_class(root, artifact.path)
        if artifact.integrity_class is not expected:
            errors.append(
                f"Artifact {artifact.path!r} is classified {artifact.integrity_class.value!r}; "
                f"the signed root requires {expected.value!r}"
            )
        if manifest.manifest_type is ManifestType.RELEASE and expected is not IntegrityClass.ORDINARY:
            errors.append(
                f"Release manifest cannot authorize protected or sealed artifact {artifact.path!r}"
            )
        if manifest.manifest_type is ManifestType.PROTECTED and expected is IntegrityClass.ORDINARY:
            errors.append(
                f"Protected manifest contains ordinary artifact {artifact.path!r}"
            )

    root_dir = Path(artifact_root).resolve()
    if manifest.coverage_patterns:
        covered: set[str] = set()
        for pattern in manifest.coverage_patterns:
            for path in root_dir.glob(pattern):
                if not path.is_file():
                    continue
                resolved = path.resolve()
                try:
                    relative = resolved.relative_to(root_dir).as_posix()
                except ValueError:
                    errors.append(f"Covered path resolves outside artifact root: {path}")
                    continue
                if any(fnmatch.fnmatch(relative, pattern) for pattern in manifest.excluded_patterns):
                    continue
                covered.add(relative)
        unexpected = sorted(covered - observed_paths)
        if unexpected:
            errors.append("Manifest omits covered artifacts: " + ", ".join(unexpected))

    if manifest.manifest_type is ManifestType.PROTECTED:
        required: set[str] = set()
        for pattern in (*root.protected_paths, *root.sealed_paths):
            for path in root_dir.glob(pattern):
                if path.is_file():
                    resolved = path.resolve()
                    try:
                        required.add(resolved.relative_to(root_dir).as_posix())
                    except ValueError:
                        errors.append(f"Protected path resolves outside artifact root: {path}")
        missing = sorted(required - observed_paths)
        if missing:
            errors.append(
                "Protected manifest omits root-protected artifacts: " + ", ".join(missing)
            )
    return tuple(errors)


def _selected_files(root: Path, include: Sequence[str], exclude: Sequence[str]) -> Iterable[Path]:
    candidates: set[Path] = set()
    for pattern in include:
        for path in root.glob(pattern):
            if path.is_file():
                candidates.add(path.resolve())
    for path in sorted(candidates, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(relative, pattern) for pattern in exclude):
            continue
        yield path


def _resolve_integrity_class(
    relative_path: str,
    classes: Mapping[str, IntegrityClass],
    default: IntegrityClass,
) -> IntegrityClass:
    selected = default
    for pattern, value in classes.items():
        if fnmatch.fnmatch(relative_path, pattern):
            selected = value
    return selected


def _safe_artifact_path(root: Path, relative_path: str) -> Path:
    if not relative_path or Path(relative_path).is_absolute():
        raise ValueError(f"Invalid artifact path: {relative_path!r}")
    path = (root / relative_path).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Artifact path escapes verification root: {relative_path!r}") from exc
    return path
