#!/usr/bin/env python3
"""Generate unsigned manifests for the exact paths installed by the wheel."""

from __future__ import annotations

import argparse
import shutil
import tempfile
from pathlib import Path

from caretaker.integrity import (
    IntegrityClass,
    ManifestType,
    build_manifest,
    load_root,
    write_manifest,
)


PRODUCTION_PROFILES = (
    "caretaker-observe-only-v1.json",
    "caretaker-balanced-v1.json",
    "caretaker-high-assurance-v1.json",
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--repository", type=Path, default=Path("."))
    result.add_argument("--package-version", required=True)
    result.add_argument("--manifest-version", type=int, required=True)
    result.add_argument("--force", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    repository = args.repository.resolve()
    root = load_root(repository / "root.json")
    outputs = (
        repository / "wheel-release-manifest.json",
        repository / "wheel-protected-manifest.json",
    )
    if not args.force and any(path.exists() for path in outputs):
        raise SystemExit("wheel manifests exist; pass --force only after deciding to replace them")
    for profile in PRODUCTION_PROFILES:
        for slot in "abc":
            signature = repository / "profiles" / f"{profile}.key-{slot}.asc"
            if not signature.is_file():
                raise SystemExit(
                    f"signed profile input is missing: {signature}; sign profiles before wheel manifests"
                )

    with tempfile.TemporaryDirectory(prefix="caretaker-wheel-manifest-") as temporary:
        stage = Path(temporary)
        package = stage / "caretaker"
        shutil.copytree(
            repository / "src" / "caretaker",
            package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "_publication"),
        )
        shutil.copytree(repository / "profiles", package / "profiles")
        mapped_protected = tuple(_wheel_pattern(item) for item in root.protected_paths)
        mapped_sealed = tuple(_wheel_pattern(item) for item in root.sealed_paths)
        path_classes = {item: IntegrityClass.PROTECTED for item in mapped_protected}
        path_classes.update({item: IntegrityClass.SEALED for item in mapped_sealed})
        common = dict(
            root_dir=stage,
            project=root.project,
            package_version=args.package_version,
            manifest_version=args.manifest_version,
            root_version=root.root_version,
            path_classes=path_classes,
            metadata={"artifact_layout": "wheel"},
        )
        release = build_manifest(
            **common,
            manifest_type=ManifestType.RELEASE,
            include=("caretaker/**/*.py", "caretaker/profiles/*"),
            exclude=(*mapped_protected, *mapped_sealed),
        )
        protected = build_manifest(
            **common,
            manifest_type=ManifestType.PROTECTED,
            include=(*mapped_protected, *mapped_sealed),
        )
    write_manifest(outputs[0], release)
    write_manifest(outputs[1], protected)
    for output in outputs:
        print(f"Wrote unsigned installed-layout manifest: {output}")
    print("Sign both manifests with slots A, B, and C before building the release wheel.")
    return 0


def _wheel_pattern(pattern: str) -> str:
    return pattern.removeprefix("src/") if pattern.startswith("src/caretaker/") else pattern


if __name__ == "__main__":
    raise SystemExit(main())
