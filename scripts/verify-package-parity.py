#!/usr/bin/env python3
"""Verify that a source distribution and wheel carry the same release payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
import zipfile
from pathlib import Path


def _metadata_version(text: str) -> str:
    match = re.search(r"^Version:\s*(\S+)\s*$", text, re.MULTILINE)
    if match is None:
        raise ValueError("package metadata has no Version field")
    return match.group(1)


def _sdist_payload(path: Path) -> tuple[str, dict[str, str]]:
    with tarfile.open(path, "r:gz") as archive:
        members = {item.name: item for item in archive.getmembers() if item.isfile()}
        metadata = next((name for name in members if name.endswith("/PKG-INFO")), None)
        if metadata is None:
            raise ValueError("source distribution has no PKG-INFO")
        version = _metadata_version(archive.extractfile(members[metadata]).read().decode("utf-8"))
        payload: dict[str, str] = {}
        for name, member in members.items():
            if "/src/caretaker/" in name:
                relative = "caretaker/" + name.split("/src/caretaker/", 1)[1]
            elif "/profiles/" in name:
                relative = "caretaker/profiles/" + name.split("/profiles/", 1)[1]
            else:
                relative = ""
            if relative.startswith("caretaker/") and (
                relative.endswith(".py") or relative.startswith("caretaker/profiles/")
            ):
                payload[relative] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
    return version, payload


def _wheel_payload(path: Path) -> tuple[str, dict[str, str]]:
    with zipfile.ZipFile(path) as archive:
        metadata_name = next((name for name in archive.namelist() if name.endswith(".dist-info/METADATA")), None)
        if metadata_name is None:
            raise ValueError("wheel has no METADATA")
        version = _metadata_version(archive.read(metadata_name).decode("utf-8"))
        payload = {
            name: hashlib.sha256(archive.read(name)).hexdigest()
            for name in archive.namelist()
            if name.startswith("caretaker/")
            and (name.endswith(".py") or name.startswith("caretaker/profiles/"))
        }
    return version, payload


def _source_payload(root: Path) -> dict[str, str]:
    payload: dict[str, str] = {}
    source = root / "src" / "caretaker"
    if not source.is_dir():
        raise ValueError(f"source root has no src/caretaker directory: {root}")
    for path in sorted(source.rglob("*")):
        if path.is_file() and path.suffix == ".py":
            payload[f"caretaker/{path.relative_to(source).as_posix()}"] = hashlib.sha256(path.read_bytes()).hexdigest()
    profiles = root / "profiles"
    if profiles.is_dir():
        for path in sorted(profiles.rglob("*")):
            if path.is_file():
                payload[f"caretaker/profiles/{path.relative_to(profiles).as_posix()}"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return payload


def verify_payloads(
    *, sdist_path: Path, wheel_path: Path, source_root: Path | None, version: str
) -> dict[str, object]:
    sdist_version, sdist = _sdist_payload(sdist_path)
    wheel_version, wheel = _wheel_payload(wheel_path)
    source = _source_payload(source_root) if source_root is not None else None
    if sdist_version != version or wheel_version != version:
        raise ValueError(
            f"package metadata version mismatch: expected {version}, "
            f"sdist={sdist_version}, wheel={wheel_version}"
        )
    if sdist != wheel:
        missing = sorted(set(sdist) - set(wheel))
        extra = sorted(set(wheel) - set(sdist))
        changed = sorted(name for name in set(sdist) & set(wheel) if sdist[name] != wheel[name])
        raise ValueError(
            "source/wheel payload mismatch: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )
    if source is not None and source != wheel:
        missing = sorted(set(source) - set(wheel))
        extra = sorted(set(wheel) - set(source))
        changed = sorted(name for name in set(source) & set(wheel) if source[name] != wheel[name])
        raise ValueError(
            "source/package payload mismatch: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )
    return {"version": version, "source": source, "sdist": sdist, "wheel": wheel}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdist", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()
    try:
        result = verify_payloads(
            sdist_path=args.sdist,
            wheel_path=args.wheel,
            source_root=args.source_root,
            version=args.version,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if args.json_output:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(f"Verified exact source/wheel/source payload parity for Caretaker {args.version}: {len(result['wheel'])} members")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
