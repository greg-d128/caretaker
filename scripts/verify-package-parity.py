#!/usr/bin/env python3
"""Verify that a source distribution and wheel carry the same release payload."""

from __future__ import annotations

import argparse
import hashlib
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdist", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    sdist_version, sdist = _sdist_payload(args.sdist)
    wheel_version, wheel = _wheel_payload(args.wheel)
    if sdist_version != args.version or wheel_version != args.version:
        raise SystemExit(
            f"package metadata version mismatch: expected {args.version}, "
            f"sdist={sdist_version}, wheel={wheel_version}"
        )
    if sdist != wheel:
        missing = sorted(set(sdist) - set(wheel))
        extra = sorted(set(wheel) - set(sdist))
        changed = sorted(name for name in set(sdist) & set(wheel) if sdist[name] != wheel[name])
        raise SystemExit(
            "source/wheel payload mismatch: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )
    print(f"Verified exact source/wheel payload parity for Caretaker {args.version}: {len(sdist)} members")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
