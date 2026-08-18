#!/usr/bin/env python3
"""Verify the conventional three-key Caretaker publication file set."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from caretaker.integrity.cli import main as integrity_main


def main() -> int:
    directory = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    public_key_directory = Path(sys.argv[2]) if len(sys.argv) > 2 else directory / "release-keys"
    if not public_key_directory.is_dir():
        public_key_directory = directory
    root = directory / "root.json"
    slots = json.loads(root.read_text())["key_slots"]
    public_keys = [
        public_key_directory / f"caretaker-key-{slot.lower()}.asc"
        for slot in sorted(slots)
    ]
    root_signatures = [directory / f"root.json.key-{slot.lower()}.asc" for slot in sorted(slots)]
    common = ["--root", str(root), "--artifact-root", str(directory)]
    for path in public_keys:
        common += ["--public-key", str(path)]
    for path in root_signatures:
        common += ["--root-signature", str(path)]
    for fingerprint in slots.values():
        common += ["--trusted-fingerprint", fingerprint]

    for name in ("release-manifest.json", "protected-manifest.json"):
        arguments = ["verify", *common, "--manifest", str(directory / name)]
        for slot in sorted(slots):
            arguments += ["--signature", str(directory / f"{name}.key-{slot.lower()}.asc")]
        if integrity_main(arguments):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
