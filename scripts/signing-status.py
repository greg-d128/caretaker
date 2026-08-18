#!/usr/bin/env python3
"""Show the conventional Caretaker publication's signing progress."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ARTIFACTS = ("root.json", "release-manifest.json", "protected-manifest.json")


def main() -> int:
    if len(sys.argv) not in {1, 2, 3, 4}:
        print("usage: signing-status.py [PUBLICATION_DIR] [ROOT] [PUBLIC_KEY_DIR]", file=sys.stderr)
        return 2
    directory = Path(sys.argv[1] if len(sys.argv) >= 2 else ".")
    root_path = Path(sys.argv[2]) if len(sys.argv) >= 3 else directory / "root.json"
    public_key_directory = Path(sys.argv[3]) if len(sys.argv) >= 4 else directory
    if not root_path.is_file():
        print(f"Root policy: MISSING ({root_path})")
        print("Next action: provide root.json before generating or signing manifests.")
        return 0
    try:
        root = json.loads(root_path.read_text(encoding="utf-8"))
        slots = dict(root["key_slots"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Root policy: INVALID ({type(exc).__name__}: {exc})")
        print("Next action: repair and validate root.json with make root-check.")
        return 0

    print(f"Root policy: present (version {root.get('root_version', '?')})")
    missing_artifacts: list[str] = []
    for artifact in ARTIFACTS[1:]:
        present = (directory / artifact).is_file()
        print(f"{artifact}: {'present' if present else 'MISSING'}")
        if not present:
            missing_artifacts.append(artifact)

    missing_keys: list[str] = []
    for slot in sorted(slots):
        filename = f"caretaker-key-{slot.lower()}.asc"
        path = public_key_directory / filename
        present = path.is_file()
        print(f"Public key {slot}: {'present' if present else 'MISSING'} ({path})")
        if not present:
            missing_keys.append(slot)

    missing_signatures: list[tuple[str, str]] = []
    print("Signatures:")
    for artifact in ARTIFACTS:
        states = []
        for slot in sorted(slots):
            filename = f"{artifact}.key-{slot.lower()}.asc"
            present = (directory / filename).is_file()
            states.append(f"{slot}={'yes' if present else 'NO'}")
            if not present:
                missing_signatures.append((artifact, slot))
        print(f"  {artifact}: {', '.join(states)}")

    if missing_artifacts:
        print("Next action: generate and review the missing manifest(s): " + ", ".join(missing_artifacts))
    elif missing_keys:
        print("Next action: collect the missing public certificate(s): " + ", ".join(missing_keys))
    elif missing_signatures:
        artifact, slot = missing_signatures[0]
        target = {
            "root.json": "sign-root",
            "release-manifest.json": "sign-release",
            "protected-manifest.json": "sign-protected",
        }[artifact]
        print(f"Next action: obtain slot {slot} signature for {artifact} (make {target} KEY_SLOT={slot.lower()}).")
    else:
        print("Next action: run make verify-publication PUBLICATION_DIR=. before publishing.")
    print("Presence is not cryptographic verification; verify-publication performs that check.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
