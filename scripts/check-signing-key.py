#!/usr/bin/env python3
"""Confirm that one signing station owns the expected slot's signing subkey."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def fail(message: str) -> None:
    print(f"signing-check: {message}", file=sys.stderr)
    raise SystemExit(2)


def main() -> int:
    if len(sys.argv) != 4:
        fail("usage: check-signing-key.py ROOT KEY_SLOT PRIMARY_FINGERPRINT")
    root_path, slot, requested = Path(sys.argv[1]), sys.argv[2].upper(), sys.argv[3].upper()
    expected = json.loads(root_path.read_text())["key_slots"].get(slot, "").upper()
    if not expected:
        fail(f"unknown key slot {slot!r}")
    if requested != expected:
        fail(f"slot {slot} expects primary fingerprint {expected}, not {requested}")

    result = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--list-secret-keys", "--with-subkey-fingerprint", requested],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        fail(f"secret key for slot {slot} is unavailable")
    primary = None
    awaiting_primary = False
    usable_signing_subkey = False
    for line in result.stdout.splitlines():
        fields = line.split(":")
        if fields[0] == "sec":
            awaiting_primary = True
        elif fields[0] == "fpr" and awaiting_primary:
            primary = fields[9].upper()
            awaiting_primary = False
        elif fields[0] == "ssb":
            validity = fields[1]
            capabilities = fields[11].lower()
            usable_signing_subkey |= validity not in {"e", "r"} and "s" in capabilities
    if primary != requested:
        fail("GnuPG did not return the requested primary identity")
    if not usable_signing_subkey:
        fail("no usable secret signing subkey is available")
    print(f"Signing identity valid: slot {slot}, primary {primary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
