#!/usr/bin/env python3
"""Review a Caretaker root policy and its optional public certificates."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


PLACEHOLDERS = {"A" * 40, "B" * 40, "C" * 40}


def fail(message: str) -> None:
    print(f"root-check: {message}", file=sys.stderr)
    raise SystemExit(2)


def certificate(path: Path) -> tuple[str, bool]:
    result = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--show-keys", "--with-subkey-fingerprint", str(path)],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        fail(f"cannot inspect public certificate {path}: {result.stderr.strip()}")
    primary = None
    signing_subkey = False
    awaiting_primary = False
    for line in result.stdout.splitlines():
        fields = line.split(":")
        kind = fields[0]
        if kind in {"sec", "ssb"}:
            fail(f"secret-key material is not allowed in {path}")
        if kind == "pub":
            awaiting_primary = True
        elif kind == "fpr" and awaiting_primary:
            primary = fields[9].upper()
            awaiting_primary = False
        elif kind == "sub":
            validity = fields[1]
            capabilities = fields[11].lower()
            signing_subkey |= validity not in {"e", "r"} and "s" in capabilities
    if primary is None:
        fail(f"no primary public certificate found in {path}")
    return primary, signing_subkey


def main() -> int:
    if len(sys.argv) < 3:
        fail("usage: check-root.py ROOT ROOT_DIRECTORY [PUBLIC_KEY.asc ...]")
    root_path = Path(sys.argv[1])
    root_directory = Path(sys.argv[2])
    raw = root_path.read_bytes()
    data = json.loads(raw)
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    if raw != canonical:
        fail(f"{root_path} is not canonical JSON")

    slots = {name: value.upper() for name, value in data.get("key_slots", {}).items()}
    if set(slots) != {"A", "B", "C"}:
        fail("key_slots must contain exactly A, B, and C")
    if any(value in PLACEHOLDERS for value in slots.values()):
        fail("placeholder fingerprints must be replaced before publication")
    if len(set(slots.values())) != 3:
        fail("key slots must contain three distinct primary fingerprints")
    for name, value in slots.items():
        if len(value) != 40 or any(character not in "0123456789ABCDEF" for character in value):
            fail(f"slot {name} is not a full hexadecimal primary fingerprint")
    expected = set(slots.values())
    for role_name in ("release", "protected", "root"):
        role = data.get("roles", {}).get(role_name, {})
        observed = {value.upper() for value in role.get("authorized_primary_fingerprints", [])}
        if observed != expected:
            fail(f"role {role_name} fingerprints do not exactly match key_slots")

    missing = []
    for pattern in data.get("protected_paths", []) + data.get("sealed_paths", []):
        if not list(root_directory.glob(pattern)):
            missing.append(pattern)
    if missing:
        fail("protected/sealed patterns match no files: " + ", ".join(missing))

    public_keys = [Path(value) for value in sys.argv[3:]]
    if public_keys:
        certificates = dict(certificate(path) for path in public_keys)
        if set(certificates) != expected:
            fail("public certificates do not exactly match the three key-slot fingerprints")
        without_signing = [fingerprint for fingerprint, usable in certificates.items() if not usable]
        if without_signing:
            fail("public certificates lack a usable signing subkey: " + ", ".join(without_signing))

    print(f"Root policy valid: {root_path}")
    print(f"Root version: {data['root_version']}")
    print("Key slots: " + ", ".join(f"{name}={value}" for name, value in sorted(slots.items())))
    if public_keys:
        print("Public certificates: valid, public-only, and signing-capable")
    else:
        print("Public certificates: not checked (set PUBLIC_KEYS to check them)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
