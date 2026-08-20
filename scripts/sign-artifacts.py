#!/usr/bin/env python3
"""Check or sign every public Caretaker release artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Artifact:
    path: str
    generated_later: bool = False


ARTIFACTS = (
    Artifact("root.json"),
    Artifact("release-manifest.json"),
    Artifact("protected-manifest.json"),
    Artifact("profiles/caretaker-observe-only-v1.json"),
    Artifact("profiles/caretaker-balanced-v1.json"),
    Artifact("profiles/caretaker-high-assurance-v1.json"),
    Artifact("wheel-release-manifest.json", generated_later=True),
    Artifact("wheel-protected-manifest.json", generated_later=True),
)


def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, **kwargs)


def load_slots(root: Path) -> dict[str, str]:
    try:
        document = json.loads(root.read_text(encoding="utf-8"))
        slots = {str(k).lower(): str(v).upper() for k, v in document["key_slots"].items()}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"cannot read key slots from {root}: {exc}") from exc
    if set(slots) != {"a", "b", "c"}:
        raise ValueError(f"{root} must define key slots A, B, and C")
    return slots


def verification_home(
    public_key_dir: Path,
) -> tuple[tempfile.TemporaryDirectory[str], set[str]]:
    temporary = tempfile.TemporaryDirectory(prefix="caretaker-sign-check-")
    os.chmod(temporary.name, 0o700)
    keys = [public_key_dir / f"caretaker-key-{slot}.asc" for slot in "abc"]
    missing = [str(path) for path in keys if not path.is_file()]
    if missing:
        temporary.cleanup()
        raise ValueError("public certificate(s) missing: " + ", ".join(missing))
    result = run([
        "gpg", "--batch", "--no-autostart", "--homedir", temporary.name,
        "--import", *map(str, keys),
    ])
    if result.returncode:
        temporary.cleanup()
        raise ValueError("cannot import public certificates: " + (result.stderr.strip() or "gpg failed"))
    listing = run([
        "gpg", "--batch", "--no-autostart", "--homedir", temporary.name,
        "--with-colons", "--fingerprint", "--list-keys",
    ])
    primary_fingerprints: set[str] = set()
    awaiting_primary = False
    for line in listing.stdout.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            awaiting_primary = True
        elif awaiting_primary and fields[0] == "fpr":
            primary_fingerprints.add(fields[9].upper())
            awaiting_primary = False
    if listing.returncode:
        temporary.cleanup()
        raise ValueError("cannot list imported public certificates: " + (listing.stderr.strip() or "gpg failed"))
    return temporary, primary_fingerprints


def signature_valid(home: str, artifact: Path, signature: Path, fingerprint: str) -> bool:
    result = run([
        "gpg", "--batch", "--no-autostart", "--homedir", home, "--status-fd", "1",
        "--verify", str(signature), str(artifact),
    ])
    if result.returncode:
        return False
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] == "[GNUPG:]" and fields[1] == "VALIDSIG":
            if fingerprint in {field.upper() for field in fields[2:]}:
                return True
    return False


def states(
    directory: Path, slots: dict[str, str], home: str, public_fingerprints: set[str] | None = None
) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for item in ARTIFACTS:
        artifact = directory / item.path
        if not artifact.is_file():
            state = "PENDING" if item.generated_later else "ARTIFACT MISSING"
            result[item.path] = {slot: state for slot in slots}
            continue
        slot_states: dict[str, str] = {}
        for slot, fingerprint in slots.items():
            if public_fingerprints is not None and fingerprint not in public_fingerprints:
                slot_states[slot] = "KEY MISMATCH"
                continue
            signature = directory / f"{item.path}.key-{slot}.asc"
            if not signature.is_file():
                slot_states[slot] = "MISSING"
            elif signature_valid(home, artifact, signature, fingerprint):
                slot_states[slot] = "VALID"
            else:
                slot_states[slot] = "STALE/INVALID"
        result[item.path] = slot_states
    return result


def print_states(current: dict[str, dict[str, str]]) -> None:
    print(f"{'Artifact':58} {'A':14} {'B':14} {'C':14}")
    print("-" * 104)
    for path, values in current.items():
        print(f"{path:58} {values['a']:14} {values['b']:14} {values['c']:14}")
    counts: dict[str, int] = {}
    for values in current.values():
        for value in values.values():
            counts[value] = counts.get(value, 0) + 1
    print("\nSummary: " + ", ".join(f"{name.lower()}={count}" for name, count in sorted(counts.items())))


def sign(directory: Path, slot: str, fingerprint: str, current: dict[str, dict[str, str]]) -> int:
    changed = 0
    for item in ARTIFACTS:
        state = current[item.path][slot]
        if state == "VALID":
            print(f"KEEP  {item.path} (valid slot {slot.upper()} signature)")
            continue
        if state == "PENDING":
            print(f"WAIT  {item.path} (generate it before signing)")
            continue
        if state == "ARTIFACT MISSING":
            print(f"ERROR {item.path} (required artifact is missing)", file=sys.stderr)
            return 2
        artifact = directory / item.path
        output = directory / f"{item.path}.key-{slot}.asc"
        output.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
        os.close(fd)
        temporary = Path(temporary_name)
        temporary.unlink()
        try:
            print(f"SIGN  {item.path}  sha256={hashlib.sha256(artifact.read_bytes()).hexdigest()}")
            result = subprocess.run([
                "gpg", "--local-user", fingerprint, "--armor", "--detach-sign",
                "--output", str(temporary), str(artifact),
            ])
            if result.returncode:
                return result.returncode
            verified = subprocess.run(["gpg", "--verify", str(temporary), str(artifact)])
            if verified.returncode:
                print(f"New signature did not verify: {item.path}", file=sys.stderr)
                return verified.returncode
            os.replace(temporary, output)
            changed += 1
        finally:
            temporary.unlink(missing_ok=True)
    print(f"\nCreated or replaced {changed} slot {slot.upper()} signature(s).")
    print("Next steps: return the changed .asc files, repeat on other slots, then run make sign-check.")
    if any(values[slot] == "PENDING" for values in current.values()):
        print("After all profile signatures are collected, run make wheel-manifests and then make sign-all again.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "sign"))
    parser.add_argument("--directory", type=Path, default=Path("."))
    parser.add_argument("--root", type=Path, default=Path("root.json"))
    parser.add_argument("--public-key-dir", type=Path, default=Path("release-keys"))
    parser.add_argument("--key-slot", type=str.lower, choices=tuple("abc"))
    parser.add_argument("--signing-key")
    args = parser.parse_args()
    root = args.root if args.root.is_absolute() else args.directory / args.root
    key_dir = args.public_key_dir if args.public_key_dir.is_absolute() else args.directory / args.public_key_dir
    try:
        slots = load_slots(root)
        temporary, public_fingerprints = verification_home(key_dir)
        with temporary as home:
            current = states(args.directory, slots, home, public_fingerprints)
            print_states(current)
            if args.command == "check":
                print(
                    "\nChanged artifacts are MISSING or STALE/INVALID. KEY MISMATCH means the "
                    "published certificate does not match root.json. PENDING wheel manifests have "
                    "not been generated yet."
                )
                return 0
            if not args.key_slot:
                parser.error("--key-slot is required for sign")
            expected = slots[args.key_slot]
            if expected not in public_fingerprints:
                parser.error(
                    f"public certificate for slot {args.key_slot.upper()} does not provide {expected}"
                )
            fingerprint = (args.signing_key or expected).upper()
            if fingerprint != expected:
                parser.error(f"slot {args.key_slot.upper()} requires {expected}, not {fingerprint}")
            return sign(args.directory, args.key_slot, fingerprint, current)
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
