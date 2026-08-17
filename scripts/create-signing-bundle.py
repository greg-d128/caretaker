#!/usr/bin/env python3
"""Create a minimal, reviewable directory for an offline signing station."""

from __future__ import annotations

import argparse
import hashlib
import shutil
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--release-manifest", type=Path, required=True)
    parser.add_argument("--protected-manifest", type=Path, required=True)
    parser.add_argument("--public-key-dir", type=Path, required=True)
    args = parser.parse_args()

    repository = Path(__file__).resolve().parents[1]
    inputs = {
        "root.json": args.root,
        "release-manifest.json": args.release_manifest,
        "protected-manifest.json": args.protected_manifest,
        "caretaker-key-a.asc": args.public_key_dir / "caretaker-key-a.asc",
        "caretaker-key-b.asc": args.public_key_dir / "caretaker-key-b.asc",
        "caretaker-key-c.asc": args.public_key_dir / "caretaker-key-c.asc",
        "sign-code.sh": repository / "scripts/sign-code.sh",
        "check-signing-key.py": repository / "scripts/check-signing-key.py",
        "signing-status.py": repository / "scripts/signing-status.py",
        "Makefile": repository / "scripts/signing-station.Makefile",
    }
    missing = [str(path) for path in inputs.values() if not path.is_file()]
    if missing:
        parser.error("required signing input(s) missing: " + ", ".join(missing))
    if args.output.exists():
        parser.error(f"output already exists; review and remove or rename it first: {args.output}")

    args.output.mkdir(parents=True, mode=0o700)
    for name, source in inputs.items():
        destination = args.output / name
        shutil.copyfile(source, destination)
        destination.chmod(0o700 if name.endswith((".sh", ".py")) else 0o600)

    readme = args.output / "README.txt"
    readme.write_text(
        "Caretaker offline signing bundle\n"
        "================================\n\n"
        "1. Compare SHA256SUMS and the three artifact hashes with the coordinator.\n"
        "2. Run: make status\n"
        "3. Run: make check KEY_SLOT=a\n"
        "4. Sign both release manifests: make sign-release-set KEY_SLOT=a\n"
        "5. Sign root only when requested: make sign-root KEY_SLOT=a\n"
        "6. Return only the new *.asc signature files and reviewed hashes.\n\n"
        "Use this station's own slot. Never copy a private key into this directory.\n",
        encoding="utf-8",
    )
    readme.chmod(0o600)

    inventory = []
    for path in sorted(args.output.iterdir(), key=lambda item: item.name):
        if path.name == "SHA256SUMS":
            continue
        inventory.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    sums = args.output / "SHA256SUMS"
    sums.write_text("\n".join(inventory) + "\n", encoding="ascii")
    sums.chmod(0o600)
    print(f"Created offline signing bundle: {args.output}")
    print("Next steps: transfer it, compare SHA256SUMS, then run make status on the station.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
