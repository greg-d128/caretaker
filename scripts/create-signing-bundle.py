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
        Path("root.json"): args.root,
        Path("release-manifest.json"): args.release_manifest,
        Path("protected-manifest.json"): args.protected_manifest,
        Path("profiles/caretaker-observe-only-v1.json"): repository / "profiles/caretaker-observe-only-v1.json",
        Path("profiles/caretaker-balanced-v1.json"): repository / "profiles/caretaker-balanced-v1.json",
        Path("profiles/caretaker-high-assurance-v1.json"): repository / "profiles/caretaker-high-assurance-v1.json",
        Path("release-keys/caretaker-key-a.asc"): args.public_key_dir / "caretaker-key-a.asc",
        Path("release-keys/caretaker-key-b.asc"): args.public_key_dir / "caretaker-key-b.asc",
        Path("release-keys/caretaker-key-c.asc"): args.public_key_dir / "caretaker-key-c.asc",
        Path("sign-artifacts.py"): repository / "scripts/sign-artifacts.py",
        Path("check-signing-key.py"): repository / "scripts/check-signing-key.py",
        Path("signing-status.py"): repository / "scripts/signing-status.py",
        Path("Makefile"): repository / "scripts/signing-station.Makefile",
    }
    for name in ("wheel-release-manifest.json", "wheel-protected-manifest.json"):
        source = repository / name
        if source.is_file():
            inputs[Path(name)] = source
    for destination, source in tuple(inputs.items()):
        if source.suffix != ".json":
            continue
        for slot in "abc":
            signature = Path(f"{source}.key-{slot}.asc")
            if signature.is_file():
                inputs[Path(f"{destination}.key-{slot}.asc")] = signature
    missing = [str(path) for path in inputs.values() if not path.is_file()]
    if missing:
        parser.error("required signing input(s) missing: " + ", ".join(missing))
    if args.output.exists():
        parser.error(f"output already exists; review and remove or rename it first: {args.output}")

    args.output.mkdir(parents=True, mode=0o700)
    for name, source in inputs.items():
        destination = args.output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o700 if name.suffix == ".py" else 0o600)

    readme = args.output / "README.txt"
    readme.write_text(
        "Caretaker offline signing bundle\n"
        "================================\n\n"
        "1. Compare SHA256SUMS and the three artifact hashes with the coordinator.\n"
        "2. Run: make status\n"
        "3. Run: make check KEY_SLOT=a\n"
        "4. Check all artifacts: make sign-check\n"
        "5. Sign every missing or changed artifact: make sign-all KEY_SLOT=a\n"
        "6. Return only the changed *.asc signature files and reviewed hashes.\n\n"
        "Use this station's own slot. Never copy a private key into this directory.\n",
        encoding="utf-8",
    )
    readme.chmod(0o600)

    inventory_paths = [args.output / name for name in inputs]
    inventory_paths.append(readme)
    inventory = []
    for path in sorted(inventory_paths, key=lambda item: str(item.relative_to(args.output))):
        relative = path.relative_to(args.output)
        inventory.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}")
    sums = args.output / "SHA256SUMS"
    sums.write_text("\n".join(inventory) + "\n", encoding="ascii")
    sums.chmod(0o600)
    print(f"Created offline signing bundle: {args.output}")
    print("Next steps: transfer it, compare SHA256SUMS, then run make status on the station.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
