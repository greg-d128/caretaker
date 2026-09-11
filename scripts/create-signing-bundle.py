#!/usr/bin/env python3
"""Create a minimal, reviewable directory for an offline signing station."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path


def _workflow_module(repository: Path):
    spec = importlib.util.spec_from_file_location(
        "caretaker_release_candidate", repository / "scripts" / "release-candidate.py"
    )
    if spec is None or spec.loader is None:
        raise ValueError("cannot load release-candidate workflow")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _reject_private_key(path: Path) -> None:
    if path.suffix.lower() not in {".asc", ".key", ".pem"}:
        return
    data = path.read_bytes()
    if b"BEGIN PGP PRIVATE KEY BLOCK" in data or b"BEGIN OPENSSH PRIVATE KEY" in data:
        raise ValueError(f"private signing key material is not permitted in a signing bundle: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--release-manifest", type=Path, required=True)
    parser.add_argument("--protected-manifest", type=Path, required=True)
    parser.add_argument("--public-key-dir", type=Path, required=True)
    parser.add_argument("--finalization-record", type=Path)
    parser.add_argument("--candidate-record", type=Path)
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
    finalization = None
    if args.finalization_record:
        workflow = _workflow_module(repository)
        finalization = workflow.load_record(args.finalization_record.resolve(), workflow.FINALIZATION_KIND)
        workflow.validate_finalization(repository, finalization)
        expected = {
            args.release_manifest.resolve(): "release-manifest.json",
            args.protected_manifest.resolve(): "protected-manifest.json",
        }
        for source, name in expected.items():
            recorded = finalization.get("publication", {}).get(name)
            if not isinstance(recorded, dict) or Path(str(recorded.get("path", ""))).resolve() != source:
                parser.error(f"finalization record does not approve {source}")
            if workflow.sha256_file(source) != recorded.get("sha256"):
                parser.error(f"manifest changed after finalization: {source}")
        inputs[Path("finalization.json")] = args.finalization_record.resolve()
        if args.candidate_record:
            candidate = workflow.load_record(args.candidate_record.resolve())
            if candidate.get("candidate_id") != finalization.get("candidate_id"):
                parser.error("candidate record does not match finalization")
            inputs[Path("candidate-input.json")] = args.candidate_record.resolve()
        for name in ("wheel", "sdist"):
            entry = finalization["artifacts"][name]
            source = Path(str(entry["path"])).resolve()
            if not source.is_file() or workflow.sha256_file(source) != entry.get("sha256"):
                parser.error(f"final {name} changed or is missing: {source}")
            inputs[Path("artifacts") / source.name] = source
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
        _reject_private_key(source)
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
    if finalization is not None:
        (args.output / "signing-inputs.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "record_type": "caretaker-signing-inputs",
                    "candidate_id": finalization["candidate_id"],
                    "finalization_sha256": hashlib.sha256(args.output.joinpath("finalization.json").read_bytes()).hexdigest(),
                    "files": {
                        str(path.relative_to(args.output)): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in sorted(args.output.rglob("*"))
                        if path.is_file() and path.name not in {"README.txt", "SHA256SUMS", "signing-inputs.json"}
                    },
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
    readme.chmod(0o600)

    inventory_paths = [args.output / name for name in inputs]
    if finalization is not None:
        inventory_paths.extend([args.output / "finalization.json", args.output / "candidate-input.json", args.output / "signing-inputs.json"] if args.candidate_record else [args.output / "finalization.json", args.output / "signing-inputs.json"])
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
