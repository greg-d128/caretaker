#!/usr/bin/env python3
"""Build and freeze Caretaker release-candidate inputs.

This script deliberately records release evidence; it does not sign anything
and it does not implement Validator's cross-repository equivalence rules.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
CANDIDATE_KIND = "caretaker-candidate-input"
FREEZE_KIND = "caretaker-candidate-freeze"
FINALIZATION_KIND = "caretaker-release-finalization"
RELEASE_VERSION_PATHS = {
    "pyproject.toml",
    "src/caretaker/__init__.py",
    "README.md",
    "CHANGELOG.md",
}
RELEASE_VERSION_PREFIXES = ("catalogs/",)
GENERATED_RELEASE_FILES = {
    "release-manifest.json",
    "protected-manifest.json",
    "wheel-release-manifest.json",
    "wheel-protected-manifest.json",
}
PARITY_SCRIPT = Path(__file__).with_name("verify-package-parity.py")


class WorkflowError(ValueError):
    """An input failed a release workflow gate."""


def _canonical_bytes(document: object) -> bytes:
    return (json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).replace(microsecond=0).isoformat()


def _run(repository: Path, *command: str) -> str:
    result = subprocess.run(command, cwd=repository, text=True, capture_output=True)
    if result.returncode:
        raise WorkflowError(result.stderr.strip() or result.stdout.strip() or f"command failed: {' '.join(command)}")
    return result.stdout.strip()


def git_revision(repository: Path) -> str:
    return _run(repository, "git", "rev-parse", "HEAD")


def git_status(repository: Path) -> str:
    return _run(repository, "git", "status", "--porcelain", "--untracked-files=all")


def require_clean(repository: Path) -> None:
    status = git_status(repository)
    if status:
        raise WorkflowError("source revision is dirty; commit or remove changes before the candidate build:\n" + status)


def _tracked_paths(repository: Path) -> list[str]:
    output = subprocess.run(
        ["git", "ls-files", "-z"], cwd=repository, text=False, capture_output=True, check=True
    ).stdout
    return sorted(item.decode("utf-8") for item in output.split(b"\0") if item)


def source_inventory(repository: Path) -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    for name in _tracked_paths(repository):
        if name in GENERATED_RELEASE_FILES or ".key-" in name or name.startswith("release-keys/"):
            continue
        path = repository / name
        if not path.is_file():
            raise WorkflowError(f"tracked source input is missing: {name}")
        inventory[name] = {"sha256": sha256_file(path), "size_bytes": path.stat().st_size}
    return inventory


def inventory_digest(inventory: dict[str, dict[str, Any]]) -> str:
    return _sha256_bytes(_canonical_bytes(inventory))


def _input_paths(repository: Path) -> list[str]:
    patterns = (
        "pyproject.toml",
        "setup.py",
        "MANIFEST.in",
        "root.json",
        "profiles/*.json",
        "catalogs/*.json",
        "constraints/*",
    )
    paths: set[str] = set()
    for pattern in patterns:
        paths.update(path.relative_to(repository).as_posix() for path in repository.glob(pattern) if path.is_file())
    return sorted(paths)


def contract_input_inventory(repository: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name in _input_paths(repository):
        path = repository / name
        result[name] = {"sha256": sha256_file(path), "size_bytes": path.stat().st_size}
    return result


def build_identity() -> dict[str, Any]:
    tool_versions: dict[str, str] = {}
    for name in ("build", "setuptools", "wheel", "twine"):
        try:
            tool_versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            tool_versions[name] = "unavailable"
    return {
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_full_version": sys.version,
        "platform": platform.platform(),
        "build_tool": tool_versions,
        "source_date_epoch": None,
    }


def _ensure_no_private_key_material(paths: list[Path]) -> None:
    for path in paths:
        if path.suffix.lower() not in {".asc", ".key", ".pem"}:
            continue
        if not path.is_file() or path.stat().st_size > 10 * 1024 * 1024:
            continue
        data = path.read_bytes()
        if b"BEGIN PGP PRIVATE KEY BLOCK" in data or b"BEGIN OPENSSH PRIVATE KEY" in data:
            raise WorkflowError(f"private signing key material is not permitted in candidate inputs: {path}")


def _package_artifacts(directory: Path, version: str) -> tuple[Path, Path]:
    wheel = directory / f"caretaker-{version}-py3-none-any.whl"
    sdist = directory / f"caretaker-{version}.tar.gz"
    missing = [str(path) for path in (wheel, sdist) if not path.is_file()]
    if missing:
        raise WorkflowError("fresh candidate artifacts are missing: " + ", ".join(missing))
    extras = sorted(
        path.name for path in directory.iterdir() if path.is_file() and path.suffix in {".whl", ".gz"} and path not in {wheel, sdist}
    )
    if extras:
        raise WorkflowError("candidate output contains stale distribution artifacts: " + ", ".join(extras))
    return wheel, sdist


def _artifact_record(path: Path, *, root: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path.resolve()),
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def _parity(
    repository: Path, wheel: Path, sdist: Path, version: str
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(PARITY_SCRIPT),
        "--sdist",
        str(sdist),
        "--wheel",
        str(wheel),
        "--source-root",
        str(repository),
        "--version",
        version,
        "--json",
    ]
    result = subprocess.run(command, cwd=repository, text=True, capture_output=True)
    if result.returncode:
        raise WorkflowError(result.stderr.strip() or result.stdout.strip() or "package/source parity failed")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise WorkflowError(f"parity checker returned invalid JSON: {exc}") from exc


def _record_id(document: dict[str, Any]) -> str:
    body = {key: value for key, value in document.items() if key not in {"candidate_id", "record_sha256"}}
    if document.get("record_type") == FREEZE_KIND:
        body["record_type"] = CANDIDATE_KIND
        body["status"] = "UNSIGNED_DEVELOPMENT"
        body.pop("freeze", None)
    return "cand-" + _sha256_bytes(_canonical_bytes(body))[:32]


def _write_record(path: Path, document: dict[str, Any], *, force: bool = False) -> None:
    if path.exists() and not force:
        raise WorkflowError(f"refusing to replace existing record: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical_bytes(document))


def load_record(path: Path, expected_kind: str | None = None) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"cannot read workflow record {path}: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION:
        raise WorkflowError(f"unsupported workflow record schema: {path}")
    if expected_kind and document.get("record_type") != expected_kind:
        raise WorkflowError(f"{path} is not a {expected_kind} record")
    if document.get("record_type") in {CANDIDATE_KIND, FREEZE_KIND}:
        if document.get("candidate_id") != _record_id(document):
            raise WorkflowError(f"candidate record identity does not match its canonical bytes: {path}")
    return document


def _path_changed_only_by_version(path: str, old: bytes, new: bytes, old_version: str, new_version: str) -> bool:
    if path not in RELEASE_VERSION_PATHS and not path.startswith(RELEASE_VERSION_PREFIXES):
        return False
    return old.replace(old_version.encode(), new_version.encode()) == new


def compare_release_inputs(
    repository: Path,
    candidate_inventory: dict[str, dict[str, Any]],
    candidate_revision: str,
    candidate_version: str,
    final_version: str,
) -> list[str]:
    current = source_inventory(repository)
    if set(current) != set(candidate_inventory):
        return sorted(set(current) ^ set(candidate_inventory))
    changed: list[str] = []
    for name, old_entry in candidate_inventory.items():
        if old_entry == current[name]:
            continue
        old_path = repository / name
        # Candidate source bytes are not stored in the record. For the small
        # version-only allowlist, retrieve them from the candidate revision.
        try:
            old_bytes = subprocess.run(
                ["git", "show", f"{candidate_revision}:{name}"], cwd=repository, capture_output=True, check=True
            ).stdout
        except subprocess.CalledProcessError:
            changed.append(name)
            continue
        if not _path_changed_only_by_version(name, old_bytes, old_path.read_bytes(), candidate_version, final_version):
            changed.append(name)
    return changed


def validate_candidate_source(repository: Path, record: dict[str, Any], *, final_version: str | None = None) -> None:
    require_clean(repository)
    source = record.get("source")
    if not isinstance(source, dict) or source.get("clean") is not True:
        raise WorkflowError("candidate record does not assert a clean source revision")
    inventory = source.get("inventory")
    if not isinstance(inventory, dict):
        raise WorkflowError("candidate record has no source inventory")
    if final_version is None:
        current = source_inventory(repository)
        if current != inventory:
            raise WorkflowError("source changed after candidate build")
    else:
        changed = compare_release_inputs(
            repository,
            inventory,
            str(source.get("revision", "")),
            str(record["package_version"]),
            final_version,
        )
        if changed:
            raise WorkflowError("functional source inputs changed after candidate freeze: " + ", ".join(changed))


def build_candidate(args: argparse.Namespace) -> int:
    repository = args.repository.resolve()
    output = args.output.resolve()
    require_clean(repository)
    if output.exists():
        if not output.is_dir() or any(output.iterdir()):
            raise WorkflowError(f"candidate output must be a new or empty disposable directory: {output}")
    else:
        output.mkdir(parents=True)
    artifacts = output / "artifacts"
    artifacts.mkdir()
    identity = build_identity()
    commit_epoch = _run(repository, "git", "show", "-s", "--format=%ct", "HEAD")
    identity["source_date_epoch"] = int(commit_epoch)
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env["SOURCE_DATE_EPOCH"] = commit_epoch
    env["CARETAKER_RELEASE_SIGNING"] = "disabled"
    _ensure_no_private_key_material([repository / name for name in _tracked_paths(repository)])
    result = subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--wheel", "--sdist", "--outdir", str(artifacts)],
        cwd=repository,
        env=env,
        text=True,
        capture_output=True,
    )
    if result.returncode:
        raise WorkflowError(result.stderr.strip() or result.stdout.strip() or "candidate build failed")
    wheel, sdist = _package_artifacts(artifacts, args.package_version)
    parity = _parity(repository, wheel, sdist, args.package_version)
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_type": CANDIDATE_KIND,
        "status": "UNSIGNED_DEVELOPMENT",
        "release_eligible": False,
        "contract_line": args.contract_line or _contract_line(args.package_version),
        "package_version": args.package_version,
        "candidate_id": "",
        "created_at": _now(),
        "source": {
            "revision": git_revision(repository),
            "clean": True,
            "inventory": source_inventory(repository),
        },
        "contract_inputs": contract_input_inventory(repository),
        "artifacts": {
            "root": str(output),
            "wheel": _artifact_record(wheel, root=output),
            "sdist": _artifact_record(sdist, root=output),
        },
        "canonical_parity": parity,
        "build_identity": identity,
        "signing": {
            "mode": "none",
            "private_key_material_used": False,
            "release_status": "UNSIGNED_DEVELOPMENT",
        },
        "finalization": None,
    }
    record["source"]["inventory_sha256"] = inventory_digest(record["source"]["inventory"])
    record["candidate_id"] = _record_id(record)
    _write_record(output / "candidate-input.json", record)
    print(f"Built unsigned development candidate {record['candidate_id']} in {output}")
    return 0


def _contract_line(version: str) -> str:
    return "caretaker-" + re.sub(r"(?:a|b|rc)\d+$", "", version)


def _evidence_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise WorkflowError(f"evidence record is missing: {path}")
    return {"path": str(path.resolve()), "sha256": sha256_file(path), "size_bytes": path.stat().st_size}


def freeze_candidate(args: argparse.Namespace) -> int:
    candidate_path = args.candidate.resolve()
    candidate = load_record(candidate_path, CANDIDATE_KIND)
    repository = args.repository.resolve()
    validate_candidate_source(repository, candidate)
    validate_artifact_records(candidate)
    output = args.output.resolve()
    frozen = dict(candidate)
    frozen["record_type"] = FREEZE_KIND
    frozen["status"] = "CANDIDATE_FROZEN"
    frozen["freeze"] = {
        "frozen_at": _now(),
        "candidate_input": {
            "path": str(candidate_path),
            "sha256": sha256_file(candidate_path),
        },
        "validator": _evidence_record(args.validator_result) if args.validator_result else None,
        "crucible": _evidence_record(args.crucible_result) if args.crucible_result else None,
        "architect": _evidence_record(args.architect_audit) if args.architect_audit else None,
    }
    frozen["candidate_id"] = ""
    frozen["candidate_id"] = _record_id(frozen)
    _write_record(output, frozen, force=args.force)
    print(f"Froze candidate {frozen['candidate_id']}: {output}")
    return 0


def _artifact_from_record(record: dict[str, Any], name: str) -> Path:
    artifact = record.get("artifacts", {}).get(name)
    if not isinstance(artifact, dict) or not artifact.get("path"):
        raise WorkflowError(f"finalization record has no {name} artifact")
    return Path(str(artifact["path"]))


def validate_artifact_records(record: dict[str, Any]) -> None:
    for name in ("wheel", "sdist"):
        entry = record.get("artifacts", {}).get(name)
        if not isinstance(entry, dict):
            raise WorkflowError(f"finalization record has no {name} artifact record")
        path = Path(str(entry["path"]))
        if not path.is_absolute() and record.get("artifacts", {}).get("root"):
            path = Path(str(record["artifacts"]["root"])) / path
        if not path.is_file():
            raise WorkflowError(f"final artifact is missing: {path}")
        if sha256_file(path) != entry.get("sha256") or path.stat().st_size != entry.get("size_bytes"):
            raise WorkflowError(f"final artifact changed after finalization: {path}")


def validate_finalization(repository: Path, record: dict[str, Any]) -> None:
    if record.get("record_type") != FINALIZATION_KIND:
        raise WorkflowError("not a release finalization record")
    candidate_id = record.get("candidate_id")
    if not isinstance(candidate_id, str) or not candidate_id:
        raise WorkflowError("finalization has no candidate identity")
    if record.get("status") != "FINALIZED_UNSIGNED":
        raise WorkflowError("finalization is not an unsigned pre-signing record")
    source = record.get("source")
    if not isinstance(source, dict) or source.get("clean") is not True:
        raise WorkflowError("finalization does not bind a clean final source")
    require_clean(repository)
    current = source_inventory(repository)
    if current != source.get("inventory"):
        raise WorkflowError("source changed after finalization")
    validate_artifact_records(record)
    publication = record.get("publication", {})
    for name, entry in publication.items():
        if not isinstance(entry, dict):
            raise WorkflowError(f"invalid publication record for {name}")
        path = Path(str(entry.get("path", "")))
        if not path.is_file():
            raise WorkflowError(f"publication input is missing: {path}")
        if sha256_file(path) != entry.get("sha256"):
            raise WorkflowError(f"publication input changed after finalization: {path}")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkflowError(f"publication input is not JSON: {path}: {exc}") from exc
        if document.get("package_version") not in {None, record["package_version"]}:
            raise WorkflowError(f"publication version mismatch in {path}")
    handoff = record.get("equivalence_handoff")
    if not isinstance(handoff, dict) or handoff.get("status") not in {"PASS", "PASSED", "EQUIVALENT"}:
        raise WorkflowError("Validator equivalence handoff is missing or not accepted")
    handoff_path = Path(str(handoff.get("path", "")))
    if not handoff_path.is_file() or sha256_file(handoff_path) != handoff.get("sha256"):
        raise WorkflowError("Validator equivalence handoff changed or is missing")


def finalize_release(args: argparse.Namespace) -> int:
    candidate = load_record(args.candidate.resolve())
    if candidate.get("record_type") not in {CANDIDATE_KIND, FREEZE_KIND}:
        raise WorkflowError("finalization requires a candidate input or frozen candidate record")
    repository = args.repository.resolve()
    validate_candidate_source(repository, candidate, final_version=args.final_version)
    wheel, sdist = _package_artifacts(args.final_dist.resolve(), args.final_version)
    parity = _parity(repository, wheel, sdist, args.final_version)
    handoff_path = args.equivalence.resolve()
    try:
        handoff_document = json.loads(handoff_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"cannot read Validator equivalence handoff: {exc}") from exc
    if not isinstance(handoff_document, dict) or handoff_document.get("status") not in {"PASS", "PASSED", "EQUIVALENT"}:
        raise WorkflowError("Validator equivalence handoff is not accepted")
    if handoff_document.get("candidate_id") not in {None, candidate["candidate_id"]}:
        raise WorkflowError("Validator equivalence handoff names a different candidate")
    publication: dict[str, dict[str, Any]] = {}
    for path in [item.resolve() for item in args.manifest]:
        if not path.is_file():
            raise WorkflowError(f"publication manifest is missing: {path}")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkflowError(f"publication manifest is not JSON: {path}: {exc}") from exc
        if document.get("package_version") not in {None, args.final_version}:
            raise WorkflowError(f"publication manifest version does not match {args.final_version}: {path}")
        publication[path.name] = {
            "path": str(path),
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
    final: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_type": FINALIZATION_KIND,
        "status": "FINALIZED_UNSIGNED",
        "release_eligible": False,
        "candidate_id": candidate["candidate_id"],
        "contract_line": candidate["contract_line"],
        "development_package_version": candidate["package_version"],
        "package_version": args.final_version,
        "created_at": _now(),
        "source": {
            "revision": git_revision(repository),
            "clean": True,
            "inventory": source_inventory(repository),
        },
        "artifacts": {
            "root": str(args.final_dist.resolve()),
            "wheel": {**_artifact_record(wheel, root=args.final_dist.resolve()), "path": str(wheel.resolve())},
            "sdist": {**_artifact_record(sdist, root=args.final_dist.resolve()), "path": str(sdist.resolve())},
        },
        "canonical_parity": parity,
        "publication": publication,
        "equivalence_handoff": {
            "path": str(handoff_path),
            "sha256": sha256_file(handoff_path),
            "status": handoff_document.get("status"),
        },
        "signing": {"mode": "external-detached-manifests", "prepared": False},
    }
    final_path = args.output.resolve()
    _write_record(final_path, final, force=args.force)
    validate_finalization(repository, final)
    print(f"Finalized candidate {final['candidate_id']} for signing: {final_path}")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="build a fresh unsigned development candidate")
    build.add_argument("--repository", type=Path, default=Path("."))
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--package-version", required=True)
    build.add_argument("--contract-line")
    build.set_defaults(function=build_candidate)

    freeze = sub.add_parser("freeze", help="freeze an already tested candidate input")
    freeze.add_argument("--repository", type=Path, default=Path("."))
    freeze.add_argument("--candidate", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    freeze.add_argument("--validator-result", type=Path)
    freeze.add_argument("--crucible-result", type=Path)
    freeze.add_argument("--architect-audit", type=Path)
    freeze.add_argument("--force", action="store_true")
    freeze.set_defaults(function=freeze_candidate)

    finalize = sub.add_parser("finalize", help="record the final release-only transformation")
    finalize.add_argument("--repository", type=Path, default=Path("."))
    finalize.add_argument("--candidate", type=Path, required=True)
    finalize.add_argument("--final-version", required=True)
    finalize.add_argument("--final-dist", type=Path, required=True)
    finalize.add_argument("--manifest", type=Path, action="append", default=[])
    finalize.add_argument("--equivalence", type=Path, required=True, help="Validator-produced equivalence handoff")
    finalize.add_argument("--output", type=Path, required=True)
    finalize.add_argument("--force", action="store_true")
    finalize.set_defaults(function=finalize_release)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.function(args)
    except (WorkflowError, OSError, subprocess.CalledProcessError) as exc:
        print(f"release-candidate: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
