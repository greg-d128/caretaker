"""Read-only, versioned documentation cards shipped with Caretaker."""

from __future__ import annotations

import json
from contextlib import contextmanager
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any, Iterator

from .. import __version__

CONTRACT_LINE = "caretaker-0.6.5"
SCHEMA_VERSION = 1
_PACKAGE = "caretaker.llm_docs"


class DocumentationError(ValueError):
    """Raised when the packaged documentation index is invalid or unavailable."""


def _resource(relative_path: str):
    if not isinstance(relative_path, str) or not relative_path:
        raise DocumentationError("documentation path must be a non-empty string")
    path = Path(relative_path)
    if path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise DocumentationError("documentation paths must be safe relative paths")
    resource = files(_PACKAGE).joinpath(*path.parts)
    if not resource.is_file():
        raise DocumentationError(f"documentation resource is unavailable: {relative_path}")
    return resource


def load_index() -> dict[str, Any]:
    """Return and validate the packaged documentation index."""

    try:
        payload = json.loads(_resource("index.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DocumentationError("cannot read packaged documentation index") from exc
    if not isinstance(payload, dict):
        raise DocumentationError("documentation index must be an object")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise DocumentationError("unsupported documentation index schema")
    if payload.get("product") != "Caretaker":
        raise DocumentationError("documentation index has the wrong product")
    if payload.get("package_version") != __version__:
        raise DocumentationError("documentation package version does not match Caretaker")
    if payload.get("contract_line") != CONTRACT_LINE:
        raise DocumentationError("documentation contract line is invalid")
    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        raise DocumentationError("documentation index has no entries")
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise DocumentationError("documentation entries must be objects")
        for field in (
            "id", "path", "kind", "title", "keywords", "audience",
            "prerequisites", "status", "token_estimate", "related",
            "canonical_sources",
        ):
            if field not in entry:
                raise DocumentationError(f"documentation entry is missing {field!r}")
        identifier = entry["id"]
        path = entry["path"]
        if not isinstance(identifier, str) or not identifier or identifier in seen_ids:
            raise DocumentationError("documentation entry IDs must be non-empty and unique")
        if not isinstance(path, str) or not path or path in seen_paths:
            raise DocumentationError("documentation entry paths must be unique strings")
        if entry["kind"] not in {"start", "global", "task", "reference"}:
            raise DocumentationError(f"unsupported documentation entry kind: {entry['kind']!r}")
        if not all(isinstance(entry[field], list) for field in (
            "keywords", "audience", "prerequisites", "related", "canonical_sources"
        )):
            raise DocumentationError("documentation list fields must be arrays")
        if not isinstance(entry["title"], str) or not entry["title"]:
            raise DocumentationError("documentation titles must be non-empty strings")
        if not isinstance(entry["token_estimate"], int) or isinstance(entry["token_estimate"], bool):
            raise DocumentationError("documentation token estimates must be integers")
        _resource(path)
        seen_ids.add(identifier)
        seen_paths.add(path)
    return payload


def find_entry(identifier: str) -> dict[str, Any]:
    """Find one exact entry ID; prefixes and paths are intentionally rejected."""

    if not isinstance(identifier, str) or not identifier or identifier != identifier.strip():
        raise DocumentationError("task ID must be a non-empty exact ID")
    candidate = Path(identifier)
    if candidate.is_absolute() or ".." in candidate.parts or "/" in identifier or "\\" in identifier:
        raise DocumentationError("task IDs are exact safe relative identifiers, not filesystem paths")
    entries = load_index()["entries"]
    matches = [entry for entry in entries if entry["id"] == identifier]
    if not matches:
        prefix_matches = [entry["id"] for entry in entries if entry["id"].startswith(identifier)]
        if prefix_matches:
            raise DocumentationError(
                "ambiguous or incomplete documentation ID; use one of: "
                + ", ".join(sorted(prefix_matches))
            )
        raise DocumentationError(f"unknown documentation ID: {identifier}")
    return matches[0]


def read_entry(identifier: str) -> tuple[dict[str, Any], str]:
    entry = find_entry(identifier)
    try:
        body = _resource(entry["path"]).read_text(encoding="utf-8")
    except OSError as exc:
        raise DocumentationError(f"cannot read documentation entry: {identifier}") from exc
    return entry, body


@contextmanager
def entry_path(identifier: str) -> Iterator[Path]:
    """Yield a temporary/local filesystem path for an installed resource."""

    entry = find_entry(identifier)
    with as_file(_resource(entry["path"])) as path:
        yield path


__all__ = [
    "CONTRACT_LINE",
    "DocumentationError",
    "SCHEMA_VERSION",
    "entry_path",
    "find_entry",
    "load_index",
    "read_entry",
]
