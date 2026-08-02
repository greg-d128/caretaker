from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


CANONICAL_JSON_VERSION = 1


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the exact UTF-8 representation signed by OpenPGP.

    The V1 format is sorted, compact JSON with a single trailing newline.
    Floats are rejected because cross-language canonicalization is otherwise
    unnecessarily ambiguous for integrity metadata.
    """

    _reject_floats(value)
    text = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return (text + "\n").encode("utf-8")


def write_canonical_json(path: str | Path, value: Mapping[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(canonical_json_bytes(value))


def load_json_object(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def assert_canonical_json(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    value = load_json_object(source)
    expected = canonical_json_bytes(value)
    observed = source.read_bytes()
    if observed != expected:
        raise ValueError(
            f"{source} is not Caretaker canonical JSON V{CANONICAL_JSON_VERSION}; "
            "rewrite it before signing"
        )
    return value


def _reject_floats(value: Any, path: str = "$") -> None:
    if isinstance(value, float):
        raise TypeError(f"Floating-point value is not permitted in canonical metadata at {path}")
    if isinstance(value, Mapping):
        for key, item in value.items():
            _reject_floats(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_floats(item, f"{path}[{index}]")
