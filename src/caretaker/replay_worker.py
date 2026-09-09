"""JSON-only worker used by isolated historical replay backends."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

from .validation import assess_candidate_source, sanitized_function_tree
from .validation_worker import _install_validation_audit_hook, validate_structure


def _json_exact(value: Any, *, depth: int = 0) -> bool:
    if depth > 6:
        return False
    if value is None or isinstance(value, (bool, int, str)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_json_exact(item, depth=depth + 1) for item in value)
    if isinstance(value, dict):
        if any(key in {"redacted", "truncated", "representation", "<truncated_items>"} for key in value):
            return False
        return all(
            isinstance(key, str) and _json_exact(item, depth=depth + 1)
            for key, item in value.items()
        )
    return False


def run_payload(payload: dict[str, Any]) -> dict[str, Any]:
    source = payload.get("source")
    entrypoint = payload.get("entrypoint")
    args = payload.get("args")
    kwargs = payload.get("kwargs")
    expected = payload.get("expected")
    if not isinstance(source, str) or not isinstance(entrypoint, str):
        return {"outcome": "ERROR", "error": "source and entrypoint are required"}
    if not isinstance(args, list) or not isinstance(kwargs, dict) or not _json_exact(expected):
        return {"outcome": "ERROR", "error": "replay inputs are not exact JSON values"}
    if not _json_exact(args) or not _json_exact(kwargs):
        return {"outcome": "ERROR", "error": "replay inputs are not exact JSON values"}
    assessment = assess_candidate_source(source)
    if assessment.hard_disqualifications or assessment.review_required_findings:
        return {
            "outcome": "ERROR",
            "error": "replay subject source failed static safety checks",
        }
    try:
        validate_structure(source, entrypoint, False)
        safe_tree = sanitized_function_tree(source)
        compiled = compile(safe_tree, "<caretaker-replay>", "exec", dont_inherit=True)
        namespace: dict[str, Any] = {"__name__": "__caretaker_replay__"}
        exec(compiled, namespace, namespace)
        function = namespace[entrypoint]
        result = function(*args, **kwargs)
    except BaseException as exc:
        return {
            "outcome": "FAILED",
            "error": f"{type(exc).__name__}: {exc}",
        }
    if not _json_exact(result):
        return {"outcome": "ERROR", "error": "replay output is not an exact JSON value"}
    return {
        "outcome": "PASSED" if result == expected else "FAILED",
        "output": result,
        "expected": expected,
        **({"error": "replay output differed from expected"} if result != expected else {}),
    }


def main(argv: list[str] | None = None) -> int:
    arguments = list(argv if argv is not None else sys.argv[1:])
    if len(arguments) != 2:
        raise SystemExit("usage: python -m caretaker.replay_worker REQUEST.json RESULT.json")
    request_path, result_path = (Path(item) for item in arguments)
    try:
        payload = json.loads(request_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            _install_validation_audit_hook(payload, result_path)
        result = run_payload(payload) if isinstance(payload, dict) else {
            "outcome": "ERROR",
            "error": "replay request must be a JSON object",
        }
    except BaseException as exc:
        result = {"outcome": "ERROR", "error": f"{type(exc).__name__}: {exc}"}
    result_path.write_text(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False), encoding="utf-8")
    return 0 if result.get("outcome") in {"PASSED", "FAILED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
