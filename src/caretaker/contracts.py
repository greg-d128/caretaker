from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .domain import ComparisonResult, ValidationResult


Validator = Callable[[Any], bool | ValidationResult]
Comparator = Callable[[Any, Any], bool | ComparisonResult | ValidationResult]


def normalize_validation_result(
    value: bool | ValidationResult,
    *,
    false_reason: str = "validator returned false",
) -> ValidationResult:
    if isinstance(value, ValidationResult):
        return value
    if value is True:
        return ValidationResult(valid=True)
    if value is False:
        return ValidationResult(valid=False, reason=false_reason)
    raise TypeError(
        "A Caretaker validator must return bool or ValidationResult; "
        f"received {type(value).__module__}.{type(value).__qualname__}"
    )


def normalize_comparison_result(
    value: bool | ComparisonResult | ValidationResult,
    *,
    false_reason: str = "comparator reported non-equivalent outputs",
) -> ComparisonResult:
    if isinstance(value, ComparisonResult):
        return value
    if isinstance(value, ValidationResult):
        return ComparisonResult(
            equivalent=value.valid,
            reason=value.reason,
            evidence=value.evidence,
        )
    if value is True:
        return ComparisonResult(equivalent=True)
    if value is False:
        return ComparisonResult(equivalent=False, reason=false_reason)
    raise TypeError(
        "A Caretaker comparator must return bool, ValidationResult, or "
        f"ComparisonResult; received {type(value).__module__}.{type(value).__qualname__}"
    )


def evidence_text(evidence: Mapping[str, Any]) -> str:
    if not evidence:
        return ""
    return ", ".join(f"{key}={value!r}" for key, value in evidence.items())
