"""Strict primitive validators shared by Caretaker trust boundaries."""

from __future__ import annotations

import math
import dataclasses
from collections.abc import Iterable
from enum import Enum
from typing import TypeVar
from uuid import UUID


EnumT = TypeVar("EnumT", bound=Enum)


def exact_bool(value: object, *, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def integer(value: object, *, name: str, minimum: int | None = None, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be at most {maximum}")
    return value


def finite_number(
    value: object,
    *,
    name: str,
    minimum: float | None = None,
    maximum: float | None = None,
) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number")
    numeric = float(value)
    if not math.isfinite(numeric):
        raise ValueError(f"{name} must be finite")
    if minimum is not None and numeric < minimum:
        raise ValueError(f"{name} must be at least {minimum:g}")
    if maximum is not None and numeric > maximum:
        raise ValueError(f"{name} must be at most {maximum:g}")
    return value


def bounded_text(value: object, *, name: str, maximum: int, required: bool = True) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be text")
    result = value.strip()
    if required and not result:
        raise ValueError(f"{name} is required")
    if len(result) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")
    return result


def uuid_text(value: object, *, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a UUID string")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a UUID string") from exc
    if str(parsed) != value:
        raise ValueError(f"{name} must use canonical UUID formatting")
    return value


def enum_value(enum_type: type[EnumT], value: object, *, name: str) -> EnumT:
    if isinstance(value, enum_type):
        return value
    raise ValueError(f"{name} must be a {enum_type.__name__}")


def string_sequence(value: object, *, name: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise ValueError(f"{name} must be a sequence of strings")
    result = tuple(value)
    if any(not isinstance(item, str) for item in result):
        raise ValueError(f"{name} must be a sequence of strings")
    return result


def declared_primitive_errors(value: object, *, prefix: str) -> tuple[str, ...]:
    """Check dataclass fields whose defaults declare bool/int/float primitives."""
    errors: list[str] = []

    def visit(current: object, path: str) -> None:
        if not dataclasses.is_dataclass(current):
            return
        for item in dataclasses.fields(current):
            name = f"{path}.{item.name}"
            field_value = getattr(current, item.name)
            try:
                if isinstance(item.default, bool):
                    exact_bool(field_value, name=name)
                elif isinstance(item.default, float):
                    finite_number(field_value, name=name)
                elif isinstance(item.default, int) and not isinstance(item.default, bool):
                    integer(field_value, name=name)
            except ValueError as exc:
                errors.append(str(exc))
            visit(field_value, name)

    visit(value, prefix)
    return tuple(errors)


__all__ = [
    "bounded_text",
    "declared_primitive_errors",
    "enum_value",
    "exact_bool",
    "finite_number",
    "integer",
    "string_sequence",
    "uuid_text",
]
