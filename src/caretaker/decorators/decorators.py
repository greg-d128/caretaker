"""Compatibility imports for the original Caretaker decorator module."""

from __future__ import annotations

import functools
import warnings
from collections.abc import Callable
from typing import Any, TypeVar

from .api import repair

F = TypeVar("F", bound=Callable[..., Any])


def input_validator(*required_params: object) -> Callable[[F], F]:
    """Preserve the original parameter-presence decorator with metadata intact."""

    def decorator(function: F) -> F:
        @functools.wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            available = list(args) + list(kwargs.values())
            for parameter in required_params:
                if parameter not in available:
                    raise ValueError(f"Missing required parameter: {parameter}")
            return function(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


def exception_handler(function: F) -> F:
    """Deprecated compatibility alias for the policy-driven `repair` decorator."""

    warnings.warn(
        "caretaker.decorators.decorators.exception_handler is deprecated; "
        "use caretaker.repair with an explicit RepairPolicy.",
        DeprecationWarning,
        stacklevel=2,
    )
    return repair(function)
