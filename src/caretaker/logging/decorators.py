from __future__ import annotations

import functools
import inspect
import logging
import time
from typing import Any, Callable, Mapping, TypeVar
from uuid import uuid4

from ..runtime import set_runtime_context
from .handler import get_runtime
from .masking import MaskFunction, apply_mask
from .models import LogChannel

F = TypeVar("F", bound=Callable[..., Any])


def _population_designator(
    function: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
    *,
    baseline_dimensions: tuple[str, ...],
    population_key: Callable[[inspect.BoundArguments], Mapping[str, Any] | str] | None,
) -> str | None:
    if not baseline_dimensions and population_key is None:
        return None
    bound = inspect.signature(function).bind_partial(*args, **kwargs)
    bound.apply_defaults()
    if population_key is not None:
        value = population_key(bound)
    else:
        value = {name: bound.arguments.get(name) for name in baseline_dimensions}
    return repr(value)


def logged(
    function: F | None = None,
    *,
    timing: bool = True,
    exceptions: bool = True,
    arguments: bool = False,
    result: bool = False,
    mask: MaskFunction | None = None,
    baseline_dimensions: tuple[str, ...] = (),
    population_key: Callable[[inspect.BoundArguments], Mapping[str, Any] | str] | None = None,
    target_id: str | None = None,
) -> F | Callable[[F], F]:
    """Add call-correlated Caretaker logging without enabling Guard or Repair."""

    def decorate(original: F) -> F:
        resolved_target = target_id or f"{original.__module__}:{original.__qualname__}"

        @functools.wraps(original)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            runtime = get_runtime()
            call_id = uuid4()
            tokens = set_runtime_context(target_id=resolved_target, call_id=call_id, operation="logged-function-call")
            started = time.perf_counter()
            masked = apply_mask(mask, args, kwargs)
            population = _population_designator(
                original, masked.masked_args, masked.masked_kwargs,
                baseline_dimensions=baseline_dimensions, population_key=population_key,
            )
            if runtime is not None:
                fields: dict[str, Any] = {
                    "event": "function.call.started",
                    "population_designator": population,
                    "masking": {
                        "fully_removed_fields": masked.fully_removed_fields,
                        "format_preserved_fields": masked.format_preserved_fields,
                        "structural_metadata": masked.structural_metadata,
                    },
                }
                active_policy = runtime.active_policy
                if arguments or active_policy.capture.capture_arguments:
                    fields["args"] = masked.masked_args
                    fields["kwargs"] = masked.masked_kwargs
                runtime.event(
                    logger_name=original.__module__, severity=logging.DEBUG,
                    channel=LogChannel.APPLICATION, message=f"Calling {resolved_target}", fields=fields,
                )
            try:
                output = original(*args, **kwargs)
            except BaseException as exc:
                if runtime is not None and exceptions:
                    runtime.event(
                        logger_name=original.__module__, severity=logging.ERROR,
                        channel=LogChannel.APPLICATION, message=f"{resolved_target} raised {type(exc).__name__}",
                        fields={
                            "event": "function.call.failed",
                            "exception_type": type(exc).__name__,
                            "exception_message": str(exc),
                            "elapsed_seconds": time.perf_counter() - started if timing else None,
                            "population_designator": population,
                        },
                    )
                raise
            else:
                if runtime is not None:
                    fields = {
                        "event": "function.call.completed",
                        "elapsed_seconds": time.perf_counter() - started if timing else None,
                        "population_designator": population,
                    }
                    active_policy = runtime.active_policy
                    if result or active_policy.capture.capture_results:
                        fields["result"] = repr(output)[:active_policy.capture.maximum_value_characters]
                    runtime.event(
                        logger_name=original.__module__, severity=logging.DEBUG,
                        channel=LogChannel.APPLICATION, message=f"Completed {resolved_target}", fields=fields,
                    )
                return output
            finally:
                tokens.reset()

        setattr(wrapper, "__caretaker_mask__", mask)
        setattr(wrapper, "__caretaker_population_key__", population_key)
        setattr(wrapper, "__caretaker_baseline_dimensions__", baseline_dimensions)
        return wrapper  # type: ignore[return-value]

    return decorate(function) if function is not None else decorate
