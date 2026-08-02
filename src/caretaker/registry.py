from __future__ import annotations

import hashlib
import inspect
import textwrap
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any

from .domain import (
    CallableContract,
    CallableKind,
    RegisteredCase,
    SourceLocation,
    TargetCapability,
    TargetSupportAssessment,
)
from .integrity.models import IntegrityClass
from .logging.masking import MaskFunction
from .policy import RepairPolicy, validate_policy
from .slot import FunctionSlot


@dataclass(frozen=True, slots=True)
class RepairTarget:
    target_id: str
    display_name: str
    source: SourceLocation
    contract: CallableContract
    support: TargetSupportAssessment
    policy: RepairPolicy
    slot: FunctionSlot
    registered_cases: tuple[RegisteredCase, ...] = ()
    tags: frozenset[str] = frozenset()
    metadata: Mapping[str, str] = field(default_factory=dict)
    integrity_class: IntegrityClass = IntegrityClass.ORDINARY
    mask_function: MaskFunction | None = None


class TargetRegistry:
    def __init__(self) -> None:
        self._targets: dict[str, RepairTarget] = {}
        self._lock = RLock()

    def register(self, target: RepairTarget) -> None:
        with self._lock:
            existing = self._targets.get(target.target_id)
            if existing is not None and existing.slot is not target.slot:
                raise ValueError(f"Target already registered: {target.target_id}")
            self._targets[target.target_id] = target

    def get(self, target_id: str) -> RepairTarget:
        with self._lock:
            return self._targets[target_id]

    def find(self, target_id: str | None) -> RepairTarget | None:
        if target_id is None:
            return None
        with self._lock:
            return self._targets.get(target_id)

    def all(self) -> tuple[RepairTarget, ...]:
        with self._lock:
            return tuple(self._targets.values())


def build_target(
    function: Callable[..., Any],
    *,
    policy: RepairPolicy,
    target_id: str | None = None,
    registered_cases: tuple[RegisteredCase, ...] = (),
    tags: frozenset[str] = frozenset(),
    metadata: Mapping[str, str] | None = None,
    integrity_class: IntegrityClass = IntegrityClass.ORDINARY,
    mask_function: MaskFunction | None = None,
) -> RepairTarget:
    validate_policy(policy)
    resolved_id = target_id or f"{function.__module__}:{function.__qualname__}"
    try:
        source_text = textwrap.dedent(inspect.getsource(function))
        source_hash = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    except (OSError, TypeError):
        source_text = None
        source_hash = None

    source_file = inspect.getsourcefile(function)
    try:
        _, first_line = inspect.getsourcelines(function)
    except (OSError, TypeError):
        first_line = None

    is_async = inspect.iscoroutinefunction(function)
    is_generator = inspect.isgeneratorfunction(function)
    is_async_generator = inspect.isasyncgenfunction(function)

    if is_async_generator:
        kind = CallableKind.ASYNC_GENERATOR
    elif is_generator:
        kind = CallableKind.GENERATOR
    elif is_async:
        kind = CallableKind.COROUTINE
    elif "." in function.__qualname__ and "<locals>" not in function.__qualname__:
        kind = CallableKind.INSTANCE_METHOD
    else:
        kind = CallableKind.FUNCTION

    reasons: list[str] = []
    capability = TargetCapability.REPAIRABLE
    if function.__module__ == "caretaker" or function.__module__.startswith("caretaker."):
        capability = TargetCapability.DIAGNOSTIC_ONLY
        reasons.append("Caretaker internal code is never eligible for generated self-modification.")
    if "<locals>" in function.__qualname__:
        capability = TargetCapability.DIAGNOSTIC_ONLY
        reasons.append("Nested functions and closures are diagnostic-only in V1.")
    if function.__closure__:
        capability = TargetCapability.DIAGNOSTIC_ONLY
        reasons.append("Closure reconstruction is not supported in V1.")
    if is_async or is_generator or is_async_generator:
        capability = TargetCapability.DIAGNOSTIC_ONLY
        reasons.append("V1 repair execution supports synchronous non-generator callables only.")
    if source_text is None:
        capability = TargetCapability.DIAGNOSTIC_ONLY
        reasons.append("Python source is unavailable.")
    if integrity_class is IntegrityClass.SEALED:
        capability = TargetCapability.DIAGNOSTIC_ONLY
        reasons.append("Sealed integrity targets prohibit generated activation.")
    elif (
        integrity_class is IntegrityClass.PROTECTED
        and not policy.integrity.allow_protected_automatic_repair
    ):
        capability = TargetCapability.DIAGNOSTIC_ONLY
        reasons.append("Protected integrity targets are diagnostic-only by default.")
    if not reasons:
        reasons.append("Synchronous Python callable with retrievable source.")

    annotations = {
        str(key): _annotation_text(value)
        for key, value in getattr(function, "__annotations__", {}).items()
    }
    slot = FunctionSlot(
        target_id=resolved_id,
        original=function,
        original_source=source_text,
        original_source_hash=source_hash,
    )
    return RepairTarget(
        target_id=resolved_id,
        display_name=function.__qualname__,
        source=SourceLocation(
            module_name=function.__module__,
            qualified_name=function.__qualname__,
            filename=Path(source_file) if source_file else None,
            first_line_number=first_line,
        ),
        contract=CallableContract(
            kind=kind,
            signature_text=str(inspect.signature(function)),
            is_async=is_async,
            is_generator=is_generator,
            is_async_generator=is_async_generator,
            annotations=annotations,
        ),
        support=TargetSupportAssessment(capability=capability, reasons=tuple(reasons)),
        policy=policy,
        slot=slot,
        registered_cases=registered_cases,
        tags=tags,
        metadata=metadata or {},
        integrity_class=integrity_class,
        mask_function=mask_function,
    )


def _annotation_text(value: object) -> str:
    if isinstance(value, str):
        return value
    return getattr(value, "__qualname__", repr(value))
