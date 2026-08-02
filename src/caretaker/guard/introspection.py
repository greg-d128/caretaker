from __future__ import annotations

import hashlib
import inspect
import json
import marshal
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from types import FunctionType, ModuleType
from typing import Any
from uuid import uuid4

from ..evidence.identity import identify_function, identify_module
from ..evidence.models import (
    FunctionStateSummary,
    InspectionDifference,
    InspectionDifferenceKind,
    InspectionKind,
    ModuleStateSummary,
    RuntimeInspection,
    utcnow,
)
from ..evidence.store import EvidenceStore


def _hash_object(value: object) -> str:
    try:
        payload = json.dumps(value, sort_keys=True, default=repr).encode("utf-8")
    except Exception:
        payload = repr(value).encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()


def _function_code_hash(function: Callable[..., Any]) -> str | None:
    code = getattr(function, "__code__", None)
    if code is None:
        return None
    try:
        return hashlib.sha256(marshal.dumps(code)).hexdigest()
    except Exception:
        return hashlib.sha256(code.co_code).hexdigest()


def _global_identity(value: object) -> str:
    if isinstance(value, ModuleType):
        return f"module:{value.__name__}:{getattr(value, '__file__', '')}"
    if inspect.isfunction(value) or inspect.ismethod(value):
        return f"callable:{getattr(value, '__module__', '')}:{getattr(value, '__qualname__', '')}:{_function_code_hash(value) or ''}"
    return f"{type(value).__module__}.{type(value).__qualname__}:{id(value)}"


class RuntimeInspector:
    def __init__(self, store: EvidenceStore) -> None:
        self.store = store
        self._load_inspections: dict[str, RuntimeInspection] = {}
        self._previous_inspections: dict[str, RuntimeInspection] = {}
        self._lock = threading.RLock()

    def inspect_module(
        self,
        module: ModuleType,
        *,
        kind: InspectionKind = InspectionKind.PERIODIC,
        behavior_window_id=None,
    ) -> RuntimeInspection:
        identity = identify_module(module)
        state = self._module_state(module)
        runtime_fingerprint = _hash_object(
            {
                "globals": state.global_names,
                "functions": state.function_fingerprints,
                "classes": state.class_names,
                "loader": state.loader_name,
            }
        )
        key = identity.logical_name
        with self._lock:
            load = self._load_inspections.get(key)
            previous = self._previous_inspections.get(key)
        inspection = RuntimeInspection(
            inspection_id=uuid4(),
            subject=identity,
            inspection_kind=kind,
            occurred_at=utcnow(),
            source_fingerprint=identity.source_hash,
            runtime_fingerprint=runtime_fingerprint,
            dependency_fingerprints={},
            module_state_summary=state,
            function_state_summary=None,
            behavior_window_id=behavior_window_id,
            differences_from_load=self._compare_module(load, state, runtime_fingerprint),
            differences_from_previous=self._compare_module(previous, state, runtime_fingerprint),
        )
        with self._lock:
            if kind in {InspectionKind.PRE_LOAD, InspectionKind.POST_LOAD, InspectionKind.CANDIDATE_PROBATION} and load is None:
                self._load_inspections[key] = inspection
            self._previous_inspections[key] = inspection
        self.store.record_code_identity(identity)
        self.store.record_inspection(inspection)
        return inspection

    def inspect_function(
        self,
        function: Callable[..., Any],
        *,
        kind: InspectionKind = InspectionKind.PERIODIC,
        behavior_window_id=None,
        reference_id: str | None = None,
    ) -> RuntimeInspection:
        identity = identify_function(function)
        state = self._function_state(function)
        runtime_fingerprint = _hash_object(
            {
                "bytecode": state.bytecode_hash,
                "defaults": state.defaults_hash,
                "annotations": state.annotations_hash,
                "globals": state.referenced_globals,
            }
        )
        key = reference_id or identity.logical_name
        with self._lock:
            load = self._load_inspections.get(key)
            previous = self._previous_inspections.get(key)
        inspection = RuntimeInspection(
            inspection_id=uuid4(),
            subject=identity,
            inspection_kind=kind,
            occurred_at=utcnow(),
            source_fingerprint=identity.source_hash,
            runtime_fingerprint=runtime_fingerprint,
            dependency_fingerprints=state.referenced_globals,
            module_state_summary=None,
            function_state_summary=state,
            behavior_window_id=behavior_window_id,
            differences_from_load=self._compare_function(load, state, runtime_fingerprint),
            differences_from_previous=self._compare_function(previous, state, runtime_fingerprint),
        )
        with self._lock:
            if kind in {InspectionKind.PRE_LOAD, InspectionKind.POST_LOAD, InspectionKind.CANDIDATE_PROBATION} and load is None:
                self._load_inspections[key] = inspection
            self._previous_inspections[key] = inspection
        self.store.record_code_identity(identity)
        self.store.record_inspection(inspection)
        return inspection

    def _module_state(self, module: ModuleType) -> ModuleStateSummary:
        names = tuple(sorted(name for name in vars(module) if not name.startswith("__")))
        functions = {
            name: _function_code_hash(value) or "unavailable"
            for name, value in vars(module).items()
            if isinstance(value, FunctionType) and getattr(value, "__module__", None) == module.__name__
        }
        classes = tuple(
            sorted(
                name
                for name, value in vars(module).items()
                if inspect.isclass(value) and getattr(value, "__module__", None) == module.__name__
            )
        )
        loader = getattr(getattr(module, "__spec__", None), "loader", None)
        return ModuleStateSummary(
            module_name=module.__name__,
            source_path=getattr(module, "__file__", None),
            loader_name=f"{type(loader).__module__}.{type(loader).__qualname__}" if loader else None,
            global_names=names,
            function_fingerprints=functions,
            class_names=classes,
        )

    def _function_state(self, function: Callable[..., Any]) -> FunctionStateSummary:
        code = getattr(function, "__code__", None)
        referenced: dict[str, str] = {}
        if code is not None:
            globals_dict = getattr(function, "__globals__", {})
            for name in code.co_names:
                if name in globals_dict:
                    referenced[name] = _global_identity(globals_dict[name])
        identity = identify_function(function)
        return FunctionStateSummary(
            module_name=identity.module_name,
            qualified_name=identity.qualified_name or getattr(function, "__name__", "<unknown>"),
            source_hash=identity.source_hash,
            bytecode_hash=identity.bytecode_hash,
            defaults_hash=_hash_object(getattr(function, "__defaults__", None)),
            annotations_hash=_hash_object(getattr(function, "__annotations__", {})),
            referenced_globals=referenced,
        )

    def _compare_module(
        self,
        reference: RuntimeInspection | None,
        current: ModuleStateSummary,
        runtime_fingerprint: str,
    ) -> tuple[InspectionDifference, ...]:
        if reference is None or reference.module_state_summary is None:
            return ()
        before = reference.module_state_summary
        differences: list[InspectionDifference] = []
        if reference.runtime_fingerprint != runtime_fingerprint:
            differences.append(
                InspectionDifference(
                    path="module.runtime_fingerprint",
                    kind=InspectionDifferenceKind.CHANGED,
                    before=reference.runtime_fingerprint,
                    after=runtime_fingerprint,
                )
            )
        added = sorted(set(current.global_names) - set(before.global_names))
        removed = sorted(set(before.global_names) - set(current.global_names))
        for name in added:
            differences.append(InspectionDifference(f"globals.{name}", InspectionDifferenceKind.ADDED, None, name))
        for name in removed:
            differences.append(InspectionDifference(f"globals.{name}", InspectionDifferenceKind.REMOVED, name, None))
        for name in sorted(set(before.function_fingerprints) | set(current.function_fingerprints)):
            old = before.function_fingerprints.get(name)
            new = current.function_fingerprints.get(name)
            if old != new:
                differences.append(
                    InspectionDifference(
                        f"functions.{name}",
                        InspectionDifferenceKind.REPLACED,
                        old,
                        new,
                    )
                )
        return tuple(differences)

    def _compare_function(
        self,
        reference: RuntimeInspection | None,
        current: FunctionStateSummary,
        runtime_fingerprint: str,
    ) -> tuple[InspectionDifference, ...]:
        if reference is None or reference.function_state_summary is None:
            return ()
        before = reference.function_state_summary
        differences: list[InspectionDifference] = []
        fields = (
            ("bytecode", before.bytecode_hash, current.bytecode_hash),
            ("defaults", before.defaults_hash, current.defaults_hash),
            ("annotations", before.annotations_hash, current.annotations_hash),
        )
        for name, old, new in fields:
            if old != new:
                differences.append(
                    InspectionDifference(
                        f"function.{name}",
                        InspectionDifferenceKind.REPLACED,
                        old,
                        new,
                    )
                )
        for name in sorted(set(before.referenced_globals) | set(current.referenced_globals)):
            old = before.referenced_globals.get(name)
            new = current.referenced_globals.get(name)
            if old != new:
                differences.append(
                    InspectionDifference(
                        f"globals.{name}",
                        InspectionDifferenceKind.REPLACED,
                        old,
                        new,
                    )
                )
        if reference.runtime_fingerprint != runtime_fingerprint and not differences:
            differences.append(
                InspectionDifference(
                    "function.runtime_fingerprint",
                    InspectionDifferenceKind.CHANGED,
                    reference.runtime_fingerprint,
                    runtime_fingerprint,
                )
            )
        return tuple(differences)


@dataclass
class PeriodicInspectionTarget:
    key: str
    module_name: str | None = None
    function: Callable[..., Any] | None = None
    function_resolver: Callable[[], Callable[..., Any]] | None = None
    interval_seconds: float = 600.0
    next_due: float = 0.0


class PeriodicInspector:
    def __init__(
        self,
        inspector: RuntimeInspector,
        *,
        on_inspection: Callable[[RuntimeInspection], None] | None = None,
    ) -> None:
        self.inspector = inspector
        self.on_inspection = on_inspection
        self._targets: dict[str, PeriodicInspectionTarget] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()

    def register_module(self, module_name: str, *, interval_seconds: float = 600.0) -> None:
        with self._lock:
            self._targets[f"module:{module_name}"] = PeriodicInspectionTarget(
                key=f"module:{module_name}",
                module_name=module_name,
                interval_seconds=interval_seconds,
            )

    def register_function(self, function: Callable[..., Any], *, interval_seconds: float = 600.0) -> None:
        key = f"function:{function.__module__}:{function.__qualname__}"
        with self._lock:
            self._targets[key] = PeriodicInspectionTarget(
                key=key,
                function=function,
                interval_seconds=interval_seconds,
            )

    def register_function_resolver(
        self,
        key: str,
        resolver: Callable[[], Callable[..., Any]],
        *,
        interval_seconds: float = 600.0,
    ) -> None:
        with self._lock:
            self._targets[key] = PeriodicInspectionTarget(
                key=key,
                function_resolver=resolver,
                interval_seconds=interval_seconds,
            )

    def inspect_now(self) -> tuple[RuntimeInspection, ...]:
        inspections: list[RuntimeInspection] = []
        with self._lock:
            targets = tuple(self._targets.values())
        for target in targets:
            inspection: RuntimeInspection | None = None
            function = target.function_resolver() if target.function_resolver is not None else target.function
            if function is not None:
                inspection = self.inspector.inspect_function(function)
            elif target.module_name and target.module_name in sys.modules:
                inspection = self.inspector.inspect_module(sys.modules[target.module_name])
            if inspection is not None:
                inspections.append(inspection)
                if self.on_inspection is not None:
                    self.on_inspection(inspection)
        return tuple(inspections)

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="caretaker-periodic-inspector", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        import time

        while not self._stop.wait(0.25):
            now = time.monotonic()
            with self._lock:
                targets = tuple(self._targets.values())
            for target in targets:
                if target.next_due > now:
                    continue
                inspection: RuntimeInspection | None = None
                function = target.function_resolver() if target.function_resolver is not None else target.function
                if function is not None:
                    inspection = self.inspector.inspect_function(function)
                elif target.module_name and target.module_name in sys.modules:
                    inspection = self.inspector.inspect_module(sys.modules[target.module_name])
                target.next_due = now + max(0.1, target.interval_seconds)
                if inspection is not None and self.on_inspection is not None:
                    self.on_inspection(inspection)
