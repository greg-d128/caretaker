from __future__ import annotations

import json
import sys
from dataclasses import replace
import threading
from pathlib import Path
from threading import RLock
from types import TracebackType
from typing import Any
from uuid import UUID, uuid4

from .domain import InternalIncident, utcnow
from .registry import TargetRegistry
from .runtime import snapshot_context
from .state import exception_evidence, value_snapshot
from .store import RepairPostmortemStore, _jsonable
from .telemetry import CorrelatedLogHandler, logger


class PostMortemRecorder:
    def __init__(
        self,
        *,
        store: RepairPostmortemStore,
        registry: TargetRegistry,
        log_handler: CorrelatedLogHandler | None = None,
        emergency_path: str | Path = ".caretaker/emergency/internal-incidents.jsonl",
    ) -> None:
        self.store = store
        self.registry = registry
        self.log_handler = log_handler
        self.emergency_path = Path(emergency_path)
        self._lock = RLock()
        self._active = False

    def capture(
        self,
        internal_exception: BaseException,
        *,
        component: str,
        operation: str,
        original_exception: BaseException | None = None,
        original_incident_id: UUID | None = None,
    ) -> InternalIncident | None:
        with self._lock:
            if self._active:
                self._emergency_stderr(
                    f"recursive post-mortem failure: {type(internal_exception).__name__}: {internal_exception}"
                )
                return None
            self._active = True
        errors: list[str] = []
        try:
            context = snapshot_context()
            target_id = context.get("target_id")
            target = self.registry.find(target_id if isinstance(target_id, str) else None)
            slot_states = (target.slot.snapshot(),) if target else ()
            active_context = {
                key: value_snapshot(value, name=key)
                for key, value in context.items()
            }
            recent_events = self.store.recent_events(
                target_id if isinstance(target_id, str) else None,
                limit=100,
            )
            recent_logs = (
                self.log_handler.recent(
                    target_id=target_id if isinstance(target_id, str) else None,
                    limit=200,
                )
                if self.log_handler
                else ()
            )
            record = InternalIncident(
                internal_incident_id=uuid4(),
                occurred_at=utcnow(),
                component=component,
                operation=operation,
                active_target_id=target_id if isinstance(target_id, str) else None,
                active_incident_id=_as_uuid(context.get("incident_id")),
                active_episode_id=_as_uuid(context.get("episode_id")),
                active_attempt_id=_as_uuid(context.get("attempt_id")),
                active_candidate_id=_as_uuid(context.get("candidate_id")),
                exception=exception_evidence(internal_exception, capture_locals=True),
                slot_states=slot_states,
                active_context=active_context,
                recent_events=recent_events,
                recent_logs=recent_logs,
                original_application_incident_id=original_incident_id,
                original_application_exception=(
                    exception_evidence(original_exception, capture_locals=False)
                    if original_exception
                    else None
                ),
                post_mortem_complete=True,
                post_mortem_errors=(),
            )
            try:
                self.store.record_internal_incident(record)
            except Exception as exc:
                errors.append(f"primary store failed: {type(exc).__name__}: {exc}")
            try:
                self._write_emergency(record)
            except Exception as exc:
                errors.append(f"emergency store failed: {type(exc).__name__}: {exc}")
            if errors:
                record = replace(
                    record,
                    post_mortem_complete=False,
                    post_mortem_errors=tuple(errors),
                )
            self._emergency_stderr(
                f"Caretaker internal incident {record.internal_incident_id}: "
                f"{type(internal_exception).__name__}: {internal_exception}"
            )
            return record
        except BaseException as exc:
            self._emergency_stderr(
                f"post-mortem capture failed: {type(exc).__name__}: {exc}; "
                f"original internal failure: {type(internal_exception).__name__}: {internal_exception}"
            )
            return None
        finally:
            with self._lock:
                self._active = False

    def _write_emergency(self, record: InternalIncident) -> None:
        self.emergency_path.parent.mkdir(parents=True, exist_ok=True)
        with self.emergency_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(_jsonable(record), sort_keys=True, allow_nan=False) + "\n")

    @staticmethod
    def _emergency_stderr(message: str) -> None:
        try:
            sys.stderr.write(message + "\n")
            sys.stderr.flush()
        except Exception:
            pass


class ExceptionHookManager:
    def __init__(self, recorder: PostMortemRecorder) -> None:
        self.recorder = recorder
        self._previous_sys = None
        self._previous_threading = None
        self._previous_unraisable = None

    def install(self) -> None:
        if self._previous_sys is not None:
            return
        self._previous_sys = sys.excepthook
        self._previous_threading = threading.excepthook
        self._previous_unraisable = sys.unraisablehook

        def sys_hook(exc_type: type[BaseException], exc: BaseException, tb: TracebackType | None) -> None:
            self.recorder.capture(exc, component="global-hook", operation="sys.excepthook")
            assert self._previous_sys is not None
            self._previous_sys(exc_type, exc, tb)

        def threading_hook(args: threading.ExceptHookArgs) -> None:
            self.recorder.capture(
                args.exc_value,
                component="global-hook",
                operation="threading.excepthook",
            )
            assert self._previous_threading is not None
            self._previous_threading(args)

        def unraisable_hook(args: sys.UnraisableHookArgs) -> None:
            if args.exc_value is not None:
                self.recorder.capture(
                    args.exc_value,
                    component="global-hook",
                    operation="sys.unraisablehook",
                )
            assert self._previous_unraisable is not None
            self._previous_unraisable(args)

        sys.excepthook = sys_hook
        threading.excepthook = threading_hook
        sys.unraisablehook = unraisable_hook

    def uninstall(self) -> None:
        if self._previous_sys is None:
            return
        sys.excepthook = self._previous_sys
        threading.excepthook = self._previous_threading
        sys.unraisablehook = self._previous_unraisable
        self._previous_sys = None
        self._previous_threading = None
        self._previous_unraisable = None


def _as_uuid(value: object) -> UUID | None:
    return value if isinstance(value, UUID) else None
