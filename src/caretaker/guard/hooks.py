from __future__ import annotations

import sys
import threading
from types import TracebackType
from typing import Any
from uuid import UUID

from ..control_plane import (
    RuntimeControlPlane,
    RuntimeSignal,
    SignalDomain,
    SignalSeverity,
)
from ..evidence.identity import identify_module
from ..evidence.models import InspectionKind
from ..runtime import snapshot_context
from .introspection import RuntimeInspector


class GuardHookManager:
    """Normalize global/system failures into control-plane signals.

    Hook handlers capture and inspect only. They do not call an LLM or perform a
    synchronous repair while Python is already unwinding an unhandled failure.
    """

    def __init__(
        self,
        *,
        run_id: UUID,
        control_plane: RuntimeControlPlane,
        inspector: RuntimeInspector,
    ) -> None:
        self.run_id = run_id
        self.control_plane = control_plane
        self.inspector = inspector
        self._previous_sys = sys.excepthook
        self._previous_threading = threading.excepthook
        self._previous_unraisable = sys.unraisablehook
        self._installed = False

    def install(self) -> None:
        if self._installed:
            return
        self._previous_sys = sys.excepthook
        self._previous_threading = threading.excepthook
        self._previous_unraisable = sys.unraisablehook
        sys.excepthook = self._sys_hook
        threading.excepthook = self._thread_hook
        sys.unraisablehook = self._unraisable_hook
        self._installed = True

    def uninstall(self) -> None:
        if not self._installed:
            return
        sys.excepthook = self._previous_sys
        threading.excepthook = self._previous_threading
        sys.unraisablehook = self._previous_unraisable
        self._installed = False

    def _sys_hook(
        self,
        exception_type: type[BaseException],
        exception: BaseException,
        traceback: TracebackType | None,
    ) -> None:
        self._capture("sys.excepthook", exception, traceback)
        self._previous_sys(exception_type, exception, traceback)

    def _thread_hook(self, args: threading.ExceptHookArgs) -> None:
        self._capture("threading.excepthook", args.exc_value, args.exc_traceback)
        self._previous_threading(args)

    def _unraisable_hook(self, args: sys.UnraisableHookArgs) -> None:
        exception = args.exc_value or RuntimeError(args.err_msg or "unraisable exception")
        self._capture("sys.unraisablehook", exception, args.exc_traceback)
        self._previous_unraisable(args)

    def _capture(
        self,
        hook_name: str,
        exception: BaseException,
        traceback: TracebackType | None,
    ) -> None:
        context = snapshot_context()
        module_name = None
        inspection_id = None
        cursor = traceback
        while cursor is not None:
            name = cursor.tb_frame.f_globals.get("__name__")
            if isinstance(name, str) and not name.startswith("caretaker"):
                module_name = name
            cursor = cursor.tb_next
        identity = identify_module(module_name) if module_name else None
        if module_name and module_name in sys.modules:
            try:
                inspection = self.inspector.inspect_module(
                    sys.modules[module_name],
                    kind=InspectionKind.EVENT_DRIVEN,
                )
                inspection_id = inspection.inspection_id
            except Exception:
                inspection_id = None
        signal = RuntimeSignal.create(
            domain=SignalDomain.FAILURE,
            kind=hook_name,
            severity=SignalSeverity.HIGH,
            run_id=self.run_id,
            source_component="guard.system-hooks",
            call_id=context.get("call_id"),
            target_id=context.get("target_id"),
            module_identity=identity,
            evidence_refs=((inspection_id,) if inspection_id else ()),
            attributes={
                "exception_type": type(exception).__name__,
                "exception_message": str(exception),
                "post_mortem_only": True,
            },
        )
        self.control_plane.submit(signal)
