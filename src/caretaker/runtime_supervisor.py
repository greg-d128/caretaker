"""Application-runtime ownership boundary for Caretaker supervision.

The implementation currently delegates to the historical logging supervisor
for compatibility.  The public application runtime owns the composition seam
used by ``caretaker.run``; worker health, control, and shutdown internals can
move here incrementally without changing the logging API.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from .logging.supervisor import CaretakerApplicationSupervisor
from .runtime_supervision import (
    AdaptiveAggregationQueueRegistry,
    ApplicationWorkerLifecycle,
    Watchdog,
    WorkRegistry,
    WorkerRegistry,
    run_supervisor_control_cycle,
)


class ApplicationRuntimeSupervisor:
    """Application-scoped runtime owner with compatibility delegation.

    This class does not add authority or host-level process management.  It
    owns the application-runtime entry point and delegates the existing
    behavior until the implementation internals are extracted from the
    logging package.
    """

    def __init__(
        self,
        runtime: Any,
        *,
        application_pid: int | None = None,
        application_process_group_id: int | None = None,
        application_process: Any | None = None,
        acceptance_store: Any | None = None,
        acceptance_store_path: str | Path | None = None,
        failure_store: Any | None = None,
    ) -> None:
        self._implementation = CaretakerApplicationSupervisor(
            runtime,
            application_pid=application_pid,
            application_process_group_id=application_process_group_id,
            application_process=application_process,
            acceptance_store=acceptance_store,
            acceptance_store_path=acceptance_store_path,
            failure_store=failure_store,
        )

    @property
    def implementation(self) -> CaretakerApplicationSupervisor:
        """Return the compatibility implementation for diagnostics only."""

        return self._implementation

    def start(self) -> None:
        self._implementation.start()

    def stop(self) -> None:
        self._implementation.stop()

    def run_control_cycle(
        self,
        *,
        supervisor_time: datetime | None = None,
        on_expired_workers: Callable[[tuple[Any, ...], datetime], Any] | None = None,
        on_cycle: Callable[[datetime], Any] | None = None,
    ) -> dict[str, Any]:
        """Run the application-owned control cycle through the runtime seam."""
        return run_supervisor_control_cycle(
            self._implementation,
            supervisor_time=supervisor_time,
            on_expired_workers=on_expired_workers,
            on_cycle=on_cycle,
        )

    def __getattr__(self, name: str) -> Any:
        # Compatibility for the existing run/control code while ownership is
        # extracted method-by-method. Private implementation details are not
        # exposed through this path.
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self._implementation, name)


__all__ = [
    "AdaptiveAggregationQueueRegistry",
    "ApplicationWorkerLifecycle",
    "ApplicationRuntimeSupervisor",
    "Watchdog",
    "WorkRegistry",
    "WorkerRegistry",
]
