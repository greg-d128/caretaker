"""Application-runtime ownership boundary for Caretaker supervision.

The implementation currently delegates to the historical logging supervisor
for compatibility.  The public application runtime owns the composition seam
used by ``caretaker.run``; worker health, control, and shutdown internals can
move here incrementally without changing the logging API.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
import signal
from pathlib import Path
from typing import Any

from .logging.supervisor import CaretakerApplicationSupervisor
from .runtime_supervision import (
    AdaptiveAggregationQueueRegistry,
    ApplicationWorkerLifecycle,
    capture_worker_failure_evidence,
    Watchdog,
    WorkRegistry,
    WorkerRegistry,
    monitor_application,
    run_supervisor_control_cycle,
    stop_application,
    stop_runtime_supervisor,
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
        stop_runtime_supervisor(self._implementation)

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

    def capture_worker_failure_evidence(
        self,
        worker: Any,
        *,
        diagnostic_debug: bool | None = None,
        critical_evidence: bool = False,
        collect_postmortem: Callable[[Any, Any], Any] | None = None,
        require_complete_postmortem: bool = False,
        reconciliation_scope: str | None = None,
    ) -> dict[str, Any]:
        """Persist one rollback envelope through the runtime seam."""
        return capture_worker_failure_evidence(
            self._implementation,
            worker,
            diagnostic_debug=diagnostic_debug,
            critical_evidence=critical_evidence,
            collect_postmortem=collect_postmortem,
            require_complete_postmortem=require_complete_postmortem,
            reconciliation_scope=reconciliation_scope,
        )

    def monitor_application(
        self,
        *,
        interval_seconds: float = 1.0,
        on_expired_workers: Callable[[tuple[Any, ...], datetime], Any] | None = None,
        on_cycle: Callable[[datetime], Any] | None = None,
    ) -> None:
        """Monitor the application boundary through the runtime seam."""
        return monitor_application(
            self._implementation,
            interval_seconds=interval_seconds,
            on_expired_workers=on_expired_workers,
            on_cycle=on_cycle,
        )

    def stop_application(
        self,
        *,
        graceful_signal: int = signal.SIGTERM,
        timeout_seconds: float = 10.0,
    ) -> dict[str, object]:
        """Stop the application boundary through the runtime seam."""
        return stop_application(
            self._implementation,
            graceful_signal=graceful_signal,
            timeout_seconds=timeout_seconds,
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
