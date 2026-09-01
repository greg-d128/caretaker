"""Application-runtime scheduling and health-monitoring primitives.

These primitives are owned by the application runtime.  The logging package
re-exports them temporarily for compatibility with existing integrations, but
their implementation must not depend on logging internals.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import UUID, uuid4

from .adaptive_aggregation import QueueAdaptiveAggregationStore
from .logging.models import (
    ActiveWork,
    CaretakerComponent,
    WorkState,
    WorkerHealth,
    WorkerState,
)


MAX_ADAPTIVE_QUEUE_WORKERS = 128


class WorkRegistry:
    """Bounded in-memory registry for application-runtime work."""

    def __init__(self, *, recent_seconds: float = 60.0) -> None:
        self.recent_seconds = recent_seconds
        self._active: dict[UUID, ActiveWork] = {}
        self._recent: dict[UUID, ActiveWork] = {}
        self._lock = threading.RLock()

    def start(
        self,
        *,
        component: CaretakerComponent,
        work_kind: str,
        scope: str,
        root_signal_id: UUID,
        expected_code_fingerprints: Mapping[str, str] | None = None,
        parent_work_id: UUID | None = None,
    ) -> ActiveWork:
        work = ActiveWork(
            work_id=uuid4(), component=component, work_kind=work_kind, scope=scope,
            started_at=datetime.now(timezone.utc), expected_completion_at=None,
            current_state=WorkState.ACTIVE,
            expected_code_fingerprints=dict(expected_code_fingerprints or {}),
            parent_work_id=parent_work_id, root_signal_id=root_signal_id,
        )
        with self._lock:
            self._active[work.work_id] = work
        return work

    def finish(self, work_id: UUID, *, state: WorkState = WorkState.COMPLETED) -> ActiveWork:
        with self._lock:
            work = self._active.pop(work_id)
            completed = replace(
                work, current_state=state,
                recently_changed_until=datetime.now(timezone.utc) + timedelta(seconds=self.recent_seconds),
            )
            self._recent[work_id] = completed
            return completed

    def overlapping(self, scope: str) -> tuple[ActiveWork, ...]:
        self.expire_recent()
        with self._lock:
            return tuple(
                item for item in (*self._active.values(), *self._recent.values())
                if scope == item.scope or scope.startswith(item.scope + ".") or item.scope.startswith(scope + ".")
            )

    def all(self) -> tuple[ActiveWork, ...]:
        self.expire_recent()
        with self._lock:
            return tuple((*self._active.values(), *self._recent.values()))

    def expire_recent(self) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            for work_id, work in tuple(self._recent.items()):
                if work.recently_changed_until and work.recently_changed_until <= now:
                    self._recent.pop(work_id, None)


class Watchdog:
    """Application-runtime health monitor with bounded callback delivery."""

    def __init__(
        self,
        registry: Any,
        *,
        on_unhealthy: Callable[[WorkerHealth], None],
        interval_seconds: float = 2.0,
    ) -> None:
        self.registry = registry
        self.on_unhealthy = on_unhealthy
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="caretaker-watchdog", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        seen: set[UUID] = set()
        while not self._stop.wait(self.interval_seconds):
            unhealthy = self.registry.unhealthy()
            for worker in unhealthy:
                if worker.worker_id not in seen:
                    self.on_unhealthy(worker)
                    seen.add(worker.worker_id)
            healthy = {
                item.worker_id
                for item in self.registry.all()
                if item not in self.registry.unhealthy()
            }
            seen.intersection_update(set(item.worker_id for item in self.registry.all()) - healthy)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)


class AdaptiveAggregationQueueRegistry:
    """Own application-worker queue bindings used by supervisor cycles."""

    def __init__(
        self,
        *,
        worker_lookup: Callable[[UUID], WorkerHealth],
        maximum_workers: int = MAX_ADAPTIVE_QUEUE_WORKERS,
    ) -> None:
        self.worker_lookup = worker_lookup
        self.maximum_workers = maximum_workers
        self._queues: dict[UUID, QueueAdaptiveAggregationStore] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _parse_worker_id(worker_id: UUID | str) -> UUID:
        try:
            return worker_id if isinstance(worker_id, UUID) else UUID(str(worker_id))
        except (TypeError, ValueError) as exc:
            raise ValueError("adaptive queue binding requires a valid worker ID") from exc

    def bind(
        self,
        worker_id: UUID | str,
        queue_store: QueueAdaptiveAggregationStore,
    ) -> dict[str, Any]:
        """Bind one application-owned queue to a live worker."""
        parsed_worker_id = self._parse_worker_id(worker_id)
        if not isinstance(queue_store, QueueAdaptiveAggregationStore):
            raise TypeError("adaptive queue binding requires a QueueAdaptiveAggregationStore")
        try:
            worker = self.worker_lookup(parsed_worker_id)
        except KeyError as exc:
            raise PermissionError("adaptive queue binding requires a registered worker") from exc
        if worker.state not in {WorkerState.STARTING, WorkerState.HEALTHY, WorkerState.DEGRADED}:
            raise PermissionError(
                "adaptive queue binding cannot target a failed or unauthorized worker"
            )
        with self._lock:
            existing = self._queues.get(parsed_worker_id)
            if existing is not None and existing is not queue_store:
                raise ValueError("adaptive queue is already bound; unbind it before replacement")
            self._queues[parsed_worker_id] = queue_store
        return {
            "bound": True,
            "authority_granted": False,
            "worker_id": str(worker.worker_id),
            "worker_pid": worker.process_id,
            "transport": "QUEUE",
        }

    def unbind(
        self,
        worker_id: UUID | str,
        *,
        queue_store: QueueAdaptiveAggregationStore | None = None,
    ) -> dict[str, Any]:
        """Remove a binding without draining or deleting its evidence."""
        parsed_worker_id = self._parse_worker_id(worker_id)
        if queue_store is not None and not isinstance(queue_store, QueueAdaptiveAggregationStore):
            raise TypeError("adaptive queue unbinding requires a QueueAdaptiveAggregationStore")
        with self._lock:
            existing = self._queues.get(parsed_worker_id)
            if existing is None:
                return {
                    "unbound": False,
                    "authority_granted": False,
                    "worker_id": str(parsed_worker_id),
                }
            if queue_store is not None and existing is not queue_store:
                raise ValueError("adaptive queue unbinding does not match its bound queue")
            self._queues.pop(parsed_worker_id)
        return {
            "unbound": True,
            "authority_granted": False,
            "worker_id": str(parsed_worker_id),
        }

    def snapshot(self) -> dict[UUID, QueueAdaptiveAggregationStore]:
        """Return a shallow snapshot for one bounded control cycle."""
        with self._lock:
            return dict(self._queues)

    def status(self) -> tuple[dict[str, Any], ...]:
        """Return a bounded read-only projection of queue bindings."""
        bindings = tuple(self.snapshot().items())[: self.maximum_workers]
        result: list[dict[str, Any]] = []
        for worker_id, queue_store in bindings:
            try:
                worker = self.worker_lookup(worker_id)
            except KeyError:
                continue
            result.append(
                {
                    "worker_id": str(worker_id),
                    "worker_pid": worker.process_id,
                    "worker_state": worker.state.name,
                    "queue": queue_store.status(),
                    "authority_granted": False,
                }
            )
        return tuple(result)


__all__ = ["AdaptiveAggregationQueueRegistry", "Watchdog", "WorkRegistry"]
