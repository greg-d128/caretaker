"""Durable supervisor-owned aggregation for adaptive worker observations.

Workers submit bounded, non-authoritative observation batches.  Only the
supervisor-side ledger merges them, and it accepts a batch only when the
supervisor supplies matching target-generation and policy context.  This
module intentionally does not activate Behavior or Repair changes; it
provides the durable ownership, promotion-evidence, and protocol boundaries
those decisions require.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import threading
import time
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from .transport import (
    APPLICATION_TRANSPORT_MAX_DRAIN_MESSAGES,
    ApplicationLocalQueueTransport,
    ApplicationTransportError,
)


ADAPTIVE_AGGREGATION_SCHEMA_VERSION = 1
ADAPTIVE_POLICY_LEDGER_SCHEMA_VERSION = 1
ADAPTIVE_POLICY_ACCEPTANCE_SCHEMA_VERSION = 1
ADAPTIVE_POLICY_INSTALLATION_SCHEMA_VERSION = 1
ADAPTIVE_BATCH_REVALIDATION_SCHEMA_VERSION = 1
ADAPTIVE_REPAIR_HANDOFF_SCHEMA_VERSION = 1
MAX_BATCH_TEXT = 256
MAX_AGGREGATION_SCOPE_TEXT = 256
MAX_BATCH_EVENTS = 256
MAX_BATCH_COUNTER = 1000
MAX_WORKER_PROVENANCE = 128
MAX_PROCESSED_BATCH_IDS = 4096
MAX_RETAINED_EVENTS = 512
MAX_TRANSITION_REASON = 512
MAX_DISTRIBUTION_CONFLICTS = 128
DEFAULT_DISTRIBUTION_Z_THRESHOLD = 3.0
DEFAULT_DISTRIBUTION_MINIMUM_OBSERVATIONS = 30
MAX_POPULATION_AGGREGATES = 128
MAX_POPULATION_COMPARISONS = 256
MAX_POPULATION_INCOMPLETE_REASONS = 128
DEFAULT_TRANSITION_TIMEOUT_SECONDS = 60.0
MAX_TRANSITION_TIMEOUT_SECONDS = 86_400.0
MAX_DURATION_SECONDS = 86_400.0
MAX_DURATION_SAMPLES = MAX_BATCH_EVENTS
MAX_RESOURCE_METRICS = 32
MAX_RESOURCE_VALUE = 1.0e18
MAX_RESOURCE_SAMPLES = MAX_BATCH_EVENTS
MAX_THRESHOLD_CHANGES = 16
MAX_THRESHOLD_DELAY_SECONDS = 86_400.0
MAX_THRESHOLD_PROPOSAL_TTL_SECONDS = 86_400.0
MAX_BATCH_REVALIDATION_RESULT_BYTES = 8 * 1024
MAX_BATCH_REVALIDATION_IDS = 256
MAX_TRANSITION_SIGNATURE_BYTES = 16 * 1024
MAX_POLICY_INSTALLATION_RESULT_BYTES = 4 * 1024
MAX_BACKPRESSURE_INCIDENT_ID = 256
_ADAPTIVE_POLICY_ID_NAMESPACE = uuid5(
    NAMESPACE_URL, "https://caretaker.dev/adaptive-policy-id"
)
_DISTRIBUTION_COUNTER_NAMES = (
    "exception_count",
    "timing_breach_count",
)
_BATCH_COUNTER_NAMES = (
    "exception_count",
    "timing_breach_count",
    "behavior_observation_calls",
    "behavior_samples",
    "repair_evidence_samples",
    "problem_reproductions",
    "successful_executions",
    "failed_executions",
)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AdaptiveAggregationError(ValueError):
    """Raised when an adaptive observation batch is malformed or unsafe."""


class AdaptiveAggregationBackpressureAction(Enum):
    """Policy response when a worker cannot submit its evidence batch."""

    RETAIN = "RETAIN"
    DROP = "DROP"
    REDUCE = "REDUCE"
    INCIDENT = "INCIDENT"


class RemoteAdaptiveAggregationStore:
    """Submit bounded adaptive batches through the supervisor control plane.

    The remote path is intentionally a submission-only adapter. The supervisor
    validates the batch again and binds its worker PID to the authenticated
    Unix peer before writing the durable ledger. A missing path is not treated
    as a local fallback: callers must choose the local store explicitly when
    running without supervision.
    """

    def __init__(self, socket_path: str | Path, *, timeout: float = 5.0) -> None:
        self.socket_path = str(socket_path)
        self.timeout = float(timeout)
        if self.timeout <= 0:
            raise ValueError("adaptive aggregation transport timeout must be positive")

    def submit(self, batch: Mapping[str, Any]) -> dict[str, Any]:
        normalized = normalize_adaptive_observation_batch(batch)
        from .logging.ipc import control_request

        try:
            response = control_request(
                self.socket_path,
                {"command": "adaptive-observation-submit", "batch": normalized},
                timeout=self.timeout,
            )
        except OSError as exc:
            raise AdaptiveAggregationError(
                "supervisor adaptive aggregation transport is unavailable"
            ) from exc
        if not isinstance(response, Mapping) or not response.get("ok"):
            error = (
                response.get("error", "supervisor rejected adaptive observation batch")
                if isinstance(response, Mapping)
                else "invalid supervisor adaptive aggregation response"
            )
            raise AdaptiveAggregationError(str(error)[:2048])
        result = response.get("result")
        if not isinstance(result, Mapping):
            raise AdaptiveAggregationError(
                "supervisor returned an invalid adaptive aggregation acknowledgement"
            )
        return dict(result)


class QueueAdaptiveAggregationStore:
    """Submit adaptive batches through an application-owned local queue.

    This adapter is useful when the embedding application already has a
    bounded ``queue.Queue`` or ``multiprocessing.Queue`` between workers and
    its supervisor.  It puts canonical bytes on the queue and returns a
    delivery acknowledgement only; the supervisor must call ``receive`` and
    submit the resulting batch to ``SupervisorAdaptiveAggregationStore``.
    Queue transport does not authenticate a sender and never grants authority.
    """

    def __init__(
        self,
        channel: Any | ApplicationLocalQueueTransport,
        *,
        maximum_message_bytes: int = 128 * 1024,
    ) -> None:
        self.transport = (
            channel
            if isinstance(channel, ApplicationLocalQueueTransport)
            else ApplicationLocalQueueTransport(
                channel,
                maximum_message_bytes=maximum_message_bytes,
            )
        )

    def submit(self, batch: Mapping[str, Any]) -> dict[str, Any]:
        normalized = normalize_adaptive_observation_batch(batch)
        try:
            delivery = self.transport.send("adaptive-observation-batch", normalized)
        except ApplicationTransportError as exc:
            raise AdaptiveAggregationError(str(exc)) from exc
        return {
            "status": "QUEUED",
            "batch_id": str(normalized["batch_id"]),
            "transport": "QUEUE",
            "message_id": delivery["message_id"],
        }

    def receive(self, *, timeout: float = 0.0) -> dict[str, Any] | None:
        """Receive and validate one batch for supervisor-side submission."""
        try:
            message = self.transport.receive(timeout=timeout)
        except ApplicationTransportError as exc:
            raise AdaptiveAggregationError(str(exc)) from exc
        if message is None:
            return None
        if message["message_type"] != "adaptive-observation-batch":
            raise AdaptiveAggregationError(
                "application queue message is not an adaptive observation batch"
            )
        try:
            return normalize_adaptive_observation_batch(message["payload"])
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError(
                "application queue adaptive observation batch is invalid"
            ) from exc

    def drain_to(
        self,
        store: "SupervisorAdaptiveAggregationStore",
        *,
        limit: int = APPLICATION_TRANSPORT_MAX_DRAIN_MESSAGES,
    ) -> tuple[dict[str, Any], ...]:
        """Forward a bounded queue slice into the supervisor ledger.

        The caller is responsible for invoking this method from the
        supervisor context and for supplying the normal authoritative context
        during the later reconciliation step.  Queue receipt itself does not
        merge, promote, or authorize any batch.
        """
        if not hasattr(store, "submit") or not callable(store.submit):
            raise TypeError("queue adaptive aggregation drain requires a store")
        if not 1 <= int(limit) <= APPLICATION_TRANSPORT_MAX_DRAIN_MESSAGES:
            raise ValueError(
                "queue adaptive aggregation drain limit must be between 1 and "
                f"{APPLICATION_TRANSPORT_MAX_DRAIN_MESSAGES}"
            )
        results: list[dict[str, Any]] = []
        for _ in range(int(limit)):
            batch = self.receive()
            if batch is None:
                break
            results.append(dict(store.submit(batch)))
        return tuple(results)


class AdaptiveObservationBatcher:
    """Collect bounded worker observations and periodically submit one batch.

    The batcher is deliberately process-local and non-authoritative. It only
    writes evidence to the supervisor ledger; a failed optional submission must
    not change the wrapped application's result.
    """

    def __init__(
        self,
        store: "SupervisorAdaptiveAggregationStore",
        *,
        worker_id: str,
        worker_pid: int,
        target_id: str,
        generation_id: str,
        code_hash: str,
        monitoring_fingerprint: str,
        policy_fingerprint: str,
        authority_policy_generation: str,
        authority_policy_fingerprint: str,
        aggregation_scope: str | None = None,
        flush_after_observations: int = 64,
        flush_interval_seconds: float = 5.0,
        backpressure_action: AdaptiveAggregationBackpressureAction = (
            AdaptiveAggregationBackpressureAction.RETAIN
        ),
        backpressure_incident_callback: Callable[[Mapping[str, Any]], Any] | None = None,
        backpressure_audit_callback: Callable[..., Any] | None = None,
    ) -> None:
        if not 0 < int(flush_after_observations) <= MAX_BATCH_COUNTER:
            raise ValueError(
                f"flush_after_observations must be between 1 and {MAX_BATCH_COUNTER}"
            )
        if float(flush_interval_seconds) < 0:
            raise ValueError("flush_interval_seconds cannot be negative")
        if not isinstance(backpressure_action, AdaptiveAggregationBackpressureAction):
            raise ValueError(
                "backpressure_action must be an AdaptiveAggregationBackpressureAction"
            )
        if backpressure_incident_callback is not None and not callable(
            backpressure_incident_callback
        ):
            raise ValueError("backpressure_incident_callback must be callable")
        if backpressure_audit_callback is not None and not callable(
            backpressure_audit_callback
        ):
            raise ValueError("backpressure_audit_callback must be callable")
        extended_aggregation_target_id(str(target_id), aggregation_scope)
        self.store = store
        self.worker_id = str(worker_id)
        self.worker_pid = int(worker_pid)
        self.flush_after_observations = int(flush_after_observations)
        self.flush_interval_seconds = float(flush_interval_seconds)
        self.backpressure_action = backpressure_action
        self.backpressure_incident_callback = backpressure_incident_callback
        self.backpressure_audit_callback = backpressure_audit_callback
        self._lock = threading.RLock()
        self._sequence = 0
        self._records = 0
        self._first_observed_at: str | None = None
        self._last_observed_at: str | None = None
        self._counters = {name: 0 for name in _BATCH_COUNTER_NAMES}
        self._events = {"exception_events": [], "timing_events": []}
        self._duration_samples: list[float] = []
        self._duration_samples_truncated = False
        self._resource_samples: dict[str, list[float]] = {}
        self._resource_samples_truncated: dict[str, bool] = {}
        self._last_flush_monotonic = time.monotonic()
        self._last_error: str | None = None
        self._dropped_records = 0
        self._backpressure_incident_id: str | None = None
        self._backpressure_audit_emitted = False
        self._last_audit_error: str | None = None
        self._context = {
            "target_id": str(target_id),
            "aggregation_scope": (
                str(aggregation_scope).strip() if aggregation_scope is not None else None
            ),
            "generation_id": str(generation_id),
            "code_hash": str(code_hash),
            "monitoring_fingerprint": str(monitoring_fingerprint),
            "policy_fingerprint": str(policy_fingerprint),
            "authority_policy_generation": str(authority_policy_generation),
            "authority_policy_fingerprint": str(authority_policy_fingerprint),
        }

    @property
    def context(self) -> Mapping[str, str | None]:
        with self._lock:
            return dict(self._context)

    def record(
        self,
        *,
        observed_at: str | None = None,
        event_kind: str | None = None,
        duration_seconds: float | None = None,
        resource_values: Mapping[str, float] | None = None,
        **increments: int,
    ) -> dict[str, Any] | None:
        """Record one observation and flush when the bounded policy requires it."""
        with self._lock:
            if event_kind not in {None, "exception", "timing"}:
                raise ValueError("event_kind must be exception or timing")
            normalized_duration: float | None = None
            if duration_seconds is not None:
                if isinstance(duration_seconds, bool):
                    raise ValueError("duration_seconds must be a number")
                try:
                    normalized_duration = float(duration_seconds)
                except (TypeError, ValueError) as exc:
                    raise ValueError("duration_seconds must be a number") from exc
                if not math.isfinite(normalized_duration) or not 0 <= normalized_duration <= MAX_DURATION_SECONDS:
                    raise ValueError(
                        "duration_seconds must be finite and between 0 and "
                        f"{MAX_DURATION_SECONDS:g}"
                    )
                if event_kind != "timing":
                    raise ValueError("duration_seconds requires a timing event")
            normalized_resources: dict[str, float] = {}
            if resource_values is not None:
                if not isinstance(resource_values, Mapping):
                    raise ValueError("resource_values must be a mapping")
                if len(resource_values) > MAX_RESOURCE_METRICS:
                    raise ValueError(
                        f"resource_values exceeds {MAX_RESOURCE_METRICS} metrics"
                    )
                for raw_name, raw_value in resource_values.items():
                    name = str(raw_name).strip()
                    if not name or len(name) > MAX_BATCH_TEXT:
                        raise ValueError(
                            f"resource metric names must be 1..{MAX_BATCH_TEXT} characters"
                        )
                    if isinstance(raw_value, bool):
                        raise ValueError(f"resource_values[{name!r}] must be a number")
                    try:
                        numeric = float(raw_value)
                    except (TypeError, ValueError) as exc:
                        raise ValueError(
                            f"resource_values[{name!r}] must be a number"
                        ) from exc
                    if not math.isfinite(numeric) or not 0 <= numeric <= MAX_RESOURCE_VALUE:
                        raise ValueError(
                            f"resource_values[{name!r}] must be finite and between 0 and "
                            f"{MAX_RESOURCE_VALUE:g}"
                        )
                    normalized_resources[name] = numeric
                if len(set(self._resource_samples).union(normalized_resources)) > MAX_RESOURCE_METRICS:
                    raise ValueError(
                        f"resource metrics exceed {MAX_RESOURCE_METRICS} per batch"
                    )
            for name, value in increments.items():
                if name not in _BATCH_COUNTER_NAMES:
                    raise ValueError(f"unknown adaptive aggregation counter: {name}")
                if isinstance(value, bool) or int(value) < 0:
                    raise ValueError(f"{name} must be a non-negative integer")
                if int(value) > MAX_BATCH_COUNTER:
                    raise ValueError(f"{name} exceeds {MAX_BATCH_COUNTER}")
            if self._records >= MAX_BATCH_COUNTER:
                result = self._flush_locked()
                if result is not None and result.get("status") in {
                    "ERROR",
                    "DEFERRED",
                    "INCIDENT_RECORDED",
                    "INCIDENT_ALREADY_RECORDED",
                    "INCIDENT_UNAVAILABLE",
                    "INCIDENT_REJECTED",
                    "INCIDENT_FAILED",
                }:
                    self._dropped_records += 1
                    return {
                        "status": "DROPPED",
                        "dropped_records": 1,
                        "reason": "local_batch_capacity",
                        "flush": result,
                    }
            timestamp = observed_at or _utcnow_iso()
            self._records += 1
            self._sequence += 1
            self._first_observed_at = self._first_observed_at or timestamp
            self._last_observed_at = timestamp
            if normalized_duration is not None:
                if len(self._duration_samples) < MAX_DURATION_SAMPLES:
                    self._duration_samples.append(normalized_duration)
                else:
                    self._duration_samples_truncated = True
            for name, numeric in normalized_resources.items():
                samples = self._resource_samples.setdefault(name, [])
                if len(samples) < MAX_RESOURCE_SAMPLES:
                    samples.append(numeric)
                else:
                    self._resource_samples_truncated[name] = True
            for name, value in increments.items():
                self._counters[name] += int(value)
            if event_kind is not None:
                event_name = {
                    "exception": "exception_events",
                    "timing": "timing_events",
                }.get(str(event_kind))
                assert event_name is not None
                self._events[event_name].append(timestamp)
            if (
                self._records >= self.flush_after_observations
                or (
                    self.flush_interval_seconds > 0
                    and time.monotonic() - self._last_flush_monotonic
                    >= self.flush_interval_seconds
                )
            ):
                return self._flush_locked()
            return None

    def flush(self) -> dict[str, Any] | None:
        with self._lock:
            return self._flush_locked()

    def rebind(self, **context: str | None) -> dict[str, Any] | None:
        """Flush the old generation/policy episode before changing its context."""
        with self._lock:
            result = self._flush_locked()
            if isinstance(result, Mapping) and result.get("status") in {
                "ERROR",
                "DEFERRED",
                "INCIDENT_RECORDED",
                "INCIDENT_ALREADY_RECORDED",
                "INCIDENT_UNAVAILABLE",
                "INCIDENT_REJECTED",
                "INCIDENT_FAILED",
            }:
                # RETAIN (and a failed REDUCE retry) must not discard the old
                # context or pending records merely because a generation or
                # population boundary was reached. The caller can retry the
                # rebind after the submission path recovers.
                return result
            next_context: dict[str, str | None] = {}
            for name in self._context:
                value = context[name]
                next_context[name] = (
                    str(value).strip()
                    if value is not None
                    else None
                )
            extended_aggregation_target_id(
                str(next_context["target_id"]),
                next_context["aggregation_scope"],
            )
            self._context = next_context
            self._reset_locked()
            return result

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "worker_id": self.worker_id,
                "worker_pid": self.worker_pid,
                "target_id": self._context["target_id"],
                "aggregation_scope": self._context["aggregation_scope"],
                "generation_id": self._context["generation_id"],
                "pending_records": self._records,
                "next_sequence": self._sequence + 1,
                "dropped_records": self._dropped_records,
                "last_error": self._last_error,
                "backpressure_action": self.backpressure_action.name,
                "backpressure_incident_recorded": self._backpressure_incident_id is not None,
                "backpressure_incident_id": self._backpressure_incident_id,
                "backpressure_audit_emitted": self._backpressure_audit_emitted,
                "last_audit_error": self._last_audit_error,
            }

    def set_backpressure_action(
        self,
        action: AdaptiveAggregationBackpressureAction,
    ) -> None:
        """Apply a validated policy change to the process-local batcher."""
        if not isinstance(action, AdaptiveAggregationBackpressureAction):
            raise ValueError(
                "backpressure_action must be an AdaptiveAggregationBackpressureAction"
            )
        with self._lock:
            self.backpressure_action = action

    def _snapshot_locked(self) -> dict[str, Any]:
        assert self._first_observed_at is not None
        assert self._last_observed_at is not None
        return {
            "batch_id": str(uuid4()),
            "worker_id": self.worker_id,
            "worker_pid": self.worker_pid,
            **self._context,
            "created_at": _utcnow_iso(),
            "first_observed_at": self._first_observed_at,
            "last_observed_at": self._last_observed_at,
            "sequence_start": self._sequence - self._records + 1,
            "sequence_end": self._sequence,
            "observation_count": self._records,
            **self._counters,
            **self._events,
            "duration_samples": list(self._duration_samples),
            "duration_samples_truncated": self._duration_samples_truncated,
            "resource_samples": {
                name: list(samples)
                for name, samples in sorted(self._resource_samples.items())
            },
            "resource_samples_truncated": dict(self._resource_samples_truncated),
        }

    def _reset_locked(self) -> None:
        self._records = 0
        self._first_observed_at = None
        self._last_observed_at = None
        self._counters = {name: 0 for name in _BATCH_COUNTER_NAMES}
        self._events = {"exception_events": [], "timing_events": []}
        self._duration_samples = []
        self._duration_samples_truncated = False
        self._resource_samples = {}
        self._resource_samples_truncated = {}
        self._last_flush_monotonic = time.monotonic()
        self._backpressure_incident_id = None
        self._backpressure_audit_emitted = False
        self._last_audit_error = None

    def _emit_backpressure_audit_locked(
        self,
        batch: Mapping[str, Any],
        outcome: dict[str, Any],
    ) -> dict[str, Any]:
        """Send one bounded, output-only audit envelope for this episode."""
        if self._backpressure_audit_emitted:
            outcome["audit_status"] = "ALREADY_EMITTED"
            return outcome
        callback = self.backpressure_audit_callback
        if callback is None:
            outcome["audit_status"] = "NOT_CONFIGURED"
            return outcome
        status = str(outcome.get("status") or "UNKNOWN")[:64]
        try:
            callback(
                "ADAPTIVE_AGGREGATION_BACKPRESSURE",
                actor={
                    "type": "caretaker",
                    "id": f"adaptive-worker:{self.worker_id}"[:256],
                },
                scope={
                    "target_id": self._context["target_id"],
                    "aggregation_scope": self._context["aggregation_scope"],
                    "generation_id": self._context["generation_id"],
                    "batch_id": str(batch["batch_id"]),
                },
                policy={
                    "fingerprint": self._context["policy_fingerprint"],
                    "authority_generation": self._context[
                        "authority_policy_generation"
                    ],
                    "authority_fingerprint": self._context[
                        "authority_policy_fingerprint"
                    ],
                },
                outcome={
                    "state": status,
                    "incident_recorded": status
                    in {"INCIDENT_RECORDED", "INCIDENT_ALREADY_RECORDED"},
                    "authority_granted": False,
                },
                details={
                    "action": self.backpressure_action.name,
                    "pending_records": self._records,
                    "sequence_start": batch["sequence_start"],
                    "sequence_end": batch["sequence_end"],
                    "incident_id": outcome.get("incident_id"),
                    "error": self._last_error,
                    "authority_granted": False,
                },
            )
        except Exception as exc:
            self._last_audit_error = f"{type(exc).__name__}: {exc}"[:256]
            outcome["audit_status"] = "FAILED"
            outcome["audit_error"] = self._last_audit_error
            return outcome
        self._backpressure_audit_emitted = True
        outcome["audit_status"] = "EMITTED"
        return outcome

    def _record_backpressure_incident_locked(
        self,
        batch: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Notify the application once while retaining the failed evidence.

        The callback receives incident context, never the observation batch. Its
        return value is evidence that the application accepted responsibility for
        creating an incident; it is not Caretaker authority and cannot authorize a
        policy, Repair, or data-loss decision.
        """
        if self._backpressure_incident_id is not None:
            return self._emit_backpressure_audit_locked(batch, {
                "status": "INCIDENT_ALREADY_RECORDED",
                "accepted": True,
                "incident_id": self._backpressure_incident_id,
                "pending_records": self._records,
                "error": self._last_error,
            })
        callback = self.backpressure_incident_callback
        if callback is None:
            return self._emit_backpressure_audit_locked(batch, {
                "status": "INCIDENT_UNAVAILABLE",
                "accepted": False,
                "reason": "no application-owned incident callback is configured",
                "pending_records": self._records,
                "error": self._last_error,
            })
        payload = {
            "event": "adaptive-aggregation-backpressure",
            "action": AdaptiveAggregationBackpressureAction.INCIDENT.name,
            "batch_id": str(batch["batch_id"]),
            "target_id": self._context["target_id"],
            "aggregation_scope": self._context["aggregation_scope"],
            "generation_id": self._context["generation_id"],
            "policy_fingerprint": self._context["policy_fingerprint"],
            "authority_policy_generation": self._context[
                "authority_policy_generation"
            ],
            "authority_policy_fingerprint": self._context[
                "authority_policy_fingerprint"
            ],
            "pending_records": self._records,
            "sequence_start": batch["sequence_start"],
            "sequence_end": batch["sequence_end"],
            "error": self._last_error,
        }
        try:
            response = callback(payload)
        except Exception as exc:
            return self._emit_backpressure_audit_locked(batch, {
                "status": "INCIDENT_FAILED",
                "accepted": False,
                "reason": f"{type(exc).__name__}: {exc}"[:256],
                "pending_records": self._records,
                "error": self._last_error,
            })
        if not isinstance(response, Mapping) or response.get("accepted") is not True:
            return self._emit_backpressure_audit_locked(batch, {
                "status": "INCIDENT_REJECTED",
                "accepted": False,
                "reason": "application-owned incident callback did not accept the incident",
                "pending_records": self._records,
                "error": self._last_error,
            })
        incident_id = response.get("incident_id")
        if incident_id is None:
            return self._emit_backpressure_audit_locked(batch, {
                "status": "INCIDENT_REJECTED",
                "accepted": False,
                "reason": "application-owned incident callback returned no incident_id",
                "pending_records": self._records,
                "error": self._last_error,
            })
        incident_id = str(incident_id).strip()
        if not incident_id or len(incident_id) > MAX_BACKPRESSURE_INCIDENT_ID:
            return self._emit_backpressure_audit_locked(batch, {
                "status": "INCIDENT_REJECTED",
                "accepted": False,
                "reason": "application-owned incident callback returned an invalid incident_id",
                "pending_records": self._records,
                "error": self._last_error,
            })
        self._backpressure_incident_id = incident_id
        return self._emit_backpressure_audit_locked(batch, {
            "status": "INCIDENT_RECORDED",
            "accepted": True,
            "incident_id": incident_id,
            "pending_records": self._records,
            "error": self._last_error,
        })

    def _flush_locked(self) -> dict[str, Any] | None:
        if self._records <= 0:
            return None
        batch = self._snapshot_locked()
        try:
            result = self.store.submit(batch)
        except Exception as exc:
            self._last_error = f"{type(exc).__name__}: {exc}"[:256]
            if self.backpressure_action is AdaptiveAggregationBackpressureAction.DROP:
                dropped_records = self._records
                self._dropped_records += dropped_records
                self._reset_locked()
                return {
                    "status": "DROPPED",
                    "batch_id": batch["batch_id"],
                    "dropped_records": dropped_records,
                    "error": self._last_error,
                }
            if self.backpressure_action is AdaptiveAggregationBackpressureAction.REDUCE:
                reduced = dict(batch)
                reduced["exception_events"] = []
                reduced["timing_events"] = []
                reduced["duration_samples"] = []
                reduced["duration_samples_truncated"] = True
                reduced["resource_samples"] = {}
                reduced["resource_samples_truncated"] = {}
                try:
                    result = self.store.submit(reduced)
                except Exception as reduced_exc:
                    self._last_error = (
                        f"{type(reduced_exc).__name__}: {reduced_exc}"[:256]
                    )
                    return {"status": "ERROR", "error": self._last_error}
                self._last_error = None
                self._reset_locked()
                return {
                    **dict(result),
                    "status": "REDUCED",
                    "batch_id": batch["batch_id"],
                    "dropped_detail": True,
                }
            if self.backpressure_action is AdaptiveAggregationBackpressureAction.INCIDENT:
                return self._record_backpressure_incident_locked(batch)
            return {"status": "DEFERRED", "error": self._last_error}
        self._last_error = None
        self._reset_locked()
        return dict(result)


def _text(value: Any, *, name: str, limit: int, required: bool = True) -> str | None:
    if value is None:
        if required:
            raise AdaptiveAggregationError(f"{name} is required")
        return None
    result = str(value).strip()
    if required and not result:
        raise AdaptiveAggregationError(f"{name} is required")
    if not result:
        return None
    if len(result) > limit:
        raise AdaptiveAggregationError(f"{name} exceeds {limit} characters")
    return result


def extended_aggregation_target_id(
    target_id: str,
    aggregation_scope: str | None = None,
) -> str:
    """Return the exact context key for one target and optional population.

    A scoped identity is intentionally opaque to callers. It is used as a key
    in supervisor generation and policy maps, while the durable aggregate also
    retains the original target and scope separately for operator display.
    """
    target = _text(target_id, name="target_id", limit=MAX_BATCH_TEXT)
    assert target is not None
    if aggregation_scope is None:
        return target
    scope = _text(
        aggregation_scope,
        name="aggregation_scope",
        limit=MAX_AGGREGATION_SCOPE_TEXT,
    )
    assert scope is not None
    return f"{target}::aggregation-scope::{scope}"


def _count(value: Any, *, name: str, maximum: int = MAX_BATCH_COUNTER) -> int:
    if isinstance(value, bool):
        raise AdaptiveAggregationError(f"{name} must be an integer")
    try:
        result = int(value or 0)
    except (TypeError, ValueError) as exc:
        raise AdaptiveAggregationError(f"{name} must be an integer") from exc
    if result < 0 or result > maximum:
        raise AdaptiveAggregationError(f"{name} must be between 0 and {maximum}")
    return result


def _timestamp(value: Any, *, name: str) -> str:
    result = _text(value, name=name, limit=64)
    assert result is not None
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AdaptiveAggregationError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise AdaptiveAggregationError(f"{name} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def _event_times(value: Any, *, name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise AdaptiveAggregationError(f"{name} must be a list")
    if len(value) > MAX_BATCH_EVENTS:
        raise AdaptiveAggregationError(f"{name} exceeds {MAX_BATCH_EVENTS} entries")
    return sorted(_timestamp(item, name=f"{name}[]") for item in value)


def _duration_samples(value: Any, *, name: str) -> list[float]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise AdaptiveAggregationError(f"{name} must be a list")
    if len(value) > MAX_DURATION_SAMPLES:
        raise AdaptiveAggregationError(f"{name} exceeds {MAX_DURATION_SAMPLES} entries")
    samples: list[float] = []
    for item in value:
        if isinstance(item, bool):
            raise AdaptiveAggregationError(f"{name}[] must be a number")
        try:
            duration = float(item)
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError(f"{name}[] must be a number") from exc
        if not math.isfinite(duration) or not 0 <= duration <= MAX_DURATION_SECONDS:
            raise AdaptiveAggregationError(
                f"{name}[] must be finite and between 0 and {MAX_DURATION_SECONDS:g}"
            )
        samples.append(duration)
    return samples


def _resource_samples(value: Any, *, name: str) -> dict[str, list[float]]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise AdaptiveAggregationError(f"{name} must be an object")
    if len(value) > MAX_RESOURCE_METRICS:
        raise AdaptiveAggregationError(
            f"{name} exceeds {MAX_RESOURCE_METRICS} metrics"
        )
    result: dict[str, list[float]] = {}
    for raw_metric, raw_values in value.items():
        metric = _text(
            raw_metric,
            name=f"{name} metric",
            limit=MAX_BATCH_TEXT,
        )
        assert metric is not None
        if not isinstance(raw_values, (list, tuple)):
            raise AdaptiveAggregationError(f"{name}[{metric!r}] must be a list")
        if len(raw_values) > MAX_RESOURCE_SAMPLES:
            raise AdaptiveAggregationError(
                f"{name}[{metric!r}] exceeds {MAX_RESOURCE_SAMPLES} entries"
            )
        samples: list[float] = []
        for raw_value in raw_values:
            if isinstance(raw_value, bool):
                raise AdaptiveAggregationError(
                    f"{name}[{metric!r}][] must be a number"
                )
            try:
                numeric = float(raw_value)
            except (TypeError, ValueError) as exc:
                raise AdaptiveAggregationError(
                    f"{name}[{metric!r}][] must be a number"
                ) from exc
            if not math.isfinite(numeric) or not 0 <= numeric <= MAX_RESOURCE_VALUE:
                raise AdaptiveAggregationError(
                    f"{name}[{metric!r}][] must be finite and between 0 and "
                    f"{MAX_RESOURCE_VALUE:g}"
                )
            samples.append(numeric)
        result[metric] = samples
    return result


def _resource_samples_truncated(value: Any, *, name: str) -> dict[str, bool]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise AdaptiveAggregationError(f"{name} must be an object")
    if len(value) > MAX_RESOURCE_METRICS:
        raise AdaptiveAggregationError(
            f"{name} exceeds {MAX_RESOURCE_METRICS} metrics"
        )
    result: dict[str, bool] = {}
    for raw_metric, raw_truncated in value.items():
        metric = _text(
            raw_metric,
            name=f"{name} metric",
            limit=MAX_BATCH_TEXT,
        )
        assert metric is not None
        if not isinstance(raw_truncated, bool):
            raise AdaptiveAggregationError(
                f"{name}[{metric!r}] must be a boolean"
            )
        result[metric] = raw_truncated
    return result


def normalize_adaptive_observation_batch(value: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize one worker batch into the signed-context-independent protocol."""
    if not isinstance(value, Mapping):
        raise AdaptiveAggregationError("adaptive observation batch must be an object")
    try:
        batch_id = str(UUID(str(value.get("batch_id"))))
    except (TypeError, ValueError) as exc:
        raise AdaptiveAggregationError("batch_id must be a UUID") from exc
    worker_pid = _count(value.get("worker_pid"), name="worker_pid", maximum=2**31 - 1)
    sequence_start = _count(value.get("sequence_start"), name="sequence_start", maximum=2**63 - 1)
    sequence_end = _count(value.get("sequence_end"), name="sequence_end", maximum=2**63 - 1)
    if sequence_end < sequence_start:
        raise AdaptiveAggregationError("sequence_end must not precede sequence_start")
    raw_observation_count = value.get("observation_count")
    observation_count = _count(
        (sequence_end - sequence_start + 1)
        if raw_observation_count is None
        else raw_observation_count,
        name="observation_count",
    )
    if observation_count <= 0:
        raise AdaptiveAggregationError("observation_count must be greater than zero")
    duration_samples_present = "duration_samples" in value
    normalized = {
        "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
        "batch_id": batch_id,
        "worker_id": _text(value.get("worker_id"), name="worker_id", limit=MAX_BATCH_TEXT),
        "worker_pid": worker_pid,
        "target_id": _text(value.get("target_id"), name="target_id", limit=MAX_BATCH_TEXT),
        "aggregation_scope": _text(
            value.get("aggregation_scope"),
            name="aggregation_scope",
            limit=MAX_AGGREGATION_SCOPE_TEXT,
            required=False,
        ),
        "generation_id": _text(value.get("generation_id"), name="generation_id", limit=MAX_BATCH_TEXT),
        "code_hash": _text(value.get("code_hash"), name="code_hash", limit=MAX_BATCH_TEXT),
        "monitoring_fingerprint": _text(
            value.get("monitoring_fingerprint"), name="monitoring_fingerprint", limit=MAX_BATCH_TEXT
        ),
        "policy_fingerprint": _text(
            value.get("policy_fingerprint"), name="policy_fingerprint", limit=MAX_BATCH_TEXT
        ),
        "authority_policy_generation": _text(
            value.get("authority_policy_generation"),
            name="authority_policy_generation",
            limit=MAX_BATCH_TEXT,
        ),
        "authority_policy_fingerprint": _text(
            value.get("authority_policy_fingerprint"),
            name="authority_policy_fingerprint",
            limit=MAX_BATCH_TEXT,
        ),
        "created_at": _timestamp(value.get("created_at"), name="created_at"),
        "first_observed_at": _timestamp(
            value.get("first_observed_at") or value.get("created_at"),
            name="first_observed_at",
        ),
        "last_observed_at": _timestamp(
            value.get("last_observed_at") or value.get("created_at"),
            name="last_observed_at",
        ),
        "sequence_start": sequence_start,
        "sequence_end": sequence_end,
        "observation_count": observation_count,
        "exception_count": _count(value.get("exception_count"), name="exception_count"),
        "timing_breach_count": _count(
            value.get("timing_breach_count"), name="timing_breach_count"
        ),
        "behavior_observation_calls": _count(
            value.get("behavior_observation_calls"), name="behavior_observation_calls"
        ),
        "behavior_samples": _count(value.get("behavior_samples"), name="behavior_samples"),
        "repair_evidence_samples": _count(
            value.get("repair_evidence_samples"), name="repair_evidence_samples"
        ),
        "problem_reproductions": _count(
            value.get("problem_reproductions"), name="problem_reproductions"
        ),
        "successful_executions": _count(
            value.get("successful_executions"), name="successful_executions"
        ),
        "failed_executions": _count(
            value.get("failed_executions"), name="failed_executions"
        ),
        "exception_events": _event_times(value.get("exception_events"), name="exception_events"),
        "timing_events": _event_times(value.get("timing_events"), name="timing_events"),
        "duration_samples": _duration_samples(
            value.get("duration_samples"), name="duration_samples"
        ),
        "duration_samples_truncated": value.get(
            "duration_samples_truncated",
            not duration_samples_present,
        ),
        "resource_samples": _resource_samples(
            value.get("resource_samples"), name="resource_samples"
        ),
        "resource_samples_truncated": _resource_samples_truncated(
            value.get("resource_samples_truncated"),
            name="resource_samples_truncated",
        ),
    }
    if not isinstance(normalized["duration_samples_truncated"], bool):
        raise AdaptiveAggregationError("duration_samples_truncated must be a boolean")
    for metric in normalized["resource_samples_truncated"]:
        if metric not in normalized["resource_samples"]:
            raise AdaptiveAggregationError(
                f"resource_samples_truncated contains unknown metric {metric!r}"
            )
    if normalized["last_observed_at"] < normalized["first_observed_at"]:
        raise AdaptiveAggregationError("last_observed_at must not precede first_observed_at")
    if sum(
        normalized[name]
        for name in (
            "exception_count",
            "timing_breach_count",
            "behavior_observation_calls",
            "behavior_samples",
            "repair_evidence_samples",
            "problem_reproductions",
            "successful_executions",
            "failed_executions",
        )
    ) <= 0:
        raise AdaptiveAggregationError("adaptive observation batch must contain observations")
    if (
        not normalized["duration_samples_truncated"]
        and len(normalized["duration_samples"]) != normalized["timing_breach_count"]
    ):
        raise AdaptiveAggregationError(
            "complete duration_samples must match timing_breach_count"
        )
    if len(normalized["duration_samples"]) > normalized["timing_breach_count"]:
        raise AdaptiveAggregationError(
            "duration_samples cannot exceed timing_breach_count"
        )
    return normalized


def _content_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _transition_signature_payload(transition: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical transition fields covered by its runtime signature."""
    return {
        str(key): value
        for key, value in transition.items()
        if key not in {
            "signature",
            "signature_status",
            # These are mutable/projection fields added after the immutable
            # transition request is written.
            "status",
            "duplicate",
            "context_status",
            "rollback_status",
        }
    }


def _policy_acceptance_signature_payload(acceptance: Mapping[str, Any]) -> dict[str, Any]:
    """Return the immutable acceptance fields covered by its signature."""
    return {
        str(key): value
        for key, value in acceptance.items()
        if key not in {"signature", "signature_status", "duplicate"}
    }


def _normalize_transition_signature(value: Any) -> Mapping[str, Any] | str | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        try:
            encoded = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError("adaptive transition signature is not JSON data") from exc
        if len(encoded) > MAX_TRANSITION_SIGNATURE_BYTES:
            raise AdaptiveAggregationError("adaptive transition signature is too large")
        return dict(value)
    return str(value)[:MAX_TRANSITION_REASON]


def verify_adaptive_policy_transition_signature(
    transition: Mapping[str, Any],
    *,
    identity_journal: Any,
) -> dict[str, Any]:
    """Verify a signed adaptive transition without granting policy authority."""
    signature = transition.get("signature")
    if signature is None:
        return {"valid": False, "status": "UNSIGNED", "reason": "signature is absent"}
    if not isinstance(signature, Mapping):
        return {"valid": False, "status": "MALFORMED", "reason": "signature envelope is not an object"}
    from .logging.signing import (
        deserialize_signed_artifact,
        verify_signed_artifact,
    )
    try:
        artifact = deserialize_signed_artifact(signature)
    except Exception as exc:
        return {
            "valid": False,
            "status": "MALFORMED",
            "reason": f"signature envelope cannot be decoded: {type(exc).__name__}",
        }
    if artifact.artifact_kind != "adaptive-policy-transition":
        return {"valid": False, "status": "INVALID", "reason": "unexpected artifact kind"}
    expected_hash = _content_hash(_transition_signature_payload(transition))
    if artifact.content_hash != expected_hash:
        return {"valid": False, "status": "INVALID", "reason": "signature binds different transition content"}
    if str(artifact.context.get("transition_id") or "") != str(
        transition.get("transition_id") or transition.get("request_id") or ""
    ):
        return {"valid": False, "status": "INVALID", "reason": "signature context does not match transition"}
    fingerprint = artifact.public_key_fingerprint
    if not fingerprint or identity_journal is None:
        return {"valid": False, "status": "UNVERIFIABLE", "reason": "signing identity is unavailable"}
    try:
        identity_ok, identity_error = identity_journal.verify_identity(fingerprint)
        if not identity_ok:
            return {
                "valid": False,
                "status": "INVALID",
                "reason": f"signing identity chain is invalid: {identity_error}",
            }
        public_key = identity_journal.public_key(fingerprint)
    except Exception as exc:
        return {
            "valid": False,
            "status": "UNVERIFIABLE",
            "reason": f"signing identity lookup failed: {type(exc).__name__}",
        }
    if public_key is None or not verify_signed_artifact(artifact, public_key):
        return {"valid": False, "status": "INVALID", "reason": "signature is invalid"}
    return {
        "valid": True,
        "status": "VERIFIED",
        "signer_identity_id": artifact.signer_identity_id,
        "signer_mode": artifact.signer_mode.name,
        "public_key_fingerprint": fingerprint,
    }


def verify_adaptive_policy_acceptance_signature(
    acceptance: Mapping[str, Any],
    *,
    identity_journal: Any,
) -> dict[str, Any]:
    """Verify a signed persistent-acceptance record without granting authority."""
    signature = acceptance.get("signature")
    if signature is None:
        return {"valid": False, "status": "UNSIGNED", "reason": "signature is absent"}
    if not isinstance(signature, Mapping):
        return {"valid": False, "status": "MALFORMED", "reason": "signature envelope is not an object"}
    from .logging.signing import deserialize_signed_artifact, verify_signed_artifact

    try:
        artifact = deserialize_signed_artifact(signature)
    except Exception as exc:
        return {
            "valid": False,
            "status": "MALFORMED",
            "reason": f"signature envelope cannot be decoded: {type(exc).__name__}",
        }
    if artifact.artifact_kind != "adaptive-policy-acceptance":
        return {"valid": False, "status": "INVALID", "reason": "unexpected artifact kind"}
    if artifact.content_hash != _content_hash(_policy_acceptance_signature_payload(acceptance)):
        return {"valid": False, "status": "INVALID", "reason": "signature binds different acceptance content"}
    if str(artifact.context.get("acceptance_id") or "") != str(acceptance.get("acceptance_id") or ""):
        return {"valid": False, "status": "INVALID", "reason": "signature context does not match acceptance"}
    if str(artifact.context.get("transition_id") or "") != str(acceptance.get("transition_id") or ""):
        return {"valid": False, "status": "INVALID", "reason": "signature transition context does not match acceptance"}
    fingerprint = artifact.public_key_fingerprint
    if not fingerprint or identity_journal is None:
        return {"valid": False, "status": "UNVERIFIABLE", "reason": "signing identity is unavailable"}
    try:
        identity_ok, identity_error = identity_journal.verify_identity(fingerprint)
        if not identity_ok:
            return {
                "valid": False,
                "status": "INVALID",
                "reason": f"signing identity chain is invalid: {identity_error}",
            }
        public_key = identity_journal.public_key(fingerprint)
    except Exception as exc:
        return {
            "valid": False,
            "status": "UNVERIFIABLE",
            "reason": f"signing identity lookup failed: {type(exc).__name__}",
        }
    if public_key is None or not verify_signed_artifact(artifact, public_key):
        return {"valid": False, "status": "INVALID", "reason": "signature is invalid"}
    return {
        "valid": True,
        "status": "VERIFIED",
        "signer_identity_id": artifact.signer_identity_id,
        "signer_mode": artifact.signer_mode.name,
        "public_key_fingerprint": fingerprint,
    }


def _adaptive_policy_id(fingerprint: str) -> str:
    """Return a stable UUID until policy snapshots have native IDs."""
    return str(uuid5(_ADAPTIVE_POLICY_ID_NAMESPACE, str(fingerprint)))


def _policy_id(value: Any, *, fingerprint: str, name: str) -> str:
    if value is None or not str(value).strip():
        return _adaptive_policy_id(fingerprint)
    try:
        return str(UUID(str(value)))
    except (TypeError, ValueError) as exc:
        raise AdaptiveAggregationError(f"{name} must be a UUID") from exc


def _duration_statistics(samples: list[float] | tuple[float, ...]) -> dict[str, Any]:
    """Return mergeable, bounded statistics for timing-breach durations."""
    if not samples:
        return {
            "count": 0,
            "mean": 0.0,
            "m2": 0.0,
            "minimum": None,
            "maximum": None,
        }
    mean = 0.0
    m2 = 0.0
    minimum = float(samples[0])
    maximum = minimum
    for index, value in enumerate(samples, start=1):
        numeric = float(value)
        delta = numeric - mean
        mean += delta / index
        m2 += delta * (numeric - mean)
        minimum = min(minimum, numeric)
        maximum = max(maximum, numeric)
    return {
        "count": len(samples),
        "mean": mean,
        "m2": max(0.0, m2),
        "minimum": minimum,
        "maximum": maximum,
    }


def _merge_duration_statistics(
    current: Mapping[str, Any] | None,
    incoming: Mapping[str, Any],
) -> dict[str, Any]:
    """Merge two Welford summaries without retaining unbounded raw samples."""
    left = current if isinstance(current, Mapping) else _duration_statistics(())
    left_count = int(left.get("count") or 0)
    right_count = int(incoming.get("count") or 0)
    if right_count <= 0:
        return {
            "count": left_count,
            "mean": float(left.get("mean") or 0.0),
            "m2": max(0.0, float(left.get("m2") or 0.0)),
            "minimum": left.get("minimum"),
            "maximum": left.get("maximum"),
        }
    if left_count <= 0:
        return {
            "count": right_count,
            "mean": float(incoming.get("mean") or 0.0),
            "m2": max(0.0, float(incoming.get("m2") or 0.0)),
            "minimum": incoming.get("minimum"),
            "maximum": incoming.get("maximum"),
        }
    total = left_count + right_count
    left_mean = float(left.get("mean") or 0.0)
    right_mean = float(incoming.get("mean") or 0.0)
    delta = right_mean - left_mean
    return {
        "count": total,
        "mean": left_mean + delta * right_count / total,
        "m2": max(
            0.0,
            float(left.get("m2") or 0.0)
            + float(incoming.get("m2") or 0.0)
            + delta * delta * left_count * right_count / total,
        ),
        "minimum": min(
            value for value in (left.get("minimum"), incoming.get("minimum"))
            if value is not None
        ),
        "maximum": max(
            value for value in (left.get("maximum"), incoming.get("maximum"))
            if value is not None
        ),
    }


_POPULATION_CONTEXT_FIELDS = (
    "target_id",
    "generation_id",
    "code_hash",
    "monitoring_fingerprint",
    "policy_fingerprint",
    "authority_policy_generation",
    "authority_policy_fingerprint",
)
_POPULATION_RATE_METRICS = (
    ("exception_rate", "exception_count", "total_observations"),
    ("timing_breach_rate", "timing_breach_count", "total_observations"),
    ("behavior_sample_rate", "behavior_samples", "behavior_observation_calls"),
    ("repair_reproduction_rate", "problem_reproductions", "behavior_observation_calls"),
    ("failure_rate", "failed_executions", "execution_count"),
)


def _population_count(
    aggregate: Mapping[str, Any],
    field: str,
    *,
    reasons: list[str],
    aggregate_index: int,
) -> int | None:
    value = aggregate.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        reasons.append(f"aggregate-{aggregate_index}:{field} is not a non-negative integer")
        return None
    return value


def _population_context(
    aggregate: Mapping[str, Any],
    *,
    aggregate_index: int,
    reasons: list[str],
) -> tuple[str, ...] | None:
    values: list[str] = []
    for field in _POPULATION_CONTEXT_FIELDS:
        value = aggregate.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > MAX_BATCH_TEXT:
            reasons.append(f"aggregate-{aggregate_index}:{field} is invalid")
            return None
        values.append(value.strip())
    return tuple(values)


def _population_metric_observations(
    aggregate: Mapping[str, Any],
    *,
    count_field: str,
    denominator_field: str,
    aggregate_index: int,
    reasons: list[str],
) -> tuple[int, int] | None:
    count = _population_count(
        aggregate,
        count_field,
        reasons=reasons,
        aggregate_index=aggregate_index,
    )
    if denominator_field == "execution_count":
        successful = _population_count(
            aggregate,
            "successful_executions",
            reasons=reasons,
            aggregate_index=aggregate_index,
        )
        failed = _population_count(
            aggregate,
            "failed_executions",
            reasons=reasons,
            aggregate_index=aggregate_index,
        )
        denominator = (
            successful + failed
            if successful is not None and failed is not None
            else None
        )
    else:
        denominator = _population_count(
            aggregate,
            denominator_field,
            reasons=reasons,
            aggregate_index=aggregate_index,
        )
    if count is None or denominator is None:
        return None
    if count > denominator:
        reasons.append(
            f"aggregate-{aggregate_index}:{count_field} exceeds {denominator_field}"
        )
        return None
    return count, denominator


def _population_z_score(
    left_rate: float,
    right_rate: float,
    left_count: int,
    right_count: int,
) -> tuple[float, float]:
    pooled = (left_count * left_rate + right_count * right_rate) / (
        left_count + right_count
    )
    standard_error = math.sqrt(
        max(0.0, pooled * (1.0 - pooled))
        * (1.0 / left_count + 1.0 / right_count)
    )
    difference = abs(left_rate - right_rate)
    if difference == 0.0:
        return 0.0, standard_error
    if standard_error <= 0.0:
        return 1.0e12, standard_error
    return difference / standard_error, standard_error


def _population_duration_observations(
    aggregate: Mapping[str, Any],
    *,
    aggregate_index: int,
    reasons: list[str],
) -> tuple[int, float, float] | None:
    raw = aggregate.get("timing_duration_statistics")
    if not isinstance(raw, Mapping):
        reasons.append(
            f"aggregate-{aggregate_index}:timing_duration_statistics is unavailable"
        )
        return None
    count = raw.get("count")
    mean = raw.get("mean")
    m2 = raw.get("m2")
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
        or isinstance(mean, bool)
        or not isinstance(mean, (int, float))
        or not math.isfinite(float(mean))
        or isinstance(m2, bool)
        or not isinstance(m2, (int, float))
        or not math.isfinite(float(m2))
        or float(m2) < 0.0
    ):
        reasons.append(f"aggregate-{aggregate_index}:timing duration statistics are invalid")
        return None
    return count, float(mean), float(m2)


def compare_adaptive_populations(
    aggregates: Sequence[Mapping[str, Any]],
    *,
    target_id: str | None = None,
    generation_id: str | None = None,
    minimum_observations: int = DEFAULT_DISTRIBUTION_MINIMUM_OBSERVATIONS,
    z_threshold: float = DEFAULT_DISTRIBUTION_Z_THRESHOLD,
) -> dict[str, Any]:
    """Compare separately retained adaptive populations as evidence only.

    Aggregates are comparable only when their target, generation, code,
    monitoring, policy, and authority contexts match exactly.  The function
    never merges aggregate state and never makes a policy, Guard, Repair, or
    authority decision.  A non-conflicting result is statistical evidence for
    the sampled populations, not proof that they are equivalent.
    """
    if isinstance(aggregates, (str, bytes, Mapping)) or not isinstance(
        aggregates, Sequence
    ):
        raise TypeError("aggregates must be a sequence of mappings")
    if len(aggregates) > MAX_POPULATION_AGGREGATES:
        raise ValueError(
            f"aggregates cannot contain more than {MAX_POPULATION_AGGREGATES} items"
        )
    aggregate_values = tuple(aggregates)
    if isinstance(minimum_observations, bool) or not isinstance(minimum_observations, int):
        raise ValueError("minimum_observations must be an integer")
    if minimum_observations < 2:
        raise ValueError("minimum_observations must be at least 2")
    try:
        threshold = float(z_threshold)
    except (TypeError, ValueError) as exc:
        raise ValueError("z_threshold must be a finite positive number") from exc
    if not math.isfinite(threshold) or threshold <= 0.0:
        raise ValueError("z_threshold must be a finite positive number")
    if target_id is not None and (
        not isinstance(target_id, str)
        or not target_id.strip()
        or len(target_id.strip()) > MAX_BATCH_TEXT
    ):
        raise ValueError(
            f"target_id must be a non-empty string of at most {MAX_BATCH_TEXT} characters"
        )
    if generation_id is not None and (
        not isinstance(generation_id, str)
        or not generation_id.strip()
        or len(generation_id.strip()) > MAX_BATCH_TEXT
    ):
        raise ValueError(
            f"generation_id must be a non-empty string of at most {MAX_BATCH_TEXT} characters"
        )

    reasons: list[str] = []
    population_rows: list[dict[str, Any]] = []
    contexts: list[tuple[str, ...]] = []
    population_keys: set[str] = set()
    for index, aggregate in enumerate(aggregate_values):
        if not isinstance(aggregate, Mapping):
            reasons.append(f"aggregate-{index}:value is not a mapping")
            continue
        aggregate_target = aggregate.get("target_id")
        aggregate_generation = aggregate.get("generation_id")
        if target_id is not None and aggregate_target != target_id.strip():
            continue
        if generation_id is not None and aggregate_generation != generation_id.strip():
            continue
        context = _population_context(
            aggregate,
            aggregate_index=index,
            reasons=reasons,
        )
        if context is None:
            continue
        scope = aggregate.get("aggregation_scope")
        if scope is not None and (
            not isinstance(scope, str)
            or not scope.strip()
            or len(scope.strip()) > MAX_AGGREGATION_SCOPE_TEXT
        ):
            reasons.append(f"aggregate-{index}:aggregation_scope is invalid")
            continue
        normalized_scope = scope.strip() if isinstance(scope, str) else None
        try:
            expected_target = extended_aggregation_target_id(
                context[0], normalized_scope
            )
        except (AdaptiveAggregationError, TypeError, ValueError):
            reasons.append(f"aggregate-{index}:aggregation identity is invalid")
            continue
        if aggregate.get("aggregation_target_id") != expected_target:
            reasons.append(f"aggregate-{index}:aggregation_target_id is inconsistent")
            continue
        if expected_target in population_keys:
            reasons.append(f"duplicate population identity: {expected_target}")
            continue
        total_observations = _population_count(
            aggregate,
            "total_observations",
            reasons=reasons,
            aggregate_index=index,
        )
        if total_observations is None:
            continue
        population_keys.add(expected_target)
        contexts.append(context)
        execution_count = (
            _population_count(
                aggregate,
                "successful_executions",
                reasons=reasons,
                aggregate_index=index,
            )
            or 0
        ) + (
            _population_count(
                aggregate,
                "failed_executions",
                reasons=reasons,
                aggregate_index=index,
            )
            or 0
        )
        population_rows.append({
            "population_id": expected_target,
            "target_id": context[0],
            "aggregation_scope": normalized_scope,
            "aggregation_target_id": expected_target,
            "total_observations": total_observations,
            "execution_count": execution_count,
            "worker_count": len(aggregate.get("workers") or {})
            if isinstance(aggregate.get("workers") or {}, Mapping)
            else 0,
            "first_observed_at": (
                aggregate.get("first_observed_at")[:MAX_BATCH_TEXT]
                if isinstance(aggregate.get("first_observed_at"), str)
                else None
            ),
            "last_observed_at": (
                aggregate.get("last_observed_at")[:MAX_BATCH_TEXT]
                if isinstance(aggregate.get("last_observed_at"), str)
                else None
            ),
            "aggregate": aggregate,
            "aggregate_index": index,
        })

    population_rows.sort(key=lambda item: str(item["population_id"]))
    context = contexts[0] if contexts else None
    if contexts and any(item != context for item in contexts[1:]):
        reasons.append("selected populations have different comparison contexts")
    public_populations = [
        {
            key: value
            for key, value in population.items()
            if key not in {"aggregate", "aggregate_index"}
        }
        for population in population_rows
    ]
    comparisons: list[dict[str, Any]] = []
    incomplete_metrics: list[dict[str, Any]] = []
    if len(population_rows) >= 2 and not any(
        reason == "selected populations have different comparison contexts"
        for reason in reasons
    ):
        for left_index, left in enumerate(population_rows[:-1]):
            for right in population_rows[left_index + 1 :]:
                left_aggregate = left["aggregate"]
                right_aggregate = right["aggregate"]
                for metric, count_field, denominator_field in _POPULATION_RATE_METRICS:
                    left_reasons: list[str] = []
                    right_reasons: list[str] = []
                    left_values = _population_metric_observations(
                        left_aggregate,
                        count_field=count_field,
                        denominator_field=denominator_field,
                        aggregate_index=left["aggregate_index"],
                        reasons=left_reasons,
                    )
                    right_values = _population_metric_observations(
                        right_aggregate,
                        count_field=count_field,
                        denominator_field=denominator_field,
                        aggregate_index=right["aggregate_index"],
                        reasons=right_reasons,
                    )
                    if (
                        left_values is None
                        or right_values is None
                        or left_values[1] < minimum_observations
                        or right_values[1] < minimum_observations
                    ):
                        reason = (
                            "invalid counts"
                            if left_reasons or right_reasons
                            else f"both populations need at least {minimum_observations} observations"
                        )
                        incomplete_metrics.append({
                            "population_a": left["population_id"],
                            "population_b": right["population_id"],
                            "metric": metric,
                            "reason": reason,
                        })
                        continue
                    left_count, left_denominator = left_values
                    right_count, right_denominator = right_values
                    left_rate = left_count / left_denominator
                    right_rate = right_count / right_denominator
                    z_score, standard_error = _population_z_score(
                        left_rate,
                        right_rate,
                        left_denominator,
                        right_denominator,
                    )
                    comparisons.append({
                        "population_a": left["population_id"],
                        "population_b": right["population_id"],
                        "metric": metric,
                        "method": "pooled_proportion_z_test",
                        "population_a_count": left_count,
                        "population_b_count": right_count,
                        "population_a_observations": left_denominator,
                        "population_b_observations": right_denominator,
                        "population_a_rate": left_rate,
                        "population_b_rate": right_rate,
                        "standard_error": standard_error,
                        "z_score": z_score,
                        "z_threshold": threshold,
                        "conflict": z_score > threshold,
                    })
                left_duration_reasons: list[str] = []
                right_duration_reasons: list[str] = []
                left_duration = _population_duration_observations(
                    left_aggregate,
                    aggregate_index=left["aggregate_index"],
                    reasons=left_duration_reasons,
                )
                right_duration = _population_duration_observations(
                    right_aggregate,
                    aggregate_index=right["aggregate_index"],
                    reasons=right_duration_reasons,
                )
                if (
                    left_duration is None
                    or right_duration is None
                    or left_duration[0] < minimum_observations
                    or right_duration[0] < minimum_observations
                ):
                    incomplete_metrics.append({
                        "population_a": left["population_id"],
                        "population_b": right["population_id"],
                        "metric": "timing_duration_seconds",
                        "reason": (
                            "invalid timing duration statistics"
                            if left_duration_reasons or right_duration_reasons
                            else f"both populations need at least {minimum_observations} duration observations"
                        ),
                    })
                else:
                    left_count, left_mean, left_m2 = left_duration
                    right_count, right_mean, right_m2 = right_duration
                    left_variance = left_m2 / (left_count - 1) if left_count > 1 else 0.0
                    right_variance = right_m2 / (right_count - 1) if right_count > 1 else 0.0
                    standard_error = math.sqrt(
                        left_variance / left_count + right_variance / right_count
                    )
                    difference = abs(left_mean - right_mean)
                    if difference == 0.0:
                        z_score = 0.0
                    elif standard_error <= 0.0:
                        z_score = 1.0e12
                    else:
                        z_score = difference / standard_error
                    comparisons.append({
                        "population_a": left["population_id"],
                        "population_b": right["population_id"],
                        "metric": "timing_duration_seconds",
                        "method": "welch_mean_z_test",
                        "population_a_mean": left_mean,
                        "population_b_mean": right_mean,
                        "population_a_standard_deviation": left_variance**0.5,
                        "population_b_standard_deviation": right_variance**0.5,
                        "population_a_observations": left_count,
                        "population_b_observations": right_count,
                        "standard_error": standard_error,
                        "z_score": z_score,
                        "z_threshold": threshold,
                        "conflict": z_score > threshold,
                    })
    conflict_count = sum(1 for item in comparisons if item.get("conflict"))
    if len(comparisons) > MAX_POPULATION_COMPARISONS:
        comparisons = comparisons[:MAX_POPULATION_COMPARISONS]
        reasons.append("comparison output reached its bounded limit")
    incomplete_metrics = incomplete_metrics[:MAX_POPULATION_INCOMPLETE_REASONS]
    unique_reasons = list(dict.fromkeys(reasons))[:MAX_POPULATION_INCOMPLETE_REASONS]
    if len(population_rows) < 2:
        status = "INCOMPLETE_EVIDENCE"
        if not unique_reasons:
            unique_reasons.append("at least two distinct populations are required")
    elif any(
        reason == "selected populations have different comparison contexts"
        for reason in unique_reasons
    ):
        status = "INCOMPLETE_EVIDENCE"
    elif not comparisons:
        status = "INCOMPLETE_EVIDENCE"
        if not unique_reasons:
            unique_reasons.append("no metrics have sufficient comparable evidence")
    else:
        status = "DISTRIBUTION_CONFLICT" if conflict_count else "COMPARABLE"
    report: dict[str, Any] = {
        "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
        "report_kind": "ADAPTIVE_POPULATION_COMPARISON",
        "status": status,
        "target_id": context[0] if context else target_id,
        "generation_id": context[1] if context else generation_id,
        "comparison_context": (
            {
                field: context[index]
                for index, field in enumerate(_POPULATION_CONTEXT_FIELDS)
            }
            if context and not any(
                reason == "selected populations have different comparison contexts"
                for reason in unique_reasons
            )
            else None
        ),
        "population_count": len(public_populations),
        "populations": public_populations,
        "comparisons": comparisons,
        "conflict_count": conflict_count,
        "incomplete_metrics": incomplete_metrics,
        "reasons": unique_reasons,
        "minimum_observations": minimum_observations,
        "z_threshold": threshold,
        "comparison_truncated": "comparison output reached its bounded limit" in unique_reasons,
        "evidence_only": True,
        "authority_granted": False,
    }
    report["content_sha256"] = _content_hash(report)
    return report


def verify_adaptive_population_comparison_report(
    report: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify the content hash of an evidence-only population comparison."""
    if not isinstance(report, Mapping):
        return {"valid": False, "status": "MALFORMED", "reason": "report is not an object"}
    if report.get("report_kind") != "ADAPTIVE_POPULATION_COMPARISON":
        return {"valid": False, "status": "INVALID", "reason": "unexpected report kind"}
    if report.get("evidence_only") is not True or report.get("authority_granted") is not False:
        return {
            "valid": False,
            "status": "INVALID",
            "reason": "report authority markers are invalid",
        }
    stored = report.get("content_sha256")
    if not isinstance(stored, str) or len(stored) != 64:
        return {"valid": False, "status": "INVALID", "reason": "content hash is missing"}
    payload = dict(report)
    payload.pop("content_sha256", None)
    if _content_hash(payload) != stored:
        return {"valid": False, "status": "INVALID", "reason": "content hash is invalid"}
    return {"valid": True, "status": "VERIFIED", "content_sha256": stored}


def _promotion_policy(value: Any, *, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AdaptiveAggregationError(f"{name} promotion policy must be an object")
    enabled = value.get("enabled", False)
    if not isinstance(enabled, bool):
        raise AdaptiveAggregationError(f"{name}.enabled must be a boolean")
    if isinstance(value.get("occurrences", 0), bool):
        raise AdaptiveAggregationError(f"{name}.occurrences must be an integer")
    try:
        occurrences = int(value.get("occurrences", 0))
    except (TypeError, ValueError) as exc:
        raise AdaptiveAggregationError(f"{name}.occurrences must be an integer") from exc
    if occurrences <= 0 or occurrences > MAX_BATCH_EVENTS:
        raise AdaptiveAggregationError(
            f"{name}.occurrences must be between 1 and {MAX_BATCH_EVENTS}"
        )
    try:
        window_seconds = float(value.get("window_seconds", 0))
    except (TypeError, ValueError) as exc:
        raise AdaptiveAggregationError(f"{name}.window_seconds must be a number") from exc
    if window_seconds <= 0:
        raise AdaptiveAggregationError(f"{name}.window_seconds must be greater than zero")
    promote_to = str(value.get("promote_to", "")).strip().upper()
    if promote_to not in {"BEHAVIOR", "REPAIR"}:
        raise AdaptiveAggregationError(
            f"{name}.promote_to must be BEHAVIOR or REPAIR"
        )
    return {
        "enabled": enabled,
        "occurrences": occurrences,
        "window_seconds": window_seconds,
        "promote_to": promote_to,
    }


def _transition_timeout(value: Any) -> float:
    """Normalize the policy timeout captured by a worker transition request."""
    if isinstance(value, bool):
        raise AdaptiveAggregationError(
            "transition_timeout_seconds must be a number"
        )
    try:
        timeout = float(
            DEFAULT_TRANSITION_TIMEOUT_SECONDS
            if value is None
            else value
        )
    except (TypeError, ValueError) as exc:
        raise AdaptiveAggregationError(
            "transition_timeout_seconds must be a number"
        ) from exc
    if not math.isfinite(timeout) or not 0 < timeout <= MAX_TRANSITION_TIMEOUT_SECONDS:
        raise AdaptiveAggregationError(
            "transition_timeout_seconds must be greater than zero and no more than 86400"
        )
    return timeout


def _repair_evidence_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AdaptiveAggregationError("repair_evidence policy must be an object")
    enabled = value.get("enabled", False)
    if not isinstance(enabled, bool):
        raise AdaptiveAggregationError("repair_evidence.enabled must be a boolean")
    integer_fields = (
        "minimum_behavior_samples",
        "minimum_observation_calls",
    )
    normalized: dict[str, Any] = {"enabled": enabled}
    for name in integer_fields:
        if isinstance(value.get(name, 0), bool):
            raise AdaptiveAggregationError(f"repair_evidence.{name} must be an integer")
        try:
            result = int(value.get(name, 0))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError(
                f"repair_evidence.{name} must be an integer"
            ) from exc
        if result < 0 or result > MAX_BATCH_COUNTER:
            raise AdaptiveAggregationError(
                f"repair_evidence.{name} must be between 0 and {MAX_BATCH_COUNTER}"
            )
        normalized[name] = result
    try:
        duration = float(value.get("minimum_duration_seconds", 0))
    except (TypeError, ValueError) as exc:
        raise AdaptiveAggregationError(
            "repair_evidence.minimum_duration_seconds must be a number"
        ) from exc
    if duration < 0:
        raise AdaptiveAggregationError(
            "repair_evidence.minimum_duration_seconds cannot be negative"
        )
    require_reproduction = value.get("require_problem_reproduction", False)
    if not isinstance(require_reproduction, bool):
        raise AdaptiveAggregationError(
            "repair_evidence.require_problem_reproduction must be a boolean"
        )
    normalized["minimum_duration_seconds"] = duration
    normalized["require_problem_reproduction"] = require_reproduction
    return normalized


def _threshold_changes(value: Any) -> dict[str, Any]:
    """Validate the bounded threshold-only portion of a proposal."""
    if not isinstance(value, Mapping) or not value:
        raise AdaptiveAggregationError("threshold changes must be a non-empty object")
    if len(value) > MAX_THRESHOLD_CHANGES:
        raise AdaptiveAggregationError(
            f"threshold changes exceed {MAX_THRESHOLD_CHANGES} fields"
        )
    integer_fields = {
        "exception.occurrences",
        "soft_timing.occurrences",
        "repair_evidence.minimum_behavior_samples",
        "repair_evidence.minimum_observation_calls",
    }
    duration_fields = {
        "exception.window_seconds",
        "soft_timing.window_seconds",
        "repair_evidence.minimum_duration_seconds",
        "transition_timeout_seconds",
    }
    boolean_fields = {"repair_evidence.require_problem_reproduction"}
    allowed = integer_fields | duration_fields | boolean_fields
    normalized: dict[str, Any] = {}
    for raw_name, raw_value in value.items():
        name = str(raw_name).strip()
        if name not in allowed:
            raise AdaptiveAggregationError(
                f"unsupported adaptive threshold field {name!r}"
            )
        if name in integer_fields:
            if isinstance(raw_value, bool):
                raise AdaptiveAggregationError(f"{name} must be an integer")
            try:
                integer = int(raw_value)
            except (TypeError, ValueError) as exc:
                raise AdaptiveAggregationError(f"{name} must be an integer") from exc
            if integer <= 0 and name.endswith("occurrences"):
                raise AdaptiveAggregationError(f"{name} must be greater than zero")
            if integer < 0 or integer > MAX_BATCH_COUNTER:
                raise AdaptiveAggregationError(
                    f"{name} must be between 0 and {MAX_BATCH_COUNTER}"
                )
            normalized[name] = integer
        elif name in duration_fields:
            if isinstance(raw_value, bool):
                raise AdaptiveAggregationError(f"{name} must be a number")
            try:
                duration = float(raw_value)
            except (TypeError, ValueError) as exc:
                raise AdaptiveAggregationError(f"{name} must be a number") from exc
            if (
                not math.isfinite(duration)
                or duration < 0
                or duration > MAX_THRESHOLD_PROPOSAL_TTL_SECONDS
                or (name == "transition_timeout_seconds" and duration <= 0)
            ):
                raise AdaptiveAggregationError(
                    f"{name} must be within the supported bounded range"
                )
            normalized[name] = duration
        else:
            if not isinstance(raw_value, bool):
                raise AdaptiveAggregationError(f"{name} must be a boolean")
            normalized[name] = raw_value
    return {name: normalized[name] for name in sorted(normalized)}


def _safe_write(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        temporary.replace(path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            pass
        else:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _immutable_write(path: Path, value: Mapping[str, Any]) -> bool:
    """Create a record once, accepting only an identical retry."""
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AdaptiveAggregationError(
                f"immutable record {path.name} is unreadable"
            ) from exc
        if existing == value:
            return False
        raise AdaptiveAggregationError(
            f"immutable record {path.name} already contains different content"
        )
    _safe_write(path, value)
    return True


class SupervisorAdaptiveAggregationStore:
    """Durable single-writer ledger for bounded worker observation batches.

    Worker submission only creates a uniquely named immutable pending file.
    ``reconcile`` is supervisor-owned: it validates the supervisor-provided
    current context, merges accepted batches, and atomically checkpoints the
    aggregate before archiving the input. A worker cannot change policy,
    authority, or generation context by choosing different batch fields.
    """

    _STATE_SCHEMA_VERSION = 1

    def __init__(
        self,
        root: str | Path,
        *,
        maximum_pending: int = 4096,
        maximum_workers: int = MAX_WORKER_PROVENANCE,
        maximum_retained_events: int = MAX_RETAINED_EVENTS,
        distribution_z_threshold: float = DEFAULT_DISTRIBUTION_Z_THRESHOLD,
        distribution_minimum_observations: int = DEFAULT_DISTRIBUTION_MINIMUM_OBSERVATIONS,
        audit_event: Callable[..., Any] | None = None,
    ) -> None:
        if int(maximum_pending) <= 0:
            raise ValueError("maximum_pending must be greater than zero")
        if int(maximum_workers) <= 0:
            raise ValueError("maximum_workers must be greater than zero")
        if int(maximum_retained_events) <= 0:
            raise ValueError("maximum_retained_events must be greater than zero")
        if float(distribution_z_threshold) <= 0:
            raise ValueError("distribution_z_threshold must be greater than zero")
        if int(distribution_minimum_observations) <= 1:
            raise ValueError("distribution_minimum_observations must be greater than one")
        self.root = Path(root)
        self.pending_directory = self.root / "adaptive" / "aggregation" / "pending"
        self.archive_directory = self.root / "adaptive" / "aggregation" / "archive"
        self.rejected_directory = self.root / "adaptive" / "aggregation" / "rejected"
        self.acknowledgement_directory = self.root / "adaptive" / "aggregation" / "acknowledgements"
        self.state_directory = self.root / "adaptive" / "aggregation" / "state"
        self.transition_directory = self.root / "adaptive" / "aggregation" / "transitions"
        self.transition_acknowledgement_directory = (
            self.root / "adaptive" / "aggregation" / "transition-acknowledgements"
        )
        self.proposal_review_directory = self.root / "adaptive" / "aggregation" / "proposal-reviews"
        self.repair_proposal_review_directory = self.root / "adaptive" / "aggregation" / "repair-proposal-reviews"
        self.repair_handoff_directory = self.root / "adaptive" / "aggregation" / "repair-handoffs"
        self.repair_handoff_outcome_directory = self.root / "adaptive" / "aggregation" / "repair-handoff-outcomes"
        self.transition_rollback_directory = self.root / "adaptive" / "aggregation" / "transition-rollbacks"
        self.policy_ledger_directory = self.root / "adaptive" / "policy-ledger"
        self.policy_acceptance_directory = self.root / "adaptive" / "policy-acceptance"
        self.policy_installation_directory = self.root / "adaptive" / "policy-installation"
        self.conflict_directory = self.root / "adaptive" / "aggregation" / "conflicts"
        self.revalidation_directory = self.root / "adaptive" / "aggregation" / "revalidations"
        for directory in (
            self.pending_directory,
            self.archive_directory,
            self.rejected_directory,
            self.acknowledgement_directory,
            self.state_directory,
            self.transition_directory,
            self.transition_acknowledgement_directory,
            self.proposal_review_directory,
            self.repair_proposal_review_directory,
            self.repair_handoff_directory,
            self.repair_handoff_outcome_directory,
            self.transition_rollback_directory,
            self.policy_ledger_directory,
            self.policy_acceptance_directory,
            self.policy_installation_directory,
            self.conflict_directory,
            self.revalidation_directory,
        ):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                directory.chmod(0o700)
            except OSError:
                pass
        self.maximum_pending = int(maximum_pending)
        self.maximum_workers = int(maximum_workers)
        self.maximum_retained_events = int(maximum_retained_events)
        self.distribution_z_threshold = float(distribution_z_threshold)
        self.distribution_minimum_observations = int(distribution_minimum_observations)
        if audit_event is not None and not callable(audit_event):
            raise TypeError("adaptive aggregation audit_event must be callable")
        self.audit_event = audit_event
        self._lock = threading.RLock()

    def _emit_revalidation_audit(
        self,
        record: Mapping[str, Any],
        *,
        duplicate: bool,
    ) -> str | None:
        if self.audit_event is None:
            return None
        try:
            from .logging.models import EvidencePriority

            self.audit_event(
                "ADAPTIVE_BATCH_REVALIDATED",
                actor={"type": "supervisor"},
                scope={
                    "batch_id": str(record.get("batch_id") or ""),
                    "revalidation_id": str(record.get("revalidation_id") or ""),
                },
                policy={
                    "fingerprint": str(
                        record.get("requested_policy_fingerprint") or ""
                    ),
                },
                outcome={
                    "state": str(record.get("status") or "UNKNOWN"),
                    "authority_granted": False,
                },
                details={
                    "source_policy_fingerprint": record.get(
                        "source_policy_fingerprint"
                    ),
                    "validator_id": record.get("validator_id"),
                    "duplicate": duplicate,
                    "aggregate_modified": False,
                },
                priority=EvidencePriority.IMPORTANT,
            )
        except Exception as exc:
            return f"{type(exc).__name__}: {exc}"[:256]
        return None

    def _emit_policy_installation_audit(
        self,
        record: Mapping[str, Any],
        *,
        duplicate: bool = False,
    ) -> str | None:
        if self.audit_event is None:
            return None
        try:
            from .logging.models import EvidencePriority

            self.audit_event(
                "ADAPTIVE_POLICY_INSTALLATION",
                actor={
                    "type": "deployment",
                    "id": str(
                        record.get("installed_by")
                        or record.get("deployment_authority_id")
                        or "deployment"
                    )[:128],
                },
                scope={
                    "target_id": str(record.get("target_id") or "")[:512],
                    "aggregation_scope": record.get("aggregation_scope"),
                    "acceptance_id": str(record.get("acceptance_id") or "")[:128],
                    "installation_id": str(record.get("installation_id") or "")[:128],
                },
                policy={
                    "policy_id": str(record.get("policy_id") or "")[:128],
                    "fingerprint": str(record.get("policy_fingerprint") or "")[:512],
                    "prior_policy_id": str(record.get("prior_policy_id") or "")[:128],
                    "prior_fingerprint": str(
                        record.get("prior_policy_fingerprint") or ""
                    )[:512],
                    "authority_type": "deployment",
                },
                outcome={
                    "state": str(record.get("status") or "UNKNOWN")[:64],
                    "policy_mutated": False,
                    "authority_granted": False,
                },
                details={
                    "deployment_artifact_hash": record.get("deployment_artifact_hash"),
                    "reason": record.get("reason"),
                    "duplicate": duplicate,
                    "handler_status": record.get("handler_status"),
                },
                priority=EvidencePriority.CRITICAL,
            )
        except Exception as exc:
            return f"{type(exc).__name__}: {exc}"[:256]
        return None

    @staticmethod
    def _batch_path(directory: Path, batch_id: str) -> Path:
        return directory / f"{batch_id}.json"

    @staticmethod
    def _aggregate_key(batch: Mapping[str, Any]) -> str:
        context = "\0".join(
            str(batch.get(name) or "")
            for name in (
                "target_id",
                "aggregation_scope",
                "generation_id",
                "code_hash",
                "monitoring_fingerprint",
                "policy_fingerprint",
                "authority_policy_generation",
                "authority_policy_fingerprint",
            )
        )
        return hashlib.sha256(context.encode("utf-8")).hexdigest()

    def submit(self, batch: Mapping[str, Any]) -> dict[str, Any]:
        normalized = normalize_adaptive_observation_batch(batch)
        batch_id = str(normalized["batch_id"])
        pending = self._batch_path(self.pending_directory, batch_id)
        archive = self._batch_path(self.archive_directory, batch_id)
        rejected = self._batch_path(self.rejected_directory, batch_id)
        for existing in (pending, archive, rejected):
            if existing.exists():
                try:
                    envelope = json.loads(existing.read_text(encoding="utf-8"))
                    existing_batch = envelope.get("batch") if isinstance(envelope, Mapping) else None
                    if isinstance(existing_batch, Mapping) and _content_hash(existing_batch) == _content_hash(normalized):
                        return {"status": "DUPLICATE", "batch_id": batch_id}
                except (OSError, TypeError, ValueError, json.JSONDecodeError):
                    pass
                raise AdaptiveAggregationError("batch_id is already used for different content")
        pending_count = sum(1 for _ in self.pending_directory.glob("*.json"))
        if pending_count >= self.maximum_pending:
            raise AdaptiveAggregationError(
                f"adaptive aggregation pending queue is full ({self.maximum_pending})"
            )
        envelope = {
            "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
            "batch": normalized,
            "batch_sha256": _content_hash(normalized),
        }
        _safe_write(pending, envelope)
        return {"status": "QUEUED", "batch_id": batch_id}

    def _load_batch(self, path: Path) -> dict[str, Any]:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(envelope, Mapping):
            raise AdaptiveAggregationError("batch envelope must be an object")
        if int(envelope.get("schema_version") or 0) != ADAPTIVE_AGGREGATION_SCHEMA_VERSION:
            raise AdaptiveAggregationError("unsupported adaptive aggregation schema")
        batch = normalize_adaptive_observation_batch(envelope.get("batch") or {})
        if str(envelope.get("batch_sha256") or "") != _content_hash(batch):
            raise AdaptiveAggregationError("adaptive observation batch hash is invalid")
        if str(path.stem) != str(batch["batch_id"]):
            raise AdaptiveAggregationError("batch ID does not match its filename")
        return batch

    def _revalidation_path(self, revalidation_id: str) -> Path:
        return self.revalidation_directory / f"{revalidation_id}.json"

    def _load_revalidation_record(self, path: Path) -> dict[str, Any]:
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AdaptiveAggregationError("adaptive batch revalidation is unreadable") from exc
        if not isinstance(envelope, Mapping):
            raise AdaptiveAggregationError("adaptive batch revalidation must be an object")
        if int(envelope.get("schema_version") or 0) != ADAPTIVE_BATCH_REVALIDATION_SCHEMA_VERSION:
            raise AdaptiveAggregationError("unsupported adaptive batch revalidation schema")
        record = envelope.get("record")
        if not isinstance(record, Mapping):
            raise AdaptiveAggregationError("adaptive batch revalidation record is missing")
        try:
            revalidation_id = str(UUID(str(record.get("revalidation_id"))))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError("adaptive batch revalidation ID is invalid") from exc
        if revalidation_id != path.stem:
            raise AdaptiveAggregationError("adaptive batch revalidation ID does not match its filename")
        if str(envelope.get("record_sha256") or "") != _content_hash(record):
            raise AdaptiveAggregationError("adaptive batch revalidation hash is invalid")
        return dict(record)

    @staticmethod
    def _revalidation_text(value: Any, *, name: str) -> str:
        result = str(value or "").strip()
        if not result or len(result) > MAX_BATCH_TEXT:
            raise AdaptiveAggregationError(
                f"adaptive batch revalidation {name} is invalid"
            )
        return result

    @staticmethod
    def _revalidation_result(value: Any) -> dict[str, Any]:
        if not isinstance(value, Mapping) or not isinstance(value.get("valid"), bool):
            raise AdaptiveAggregationError(
                "adaptive batch revalidation validator must return a mapping with boolean valid"
            )
        result = dict(value)
        try:
            encoded = json.dumps(
                result,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError(
                "adaptive batch revalidation result is not JSON data"
            ) from exc
        if len(encoded) > MAX_BATCH_REVALIDATION_RESULT_BYTES:
            raise AdaptiveAggregationError("adaptive batch revalidation result is too large")
        return result

    def revalidate_archived_batches(
        self,
        *,
        policy_fingerprint: str,
        validator: Callable[[Mapping[str, Any], str], Mapping[str, Any]] | None = None,
        validator_id: str | None = None,
        batch_ids: Sequence[str] | None = None,
        maximum_batches: int = 100,
    ) -> dict[str, Any]:
        """Record evidence from rechecking archived batches under a policy hash.

        The optional validator is application/deployment supplied because a
        fingerprint alone cannot describe the policy semantics needed to
        re-evaluate a historical batch. This method never edits archived
        batches or aggregate state, grants authority, or promotes a repair.
        """
        if isinstance(maximum_batches, bool) or not isinstance(maximum_batches, int):
            raise AdaptiveAggregationError("maximum_batches must be an integer")
        if maximum_batches <= 0:
            raise AdaptiveAggregationError("maximum_batches must be greater than zero")
        requested_policy = self._revalidation_text(
            policy_fingerprint,
            name="policy_fingerprint",
        )
        if validator is not None and not callable(validator):
            raise AdaptiveAggregationError("adaptive batch revalidation validator must be callable")
        resolved_validator_id = self._revalidation_text(
            validator_id or ("application-validator" if validator is not None else "identity-only"),
            name="validator_id",
        )
        selected_ids: set[str] | None = None
        if batch_ids is not None:
            if isinstance(batch_ids, (str, bytes, bytearray)):
                raise AdaptiveAggregationError("batch_ids must be a sequence of UUIDs")
            if len(batch_ids) > MAX_BATCH_REVALIDATION_IDS:
                raise AdaptiveAggregationError(
                    f"batch_ids cannot contain more than {MAX_BATCH_REVALIDATION_IDS} values"
                )
            selected_ids = set()
            for value in batch_ids:
                try:
                    selected_ids.add(str(UUID(str(value))))
                except (TypeError, ValueError) as exc:
                    raise AdaptiveAggregationError("batch_ids must contain UUIDs") from exc
        paths = sorted(self.archive_directory.glob("*.json"))
        if selected_ids is not None:
            paths = [path for path in paths if path.stem in selected_ids]
        paths = paths[:maximum_batches]
        reports: list[dict[str, Any]] = []
        audit_errors: list[str] = []
        for path in paths:
            try:
                batch = self._load_batch(path)
                batch_id = str(batch["batch_id"])
                batch_hash = _content_hash(batch)
                source_policy = str(batch["policy_fingerprint"])
            except Exception as exc:
                batch = None
                batch_id = path.stem[:MAX_BATCH_TEXT]
                batch_hash = None
                source_policy = None
                validation_status = "INVALID_SOURCE"
                validation_reason = f"{type(exc).__name__}: {exc}"[:256]
                validator_result: Mapping[str, Any] = {"valid": False, "reason": validation_reason}
            else:
                if validator is None:
                    if source_policy == requested_policy:
                        validation_status = "MATCHED_POLICY"
                        validation_reason = "archived batch already carries the requested policy fingerprint"
                        validator_result = {"valid": True, "mode": "identity-only"}
                    else:
                        validation_status = "REVALIDATION_REQUIRED"
                        validation_reason = "a deployment validator is required to assess a different policy fingerprint"
                        validator_result = {"valid": False, "mode": "identity-only"}
                else:
                    try:
                        validator_result = self._revalidation_result(
                            validator(dict(batch), requested_policy)
                        )
                        validation_status = (
                            "VALIDATED" if validator_result["valid"] else "REJECTED"
                        )
                        validation_reason = str(
                            validator_result.get("reason") or validation_status
                        )[:256]
                    except Exception as exc:
                        validation_status = "VALIDATION_FAILED"
                        validation_reason = f"{type(exc).__name__}: {exc}"[:256]
                        validator_result = {"valid": False, "reason": validation_reason}
            identity = "\0".join(
                (
                    batch_hash or batch_id,
                    requested_policy,
                    resolved_validator_id,
                )
            )
            revalidation_id = str(
                uuid5(
                    NAMESPACE_URL,
                    "caretaker:adaptive-batch-revalidation:" + hashlib.sha256(
                        identity.encode("utf-8")
                    ).hexdigest(),
                )
            )
            path_out = self._revalidation_path(revalidation_id)
            if path_out.exists():
                record = self._load_revalidation_record(path_out)
                reports.append({**record, "duplicate": True})
                audit_error = self._emit_revalidation_audit(record, duplicate=True)
                if audit_error is not None:
                    audit_errors.append(audit_error)
                continue
            record = {
                "revalidation_id": revalidation_id,
                "batch_id": batch_id,
                "batch_sha256": batch_hash,
                "source_policy_fingerprint": source_policy,
                "requested_policy_fingerprint": requested_policy,
                "validator_id": resolved_validator_id,
                "status": validation_status,
                "reason": validation_reason,
                "validator_result": dict(validator_result),
                "checked_at": _utcnow_iso(),
                "authority_granted": False,
                "aggregate_modified": False,
            }
            _immutable_write(
                path_out,
                {
                    "schema_version": ADAPTIVE_BATCH_REVALIDATION_SCHEMA_VERSION,
                    "record": record,
                    "record_sha256": _content_hash(record),
                },
            )
            reports.append({**record, "duplicate": False})
            audit_error = self._emit_revalidation_audit(record, duplicate=False)
            if audit_error is not None:
                audit_errors.append(audit_error)
        return {
            "schema_version": ADAPTIVE_BATCH_REVALIDATION_SCHEMA_VERSION,
            "status": "COMPLETED",
            "requested_policy_fingerprint": requested_policy,
            "validator_id": resolved_validator_id,
            "checked_count": len(reports),
            "truncated": len(paths) >= maximum_batches
            and len(paths) < len(
                [path for path in self.archive_directory.glob("*.json") if selected_ids is None or path.stem in selected_ids]
            ),
            "reports": reports,
            "audit_errors": audit_errors[:20],
            "authority_granted": False,
            "aggregate_modified": False,
        }

    def list_batch_revalidations(self, *, limit: int = 100) -> tuple[dict[str, Any], ...]:
        """List durable batch revalidation evidence, newest first."""
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise AdaptiveAggregationError("revalidation limit must be a positive integer")
        records: list[dict[str, Any]] = []
        for path in sorted(self.revalidation_directory.glob("*.json"), reverse=True):
            try:
                records.append(self._load_revalidation_record(path))
            except AdaptiveAggregationError:
                continue
            if len(records) >= min(limit, 500):
                break
        records.sort(key=lambda item: str(item.get("checked_at") or ""), reverse=True)
        return tuple(records)

    def _state_path(self, key: str) -> Path:
        return self.state_directory / f"{key}.json"

    def _acknowledgement_path(self, batch_id: str) -> Path:
        return self.acknowledgement_directory / f"{batch_id}.json"

    def _transition_path(self, request_id: str) -> Path:
        return self.transition_directory / f"{request_id}.json"

    def _transition_acknowledgement_path(self, request_id: str, worker_id: str) -> Path:
        worker_key = hashlib.sha256(worker_id.encode("utf-8")).hexdigest()[:32]
        return self.transition_acknowledgement_directory / f"{request_id}-{worker_key}.json"

    def _proposal_review_path(self, request_id: str) -> Path:
        return self.proposal_review_directory / f"{request_id}.json"

    def _repair_proposal_review_path(self, request_id: str) -> Path:
        return self.repair_proposal_review_directory / f"{request_id}.json"

    def _repair_handoff_path(self, handoff_id: str) -> Path:
        return self.repair_handoff_directory / f"{handoff_id}.json"

    def _repair_handoff_outcome_path(self, handoff_id: str) -> Path:
        return self.repair_handoff_outcome_directory / f"{handoff_id}.json"

    def _transition_rollback_path(self, request_id: str) -> Path:
        return self.transition_rollback_directory / f"{request_id}.json"

    def _policy_ledger_path(self, record_id: str) -> Path:
        return self.policy_ledger_directory / f"{record_id}.json"

    def _policy_acceptance_path(self, acceptance_id: str) -> Path:
        return self.policy_acceptance_directory / f"{acceptance_id}.json"

    def _policy_installation_path(self, installation_id: str, status: str) -> Path:
        return self.policy_installation_directory / f"{installation_id}-{status.lower()}.json"

    def _load_policy_installation_record(self, path: Path) -> dict[str, Any]:
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AdaptiveAggregationError(
                "adaptive policy installation record is unreadable"
            ) from exc
        if not isinstance(envelope, Mapping):
            raise AdaptiveAggregationError(
                "adaptive policy installation envelope must be an object"
            )
        if int(envelope.get("schema_version") or 0) != ADAPTIVE_POLICY_INSTALLATION_SCHEMA_VERSION:
            raise AdaptiveAggregationError(
                "unsupported adaptive policy installation schema"
            )
        record = envelope.get("record")
        if not isinstance(record, Mapping):
            raise AdaptiveAggregationError(
                "adaptive policy installation record is missing"
            )
        try:
            installation_id = str(UUID(str(record.get("installation_id"))))
            acceptance_id = str(UUID(str(record.get("acceptance_id"))))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError(
                "adaptive policy installation IDs are invalid"
            ) from exc
        if not path.name.startswith(f"{installation_id}-"):
            raise AdaptiveAggregationError(
                "adaptive policy installation ID does not match its filename"
            )
        if not acceptance_id:
            raise AdaptiveAggregationError(
                "adaptive policy installation acceptance ID is missing"
            )
        if str(envelope.get("record_sha256") or "") != _content_hash(record):
            raise AdaptiveAggregationError(
                "adaptive policy installation hash is invalid"
            )
        return dict(record)

    def _load_policy_ledger_record(self, path: Path) -> dict[str, Any]:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(envelope, Mapping):
            raise AdaptiveAggregationError("adaptive policy ledger envelope must be an object")
        if int(envelope.get("schema_version") or 0) != ADAPTIVE_POLICY_LEDGER_SCHEMA_VERSION:
            raise AdaptiveAggregationError("unsupported adaptive policy ledger schema")
        record = envelope.get("record")
        if not isinstance(record, Mapping):
            raise AdaptiveAggregationError("adaptive policy ledger record is missing")
        try:
            record_id = str(UUID(str(record.get("record_id"))))
            transition_id = str(UUID(str(record.get("transition_id"))))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError("adaptive policy ledger IDs are invalid") from exc
        if record_id != path.stem:
            raise AdaptiveAggregationError("adaptive policy ledger ID does not match its filename")
        if not transition_id:
            raise AdaptiveAggregationError("adaptive policy ledger transition ID is missing")
        if str(envelope.get("record_sha256") or "") != _content_hash(record):
            raise AdaptiveAggregationError("adaptive policy ledger hash is invalid")
        return dict(record)

    def _load_policy_acceptance_record(self, path: Path) -> dict[str, Any]:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(envelope, Mapping):
            raise AdaptiveAggregationError("adaptive policy acceptance envelope must be an object")
        if int(envelope.get("schema_version") or 0) != ADAPTIVE_POLICY_ACCEPTANCE_SCHEMA_VERSION:
            raise AdaptiveAggregationError("unsupported adaptive policy acceptance schema")
        acceptance = envelope.get("acceptance")
        if not isinstance(acceptance, Mapping):
            raise AdaptiveAggregationError("adaptive policy acceptance record is missing")
        try:
            acceptance_id = str(UUID(str(acceptance.get("acceptance_id"))))
            transition_id = str(UUID(str(acceptance.get("transition_id"))))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError("adaptive policy acceptance IDs are invalid") from exc
        if acceptance_id != path.stem:
            raise AdaptiveAggregationError("adaptive policy acceptance ID does not match its filename")
        if not transition_id:
            raise AdaptiveAggregationError("adaptive policy acceptance transition ID is missing")
        if str(envelope.get("acceptance_sha256") or "") != _content_hash(acceptance):
            raise AdaptiveAggregationError("adaptive policy acceptance hash is invalid")
        return dict(acceptance)

    def _load_policy_acceptance(self, transition_id: str) -> dict[str, Any] | None:
        for path in sorted(self.policy_acceptance_directory.glob("*.json")):
            acceptance = self._load_policy_acceptance_record(path)
            if str(acceptance.get("transition_id")) == str(transition_id):
                return acceptance
        return None

    def _record_policy_ledger_state(
        self,
        transition: Mapping[str, Any],
        *,
        status: str,
        recorded_at: datetime | None = None,
        acknowledgement_count: int = 0,
    ) -> dict[str, Any]:
        transition_id = str(UUID(str(transition["request_id"])))
        with self._lock:
            for path in sorted(self.policy_ledger_directory.glob("*.json")):
                existing = self._load_policy_ledger_record(path)
                if (
                    str(existing.get("transition_id")) == transition_id
                    and str(existing.get("status")) == status
                ):
                    return existing
            recorded = (recorded_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
            previous_fingerprint = str(transition.get("previous_policy_fingerprint") or "")
            applied_fingerprint = str(transition.get("policy_fingerprint") or "")
            required_workers = transition.get("required_workers") or ()
            record = {
                "record_id": str(uuid4()),
                "transition_id": transition_id,
                "authority_type": str(transition.get("authority_type") or "operator"),
                "prior_policy_id": str(transition.get("prior_policy_id") or _adaptive_policy_id(previous_fingerprint)),
                "policy_id": str(transition.get("policy_id") or _adaptive_policy_id(applied_fingerprint)),
                "prior_policy_fingerprint": previous_fingerprint,
                "policy_fingerprint": applied_fingerprint,
                "target_id": transition.get("target_id"),
                "aggregation_scope": transition.get("aggregation_scope"),
                "fields_affected": sorted(
                    str(key) for key in (transition.get("changes") or {}).keys()
                ),
                "change_description": str(
                    transition.get("change_description") or transition.get("reason") or ""
                )[:MAX_TRANSITION_REASON],
                "signature": transition.get("signature"),
                "signature_status": str(transition.get("signature_status") or "UNSIGNED"),
                "status": status,
                "effective_at": transition.get("effective_at") or transition.get("created_at"),
                "recorded_at": recorded.isoformat(),
                "authority_expires_at": transition.get("authority_expires_at") or transition.get("expires_at"),
                "authority_policy_generation": transition.get("authority_policy_generation"),
                "authority_policy_fingerprint": transition.get("authority_policy_fingerprint"),
                "authority_lease_id": transition.get("authority_lease_id"),
                "proposal_request_id": transition.get("proposal_request_id"),
                "proposal_review_sha256": transition.get("proposal_review_sha256"),
                "evidence_refs": list(transition.get("evidence_refs") or ()),
                "rollback_of": transition.get("rollback_of"),
                "supersedes": transition.get("supersedes"),
                "required_worker_count": len(required_workers),
                "acknowledgement_count": int(acknowledgement_count),
            }
            envelope = {
                "schema_version": ADAPTIVE_POLICY_LEDGER_SCHEMA_VERSION,
                "record": record,
                "record_sha256": _content_hash(record),
            }
            _immutable_write(self._policy_ledger_path(str(record["record_id"])), envelope)
            return record

    def list_policy_transition_ledger(
        self,
        *,
        transition_id: str | None = None,
        limit: int = 500,
    ) -> tuple[dict[str, Any], ...]:
        """List immutable adaptive-policy lineage records, newest first."""
        normalized_transition = None
        if transition_id is not None:
            try:
                normalized_transition = str(UUID(str(transition_id)))
            except (TypeError, ValueError) as exc:
                raise AdaptiveAggregationError("transition_id must be a UUID") from exc
        bounded = max(1, min(int(limit), 500))
        records: list[dict[str, Any]] = []
        for path in sorted(self.policy_ledger_directory.glob("*.json"), reverse=True):
            record = self._load_policy_ledger_record(path)
            if normalized_transition is not None and str(record.get("transition_id")) != normalized_transition:
                continue
            records.append(record)
            if len(records) >= bounded:
                break
        records.sort(key=lambda item: str(item.get("recorded_at") or ""), reverse=True)
        return tuple(records)

    def _write_acknowledgement(
        self,
        batch: Mapping[str, Any],
        *,
        status: str,
        aggregate_key: str | None = None,
        reason: str | None = None,
    ) -> None:
        payload: dict[str, Any] = {
            "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
            "batch_id": str(batch["batch_id"]),
            "batch_sha256": _content_hash(batch),
            "status": status,
            "acknowledged_at": _utcnow_iso(),
        }
        if aggregate_key is not None:
            payload["aggregate_key"] = aggregate_key
        if reason is not None:
            payload["reason"] = str(reason)[:256]
        _safe_write(self._acknowledgement_path(str(batch["batch_id"])), payload)

    def acknowledgement(self, batch_id: str) -> dict[str, Any] | None:
        """Read one supervisor acknowledgement without exposing worker payloads."""
        try:
            normalized_id = str(UUID(str(batch_id)))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError("batch_id must be a UUID") from exc
        path = self._acknowledgement_path(normalized_id)
        if not path.exists():
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, Mapping):
            raise AdaptiveAggregationError("adaptive acknowledgement must be an object")
        if str(value.get("batch_id") or "") != normalized_id:
            raise AdaptiveAggregationError("adaptive acknowledgement batch ID is invalid")
        if int(value.get("schema_version") or 0) != ADAPTIVE_AGGREGATION_SCHEMA_VERSION:
            raise AdaptiveAggregationError("unsupported adaptive acknowledgement schema")
        return dict(value)

    def _load_state(self, key: str) -> dict[str, Any] | None:
        path = self._state_path(key)
        if not path.exists():
            return None
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(envelope, Mapping):
            raise AdaptiveAggregationError("adaptive aggregate state must be an object")
        aggregate = envelope.get("aggregate")
        if not isinstance(aggregate, Mapping):
            raise AdaptiveAggregationError("adaptive aggregate state is missing its aggregate")
        if str(envelope.get("aggregate_sha256") or "") != _content_hash(aggregate):
            raise AdaptiveAggregationError("adaptive aggregate state hash is invalid")
        if str(aggregate.get("aggregate_key") or "") != key:
            raise AdaptiveAggregationError("adaptive aggregate state key is invalid")
        return dict(aggregate)

    def _write_state(self, aggregate: Mapping[str, Any]) -> None:
        payload = dict(aggregate)
        envelope = {
            "schema_version": self._STATE_SCHEMA_VERSION,
            "aggregate": payload,
            "aggregate_sha256": _content_hash(payload),
        }
        _safe_write(self._state_path(str(payload["aggregate_key"])), envelope)

    def _new_aggregate(self, batch: Mapping[str, Any], key: str) -> dict[str, Any]:
        return {
            "schema_version": self._STATE_SCHEMA_VERSION,
            "aggregate_key": key,
            "target_id": batch["target_id"],
            "aggregation_scope": batch.get("aggregation_scope"),
            "aggregation_target_id": extended_aggregation_target_id(
                str(batch["target_id"]),
                batch.get("aggregation_scope"),
            ),
            "generation_id": batch["generation_id"],
            "code_hash": batch["code_hash"],
            "monitoring_fingerprint": batch["monitoring_fingerprint"],
            "policy_fingerprint": batch["policy_fingerprint"],
            "authority_policy_generation": batch["authority_policy_generation"],
            "authority_policy_fingerprint": batch["authority_policy_fingerprint"],
            "first_observed_at": batch["first_observed_at"],
            "last_observed_at": batch["last_observed_at"],
            "total_batches": 0,
            "total_observations": 0,
            "exception_count": 0,
            "timing_breach_count": 0,
            "behavior_observation_calls": 0,
            "behavior_samples": 0,
            "repair_evidence_samples": 0,
            "problem_reproductions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "exception_events": [],
            "timing_events": [],
            "timing_duration_statistics": _duration_statistics(()),
            "resource_statistics": {},
            "workers": {},
            "worker_overflow_count": 0,
            "processed_batch_ids": [],
            "distribution_conflicts": [],
        }

    def _distribution_conflicts(
        self,
        aggregate: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        workers = aggregate.get("workers")
        if not isinstance(workers, Mapping):
            return []
        eligible = [
            (str(worker_id), worker)
            for worker_id, worker in workers.items()
            if isinstance(worker, Mapping)
            and bool(worker.get("distribution_complete"))
            and int(worker.get("observations") or 0)
            >= self.distribution_minimum_observations
        ]
        if len(eligible) < 2:
            return []
        conflicts: list[dict[str, Any]] = []
        for metric in _DISTRIBUTION_COUNTER_NAMES:
            for worker_id, worker in eligible:
                worker_observations = int(worker["observations"])
                worker_count = int(
                    (worker.get("distribution_counters") or {}).get(metric) or 0
                )
                other_observations = sum(
                    int(other["observations"])
                    for other_id, other in eligible
                    if other_id != worker_id
                )
                if other_observations < self.distribution_minimum_observations:
                    continue
                other_count = sum(
                    int((other.get("distribution_counters") or {}).get(metric) or 0)
                    for other_id, other in eligible
                    if other_id != worker_id
                )
                worker_rate = worker_count / worker_observations
                other_rate = other_count / other_observations
                baseline_rate = (worker_count + other_count) / (
                    worker_observations + other_observations
                )
                standard_error = (
                    max(baseline_rate, 1e-9)
                    * (1 / worker_observations + 1 / other_observations)
                ) ** 0.5
                z_score = abs(worker_rate - other_rate) / standard_error
                if z_score <= self.distribution_z_threshold:
                    continue
                conflicts.append({
                    "worker_id": worker_id,
                    "metric": metric,
                    "worker_rate": worker_rate,
                    "comparison_rate": other_rate,
                    "baseline_rate": baseline_rate,
                    "z_score": z_score,
                    "z_threshold": self.distribution_z_threshold,
                    "worker_observations": worker_observations,
                    "comparison_observations": other_observations,
                    "worker_count": worker_count,
                    "comparison_count": other_count,
                })
        duration_eligible = [
            (str(worker_id), worker)
            for worker_id, worker in workers.items()
            if isinstance(worker, Mapping)
            and bool(worker.get("timing_duration_complete", True))
            and isinstance(worker.get("timing_duration_statistics"), Mapping)
            and int(
                (worker.get("timing_duration_statistics") or {}).get("count") or 0
            ) >= self.distribution_minimum_observations
        ]
        if len(duration_eligible) >= 2:
            for worker_id, worker in duration_eligible:
                worker_stats = worker["timing_duration_statistics"]
                worker_count = int(worker_stats.get("count") or 0)
                other_stats = _duration_statistics(())
                for other_id, other in duration_eligible:
                    if other_id == worker_id:
                        continue
                    other_stats = _merge_duration_statistics(
                        other_stats,
                        other["timing_duration_statistics"],
                    )
                other_count = int(other_stats["count"])
                if other_count < self.distribution_minimum_observations:
                    continue
                worker_mean = float(worker_stats.get("mean") or 0.0)
                other_mean = float(other_stats.get("mean") or 0.0)
                worker_variance = (
                    float(worker_stats.get("m2") or 0.0) / (worker_count - 1)
                    if worker_count > 1
                    else 0.0
                )
                other_variance = (
                    float(other_stats.get("m2") or 0.0) / (other_count - 1)
                    if other_count > 1
                    else 0.0
                )
                standard_error = (
                    worker_variance / worker_count
                    + other_variance / other_count
                ) ** 0.5
                difference = abs(worker_mean - other_mean)
                z_score = difference / max(standard_error, 1e-12)
                if z_score <= self.distribution_z_threshold:
                    continue
                conflicts.append({
                    "worker_id": worker_id,
                    "metric": "timing_duration_seconds",
                    "worker_mean": worker_mean,
                    "comparison_mean": other_mean,
                    "worker_standard_deviation": worker_variance ** 0.5,
                    "comparison_standard_deviation": other_variance ** 0.5,
                    "z_score": z_score,
                    "z_threshold": self.distribution_z_threshold,
                    "worker_observations": worker_count,
                    "comparison_observations": other_count,
                })
        resource_metrics = sorted({
            str(metric)
            for _worker_id, worker in workers.items()
            if isinstance(worker, Mapping)
            for metric in (worker.get("resource_statistics") or {})
        })
        for metric in resource_metrics:
            resource_eligible = [
                (str(worker_id), worker)
                for worker_id, worker in workers.items()
                if isinstance(worker, Mapping)
                and isinstance((worker.get("resource_statistics") or {}).get(metric), Mapping)
                and not bool(
                    (worker.get("resource_samples_truncated") or {}).get(metric, False)
                )
                and int(
                    ((worker.get("resource_statistics") or {}).get(metric) or {}).get("count")
                    or 0
                ) >= self.distribution_minimum_observations
            ]
            if len(resource_eligible) < 2:
                continue
            for worker_id, worker in resource_eligible:
                worker_stats = (worker.get("resource_statistics") or {})[metric]
                worker_count = int(worker_stats.get("count") or 0)
                other_stats = _duration_statistics(())
                for other_id, other in resource_eligible:
                    if other_id == worker_id:
                        continue
                    other_stats = _merge_duration_statistics(
                        other_stats,
                        (other.get("resource_statistics") or {})[metric],
                    )
                other_count = int(other_stats["count"])
                if other_count < self.distribution_minimum_observations:
                    continue
                worker_mean = float(worker_stats.get("mean") or 0.0)
                other_mean = float(other_stats.get("mean") or 0.0)
                worker_variance = (
                    float(worker_stats.get("m2") or 0.0) / (worker_count - 1)
                    if worker_count > 1
                    else 0.0
                )
                other_variance = (
                    float(other_stats.get("m2") or 0.0) / (other_count - 1)
                    if other_count > 1
                    else 0.0
                )
                standard_error = (
                    worker_variance / worker_count
                    + other_variance / other_count
                ) ** 0.5
                difference = abs(worker_mean - other_mean)
                z_score = difference / max(standard_error, 1e-12)
                if z_score <= self.distribution_z_threshold:
                    continue
                conflicts.append({
                    "worker_id": worker_id,
                    "metric": f"resource:{metric}",
                    "resource_metric": metric,
                    "worker_mean": worker_mean,
                    "comparison_mean": other_mean,
                    "worker_standard_deviation": worker_variance ** 0.5,
                    "comparison_standard_deviation": other_variance ** 0.5,
                    "z_score": z_score,
                    "z_threshold": self.distribution_z_threshold,
                    "worker_observations": worker_count,
                    "comparison_observations": other_count,
                })
        return conflicts[:MAX_DISTRIBUTION_CONFLICTS]

    def _write_conflict_reports(
        self,
        aggregate: Mapping[str, Any],
    ) -> int:
        conflicts = aggregate.get("distribution_conflicts") or ()
        written = 0
        for conflict in conflicts:
            report_key = _content_hash({
                "aggregate_key": aggregate["aggregate_key"],
                "conflict": conflict,
            })
            path = self.conflict_directory / f"{report_key}.json"
            if path.exists():
                continue
            _safe_write(
                path,
                {
                    "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
                    "report_kind": "ADAPTIVE_DISTRIBUTION_CONFLICT",
                    "aggregate_key": aggregate["aggregate_key"],
                    "target_id": aggregate["target_id"],
                    "aggregation_scope": aggregate.get("aggregation_scope"),
                    "aggregation_target_id": aggregate.get("aggregation_target_id"),
                    "generation_id": aggregate["generation_id"],
                    "code_hash": aggregate["code_hash"],
                    "policy_fingerprint": aggregate["policy_fingerprint"],
                    "authority_policy_generation": aggregate["authority_policy_generation"],
                    "authority_policy_fingerprint": aggregate["authority_policy_fingerprint"],
                    "conflict": dict(conflict),
                    "evidence_retained": True,
                },
            )
            written += 1
        return written

    def _merge(self, aggregate: dict[str, Any], batch: Mapping[str, Any]) -> None:
        aggregate["first_observed_at"] = min(
            str(aggregate["first_observed_at"]), str(batch["first_observed_at"])
        )
        aggregate["last_observed_at"] = max(
            str(aggregate["last_observed_at"]), str(batch["last_observed_at"])
        )
        aggregate["timing_duration_statistics"] = _merge_duration_statistics(
            aggregate.get("timing_duration_statistics"),
            _duration_statistics(batch.get("duration_samples") or ()),
        )
        resource_statistics = dict(aggregate.get("resource_statistics") or {})
        for metric, samples in (batch.get("resource_samples") or {}).items():
            resource_statistics[metric] = _merge_duration_statistics(
                resource_statistics.get(metric),
                _duration_statistics(samples),
            )
        aggregate["resource_statistics"] = resource_statistics
        counter_names = (
            "exception_count",
            "timing_breach_count",
            "behavior_observation_calls",
            "behavior_samples",
            "repair_evidence_samples",
            "problem_reproductions",
            "successful_executions",
            "failed_executions",
        )
        for name in counter_names:
            aggregate[name] = int(aggregate.get(name) or 0) + int(batch.get(name) or 0)
        events = {
            "exception_events": list(aggregate.get("exception_events") or ())
            + list(batch.get("exception_events") or ()),
            "timing_events": list(aggregate.get("timing_events") or ())
            + list(batch.get("timing_events") or ()),
        }
        for name, values in events.items():
            aggregate[name] = sorted(values)[-self.maximum_retained_events :]
        aggregate["total_batches"] = int(aggregate.get("total_batches") or 0) + 1
        observations = int(batch["observation_count"])
        aggregate["total_observations"] = int(aggregate.get("total_observations") or 0) + observations
        workers = dict(aggregate.get("workers") or {})
        worker_id = str(batch["worker_id"])
        is_new_worker = worker_id not in workers
        worker = dict(workers.get(worker_id) or {})
        if worker_id not in workers and len(workers) >= self.maximum_workers:
            aggregate["worker_overflow_count"] = int(aggregate.get("worker_overflow_count") or 0) + 1
        else:
            distribution_counters = dict(worker.get("distribution_counters") or {})
            for name in _DISTRIBUTION_COUNTER_NAMES:
                distribution_counters[name] = int(distribution_counters.get(name) or 0) + int(
                    batch.get(name) or 0
                )
            worker.update({
                "worker_id": worker_id,
                "worker_pid": int(batch["worker_pid"]),
                "first_sequence": min(
                    int(worker.get("first_sequence", batch["sequence_start"])),
                    int(batch["sequence_start"]),
                ),
                "last_sequence": max(
                    int(worker.get("last_sequence", batch["sequence_end"])),
                    int(batch["sequence_end"]),
                ),
                "batches": int(worker.get("batches") or 0) + 1,
                "observations": int(worker.get("observations") or 0) + observations,
                "first_seen_at": min(
                    str(worker.get("first_seen_at") or batch["created_at"]),
                    str(batch["created_at"]),
                ),
                "last_seen_at": max(
                    str(worker.get("last_seen_at") or batch["created_at"]),
                    str(batch["created_at"]),
                ),
                "distribution_counters": distribution_counters,
                "distribution_complete": is_new_worker
                or bool(worker.get("distribution_complete")),
                "timing_duration_statistics": _merge_duration_statistics(
                    worker.get("timing_duration_statistics"),
                    _duration_statistics(batch.get("duration_samples") or ()),
                ),
                "timing_duration_complete": (
                    bool(worker.get("timing_duration_complete", True))
                    and not bool(batch.get("duration_samples_truncated"))
                ),
                "resource_statistics": dict(worker.get("resource_statistics") or {}),
                "resource_samples_truncated": dict(
                    worker.get("resource_samples_truncated") or {}
                ),
            })
            for metric, samples in (batch.get("resource_samples") or {}).items():
                worker["resource_statistics"][metric] = _merge_duration_statistics(
                    worker["resource_statistics"].get(metric),
                    _duration_statistics(samples),
                )
                if bool((batch.get("resource_samples_truncated") or {}).get(metric, False)):
                    worker["resource_samples_truncated"][metric] = True
            workers[worker_id] = worker
            aggregate["workers"] = workers
        processed = list(aggregate.get("processed_batch_ids") or ())
        processed.append(str(batch["batch_id"]))
        aggregate["processed_batch_ids"] = processed[-MAX_PROCESSED_BATCH_IDS:]
        aggregate["distribution_conflicts"] = self._distribution_conflicts(aggregate)

    def _context_error(
        self,
        batch: Mapping[str, Any],
        *,
        current_generations: Mapping[str, str],
        policy_fingerprint: str | None,
        policy_fingerprints: Mapping[str, str] | None,
        authority_policy_generation: str,
        authority_policy_fingerprint: str,
    ) -> str | None:
        target = str(batch["target_id"])
        aggregation_target = extended_aggregation_target_id(
            target,
            batch.get("aggregation_scope"),
        )
        if aggregation_target not in current_generations:
            return "GENERATION_CONTEXT_UNAVAILABLE"
        if str(current_generations[aggregation_target]) != str(batch["generation_id"]):
            return "STALE_GENERATION"
        expected_policy = (
            policy_fingerprints.get(aggregation_target)
            if policy_fingerprints is not None
            else policy_fingerprint
        )
        if expected_policy is None:
            return "POLICY_CONTEXT_UNAVAILABLE"
        if str(batch["policy_fingerprint"]) != str(expected_policy):
            return "STALE_POLICY"
        if str(batch["authority_policy_generation"]) != str(authority_policy_generation):
            return "STALE_AUTHORITY_GENERATION"
        if str(batch["authority_policy_fingerprint"]) != str(authority_policy_fingerprint):
            return "STALE_AUTHORITY_FINGERPRINT"
        return None

    def _reject(self, path: Path, batch: Mapping[str, Any] | None, reason: str) -> None:
        envelope: dict[str, Any] = {
            "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
            "rejection": {
                "reason": reason,
                "rejected_at": datetime.now(timezone.utc).isoformat(),
            },
        }
        if batch is not None:
            envelope["batch"] = dict(batch)
        destination = self._batch_path(self.rejected_directory, path.stem)
        if destination.exists():
            destination = self.rejected_directory / f"{path.stem}-{uuid4().hex}.json"
        _safe_write(destination, envelope)
        if batch is not None:
            self._write_acknowledgement(batch, status="REJECTED", reason=reason)
        path.unlink(missing_ok=True)

    def reconcile(
        self,
        *,
        current_generations: Mapping[str, str],
        policy_fingerprint: str | None = None,
        policy_fingerprints: Mapping[str, str] | None = None,
        authority_policy_generation: str,
        authority_policy_fingerprint: str,
        maximum_batches: int = 100,
    ) -> dict[str, Any]:
        """Merge pending batches using supervisor-owned current context."""
        if maximum_batches <= 0:
            raise ValueError("maximum_batches must be greater than zero")
        merged = 0
        duplicates = 0
        rejected = 0
        conflicts = 0
        conflict_reports = 0
        errors: list[dict[str, str]] = []
        for path in sorted(self.pending_directory.glob("*.json"))[:maximum_batches]:
            try:
                batch = self._load_batch(path)
            except Exception as exc:
                self._reject(path, None, f"INVALID_BATCH:{type(exc).__name__}")
                rejected += 1
                continue
            reason = self._context_error(
                batch,
                current_generations=current_generations,
                policy_fingerprint=policy_fingerprint,
                policy_fingerprints=policy_fingerprints,
                authority_policy_generation=authority_policy_generation,
                authority_policy_fingerprint=authority_policy_fingerprint,
            )
            if reason is not None:
                self._reject(path, batch, reason)
                rejected += 1
                continue
            key = self._aggregate_key(batch)
            try:
                aggregate = self._load_state(key) or self._new_aggregate(batch, key)
            except Exception as exc:
                errors.append({
                    "batch_id": str(batch["batch_id"]),
                    "error": f"STATE_ERROR:{type(exc).__name__}",
                })
                continue
            if str(batch["batch_id"]) in set(aggregate.get("processed_batch_ids") or ()):
                self._write_acknowledgement(
                    batch,
                    status="DUPLICATE",
                    aggregate_key=key,
                )
                path.replace(self._batch_path(self.archive_directory, str(batch["batch_id"])))
                duplicates += 1
                continue
            self._merge(aggregate, batch)
            self._write_state(aggregate)
            conflicts += len(aggregate.get("distribution_conflicts") or ())
            conflict_reports += self._write_conflict_reports(aggregate)
            self._write_acknowledgement(
                batch,
                status="ACCEPTED",
                aggregate_key=key,
            )
            path.replace(self._batch_path(self.archive_directory, str(batch["batch_id"])))
            merged += 1
        return {
            "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
            "merged": merged,
            "duplicates": duplicates,
            "rejected": rejected,
            "conflicts": conflicts,
            "conflict_reports": conflict_reports,
            "errors": errors[:20],
            "pending": sum(1 for _ in self.pending_directory.glob("*.json")),
        }

    def _load_transition_request(self, path: Path) -> dict[str, Any]:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(envelope, Mapping):
            raise AdaptiveAggregationError("adaptive transition envelope must be an object")
        if int(envelope.get("schema_version") or 0) != ADAPTIVE_AGGREGATION_SCHEMA_VERSION:
            raise AdaptiveAggregationError("unsupported adaptive transition schema")
        request = envelope.get("request")
        if not isinstance(request, Mapping):
            raise AdaptiveAggregationError("adaptive transition request is missing")
        request_id = str(UUID(str(request.get("request_id"))))
        if request_id != path.stem:
            raise AdaptiveAggregationError("transition request ID does not match its filename")
        if str(envelope.get("request_sha256") or "") != _content_hash(request):
            raise AdaptiveAggregationError("adaptive transition request hash is invalid")
        return dict(request)

    def _load_transition_acknowledgements(
        self,
        request_id: str,
    ) -> tuple[dict[str, Any], ...]:
        result: list[dict[str, Any]] = []
        for path in sorted(self.transition_acknowledgement_directory.glob(f"{request_id}-*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(value, Mapping):
                    continue
                if str(value.get("request_id") or "") != request_id:
                    continue
                payload = {
                    key: item
                    for key, item in value.items()
                    if key not in {"acknowledged_at", "acknowledgement_sha256"}
                }
                if str(value.get("acknowledgement_sha256") or "") != _content_hash(payload):
                    continue
                result.append(dict(value))
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                continue
        return tuple(result)

    def _load_proposal_review(self, request_id: str) -> dict[str, Any] | None:
        path = self._proposal_review_path(request_id)
        if not path.exists():
            return None
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(envelope, Mapping):
            raise AdaptiveAggregationError("adaptive proposal review must be an object")
        if int(envelope.get("schema_version") or 0) != ADAPTIVE_AGGREGATION_SCHEMA_VERSION:
            raise AdaptiveAggregationError("unsupported adaptive proposal review schema")
        review = envelope.get("review")
        if not isinstance(review, Mapping):
            raise AdaptiveAggregationError("adaptive proposal review is missing its review")
        normalized_id = str(UUID(str(review.get("request_id"))))
        if normalized_id != request_id or path.stem != request_id:
            raise AdaptiveAggregationError("adaptive proposal review ID is invalid")
        if str(envelope.get("review_sha256") or "") != _content_hash(review):
            raise AdaptiveAggregationError("adaptive proposal review hash is invalid")
        return dict(review)

    def _load_repair_proposal_review(self, request_id: str) -> dict[str, Any] | None:
        path = self._repair_proposal_review_path(request_id)
        if not path.exists():
            return None
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AdaptiveAggregationError("adaptive Repair proposal review is unreadable") from exc
        if not isinstance(envelope, Mapping):
            raise AdaptiveAggregationError("adaptive Repair proposal review must be an object")
        if int(envelope.get("schema_version") or 0) != ADAPTIVE_REPAIR_HANDOFF_SCHEMA_VERSION:
            raise AdaptiveAggregationError("unsupported adaptive Repair proposal review schema")
        review = envelope.get("review")
        if not isinstance(review, Mapping):
            raise AdaptiveAggregationError("adaptive Repair proposal review is missing its review")
        try:
            normalized_id = str(UUID(str(review.get("request_id"))))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError("adaptive Repair proposal review ID is invalid") from exc
        if normalized_id != request_id or path.stem != request_id:
            raise AdaptiveAggregationError("adaptive Repair proposal review ID does not match its filename")
        if str(envelope.get("review_sha256") or "") != _content_hash(review):
            raise AdaptiveAggregationError("adaptive Repair proposal review hash is invalid")
        return dict(review)

    def _load_repair_handoff(self, path: Path) -> dict[str, Any]:
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AdaptiveAggregationError("adaptive Repair handoff is unreadable") from exc
        if not isinstance(envelope, Mapping):
            raise AdaptiveAggregationError("adaptive Repair handoff must be an object")
        if int(envelope.get("schema_version") or 0) != ADAPTIVE_REPAIR_HANDOFF_SCHEMA_VERSION:
            raise AdaptiveAggregationError("unsupported adaptive Repair handoff schema")
        handoff = envelope.get("handoff")
        if not isinstance(handoff, Mapping):
            raise AdaptiveAggregationError("adaptive Repair handoff is missing its record")
        try:
            handoff_id = str(UUID(str(handoff.get("handoff_id"))))
            proposal_id = str(UUID(str(handoff.get("proposal_request_id"))))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError("adaptive Repair handoff IDs are invalid") from exc
        if handoff_id != path.stem or not proposal_id:
            raise AdaptiveAggregationError("adaptive Repair handoff ID is invalid")
        if str(envelope.get("handoff_sha256") or "") != _content_hash(handoff):
            raise AdaptiveAggregationError("adaptive Repair handoff hash is invalid")
        return dict(handoff)

    def _load_repair_handoff_outcome(self, handoff_id: str) -> dict[str, Any] | None:
        path = self._repair_handoff_outcome_path(handoff_id)
        if not path.exists():
            return None
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AdaptiveAggregationError("adaptive Repair handoff outcome is unreadable") from exc
        if not isinstance(envelope, Mapping):
            raise AdaptiveAggregationError("adaptive Repair handoff outcome must be an object")
        outcome = envelope.get("outcome")
        if not isinstance(outcome, Mapping):
            raise AdaptiveAggregationError("adaptive Repair handoff outcome is missing its record")
        try:
            normalized_id = str(UUID(str(outcome.get("handoff_id"))))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError("adaptive Repair handoff outcome ID is invalid") from exc
        if normalized_id != handoff_id or str(envelope.get("outcome_sha256") or "") != _content_hash(outcome):
            raise AdaptiveAggregationError("adaptive Repair handoff outcome hash is invalid")
        return dict(outcome)

    def _load_transition_rollback(self, request_id: str) -> dict[str, Any] | None:
        path = self._transition_rollback_path(request_id)
        if not path.exists():
            return None
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(envelope, Mapping):
            raise AdaptiveAggregationError("adaptive transition rollback must be an object")
        if int(envelope.get("schema_version") or 0) != ADAPTIVE_AGGREGATION_SCHEMA_VERSION:
            raise AdaptiveAggregationError("unsupported adaptive transition rollback schema")
        rollback = envelope.get("rollback")
        if not isinstance(rollback, Mapping):
            raise AdaptiveAggregationError("adaptive transition rollback is missing")
        normalized_id = str(UUID(str(rollback.get("transition_request_id"))))
        if normalized_id != request_id or path.stem != request_id:
            raise AdaptiveAggregationError("adaptive transition rollback ID is invalid")
        if str(envelope.get("rollback_sha256") or "") != _content_hash(rollback):
            raise AdaptiveAggregationError("adaptive transition rollback hash is invalid")
        return dict(rollback)

    @staticmethod
    def _transition_expiry(request: Mapping[str, Any]) -> datetime | None:
        raw = request.get("expires_at")
        if raw is None or not str(raw).strip():
            return None
        try:
            parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)

    @classmethod
    def _transition_status(
        cls,
        request: Mapping[str, Any],
        acknowledgements: tuple[Mapping[str, Any], ...],
        *,
        now: datetime | None = None,
    ) -> str:
        if request.get("request_kind") in {
            "ADAPTIVE_REPAIR_PROPOSAL",
            "ADAPTIVE_THRESHOLD_PROPOSAL",
        }:
            return "PROPOSAL_ONLY"
        required = {
            str(item["worker_id"])
            for item in request.get("required_workers", ())
            if isinstance(item, Mapping) and item.get("worker_id")
        }
        by_worker = {
            str(item.get("worker_id")): item
            for item in acknowledgements
            if item.get("worker_id")
        }
        if any(not bool(item.get("applied")) for item in by_worker.values()):
            return "FAILED"
        if required and required.issubset(by_worker) and all(
            bool(by_worker[worker_id].get("applied")) for worker_id in required
        ):
            return "APPLIED"
        deadline = cls._transition_expiry(request)
        if deadline is not None:
            observed_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
            if observed_at >= deadline:
                return "EXPIRED"
        if by_worker:
            return "PARTIAL"
        return "PENDING"

    def evaluate_promotions(
        self,
        *,
        current_generations: Mapping[str, str],
        policy_fingerprint: str | None = None,
        policy_fingerprints: Mapping[str, str] | None = None,
        authority_policy_generation: str,
        authority_policy_fingerprint: str,
        promotion_policies: Mapping[str, Mapping[str, Any]],
        maximum: int = 100,
    ) -> dict[str, Any]:
        """Create durable, Behavior-only requests from supervisor aggregates.

        This evaluates evidence after reconciliation and never changes a worker's
        instrumentation itself. A request is scoped to the exact aggregate and
        current authority/policy context; a worker must validate and acknowledge it
        before any local state transition can occur.
        """
        if maximum <= 0:
            raise ValueError("maximum must be greater than zero")
        created = 0
        proposals_created = 0
        existing = 0
        skipped = 0
        errors: list[dict[str, str]] = []
        existing_requests: dict[tuple[str, str], dict[str, Any]] = {}
        for path in self.transition_directory.glob("*.json"):
            try:
                request = self._load_transition_request(path)
            except Exception:
                continue
            existing_requests[(str(request.get("aggregate_key")), str(request.get("signal")))] = request

        for path in sorted(self.state_directory.glob("*.json"))[:maximum]:
            try:
                aggregate = self._load_state(path.stem)
                if aggregate is None:
                    continue
                reason = self._context_error(
                    aggregate,
                    current_generations=current_generations,
                    policy_fingerprints=policy_fingerprints,
                    policy_fingerprint=policy_fingerprint,
                    authority_policy_generation=authority_policy_generation,
                    authority_policy_fingerprint=authority_policy_fingerprint,
                )
                if reason is not None:
                    skipped += 1
                    continue
                target = str(aggregate["target_id"])
                aggregation_target = str(
                    aggregate.get("aggregation_target_id")
                    or extended_aggregation_target_id(
                        target,
                        aggregate.get("aggregation_scope"),
                    )
                )
                raw_policy = promotion_policies.get(aggregation_target)
                if raw_policy is None and aggregate.get("aggregation_scope") is None:
                    raw_policy = promotion_policies.get(target)
                if not isinstance(raw_policy, Mapping):
                    skipped += 1
                    continue
                try:
                    transition_timeout = _transition_timeout(
                        raw_policy.get("transition_timeout_seconds")
                    )
                except AdaptiveAggregationError as exc:
                    errors.append({
                        "target_id": aggregation_target,
                        "error": str(exc)[:256],
                    })
                    continue
                workers = aggregate.get("workers")
                if not isinstance(workers, Mapping) or not workers:
                    skipped += 1
                    continue
                latest = datetime.fromisoformat(str(aggregate["last_observed_at"]))
                required_workers = [
                    {
                        "worker_id": str(worker_id),
                        "worker_pid": int(worker.get("worker_pid")),
                    }
                    for worker_id, worker in sorted(workers.items())
                    if isinstance(worker, Mapping)
                ]
                if not required_workers:
                    skipped += 1
                    continue
                signals = (
                    ("exception", "exception_events"),
                    ("soft_timing", "timing_events"),
                )
                for signal, event_name in signals:
                    try:
                        policy = _promotion_policy(raw_policy.get(signal), name=signal)
                    except AdaptiveAggregationError as exc:
                        errors.append({"target_id": aggregation_target, "error": str(exc)[:256]})
                        continue
                    if not policy["enabled"]:
                        continue
                    events = []
                    for event in aggregate.get(event_name) or ():
                        observed = datetime.fromisoformat(str(event))
                        if (latest - observed).total_seconds() <= policy["window_seconds"]:
                            events.append(observed)
                    if len(events) < policy["occurrences"]:
                        continue
                    key = (str(aggregate["aggregate_key"]), signal)
                    if key in existing_requests:
                        existing += 1
                        continue
                    created_at = _utcnow_iso()
                    request: dict[str, Any] = {
                        "request_id": str(uuid4()),
                        "request_kind": "ADAPTIVE_PROMOTION",
                        "aggregate_key": str(aggregate["aggregate_key"]),
                        "target_id": target,
                        "aggregation_scope": aggregate.get("aggregation_scope"),
                        "aggregation_target_id": aggregation_target,
                        "generation_id": str(aggregate["generation_id"]),
                        "code_hash": str(aggregate["code_hash"]),
                        "monitoring_fingerprint": str(aggregate["monitoring_fingerprint"]),
                        "policy_fingerprint": str(aggregate["policy_fingerprint"]),
                        "authority_policy_generation": str(aggregate["authority_policy_generation"]),
                        "authority_policy_fingerprint": str(aggregate["authority_policy_fingerprint"]),
                        "signal": signal,
                        "signal_level": policy["promote_to"],
                        "requested_level": "BEHAVIOR",
                        "reason": (
                            f"{len(events)} {signal} threshold events within "
                            f"{policy['window_seconds']:g}s"
                        )[:MAX_TRANSITION_REASON],
                        "created_at": created_at,
                        "transition_timeout_seconds": transition_timeout,
                        "expires_at": (
                            datetime.fromisoformat(created_at)
                            + timedelta(seconds=transition_timeout)
                        ).isoformat(),
                        "required_workers": required_workers,
                    }
                    envelope = {
                        "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
                        "request": request,
                        "request_sha256": _content_hash(request),
                    }
                    _safe_write(self._transition_path(str(request["request_id"])), envelope)
                    existing_requests[key] = request
                    created += 1

                try:
                    evidence_policy = _repair_evidence_policy(
                        raw_policy.get("repair_evidence")
                    )
                except AdaptiveAggregationError as exc:
                    errors.append({"target_id": aggregation_target, "error": str(exc)[:256]})
                    evidence_policy = None
                if evidence_policy is not None and evidence_policy["enabled"]:
                    behavior_applied = any(
                        candidate.get("aggregate_key") == aggregate["aggregate_key"]
                        and candidate.get("request_kind") == "ADAPTIVE_PROMOTION"
                        and self._transition_status(
                            candidate,
                            self._load_transition_acknowledgements(
                                str(candidate["request_id"])
                            ),
                        )
                        == "APPLIED"
                        for candidate in existing_requests.values()
                    )
                    duration_seconds = max(
                        0.0,
                        (
                            latest
                            - datetime.fromisoformat(str(aggregate["first_observed_at"]))
                        ).total_seconds(),
                    )
                    evidence_sufficient = (
                        int(aggregate.get("behavior_samples") or 0)
                        >= evidence_policy["minimum_behavior_samples"]
                        and int(aggregate.get("behavior_observation_calls") or 0)
                        >= evidence_policy["minimum_observation_calls"]
                        and duration_seconds >= evidence_policy["minimum_duration_seconds"]
                        and (
                            not evidence_policy["require_problem_reproduction"]
                            or int(aggregate.get("problem_reproductions") or 0) > 0
                        )
                    )
                    key = (str(aggregate["aggregate_key"]), "repair_evidence")
                    if behavior_applied and evidence_sufficient:
                        if key in existing_requests:
                            existing += 1
                        else:
                            proposal: dict[str, Any] = {
                                "request_id": str(uuid4()),
                                "request_kind": "ADAPTIVE_REPAIR_PROPOSAL",
                                "aggregate_key": str(aggregate["aggregate_key"]),
                                "target_id": target,
                                "aggregation_scope": aggregate.get("aggregation_scope"),
                                "aggregation_target_id": aggregation_target,
                                "generation_id": str(aggregate["generation_id"]),
                                "code_hash": str(aggregate["code_hash"]),
                                "monitoring_fingerprint": str(aggregate["monitoring_fingerprint"]),
                                "policy_fingerprint": str(aggregate["policy_fingerprint"]),
                                "authority_policy_generation": str(aggregate["authority_policy_generation"]),
                                "authority_policy_fingerprint": str(aggregate["authority_policy_fingerprint"]),
                                "signal": "repair_evidence",
                                "signal_level": "REPAIR",
                                "requested_level": "REPAIR",
                                "reason": (
                                    "application-wide behavioral evidence satisfies "
                                    "the configured Repair evidence gate"
                                ),
                                "created_at": _utcnow_iso(),
                                "required_workers": required_workers,
                                "evidence": {
                                    "behavior_samples": int(aggregate.get("behavior_samples") or 0),
                                    "behavior_observation_calls": int(
                                        aggregate.get("behavior_observation_calls") or 0
                                    ),
                                    "problem_reproductions": int(
                                        aggregate.get("problem_reproductions") or 0
                                    ),
                                    "duration_seconds": duration_seconds,
                                },
                                "proposal_only": True,
                            }
                            _safe_write(
                                self._transition_path(str(proposal["request_id"])),
                                {
                                    "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
                                    "request": proposal,
                                    "request_sha256": _content_hash(proposal),
                                },
                            )
                            existing_requests[key] = proposal
                            created += 1
                            proposals_created += 1
            except Exception as exc:
                errors.append({
                    "aggregate_key": path.stem,
                    "error": f"EVALUATION_ERROR:{type(exc).__name__}",
                })
        return {
            "created": created,
            "proposals_created": proposals_created,
            "existing": existing,
            "skipped": skipped,
            "errors": errors[:20],
        }

    def create_threshold_proposal(
        self,
        *,
        target_id: str,
        aggregation_scope: str | None = None,
        generation_id: str,
        code_hash: str,
        monitoring_fingerprint: str,
        policy_fingerprint: str,
        authority_policy_generation: str,
        authority_policy_fingerprint: str,
        changes: Mapping[str, Any],
        requested_by: str,
        reason: str,
        effective_after_seconds: float = 60.0,
        expires_in_seconds: float = 3_600.0,
    ) -> dict[str, Any]:
        """Persist a delayed, threshold-only proposal without applying it.

        A proposal is evidence and operator input, not a policy mutation. The
        caller must provide the supervisor's current context so later status
        reads can identify a stale proposal before a future policy workflow
        considers it.
        """
        normalized_target = _text(
            target_id, name="target_id", limit=MAX_BATCH_TEXT
        )
        assert normalized_target is not None
        normalized_scope = _text(
            aggregation_scope,
            name="aggregation_scope",
            limit=MAX_AGGREGATION_SCOPE_TEXT,
            required=False,
        )
        aggregation_target = extended_aggregation_target_id(
            normalized_target,
            normalized_scope,
        )
        context_values = {
            "generation_id": generation_id,
            "code_hash": code_hash,
            "monitoring_fingerprint": monitoring_fingerprint,
            "policy_fingerprint": policy_fingerprint,
            "authority_policy_generation": authority_policy_generation,
            "authority_policy_fingerprint": authority_policy_fingerprint,
        }
        normalized_context = {
            name: _text(value, name=name, limit=MAX_BATCH_TEXT)
            for name, value in context_values.items()
        }
        if not 0 <= float(effective_after_seconds) <= MAX_THRESHOLD_DELAY_SECONDS:
            raise AdaptiveAggregationError(
                "effective_after_seconds must be between 0 and 86400"
            )
        if not 0 < float(expires_in_seconds) <= MAX_THRESHOLD_PROPOSAL_TTL_SECONDS:
            raise AdaptiveAggregationError(
                "expires_in_seconds must be greater than zero and no more than 86400"
            )
        normalized_changes = _threshold_changes(changes)
        proposer = _text(
            requested_by, name="requested_by", limit=MAX_BATCH_TEXT
        )
        proposal_reason = _text(
            reason, name="reason", limit=MAX_TRANSITION_REASON
        )
        assert proposer is not None and proposal_reason is not None
        created_at = _utcnow_iso()
        created = datetime.fromisoformat(created_at)
        request = {
            "request_id": str(uuid4()),
            "request_kind": "ADAPTIVE_THRESHOLD_PROPOSAL",
            "target_id": normalized_target,
            "aggregation_scope": normalized_scope,
            "aggregation_target_id": aggregation_target,
            **normalized_context,
            "changes": normalized_changes,
            "requested_by": proposer,
            "reason": proposal_reason,
            "created_at": created_at,
            "effective_after_seconds": float(effective_after_seconds),
            "effective_at": (
                created + timedelta(seconds=float(effective_after_seconds))
            ).isoformat(),
            "expires_at": (
                created + timedelta(seconds=float(expires_in_seconds))
            ).isoformat(),
            "proposal_only": True,
            "required_workers": [],
        }
        _safe_write(
            self._transition_path(str(request["request_id"])),
            {
                "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
                "request": request,
                "request_sha256": _content_hash(request),
            },
        )
        return {
            **request,
            "status": "PROPOSAL_ONLY",
            "context_status": "UNVERIFIED",
        }

    def review_threshold_proposal(
        self,
        request_id: str,
        *,
        decision: str,
        reviewed_by: str,
        reason: str,
        current_generations: Mapping[str, str],
        policy_fingerprints: Mapping[str, str],
        authority_policy_generation: str,
        authority_policy_fingerprint: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Record a context-checked review without applying a threshold change.

        An approval only makes a proposal eligible for a future staged policy
        workflow.  It never changes a policy, grants authority, or causes a
        worker to reload thresholds.
        """
        try:
            normalized_id = str(UUID(str(request_id)))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError("proposal request_id must be a UUID") from exc
        if not all(
            value is not None
            for value in (
                current_generations,
                policy_fingerprints,
                authority_policy_generation,
                authority_policy_fingerprint,
            )
        ):
            raise ValueError(
                "threshold proposal review requires generation, policy, and authority context"
            )
        request = self._load_transition_request(self._transition_path(normalized_id))
        if request.get("request_kind") != "ADAPTIVE_THRESHOLD_PROPOSAL":
            raise PermissionError("only adaptive threshold proposals can be reviewed")
        context_error = self._context_error(
            request,
            current_generations=current_generations,
            policy_fingerprints=policy_fingerprints,
            policy_fingerprint=None,
            authority_policy_generation=str(authority_policy_generation),
            authority_policy_fingerprint=str(authority_policy_fingerprint),
        )
        if context_error is not None:
            raise PermissionError(f"adaptive threshold proposal context is stale: {context_error}")
        observed_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        expiry = self._transition_expiry(request)
        if expiry is not None and observed_at >= expiry:
            raise PermissionError("adaptive threshold proposal has expired")
        normalized_decision = str(decision).strip().upper()
        if normalized_decision not in {"APPROVE", "REJECT"}:
            raise AdaptiveAggregationError("threshold proposal decision must be APPROVE or REJECT")
        reviewer = _text(reviewed_by, name="reviewed_by", limit=MAX_BATCH_TEXT)
        review_reason = _text(reason, name="reason", limit=MAX_TRANSITION_REASON)
        assert reviewer is not None and review_reason is not None
        review_status = (
            "APPROVED_FOR_STAGED_POLICY_REVIEW"
            if normalized_decision == "APPROVE"
            else "REJECTED"
        )
        review = {
            "request_id": normalized_id,
            "request_sha256": _content_hash(request),
            "review_decision": normalized_decision,
            "review_status": review_status,
            "reviewed_by": reviewer,
            "reason": review_reason,
            "reviewed_at": observed_at.isoformat(),
            "target_id": str(request["target_id"]),
            "aggregation_scope": request.get("aggregation_scope"),
            "generation_id": str(request["generation_id"]),
            "code_hash": str(request["code_hash"]),
            "monitoring_fingerprint": str(request["monitoring_fingerprint"]),
            "policy_fingerprint": str(request["policy_fingerprint"]),
            "authority_policy_generation": str(request["authority_policy_generation"]),
            "authority_policy_fingerprint": str(request["authority_policy_fingerprint"]),
            "policy_applied": False,
            "authority_granted": False,
        }
        with self._lock:
            existing = self._load_proposal_review(normalized_id)
            if existing is not None:
                comparable = {
                    key: existing.get(key)
                    for key in (
                        "request_id",
                        "request_sha256",
                        "review_decision",
                        "reviewed_by",
                        "reason",
                    )
                }
                if comparable != {
                    key: review.get(key)
                    for key in comparable
                }:
                    raise AdaptiveAggregationError("conflicting adaptive proposal review")
                return {
                    **existing,
                    "status": "DUPLICATE",
                    "proposal_only": True,
                }
            _safe_write(
                self._proposal_review_path(normalized_id),
                {
                    "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
                    "review": review,
                    "review_sha256": _content_hash(review),
                },
            )
        return {
            **review,
            "status": "RECORDED",
            "proposal_only": True,
        }

    def review_repair_proposal(
        self,
        request_id: str,
        *,
        decision: str,
        reviewed_by: str,
        reason: str,
        current_generations: Mapping[str, str],
        policy_fingerprints: Mapping[str, str],
        authority_policy_generation: str,
        authority_policy_fingerprint: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Record an operator review before an adaptive Repair handoff.

        This review is deliberately separate from Repair approval.  It only
        authorizes the supervisor to offer the retained evidence to the
        application's ordinary Repair trigger path; it never creates a
        candidate, changes policy, or grants execution authority.
        """
        try:
            normalized_id = str(UUID(str(request_id)))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError("Repair proposal request_id must be a UUID") from exc
        request = self._load_transition_request(self._transition_path(normalized_id))
        if request.get("request_kind") != "ADAPTIVE_REPAIR_PROPOSAL":
            raise PermissionError("only adaptive Repair proposals can be reviewed")
        if request.get("proposal_only") is not True:
            raise PermissionError("adaptive Repair proposal is not proposal-only evidence")
        context_error = self._context_error(
            request,
            current_generations=current_generations,
            policy_fingerprints=policy_fingerprints,
            policy_fingerprint=None,
            authority_policy_generation=str(authority_policy_generation),
            authority_policy_fingerprint=str(authority_policy_fingerprint),
        )
        if context_error is not None:
            raise PermissionError(f"adaptive Repair proposal context is stale: {context_error}")
        normalized_decision = str(decision).strip().upper()
        if normalized_decision not in {"APPROVE", "REJECT"}:
            raise AdaptiveAggregationError("Repair proposal decision must be APPROVE or REJECT")
        reviewer = _text(reviewed_by, name="reviewed_by", limit=MAX_BATCH_TEXT)
        review_reason = _text(reason, name="reason", limit=MAX_TRANSITION_REASON)
        assert reviewer is not None and review_reason is not None
        review = {
            "request_id": normalized_id,
            "request_sha256": _content_hash(request),
            "review_decision": normalized_decision,
            "review_status": (
                "APPROVED_FOR_REPAIR_HANDOFF"
                if normalized_decision == "APPROVE"
                else "REJECTED"
            ),
            "reviewed_by": reviewer,
            "reason": review_reason,
            "reviewed_at": (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(),
            "target_id": str(request["target_id"]),
            "aggregation_scope": request.get("aggregation_scope"),
            "aggregation_target_id": request.get("aggregation_target_id"),
            "generation_id": str(request["generation_id"]),
            "code_hash": str(request["code_hash"]),
            "monitoring_fingerprint": str(request["monitoring_fingerprint"]),
            "policy_fingerprint": str(request["policy_fingerprint"]),
            "authority_policy_generation": str(request["authority_policy_generation"]),
            "authority_policy_fingerprint": str(request["authority_policy_fingerprint"]),
            "repair_workflow_requested": False,
            "policy_mutated": False,
            "authority_granted": False,
        }
        path = self._repair_proposal_review_path(normalized_id)
        with self._lock:
            existing = self._load_repair_proposal_review(normalized_id)
            if existing is not None:
                comparable_keys = (
                    "request_id", "request_sha256", "review_decision", "reviewed_by", "reason"
                )
                if {key: existing.get(key) for key in comparable_keys} != {
                    key: review.get(key) for key in comparable_keys
                }:
                    raise AdaptiveAggregationError("conflicting adaptive Repair proposal review")
                return {**existing, "status": "DUPLICATE", "proposal_only": True}
            _safe_write(
                path,
                {
                    "schema_version": ADAPTIVE_REPAIR_HANDOFF_SCHEMA_VERSION,
                    "review": review,
                    "review_sha256": _content_hash(review),
                },
            )
        return {**review, "status": "RECORDED", "proposal_only": True}

    def create_adaptive_repair_handoff(
        self,
        proposal_request_id: str,
        *,
        promoted_by: str,
        reason: str,
        current_generations: Mapping[str, str],
        policy_fingerprints: Mapping[str, str],
        authority_policy_generation: str,
        authority_policy_fingerprint: str,
        dispatch_callback: Callable[[Mapping[str, Any]], Any] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Offer an approved proposal to the application's normal Repair path.

        The pending handoff is persisted before an optional application-owned
        callback runs.  A callback must explicitly acknowledge queueing; its
        result cannot grant authority or bypass ordinary Repair gates. Pending
        handoffs are not replayed automatically after restart.
        """
        try:
            normalized_id = str(UUID(str(proposal_request_id)))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError("Repair proposal request_id must be a UUID") from exc
        request = self._load_transition_request(self._transition_path(normalized_id))
        if request.get("request_kind") != "ADAPTIVE_REPAIR_PROPOSAL":
            raise PermissionError("only adaptive Repair proposals can be handed off")
        if request.get("proposal_only") is not True:
            raise PermissionError("adaptive Repair proposal is not proposal-only evidence")
        context_error = self._context_error(
            request,
            current_generations=current_generations,
            policy_fingerprints=policy_fingerprints,
            policy_fingerprint=None,
            authority_policy_generation=str(authority_policy_generation),
            authority_policy_fingerprint=str(authority_policy_fingerprint),
        )
        if context_error is not None:
            raise PermissionError(f"adaptive Repair proposal context is stale: {context_error}")
        review = self._load_repair_proposal_review(normalized_id)
        if review is None or review.get("review_status") != "APPROVED_FOR_REPAIR_HANDOFF":
            raise PermissionError("adaptive Repair proposal requires an approved operator review")
        if str(review.get("request_sha256") or "") != _content_hash(request):
            raise PermissionError("adaptive Repair proposal review is bound to different content")
        actor = _text(promoted_by, name="promoted_by", limit=MAX_BATCH_TEXT)
        handoff_reason = _text(reason, name="reason", limit=MAX_TRANSITION_REASON)
        assert actor is not None and handoff_reason is not None
        with self._lock:
            for path in sorted(self.repair_handoff_directory.glob("*.json")):
                existing = self._load_repair_handoff(path)
                if str(existing.get("proposal_request_id")) == normalized_id:
                    outcome = self._load_repair_handoff_outcome(str(existing["handoff_id"]))
                    return {
                        **existing,
                        "outcome": outcome,
                        "status": str(outcome.get("state") if outcome else "PENDING"),
                        "duplicate": True,
                    }
            created_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
            handoff = {
                "handoff_id": str(uuid4()),
                "handoff_kind": "ADAPTIVE_REPAIR_HANDOFF",
                "proposal_request_id": normalized_id,
                "proposal_sha256": _content_hash(request),
                "review_sha256": str(review.get("review_sha256") or _content_hash(review)),
                "target_id": str(request["target_id"]),
                "aggregation_scope": request.get("aggregation_scope"),
                "aggregation_target_id": request.get("aggregation_target_id"),
                "generation_id": str(request["generation_id"]),
                "code_hash": str(request["code_hash"]),
                "monitoring_fingerprint": str(request["monitoring_fingerprint"]),
                "policy_fingerprint": str(request["policy_fingerprint"]),
                "authority_policy_generation": str(request["authority_policy_generation"]),
                "authority_policy_fingerprint": str(request["authority_policy_fingerprint"]),
                "requested_level": "REPAIR",
                "promoted_by": actor,
                "reason": handoff_reason,
                "created_at": created_at.isoformat(),
                "state": "PENDING",
                "proposal_only": False,
                "policy_mutated": False,
                "authority_granted": False,
            }
            _safe_write(
                self._repair_handoff_path(str(handoff["handoff_id"])),
                {
                    "schema_version": ADAPTIVE_REPAIR_HANDOFF_SCHEMA_VERSION,
                    "handoff": handoff,
                    "handoff_sha256": _content_hash(handoff),
                },
            )
        if dispatch_callback is None:
            return {**handoff, "status": "PENDING", "outcome": None, "duplicate": False}
        try:
            response = dispatch_callback(handoff)
            accepted = isinstance(response, Mapping) and response.get("accepted") is True
            state = "DISPATCHED" if accepted else "REJECTED"
            detail = {
                "accepted": accepted,
                "queued": bool(response.get("queued")) if isinstance(response, Mapping) else False,
                "target_id": handoff["target_id"],
            }
        except Exception as exc:
            state = "FAILED"
            detail = {
                "accepted": False,
                "queued": False,
                "target_id": handoff["target_id"],
                "error": f"{type(exc).__name__}: {str(exc)[:256]}",
            }
        outcome = {
            "handoff_id": handoff["handoff_id"],
            "proposal_request_id": normalized_id,
            "state": state,
            "recorded_at": _utcnow_iso(),
            **detail,
            "policy_mutated": False,
            "authority_granted": False,
        }
        _safe_write(
            self._repair_handoff_outcome_path(str(handoff["handoff_id"])),
            {
                "schema_version": ADAPTIVE_REPAIR_HANDOFF_SCHEMA_VERSION,
                "outcome": outcome,
                "outcome_sha256": _content_hash(outcome),
            },
        )
        return {**handoff, "status": state, "outcome": outcome, "duplicate": False}

    def list_repair_handoffs(
        self,
        *,
        proposal_request_id: str | None = None,
        limit: int = 100,
    ) -> tuple[dict[str, Any], ...]:
        bounded = max(1, min(int(limit), 500))
        result: list[dict[str, Any]] = []
        for path in sorted(self.repair_handoff_directory.glob("*.json"), reverse=True):
            try:
                handoff = self._load_repair_handoff(path)
                if proposal_request_id is not None and str(handoff.get("proposal_request_id")) != str(proposal_request_id):
                    continue
                outcome = self._load_repair_handoff_outcome(str(handoff["handoff_id"]))
                visible = dict(handoff)
                visible["outcome"] = outcome
                visible["status"] = str(outcome.get("state") if outcome else "PENDING")
                result.append(visible)
            except Exception:
                continue
            if len(result) >= bounded:
                break
        result.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        return tuple(result)

    def create_threshold_policy_transition(
        self,
        proposal_request_id: str,
        *,
        applied_policy_fingerprint: str,
        current_generations: Mapping[str, str],
        current_policy_fingerprints: Mapping[str, str],
        authority_policy_generation: str,
        authority_policy_fingerprint: str,
        required_workers: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
        applied_by: str,
        reason: str,
        authority_lease_id: str | None = None,
        authority_type: str = "operator",
        prior_policy_id: str | None = None,
        policy_id: str | None = None,
        signature: Mapping[str, Any] | str | None = None,
        artifact_signer: Any | None = None,
        authority_expires_at: str | None = None,
        effective_at: datetime | None = None,
        transition_timeout_seconds: float = DEFAULT_TRANSITION_TIMEOUT_SECONDS,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Record worker verification for an already-applied threshold change.

        The application-owned authority workflow applies the policy before
        calling this method.  This method only creates a durable transition
        request whose workers must confirm the new exact context.  It never
        changes policy or grants authority.
        """
        try:
            proposal_id = str(UUID(str(proposal_request_id)))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError("proposal request_id must be a UUID") from exc
        proposal = self._load_transition_request(self._transition_path(proposal_id))
        if proposal.get("request_kind") != "ADAPTIVE_THRESHOLD_PROPOSAL":
            raise PermissionError("only adaptive threshold proposals can start a policy transition")
        review = self._load_proposal_review(proposal_id)
        if review is None or review.get("review_status") != "APPROVED_FOR_STAGED_POLICY_REVIEW":
            raise PermissionError("adaptive threshold proposal requires an approved review")
        if str(review.get("request_sha256") or "") != _content_hash(proposal):
            raise PermissionError("adaptive threshold proposal review is bound to different content")
        aggregation_target = str(
            proposal.get("aggregation_target_id")
            or extended_aggregation_target_id(
                str(proposal["target_id"]), proposal.get("aggregation_scope")
            )
        )
        if aggregation_target not in current_generations:
            raise PermissionError("adaptive threshold policy transition generation is unavailable")
        if str(current_generations[aggregation_target]) != str(proposal["generation_id"]):
            raise PermissionError("adaptive threshold policy transition generation is stale")
        previous_policy = str(proposal["policy_fingerprint"])
        applied_policy = _text(
            applied_policy_fingerprint,
            name="applied_policy_fingerprint",
            limit=MAX_BATCH_TEXT,
        )
        assert applied_policy is not None
        if applied_policy == previous_policy:
            raise AdaptiveAggregationError(
                "applied_policy_fingerprint must differ from the proposal policy fingerprint"
            )
        if str(current_policy_fingerprints.get(aggregation_target) or "") != applied_policy:
            raise PermissionError("applied adaptive policy fingerprint is not current")
        authority_generation = _text(
            authority_policy_generation,
            name="authority_policy_generation",
            limit=MAX_BATCH_TEXT,
        )
        authority_fingerprint = _text(
            authority_policy_fingerprint,
            name="authority_policy_fingerprint",
            limit=MAX_BATCH_TEXT,
        )
        actor = _text(applied_by, name="applied_by", limit=MAX_BATCH_TEXT)
        transition_reason = _text(reason, name="reason", limit=MAX_TRANSITION_REASON)
        lease_id = None
        if authority_lease_id is not None:
            try:
                lease_id = str(UUID(str(authority_lease_id)))
            except (TypeError, ValueError) as exc:
                raise AdaptiveAggregationError("authority_lease_id must be a UUID") from exc
        assert authority_generation is not None
        assert authority_fingerprint is not None
        assert actor is not None and transition_reason is not None
        normalized_authority_type = str(authority_type).strip().lower()
        if normalized_authority_type not in {"operator", "deployment", "adaptive"}:
            raise AdaptiveAggregationError(
                "authority_type must be operator, deployment, or adaptive"
            )
        if normalized_authority_type == "adaptive":
            raise PermissionError(
                "adaptive authority may propose a policy but cannot activate a persistent transition"
            )
        prior_policy_id_value = _policy_id(
            prior_policy_id,
            fingerprint=previous_policy,
            name="prior_policy_id",
        )
        policy_id_value = _policy_id(
            policy_id,
            fingerprint=applied_policy,
            name="policy_id",
        )
        signature = _normalize_transition_signature(signature)
        timeout = _transition_timeout(transition_timeout_seconds)
        if not isinstance(required_workers, (list, tuple)) or not required_workers:
            raise AdaptiveAggregationError("adaptive policy transition requires workers")
        if len(required_workers) > MAX_WORKER_PROVENANCE:
            raise AdaptiveAggregationError(
                f"adaptive policy transition exceeds {MAX_WORKER_PROVENANCE} workers"
            )
        normalized_workers: list[dict[str, Any]] = []
        worker_ids: set[str] = set()
        for item in required_workers:
            if not isinstance(item, Mapping):
                raise AdaptiveAggregationError("adaptive policy transition worker must be an object")
            worker_id = _text(item.get("worker_id"), name="worker_id", limit=MAX_BATCH_TEXT)
            if worker_id is None or worker_id in worker_ids:
                raise AdaptiveAggregationError("adaptive policy transition worker IDs must be unique")
            try:
                worker_pid = int(item.get("worker_pid"))
            except (TypeError, ValueError) as exc:
                raise AdaptiveAggregationError("adaptive policy transition worker_pid must be an integer") from exc
            if worker_pid < 0:
                raise AdaptiveAggregationError("adaptive policy transition worker_pid cannot be negative")
            worker_ids.add(worker_id)
            normalized_workers.append({"worker_id": worker_id, "worker_pid": worker_pid})
        created_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        effective_timestamp = effective_at or created_at
        if effective_timestamp.tzinfo is None:
            effective_timestamp = effective_timestamp.replace(tzinfo=timezone.utc)
        else:
            effective_timestamp = effective_timestamp.astimezone(timezone.utc)
        expires_at = created_at + timedelta(seconds=timeout)
        for path in sorted(self.transition_directory.glob("*.json")):
            try:
                existing = self._load_transition_request(path)
            except Exception:
                continue
            if (
                existing.get("request_kind") == "ADAPTIVE_POLICY_TRANSITION"
                and str(existing.get("proposal_request_id")) == proposal_id
            ):
                return {
                    **existing,
                    "status": self._transition_status(
                        existing,
                        self._load_transition_acknowledgements(str(existing["request_id"])),
                        now=created_at,
                    ),
                    "duplicate": True,
                }
        transition = {
            "request_id": str(uuid4()),
            "request_kind": "ADAPTIVE_POLICY_TRANSITION",
            "proposal_request_id": proposal_id,
            "proposal_review_sha256": str(review.get("review_sha256") or _content_hash(review)),
            "target_id": str(proposal["target_id"]),
            "aggregation_scope": proposal.get("aggregation_scope"),
            "aggregation_target_id": aggregation_target,
            "generation_id": str(proposal["generation_id"]),
            "code_hash": str(proposal["code_hash"]),
            "monitoring_fingerprint": str(proposal["monitoring_fingerprint"]),
            "previous_policy_fingerprint": previous_policy,
            "policy_fingerprint": applied_policy,
            "prior_policy_id": prior_policy_id_value,
            "policy_id": policy_id_value,
            "transition_id": None,
            "record_id": str(uuid4()),
            "authority_type": normalized_authority_type,
            "change_description": transition_reason,
            "signature": signature,
            "signature_status": "UNSIGNED" if signature is None else "UNVERIFIED",
            "authority_policy_generation": authority_generation,
            "authority_policy_fingerprint": authority_fingerprint,
            "changes": dict(proposal.get("changes") or {}),
            "requested_level": "POLICY",
            "reason": transition_reason,
            "applied_by": actor,
            "authority_lease_id": lease_id,
            "authority_expires_at": authority_expires_at,
            "policy_applied": True,
            "authority_granted": False,
            "created_at": created_at.isoformat(),
            "recorded_at": created_at.isoformat(),
            "effective_at": effective_timestamp.isoformat(),
            "transition_timeout_seconds": timeout,
            "expires_at": expires_at.isoformat(),
            "required_workers": normalized_workers,
        }
        transition["transition_id"] = transition["request_id"]
        if signature is None and artifact_signer is not None:
            try:
                signed_artifact = artifact_signer.sign_artifact(
                    artifact_kind="adaptive-policy-transition",
                    content_hash=_content_hash(_transition_signature_payload(transition)),
                    context={
                        "transition_id": transition["transition_id"],
                        "proposal_request_id": transition["proposal_request_id"],
                        "policy_id": transition["policy_id"],
                        "target_id": transition["target_id"],
                    },
                )
            except Exception as exc:
                raise AdaptiveAggregationError(
                    "adaptive policy transition signing failed"
                ) from exc
            if signed_artifact is not None:
                from .logging.signing import serialize_signed_artifact

                signature = serialize_signed_artifact(signed_artifact)
                transition["signature"] = signature
                transition["signature_status"] = signed_artifact.signer_mode.name
        _safe_write(
            self._transition_path(str(transition["request_id"])),
            {
                "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
                "request": transition,
                "request_sha256": _content_hash(transition),
            },
        )
        self._record_policy_ledger_state(
            transition,
            status="PENDING",
            recorded_at=created_at,
        )
        return {
            **transition,
            "status": "PENDING",
            "duplicate": False,
        }

    def record_transition_rollback(
        self,
        transition_request_id: str,
        *,
        rolled_back_by: str,
        reason: str,
        authority_lease_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Record an explicit rollback before a policy transition is accepted.

        The transition request remains immutable evidence.  A separate,
        content-hashed record describes the operator decision and prevents a
        later worker acknowledgement or retry from treating the staged policy
        as active.  An accepted transition requires a new incident and cannot
        be rolled back through this operation.
        """
        try:
            normalized_id = str(UUID(str(transition_request_id)))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError(
                "adaptive transition request_id must be a UUID"
            ) from exc
        stored = self._load_transition_request(self._transition_path(normalized_id))
        if stored.get("request_kind") != "ADAPTIVE_POLICY_TRANSITION":
            raise PermissionError(
                "only an adaptive policy transition can be rolled back"
            )
        existing = self._load_transition_rollback(normalized_id)
        if existing is not None:
            return {**existing, "duplicate": True}
        if self._transition_status(
            stored,
            self._load_transition_acknowledgements(normalized_id),
        ) == "APPLIED":
            raise PermissionError(
                "accepted adaptive policy transitions require a new incident"
            )
        actor = _text(rolled_back_by, name="rolled_back_by", limit=MAX_BATCH_TEXT)
        rollback_reason = _text(reason, name="reason", limit=MAX_TRANSITION_REASON)
        assert actor is not None and rollback_reason is not None
        lease_id = None
        if authority_lease_id is not None:
            try:
                lease_id = str(UUID(str(authority_lease_id)))
            except (TypeError, ValueError) as exc:
                raise AdaptiveAggregationError("authority_lease_id must be a UUID") from exc
        stored_lease_id = str(stored.get("authority_lease_id") or "") or None
        if stored_lease_id != lease_id:
            raise PermissionError("adaptive transition rollback lease does not match the transition")
        rollback = {
            "transition_request_id": normalized_id,
            "request_kind": "ADAPTIVE_POLICY_ROLLBACK",
            "proposal_request_id": stored.get("proposal_request_id"),
            "target_id": stored.get("target_id"),
            "aggregation_scope": stored.get("aggregation_scope"),
            "aggregation_target_id": stored.get("aggregation_target_id"),
            "previous_policy_fingerprint": stored.get("previous_policy_fingerprint"),
            "applied_policy_fingerprint": stored.get("policy_fingerprint"),
            "authority_lease_id": lease_id,
            "rolled_back_by": actor,
            "reason": rollback_reason,
            "created_at": (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(),
            "status": "ROLLED_BACK",
            "policy_applied": False,
            "authority_granted": False,
        }
        _safe_write(
            self._transition_rollback_path(normalized_id),
            {
                "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
                "rollback": rollback,
                "rollback_sha256": _content_hash(rollback),
            },
        )
        self._record_policy_ledger_state(
            stored,
            status="ROLLED_BACK",
            recorded_at=now,
            acknowledgement_count=0,
        )
        return {**rollback, "duplicate": False}

    def record_policy_transition_acceptance(
        self,
        transition_request_id: str,
        *,
        accepted_by: str,
        reason: str,
        policy_allows_persistent_acceptance: bool,
        current_generations: Mapping[str, str],
        current_policy_fingerprints: Mapping[str, str],
        authority_policy_generation: str,
        authority_policy_fingerprint: str,
        authority_type: str = "operator",
        incident_id: str | None = None,
        signature: Mapping[str, Any] | str | None = None,
        artifact_signer: Any | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Persist an operator acceptance of an already-applied transition.

        Acceptance is a durable deployment handoff record.  It is deliberately
        separate from the runtime transition and never changes the active
        authority stack, renews a lease, or re-applies a policy after restart.
        The exact changed context must still be live when the operator accepts
        it, so an expired runtime lease cannot be converted into persistence.
        """
        if policy_allows_persistent_acceptance is not True:
            raise PermissionError("persistent adaptive policy acceptance is disabled by policy")
        try:
            normalized_id = str(UUID(str(transition_request_id)))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError(
                "adaptive transition request_id must be a UUID"
            ) from exc
        stored = self._load_transition_request(self._transition_path(normalized_id))
        if stored.get("request_kind") != "ADAPTIVE_POLICY_TRANSITION":
            raise PermissionError("only an adaptive policy transition can be accepted")
        existing = self._load_policy_acceptance(normalized_id)
        if existing is not None:
            return {**existing, "duplicate": True}
        if self._load_transition_rollback(normalized_id) is not None:
            raise PermissionError("rolled-back adaptive policy transitions cannot be accepted")
        observed_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if self._transition_status(
            stored,
            self._load_transition_acknowledgements(normalized_id),
            now=observed_at,
        ) != "APPLIED":
            raise PermissionError("adaptive policy transition must be APPLIED before acceptance")
        authority_expiry = self._transition_expiry(
            {"expires_at": stored.get("authority_expires_at")}
        )
        if authority_expiry is not None and observed_at >= authority_expiry:
            raise PermissionError("adaptive policy transition authority has expired")
        context_error = self._context_error(
            stored,
            current_generations=current_generations,
            policy_fingerprints=current_policy_fingerprints,
            policy_fingerprint=None,
            authority_policy_generation=str(authority_policy_generation),
            authority_policy_fingerprint=str(authority_policy_fingerprint),
        )
        if context_error is not None:
            raise PermissionError(f"adaptive policy transition context is stale: {context_error}")
        actor = _text(accepted_by, name="accepted_by", limit=MAX_BATCH_TEXT)
        acceptance_reason = _text(reason, name="reason", limit=MAX_TRANSITION_REASON)
        assert actor is not None and acceptance_reason is not None
        normalized_authority_type = str(authority_type).strip().lower()
        if normalized_authority_type not in {"operator", "deployment"}:
            raise PermissionError("only operator or deployment authority can accept a persistent policy")
        normalized_incident_id = None
        if incident_id is not None and str(incident_id).strip():
            try:
                normalized_incident_id = str(UUID(str(incident_id)))
            except (TypeError, ValueError) as exc:
                raise AdaptiveAggregationError("incident_id must be a UUID") from exc
        acceptance = {
            "acceptance_id": str(uuid4()),
            "transition_id": normalized_id,
            "request_kind": "ADAPTIVE_POLICY_ACCEPTANCE",
            "proposal_request_id": stored.get("proposal_request_id"),
            "target_id": stored.get("target_id"),
            "aggregation_scope": stored.get("aggregation_scope"),
            "aggregation_target_id": stored.get("aggregation_target_id"),
            "generation_id": stored.get("generation_id"),
            "code_hash": stored.get("code_hash"),
            "monitoring_fingerprint": stored.get("monitoring_fingerprint"),
            "prior_policy_id": stored.get("prior_policy_id"),
            "policy_id": stored.get("policy_id"),
            "prior_policy_fingerprint": stored.get("previous_policy_fingerprint"),
            "policy_fingerprint": stored.get("policy_fingerprint"),
            "fields_affected": sorted(
                str(key) for key in (stored.get("changes") or {}).keys()
            ),
            "change_description": str(
                stored.get("change_description") or stored.get("reason") or ""
            )[:MAX_TRANSITION_REASON],
            "authority_type": normalized_authority_type,
            "accepted_by": actor,
            "reason": acceptance_reason,
            "incident_id": normalized_incident_id,
            "authority_policy_generation": str(authority_policy_generation),
            "authority_policy_fingerprint": str(authority_policy_fingerprint),
            "authority_lease_id": stored.get("authority_lease_id"),
            "authority_expires_at": stored.get("authority_expires_at"),
            "effective_at": stored.get("effective_at"),
            "accepted_at": observed_at.isoformat(),
            "signature": _normalize_transition_signature(signature),
            "signature_status": "UNSIGNED" if signature is None else "UNVERIFIED",
            "policy_mutated": False,
            "authority_granted": False,
        }
        if acceptance["signature"] is None and artifact_signer is not None:
            try:
                signed_artifact = artifact_signer.sign_artifact(
                    artifact_kind="adaptive-policy-acceptance",
                    content_hash=_content_hash(_policy_acceptance_signature_payload(acceptance)),
                    context={
                        "acceptance_id": acceptance["acceptance_id"],
                        "transition_id": acceptance["transition_id"],
                        "policy_id": acceptance["policy_id"],
                    },
                )
            except Exception as exc:
                raise AdaptiveAggregationError(
                    "adaptive policy acceptance signing failed"
                ) from exc
            if signed_artifact is not None:
                from .logging.signing import serialize_signed_artifact

                acceptance["signature"] = serialize_signed_artifact(signed_artifact)
                acceptance["signature_status"] = signed_artifact.signer_mode.name
        _immutable_write(
            self._policy_acceptance_path(str(acceptance["acceptance_id"])),
            {
                "schema_version": ADAPTIVE_POLICY_ACCEPTANCE_SCHEMA_VERSION,
                "acceptance": acceptance,
                "acceptance_sha256": _content_hash(acceptance),
            },
        )
        return {**acceptance, "duplicate": False}

    def install_policy_acceptance(
        self,
        acceptance_id: str,
        *,
        deployment_authority_id: str,
        deployment_authority_fingerprint: str,
        current_generations: Mapping[str, str],
        current_policy_fingerprints: Mapping[str, str],
        authority_policy_generation: str,
        authority_policy_fingerprint: str,
        installer: Callable[[Mapping[str, Any]], Any],
        reason: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Install an accepted policy through an explicit deployment callback.

        The callback is the deployment-owned boundary that may update a
        deployment artifact or persistent policy source.  Caretaker only
        validates the immutable acceptance and current context, supplies a
        bounded handoff packet, and records the callback outcome.  It never
        edits the authority stack, grants authority, or treats a callback's
        response as proof of external effects.

        A successful callback must return ``accepted=True``, the exact
        accepted policy fingerprint, and a non-empty deployment artifact hash.
        A pending handoff is retained as evidence and is not automatically
        replayed after restart; deployment must reconcile it deliberately.
        """
        try:
            normalized_acceptance_id = str(UUID(str(acceptance_id)))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError(
                "adaptive policy acceptance_id must be a UUID"
            ) from exc
        if not callable(installer):
            raise TypeError("adaptive policy installer must be callable")
        deployment_actor = _text(
            deployment_authority_id,
            name="deployment_authority_id",
            limit=MAX_BATCH_TEXT,
        )
        deployment_fingerprint = _text(
            deployment_authority_fingerprint,
            name="deployment_authority_fingerprint",
            limit=MAX_BATCH_TEXT,
        )
        installation_reason = _text(
            reason,
            name="reason",
            limit=MAX_TRANSITION_REASON,
        )
        assert deployment_actor is not None
        assert deployment_fingerprint is not None
        assert installation_reason is not None

        acceptance_path = self._policy_acceptance_path(normalized_acceptance_id)
        if not acceptance_path.exists():
            raise KeyError(f"No adaptive policy acceptance found for {normalized_acceptance_id}")
        acceptance = self._load_policy_acceptance_record(acceptance_path)
        if str(acceptance.get("request_kind")) != "ADAPTIVE_POLICY_ACCEPTANCE":
            raise PermissionError("only an adaptive policy acceptance can be installed")
        if acceptance.get("policy_mutated") is not False:
            raise PermissionError("adaptive policy acceptance has an invalid mutation marker")
        if acceptance.get("authority_granted") is not False:
            raise PermissionError("adaptive policy acceptance has an invalid authority marker")

        observed_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        expiry = self._transition_expiry(
            {"expires_at": acceptance.get("authority_expires_at")}
        )
        if expiry is not None and observed_at >= expiry:
            raise PermissionError("adaptive policy acceptance authority has expired")
        context_error = self._context_error(
            acceptance,
            current_generations=current_generations,
            policy_fingerprints=current_policy_fingerprints,
            policy_fingerprint=None,
            authority_policy_generation=str(authority_policy_generation),
            authority_policy_fingerprint=str(authority_policy_fingerprint),
        )
        if context_error is not None:
            raise PermissionError(
                f"adaptive policy acceptance context is stale: {context_error}"
            )

        with self._lock:
            records = [
                self._load_policy_installation_record(path)
                for path in sorted(self.policy_installation_directory.glob("*.json"))
            ]
            for existing in records:
                if str(existing.get("acceptance_id")) != normalized_acceptance_id:
                    continue
                if existing.get("status") == "INSTALLED":
                    audit_error = self._emit_policy_installation_audit(
                        existing,
                        duplicate=True,
                    )
                    result = {**existing, "duplicate": True}
                    if audit_error is not None:
                        result["audit_errors"] = [audit_error]
                    return result
                if existing.get("status") == "PENDING":
                    return {
                        **existing,
                        "duplicate": True,
                        "requires_reconciliation": True,
                    }
                if existing.get("status") == "RECONCILED":
                    return {
                        **existing,
                        "duplicate": True,
                        "requires_reconciliation": False,
                    }

            installation_id = str(uuid4())
            packet = {
                "acceptance_id": normalized_acceptance_id,
                "transition_id": acceptance.get("transition_id"),
                "target_id": acceptance.get("target_id"),
                "aggregation_scope": acceptance.get("aggregation_scope"),
                "generation_id": acceptance.get("generation_id"),
                "code_hash": acceptance.get("code_hash"),
                "monitoring_fingerprint": acceptance.get("monitoring_fingerprint"),
                "prior_policy_id": acceptance.get("prior_policy_id"),
                "policy_id": acceptance.get("policy_id"),
                "prior_policy_fingerprint": acceptance.get("prior_policy_fingerprint"),
                "policy_fingerprint": acceptance.get("policy_fingerprint"),
                "fields_affected": list(acceptance.get("fields_affected") or ()),
                "changes": dict(acceptance.get("changes") or {}),
                "effective_at": acceptance.get("effective_at"),
                "accepted_at": acceptance.get("accepted_at"),
                "acceptance_sha256": _content_hash(acceptance),
            }
            encoded_packet = json.dumps(
                packet,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
            if len(encoded_packet) > MAX_POLICY_INSTALLATION_RESULT_BYTES:
                raise AdaptiveAggregationError(
                    "adaptive policy installation packet is too large"
                )
            pending = {
                "installation_id": installation_id,
                "acceptance_id": normalized_acceptance_id,
                "transition_id": acceptance.get("transition_id"),
                "target_id": acceptance.get("target_id"),
                "aggregation_scope": acceptance.get("aggregation_scope"),
                "generation_id": acceptance.get("generation_id"),
                "prior_policy_id": acceptance.get("prior_policy_id"),
                "policy_id": acceptance.get("policy_id"),
                "prior_policy_fingerprint": acceptance.get("prior_policy_fingerprint"),
                "policy_fingerprint": acceptance.get("policy_fingerprint"),
                "deployment_authority_id": deployment_actor,
                "deployment_authority_fingerprint": deployment_fingerprint,
                "installed_by": deployment_actor,
                "reason": installation_reason,
                "status": "PENDING",
                "handler_status": "NOT_CALLED",
                "created_at": observed_at.isoformat(),
                "recorded_at": observed_at.isoformat(),
                "authority_policy_generation": str(authority_policy_generation),
                "authority_policy_fingerprint": str(authority_policy_fingerprint),
                "authority_expires_at": acceptance.get("authority_expires_at"),
                "acceptance_sha256": _content_hash(acceptance),
                "policy_mutated": False,
                "authority_granted": False,
            }
            _immutable_write(
                self._policy_installation_path(installation_id, "PENDING"),
                {
                    "schema_version": ADAPTIVE_POLICY_INSTALLATION_SCHEMA_VERSION,
                    "record": pending,
                    "record_sha256": _content_hash(pending),
                },
            )
        audit_errors: list[str] = []
        audit_error = self._emit_policy_installation_audit(pending)
        if audit_error is not None:
            audit_errors.append(audit_error)

        try:
            handler_result = installer(dict(packet))
        except Exception as exc:
            final_status = "FAILED"
            handler_status = "EXCEPTION"
            error = f"{type(exc).__name__}: {exc}"[:256]
            handler_result = None
        else:
            error = None
            if not isinstance(handler_result, Mapping):
                final_status = "REJECTED"
                handler_status = "INVALID_RESULT"
            elif handler_result.get("accepted") is not True:
                final_status = "REJECTED"
                handler_status = "REJECTED_BY_DEPLOYMENT"
            else:
                installed_fingerprint = str(
                    handler_result.get("policy_fingerprint")
                    or handler_result.get("installed_policy_fingerprint")
                    or ""
                ).strip()
                artifact_hash = str(
                    handler_result.get("deployment_artifact_hash") or ""
                ).strip()
                if installed_fingerprint != str(acceptance.get("policy_fingerprint")):
                    final_status = "REJECTED"
                    handler_status = "POLICY_FINGERPRINT_MISMATCH"
                elif not artifact_hash or len(artifact_hash) > MAX_BATCH_TEXT:
                    final_status = "REJECTED"
                    handler_status = "DEPLOYMENT_ARTIFACT_HASH_REQUIRED"
                else:
                    final_status = "INSTALLED"
                    handler_status = "ACCEPTED"

        final = {
            **pending,
            "status": final_status,
            "handler_status": handler_status,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        if error is not None:
            final["error"] = error
        if final_status == "INSTALLED" and isinstance(handler_result, Mapping):
            final["deployment_artifact_hash"] = str(
                handler_result.get("deployment_artifact_hash")
            )[:MAX_BATCH_TEXT]
            final["installed_policy_fingerprint"] = str(
                handler_result.get("policy_fingerprint")
                or handler_result.get("installed_policy_fingerprint")
            )[:MAX_BATCH_TEXT]
        elif isinstance(handler_result, Mapping) and handler_result.get("reason"):
            final["handler_reason"] = str(handler_result.get("reason"))[:MAX_TRANSITION_REASON]
        encoded_final = json.dumps(
            final,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded_final) > MAX_POLICY_INSTALLATION_RESULT_BYTES:
            final.pop("handler_reason", None)
            final.pop("error", None)
        _immutable_write(
            self._policy_installation_path(installation_id, final_status),
            {
                "schema_version": ADAPTIVE_POLICY_INSTALLATION_SCHEMA_VERSION,
                "record": final,
                "record_sha256": _content_hash(final),
            },
        )
        audit_error = self._emit_policy_installation_audit(final)
        if audit_error is not None:
            audit_errors.append(audit_error)
        return {
            **final,
            "duplicate": False,
            **({"audit_errors": audit_errors} if audit_errors else {}),
        }

    def reconcile_policy_installation(
        self,
        installation_id: str,
        *,
        deployment_authority_id: str,
        deployment_authority_fingerprint: str,
        observed_state: str,
        reason: str,
        observed_policy_fingerprint: str | None = None,
        deployment_artifact_hash: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Reconcile a pending external installation without replaying it.

        This is an evidence operation for a deployment crash window.  It does
        not require the runtime lease to remain active and it does not make a
        deployment report authoritative.  ``INSTALLED`` requires both the
        exact accepted policy fingerprint and an artifact hash; ``UNKNOWN``
        must remain visibly unresolved rather than being inferred as success.
        """
        try:
            normalized_id = str(UUID(str(installation_id)))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError(
                "adaptive policy installation_id must be a UUID"
            ) from exc
        actor = _text(
            deployment_authority_id,
            name="deployment_authority_id",
            limit=MAX_BATCH_TEXT,
        )
        authority_fingerprint = _text(
            deployment_authority_fingerprint,
            name="deployment_authority_fingerprint",
            limit=MAX_BATCH_TEXT,
        )
        reconciliation_reason = _text(
            reason,
            name="reason",
            limit=MAX_TRANSITION_REASON,
        )
        assert actor is not None
        assert authority_fingerprint is not None
        assert reconciliation_reason is not None
        normalized_state = str(observed_state).strip().upper()
        if normalized_state not in {"INSTALLED", "NOT_INSTALLED", "UNKNOWN"}:
            raise AdaptiveAggregationError(
                "observed_state must be INSTALLED, NOT_INSTALLED, or UNKNOWN"
            )
        observed_policy = None
        if observed_policy_fingerprint is not None and str(observed_policy_fingerprint).strip():
            observed_policy = _text(
                observed_policy_fingerprint,
                name="observed_policy_fingerprint",
                limit=MAX_BATCH_TEXT,
            )
        artifact_hash = None
        if deployment_artifact_hash is not None and str(deployment_artifact_hash).strip():
            artifact_hash = _text(
                deployment_artifact_hash,
                name="deployment_artifact_hash",
                limit=MAX_BATCH_TEXT,
            )

        records = [
            self._load_policy_installation_record(path)
            for path in sorted(self.policy_installation_directory.glob("*.json"))
            if str(path.name).startswith(f"{normalized_id}-")
        ]
        if not records:
            raise KeyError(f"No adaptive policy installation found for {normalized_id}")
        pending = next(
            (item for item in records if item.get("status") == "PENDING"),
            None,
        )
        reconciled = next(
            (item for item in records if item.get("status") == "RECONCILED"),
            None,
        )
        if reconciled is not None:
            comparable = {
                "observed_state": reconciled.get("observed_state"),
                "reason": reconciled.get("reason"),
                "observed_policy_fingerprint": reconciled.get(
                    "observed_policy_fingerprint"
                ),
                "deployment_artifact_hash": reconciled.get(
                    "deployment_artifact_hash"
                ),
            }
            requested = {
                "observed_state": normalized_state,
                "reason": reconciliation_reason,
                "observed_policy_fingerprint": observed_policy,
                "deployment_artifact_hash": artifact_hash,
            }
            if comparable != requested:
                raise AdaptiveAggregationError(
                    "conflicting adaptive policy installation reconciliation"
                )
            audit_error = self._emit_policy_installation_audit(
                reconciled,
                duplicate=True,
            )
            result = {
                **reconciled,
                "duplicate": True,
                "requires_reconciliation": False,
            }
            if audit_error is not None:
                result["audit_errors"] = [audit_error]
            return result
        if pending is None:
            raise PermissionError(
                "adaptive policy installation has no pending record to reconcile"
            )
        if pending.get("deployment_authority_id") != actor:
            raise PermissionError("deployment installation authority identity does not match")
        if pending.get("deployment_authority_fingerprint") != authority_fingerprint:
            raise PermissionError(
                "deployment installation authority fingerprint does not match"
            )
        expected_policy = str(pending.get("policy_fingerprint") or "")
        if normalized_state == "INSTALLED":
            if observed_policy != expected_policy:
                raise AdaptiveAggregationError(
                    "installed reconciliation policy fingerprint does not match acceptance"
                )
            if artifact_hash is None:
                raise AdaptiveAggregationError(
                    "installed reconciliation requires a deployment artifact hash"
                )
        else:
            if observed_policy is not None or artifact_hash is not None:
                raise AdaptiveAggregationError(
                    "non-installed reconciliation cannot claim policy or artifact state"
                )
        observed_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        final = {
            **pending,
            "status": "RECONCILED",
            "handler_status": "RECONCILED_BY_DEPLOYMENT",
            "observed_state": normalized_state,
            "observed_policy_fingerprint": observed_policy,
            "deployment_artifact_hash": artifact_hash,
            "reconciled_by": actor,
            "reason": reconciliation_reason,
            "recorded_at": observed_at.isoformat(),
            "external_install_observed": normalized_state == "INSTALLED",
            "policy_mutated": False,
            "authority_granted": False,
        }
        _immutable_write(
            self._policy_installation_path(normalized_id, "RECONCILED"),
            {
                "schema_version": ADAPTIVE_POLICY_INSTALLATION_SCHEMA_VERSION,
                "record": final,
                "record_sha256": _content_hash(final),
            },
        )
        audit_error = self._emit_policy_installation_audit(final)
        return {
            **final,
            "duplicate": False,
            **({"audit_errors": [audit_error]} if audit_error else {}),
        }

    def list_policy_installations(
        self,
        *,
        acceptance_id: str | None = None,
        limit: int = 500,
    ) -> tuple[dict[str, Any], ...]:
        """List immutable deployment installation outcomes, newest first."""
        normalized_acceptance = None
        if acceptance_id is not None:
            try:
                normalized_acceptance = str(UUID(str(acceptance_id)))
            except (TypeError, ValueError) as exc:
                raise AdaptiveAggregationError("acceptance_id must be a UUID") from exc
        bounded = max(1, min(int(limit), 500))
        records: list[dict[str, Any]] = []
        for path in sorted(self.policy_installation_directory.glob("*.json"), reverse=True):
            record = self._load_policy_installation_record(path)
            if normalized_acceptance is not None and str(record.get("acceptance_id")) != normalized_acceptance:
                continue
            records.append(record)
            if len(records) >= bounded:
                break
        records.sort(key=lambda item: str(item.get("recorded_at") or ""), reverse=True)
        return tuple(records)

    def list_policy_transition_acceptances(
        self,
        *,
        transition_id: str | None = None,
        limit: int = 500,
    ) -> tuple[dict[str, Any], ...]:
        """List immutable adaptive-policy acceptance records, newest first."""
        normalized_transition = None
        if transition_id is not None:
            try:
                normalized_transition = str(UUID(str(transition_id)))
            except (TypeError, ValueError) as exc:
                raise AdaptiveAggregationError("transition_id must be a UUID") from exc
        bounded = max(1, min(int(limit), 500))
        records: list[dict[str, Any]] = []
        for path in sorted(self.policy_acceptance_directory.glob("*.json"), reverse=True):
            record = self._load_policy_acceptance_record(path)
            if normalized_transition is not None and str(record.get("transition_id")) != normalized_transition:
                continue
            records.append(record)
            if len(records) >= bounded:
                break
        records.sort(key=lambda item: str(item.get("accepted_at") or ""), reverse=True)
        return tuple(records)

    def list_transition_requests(
        self,
        *,
        request_id: str | None = None,
        target_id: str | None = None,
        aggregation_scope: str | None = None,
        worker_id: str | None = None,
        limit: int = 100,
        now: datetime | None = None,
        current_generations: Mapping[str, str] | None = None,
        policy_fingerprints: Mapping[str, str] | None = None,
        authority_policy_generation: str | None = None,
        authority_policy_fingerprint: str | None = None,
    ) -> tuple[dict[str, Any], ...]:
        context_arguments = (
            current_generations,
            policy_fingerprints,
            authority_policy_generation,
            authority_policy_fingerprint,
        )
        if any(value is not None for value in context_arguments) and not all(
            value is not None for value in context_arguments
        ):
            raise ValueError(
                "transition context validation requires generation, policy, and authority context"
            )
        bounded = max(1, min(int(limit), 500))
        result: list[dict[str, Any]] = []
        for path in sorted(self.transition_directory.glob("*.json")):
            if len(result) >= bounded:
                break
            try:
                request = self._load_transition_request(path)
            except Exception:
                continue
            if request_id is not None and str(request.get("request_id")) != str(request_id):
                continue
            if target_id is not None and str(request.get("target_id")) != str(target_id):
                continue
            if aggregation_scope is not None and str(request.get("aggregation_scope") or "") != str(
                aggregation_scope
            ):
                continue
            required = request.get("required_workers") or ()
            if worker_id is not None and not any(
                isinstance(item, Mapping) and str(item.get("worker_id")) == str(worker_id)
                for item in required
            ):
                continue
            acknowledgements = self._load_transition_acknowledgements(str(request["request_id"]))
            visible = dict(request)
            observed_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
            visible["status"] = self._transition_status(
                request,
                acknowledgements,
                now=observed_at,
            )
            visible["acknowledgement_count"] = len(acknowledgements)
            visible["acknowledged_worker_ids"] = sorted(
                str(item["worker_id"]) for item in acknowledgements if item.get("worker_id")
            )
            deadline = self._transition_expiry(request)
            visible["deadline_status"] = (
                "UNSPECIFIED"
                if deadline is None
                else (
                    "COMPLETED"
                    if visible["status"] == "APPLIED"
                    else "EXPIRED"
                    if observed_at >= deadline
                    else "ACTIVE"
                )
            )
            required_ids = {
                str(item["worker_id"])
                for item in required
                if isinstance(item, Mapping) and item.get("worker_id")
            }
            acknowledged_ids = {
                str(item.get("worker_id"))
                for item in acknowledgements
                if item.get("worker_id")
            }
            visible["stale_worker_ids"] = sorted(
                required_ids - acknowledged_ids
            ) if visible["deadline_status"] == "EXPIRED" else []
            if deadline is None:
                visible["remaining_seconds"] = None
            else:
                visible["remaining_seconds"] = max(
                    0.0,
                    (deadline - observed_at).total_seconds(),
                )
            if current_generations is None:
                visible["context_status"] = "UNVERIFIED"
            else:
                context_error = self._context_error(
                    request,
                    current_generations=current_generations,
                    policy_fingerprints=policy_fingerprints,
                    policy_fingerprint=None,
                    authority_policy_generation=str(authority_policy_generation),
                    authority_policy_fingerprint=str(authority_policy_fingerprint),
                )
                visible["context_status"] = context_error or "CURRENT"
            if request.get("request_kind") == "ADAPTIVE_THRESHOLD_PROPOSAL":
                try:
                    review = self._load_proposal_review(str(request["request_id"]))
                except Exception as exc:
                    visible["review_status"] = "INVALID"
                    visible["review_error"] = f"{type(exc).__name__}: {exc}"[:256]
                else:
                    visible["review"] = review
                    visible["review_status"] = (
                        str(review.get("review_status"))
                        if review is not None
                        else "UNREVIEWED"
                    )
            if request.get("request_kind") == "ADAPTIVE_REPAIR_PROPOSAL":
                try:
                    review = self._load_repair_proposal_review(str(request["request_id"]))
                except Exception as exc:
                    visible["review_status"] = "INVALID"
                    visible["review_error"] = f"{type(exc).__name__}: {exc}"[:256]
                else:
                    visible["review"] = review
                    visible["review_status"] = (
                        str(review.get("review_status"))
                        if review is not None
                        else "UNREVIEWED"
                    )
                handoffs = self.list_repair_handoffs(
                    proposal_request_id=str(request["request_id"]),
                    limit=1,
                )
                if handoffs:
                    visible["repair_handoff"] = handoffs[0]
                    visible["handoff_status"] = handoffs[0].get("status")
                else:
                    visible["handoff_status"] = "NOT_REQUESTED"
            if request.get("request_kind") == "ADAPTIVE_POLICY_TRANSITION":
                try:
                    rollback = self._load_transition_rollback(str(request["request_id"]))
                except Exception as exc:
                    visible["rollback_status"] = "INVALID"
                    visible["rollback_error"] = f"{type(exc).__name__}: {exc}"[:256]
                else:
                    visible["rollback"] = rollback
                    if rollback is not None:
                        visible["rollback_status"] = "ROLLED_BACK"
                        visible["status"] = "ROLLED_BACK"
                    else:
                        visible["rollback_status"] = "NOT_REQUESTED"
                try:
                    acceptance = self._load_policy_acceptance(str(request["request_id"]))
                except Exception as exc:
                    visible["acceptance_status"] = "INVALID"
                    visible["acceptance_error"] = f"{type(exc).__name__}: {exc}"[:256]
                else:
                    visible["acceptance"] = acceptance
                    visible["acceptance_status"] = (
                        "ACCEPTED" if acceptance is not None else "NOT_RECORDED"
                    )
            result.append(visible)
        return tuple(result)

    def acknowledge_transition(
        self,
        request: Mapping[str, Any],
        *,
        peer_pid: int,
        current_generations: Mapping[str, str] | None = None,
        policy_fingerprints: Mapping[str, str] | None = None,
        authority_policy_generation: str | None = None,
        authority_policy_fingerprint: str | None = None,
    ) -> dict[str, Any]:
        """Record a worker's context-checked application of a transition request."""
        context_arguments = (
            current_generations,
            policy_fingerprints,
            authority_policy_generation,
            authority_policy_fingerprint,
        )
        if any(value is not None for value in context_arguments) and not all(
            value is not None for value in context_arguments
        ):
            raise ValueError(
                "transition context validation requires generation, policy, and authority context"
            )
        try:
            request_id = str(UUID(str(request.get("request_id"))))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError("transition request_id must be a UUID") from exc
        stored = self._load_transition_request(self._transition_path(request_id))
        if stored.get("request_kind") not in {
            "ADAPTIVE_PROMOTION",
            "ADAPTIVE_POLICY_TRANSITION",
        }:
            raise PermissionError(
                "only Behavior promotion or adaptive policy transition requests can be acknowledged"
            )
        if current_generations is not None:
            context_error = self._context_error(
                stored,
                current_generations=current_generations,
                policy_fingerprints=policy_fingerprints,
                policy_fingerprint=None,
                authority_policy_generation=str(authority_policy_generation),
                authority_policy_fingerprint=str(authority_policy_fingerprint),
            )
            if context_error is not None:
                raise PermissionError(
                    f"adaptive transition context is stale: {context_error}"
                )
        if self._load_transition_rollback(request_id) is not None:
            raise PermissionError("adaptive transition has been rolled back")
        acknowledgements = self._load_transition_acknowledgements(request_id)
        if self._transition_status(stored, acknowledgements) == "EXPIRED":
            raise PermissionError("adaptive transition request has expired")
        worker_id = _text(request.get("worker_id"), name="worker_id", limit=MAX_BATCH_TEXT)
        assert worker_id is not None
        required = {
            str(item["worker_id"]): int(item["worker_pid"])
            for item in stored.get("required_workers", ())
            if isinstance(item, Mapping) and item.get("worker_id")
        }
        if worker_id not in required:
            raise PermissionError("worker is not a required recipient of this transition")
        if int(peer_pid) != required[worker_id]:
            raise PermissionError("transition peer process does not match worker provenance")
        for name in (
            "target_id",
            "aggregation_scope",
            "generation_id",
            "code_hash",
            "monitoring_fingerprint",
            "policy_fingerprint",
            "authority_policy_generation",
            "authority_policy_fingerprint",
        ):
            if str(request.get(name) or "") != str(stored.get(name) or ""):
                raise PermissionError(f"transition {name} does not match supervisor request")
        applied = request.get("applied")
        if not isinstance(applied, bool):
            raise AdaptiveAggregationError("transition applied must be a boolean")
        observed_level = str(request.get("observed_level") or "").strip().upper()
        if applied and observed_level != str(stored["requested_level"]):
            raise PermissionError("applied transition level does not match supervisor request")
        payload: dict[str, Any] = {
            "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
            "request_id": request_id,
            "worker_id": worker_id,
            "worker_pid": int(peer_pid),
            "applied": applied,
            "observed_level": observed_level or None,
            "error": str(request.get("error") or "")[:MAX_TRANSITION_REASON] or None,
        }
        payload["acknowledgement_sha256"] = _content_hash(payload)
        path = self._transition_acknowledgement_path(request_id, worker_id)
        duplicate = False
        if path.exists():
            existing = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(existing, Mapping) or str(existing.get("acknowledgement_sha256")) != payload["acknowledgement_sha256"]:
                raise AdaptiveAggregationError("conflicting transition acknowledgement")
            duplicate = True
        else:
            _safe_write(
                path,
                {
                    **payload,
                    "acknowledged_at": _utcnow_iso(),
                },
            )
        acknowledgements = self._load_transition_acknowledgements(request_id)
        transition_status = self._transition_status(stored, acknowledgements)
        if transition_status in {"APPLIED", "FAILED"}:
            self._record_policy_ledger_state(
                stored,
                status=transition_status,
                acknowledgement_count=len(acknowledgements),
            )
        return {
            "status": "DUPLICATE" if duplicate else "RECORDED",
            "request_id": request_id,
            "worker_id": worker_id,
            "transition_status": transition_status,
        }

    def list_aggregates(self, *, limit: int = 100) -> tuple[dict[str, Any], ...]:
        bounded = max(1, min(int(limit), 500))
        result: list[dict[str, Any]] = []
        for path in sorted(self.state_directory.glob("*.json"))[:bounded]:
            try:
                aggregate = self._load_state(path.stem)
            except Exception:
                continue
            if aggregate is not None:
                visible = dict(aggregate)
                visible["processed_batch_count"] = len(
                    aggregate.get("processed_batch_ids") or ()
                )
                visible.pop("processed_batch_ids", None)
                result.append(visible)
        return tuple(result)

    def status(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
            "maximum_pending": self.maximum_pending,
            "maximum_workers": self.maximum_workers,
            "maximum_retained_events": self.maximum_retained_events,
            "distribution_z_threshold": self.distribution_z_threshold,
            "distribution_minimum_observations": self.distribution_minimum_observations,
            "pending": sum(1 for _ in self.pending_directory.glob("*.json")),
            "rejected": sum(1 for _ in self.rejected_directory.glob("*.json")),
            "acknowledgements": sum(
                1 for _ in self.acknowledgement_directory.glob("*.json")
            ),
            "aggregates": sum(1 for _ in self.state_directory.glob("*.json")),
            "transition_requests": sum(
                1 for _ in self.transition_directory.glob("*.json")
            ),
            "transition_acknowledgements": sum(
                1 for _ in self.transition_acknowledgement_directory.glob("*.json")
            ),
            "proposal_reviews": sum(
                1 for _ in self.proposal_review_directory.glob("*.json")
            ),
            "repair_proposal_reviews": sum(
                1 for _ in self.repair_proposal_review_directory.glob("*.json")
            ),
            "repair_handoffs": sum(
                1 for _ in self.repair_handoff_directory.glob("*.json")
            ),
            "repair_handoff_outcomes": sum(
                1 for _ in self.repair_handoff_outcome_directory.glob("*.json")
            ),
            "transition_rollbacks": sum(
                1 for _ in self.transition_rollback_directory.glob("*.json")
            ),
            "policy_ledger_records": sum(
                1 for _ in self.policy_ledger_directory.glob("*.json")
            ),
            "policy_acceptance_records": sum(
                1 for _ in self.policy_acceptance_directory.glob("*.json")
            ),
            "policy_installation_records": sum(
                1 for _ in self.policy_installation_directory.glob("*.json")
            ),
            "revalidations": sum(
                1 for _ in self.revalidation_directory.glob("*.json")
            ),
            "conflict_reports": sum(1 for _ in self.conflict_directory.glob("*.json")),
        }
