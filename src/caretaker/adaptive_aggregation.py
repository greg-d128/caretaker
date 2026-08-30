"""Durable supervisor-owned aggregation for adaptive worker observations.

Workers submit bounded, non-authoritative observation batches.  Only the
supervisor-side ledger merges them, and it accepts a batch only when the
supervisor supplies matching target-generation and policy context.  This
module intentionally does not make promotion or Repair decisions yet; it
provides the durable ownership and protocol boundary those decisions require.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from uuid import UUID, uuid4


ADAPTIVE_AGGREGATION_SCHEMA_VERSION = 1
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
    ) -> None:
        if not 0 < int(flush_after_observations) <= MAX_BATCH_COUNTER:
            raise ValueError(
                f"flush_after_observations must be between 1 and {MAX_BATCH_COUNTER}"
            )
        if float(flush_interval_seconds) < 0:
            raise ValueError("flush_interval_seconds cannot be negative")
        extended_aggregation_target_id(str(target_id), aggregation_scope)
        self.store = store
        self.worker_id = str(worker_id)
        self.worker_pid = int(worker_pid)
        self.flush_after_observations = int(flush_after_observations)
        self.flush_interval_seconds = float(flush_interval_seconds)
        self._lock = threading.RLock()
        self._sequence = 0
        self._records = 0
        self._first_observed_at: str | None = None
        self._last_observed_at: str | None = None
        self._counters = {name: 0 for name in _BATCH_COUNTER_NAMES}
        self._events = {"exception_events": [], "timing_events": []}
        self._last_flush_monotonic = time.monotonic()
        self._last_error: str | None = None
        self._dropped_records = 0
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
        **increments: int,
    ) -> dict[str, Any] | None:
        """Record one observation and flush when the bounded policy requires it."""
        with self._lock:
            if event_kind not in {None, "exception", "timing"}:
                raise ValueError("event_kind must be exception or timing")
            for name, value in increments.items():
                if name not in _BATCH_COUNTER_NAMES:
                    raise ValueError(f"unknown adaptive aggregation counter: {name}")
                if isinstance(value, bool) or int(value) < 0:
                    raise ValueError(f"{name} must be a non-negative integer")
                if int(value) > MAX_BATCH_COUNTER:
                    raise ValueError(f"{name} exceeds {MAX_BATCH_COUNTER}")
            if self._records >= MAX_BATCH_COUNTER:
                result = self._flush_locked()
                if result is not None and result.get("status") == "ERROR":
                    self._dropped_records += 1
                    return result
            timestamp = observed_at or _utcnow_iso()
            self._records += 1
            self._sequence += 1
            self._first_observed_at = self._first_observed_at or timestamp
            self._last_observed_at = timestamp
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
            }

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
        }

    def _reset_locked(self) -> None:
        self._records = 0
        self._first_observed_at = None
        self._last_observed_at = None
        self._counters = {name: 0 for name in _BATCH_COUNTER_NAMES}
        self._events = {"exception_events": [], "timing_events": []}
        self._last_flush_monotonic = time.monotonic()

    def _flush_locked(self) -> dict[str, Any] | None:
        if self._records <= 0:
            return None
        batch = self._snapshot_locked()
        try:
            result = self.store.submit(batch)
        except Exception as exc:
            self._last_error = f"{type(exc).__name__}: {exc}"[:256]
            return {"status": "ERROR", "error": self._last_error}
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
    }
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
    return normalized


def _content_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


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
        self.conflict_directory = self.root / "adaptive" / "aggregation" / "conflicts"
        for directory in (
            self.pending_directory,
            self.archive_directory,
            self.rejected_directory,
            self.acknowledgement_directory,
            self.state_directory,
            self.transition_directory,
            self.transition_acknowledgement_directory,
            self.conflict_directory,
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

    def _state_path(self, key: str) -> Path:
        return self.state_directory / f"{key}.json"

    def _acknowledgement_path(self, batch_id: str) -> Path:
        return self.acknowledgement_directory / f"{batch_id}.json"

    def _transition_path(self, request_id: str) -> Path:
        return self.transition_directory / f"{request_id}.json"

    def _transition_acknowledgement_path(self, request_id: str, worker_id: str) -> Path:
        worker_key = hashlib.sha256(worker_id.encode("utf-8")).hexdigest()[:32]
        return self.transition_acknowledgement_directory / f"{request_id}-{worker_key}.json"

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
            })
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

    @staticmethod
    def _transition_status(
        request: Mapping[str, Any],
        acknowledgements: tuple[Mapping[str, Any], ...],
    ) -> str:
        if request.get("request_kind") == "ADAPTIVE_REPAIR_PROPOSAL":
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
                        "created_at": _utcnow_iso(),
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

    def list_transition_requests(
        self,
        *,
        target_id: str | None = None,
        aggregation_scope: str | None = None,
        worker_id: str | None = None,
        limit: int = 100,
    ) -> tuple[dict[str, Any], ...]:
        bounded = max(1, min(int(limit), 500))
        result: list[dict[str, Any]] = []
        for path in sorted(self.transition_directory.glob("*.json")):
            if len(result) >= bounded:
                break
            try:
                request = self._load_transition_request(path)
            except Exception:
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
            visible["status"] = self._transition_status(request, acknowledgements)
            visible["acknowledgement_count"] = len(acknowledgements)
            visible["acknowledged_worker_ids"] = sorted(
                str(item["worker_id"]) for item in acknowledgements if item.get("worker_id")
            )
            result.append(visible)
        return tuple(result)

    def acknowledge_transition(
        self,
        request: Mapping[str, Any],
        *,
        peer_pid: int,
    ) -> dict[str, Any]:
        """Record a worker's context-checked application of a transition request."""
        try:
            request_id = str(UUID(str(request.get("request_id"))))
        except (TypeError, ValueError) as exc:
            raise AdaptiveAggregationError("transition request_id must be a UUID") from exc
        stored = self._load_transition_request(self._transition_path(request_id))
        if stored.get("request_kind") != "ADAPTIVE_PROMOTION":
            raise PermissionError("only Behavior promotion requests can be acknowledged")
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
        return {
            "status": "DUPLICATE" if duplicate else "RECORDED",
            "request_id": request_id,
            "worker_id": worker_id,
            "transition_status": self._transition_status(stored, acknowledgements),
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
            "conflict_reports": sum(1 for _ in self.conflict_directory.glob("*.json")),
        }
