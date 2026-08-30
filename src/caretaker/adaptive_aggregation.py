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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from uuid import UUID, uuid4


ADAPTIVE_AGGREGATION_SCHEMA_VERSION = 1
MAX_BATCH_TEXT = 256
MAX_BATCH_EVENTS = 256
MAX_BATCH_COUNTER = 1000
MAX_WORKER_PROVENANCE = 128
MAX_PROCESSED_BATCH_IDS = 4096
MAX_RETAINED_EVENTS = 512


class AdaptiveAggregationError(ValueError):
    """Raised when an adaptive observation batch is malformed or unsafe."""


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
    normalized = {
        "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
        "batch_id": batch_id,
        "worker_id": _text(value.get("worker_id"), name="worker_id", limit=MAX_BATCH_TEXT),
        "worker_pid": worker_pid,
        "target_id": _text(value.get("target_id"), name="target_id", limit=MAX_BATCH_TEXT),
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
    ) -> None:
        if int(maximum_pending) <= 0:
            raise ValueError("maximum_pending must be greater than zero")
        if int(maximum_workers) <= 0:
            raise ValueError("maximum_workers must be greater than zero")
        if int(maximum_retained_events) <= 0:
            raise ValueError("maximum_retained_events must be greater than zero")
        self.root = Path(root)
        self.pending_directory = self.root / "adaptive" / "aggregation" / "pending"
        self.archive_directory = self.root / "adaptive" / "aggregation" / "archive"
        self.rejected_directory = self.root / "adaptive" / "aggregation" / "rejected"
        self.state_directory = self.root / "adaptive" / "aggregation" / "state"
        for directory in (
            self.pending_directory,
            self.archive_directory,
            self.rejected_directory,
            self.state_directory,
        ):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                directory.chmod(0o700)
            except OSError:
                pass
        self.maximum_pending = int(maximum_pending)
        self.maximum_workers = int(maximum_workers)
        self.maximum_retained_events = int(maximum_retained_events)

    @staticmethod
    def _batch_path(directory: Path, batch_id: str) -> Path:
        return directory / f"{batch_id}.json"

    @staticmethod
    def _aggregate_key(batch: Mapping[str, Any]) -> str:
        context = "\0".join(
            str(batch[name])
            for name in (
                "target_id",
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
        }

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
        observations = sum(int(batch.get(name) or 0) for name in counter_names)
        aggregate["total_observations"] = int(aggregate.get("total_observations") or 0) + observations
        workers = dict(aggregate.get("workers") or {})
        worker_id = str(batch["worker_id"])
        worker = dict(workers.get(worker_id) or {})
        if worker_id not in workers and len(workers) >= self.maximum_workers:
            aggregate["worker_overflow_count"] = int(aggregate.get("worker_overflow_count") or 0) + 1
        else:
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
            })
            workers[worker_id] = worker
            aggregate["workers"] = workers
        processed = list(aggregate.get("processed_batch_ids") or ())
        processed.append(str(batch["batch_id"]))
        aggregate["processed_batch_ids"] = processed[-MAX_PROCESSED_BATCH_IDS:]

    def _context_error(
        self,
        batch: Mapping[str, Any],
        *,
        current_generations: Mapping[str, str],
        policy_fingerprint: str,
        authority_policy_generation: str,
        authority_policy_fingerprint: str,
    ) -> str | None:
        target = str(batch["target_id"])
        if target not in current_generations:
            return "GENERATION_CONTEXT_UNAVAILABLE"
        if str(current_generations[target]) != str(batch["generation_id"]):
            return "STALE_GENERATION"
        if str(batch["policy_fingerprint"]) != str(policy_fingerprint):
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
        path.unlink(missing_ok=True)

    def reconcile(
        self,
        *,
        current_generations: Mapping[str, str],
        policy_fingerprint: str,
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
                path.replace(self._batch_path(self.archive_directory, str(batch["batch_id"])))
                duplicates += 1
                continue
            self._merge(aggregate, batch)
            self._write_state(aggregate)
            path.replace(self._batch_path(self.archive_directory, str(batch["batch_id"])))
            merged += 1
        return {
            "schema_version": ADAPTIVE_AGGREGATION_SCHEMA_VERSION,
            "merged": merged,
            "duplicates": duplicates,
            "rejected": rejected,
            "errors": errors[:20],
            "pending": sum(1 for _ in self.pending_directory.glob("*.json")),
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
            "pending": sum(1 for _ in self.pending_directory.glob("*.json")),
            "rejected": sum(1 for _ in self.rejected_directory.glob("*.json")),
            "aggregates": sum(1 for _ in self.state_directory.glob("*.json")),
        }
