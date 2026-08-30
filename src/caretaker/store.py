from __future__ import annotations

from .adaptive import lightweight_dependency
import dataclasses
import json
import sqlite3
from contextlib import closing
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any, Protocol
from uuid import UUID

from .integrity.models import IntegrityIncident, IntegrityVerification

from .domain import (
    CandidateGeneration,
    Incident,
    InternalIncident,
    ObservationRecord,
    PolicySnapshot,
    RepairAttempt,
    RepairCandidate,
    RepairEpisode,
    RepairEvent,
)
from .repair_recovery import RepairRecoveryRecord


class RepairStore(Protocol):
    def record_policy(self, record: PolicySnapshot) -> None: ...
    def record_incident(self, record: Incident) -> None: ...
    def record_episode(self, record: RepairEpisode) -> None: ...
    def record_generation(self, record: CandidateGeneration) -> None: ...
    def record_candidate(self, record: RepairCandidate) -> None: ...
    def record_attempt(self, record: RepairAttempt) -> None: ...
    def append_event(self, record: RepairEvent) -> None: ...
    def record_observation(self, record: ObservationRecord) -> None: ...
    def record_internal_incident(self, record: InternalIncident) -> None: ...
    def record_integrity_verification(self, record: IntegrityVerification) -> None: ...
    def record_integrity_incident(self, record: IntegrityIncident) -> None: ...
    def recent_events(self, target_id: str | None, limit: int = 50) -> tuple[RepairEvent, ...]: ...
    def attempts_for_target(self, target_id: str) -> tuple[Any, ...]: ...
    def all_attempts(self) -> tuple[Any, ...]: ...
    def record_recovery(self, record: RepairRecoveryRecord) -> None: ...
    def all_recoveries(self) -> tuple[Any, ...]: ...


class InMemoryRepairStore:
    def __init__(self, event_limit: int = 10_000) -> None:
        self.policies: dict[UUID, PolicySnapshot] = {}
        self.incidents: dict[UUID, Incident] = {}
        self.episodes: dict[UUID, RepairEpisode] = {}
        self.generations: dict[UUID, CandidateGeneration] = {}
        self.candidates: dict[UUID, RepairCandidate] = {}
        self.attempts: dict[UUID, RepairAttempt] = {}
        self.recoveries: dict[str, RepairRecoveryRecord] = {}
        self.observations: dict[UUID, ObservationRecord] = {}
        self.internal_incidents: dict[UUID, InternalIncident] = {}
        self.integrity_verifications: dict[UUID, IntegrityVerification] = {}
        self.integrity_incidents: dict[UUID, IntegrityIncident] = {}
        self.events: deque[RepairEvent] = deque(maxlen=event_limit)
        self._lock = RLock()

    def record_policy(self, record: PolicySnapshot) -> None:
        with self._lock:
            self.policies[record.policy_snapshot_id] = record

    def record_incident(self, record: Incident) -> None:
        with self._lock:
            self.incidents[record.incident_id] = record

    def record_episode(self, record: RepairEpisode) -> None:
        with self._lock:
            self.episodes[record.episode_id] = record

    def record_generation(self, record: CandidateGeneration) -> None:
        with self._lock:
            self.generations[record.generation_id] = record

    def record_candidate(self, record: RepairCandidate) -> None:
        with self._lock:
            self.candidates[record.candidate_id] = record

    def record_attempt(self, record: RepairAttempt) -> None:
        with self._lock:
            self.attempts[record.attempt_id] = record

    def append_event(self, record: RepairEvent) -> None:
        with self._lock:
            self.events.append(record)

    def record_observation(self, record: ObservationRecord) -> None:
        with self._lock:
            self.observations[record.observation_id] = record

    def record_internal_incident(self, record: InternalIncident) -> None:
        with self._lock:
            self.internal_incidents[record.internal_incident_id] = record

    def record_integrity_verification(self, record: IntegrityVerification) -> None:
        with self._lock:
            self.integrity_verifications[record.verification_id] = record

    def record_integrity_incident(self, record: IntegrityIncident) -> None:
        with self._lock:
            self.integrity_incidents[record.incident_id] = record

    def recent_events(self, target_id: str | None, limit: int = 50) -> tuple[RepairEvent, ...]:
        with self._lock:
            events = [
                event for event in self.events
                if target_id is None or event.target_id == target_id
            ]
            return tuple(events[-limit:])

    def attempts_for_target(self, target_id: str) -> tuple[RepairAttempt, ...]:
        with self._lock:
            return tuple(
                sorted(
                    (attempt for attempt in self.attempts.values() if attempt.target_id == target_id),
                    key=lambda attempt: attempt.created_at,
                )
            )

    def all_attempts(self) -> tuple[RepairAttempt, ...]:
        with self._lock:
            return tuple(sorted(self.attempts.values(), key=lambda attempt: attempt.created_at))

    def record_recovery(self, record: RepairRecoveryRecord) -> None:
        with self._lock:
            self.recoveries.setdefault(record.attempt_id, record)

    def all_recoveries(self) -> tuple[RepairRecoveryRecord, ...]:
        with self._lock:
            return tuple(sorted(self.recoveries.values(), key=lambda record: record.observed_at))


class SQLiteRepairStore:
    """Small JSON-backed event store with one logical stream per table."""

    _TABLES = {
        "policy_snapshots": "policy_snapshot_id",
        "incidents": "incident_id",
        "episodes": "episode_id",
        "generations": "generation_id",
        "candidates": "candidate_id",
        "attempts": "attempt_id",
        "recovery_records": "recovery_id",
        "events": "event_id",
        "observations": "observation_id",
        "internal_incidents": "internal_incident_id",
        "integrity_verifications": "verification_id",
        "integrity_incidents": "incident_id",
    }

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()

    @lightweight_dependency(target_id="caretaker.dependency.sqlite.repair-store")
    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS caretaker_store_metadata "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT OR REPLACE INTO caretaker_store_metadata(key, value) VALUES ('schema_version', '2')"
            )
            for table in self._TABLES:
                connection.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {table} (
                        record_id TEXT PRIMARY KEY,
                        target_id TEXT,
                        created_at TEXT NOT NULL,
                        payload TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    f"CREATE INDEX IF NOT EXISTS {table}_target_idx ON {table}(target_id, created_at)"
                )
            connection.commit()

    def _write(self, table: str, record: object, *, target_id: str | None, append: bool = False) -> None:
        id_field = self._TABLES[table]
        record_id = str(getattr(record, id_field))
        created_at = _record_time(record).isoformat()
        payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        statement = "INSERT" if append else "INSERT OR REPLACE"
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"{statement} INTO {table}(record_id, target_id, created_at, payload) VALUES (?, ?, ?, ?)",
                (record_id, target_id, created_at, payload),
            )
            connection.commit()

    def record_policy(self, record: PolicySnapshot) -> None:
        self._write("policy_snapshots", record, target_id=None)

    def record_incident(self, record: Incident) -> None:
        self._write("incidents", record, target_id=record.target.target_id)

    def record_episode(self, record: RepairEpisode) -> None:
        self._write("episodes", record, target_id=record.target_id)

    def record_generation(self, record: CandidateGeneration) -> None:
        self._write("generations", record, target_id=record.target_id)

    def record_candidate(self, record: RepairCandidate) -> None:
        self._write("candidates", record, target_id=record.target_id)

    def record_attempt(self, record: RepairAttempt) -> None:
        self._write("attempts", record, target_id=record.target_id)

    def append_event(self, record: RepairEvent) -> None:
        self._write("events", record, target_id=record.target_id, append=True)

    def record_observation(self, record: ObservationRecord) -> None:
        self._write("observations", record, target_id=record.target_id)

    def record_internal_incident(self, record: InternalIncident) -> None:
        self._write("internal_incidents", record, target_id=record.active_target_id)

    def record_integrity_verification(self, record: IntegrityVerification) -> None:
        self._write("integrity_verifications", record, target_id=None)

    def record_integrity_incident(self, record: IntegrityIncident) -> None:
        self._write("integrity_incidents", record, target_id=None)

    def recent_events(self, target_id: str | None, limit: int = 50) -> tuple[RepairEvent, ...]:
        rows = self.query_records("events", target_id=target_id, limit=limit)
        events: list[RepairEvent] = []
        for payload in rows:
            events.append(
                RepairEvent(
                    event_id=UUID(payload["event_id"]),
                    timestamp=datetime.fromisoformat(payload["timestamp"]),
                    event_type=payload["event_type"],
                    target_id=payload["target_id"],
                    incident_id=UUID(payload["incident_id"]) if payload.get("incident_id") else None,
                    episode_id=UUID(payload["episode_id"]) if payload.get("episode_id") else None,
                    attempt_id=UUID(payload["attempt_id"]) if payload.get("attempt_id") else None,
                    candidate_id=UUID(payload["candidate_id"]) if payload.get("candidate_id") else None,
                    details=payload.get("details", {}),
                )
            )
        return tuple(events)

    def attempts_for_target(self, target_id: str) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("attempts", target_id=target_id, limit=10000))

    def all_attempts(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("attempts", limit=10000))

    def record_recovery(self, record: RepairRecoveryRecord) -> None:
        self._write("recovery_records", record, target_id=record.target_id)

    def all_recoveries(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("recovery_records", limit=10000))

    def query_records(
        self,
        table: str,
        *,
        target_id: str | None = None,
        limit: int = 100,
    ) -> tuple[Mapping[str, Any], ...]:
        if table not in self._TABLES:
            raise ValueError(f"Unknown Caretaker store table: {table}")
        sql = f"SELECT payload FROM {table}"
        parameters: list[Any] = []
        if target_id is not None:
            sql += " WHERE target_id = ?"
            parameters.append(target_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        parameters.append(max(0, limit))
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return tuple(json.loads(row[0]) for row in reversed(rows))

    @property
    def schema_version(self) -> int:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT value FROM caretaker_store_metadata WHERE key='schema_version'"
            ).fetchone()
        return int(row[0]) if row else 0


def _record_time(record: object) -> datetime:
    for name in ("timestamp", "occurred_at", "created_at", "calculated_at"):
        value = getattr(record, name, None)
        if isinstance(value, datetime):
            return value
    return datetime.now().astimezone()


def _jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {field.name: _jsonable(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset, deque)):
        return [_jsonable(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return {"type": f"{type(value).__module__}.{type(value).__qualname__}", "repr": _safe_repr(value)}


def _safe_repr(value: object) -> str:
    try:
        return repr(value)
    except Exception as exc:  # pragma: no cover - defensive path
        return f"<repr failed: {type(exc).__name__}: {exc}>"
