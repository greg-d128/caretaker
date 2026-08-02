from __future__ import annotations

import dataclasses
import json
import sqlite3
from collections import deque
from collections.abc import Mapping
from contextlib import closing
from datetime import datetime
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any, Protocol
from uuid import UUID

from .models import BehaviorEvent, BehaviorWindow, CodeIdentity, RuntimeInspection


class EvidenceStore(Protocol):
    def record_code_identity(self, record: CodeIdentity) -> None: ...
    def append_behavior_event(self, record: BehaviorEvent) -> None: ...
    def record_behavior_window(self, record: BehaviorWindow) -> None: ...
    def record_inspection(self, record: RuntimeInspection) -> None: ...
    def record_guard_baseline(self, record: object) -> None: ...
    def record_guard_deviation(self, record: object) -> None: ...
    def record_guard_assessment(self, record: object) -> None: ...
    def record_guard_decision(self, record: object) -> None: ...
    def recent_behavior_events(
        self,
        *,
        target_id: str | None = None,
        module_name: str | None = None,
        limit: int = 100,
    ) -> tuple[BehaviorEvent | Mapping[str, Any], ...]: ...
    def recent_inspections(
        self,
        module_name: str,
        *,
        limit: int = 20,
    ) -> tuple[RuntimeInspection | Mapping[str, Any], ...]: ...


class InMemoryEvidenceStore:
    def __init__(self, event_limit: int = 100_000) -> None:
        self.identities: dict[str, CodeIdentity] = {}
        self.events: deque[BehaviorEvent] = deque(maxlen=event_limit)
        self.windows: dict[UUID, BehaviorWindow] = {}
        self.inspections: dict[UUID, RuntimeInspection] = {}
        self.guard_baselines: dict[UUID, object] = {}
        self.guard_deviations: dict[UUID, object] = {}
        self.guard_assessments: dict[UUID, object] = {}
        self.guard_decisions: dict[UUID, object] = {}
        self._lock = RLock()

    @staticmethod
    def _identity_key(record: CodeIdentity) -> str:
        return "|".join(
            (
                record.distribution_name or "",
                record.distribution_version or "",
                record.module_name,
                record.qualified_name or "",
                record.source_hash or "",
                record.bytecode_hash or "",
            )
        )

    def record_code_identity(self, record: CodeIdentity) -> None:
        with self._lock:
            self.identities[self._identity_key(record)] = record

    def append_behavior_event(self, record: BehaviorEvent) -> None:
        with self._lock:
            self.events.append(record)

    def record_behavior_window(self, record: BehaviorWindow) -> None:
        with self._lock:
            self.windows[record.window_id] = record

    def record_inspection(self, record: RuntimeInspection) -> None:
        with self._lock:
            self.inspections[record.inspection_id] = record

    def record_guard_baseline(self, record: object) -> None:
        with self._lock:
            self.guard_baselines[getattr(record, "baseline_id")] = record

    def record_guard_deviation(self, record: object) -> None:
        with self._lock:
            self.guard_deviations[getattr(record, "deviation_id")] = record

    def record_guard_assessment(self, record: object) -> None:
        with self._lock:
            self.guard_assessments[getattr(record, "assessment_id")] = record

    def record_guard_decision(self, record: object) -> None:
        with self._lock:
            self.guard_decisions[getattr(record, "decision_id")] = record

    def recent_behavior_events(
        self,
        *,
        target_id: str | None = None,
        module_name: str | None = None,
        limit: int = 100,
    ) -> tuple[BehaviorEvent, ...]:
        with self._lock:
            matches = [
                event
                for event in self.events
                if (target_id is None or event.target_id == target_id)
                and (module_name is None or event.code_identity.module_name == module_name)
            ]
            return tuple(matches[-limit:])

    def recent_inspections(
        self,
        module_name: str,
        *,
        limit: int = 20,
    ) -> tuple[RuntimeInspection, ...]:
        with self._lock:
            matches = [
                inspection
                for inspection in self.inspections.values()
                if inspection.subject.module_name == module_name
            ]
            matches.sort(key=lambda item: item.occurred_at)
            return tuple(matches[-limit:])


class SQLiteEvidenceStore:
    """Normalized SQLite evidence store for Guard analytics.

    Large detail fields remain JSON, while high-value dimensions are indexed as
    ordinary columns for direct SQL exploration.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS evidence_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                INSERT OR REPLACE INTO evidence_metadata(key, value)
                VALUES ('schema_version', '1');

                CREATE TABLE IF NOT EXISTS code_identities (
                    identity_key TEXT PRIMARY KEY,
                    distribution_name TEXT,
                    distribution_version TEXT,
                    module_name TEXT NOT NULL,
                    qualified_name TEXT,
                    source_hash TEXT,
                    bytecode_hash TEXT,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS code_identity_module_idx
                    ON code_identities(module_name, qualified_name);

                CREATE TABLE IF NOT EXISTS behavior_events (
                    event_id TEXT PRIMARY KEY,
                    occurred_at TEXT NOT NULL,
                    event_kind TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    target_id TEXT,
                    call_id TEXT,
                    module_name TEXT NOT NULL,
                    qualified_name TEXT,
                    resource_kind TEXT,
                    resource_value TEXT,
                    outcome TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS behavior_target_time_idx
                    ON behavior_events(target_id, occurred_at);
                CREATE INDEX IF NOT EXISTS behavior_module_time_idx
                    ON behavior_events(module_name, occurred_at);
                CREATE INDEX IF NOT EXISTS behavior_resource_idx
                    ON behavior_events(resource_kind, resource_value);

                CREATE TABLE IF NOT EXISTS behavior_windows (
                    window_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    qualified_name TEXT,
                    event_count INTEGER NOT NULL,
                    call_count INTEGER NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS behavior_window_subject_idx
                    ON behavior_windows(module_name, qualified_name, completed_at);

                CREATE TABLE IF NOT EXISTS runtime_inspections (
                    inspection_id TEXT PRIMARY KEY,
                    occurred_at TEXT NOT NULL,
                    inspection_kind TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    qualified_name TEXT,
                    source_fingerprint TEXT,
                    runtime_fingerprint TEXT,
                    significant_change_count INTEGER NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS runtime_inspection_subject_idx
                    ON runtime_inspections(module_name, qualified_name, occurred_at);

                CREATE TABLE IF NOT EXISTS guard_baselines (
                    baseline_id TEXT PRIMARY KEY,
                    module_name TEXT NOT NULL,
                    qualified_name TEXT,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    accepted_at TEXT,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS guard_baseline_subject_idx
                    ON guard_baselines(module_name, qualified_name, created_at);

                CREATE TABLE IF NOT EXISTS guard_deviations (
                    deviation_id TEXT PRIMARY KEY,
                    baseline_id TEXT NOT NULL,
                    observation_window_id TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    qualified_name TEXT,
                    category TEXT NOT NULL,
                    significance_score REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS guard_deviation_subject_idx
                    ON guard_deviations(module_name, qualified_name, significance_score, created_at);

                CREATE TABLE IF NOT EXISTS guard_assessments (
                    assessment_id TEXT PRIMARY KEY,
                    module_name TEXT NOT NULL,
                    qualified_name TEXT,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS guard_decisions (
                    decision_id TEXT PRIMARY KEY,
                    module_name TEXT NOT NULL,
                    qualified_name TEXT,
                    action TEXT NOT NULL,
                    requires_human_review INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE VIEW IF NOT EXISTS high_significance_deviations AS
                    SELECT deviation_id, module_name, qualified_name, category,
                           significance_score, created_at
                    FROM guard_deviations
                    WHERE significance_score >= 80.0;
                """
            )
            connection.commit()

    @staticmethod
    def _identity_key(record: CodeIdentity) -> str:
        return "|".join(
            (
                record.distribution_name or "",
                record.distribution_version or "",
                record.module_name,
                record.qualified_name or "",
                record.source_hash or "",
                record.bytecode_hash or "",
            )
        )

    def record_code_identity(self, record: CodeIdentity) -> None:
        payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO code_identities(
                    identity_key, distribution_name, distribution_version,
                    module_name, qualified_name, source_hash, bytecode_hash, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self._identity_key(record),
                    record.distribution_name,
                    record.distribution_version,
                    record.module_name,
                    record.qualified_name,
                    record.source_hash,
                    record.bytecode_hash,
                    payload,
                ),
            )
            connection.commit()

    def append_behavior_event(self, record: BehaviorEvent) -> None:
        payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO behavior_events(
                    event_id, occurred_at, event_kind, operation, target_id, call_id,
                    module_name, qualified_name, resource_kind, resource_value,
                    outcome, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(record.event_id),
                    record.occurred_at.isoformat(),
                    record.event_kind.name,
                    record.operation,
                    record.target_id,
                    str(record.call_id) if record.call_id else None,
                    record.code_identity.module_name,
                    record.code_identity.qualified_name,
                    record.resource.kind if record.resource else None,
                    record.resource.value if record.resource else None,
                    record.outcome.name,
                    payload,
                ),
            )
            connection.commit()

    def record_behavior_window(self, record: BehaviorWindow) -> None:
        payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO behavior_windows(
                    window_id, started_at, completed_at, module_name,
                    qualified_name, event_count, call_count, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(record.window_id),
                    record.started_at.isoformat(),
                    record.completed_at.isoformat(),
                    record.subject.module_name,
                    record.subject.qualified_name,
                    record.event_count,
                    record.call_count,
                    payload,
                ),
            )
            connection.commit()

    def record_inspection(self, record: RuntimeInspection) -> None:
        payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        significant = sum(item.significant for item in record.differences_from_load)
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO runtime_inspections(
                    inspection_id, occurred_at, inspection_kind, module_name,
                    qualified_name, source_fingerprint, runtime_fingerprint,
                    significant_change_count, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(record.inspection_id),
                    record.occurred_at.isoformat(),
                    record.inspection_kind.name,
                    record.subject.module_name,
                    record.subject.qualified_name,
                    record.source_fingerprint,
                    record.runtime_fingerprint,
                    significant,
                    payload,
                ),
            )
            connection.commit()

    def record_guard_baseline(self, record: object) -> None:
        subject = getattr(record, "subject")
        payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO guard_baselines("
                "baseline_id, module_name, qualified_name, state, created_at, accepted_at, payload"
                ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(getattr(record, "baseline_id")), subject.module_name, subject.qualified_name,
                    getattr(record, "state").name, getattr(record, "created_at").isoformat(),
                    getattr(record, "accepted_at").isoformat() if getattr(record, "accepted_at") else None,
                    payload,
                ),
            )
            connection.commit()

    def record_guard_deviation(self, record: object) -> None:
        subject = getattr(record, "subject")
        payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO guard_deviations("
                "deviation_id, baseline_id, observation_window_id, module_name, qualified_name, "
                "category, significance_score, created_at, payload"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(getattr(record, "deviation_id")), str(getattr(record, "baseline_id")),
                    str(getattr(record, "observation_window_id")), subject.module_name,
                    subject.qualified_name, getattr(record, "category").name,
                    float(getattr(record, "significance_score")), getattr(record, "created_at").isoformat(),
                    payload,
                ),
            )
            connection.commit()

    def record_guard_assessment(self, record: object) -> None:
        subject = getattr(record, "subject")
        payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO guard_assessments("
                "assessment_id, module_name, qualified_name, severity, confidence, created_at, payload"
                ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(getattr(record, "assessment_id")), subject.module_name, subject.qualified_name,
                    getattr(record, "severity").name, float(getattr(record, "confidence")),
                    getattr(record, "created_at").isoformat(), payload,
                ),
            )
            connection.commit()

    def record_guard_decision(self, record: object) -> None:
        subject = getattr(record, "subject")
        payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO guard_decisions("
                "decision_id, module_name, qualified_name, action, requires_human_review, created_at, payload"
                ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(getattr(record, "decision_id")), subject.module_name, subject.qualified_name,
                    getattr(record, "action").name, int(bool(getattr(record, "requires_human_review"))),
                    getattr(record, "created_at").isoformat(), payload,
                ),
            )
            connection.commit()

    def recent_behavior_events(
        self,
        *,
        target_id: str | None = None,
        module_name: str | None = None,
        limit: int = 100,
    ) -> tuple[Mapping[str, Any], ...]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if target_id is not None:
            clauses.append("target_id = ?")
            parameters.append(target_id)
        if module_name is not None:
            clauses.append("module_name = ?")
            parameters.append(module_name)
        sql = "SELECT payload FROM behavior_events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY occurred_at DESC LIMIT ?"
        parameters.append(max(0, limit))
        return self._query_payloads(sql, parameters)

    def recent_inspections(
        self,
        module_name: str,
        *,
        limit: int = 20,
    ) -> tuple[Mapping[str, Any], ...]:
        return self._query_payloads(
            "SELECT payload FROM runtime_inspections WHERE module_name = ? "
            "ORDER BY occurred_at DESC LIMIT ?",
            [module_name, max(0, limit)],
        )

    def query(self, sql: str, parameters: tuple[Any, ...] = ()) -> tuple[Mapping[str, Any], ...]:
        lowered = sql.lstrip().lower()
        if not lowered.startswith("select") and not lowered.startswith("with"):
            raise ValueError("EvidenceStore.query accepts read-only SELECT/CTE statements")
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(sql, parameters).fetchall()
            return tuple(dict(row) for row in rows)

    def _query_payloads(self, sql: str, parameters: list[Any]) -> tuple[Mapping[str, Any], ...]:
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(sql, parameters).fetchall()
            return tuple(json.loads(row["payload"]) for row in rows)


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
    return repr(value)
