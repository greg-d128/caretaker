"""Durable, idempotent acceptance progress for authorized workers."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


WORKER_ACCEPTANCE_SCHEMA_VERSION = 1


class WorkerAcceptanceStoreError(ValueError):
    """Raised when durable worker acceptance state is malformed or unavailable."""


def _content_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _context_key(
    *,
    target_id: str,
    generation_id: str,
    code_hash: str,
    policy_fingerprint: str,
) -> tuple[str, str, str, str]:
    values = (str(target_id), str(generation_id), str(code_hash), str(policy_fingerprint))
    if any(not value for value in values):
        raise WorkerAcceptanceStoreError("worker acceptance context fields cannot be empty")
    return values


def _progress_payload(
    *,
    target_id: str,
    generation_id: str,
    code_hash: str,
    policy_fingerprint: str,
    successful_executions: int,
    failed_executions: int,
    observation_count: int,
    last_observed_at: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": WORKER_ACCEPTANCE_SCHEMA_VERSION,
        "target_id": target_id,
        "generation_id": generation_id,
        "code_hash": code_hash,
        "policy_fingerprint": policy_fingerprint,
        "successful_executions": successful_executions,
        "failed_executions": failed_executions,
        "observation_count": observation_count,
        "last_observed_at": last_observed_at,
    }


class WorkerAcceptanceStore:
    """SQLite-backed acceptance ledger safe for concurrent application workers."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()
        with sqlite3.connect(self.path, timeout=30) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS worker_acceptance_progress (
                    target_id TEXT NOT NULL,
                    generation_id TEXT NOT NULL,
                    code_hash TEXT NOT NULL,
                    policy_fingerprint TEXT NOT NULL,
                    successful_executions INTEGER NOT NULL,
                    failed_executions INTEGER NOT NULL,
                    observation_count INTEGER NOT NULL,
                    last_observed_at TEXT,
                    content_sha256 TEXT NOT NULL,
                    PRIMARY KEY (target_id, generation_id, code_hash, policy_fingerprint)
                );
                CREATE TABLE IF NOT EXISTS worker_acceptance_observations (
                    target_id TEXT NOT NULL,
                    generation_id TEXT NOT NULL,
                    code_hash TEXT NOT NULL,
                    policy_fingerprint TEXT NOT NULL,
                    observation_id TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    observed_at TEXT NOT NULL,
                    PRIMARY KEY (
                        target_id, generation_id, code_hash, policy_fingerprint,
                        observation_id
                    )
                );
                """
            )
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _validate_counter(value: int, *, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise WorkerAcceptanceStoreError(f"{name} must be a non-negative integer")
        return value

    @staticmethod
    def _row_payload(row: sqlite3.Row | tuple[Any, ...]) -> dict[str, Any]:
        (
            target_id,
            generation_id,
            code_hash,
            policy_fingerprint,
            successful,
            failed,
            observations,
            last_observed_at,
            content_sha256,
        ) = row
        payload = _progress_payload(
            target_id=str(target_id),
            generation_id=str(generation_id),
            code_hash=str(code_hash),
            policy_fingerprint=str(policy_fingerprint),
            successful_executions=WorkerAcceptanceStore._validate_counter(
                int(successful), name="successful_executions"
            ),
            failed_executions=WorkerAcceptanceStore._validate_counter(
                int(failed), name="failed_executions"
            ),
            observation_count=WorkerAcceptanceStore._validate_counter(
                int(observations), name="observation_count"
            ),
            last_observed_at=(str(last_observed_at) if last_observed_at is not None else None),
        )
        expected = _content_hash(payload)
        if str(content_sha256) != expected:
            raise WorkerAcceptanceStoreError("worker acceptance checkpoint hash is invalid")
        return {**payload, "content_sha256": expected}

    def _read_progress(
        self,
        connection: sqlite3.Connection,
        context: tuple[str, str, str, str],
    ) -> dict[str, Any] | None:
        row = connection.execute(
            """
            SELECT target_id, generation_id, code_hash, policy_fingerprint,
                   successful_executions, failed_executions, observation_count,
                   last_observed_at, content_sha256
            FROM worker_acceptance_progress
            WHERE target_id = ? AND generation_id = ? AND code_hash = ?
              AND policy_fingerprint = ?
            """,
            context,
        ).fetchone()
        return self._row_payload(row) if row is not None else None

    def load(
        self,
        *,
        target_id: str,
        generation_id: str,
        code_hash: str,
        policy_fingerprint: str,
    ) -> dict[str, Any]:
        """Load matching progress, returning a zero checkpoint when absent."""
        context = _context_key(
            target_id=target_id,
            generation_id=generation_id,
            code_hash=code_hash,
            policy_fingerprint=policy_fingerprint,
        )
        with self._lock, sqlite3.connect(self.path, timeout=30) as connection:
            progress = self._read_progress(connection, context)
        if progress is not None:
            return progress
        payload = _progress_payload(
            target_id=context[0],
            generation_id=context[1],
            code_hash=context[2],
            policy_fingerprint=context[3],
            successful_executions=0,
            failed_executions=0,
            observation_count=0,
            last_observed_at=None,
        )
        return {**payload, "content_sha256": _content_hash(payload)}

    def record(
        self,
        *,
        observation_id: str,
        worker_id: str,
        target_id: str,
        generation_id: str,
        code_hash: str,
        policy_fingerprint: str,
        success: bool,
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        """Record one observation exactly once and return resulting progress."""
        if not isinstance(success, bool):
            raise WorkerAcceptanceStoreError("worker acceptance success must be a boolean")
        observation_id = str(observation_id)
        worker_id = str(worker_id)
        if not observation_id or len(observation_id) > 256:
            raise WorkerAcceptanceStoreError("observation_id must be 1..256 characters")
        if not worker_id or len(worker_id) > 256:
            raise WorkerAcceptanceStoreError("worker_id must be 1..256 characters")
        context = _context_key(
            target_id=target_id,
            generation_id=generation_id,
            code_hash=code_hash,
            policy_fingerprint=policy_fingerprint,
        )
        observed_at = str(observed_at or datetime.now(timezone.utc).isoformat())
        with self._lock, sqlite3.connect(self.path, timeout=30) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")
            progress = self._read_progress(connection, context)
            if progress is None:
                payload = _progress_payload(
                    target_id=context[0],
                    generation_id=context[1],
                    code_hash=context[2],
                    policy_fingerprint=context[3],
                    successful_executions=0,
                    failed_executions=0,
                    observation_count=0,
                    last_observed_at=None,
                )
                progress = {**payload, "content_sha256": _content_hash(payload)}
                connection.execute(
                    """
                    INSERT INTO worker_acceptance_progress
                    (target_id, generation_id, code_hash, policy_fingerprint,
                     successful_executions, failed_executions, observation_count,
                     last_observed_at, content_sha256)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (*context, 0, 0, 0, None, progress["content_sha256"]),
                )
            existing_observation = connection.execute(
                """
                SELECT worker_id, success
                FROM worker_acceptance_observations
                WHERE target_id = ? AND generation_id = ? AND code_hash = ?
                  AND policy_fingerprint = ? AND observation_id = ?
                """,
                (*context, observation_id),
            ).fetchone()
            if existing_observation is not None:
                if (
                    str(existing_observation[0]) != worker_id
                    or int(existing_observation[1]) != int(success)
                ):
                    raise WorkerAcceptanceStoreError(
                        "observation_id is already used for different worker evidence"
                    )
                inserted = 0
            else:
                inserted = connection.execute(
                    """
                    INSERT INTO worker_acceptance_observations
                    (target_id, generation_id, code_hash, policy_fingerprint,
                     observation_id, worker_id, success, observed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (*context, observation_id, worker_id, int(success), observed_at),
                ).rowcount
            if inserted:
                successful = int(progress["successful_executions"]) + int(success)
                failed = int(progress["failed_executions"]) + int(not success)
                observations = int(progress["observation_count"]) + 1
                payload = _progress_payload(
                    target_id=context[0],
                    generation_id=context[1],
                    code_hash=context[2],
                    policy_fingerprint=context[3],
                    successful_executions=successful,
                    failed_executions=failed,
                    observation_count=observations,
                    last_observed_at=observed_at,
                )
                digest = _content_hash(payload)
                connection.execute(
                    """
                    UPDATE worker_acceptance_progress
                    SET successful_executions = ?, failed_executions = ?,
                        observation_count = ?, last_observed_at = ?, content_sha256 = ?
                    WHERE target_id = ? AND generation_id = ? AND code_hash = ?
                      AND policy_fingerprint = ?
                    """,
                    (
                        successful,
                        failed,
                        observations,
                        observed_at,
                        digest,
                        *context,
                    ),
                )
                progress = {**payload, "content_sha256": digest}
                duplicate = False
            else:
                duplicate = True
            connection.commit()
        return {**progress, "duplicate": duplicate}


__all__ = [
    "WORKER_ACCEPTANCE_SCHEMA_VERSION",
    "WorkerAcceptanceStore",
    "WorkerAcceptanceStoreError",
]
