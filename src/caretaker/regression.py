from __future__ import annotations

import copy
import hashlib
import json
import os
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import UUID, uuid4

from .capsule import IncidentCapsulePolicy, bounded_safe_data, canonical_json_bytes
from .domain import RegisteredCase, RegressionCase


REGRESSION_FIXTURE_SCHEMA_VERSION = 1
DATA_ONLY_NOT_EXECUTABLE = "DATA_ONLY_NOT_EXECUTABLE"


class RegressionFixtureIntegrityError(ValueError):
    """Raised when a persisted regression fixture is malformed or tampered with."""


class RegressionFixtureStore:
    """Immutable, bounded, data-only storage for historical regression evidence.

    The store never unpickles or reconstructs application values.  Its JSON records
    are inspection evidence for a future isolated replay system, not executable
    ``RegisteredCase`` values and not an authorization source.
    """

    def __init__(self, directory: str | Path, *, policy: Any | None = None) -> None:
        self.policy = policy
        self.directory = Path(directory).expanduser().resolve() / "regression-fixtures"
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        self._lock = RLock()

    def _safe_policy(self) -> IncidentCapsulePolicy:
        return IncidentCapsulePolicy(
            maximum_capsule_bytes=max(1, int(getattr(self.policy, "maximum_fixture_bytes", 128 * 1024))),
            maximum_artifact_bytes=max(1, int(getattr(self.policy, "maximum_fixture_bytes", 128 * 1024))),
            maximum_artifacts=1,
            maximum_communications=1,
            maximum_depth=max(1, int(getattr(self.policy, "maximum_depth", 6))),
            maximum_collection_items=max(1, int(getattr(self.policy, "maximum_collection_items", 32))),
            maximum_text_characters=max(1, int(getattr(self.policy, "maximum_text_characters", 2048))),
        )

    @staticmethod
    def _target_key(target_id: str) -> str:
        return hashlib.sha256(target_id.encode("utf-8")).hexdigest()

    def _target_directory(self, target_id: str) -> Path:
        return self.directory / self._target_key(target_id)

    def _fixture_paths(self, fixture_id: UUID | None = None) -> list[Path]:
        if fixture_id is not None:
            return [path for path in self.directory.rglob(f"{fixture_id}.json") if path.is_file() and not path.is_symlink()]
        return sorted(
            (path for path in self.directory.rglob("*.json") if path.is_file() and not path.is_symlink()),
            key=lambda path: path.name,
        )

    @staticmethod
    def _payload_hash(payload: dict[str, Any]) -> str:
        return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()

    @classmethod
    def _verify_envelope(cls, envelope: Any) -> dict[str, Any]:
        if not isinstance(envelope, dict):
            raise RegressionFixtureIntegrityError("fixture envelope must be an object")
        expected = envelope.get("content_sha256")
        if not isinstance(expected, str):
            raise RegressionFixtureIntegrityError("fixture content hash is missing")
        payload = dict(envelope)
        payload.pop("content_sha256", None)
        actual = cls._payload_hash(payload)
        if actual != expected:
            raise RegressionFixtureIntegrityError("fixture content hash does not match")
        if payload.get("schema_version") != REGRESSION_FIXTURE_SCHEMA_VERSION:
            raise RegressionFixtureIntegrityError("unsupported regression fixture schema version")
        if payload.get("replay_status") != DATA_ONLY_NOT_EXECUTABLE:
            raise RegressionFixtureIntegrityError("fixture replay status is not data-only")
        return envelope

    def record(
        self,
        *,
        target_id: str,
        name: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        expected: Any,
        incident_id: UUID | None,
        candidate_id: UUID | None,
        source_function_version: int | None,
        source_function_hash: str | None,
        replay_safety: str,
    ) -> dict[str, Any] | None:
        """Persist a bounded JSON evidence record, returning ``None`` on refusal."""

        if not target_id:
            return None
        fixture_id = uuid4()
        created_at = datetime.now(timezone.utc).isoformat()
        safe_policy = self._safe_policy()
        try:
            payload: dict[str, Any] = {
                "schema_version": REGRESSION_FIXTURE_SCHEMA_VERSION,
                "fixture_id": str(fixture_id),
                "target_id": target_id,
                "name": str(name),
                "created_at": created_at,
                "source_incident_id": str(incident_id) if incident_id else None,
                "source_candidate_id": str(candidate_id) if candidate_id else None,
                "source_function_version": source_function_version,
                "source_function_hash": source_function_hash,
                "replay_safety": replay_safety,
                "replay_status": DATA_ONLY_NOT_EXECUTABLE,
                "args": bounded_safe_data(list(args), policy=safe_policy, name="args"),
                "kwargs": bounded_safe_data(kwargs, policy=safe_policy, name="kwargs"),
                "expected": bounded_safe_data(expected, policy=safe_policy, name="expected"),
            }
            envelope = dict(payload)
            envelope["content_sha256"] = self._payload_hash(payload)
            encoded = canonical_json_bytes(envelope)
            maximum_bytes = int(getattr(self.policy, "maximum_fixture_bytes", 128 * 1024))
            if len(encoded) > maximum_bytes:
                return None
        except Exception:
            return None

        target_directory = self._target_directory(target_id)
        path = target_directory / f"{fixture_id}.json"
        with self._lock:
            target_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            target_directory.chmod(0o700)
            maximum_cases = int(getattr(self.policy, "maximum_cases_per_target", 100))
            existing = [item for item in target_directory.glob("*.json") if item.is_file() and not item.is_symlink()]
            if len(existing) >= maximum_cases:
                return None
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
            except (FileExistsError, OSError):
                return None
        return envelope

    def list_summaries(self, *, target_id: str | None = None, limit: int = 100) -> tuple[dict[str, Any], ...]:
        paths = self._fixture_paths()
        if target_id is not None:
            paths = [path for path in paths if path.parent.name == self._target_key(target_id)]
        summaries: list[dict[str, Any]] = []
        for path in paths[: max(1, min(int(limit), 500))]:
            try:
                envelope = self._read(path)
                summaries.append({
                    "fixture_id": envelope.get("fixture_id"),
                    "target_id": envelope.get("target_id"),
                    "name": envelope.get("name"),
                    "created_at": envelope.get("created_at"),
                    "source_incident_id": envelope.get("source_incident_id"),
                    "source_function_version": envelope.get("source_function_version"),
                    "replay_safety": envelope.get("replay_safety"),
                    "replay_status": envelope.get("replay_status"),
                    "content_sha256": envelope.get("content_sha256"),
                    "integrity_verified": True,
                })
            except Exception as exc:
                summaries.append({
                    "fixture_id": path.stem,
                    "status": "INVALID",
                    "integrity_verified": False,
                    "error": f"{type(exc).__name__}: {exc}",
                })
        return tuple(summaries)

    def _read(self, path: Path) -> dict[str, Any]:
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RegressionFixtureIntegrityError(f"fixture is not valid JSON: {exc}") from exc
        return self._verify_envelope(envelope)

    def load(self, fixture_id: str | UUID) -> dict[str, Any]:
        try:
            parsed = fixture_id if isinstance(fixture_id, UUID) else UUID(str(fixture_id))
        except ValueError as exc:
            raise KeyError(f"Unknown regression fixture {fixture_id}") from exc
        paths = self._fixture_paths(parsed)
        if not paths:
            raise KeyError(f"Unknown regression fixture {parsed}")
        return self._read(paths[0])


class RegressionCorpus:
    """Bounded runtime corpus of previously successful repair examples.

    Live replay values remain in memory. An optional persistent store receives only
    bounded JSON evidence and never feeds values back into this executable corpus.
    """

    def __init__(self, maximum_cases_per_target: int = 100, *, fixture_store: RegressionFixtureStore | None = None) -> None:
        self.maximum_cases_per_target = maximum_cases_per_target
        self.fixture_store = fixture_store
        self.last_persistent_fixture_id: str | None = None
        self._cases: dict[str, deque[RegressionCase]] = defaultdict(
            lambda: deque(maxlen=maximum_cases_per_target)
        )
        self._lock = RLock()

    def add_successful_replay(
        self,
        *,
        target_id: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        expected: Any,
        incident_id: UUID | None,
        candidate_id: UUID | None,
        name: str | None = None,
        source_function_version: int | None = None,
        source_function_hash: str | None = None,
        replay_safety: str = "UNKNOWN",
    ) -> RegressionCase | None:
        try:
            case = RegressionCase(
                case_id=uuid4(),
                target_id=target_id,
                name=name or f"repaired-incident-{str(incident_id)[:8] if incident_id else 'unknown'}",
                args=copy.deepcopy(args),
                kwargs=copy.deepcopy(kwargs),
                expected=copy.deepcopy(expected),
                source_incident_id=incident_id,
                source_candidate_id=candidate_id,
            )
        except Exception:
            return None
        with self._lock:
            self._cases[target_id].append(case)
            self.last_persistent_fixture_id = None
            if self.fixture_store is not None:
                persisted = self.fixture_store.record(
                    target_id=target_id,
                    name=case.name,
                    args=case.args,
                    kwargs=dict(case.kwargs),
                    expected=case.expected,
                    incident_id=incident_id,
                    candidate_id=candidate_id,
                    source_function_version=source_function_version,
                    source_function_hash=source_function_hash,
                    replay_safety=replay_safety,
                )
                if persisted is not None:
                    self.last_persistent_fixture_id = str(persisted["fixture_id"])
        return case

    def cases_for_target(self, target_id: str) -> tuple[RegressionCase, ...]:
        with self._lock:
            return tuple(self._cases.get(target_id, ()))

    def registered_cases_for_target(self, target_id: str) -> tuple[RegisteredCase, ...]:
        return tuple(
            RegisteredCase(
                name=f"regression:{case.name}",
                args=case.args,
                kwargs=case.kwargs,
                expected=case.expected,
            )
            for case in self.cases_for_target(target_id)
        )
