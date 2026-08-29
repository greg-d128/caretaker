"""Policy-gated contract for isolated execution of historical fixtures.

Persistent regression fixtures contain JSON evidence, not executable values.  A
deployment must provide an explicitly configured isolated backend that owns any
rehydration and execution.  This module performs the authority and integrity
checks before dispatch; it does not provide a host-process fallback.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .domain import ValidationIsolationLevel
from .regression import (
    DATA_ONLY_NOT_EXECUTABLE,
    RegressionFixtureStore,
)


class ReplayExecutionError(ValueError):
    """Raised when a historical replay cannot be authorized or dispatched."""


@dataclass(frozen=True, slots=True)
class ReplayExecutionRequest:
    """JSON-only request passed to an explicitly isolated replay backend."""

    fixture_id: str
    target_id: str
    entrypoint: str
    source: str
    historical_source_hash: str
    subject_source_hash: str
    replay_safety: str
    fixture: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ReplayExecutionResult:
    fixture_id: str
    target_id: str
    outcome: str
    backend_name: str
    isolation_level: ValidationIsolationLevel
    output: Any = None
    error: str | None = None


class ReplayExecutionBackend(Protocol):
    """Backend that rehydrates and executes only inside its declared boundary."""

    def capabilities(self) -> Any: ...
    def available(self) -> tuple[bool, str | None]: ...
    def execute(self, request: ReplayExecutionRequest) -> ReplayExecutionResult: ...


class IsolatedReplayCoordinator:
    """Authorize and dispatch one historical fixture to an isolated backend."""

    def __init__(self, store: RegressionFixtureStore, *, policy: Any) -> None:
        self.store = store
        self.policy = policy

    def prepare(
        self,
        fixture_id: str,
        *,
        entrypoint: str,
        source: str,
    ) -> ReplayExecutionRequest:
        if not bool(getattr(self.policy, "replay_enabled", False)):
            raise ReplayExecutionError("persistent replay is disabled by policy")
        fixture = self.store.load(fixture_id)
        if fixture.get("replay_status") != DATA_ONLY_NOT_EXECUTABLE:
            raise ReplayExecutionError("fixture is not an inspection-only data envelope")
        replay_safety = str(fixture.get("replay_safety") or "")
        if replay_safety not in {"PURE", "IDEMPOTENT"}:
            raise ReplayExecutionError(
                "historical replay requires PURE or IDEMPOTENT replay safety"
            )
        if not entrypoint or not isinstance(source, str):
            raise ReplayExecutionError("replay requires an entrypoint and source text")
        maximum_source_bytes = int(getattr(self.policy, "maximum_source_bytes", 256 * 1024))
        if len(source.encode("utf-8")) > maximum_source_bytes:
            raise ReplayExecutionError("replay source exceeds the configured bound")
        source_hash = str(fixture.get("source_function_hash") or "")
        if not source_hash:
            raise ReplayExecutionError("fixture has no source function hash")
        actual_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
        if bool(getattr(self.policy, "replay_require_source_match", True)) and actual_hash != source_hash:
            raise ReplayExecutionError(
                "replay source hash does not match the historical fixture source hash"
            )
        target_id = str(fixture.get("target_id") or "")
        if not target_id:
            raise ReplayExecutionError("fixture has no target identity")
        return ReplayExecutionRequest(
            fixture_id=str(fixture["fixture_id"]),
            target_id=target_id,
            entrypoint=entrypoint,
            source=source,
            historical_source_hash=source_hash,
            subject_source_hash=actual_hash,
            replay_safety=replay_safety,
            fixture=fixture,
        )

    def execute(
        self,
        fixture_id: str,
        *,
        entrypoint: str,
        source: str,
        backend: ReplayExecutionBackend,
    ) -> ReplayExecutionResult:
        request = self.prepare(fixture_id, entrypoint=entrypoint, source=source)
        capabilities = backend.capabilities()
        minimum = ValidationIsolationLevel(
            int(getattr(self.policy, "replay_minimum_isolation", ValidationIsolationLevel.VM))
        )
        actual = ValidationIsolationLevel(int(capabilities.isolation_level))
        if actual < minimum:
            raise ReplayExecutionError(
                f"replay backend provides {actual.name}; policy requires at least {minimum.name}"
            )
        available, reason = backend.available()
        if not available:
            raise ReplayExecutionError(
                f"replay backend {capabilities.name!r} is unavailable"
                + (f": {reason}" if reason else "")
            )
        result = backend.execute(request)
        if not isinstance(result, ReplayExecutionResult):
            raise ReplayExecutionError("replay backend returned an invalid result")
        if result.fixture_id != request.fixture_id or result.target_id != request.target_id:
            raise ReplayExecutionError("replay result identity does not match the request")
        if result.isolation_level < minimum:
            raise ReplayExecutionError("replay result does not prove the required isolation")
        if result.outcome not in {"PASSED", "FAILED", "ERROR"}:
            raise ReplayExecutionError("replay backend returned an invalid outcome")
        return result
