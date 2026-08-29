"""Policy-gated contract for isolated execution of historical fixtures.

Persistent regression fixtures contain JSON evidence, not executable values.  A
deployment must provide an explicitly configured isolated backend that owns any
rehydration and execution.  This module performs the authority and integrity
checks before dispatch; it does not provide a host-process fallback.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from .domain import ValidationIsolationLevel
from .regression import (
    DATA_ONLY_NOT_EXECUTABLE,
    JSON_EXACT_REHYDRATION,
    RegressionFixtureStore,
)
from .validation import (
    RootlessPodmanValidationBackend,
    ValidationBackendCapabilities,
    _run_worker_command,
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
        if fixture.get("rehydration_status") != JSON_EXACT_REHYDRATION:
            raise ReplayExecutionError(
                "fixture values are bounded evidence but not exactly JSON-rehydratable"
            )
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


class RootlessPodmanReplayBackend(RootlessPodmanValidationBackend):
    """Execute exact-JSON historical fixtures in a rootless Podman container."""

    def __init__(self, image: str, *, operation_timeout_seconds: float = 60.0, **kwargs: Any) -> None:
        super().__init__(image, **kwargs)
        if operation_timeout_seconds <= 0:
            raise ValueError("operation_timeout_seconds must be > 0")
        self.operation_timeout_seconds = float(operation_timeout_seconds)

    def capabilities(self) -> ValidationBackendCapabilities:
        base = super().capabilities()
        details = dict(base.details or {})
        details.update({
            "replay_worker": "caretaker.replay_worker",
            "fixture_inputs": "exact-json-only",
        })
        return ValidationBackendCapabilities(
            name="podman-rootless-replay",
            isolation_level=base.isolation_level,
            separate_kernel=base.separate_kernel,
            rootless=base.rootless,
            network_control=base.network_control,
            resource_control=base.resource_control,
            ephemeral_workspace=base.ephemeral_workspace,
            details=details,
        )

    def _build_replay_command(self, host_workdir: Path) -> list[str]:
        source_root = Path(__file__).resolve().parents[1]
        command = [
            self.podman_executable,
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            f"--pids-limit={self.pids_limit}",
            f"--memory={self.memory}",
            f"--cpus={self.cpus:g}",
            "--userns=keep-id",
            f"--tmpfs=/tmp:rw,nosuid,nodev,noexec,size={self.tmpfs_size}",
            "--mount",
            f"type=bind,src={host_workdir},dst=/work,rw=true",
            "--mount",
            f"type=bind,src={source_root},dst=/opt/caretaker-src,ro=true",
            "--workdir=/work",
            "--env",
            "PYTHONPATH=/opt/caretaker-src",
            "--env",
            "PYTHONIOENCODING=utf-8",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            self.image,
            "python",
            "-m",
            "caretaker.replay_worker",
            "/work/request.json",
            "/work/result.json",
        ]
        return command

    def execute(self, request: ReplayExecutionRequest) -> ReplayExecutionResult:
        fixture = request.fixture
        args = fixture.get("args")
        kwargs = fixture.get("kwargs")
        expected = fixture.get("expected")
        if not isinstance(args, list) or not isinstance(kwargs, dict):
            raise ReplayExecutionError("replay fixture does not contain exact JSON call values")
        payload = {
            "fixture_id": request.fixture_id,
            "target_id": request.target_id,
            "source": request.source,
            "entrypoint": request.entrypoint,
            "args": args,
            "kwargs": kwargs,
            "expected": expected,
        }
        with tempfile.TemporaryDirectory(prefix="caretaker-podman-replay-") as temporary:
            temp = Path(temporary)
            request_path = temp / "request.json"
            output_path = temp / "result.json"
            descriptor = os.open(request_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                stream.flush()
                os.fsync(stream.fileno())
            host_environment = {
                key: os.environ[key]
                for key in ("PATH", "HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")
                if key in os.environ
            }
            raw = _run_worker_command(
                self._build_replay_command(temp),
                output_path=output_path,
                timeout_seconds=self.operation_timeout_seconds,
                cwd=temporary,
                env=host_environment,
            )
        outcome = str(raw.get("outcome") or "ERROR")
        if outcome not in {"PASSED", "FAILED", "ERROR"}:
            outcome = "ERROR"
        return ReplayExecutionResult(
            fixture_id=request.fixture_id,
            target_id=request.target_id,
            outcome=outcome,
            backend_name=self.capabilities().name,
            isolation_level=self.capabilities().isolation_level,
            output=raw.get("output"),
            error=str(raw.get("error")) if raw.get("error") else None,
        )
