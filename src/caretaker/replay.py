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
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol
from uuid import UUID

from .capsule import IncidentCapsulePolicy, bounded_safe_data, canonical_json_bytes, content_hash
from .domain import ValidationIsolationLevel
from .regression import (
    DATA_ONLY_NOT_EXECUTABLE,
    JSON_EXACT_REHYDRATION,
    RegressionFixtureStore,
)
from .validation import (
    RootlessPodmanValidationBackend,
    ValidationBackendCapabilities,
    _structured_bind_mount,
    _run_worker_command,
)
from .rooted_io import RootedFilesystem


class ReplayExecutionError(ValueError):
    """Raised when a historical replay cannot be authorized or dispatched."""


REPLAY_RESULT_SCHEMA_VERSION = 1
MAX_REPLAY_RESULT_BYTES = 512 * 1024
_REPLAY_RESULT_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _strict_json_loads(value: str) -> Any:
    return json.loads(
        value,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON constant {token} is not permitted")
        ),
    )


class ReplayResultStore:
    """Persist bounded replay responses as separate, content-addressed evidence."""

    def __init__(
        self,
        directory: str | Path,
        *,
        maximum_bytes: int = MAX_REPLAY_RESULT_BYTES,
        create_directory: bool = True,
    ) -> None:
        if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int) or maximum_bytes <= 0:
            raise ValueError("maximum_bytes must be a positive integer")
        self.maximum_bytes = maximum_bytes
        self.directory = Path(directory).expanduser().resolve() / "replay-results"
        if create_directory:
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.directory.chmod(0o700)
        self._rooted = (
            RootedFilesystem(self.directory)
            if self.directory.exists()
            else None
        )

    def _payload(self, result: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(result, Mapping):
            raise ReplayExecutionError("replay result must be a mapping")
        policy = IncidentCapsulePolicy(
            maximum_capsule_bytes=self.maximum_bytes,
            maximum_artifact_bytes=self.maximum_bytes,
            maximum_artifacts=1,
            maximum_communications=1,
            maximum_depth=8,
            maximum_collection_items=128,
            maximum_text_characters=16_384,
        )
        payload = {
            "schema_version": REPLAY_RESULT_SCHEMA_VERSION,
            "result": bounded_safe_data(
                dict(result), policy=policy, name="replay_result"
            ),
        }
        if len(canonical_json_bytes(payload)) > self.maximum_bytes:
            raise ReplayExecutionError(
                f"replay result exceeds {self.maximum_bytes} bytes"
            )
        return payload

    def record(self, result: Mapping[str, Any]) -> dict[str, Any]:
        """Write one replay response and return its immutable storage summary."""
        payload = self._payload(result)
        digest = content_hash(payload)
        path = self.directory / f"{digest}.json"
        envelope = {
            **payload,
            "content_sha256": digest,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        encoded = canonical_json_bytes(envelope)
        if self._rooted is None:
            raise ReplayExecutionError("replay result directory does not exist")
        try:
            stream = self._rooted.open_exclusive(path)
        except FileExistsError:
            loaded = self.load(digest)
            return {
                "content_sha256": digest,
                "recorded_at": loaded.get("recorded_at"),
                "path": str(path),
                "duplicate": True,
            }
        try:
            with stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try:
                path.unlink()
            except OSError:
                pass
            raise
        return {
            "content_sha256": digest,
            "recorded_at": envelope["recorded_at"],
            "path": str(path),
            "duplicate": False,
        }

    def load(self, digest: str) -> dict[str, Any]:
        """Load and verify one content-addressed replay response."""
        if not isinstance(digest, str) or _REPLAY_RESULT_DIGEST.fullmatch(digest) is None:
            raise ReplayExecutionError("replay result content hash is invalid")
        path = self.directory / f"{digest}.json"
        if self._rooted is None:
            raise ReplayExecutionError("replay result directory does not exist")
        try:
            envelope = _strict_json_loads(
                self._rooted.read_bytes(path, maximum_bytes=self.maximum_bytes).decode("utf-8")
            )
        except Exception as exc:
            raise ReplayExecutionError("replay result is not valid JSON") from exc
        if not isinstance(envelope, Mapping):
            raise ReplayExecutionError("replay result envelope must be an object")
        if set(envelope) != {"schema_version", "result", "content_sha256", "recorded_at"}:
            raise ReplayExecutionError("replay result envelope fields are invalid")
        payload = {
            "schema_version": envelope.get("schema_version"),
            "result": envelope.get("result"),
        }
        if payload["schema_version"] != REPLAY_RESULT_SCHEMA_VERSION:
            raise ReplayExecutionError("unsupported replay result schema version")
        if str(envelope.get("content_sha256") or "") != digest:
            raise ReplayExecutionError("replay result filename does not match its hash")
        if content_hash(payload) != digest:
            raise ReplayExecutionError("replay result content hash does not match")
        if not isinstance(envelope.get("result"), Mapping):
            raise ReplayExecutionError("replay result payload must be an object")
        result = envelope["result"]
        results = result.get("results")
        if results is not None:
            if not isinstance(results, list):
                raise ReplayExecutionError("replay result entries are invalid")
            for item in results:
                if not isinstance(item, Mapping) or not isinstance(item.get("fixture_id"), str):
                    raise ReplayExecutionError("replay result entry fixture identity is invalid")
                if item.get("capsule_id") is not None:
                    try:
                        UUID(str(item["capsule_id"]))
                    except (ValueError, TypeError) as exc:
                        raise ReplayExecutionError("replay result capsule identity is invalid") from exc
                if item.get("source_incident_id") and item.get("incident_id") and str(item["source_incident_id"]) != str(item["incident_id"]):
                    raise ReplayExecutionError("replay result incident provenance is inconsistent")
        if not isinstance(envelope.get("recorded_at"), str) or not envelope["recorded_at"].strip():
            raise ReplayExecutionError("replay result recorded_at is missing")
        return dict(envelope)

    def list_summaries(self, *, limit: int = 100) -> tuple[dict[str, Any], ...]:
        """Return bounded metadata without returning full replay output."""
        summaries: list[dict[str, Any]] = []
        for path in sorted(self.directory.glob("*.json"))[: max(1, min(int(limit), 500))]:
            digest = path.stem
            try:
                envelope = self.load(digest)
                result = envelope.get("result")
                results = result.get("results") if isinstance(result, Mapping) else None
                summaries.append({
                    "content_sha256": digest,
                    "recorded_at": envelope.get("recorded_at"),
                    "fixture_count": result.get("fixture_count") if isinstance(result, Mapping) else None,
                    "completed_count": result.get("completed_count") if isinstance(result, Mapping) else None,
                    "result_count": len(results) if isinstance(results, list) else None,
                    "integrity_verified": True,
                })
            except Exception as exc:
                summaries.append({
                    "content_sha256": digest,
                    "integrity_verified": False,
                    "error": f"{type(exc).__name__}: {exc}",
                })
        return tuple(summaries)


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


def execute_capsule_replay(
    coordinator: "IsolatedReplayCoordinator",
    capsule_store: Any,
    *,
    capsule_id: str,
    fixture_id: str,
    entrypoint: str,
    source: str,
) -> dict[str, Any]:
    """Execute a fixture only when it is owned by the selected capsule's incident.

    Capsule loading verifies the immutable revision chain before this function
    dispatches anything.  Replay results are returned as a separate response;
    this function never writes a capsule revision, artifact, or repair state.
    """

    envelope = capsule_store.load(capsule_id)
    capsule = envelope.get("capsule")
    if not isinstance(capsule, Mapping):
        raise ReplayExecutionError("selected Incident Capsule has no valid capsule payload")
    incident_id = str(capsule.get("incident_id") or "")
    if not incident_id:
        raise ReplayExecutionError("selected Incident Capsule has no incident identity")

    fixture = coordinator.store.load(fixture_id)
    fixture_incident_id = str(fixture.get("source_incident_id") or "")
    if not fixture_incident_id:
        raise ReplayExecutionError(
            "historical fixture is not linked to an incident and cannot be replayed from a capsule"
        )
    if fixture_incident_id != incident_id:
        raise ReplayExecutionError(
            "historical fixture is not owned by the selected Incident Capsule incident"
        )

    result = coordinator.execute(
        fixture_id,
        entrypoint=entrypoint,
        source=source,
    )
    integrity = envelope.get("integrity")
    integrity = integrity if isinstance(integrity, Mapping) else {}
    return {
        "capsule_id": str(capsule.get("capsule_id") or capsule_id),
        "incident_id": incident_id,
        "capsule_revision": int(capsule.get("revision") or 0),
        "capsule_content_sha256": integrity.get("content_sha256"),
        "fixture_id": result.fixture_id,
        "target_id": result.target_id,
        "outcome": result.outcome,
        "backend_name": result.backend_name,
        "isolation_level": result.isolation_level.name,
        "output": result.output,
        "error": result.error,
        "capsule_modified": False,
        "integrity_verified": True,
        "replay_status": "ISOLATED_RESULT_NOT_CAPSULE_DATA",
    }


def execute_historical_capsule_replays(
    coordinator: "IsolatedReplayCoordinator",
    capsule_store: Any,
    fixture_summaries: Iterable[Mapping[str, Any]],
    *,
    entrypoint: str,
    source: str,
    limit: int = 50,
    cancel_check: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Replay bounded incident-linked fixtures independently.

    This is the non-interactive Explorer path. Each fixture gets its own
    capsule binding and isolated backend invocation. Invalid, missing, or
    failed entries are returned as per-fixture evidence instead of preventing
    other historical incidents from being examined.
    """
    bounded_limit = max(1, min(int(limit), 200))
    results: list[dict[str, Any]] = []
    for summary in list(fixture_summaries)[:bounded_limit]:
        if cancel_check is not None:
            cancel_check()
        fixture_id = str(summary.get("fixture_id") or "")
        base: dict[str, Any] = {
            "fixture_id": fixture_id,
            "target_id": summary.get("target_id"),
            "source_incident_id": summary.get("source_incident_id"),
            "capsule_modified": False,
        }
        if not bool(summary.get("integrity_verified")):
            results.append({
                **base,
                "status": "SKIPPED_INVALID_FIXTURE",
                "error": summary.get("error") or "fixture integrity is not verified",
                "replay_status": "NOT_DISPATCHED",
            })
            continue
        incident_id = str(summary.get("source_incident_id") or "").strip()
        if not incident_id:
            results.append({
                **base,
                "status": "SKIPPED_UNLINKED_FIXTURE",
                "error": "historical fixture has no source incident",
                "replay_status": "NOT_DISPATCHED",
            })
            continue
        try:
            capsule = capsule_store.latest_for_incident(UUID(incident_id))
            if capsule is None:
                results.append({
                    **base,
                    "status": "SKIPPED_NO_CAPSULE",
                    "error": "no verified Incident Capsule was found for the fixture incident",
                    "replay_status": "NOT_DISPATCHED",
                })
                continue
            capsule_payload = capsule.get("capsule") if isinstance(capsule, Mapping) else None
            capsule_id = str(capsule_payload.get("capsule_id") or "") if isinstance(capsule_payload, Mapping) else ""
            if not capsule_id:
                raise ReplayExecutionError("incident capsule has no capsule identity")
            replay = execute_capsule_replay(
                coordinator,
                capsule_store,
                capsule_id=capsule_id,
                fixture_id=fixture_id,
                entrypoint=entrypoint,
                source=source,
            )
            results.append({**base, **replay, "status": "COMPLETED"})
        except Exception as exc:
            results.append({
                **base,
                "status": "FAILED",
                "error": f"{type(exc).__name__}: {exc}",
                "advisory_only": True,
                "replay_status": "NOT_DISPATCHED_OR_FAILED",
            })
    return {
        "entrypoint": entrypoint,
        "fixture_count": len(results),
        "completed_count": sum(item.get("status") == "COMPLETED" for item in results),
        "dispatched_count": sum(
            item.get("status") == "COMPLETED" and item.get("replay_status") == "ISOLATED_RESULT_NOT_CAPSULE_DATA"
            for item in results
        ),
        "results": results,
        "capsule_modified": False,
        "replay_scope": "historical-incident-linked",
    }


class ReplayExecutionBackend(Protocol):
    """Backend that rehydrates and executes only inside its declared boundary."""

    def capabilities(self) -> Any: ...
    def available(self) -> tuple[bool, str | None]: ...
    def execute(self, request: ReplayExecutionRequest) -> ReplayExecutionResult: ...


class ReplayExecutionBackendRegistry:
    """Select the lowest available replay backend allowed by policy."""

    def __init__(self, backends: tuple[ReplayExecutionBackend, ...] = ()) -> None:
        self.backends = tuple(backends)

    def select(self, minimum: ValidationIsolationLevel) -> ReplayExecutionBackend:
        if not self.backends:
            raise ReplayExecutionError("no replay execution backend is configured")
        ordered = sorted(
            self.backends,
            key=lambda item: int(item.capabilities().isolation_level),
        )
        sufficient = [
            item for item in ordered
            if item.capabilities().isolation_level >= minimum
        ]
        for item in sufficient:
            available, _reason = item.available()
            if available:
                return item
        if sufficient:
            return sufficient[0]
        return ordered[-1]


class IsolatedReplayCoordinator:
    """Authorize and dispatch one historical fixture to an isolated backend."""

    def __init__(
        self,
        store: RegressionFixtureStore,
        *,
        policy: Any,
        backend: ReplayExecutionBackend | None = None,
        backends: tuple[ReplayExecutionBackend, ...] | None = None,
    ) -> None:
        if backend is not None and backends is not None:
            raise ValueError("specify backend or backends, not both")
        self.store = store
        self.policy = policy
        configured = backends if backends is not None else (
            (backend,) if backend is not None else ()
        )
        self.backend_registry = ReplayExecutionBackendRegistry(tuple(configured))

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
        backend: ReplayExecutionBackend | None = None,
    ) -> ReplayExecutionResult:
        request = self.prepare(fixture_id, entrypoint=entrypoint, source=source)
        minimum = ValidationIsolationLevel(
            int(getattr(self.policy, "replay_minimum_isolation", ValidationIsolationLevel.VM))
        )
        backend = backend if backend is not None else self.backend_registry.select(minimum)
        capabilities = backend.capabilities()
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
        details.pop("workspace", None)
        details.update({
            "replay_worker": "caretaker.replay_worker",
            "fixture_inputs": "exact-json-only",
            "application_workspace_mount": "none",
            "caretaker_code_source": "installed-image-wheel",
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
        command = [
            self.podman_executable,
            f"--cgroup-manager={self.cgroup_manager}",
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
            _structured_bind_mount(host_workdir, "/work", read_only=False),
            "--workdir=/work",
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
