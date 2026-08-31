from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import random
import re
import threading
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from uuid import UUID, uuid4

from ..runtime import snapshot_context
from .audit import AuditStreamError, AuditStreamWriter
from .attachments import AttachmentStore
from .buffering import BufferedSegmentSink
from .models import EvidencePriority, LogChannel, LogEnvelope, LoggingCapability
from .policy import (
    ModeLeaseManager,
    OperatorLoggingPolicy,
    load_operator_policy,
    policy_snapshot,
    reconcile_policy,
    runtime_integrity_assurance,
    policy_security_warnings,
    validate_operator_logging_policy,
    OperatorPolicyWatcher,
)
from .segments import SegmentWriter


class LogSink(Protocol):
    def write(self, envelope: LogEnvelope) -> None: ...
    def flush(self) -> None: ...
    def close(self) -> Any: ...


def _safe_task_id() -> str | None:
    try:
        task = asyncio.current_task()
    except RuntimeError:
        return None
    return task.get_name() if task else None


def _redact(value: Any, *, names: tuple[str, ...], replacement: str, key: str | None = None) -> Any:
    if key and key.lower() in names:
        return replacement
    if isinstance(value, Mapping):
        return {str(item_key): _redact(item, names=names, replacement=replacement, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_redact(item, names=names, replacement=replacement) for item in value]
    if isinstance(value, str):
        result = value
        patterns = (
            r"(?i)(password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*([^\s,;]+)",
            r"(?i)bearer\s+[A-Za-z0-9._~+/-]+=*",
        )
        for pattern in patterns:
            result = re.sub(pattern, lambda match: f"{match.group(1)}={replacement}" if match.lastindex and match.lastindex >= 1 and not match.group(0).lower().startswith("bearer") else f"Bearer {replacement}", result)
        return result
    return value


class LoggingRuntime:
    def __init__(
        self,
        policy: OperatorLoggingPolicy,
        *,
        source_path: str | None = None,
        supervised: bool | None = None,
        policy_transform: Callable[[OperatorLoggingPolicy], OperatorLoggingPolicy] | None = None,
        external_signer: Any | None = None,
    ) -> None:
        self._declared_policy = policy
        self._policy_transform = policy_transform
        policy = policy_transform(policy) if policy_transform is not None else policy
        validate_operator_logging_policy(policy)
        self.policy = policy
        self.snapshot = policy_snapshot(policy, source_path=source_path)
        self.leases = ModeLeaseManager(policy, self.snapshot)
        self.effective = self.leases.effective
        self.run_id = uuid4()
        self.process_start_id = uuid4()
        self.audit = AuditStreamWriter(
            policy.audit,
            directory=policy.directory,
            run_id=self.run_id,
            process_start_id=self.process_start_id,
            supervisor_id=os.environ.get("CARETAKER_SUPERVISOR_ID"),
        )
        self.attachments = AttachmentStore(policy.directory, policy.attachments)
        self.writer = SegmentWriter(
            policy,
            run_id=self.run_id,
            process_start_id=self.process_start_id,
            external_signer=external_signer,
            attachment_checkpoint=self._attachment_manifest_checkpoint_hash,
        )
        self.sink = BufferedSegmentSink(self.writer, policy)
        self._sequence = 0
        self._lock = threading.RLock()
        self.supervised = bool(os.environ.get("CARETAKER_SUPERVISED")) if supervised is None else supervised
        self._late_warning_emitted = False
        self._closed = False
        self._policy_watcher = None
        self._emit_policy_state()
        if not self.supervised:
            self._emit_late_start_warning()
        if source_path and policy.reload.enabled:
            self._policy_watcher = OperatorPolicyWatcher(
                source_path, on_policy=self._on_policy_reload, on_error=self._on_policy_reload_error,
                interval_seconds=policy.reload.check_interval_seconds,
            )
            self._policy_watcher.start()

    @classmethod
    def from_policy_file(cls, path: str | Path) -> "LoggingRuntime":
        policy, _snapshot = load_operator_policy(path)
        return cls(policy, source_path=str(path))

    @property
    def active_policy(self) -> OperatorLoggingPolicy:
        return self.effective.effective_policy

    def _apply_effective_runtime_policy(self) -> tuple[str, ...]:
        active = self.active_policy
        warnings_out = list(self.sink.update_policy(active))
        warnings_out.extend(self.audit.update_policy(active.audit))
        self.attachments.update_policy(active.attachments)
        return tuple(warnings_out)

    def _next_sequence(self) -> int:
        with self._lock:
            self._sequence += 1
            return self._sequence

    def _attachment_manifest_checkpoint_hash(self) -> str | None:
        """Close the active attachment segment at an event rotation boundary."""
        if not self.active_policy.signing.sign_attachment_manifests:
            return None
        manifest = self.attachments.close_segment()
        if manifest is None:
            return None
        return hashlib.sha256(json_bytes(manifest)).hexdigest()

    def _emit_policy_state(self) -> None:
        self.audit.emit(
            "AUDIT_STREAM_STARTED",
            actor={"type": "supervisor" if self.supervised else "system"},
            policy={
                "policy_id": str(self.snapshot.snapshot_id),
                "fingerprint": self.snapshot.content_hash,
                "authority_generation": self.effective.generation,
            },
            details={"hash_chain": self.active_policy.audit.hash_chain},
            priority=EvidencePriority.CRITICAL,
        )
        self.event(
            logger_name="caretaker.logging.policy",
            severity=logging.INFO,
            channel=LogChannel.CARETAKER_INTERNAL,
            message="Logging policy loaded",
            fields={
                "policy_hash": self.snapshot.content_hash,
                "requested_modes": [item.name for item in self.effective.requested_modes],
                "effective_modes": [item.name for item in self.effective.effective_modes],
                "overrides": [item.field_path for item in self.effective.overrides],
                "security_warnings": policy_security_warnings(self.snapshot),
                "runtime_integrity_assurance": runtime_integrity_assurance(self.active_policy.signing),
            },
        )

    def _emit_late_start_warning(self) -> None:
        if self._late_warning_emitted:
            return
        self._late_warning_emitted = True
        message = (
            "Caretaker started after application initialization. Import-time activity before "
            "initialization could not be observed. Preferred startup: "
            "python -m caretaker.run <application-module>"
        )
        self.event(
            logger_name="caretaker.bootstrap",
            severity=logging.WARNING,
            channel=LogChannel.CARETAKER_INTERNAL,
            message=message,
            fields={"preferred_startup": "python -m caretaker.run <application-module>"},
        )
        warnings.warn(message, RuntimeWarning, stacklevel=3)

    def event(
        self,
        *,
        logger_name: str,
        severity: int,
        channel: LogChannel,
        message: str | None,
        fields: Mapping[str, Any] | None = None,
        message_template: str | None = None,
        function_version: int | None = None,
        attachment_payload: bytes | None = None,
        attachment_content_type: str = "application/octet-stream",
        attachment_priority: EvidencePriority = EvidencePriority.ORDINARY,
        origin: str = "application",
    ) -> LogEnvelope | None:
        active_policy = self.active_policy
        if self._closed or not active_policy.enabled:
            return None
        sequence = self._next_sequence()
        context = snapshot_context()
        fields = dict(fields or {})
        if active_policy.redaction.enabled:
            fields = _redact(fields, names=active_policy.redaction.secret_field_names, replacement=active_policy.redaction.replacement)
            message = _redact(message, names=active_policy.redaction.secret_field_names, replacement=active_policy.redaction.replacement) if message else None
        record_id = uuid4()
        attachment_ids: tuple[UUID, ...] = ()
        if attachment_payload is not None:
            reference = self.attachments.store(
                event_id=record_id,
                event_sequence=sequence,
                content_type=attachment_content_type,
                payload=attachment_payload,
                priority=attachment_priority,
            )
            attachment_ids = (reference.attachment_id,)
            fields["attachment"] = {
                "attachment_id": str(reference.attachment_id),
                "stored": reference.stored,
                "sampling_decision": reference.sampling_decision.name,
                "content_hash": reference.content_hash,
            }
        envelope = LogEnvelope(
            schema_version=1,
            writer_version="0.6.1",
            record_id=record_id,
            occurred_at=datetime.now(timezone.utc),
            monotonic_ns=time.monotonic_ns(),
            process_start_id=self.process_start_id,
            sequence_number=sequence,
            channel=channel,
            severity=severity,
            logger_name=logger_name,
            message_template=message_template,
            formatted_message=message,
            fields=fields,
            process_id=os.getpid(),
            thread_id=threading.get_ident(),
            task_id=_safe_task_id(),
            run_id=self.run_id,
            call_id=context.get("call_id"),
            target_id=context.get("target_id"),
            function_version=function_version,
            incident_id=context.get("incident_id"),
            guard_deviation_ids=(),
            behavior_event_ids=(),
            attachment_ids=attachment_ids,
            origin=origin,
        )
        self.sink.write(envelope)
        return envelope

    def _on_policy_reload(self, policy: OperatorLoggingPolicy, snapshot) -> None:
        self._declared_policy = policy
        if self._policy_transform is not None:
            policy = self._policy_transform(policy)
            snapshot = policy_snapshot(policy, source_path=snapshot.source_path)
        validate_operator_logging_policy(policy)
        old_snapshot_id = self.snapshot.snapshot_id
        old_hash = self.snapshot.content_hash
        # Record the request under the old effective policy before a new policy
        # can disable logging or protected channels.
        self.event(
            logger_name="caretaker.logging.policy", severity=logging.WARNING,
            channel=LogChannel.CARETAKER_INTERNAL,
            message="Operator logging policy change detected; reconciling atomically",
            fields={"old_policy_hash": old_hash, "new_policy_hash": snapshot.content_hash},
        )
        self.audit.emit(
            "POLICY_PROPOSED",
            actor={"type": "supervisor"},
            policy={
                "prior_policy_id": str(old_snapshot_id),
                "policy_id": str(snapshot.snapshot_id),
                "prior_fingerprint": old_hash,
                "fingerprint": snapshot.content_hash,
            },
            outcome={"state": "PROPOSED"},
            priority=EvidencePriority.CRITICAL,
        )
        self.policy = policy
        self.snapshot = snapshot
        self.effective = self.leases.update_base(policy, snapshot)
        restart_warnings = self._apply_effective_runtime_policy()
        self.event(
            logger_name="caretaker.logging.policy", severity=logging.WARNING,
            channel=LogChannel.CARETAKER_INTERNAL,
            message="Operator logging policy changed and was atomically reconciled",
            fields={
                "old_policy_hash": old_hash,
                "new_policy_hash": snapshot.content_hash,
                "generation": self.effective.generation,
                "overrides": [item.field_path for item in self.effective.overrides],
                "security_warnings": policy_security_warnings(snapshot),
                "restart_bound_changes": list(restart_warnings),
            },
        )
        self.audit.emit(
            "POLICY_APPLIED",
            actor={"type": "supervisor"},
            policy={
                "prior_policy_id": str(old_snapshot_id),
                "policy_id": str(snapshot.snapshot_id),
                "prior_fingerprint": old_hash,
                "fingerprint": snapshot.content_hash,
                "authority_generation": self.effective.generation,
            },
            outcome={"state": "APPLIED"},
            details={"restart_bound_changes": list(restart_warnings)},
            priority=EvidencePriority.CRITICAL,
        )


    def refresh_authority_policy(self) -> None:
        """Reapply the supervisor authority transform to the declared base policy."""
        declared = self._declared_policy
        transformed = self._policy_transform(declared) if self._policy_transform is not None else declared
        snapshot = policy_snapshot(transformed, source_path=self.snapshot.source_path)
        self._on_policy_reload(declared, snapshot)

    def _on_policy_reload_error(self, error: Exception) -> None:
        self.event(
            logger_name="caretaker.logging.policy", severity=logging.ERROR,
            channel=LogChannel.CARETAKER_INTERNAL,
            message="Operator logging policy reload failed; previous effective policy retained",
            fields={"error": f"{type(error).__name__}: {error}"},
        )
        self.audit.emit(
            "POLICY_REJECTED",
            actor={"type": "supervisor"},
            policy={
                "policy_id": str(self.snapshot.snapshot_id),
                "fingerprint": self.snapshot.content_hash,
                "authority_generation": self.effective.generation,
            },
            outcome={"state": "REJECTED"},
            details={
                "error_type": type(error).__name__,
                "error_fingerprint": hashlib.sha256(
                    str(error).encode("utf-8", errors="replace")
                ).hexdigest(),
                "prior_policy_retained": True,
            },
            priority=EvidencePriority.CRITICAL,
        )

    def acquire_mode(self, *args: Any, **kwargs: Any):
        lease = self.leases.acquire(*args, **kwargs)
        self.effective = self.leases.effective
        restart_warnings = self._apply_effective_runtime_policy()
        self.event(
            logger_name="caretaker.logging.policy",
            severity=logging.WARNING if lease.required_overrides else logging.INFO,
            channel=LogChannel.CARETAKER_INTERNAL,
            message=f"Mode lease acquired: {lease.requested_mode.name}",
            fields={
                "lease_id": str(lease.lease_id),
                "reason": lease.reason,
                "restart_bound_changes": list(restart_warnings),
                "overrides": [
                    {
                        "field": item.field_path,
                        "operator": item.operator_value,
                        "effective": item.effective_value,
                        "reason": item.reason,
                    }
                    for item in lease.required_overrides
                ],
            },
        )
        self.audit.emit(
            "AUTHORITY_SNAPSHOT_CHANGED",
            actor={"type": "operator"},
            policy={"authority_generation": self.effective.generation},
            scope={"lease_id": str(lease.lease_id)},
            outcome={"state": "APPLIED"},
            details={"mode": lease.requested_mode.name, "reason": lease.reason},
            priority=EvidencePriority.CRITICAL,
        )
        return lease

    def release_mode(self, lease_id: UUID):
        effective = self.leases.release(lease_id)
        self.effective = effective
        restart_warnings = self._apply_effective_runtime_policy()
        self.event(
            logger_name="caretaker.logging.policy",
            severity=logging.INFO,
            channel=LogChannel.CARETAKER_INTERNAL,
            message="Mode lease released and lease-specific overrides reverted",
            fields={
                "lease_id": str(lease_id),
                "generation": effective.generation,
                "restart_bound_changes": list(restart_warnings),
            },
        )
        self.audit.emit(
            "AUTHORITY_SNAPSHOT_CHANGED",
            actor={"type": "operator"},
            policy={"authority_generation": effective.generation},
            scope={"lease_id": str(lease_id)},
            outcome={"state": "RELEASED"},
            priority=EvidencePriority.CRITICAL,
        )
        return effective

    def flush(self) -> None:
        self.sink.flush()
        self.audit.flush()

    def overhead_status(self) -> dict[str, Any]:
        """Return bounded Caretaker logging-path overhead evidence."""
        return {
            "schema_version": 1,
            "scope": "caretaker_logging",
            **self.sink.overhead_status(),
        }

    def close(self) -> None:
        if self._closed:
            return
        if self._policy_watcher is not None:
            self._policy_watcher.stop()
        self.event(
            logger_name="caretaker.logging",
            severity=logging.INFO,
            channel=LogChannel.CARETAKER_INTERNAL,
            message="Caretaker logging runtime closing",
            fields={"last_sequence": self._sequence},
        )
        attachment_manifest = self.attachments.close()
        attachment_manifest_hash = (
            hashlib.sha256(json_bytes(attachment_manifest)).hexdigest()
            if (
                attachment_manifest is not None
                and self.active_policy.signing.sign_attachment_manifests
            )
            else None
        )
        self.sink.close(attachment_manifest_hash=attachment_manifest_hash)
        self.audit.close()
        self._closed = True


class CaretakerLogHandler(logging.Handler):
    """Standard-library logging handler backed by Caretaker segments."""

    def __init__(self, runtime: LoggingRuntime, *, channel: LogChannel = LogChannel.APPLICATION) -> None:
        super().__init__()
        self.runtime = runtime
        self.channel = channel

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if record.levelno < logging.ERROR:
                active_policy = self.runtime.active_policy
                rate = active_policy.sampling.debug_rate if record.levelno <= logging.DEBUG else active_policy.sampling.info_rate
                if record.levelno >= logging.WARNING:
                    rate = active_policy.sampling.warning_rate
                if random.random() > rate:
                    return
            fields = {
                key: value for key, value in vars(record).items()
                if key not in {
                    "args", "msg", "message", "exc_info", "exc_text", "stack_info",
                    "name", "levelno", "levelname", "pathname", "filename", "module",
                    "lineno", "funcName", "created", "msecs", "relativeCreated",
                    "thread", "threadName", "processName", "process",
                }
            }
            if record.exc_info:
                fields["exception_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
                fields["exception_fingerprint"] = hashlib.sha256(
                    f"{record.exc_info[0]}:{record.exc_info[1]}".encode()
                ).hexdigest()
            self.runtime.event(
                logger_name=record.name,
                severity=record.levelno,
                channel=self.channel,
                message=record.getMessage(),
                message_template=str(record.msg) if isinstance(record.msg, str) else None,
                fields=fields,
            )
        except Exception:
            self.handleError(record)


class RemoteAuditStream:
    """Output-only bridge from an application process to its supervisor.

    The supervised application must not own or open the audit file.  This
    bridge therefore exposes only the validation-decision submission used by
    the application validation boundary; the supervisor remains responsible
    for identity binding, event construction, and persistence.
    """

    def __init__(self, socket_path: str | Path | None, *, timeout: float = 5.0) -> None:
        self.socket_path = str(socket_path) if socket_path else None
        self.timeout = timeout

    def emit(
        self,
        event_type: str,
        *,
        actor: Mapping[str, Any] | None = None,
        scope: Mapping[str, Any] | None = None,
        policy: Mapping[str, Any] | None = None,
        outcome: Mapping[str, Any] | None = None,
        details: Mapping[str, Any] | None = None,
        priority: EvidencePriority = EvidencePriority.IMPORTANT,
        **_ignored: Any,
    ) -> dict[str, Any] | None:
        """Submit one bounded validation event, or remain disabled unsupervised.

        ``actor`` is deliberately ignored.  The supervisor derives it from
        authenticated peer credentials.  Other fields are treated as worker
        evidence and are validated again by the supervisor before persistence.
        """
        if event_type != "VALIDATION_DECISION":
            raise AuditStreamError(
                "supervised application audit transport permits only "
                "VALIDATION_DECISION"
            )
        if not self.socket_path:
            return None
        if not isinstance(priority, EvidencePriority):
            raise AuditStreamError("Audit priority must be an EvidencePriority")
        from .ipc import control_request

        request = {
            "command": "audit-validation-decision",
            "scope": dict(scope or {}),
            "policy": dict(policy or {}),
            "outcome": dict(outcome or {}),
            "details": dict(details or {}),
            "priority": priority.name,
        }
        try:
            response = control_request(
                self.socket_path,
                request,
                timeout=self.timeout,
            )
        except OSError as exc:
            raise AuditStreamError(
                "supervisor audit transport is unavailable"
            ) from exc
        if not isinstance(response, Mapping) or not response.get("ok"):
            error = response.get("error", "supervisor rejected audit event") if isinstance(response, Mapping) else "invalid supervisor audit response"
            raise AuditStreamError(str(error)[:2048])
        if response.get("recorded") is not True:
            return None
        event_id = response.get("event_id")
        stream_sequence = response.get("stream_sequence")
        if not isinstance(event_id, str) or not isinstance(stream_sequence, int):
            raise AuditStreamError("supervisor returned an invalid audit acknowledgement")
        return {"event_id": event_id, "stream_sequence": stream_sequence}



def json_bytes(value: Any) -> bytes:
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


_default_runtime: LoggingRuntime | None = None


def configure(
    policy: OperatorLoggingPolicy,
    *,
    attach_root: bool = True,
    replace_existing_caretaker_handler: bool = True,
    external_signer: Any | None = None,
) -> LoggingRuntime:
    global _default_runtime
    runtime = LoggingRuntime(policy, external_signer=external_signer)
    _default_runtime = runtime
    if attach_root:
        root = logging.getLogger()
        if replace_existing_caretaker_handler:
            for handler in tuple(root.handlers):
                if isinstance(handler, CaretakerLogHandler):
                    root.removeHandler(handler)
        root.addHandler(CaretakerLogHandler(runtime))
    return runtime


def configure_from_operator_policy(
    application_id: str,
    *,
    path: str | Path | None = None,
    attach_root: bool = True,
) -> LoggingRuntime:
    configured_path = path or os.environ.get("CARETAKER_LOGGING_POLICY")
    if configured_path:
        policy, _snapshot = load_operator_policy(configured_path)
        if policy.application_id == "application":
            policy = dataclass_replace(policy, application_id=application_id)
        runtime = LoggingRuntime(policy, source_path=str(configured_path))
    else:
        policy = OperatorLoggingPolicy.application_defaults(directory=f"./caretaker-data/{application_id}", application_id=application_id)
        runtime = LoggingRuntime(policy)
    global _default_runtime
    _default_runtime = runtime
    if attach_root:
        logging.getLogger().addHandler(CaretakerLogHandler(runtime))
    return runtime


def dataclass_replace(value, **changes):
    from dataclasses import replace
    return replace(value, **changes)


def get_runtime() -> LoggingRuntime | None:
    return _default_runtime


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)

class RemoteLoggingRuntime:
    """Lightweight emitter used by application processes under caretaker.run."""

    def __init__(self, policy: OperatorLoggingPolicy, socket_path: str | Path) -> None:
        from .ipc import SocketLogClient
        self._declared_policy = policy
        self.policy = policy
        self.snapshot = policy_snapshot(policy)
        self.leases = ModeLeaseManager(policy, self.snapshot)
        self.effective = self.leases.effective
        self.run_id = UUID(os.environ.get("CARETAKER_RUN_ID", str(uuid4())))
        self.process_start_id = uuid4()
        self._pid = os.getpid()
        self._sequence = 0
        self._lock = threading.RLock()
        self.client = SocketLogClient(socket_path, codec=__import__("caretaker.logging.records", fromlist=["TLVLogCodec"]).TLVLogCodec(maximum_record_bytes=policy.codec.maximum_record_bytes))
        self.audit = RemoteAuditStream(
            os.environ.get("CARETAKER_SUPERVISOR_CONTROL_SOCKET")
        )
        self.supervised = True
        self._closed = False

    @property
    def active_policy(self) -> OperatorLoggingPolicy:
        return self.effective.effective_policy

    def _next_sequence(self) -> int:
        with self._lock:
            if os.getpid() != self._pid:
                self._pid = os.getpid()
                self.process_start_id = uuid4()
                self._sequence = 0
            self._sequence += 1
            return self._sequence

    def event(self, *, logger_name: str, severity: int, channel: LogChannel, message: str | None,
              fields: Mapping[str, Any] | None = None, message_template: str | None = None,
              function_version: int | None = None, attachment_payload: bytes | None = None,
              attachment_content_type: str = "application/octet-stream",
              attachment_priority: EvidencePriority = EvidencePriority.ORDINARY,
              origin: str = "application") -> LogEnvelope | None:
        active_policy = self.active_policy
        if self._closed or not active_policy.enabled:
            return None
        sequence = self._next_sequence()
        record_id = uuid4()
        attachment_ids: tuple[UUID, ...] = ()
        if attachment_payload is not None:
            fields = dict(fields or {})
            reference = self.client.store_attachment(
                event_id=record_id,
                event_sequence=sequence,
                content_type=attachment_content_type,
                payload=attachment_payload,
                priority=attachment_priority,
            )
            attachment_ids = (UUID(reference["attachment_id"]),)
            sequence = int(reference["event_sequence"])
            fields["attachment"] = reference
        context = snapshot_context()
        sanitized_fields = dict(fields or {})
        if active_policy.redaction.enabled:
            sanitized_fields = _redact(sanitized_fields, names=active_policy.redaction.secret_field_names, replacement=active_policy.redaction.replacement)
            message = _redact(message, names=active_policy.redaction.secret_field_names, replacement=active_policy.redaction.replacement) if message else None
        envelope = LogEnvelope(
            schema_version=1, writer_version="0.6.1", record_id=record_id,
            occurred_at=datetime.now(timezone.utc), monotonic_ns=time.monotonic_ns(),
            process_start_id=self.process_start_id, sequence_number=sequence,
            channel=channel, severity=severity, logger_name=logger_name,
            message_template=message_template, formatted_message=message,
            fields=sanitized_fields, process_id=os.getpid(), thread_id=threading.get_ident(),
            task_id=_safe_task_id(), run_id=self.run_id, call_id=context.get("call_id"),
            target_id=context.get("target_id"), function_version=function_version,
            incident_id=context.get("incident_id"), attachment_ids=attachment_ids, origin=origin,
        )
        self.client.write(envelope)
        return envelope

    def apply_policy(self, policy: OperatorLoggingPolicy) -> None:
        """Replace the remote emitter policy after a supervisor authority update."""
        self.policy = policy
        self.snapshot = policy_snapshot(policy)
        self.leases = ModeLeaseManager(policy, self.snapshot)
        self.effective = self.leases.effective

    def apply_authority_policy(self, effective_authority: Any) -> None:
        self.apply_policy(
            effective_authority.apply_dataclass(self._declared_policy, prefix="logging")
        )

    def flush(self) -> None:
        self.client.flush()

    def close(self) -> None:
        if not self._closed:
            self.client.close()
            self._closed = True


def configure_remote(policy: OperatorLoggingPolicy, socket_path: str | Path, *, attach_root: bool = True) -> RemoteLoggingRuntime:
    global _default_runtime
    runtime = RemoteLoggingRuntime(policy, socket_path)
    _default_runtime = runtime  # type: ignore[assignment]
    if attach_root:
        logging.getLogger().addHandler(CaretakerLogHandler(runtime))  # type: ignore[arg-type]
    return runtime
