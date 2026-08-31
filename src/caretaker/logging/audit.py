from __future__ import annotations

import binascii
import hashlib
import json
import os
import random
import re
import threading
import time
import base64
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol
from uuid import UUID, uuid4

from .models import EvidencePriority
from .signing import (
    RuntimeArtifactSigningService,
    deserialize_signed_artifact,
    serialize_signed_artifact,
    verify_signed_artifact,
)


AUDIT_SCHEMA_VERSION = 1
AUDIT_DELIVERY_QUEUE_SCHEMA_VERSION = 1
_EVENT_TYPE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_DEFAULT_AUDIT_SECRET_FIELD_NAMES = frozenset({
    "password", "passwd", "token", "secret", "authorization", "api_key", "apikey",
})


def _event_definition(
    *,
    description: str,
    minimum_priority: EvidencePriority,
    required_fields: tuple[str, ...] = (),
    redaction_rules: tuple[str, ...] = (
        "credentials and private keys must never be included",
        "raw evidence belongs in a referenced attachment",
    ),
    example: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    return MappingProxyType({
        "description": description,
        "minimum_priority": minimum_priority,
        "required_fields": required_fields,
        "redaction_rules": redaction_rules,
        "example": MappingProxyType(dict(example or {})),
    })


# This is the finite, reviewable vocabulary for Caretaker's high-value stream.
# Unknown syntactically valid names remain forward-compatible evidence, but do
# not receive the guarantees of a registered definition.
AUDIT_EVENT_REGISTRY: Mapping[str, Mapping[str, Any]] = MappingProxyType({
    "AUDIT_STREAM_STARTED": _event_definition(
        description="A local audit stream was opened.",
        minimum_priority=EvidencePriority.CRITICAL,
        required_fields=("policy.policy_id", "policy.fingerprint", "details.hash_chain"),
        example={"hash_chain": True},
    ),
    "AUDIT_STREAM_ROTATED": _event_definition(
        description="The local audit stream or its segment was rotated.",
        minimum_priority=EvidencePriority.IMPORTANT,
        example={"segment_id": "segment-42", "content_sha256": "sha256:..."},
    ),
    "AUDIT_DELIVERY_STATUS": _event_definition(
        description="Audit delivery or local-retention status changed.",
        minimum_priority=EvidencePriority.IMPORTANT,
        example={"sink_id": "monitoring-primary", "state": "DELIVERED"},
    ),
    "AUDIT_DATA_LOSS": _event_definition(
        description="Policy-approved audit data loss or sampling was recorded.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={"category": "ordinary_metrics", "count": 1, "reason": "sampling_policy"},
    ),
    "CONSOLE_INVOCATION_STARTED": _event_definition(
        description="An operator console invocation started.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={
            "console_invocation_id": "console-uuid",
            "console_identity": {
                "algorithm": "ed25519",
                "encoding": "base64",
                "public_key_fingerprint": "sha256:...",
            },
        },
    ),
    "CONSOLE_INVOCATION_ENDED": _event_definition(
        description="An operator console invocation ended.",
        minimum_priority=EvidencePriority.IMPORTANT,
        example={"console_invocation_id": "console-uuid", "reason": "operator_exit"},
    ),
    "POLICY_PROPOSED": _event_definition(
        description="A policy change was proposed for review.",
        minimum_priority=EvidencePriority.CRITICAL,
        required_fields=("policy.policy_id", "policy.fingerprint", "outcome.state"),
        example={"state": "PROPOSED"},
    ),
    "POLICY_REVIEWED": _event_definition(
        description="An operator or deployment reviewed a policy proposal.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={"state": "APPROVED", "review_id": "review-uuid"},
    ),
    "POLICY_APPLIED": _event_definition(
        description="A policy change became effective.",
        minimum_priority=EvidencePriority.CRITICAL,
        required_fields=("policy.policy_id", "policy.fingerprint", "outcome.state"),
        example={"state": "APPLIED"},
    ),
    "POLICY_ACCEPTED": _event_definition(
        description="An operator accepted an applied policy for persistent deployment review.",
        minimum_priority=EvidencePriority.CRITICAL,
        required_fields=("policy.policy_id", "policy.fingerprint", "outcome.state"),
        example={"state": "ACCEPTED", "policy_mutated": False},
    ),
    "POLICY_REJECTED": _event_definition(
        description="A policy proposal was rejected.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={"state": "REJECTED", "reason": "stale_context"},
    ),
    "POLICY_ROLLED_BACK": _event_definition(
        description="A policy transition was rolled back before acceptance.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={"state": "ROLLED_BACK", "transition_id": "transition-uuid"},
    ),
    "POLICY_SUPERSEDED": _event_definition(
        description="A policy record was superseded by a later accepted record.",
        minimum_priority=EvidencePriority.IMPORTANT,
        example={"state": "SUPERSEDED", "replacement_policy_id": "policy-new-uuid"},
    ),
    "AUTHORITY_SNAPSHOT_CHANGED": _event_definition(
        description="The effective authority snapshot changed.",
        minimum_priority=EvidencePriority.CRITICAL,
        required_fields=("scope.lease_id", "outcome.state"),
        example={"state": "APPLIED", "lease_id": "lease-uuid"},
    ),
    "WORKER_AUTHORITY_ISSUED": _event_definition(
        description="A supervisor issued an authority packet to a worker.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={"worker_id": "worker-uuid", "authority_packet_id": "packet-uuid"},
    ),
    "WORKER_AUTHORITY_REFRESHED": _event_definition(
        description="A worker reacquired an expiring authority packet.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={"worker_id": "worker-uuid", "authority_packet_id": "packet-uuid"},
    ),
    "WORKER_AUTHORITY_EXPIRED": _event_definition(
        description="A worker authority packet expired.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={"worker_id": "worker-uuid", "authority_packet_id": "packet-uuid"},
    ),
    "WORKER_FAILED": _event_definition(
        description="A worker failure and transaction rollback were recorded.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={"transaction_state": "ROLLED_BACK", "failure_id": "failure-uuid"},
    ),
    "WORKER_REPLACEMENT_REQUESTED": _event_definition(
        description="A policy-authorized worker replacement was requested.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={"failed_worker_id": "worker-old", "replacement_request_id": "request-uuid"},
    ),
    "WORKER_REPLACED": _event_definition(
        description="A verified replacement worker was admitted.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={"failed_worker_id": "worker-old", "replacement_worker_id": "worker-new"},
    ),
    "SUPERVISOR_STATE_CHANGED": _event_definition(
        description="The application-scoped supervisor state changed.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={"state": "CONTROL_PLANE_LOST", "reason": "heartbeat_timeout"},
    ),
    "INCIDENT_CAPTURED": _event_definition(
        description="An incident was captured into durable evidence.",
        minimum_priority=EvidencePriority.IMPORTANT,
        example={"incident_id": "incident-uuid", "capture_level": "STANDARD"},
    ),
    "VALIDATION_DECISION": _event_definition(
        description="A validation result or gate decision was recorded.",
        minimum_priority=EvidencePriority.IMPORTANT,
        example={"state": "PASSED", "validation_id": "validation-uuid"},
    ),
    "RECOVERY_DECISION": _event_definition(
        description="A restart or failure-recovery decision was recorded.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={"state": "PLANNED_ONLY", "action": "ROLLBACK_TO_DEPLOYED_CODE"},
    ),
    "REPAIR_ROLLOUT_TRANSITION": _event_definition(
        description="A policy-authorized Repair rollout lifecycle transition was recorded.",
        minimum_priority=EvidencePriority.CRITICAL,
        required_fields=("scope.rollout_id", "scope.transition_id", "outcome.state"),
        example={
            "rollout_id": "rollout-uuid",
            "transition_id": "transition-uuid",
            "state": "validated",
            "action": "advance",
        },
    ),
})


def audit_event_definition(event_type: str) -> Mapping[str, Any] | None:
    """Return immutable metadata for a registered event type, if known."""
    return AUDIT_EVENT_REGISTRY.get(event_type)


def _has_field(envelope: Mapping[str, Any], path: str) -> bool:
    value: Any = envelope
    for component in path.split("."):
        if not isinstance(value, Mapping) or component not in value:
            return False
        value = value[component]
    return True


class AuditStreamError(RuntimeError):
    """Raised when the local audit stream cannot preserve its integrity."""


class AuditDeliverySink(Protocol):
    """Output-only adapter for shipping exact audit records externally."""

    sink_id: str

    def deliver(self, record: bytes) -> Mapping[str, Any] | None: ...

    def flush(self) -> None: ...


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8")


def _json_default(value: Any) -> Any:
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, EvidencePriority):
        return value.name
    raise TypeError(f"Unsupported audit value: {type(value).__name__}")


def _copy_mapping(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise AuditStreamError("Audit fields must be mappings")
    return {str(key): item for key, item in value.items()}


def _redact_audit_value(
    value: Any,
    *,
    secret_field_names: frozenset[str],
    replacement: str,
    key: str | None = None,
) -> Any:
    """Redact bounded audit values before they are hashed or signed."""
    if key is not None and key.lower() in secret_field_names:
        return replacement
    if isinstance(value, Mapping):
        return {
            str(item_key): _redact_audit_value(
                item,
                secret_field_names=secret_field_names,
                replacement=replacement,
                key=str(item_key),
            )
            for item_key, item in value.items()
        }
    if isinstance(value, (tuple, list)):
        return [
            _redact_audit_value(
                item,
                secret_field_names=secret_field_names,
                replacement=replacement,
            )
            for item in value
        ]
    if isinstance(value, str):
        result = re.sub(
            r"(?i)(password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*([^\s,;]+)",
            lambda match: f"{match.group(1)}={replacement}",
            value,
        )
        return re.sub(
            r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*",
            f"Bearer {replacement}",
            result,
        )
    return value


def verify_audit_stream(
    path: str | Path,
    *,
    hash_chain: bool = True,
    require_signatures: bool = False,
    identity_public_keys: Mapping[str, bytes | str] | None = None,
    maximum_event_bytes: int = 4096,
) -> dict[str, Any]:
    """Verify an exported audit stream without opening it for append.

    ``identity_public_keys`` maps a signed artifact's public-key fingerprint to
    its public key.  Public keys may be raw bytes or base64 text.  When
    signatures are optional, a valid signature whose key is unavailable is
    reported as ``UNAVAILABLE`` rather than treated as cryptographically
    verified.  ``require_signatures=True`` makes that condition, unsigned
    records, and invalid signatures fail the report.

    The verifier never truncates, repairs, executes, or sends records.  An
    incomplete final line is reported as invalid; recovery/truncation remains
    an explicit writer-start operation.
    """
    if maximum_event_bytes <= 0:
        raise ValueError("maximum_event_bytes must be greater than zero")
    stream_path = Path(path)
    report: dict[str, Any] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "path": str(stream_path),
        "valid": False,
        "hash_chain_valid": False,
        "signature_verification": "NOT_REQUIRED" if not require_signatures else "FAILED",
        "event_count": 0,
        "first_sequence": None,
        "last_sequence": None,
        "signed_event_count": 0,
        "unsigned_event_count": 0,
        "unverified_signature_count": 0,
        "errors": [],
    }
    errors: list[str] = report["errors"]
    if not stream_path.is_file():
        errors.append("audit stream does not exist")
        return report

    keys = dict(identity_public_keys or {})
    previous_hash: str | None = None
    previous_sequence = 0
    signature_failures = 0
    signature_unavailable = 0
    hash_failures = 0
    try:
        stream = stream_path.open("rb")
    except OSError as exc:
        errors.append(f"audit stream cannot be read: {exc}")
        return report
    with stream:
        for line_number, line in enumerate(stream, start=1):
            if len(line) > maximum_event_bytes:
                errors.append(
                    f"line {line_number}: audit record exceeds maximum_event_bytes"
                )
                hash_failures += 1
                continue
            if not line.endswith(b"\n"):
                errors.append(f"line {line_number}: incomplete final audit record")
                hash_failures += 1
                break
            try:
                event = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                errors.append(f"line {line_number}: malformed audit record: {exc}")
                hash_failures += 1
                continue
            if not isinstance(event, Mapping):
                errors.append(f"line {line_number}: audit record is not an object")
                hash_failures += 1
                continue
            sequence = event.get("stream_sequence")
            if not isinstance(sequence, int) or sequence != previous_sequence + 1:
                errors.append(f"line {line_number}: audit stream sequence is not contiguous")
                hash_failures += 1
            else:
                previous_sequence = sequence
                report["event_count"] += 1
                if report["first_sequence"] is None:
                    report["first_sequence"] = sequence
                report["last_sequence"] = sequence
            integrity = event.get("integrity")
            if not isinstance(integrity, Mapping):
                errors.append(f"line {line_number}: audit record has no integrity object")
                hash_failures += 1
                continue
            if "hash_chain" in integrity and integrity.get("hash_chain") is not hash_chain:
                errors.append(f"line {line_number}: audit hash-chain mode does not match policy")
                hash_failures += 1
            if hash_chain and integrity.get("previous_event_hash") != previous_hash:
                errors.append(f"line {line_number}: previous-event hash does not match")
                hash_failures += 1
            body = dict(event)
            body.pop("integrity", None)
            expected_content = hashlib.sha256(_canonical(body)).hexdigest()
            if integrity.get("content_sha256") != expected_content:
                errors.append(f"line {line_number}: audit record content hash does not match")
                hash_failures += 1
            else:
                previous_hash = expected_content

            signature_value = integrity.get("artifact_signature")
            if not isinstance(signature_value, Mapping):
                report["unsigned_event_count"] += 1
                if require_signatures:
                    signature_failures += 1
                    errors.append(f"line {line_number}: required audit signature is missing")
                continue
            report["signed_event_count"] += 1
            try:
                artifact = deserialize_signed_artifact(signature_value)
                if artifact.artifact_kind != "caretaker-audit-event":
                    raise ValueError("wrong artifact kind")
                if artifact.run_id != UUID(str(event.get("run_id") or "")):
                    raise ValueError("runtime identity does not match")
                if artifact.process_start_id != UUID(str(event.get("process_start_id") or "")):
                    raise ValueError("process identity does not match")
                if artifact.content_hash != expected_content:
                    raise ValueError("content hash does not match")
                expected_context = {
                    "event_id": str(event.get("event_id") or ""),
                    "event_type": str(event.get("event_type") or ""),
                    "stream_sequence": event.get("stream_sequence"),
                }
                if dict(artifact.context) != expected_context:
                    raise ValueError("context does not match")
                if integrity.get("signature_state") != artifact.signer_mode.name:
                    raise ValueError("signature state does not match")
                if integrity.get("signer_fingerprint") != artifact.public_key_fingerprint:
                    raise ValueError("signer fingerprint does not match")
            except Exception as exc:
                signature_failures += 1
                errors.append(f"line {line_number}: malformed audit signature: {exc}")
                continue
            fingerprint = artifact.public_key_fingerprint
            key = keys.get(fingerprint) if fingerprint else None
            if key is None:
                signature_unavailable += 1
                if require_signatures:
                    signature_failures += 1
                    errors.append(f"line {line_number}: public key is unavailable")
                continue
            if isinstance(key, str):
                try:
                    key = base64.b64decode(key)
                except Exception as exc:
                    signature_failures += 1
                    errors.append(f"line {line_number}: public key is malformed: {exc}")
                    continue
            try:
                verified = verify_signed_artifact(artifact, key)
            except Exception as exc:
                verified = False
                errors.append(f"line {line_number}: signature verification failed: {exc}")
            if not verified:
                signature_failures += 1
                errors.append(f"line {line_number}: audit signature is invalid")

    report["hash_chain_valid"] = hash_failures == 0
    report["unverified_signature_count"] = signature_unavailable
    if signature_failures:
        report["signature_verification"] = "FAILED"
    elif signature_unavailable:
        report["signature_verification"] = "UNAVAILABLE"
    elif report["signed_event_count"]:
        report["signature_verification"] = "VERIFIED"
    else:
        report["signature_verification"] = "NOT_REQUIRED"
    report["valid"] = not errors
    return report


class AuditStreamWriter:
    """Small append-only writer for high-value Caretaker decisions.

    The stream is deliberately not a logging handler and has no read or command
    interface.  Each line is self-contained JSON so an external collector can
    ship it without understanding the primary binary event format.  The local
    file remains bounded by the configured event size; larger evidence must be
    represented by references in ``details``.
    """

    def __init__(
        self,
        policy: Any,
        *,
        directory: str | Path,
        run_id: UUID,
        process_start_id: UUID,
        supervisor_id: UUID | str | None = None,
        artifact_signer: RuntimeArtifactSigningService | None = None,
        redaction_policy: Any | None = None,
        external_sink: AuditDeliverySink | None = None,
    ) -> None:
        self.policy = policy
        self.run_id = run_id
        self.process_start_id = process_start_id
        self.supervisor_id = str(supervisor_id) if supervisor_id is not None else None
        self._artifact_signer = artifact_signer
        self._redaction_enabled = True
        self._secret_field_names = _DEFAULT_AUDIT_SECRET_FIELD_NAMES
        self._redaction_replacement = "<redacted>"
        self._set_redaction_policy(redaction_policy)
        self.path = Path(directory) / policy.file_name
        self.delivery_queue_path = self.path.with_name(
            f"{self.path.name}.delivery.queue"
        )
        self._lock = threading.RLock()
        self._closed = False
        self._sequence = 0
        self._previous_hash: str | None = None
        self._recovered_truncated_bytes = 0
        self._pending_loss_count = 0
        self._pending_loss_priorities: dict[str, int] = {}
        self._external_sink = external_sink
        self._external_delivered_events = 0
        self._external_failed_events = 0
        self._external_last_error: str | None = None
        self._file = None
        self._validate_delivery_policy()
        if external_sink is not None and (
            not callable(getattr(external_sink, "deliver", None))
            or not callable(getattr(external_sink, "flush", None))
        ):
            raise AuditStreamError(
                "external audit sink must provide output-only deliver and flush methods"
            )
        if getattr(policy, "external_delivery_required", False) and external_sink is None:
            raise AuditStreamError(
                "external audit delivery is required but no output-only sink was provided"
            )
        if not policy.enabled:
            return
        if policy.sign_events and artifact_signer is None:
            raise AuditStreamError(
                "Audit event signing is enabled but no runtime artifact signer was provided"
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._recover_existing()
        self._file = self.path.open("ab", buffering=0)
        if self._external_sink is not None:
            delivered = self._drain_external_queue()
            if not delivered and getattr(policy, "external_delivery_required", False):
                self._file.close()
                self._file = None
                self._closed = True
                raise AuditStreamError(
                    "required external audit delivery is unavailable during startup"
                )

    @property
    def enabled(self) -> bool:
        return self._file is not None and not self._closed

    @property
    def previous_hash(self) -> str | None:
        return self._previous_hash

    @property
    def recovered_truncated_bytes(self) -> int:
        """Bytes discarded from one incomplete final record during recovery."""
        return self._recovered_truncated_bytes

    @property
    def pending_loss_count(self) -> int:
        """Number of policy-suppressed audit events awaiting a loss record."""
        with self._lock:
            return self._pending_loss_count

    def delivery_status(self) -> dict[str, Any]:
        """Return bounded external-delivery state without exposing sink data."""
        with self._lock:
            required = bool(getattr(self.policy, "external_delivery_required", False))
            pending_records = self._read_delivery_queue()
            pending_bytes = sum(len(record) for record in pending_records)
            if self._external_sink is None:
                state = "LOCAL_ONLY"
                sink_id = None
            else:
                state = "DEGRADED" if self._external_failed_events or pending_records else "ACTIVE"
                sink_id = str(
                    getattr(self._external_sink, "sink_id", None)
                    or type(self._external_sink).__name__
                )[:128]
            return {
                "state": state,
                "required": required,
                "acknowledgement_required": bool(
                    getattr(self.policy, "external_delivery_require_ack", False)
                ),
                "sink_id": sink_id,
                "delivered_events": self._external_delivered_events,
                "failed_events": self._external_failed_events,
                "last_error_type": self._external_last_error,
                "pending_records": len(pending_records),
                "pending_bytes": pending_bytes,
            }

    def _validate_delivery_policy(self) -> None:
        preserved = getattr(self.policy, "always_preserve_priorities", frozenset())
        if EvidencePriority.CRITICAL not in preserved:
            raise AuditStreamError(
                "logging.audit.always_preserve_priorities must include CRITICAL"
            )
        critical_rate = getattr(self.policy, "critical_rate", 1.0)
        if critical_rate != 1.0:
            raise AuditStreamError(
                "logging.audit.critical_rate must be 1; critical audit events cannot be sampled"
            )
        for name in ("debug_rate", "ordinary_rate", "important_rate", "critical_rate"):
            rate = getattr(self.policy, name, None)
            if not isinstance(rate, (int, float)) or isinstance(rate, bool) or not 0.0 <= rate <= 1.0:
                raise AuditStreamError(
                    f"logging.audit.{name} must be between 0 and 1"
                )
        if not isinstance(getattr(self.policy, "external_delivery_required", False), bool):
            raise AuditStreamError("logging.audit.external_delivery_required must be a boolean")
        if not isinstance(getattr(self.policy, "external_delivery_require_ack", False), bool):
            raise AuditStreamError("logging.audit.external_delivery_require_ack must be a boolean")
        for name in (
            "external_delivery_max_pending_records",
            "external_delivery_max_pending_bytes",
        ):
            value = getattr(self.policy, name, None)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise AuditStreamError(f"logging.audit.{name} must be a positive integer")

    def _set_redaction_policy(self, redaction_policy: Any | None) -> None:
        if redaction_policy is None:
            return
        self._redaction_enabled = bool(getattr(redaction_policy, "enabled", True))
        configured_names = getattr(redaction_policy, "secret_field_names", None)
        if configured_names is not None:
            self._secret_field_names = frozenset(
                str(name).lower() for name in configured_names
            )
        replacement = getattr(redaction_policy, "replacement", None)
        if replacement is not None:
            self._redaction_replacement = str(replacement)

    def _safe_mapping(self, value: Mapping[str, Any] | None) -> dict[str, Any]:
        copied = _copy_mapping(value)
        if not self._redaction_enabled:
            return copied
        return _redact_audit_value(
            copied,
            secret_field_names=self._secret_field_names,
            replacement=self._redaction_replacement,
        )

    def _deliver_to_sink(self, encoded: bytes) -> None:
        sink = self._external_sink
        if sink is None:
            return
        receipt = sink.deliver(encoded)
        if not getattr(self.policy, "external_delivery_require_ack", False):
            return
        expected_hash = hashlib.sha256(encoded).hexdigest()
        if not isinstance(receipt, Mapping):
            raise AuditStreamError(
                "external audit sink did not return the required acknowledgement"
            )
        if receipt.get("acknowledged") is not True:
            raise AuditStreamError("external audit sink did not acknowledge the record")
        if receipt.get("record_sha256") != expected_hash:
            raise AuditStreamError(
                "external audit acknowledgement is bound to a different record"
            )

    def _recover_existing(self) -> None:
        if not self.path.exists():
            return
        last_valid_offset = 0
        last_sequence = 0
        previous_hash: str | None = None
        with self.path.open("rb") as stream:
            while True:
                line_start = stream.tell()
                line = stream.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    # A process can die after writing a complete prefix.  It is
                    # safe to discard only this incomplete final line.
                    break
                try:
                    event = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise AuditStreamError(
                        f"Malformed complete audit record at byte {line_start}"
                    ) from exc
                self._validate_existing(event, last_sequence, previous_hash)
                last_valid_offset = stream.tell()
                last_sequence = int(event["stream_sequence"])
                previous_hash = str(event["integrity"]["content_sha256"])
        if last_valid_offset != self.path.stat().st_size:
            self._recovered_truncated_bytes = self.path.stat().st_size - last_valid_offset
            with self.path.open("r+b") as stream:
                stream.truncate(last_valid_offset)
        self._sequence = last_sequence
        self._previous_hash = previous_hash

    def _validate_existing(
        self,
        event: Any,
        previous_sequence: int,
        previous_hash: str | None,
    ) -> None:
        if not isinstance(event, Mapping):
            raise AuditStreamError("Audit record is not an object")
        sequence = event.get("stream_sequence")
        if not isinstance(sequence, int) or sequence != previous_sequence + 1:
            raise AuditStreamError("Audit stream sequence is not contiguous")
        integrity = event.get("integrity")
        if not isinstance(integrity, Mapping):
            raise AuditStreamError("Audit record has no integrity object")
        expected_previous = integrity.get("previous_event_hash")
        if self.policy.hash_chain and expected_previous != previous_hash:
            raise AuditStreamError("Audit stream previous-event hash does not match")
        body = dict(event)
        body.pop("integrity", None)
        expected_content = hashlib.sha256(_canonical(body)).hexdigest()
        if integrity.get("content_sha256") != expected_content:
            raise AuditStreamError("Audit record content hash does not match")
        if self.policy.sign_events:
            self._validate_existing_signature(
                event,
                integrity,
                content_hash=expected_content,
            )

    def _public_key_for_artifact(self, artifact: Any) -> bytes | None:
        signer = self._artifact_signer
        if signer is None:
            return None
        journal = getattr(signer, "journal", None)
        fingerprint = artifact.public_key_fingerprint
        if journal is not None and fingerprint:
            public_key = journal.public_key(fingerprint)
            if public_key is not None:
                return public_key
        identity = getattr(signer, "identity", None)
        if isinstance(identity, Mapping):
            value = identity.get("public_key")
            if isinstance(value, bytes):
                return value
            if isinstance(value, str):
                try:
                    return base64.b64decode(value)
                except Exception:
                    return None
        return None

    def _validate_existing_signature(
        self,
        event: Mapping[str, Any],
        integrity: Mapping[str, Any],
        *,
        content_hash: str,
    ) -> None:
        value = integrity.get("artifact_signature")
        if not isinstance(value, Mapping):
            raise AuditStreamError(
                "Audit event signing is required but the retained record has no signature"
            )
        try:
            artifact = deserialize_signed_artifact(value)
        except Exception as exc:
            raise AuditStreamError("Audit event signature is malformed") from exc
        if artifact.artifact_kind != "caretaker-audit-event":
            raise AuditStreamError("Audit event signature has the wrong artifact kind")
        if artifact.run_id != UUID(str(event.get("run_id") or "")):
            raise AuditStreamError("Audit event signature runtime identity does not match")
        if artifact.process_start_id != UUID(str(event.get("process_start_id") or "")):
            raise AuditStreamError("Audit event signature process identity does not match")
        if artifact.content_hash != content_hash:
            raise AuditStreamError("Audit event signature content hash does not match")
        expected_context = {
            "event_id": str(event.get("event_id") or ""),
            "event_type": str(event.get("event_type") or ""),
            "stream_sequence": event.get("stream_sequence"),
        }
        if dict(artifact.context) != expected_context:
            raise AuditStreamError("Audit event signature context does not match")
        public_key = self._public_key_for_artifact(artifact)
        if public_key is None or not verify_signed_artifact(artifact, public_key):
            raise AuditStreamError("Audit event signature could not be verified")

    def update_policy(
        self,
        policy: Any,
        *,
        redaction_policy: Any | None = None,
    ) -> tuple[str, ...]:
        warnings: list[str] = []
        if policy.file_name != self.policy.file_name:
            warnings.append("logging.audit.file_name is startup-bound; the existing file remains active")
        if policy.enabled != self.policy.enabled:
            warnings.append("logging.audit.enabled is run-bound; a new run is required")
        if policy.hash_chain != self.policy.hash_chain:
            warnings.append("logging.audit.hash_chain is run-bound; a new run is required")
        if policy.sign_events != self.policy.sign_events:
            warnings.append("logging.audit.sign_events is run-bound; a new run is required")
        if policy.maximum_event_bytes != self.policy.maximum_event_bytes:
            warnings.append("logging.audit.maximum_event_bytes is startup-bound; the existing limit remains active")
        for field_name in (
            "always_preserve_priorities",
            "debug_rate",
            "ordinary_rate",
            "important_rate",
            "critical_rate",
            "external_delivery_required",
            "external_delivery_require_ack",
        ):
            if getattr(policy, field_name) != getattr(self.policy, field_name):
                warnings.append(
                    f"logging.audit.{field_name} is run-bound; the existing delivery policy remains active"
                )
        for field_name in (
            "external_delivery_max_pending_records",
            "external_delivery_max_pending_bytes",
        ):
            if getattr(policy, field_name) != getattr(self.policy, field_name):
                warnings.append(
                    f"logging.audit.{field_name} is run-bound; the existing queue bound remains active"
                )
        self._set_redaction_policy(redaction_policy)
        return tuple(warnings)

    def _sampling_rate(self, priority: EvidencePriority) -> float:
        return float(getattr(self.policy, f"{priority.name.lower()}_rate", 1.0))

    def _should_retain(self, priority: EvidencePriority) -> bool:
        preserved = getattr(self.policy, "always_preserve_priorities", frozenset())
        if priority in preserved:
            return True
        rate = self._sampling_rate(priority)
        if rate <= 0.0:
            return False
        if rate >= 1.0:
            return True
        return random.random() < rate

    def _record_policy_loss(self, priority: EvidencePriority) -> None:
        self._pending_loss_count += 1
        key = priority.name
        self._pending_loss_priorities[key] = self._pending_loss_priorities.get(key, 0) + 1

    def _flush_policy_loss(self) -> None:
        if not self._pending_loss_count:
            return
        count = self._pending_loss_count
        priority_counts = dict(self._pending_loss_priorities)
        # Reset only after the critical loss record is durably written. If the
        # write fails, the caller retains the pending evidence and receives a
        # fail-closed AuditStreamError.
        self._write_event(
            "AUDIT_DATA_LOSS",
            actor={"type": "system"},
            outcome={"state": "SAMPLED"},
            details={
                "category": "audit_events",
                "count": count,
                "priority_counts": priority_counts,
                "reason": "sampling_policy",
                "loss_record_preserved": True,
            },
            priority=EvidencePriority.CRITICAL,
        )
        self._pending_loss_count = 0
        self._pending_loss_priorities.clear()

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
        occurred_at: datetime | None = None,
        monotonic_ns: int | None = None,
    ) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        if not isinstance(event_type, str) or _EVENT_TYPE.fullmatch(event_type) is None:
            raise AuditStreamError("Audit event_type must be an uppercase registry name")
        if not isinstance(priority, EvidencePriority):
            raise AuditStreamError("Audit priority must be an EvidencePriority")
        definition = audit_event_definition(event_type)
        if definition is not None:
            minimum_priority = definition["minimum_priority"]
            if priority.value < minimum_priority.value:
                raise AuditStreamError(
                    f"{event_type} requires at least {minimum_priority.name} priority"
                )
            supplied = {
                "actor": actor,
                "scope": scope,
                "policy": policy,
                "outcome": outcome,
                "details": details,
            }
            missing = [
                field for field in definition["required_fields"]
                if not _has_field(supplied, field)
            ]
            if missing:
                raise AuditStreamError(
                    f"{event_type} is missing required fields: {', '.join(missing)}"
                )
        with self._lock:
            if self._closed or self._file is None:
                return None
            if not self._should_retain(priority):
                self._record_policy_loss(priority)
                return None
            self._flush_policy_loss()
            return self._write_event(
                event_type,
                actor=actor,
                scope=scope,
                policy=policy,
                outcome=outcome,
                details=details,
                priority=priority,
                occurred_at=occurred_at,
                monotonic_ns=monotonic_ns,
            )

    def _write_event(
        self,
        event_type: str,
        *,
        actor: Mapping[str, Any] | None = None,
        scope: Mapping[str, Any] | None = None,
        policy: Mapping[str, Any] | None = None,
        outcome: Mapping[str, Any] | None = None,
        details: Mapping[str, Any] | None = None,
        priority: EvidencePriority = EvidencePriority.IMPORTANT,
        occurred_at: datetime | None = None,
        monotonic_ns: int | None = None,
    ) -> dict[str, Any]:
        """Write one already-validated retained event while holding the lock."""
        if self._closed or self._file is None:
            raise AuditStreamError("Audit stream is not open")
        with self._lock:
            self._sequence += 1
            timestamp = occurred_at or datetime.now(timezone.utc)
            body: dict[str, Any] = {
                "schema_version": AUDIT_SCHEMA_VERSION,
                "event_type": event_type,
                "event_version": 1,
                "event_id": str(uuid4()),
                "stream_sequence": self._sequence,
                "occurred_at": timestamp.isoformat(),
                "monotonic_ns": monotonic_ns if monotonic_ns is not None else time.monotonic_ns(),
                "process_start_id": str(self.process_start_id),
                "run_id": str(self.run_id),
                "supervisor_id": self.supervisor_id,
                "priority": priority.name,
                "actor": self._safe_mapping(actor),
                "scope": self._safe_mapping(scope),
                "policy": self._safe_mapping(policy),
                "outcome": self._safe_mapping(outcome),
                "details": self._safe_mapping(details),
            }
            content_hash = hashlib.sha256(_canonical(body)).hexdigest()
            event = dict(body)
            event["integrity"] = {
                "previous_event_hash": self._previous_hash if self.policy.hash_chain else None,
                "content_sha256": content_hash,
                "hash_chain": self.policy.hash_chain,
            }
            if self.policy.sign_events:
                if self._artifact_signer is None:
                    self._sequence -= 1
                    raise AuditStreamError(
                        "Audit event signing is enabled but no runtime artifact signer is available"
                    )
                signed = self._artifact_signer.sign_artifact(
                    artifact_kind="caretaker-audit-event",
                    content_hash=content_hash,
                    previous_artifact_hash=self._previous_hash,
                    context={
                        "event_id": body["event_id"],
                        "event_type": event_type,
                        "stream_sequence": self._sequence,
                    },
                    next_event_sequence=self._sequence,
                )
                if signed is None:
                    self._sequence -= 1
                    raise AuditStreamError(
                        "Audit event signing was required but the configured signer returned no signature"
                    )
                if (
                    signed.run_id != self.run_id
                    or signed.process_start_id != self.process_start_id
                ):
                    self._sequence -= 1
                    raise AuditStreamError(
                        "Audit event signer identity does not match the audit runtime"
                    )
                event["integrity"].update({
                    "artifact_signature": serialize_signed_artifact(signed),
                    "signature_state": signed.signer_mode.name,
                    "signer_fingerprint": signed.public_key_fingerprint,
                })
            encoded = _canonical(event) + b"\n"
            if len(encoded) > self.policy.maximum_event_bytes:
                self._sequence -= 1
                raise AuditStreamError(
                    f"Audit event is {len(encoded)} bytes; maximum is "
                    f"{self.policy.maximum_event_bytes}"
                )
            try:
                self._file.write(encoded)
                if priority is EvidencePriority.CRITICAL and self.policy.flush_critical:
                    self._file.flush()
                    os.fsync(self._file.fileno())
            except OSError as exc:
                raise AuditStreamError("Unable to persist audit event") from exc
            self._previous_hash = content_hash
            self._deliver_external(encoded)
            return event

    def _deliver_external(self, encoded: bytes) -> None:
        sink = self._external_sink
        if sink is None:
            return
        if not self._drain_external_queue():
            self._queue_external(encoded)
            if getattr(self.policy, "external_delivery_required", False):
                raise AuditStreamError(
                    "required external audit delivery remains unavailable"
                )
            return
        try:
            self._deliver_to_sink(encoded)
        except Exception as exc:
            self._external_failed_events += 1
            self._external_last_error = type(exc).__name__
            self._queue_external(encoded)
            if getattr(self.policy, "external_delivery_required", False):
                raise AuditStreamError(
                    "required external audit delivery failed after local persistence"
                ) from exc
            return
        self._external_delivered_events += 1

    def _read_delivery_queue(self) -> list[bytes]:
        path = self.delivery_queue_path
        if not path.exists():
            return []
        try:
            lines = path.read_bytes().splitlines()
        except OSError as exc:
            raise AuditStreamError("Unable to read external audit delivery queue") from exc
        records: list[bytes] = []
        for line in lines:
            try:
                item = json.loads(line.decode("utf-8"))
                if not isinstance(item, Mapping):
                    raise ValueError("queue item is not an object")
                if int(item.get("schema_version") or 0) != AUDIT_DELIVERY_QUEUE_SCHEMA_VERSION:
                    raise ValueError("unsupported queue schema")
                encoded = base64.b64decode(
                    str(item.get("record_base64") or ""), validate=True
                )
                if not encoded.endswith(b"\n"):
                    raise ValueError("queued record is not newline terminated")
                if hashlib.sha256(encoded).hexdigest() != item.get("record_sha256"):
                    raise ValueError("queued record hash does not match")
                if len(encoded) > self.policy.maximum_event_bytes:
                    raise ValueError("queued record exceeds maximum event bytes")
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, binascii.Error) as exc:
                raise AuditStreamError("External audit delivery queue is corrupt") from exc
            records.append(encoded)
        return records

    def _rewrite_delivery_queue(self, records: list[bytes]) -> None:
        path = self.delivery_queue_path
        if not records:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise AuditStreamError("Unable to clear external audit delivery queue") from exc
            return
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            with temporary.open("wb") as stream:
                for record in records:
                    item = {
                        "schema_version": AUDIT_DELIVERY_QUEUE_SCHEMA_VERSION,
                        "record_sha256": hashlib.sha256(record).hexdigest(),
                        "record_base64": base64.b64encode(record).decode("ascii"),
                    }
                    stream.write(_canonical(item) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary.chmod(0o600)
            temporary.replace(path)
        except OSError as exc:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise AuditStreamError("Unable to update external audit delivery queue") from exc

    def _queue_external(self, encoded: bytes) -> None:
        records = self._read_delivery_queue()
        pending_bytes = sum(len(record) for record in records)
        if (
            len(records) >= self.policy.external_delivery_max_pending_records
            or pending_bytes + len(encoded) > self.policy.external_delivery_max_pending_bytes
        ):
            self._external_last_error = "AuditDeliveryQueueFull"
            raise AuditStreamError("external audit delivery queue is full")
        item = {
            "schema_version": AUDIT_DELIVERY_QUEUE_SCHEMA_VERSION,
            "record_sha256": hashlib.sha256(encoded).hexdigest(),
            "record_base64": base64.b64encode(encoded).decode("ascii"),
        }
        try:
            with self.delivery_queue_path.open("ab") as stream:
                stream.write(_canonical(item) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            self.delivery_queue_path.chmod(0o600)
        except OSError as exc:
            raise AuditStreamError("Unable to persist external audit delivery queue") from exc

    def _drain_external_queue(self) -> bool:
        sink = self._external_sink
        records = self._read_delivery_queue()
        if sink is None or not records:
            return not records
        remaining = list(records)
        while remaining:
            try:
                self._deliver_to_sink(remaining[0])
            except Exception as exc:
                self._external_failed_events += 1
                self._external_last_error = type(exc).__name__
                return False
            self._external_delivered_events += 1
            remaining.pop(0)
            self._rewrite_delivery_queue(remaining)
        return True

    def flush(self) -> None:
        with self._lock:
            if self._file is not None and not self._closed:
                self._flush_policy_loss()
                self._file.flush()
                self._flush_external()

    def _flush_external(self) -> None:
        sink = self._external_sink
        if sink is None:
            return
        if not self._drain_external_queue():
            if getattr(self.policy, "external_delivery_required", False):
                raise AuditStreamError("required external audit delivery remains unavailable")
            return
        try:
            sink.flush()
        except Exception as exc:
            self._external_failed_events += 1
            self._external_last_error = type(exc).__name__
            if getattr(self.policy, "external_delivery_required", False):
                raise AuditStreamError("required external audit flush failed") from exc

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                if self._file is not None:
                    self._flush_policy_loss()
                    self._file.flush()
                self._flush_external()
            finally:
                if self._file is not None:
                    self._file.close()
                self._closed = True
