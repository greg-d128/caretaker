from __future__ import annotations

import binascii
import hashlib
import hmac
import json
import math
import os
import random
import re
import sqlite3
import threading
import time
import base64
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Protocol
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
AUDIT_DELIVERY_AUTH_SCHEMA_VERSION = 2
AUDIT_DELIVERY_AUTH_LEGACY_SCHEMA_VERSION = 1
AUDIT_DELIVERY_AUTH_MAX_BYTES = 64 * 1024
AUDIT_SEGMENT_MANIFEST_SCHEMA_VERSION = 1
_EVENT_TYPE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_SEGMENT_FILE = re.compile(r"^.+\.segment-(\d{20})$")
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
    "AUDIT_DELIVERY_KEY_LIFECYCLE": _event_definition(
        description="Authenticated audit delivery key lifecycle changed.",
        minimum_priority=EvidencePriority.CRITICAL,
        required_fields=("scope.key_id", "outcome.state"),
        example={
            "key_id": "audit-2026-01",
            "state": "KEY_REVOKED",
            "authority_granted": False,
        },
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
    "ADAPTIVE_POLICY_TRANSITION": _event_definition(
        description="An adaptive policy transition changed lifecycle state.",
        minimum_priority=EvidencePriority.CRITICAL,
        required_fields=("scope.transition_id", "outcome.state"),
        example={
            "state": "PENDING",
            "transition_id": "transition-uuid",
            "policy_applied": True,
            "authority_granted": False,
        },
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
    "WORKER_POSTMORTEM_RECONCILED": _event_definition(
        description="Worker post-mortem evidence was reconciled for one failure scope.",
        minimum_priority=EvidencePriority.CRITICAL,
        required_fields=("scope.reconciliation_scope", "outcome.state"),
        example={
            "state": "COMBINED",
            "unique_packet_count": 2,
            "conflict": False,
            "authority_granted": False,
        },
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
    "WORKER_COMPARISON_ASSIGNMENT": _event_definition(
        description="A supervisor issued a bounded independent evidence assignment.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={
            "assignment_id": "assignment-uuid",
            "authority_packet_id": "packet-uuid",
            "state": "ISSUED",
            "authority_granted": False,
        },
    ),
    "WORKER_COMPARISON_RESULT": _event_definition(
        description="A registered comparison worker returned bounded evidence.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={
            "assignment_id": "assignment-uuid",
            "result_id": "result-uuid",
            "state": "ACCEPTED",
            "authority_granted": False,
        },
    ),
    "WORKER_COMPARISON_RECONCILED": _event_definition(
        description="The supervisor recorded a statistical comparison of worker evidence.",
        minimum_priority=EvidencePriority.CRITICAL,
        example={
            "comparison_id": "comparison-uuid",
            "state": "COMBINED",
            "outlier_count": 0,
            "authority_granted": False,
        },
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
    "INCIDENT_REPLAY_OUTCOME": _event_definition(
        description="An isolated historical Incident Capsule replay attempt completed or was rejected.",
        minimum_priority=EvidencePriority.IMPORTANT,
        required_fields=("scope.replay_scope", "outcome.state"),
        example={
            "scope": "all",
            "state": "PARTIAL",
            "fixture_count": 4,
            "completed_count": 3,
            "capsule_modified": False,
            "authority_granted": False,
        },
    ),
    "INCIDENT_COMMUNICATION_DRAFTED": _event_definition(
        description="A bounded Incident communication draft was generated.",
        minimum_priority=EvidencePriority.IMPORTANT,
        required_fields=("scope.communication_id", "outcome.state"),
        example={
            "communication_id": "communication-uuid",
            "state": "GENERATED",
            "delivery_authorized": False,
        },
    ),
    "INCIDENT_COMMUNICATION_REVIEWED": _event_definition(
        description="An operator recorded a review decision for an Incident communication draft.",
        minimum_priority=EvidencePriority.CRITICAL,
        required_fields=("scope.communication_id", "outcome.state"),
        example={
            "communication_id": "communication-uuid",
            "state": "APPROVED",
            "delivery_authorized": False,
        },
    ),
    "ADAPTIVE_AGGREGATION_RECONCILED": _event_definition(
        description="The supervisor reconciled a bounded batch of adaptive worker evidence.",
        minimum_priority=EvidencePriority.IMPORTANT,
        required_fields=("scope.aggregation_scope", "outcome.state"),
        example={
            "scope": "application",
            "state": "RECONCILED",
            "merged": 3,
            "rejected": 0,
            "authority_granted": False,
        },
    ),
    "ADAPTIVE_AGGREGATION_BACKPRESSURE": _event_definition(
        description="Adaptive worker evidence submission encountered policy-controlled backpressure.",
        minimum_priority=EvidencePriority.CRITICAL,
        required_fields=("scope.target_id", "outcome.state"),
        example={
            "target_id": "demo.target",
            "state": "INCIDENT_RECORDED",
            "action": "INCIDENT",
            "pending_records": 4,
            "authority_granted": False,
        },
    ),
    "ADAPTIVE_BATCH_REVALIDATED": _event_definition(
        description="A retained adaptive worker batch was reviewed against a policy fingerprint.",
        minimum_priority=EvidencePriority.IMPORTANT,
        required_fields=("scope.batch_id", "outcome.state"),
        example={
            "batch_id": "batch-uuid",
            "state": "VALIDATED",
            "aggregate_modified": False,
            "authority_granted": False,
        },
    ),
    "ADAPTIVE_POLICY_INSTALLATION": _event_definition(
        description="A deployment-owned installation of an accepted adaptive policy was attempted.",
        minimum_priority=EvidencePriority.CRITICAL,
        required_fields=("scope.acceptance_id", "outcome.state"),
        example={
            "acceptance_id": "acceptance-uuid",
            "installation_id": "installation-uuid",
            "state": "INSTALLED",
            "policy_mutated": False,
            "authority_granted": False,
        },
    ),
    "BEHAVIOR_COLLECTION_OUTCOME": _event_definition(
        description="A bounded behavior collection request completed or failed.",
        minimum_priority=EvidencePriority.IMPORTANT,
        required_fields=("scope.scope", "scope.subject", "outcome.state"),
        example={
            "scope": "function",
            "subject": "demo.target",
            "state": "CAPTURED",
            "observed_calls": 50,
            "authority_granted": False,
        },
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
    "SHADOW_EXECUTION_DECISION": _event_definition(
        description="An original-authoritative shadow execution produced bounded evidence.",
        minimum_priority=EvidencePriority.IMPORTANT,
        example={
            "state": "COMPLETED",
            "candidate_authoritative": False,
            "candidate_succeeded": True,
            "equivalent": True,
            "isolation_verified": True,
        },
    ),
    "REPAIR_ROLLOUT_ROUTING_DECISION": _event_definition(
        description="A deterministic policy-bound Repair rollout routing decision was recorded.",
        minimum_priority=EvidencePriority.IMPORTANT,
        required_fields=("scope.rollout_id", "scope.routing_scope", "outcome.state"),
        example={
            "state": "SELECTED",
            "stage": "canary",
            "strategy": "canary",
            "candidate_selected": True,
            "candidate_authoritative": True,
        },
    ),
    "REPAIR_ROLLOUT_EXECUTION_OUTCOME": _event_definition(
        description="The bounded outcome of a policy-bound Repair rollout invocation was recorded.",
        minimum_priority=EvidencePriority.IMPORTANT,
        required_fields=("scope.rollout_id", "scope.routing_scope", "outcome.state"),
        example={
            "state": "COMPLETED",
            "implementation": "candidate",
            "candidate_executed": True,
            "candidate_authoritative": True,
        },
    ),
    "REPAIR_CANDIDATE_OBSERVATION": _event_definition(
        description="A bounded authoritative Repair candidate observation was recorded.",
        minimum_priority=EvidencePriority.IMPORTANT,
        required_fields=("scope.target_id", "scope.candidate_id", "outcome.state"),
        example={
            "state": "ACCEPTANCE_OBSERVED",
            "succeeded": True,
            "candidate_state": "INITIALLY_VALIDATED",
            "mode": "canary",
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


def _audit_delivery_secret(secret: bytes) -> None:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise AuditStreamError(
            "authenticated audit delivery secret must contain at least 32 bytes"
        )


def _audit_delivery_auth_payload(
    *,
    sender_id: str,
    delivery_id: str,
    record_sha256: str,
    record_base64: str,
    key_id: str | None = None,
    schema_version: int = AUDIT_DELIVERY_AUTH_SCHEMA_VERSION,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": schema_version,
        "algorithm": "HMAC-SHA256",
        "delivery_id": delivery_id,
        "record_sha256": record_sha256,
        "record_base64": record_base64,
        "sender_id": sender_id,
    }
    if key_id is not None:
        payload["key_id"] = key_id
    return payload


def _authenticated_envelope_key_id(
    value: bytes | bytearray | str | Mapping[str, Any],
) -> str | None:
    try:
        if isinstance(value, Mapping):
            envelope = value
        elif isinstance(value, (bytes, bytearray)):
            envelope = json.loads(bytes(value).decode("utf-8"))
        elif isinstance(value, str):
            envelope = json.loads(value)
        else:
            return None
        if not isinstance(envelope, Mapping):
            return None
        if envelope.get("schema_version") == AUDIT_DELIVERY_AUTH_LEGACY_SCHEMA_VERSION:
            return "default"
        key_id = envelope.get("key_id")
        return key_id if isinstance(key_id, str) and key_id.strip() else None
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return None


class AuthenticatedAuditKeyring:
    """In-memory signing/verification key lifecycle for audit delivery.

    Key material is supplied by the deployment and never persisted by this
    class. Rotation adds a new key and can make it active; revocation removes
    a key from both signing and verification. A receiver can therefore reject
    retries signed by a revoked key while retaining accepted delivery IDs.
    """

    def __init__(
        self,
        keys: Mapping[str, bytes],
        *,
        active_key_id: str,
        revoked_key_ids: Iterable[str] = (),
        audit_event: Callable[..., Any] | None = None,
    ) -> None:
        if not isinstance(keys, Mapping) or not keys:
            raise AuditStreamError("authenticated audit keyring requires at least one key")
        self._keys: dict[str, bytes] = {}
        for key_id, secret in keys.items():
            self._validate_key_id(key_id)
            _audit_delivery_secret(secret)
            self._keys[str(key_id)] = secret
        self._revoked: set[str] = set()
        for value in revoked_key_ids:
            normalized = str(value)
            self._validate_key_id(normalized)
            self._revoked.add(normalized)
        if not self._revoked.issubset(self._keys):
            raise AuditStreamError("authenticated audit keyring contains an unknown revoked key")
        self._validate_key_id(active_key_id)
        if active_key_id not in self._keys or active_key_id in self._revoked:
            raise AuditStreamError("authenticated audit keyring active key is unavailable")
        self._active_key_id = str(active_key_id)
        if audit_event is not None and not callable(audit_event):
            raise AuditStreamError("authenticated audit lifecycle audit_event must be callable")
        self._audit_event = audit_event
        self._lock = threading.RLock()
        self._emit_lifecycle(
            "KEYRING_INITIALIZED",
            self._active_key_id,
            key_count=len(self._keys),
            revoked_key_count=len(self._revoked),
        )

    @staticmethod
    def _validate_key_id(key_id: str) -> None:
        if not isinstance(key_id, str) or not key_id.strip() or len(key_id) > 128:
            raise AuditStreamError("authenticated audit key_id is invalid")

    def add_key(self, key_id: str, secret: bytes, *, make_active: bool = False) -> None:
        self._validate_key_id(key_id)
        _audit_delivery_secret(secret)
        with self._lock:
            prior_active = self._active_key_id
            self._keys[key_id] = secret
            self._revoked.discard(key_id)
            if make_active:
                self._active_key_id = key_id
            self._emit_lifecycle(
                "KEY_ADDED",
                key_id,
                prior_active_key_id=prior_active,
                made_active=make_active,
                key_count=len(self._keys),
            )

    def set_active(self, key_id: str) -> None:
        with self._lock:
            self._validate_key_id(key_id)
            if key_id not in self._keys or key_id in self._revoked:
                raise AuditStreamError("authenticated audit key is unavailable")
            prior_active = self._active_key_id
            self._active_key_id = key_id
            self._emit_lifecycle(
                "ACTIVE_KEY_CHANGED",
                key_id,
                prior_active_key_id=prior_active,
            )

    def revoke(self, key_id: str) -> None:
        with self._lock:
            self._validate_key_id(key_id)
            if key_id not in self._keys:
                raise AuditStreamError("authenticated audit key is unknown")
            if key_id == self._active_key_id:
                raise AuditStreamError("authenticated audit active key must be rotated before revocation")
            self._revoked.add(key_id)
            self._emit_lifecycle("KEY_REVOKED", key_id)

    @property
    def active_key_id(self) -> str:
        with self._lock:
            return self._active_key_id

    @property
    def key_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._keys))

    @property
    def revoked_key_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._revoked))

    def _emit_lifecycle(self, state: str, key_id: str, **details: Any) -> None:
        if self._audit_event is None:
            return
        self._audit_event(
            "AUDIT_DELIVERY_KEY_LIFECYCLE",
            actor={"type": "deployment"},
            scope={"key_id": key_id},
            outcome={"state": state, "authority_granted": False},
            details={
                **details,
                "secret_material_logged": False,
            },
            priority=EvidencePriority.CRITICAL,
        )

    def _signing_key(self) -> tuple[str, bytes]:
        with self._lock:
            if self._active_key_id in self._revoked:
                raise AuditStreamError("authenticated audit active key is revoked")
            return self._active_key_id, self._keys[self._active_key_id]

    def _verification_key(self, key_id: str) -> bytes | None:
        with self._lock:
            if key_id in self._revoked:
                return None
            return self._keys.get(key_id)

    def sign_record(self, record: bytes, *, sender_id: str) -> bytes:
        key_id, secret = self._signing_key()
        return serialize_authenticated_audit_record(
            record, secret, sender_id=sender_id, key_id=key_id
        )

    def verify_record(
        self,
        value: bytes | bytearray | str | Mapping[str, Any],
        *,
        sender_id: str | None = None,
    ) -> dict[str, Any]:
        key_id = _authenticated_envelope_key_id(value)
        if key_id is None:
            return {"valid": False, "failures": ("authenticated audit key_id is missing",)}
        secret = self._verification_key(key_id)
        if secret is None:
            return {"valid": False, "failures": ("authenticated audit key_id is revoked or unknown",)}
        return verify_authenticated_audit_record(
            value, secret, sender_id=sender_id, key_id=key_id
        )

    def acknowledgement(
        self,
        *,
        delivery_id: str,
        record_sha256: str,
        key_id: str,
        acknowledged: bool = True,
    ) -> dict[str, Any]:
        secret = self._verification_key(key_id)
        if secret is None:
            raise AuditStreamError("authenticated audit acknowledgement key is unavailable")
        return create_authenticated_audit_acknowledgement(
            delivery_id=delivery_id,
            record_sha256=record_sha256,
            secret=secret,
            key_id=key_id,
            acknowledged=acknowledged,
        )

    def verify_acknowledgement(
        self,
        acknowledgement: Mapping[str, Any],
        *,
        delivery_id: str,
        record_sha256: str,
        key_id: str,
    ) -> bool:
        secret = self._verification_key(key_id)
        if secret is None:
            return False
        return verify_authenticated_audit_acknowledgement(
            acknowledgement,
            secret,
            delivery_id=delivery_id,
            record_sha256=record_sha256,
            key_id=key_id,
        )


def serialize_authenticated_audit_record(
    record: bytes,
    secret: bytes,
    *,
    sender_id: str,
    key_id: str = "default",
) -> bytes:
    """Create a signed, replay-identifiable audit delivery envelope.

    The local record remains the exact payload being authenticated. The
    deterministic delivery ID is its digest, allowing a receiving system to
    acknowledge a retry idempotently while rejecting a different record.
    """
    _audit_delivery_secret(secret)
    AuthenticatedAuditKeyring._validate_key_id(key_id)
    if not isinstance(record, bytes) or not record.endswith(b"\n"):
        raise AuditStreamError("authenticated audit record must be newline terminated bytes")
    if len(record) > AUDIT_DELIVERY_AUTH_MAX_BYTES:
        raise AuditStreamError(
            f"authenticated audit record exceeds {AUDIT_DELIVERY_AUTH_MAX_BYTES} bytes"
        )
    if not isinstance(sender_id, str) or not sender_id.strip() or len(sender_id) > 128:
        raise AuditStreamError("authenticated audit sender_id is invalid")
    sender_id = sender_id.strip()
    record_sha256 = hashlib.sha256(record).hexdigest()
    record_base64 = base64.b64encode(record).decode("ascii")
    payload = _audit_delivery_auth_payload(
        sender_id=sender_id,
        delivery_id=record_sha256,
        record_sha256=record_sha256,
        record_base64=record_base64,
        key_id=key_id,
    )
    envelope = {
        **payload,
        "signature": hmac.new(secret, _canonical(payload), hashlib.sha256).hexdigest(),
    }
    encoded = _canonical(envelope)
    if len(encoded) > AUDIT_DELIVERY_AUTH_MAX_BYTES:
        raise AuditStreamError(
            f"authenticated audit envelope exceeds {AUDIT_DELIVERY_AUTH_MAX_BYTES} bytes"
        )
    return encoded


def verify_authenticated_audit_record(
    value: bytes | bytearray | str | Mapping[str, Any],
    secret: bytes,
    *,
    sender_id: str | None = None,
    key_id: str | None = None,
) -> dict[str, Any]:
    """Verify an authenticated audit envelope without executing its record."""
    _audit_delivery_secret(secret)
    failures: list[str] = []
    try:
        if isinstance(value, Mapping):
            encoded = _canonical(value)
        elif isinstance(value, (bytes, bytearray)):
            encoded = bytes(value)
        elif isinstance(value, str):
            encoded = value.encode("utf-8")
        else:
            raise ValueError("transport value is not JSON data")
        if len(encoded) > AUDIT_DELIVERY_AUTH_MAX_BYTES:
            raise ValueError("authenticated audit envelope exceeds size bound")
        envelope = json.loads(encoded.decode("utf-8"))
        if not isinstance(envelope, Mapping):
            raise ValueError("authenticated audit envelope must be an object")
        legacy_fields = {
            "schema_version",
            "algorithm",
            "sender_id",
            "delivery_id",
            "record_sha256",
            "record_base64",
            "signature",
        }
        schema_version = envelope.get("schema_version")
        if schema_version == AUDIT_DELIVERY_AUTH_LEGACY_SCHEMA_VERSION:
            expected_fields = legacy_fields
            envelope_key_id = "default"
        elif schema_version == AUDIT_DELIVERY_AUTH_SCHEMA_VERSION:
            expected_fields = legacy_fields | {"key_id"}
            envelope_key_id = envelope.get("key_id")
            if not isinstance(envelope_key_id, str) or not envelope_key_id.strip():
                raise ValueError("authenticated audit key_id is invalid")
            AuthenticatedAuditKeyring._validate_key_id(envelope_key_id)
        else:
            raise ValueError("unsupported authenticated audit envelope schema")
        if set(envelope) != expected_fields:
            raise ValueError("authenticated audit envelope fields are invalid")
        if key_id is not None:
            AuthenticatedAuditKeyring._validate_key_id(key_id)
            if envelope_key_id != key_id:
                raise ValueError("authenticated audit key_id does not match")
        if envelope["algorithm"] != "HMAC-SHA256":
            raise ValueError("unsupported authenticated audit envelope algorithm")
        envelope_sender = envelope["sender_id"]
        if not isinstance(envelope_sender, str) or not envelope_sender.strip():
            raise ValueError("authenticated audit sender_id is invalid")
        if sender_id is not None and envelope_sender != sender_id:
            raise ValueError("authenticated audit sender_id does not match")
        delivery_id = envelope["delivery_id"]
        record_sha256 = envelope["record_sha256"]
        signature = envelope["signature"]
        record_base64 = envelope["record_base64"]
        if (
            not isinstance(delivery_id, str)
            or len(delivery_id) != 64
            or not isinstance(record_sha256, str)
            or len(record_sha256) != 64
            or delivery_id != record_sha256
            or not isinstance(record_base64, str)
            or not isinstance(signature, str)
            or len(signature) != 64
        ):
            raise ValueError("authenticated audit envelope identifiers are invalid")
        try:
            record = base64.b64decode(record_base64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("authenticated audit record encoding is invalid") from exc
        if not record.endswith(b"\n"):
            raise ValueError("authenticated audit record is not newline terminated")
        if len(record) > AUDIT_DELIVERY_AUTH_MAX_BYTES:
            raise ValueError("authenticated audit record exceeds size bound")
        if hashlib.sha256(record).hexdigest() != record_sha256:
            raise ValueError("authenticated audit record hash does not match")
        payload = _audit_delivery_auth_payload(
            sender_id=envelope_sender,
            delivery_id=delivery_id,
            record_sha256=record_sha256,
            record_base64=record_base64,
            key_id=None if schema_version == AUDIT_DELIVERY_AUTH_LEGACY_SCHEMA_VERSION else envelope_key_id,
            schema_version=int(schema_version),
        )
        expected_signature = hmac.new(secret, _canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("authenticated audit envelope signature is invalid")
        return {
            "valid": True,
            "sender_id": envelope_sender,
            "delivery_id": delivery_id,
            "record_sha256": record_sha256,
            "record": record,
            "key_id": envelope_key_id,
            "failures": (),
        }
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        failures.append(str(exc))
    return {"valid": False, "failures": tuple(failures)}


def _authenticated_audit_ack_payload(
    *,
    delivery_id: str,
    record_sha256: str,
    acknowledged: bool,
    key_id: str | None = None,
    schema_version: int = AUDIT_DELIVERY_AUTH_SCHEMA_VERSION,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": schema_version,
        "algorithm": "HMAC-SHA256",
        "delivery_id": delivery_id,
        "record_sha256": record_sha256,
        "acknowledged": acknowledged,
    }
    if key_id is not None:
        payload["key_id"] = key_id
    return payload


def create_authenticated_audit_acknowledgement(
    *,
    delivery_id: str,
    record_sha256: str,
    secret: bytes,
    acknowledged: bool = True,
    key_id: str = "default",
) -> dict[str, Any]:
    """Create a receiver acknowledgement bound to one signed delivery."""
    _audit_delivery_secret(secret)
    AuthenticatedAuditKeyring._validate_key_id(key_id)
    payload = _authenticated_audit_ack_payload(
        delivery_id=delivery_id,
        record_sha256=record_sha256,
        acknowledged=acknowledged,
        key_id=key_id,
    )
    return {
        **payload,
        "ack_signature": hmac.new(secret, _canonical(payload), hashlib.sha256).hexdigest(),
    }


def verify_authenticated_audit_acknowledgement(
    acknowledgement: Mapping[str, Any],
    secret: bytes,
    *,
    delivery_id: str,
    record_sha256: str,
    key_id: str | None = None,
) -> bool:
    """Verify an acknowledgement's authenticity and exact delivery binding."""
    try:
        _audit_delivery_secret(secret)
        if not isinstance(acknowledgement, Mapping):
            return False
        legacy_fields = {
            "schema_version",
            "algorithm",
            "delivery_id",
            "record_sha256",
            "acknowledged",
            "ack_signature",
        }
        schema_version = acknowledgement.get("schema_version")
        if schema_version == AUDIT_DELIVERY_AUTH_LEGACY_SCHEMA_VERSION:
            expected_fields = legacy_fields
            envelope_key_id = "default"
        elif schema_version == AUDIT_DELIVERY_AUTH_SCHEMA_VERSION:
            expected_fields = legacy_fields | {"key_id"}
            envelope_key_id = acknowledgement.get("key_id")
            if not isinstance(envelope_key_id, str) or not envelope_key_id.strip():
                return False
            AuthenticatedAuditKeyring._validate_key_id(envelope_key_id)
        else:
            return False
        if set(acknowledgement) != expected_fields:
            return False
        if key_id is not None:
            AuthenticatedAuditKeyring._validate_key_id(key_id)
            if envelope_key_id != key_id:
                return False
        payload = _authenticated_audit_ack_payload(
            delivery_id=delivery_id,
            record_sha256=record_sha256,
            acknowledged=acknowledgement["acknowledged"],
            key_id=None if schema_version == AUDIT_DELIVERY_AUTH_LEGACY_SCHEMA_VERSION else envelope_key_id,
            schema_version=int(schema_version),
        )
        if (
            acknowledgement["algorithm"] != "HMAC-SHA256"
            or acknowledgement["delivery_id"] != delivery_id
            or acknowledgement["record_sha256"] != record_sha256
            or acknowledgement["acknowledged"] is not True
            or not isinstance(acknowledgement["ack_signature"], str)
        ):
            return False
        expected = hmac.new(secret, _canonical(payload), hashlib.sha256).hexdigest()
        return hmac.compare_digest(acknowledgement["ack_signature"], expected)
    except (AuditStreamError, TypeError, ValueError):
        return False


class AuthenticatedAuditDeliverySink:
    """Wrap an output-only sink with signed delivery and acknowledgements.

    The wrapped transport must accept the authenticated envelope and return a
    signed acknowledgement created by ``create_authenticated_audit_acknowledgement``.
    Receivers should retain delivery IDs (the record digest) and treat exact
    retries as idempotent; this adapter never turns the stream into a command
    channel.
    """

    def __init__(
        self,
        transport: AuditDeliverySink,
        secret: bytes | AuthenticatedAuditKeyring,
        *,
        sender_id: str,
        sink_id: str | None = None,
    ) -> None:
        if isinstance(secret, AuthenticatedAuditKeyring):
            keyring = secret
            raw_secret = None
        else:
            _audit_delivery_secret(secret)
            keyring = None
            raw_secret = secret
        if not callable(getattr(transport, "deliver", None)) or not callable(
            getattr(transport, "flush", None)
        ):
            raise AuditStreamError("authenticated audit transport is not an output-only sink")
        if not isinstance(sender_id, str) or not sender_id.strip() or len(sender_id) > 128:
            raise AuditStreamError("authenticated audit sender_id is invalid")
        self.transport = transport
        self.keyring = keyring
        self.secret = raw_secret
        self.sender_id = sender_id.strip()
        self.sink_id = str(sink_id or getattr(transport, "sink_id", "authenticated-audit"))[:128]

    def deliver(self, record: bytes) -> Mapping[str, Any]:
        if self.keyring is not None:
            envelope = self.keyring.sign_record(record, sender_id=self.sender_id)
            key_id = _authenticated_envelope_key_id(envelope)
        else:
            envelope = serialize_authenticated_audit_record(
                record,
                self.secret,
                sender_id=self.sender_id,
            )
            key_id = "default"
        receipt = self.transport.deliver(envelope)
        record_sha256 = hashlib.sha256(record).hexdigest()
        if self.keyring is not None:
            valid_ack = key_id is not None and self.keyring.verify_acknowledgement(
                receipt if isinstance(receipt, Mapping) else {},
                delivery_id=record_sha256,
                record_sha256=record_sha256,
                key_id=key_id,
            )
        else:
            valid_ack = verify_authenticated_audit_acknowledgement(
                receipt if isinstance(receipt, Mapping) else {},
                self.secret,
                delivery_id=record_sha256,
                record_sha256=record_sha256,
            )
        if not valid_ack:
            raise AuditStreamError("authenticated audit acknowledgement is invalid")
        return {"acknowledged": True, "record_sha256": record_sha256}

    def flush(self) -> None:
        self.transport.flush()


class AuthenticatedAuditReplayStore:
    """Durable, bounded receiver-side replay/idempotency store.

    This is a reference receiver boundary for an external integration. It
    stores only authenticated delivery identity and digest, not audit payloads.
    Exact retries receive the same positive acknowledgement; a different
    record cannot reuse an accepted delivery ID. Capacity exhaustion returns a
    signed negative acknowledgement so the sender retains the record locally.
    """

    def __init__(self, path: str | Path, *, maximum_records: int = 100_000) -> None:
        if isinstance(maximum_records, bool) or not isinstance(maximum_records, int):
            raise AuditStreamError("audit replay maximum_records must be an integer")
        if maximum_records <= 0:
            raise AuditStreamError("audit replay maximum_records must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.maximum_records = maximum_records
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            str(self.path), timeout=5.0, isolation_level=None, check_same_thread=False
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_delivery_replay (
                sender_id TEXT NOT NULL,
                delivery_id TEXT NOT NULL,
                record_sha256 TEXT NOT NULL,
                received_at TEXT NOT NULL,
                PRIMARY KEY (sender_id, delivery_id)
            )
            """
        )

    def receive(
        self,
        envelope: bytes | bytearray | str | Mapping[str, Any],
        secret: bytes | AuthenticatedAuditKeyring,
        *,
        sender_id: str | None = None,
    ) -> Mapping[str, Any]:
        """Verify and remember one envelope, returning a signed acknowledgement."""
        if isinstance(secret, AuthenticatedAuditKeyring):
            verification = secret.verify_record(envelope, sender_id=sender_id)
        else:
            verification = verify_authenticated_audit_record(
                envelope,
                secret,
                sender_id=sender_id,
            )
        if not verification.get("valid"):
            return {
                "acknowledged": False,
                "error": "authenticated audit envelope rejected",
            }
        resolved_sender = str(verification["sender_id"])
        delivery_id = str(verification["delivery_id"])
        record_sha256 = str(verification["record_sha256"])
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                existing = self._connection.execute(
                    "SELECT record_sha256 FROM audit_delivery_replay "
                    "WHERE sender_id = ? AND delivery_id = ?",
                    (resolved_sender, delivery_id),
                ).fetchone()
                if existing is not None:
                    accepted = str(existing[0]) == record_sha256
                else:
                    count = int(
                        self._connection.execute(
                            "SELECT COUNT(*) FROM audit_delivery_replay"
                        ).fetchone()[0]
                    )
                    accepted = count < self.maximum_records
                    if accepted:
                        self._connection.execute(
                            "INSERT INTO audit_delivery_replay "
                            "(sender_id, delivery_id, record_sha256, received_at) "
                            "VALUES (?, ?, ?, ?)",
                            (
                                resolved_sender,
                                delivery_id,
                                record_sha256,
                                datetime.now(timezone.utc).isoformat(),
                            ),
                        )
                self._connection.execute("COMMIT")
            except sqlite3.Error:
                self._connection.execute("ROLLBACK")
                accepted = False
        key_id = str(verification.get("key_id") or "default")
        if isinstance(secret, AuthenticatedAuditKeyring):
            return secret.acknowledgement(
                delivery_id=delivery_id,
                record_sha256=record_sha256,
                key_id=key_id,
                acknowledged=accepted,
            )
        return create_authenticated_audit_acknowledgement(
            delivery_id=delivery_id,
            record_sha256=record_sha256,
            secret=secret,
            acknowledged=accepted,
        )

    def count(self) -> int:
        with self._lock:
            return int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM audit_delivery_replay"
                ).fetchone()[0]
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()


def _audit_manifest_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.manifest.json")


def _audit_segment_path(path: Path, index: int) -> Path:
    return path.with_name(f"{path.name}.segment-{index:020d}")


def _write_atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("wb") as stream:
            stream.write(_canonical(value))
            stream.write(b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        temporary.replace(path)
    except OSError as exc:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise AuditStreamError(f"Unable to persist audit segment manifest: {exc}") from exc


def _read_audit_manifest(path: Path, stream_path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditStreamError("Audit segment manifest is unreadable") from exc
    if not isinstance(value, Mapping):
        raise AuditStreamError("Audit segment manifest is not an object")
    try:
        schema_version = int(value.get("schema_version") or 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise AuditStreamError("Audit segment manifest schema is invalid") from exc
    if schema_version != AUDIT_SEGMENT_MANIFEST_SCHEMA_VERSION:
        raise AuditStreamError("Unsupported audit segment manifest schema")
    if value.get("stream_file") != stream_path.name:
        raise AuditStreamError("Audit segment manifest stream filename does not match")
    if value.get("active_file") != stream_path.name:
        raise AuditStreamError("Audit segment manifest active filename does not match")
    if not isinstance(value.get("hash_chain"), bool):
        raise AuditStreamError("Audit segment manifest hash-chain mode is invalid")
    if "active_previous_segment_hash" not in value:
        raise AuditStreamError("Audit segment manifest is missing active previous hash")
    active_previous = value["active_previous_segment_hash"]
    if active_previous is not None and (
        not isinstance(active_previous, str)
        or not re.fullmatch(r"[0-9a-f]{64}", active_previous)
    ):
        raise AuditStreamError("Audit segment manifest active previous hash is invalid")
    segments = value.get("segments")
    if not isinstance(segments, list):
        raise AuditStreamError("Audit segment manifest segments are invalid")
    if len(segments) > 100_000:
        raise AuditStreamError("Audit segment manifest contains too many segments")
    for expected_index, segment in enumerate(segments):
        if not isinstance(segment, Mapping):
            raise AuditStreamError("Audit segment manifest contains an invalid segment")
        if segment.get("segment_id") != f"segment-{expected_index:020d}":
            raise AuditStreamError("Audit segment manifest IDs are not contiguous")
        file_name = segment.get("file_name")
        if not isinstance(file_name, str) or _SEGMENT_FILE.fullmatch(file_name) is None:
            raise AuditStreamError("Audit segment manifest contains an unsafe filename")
        if file_name != _audit_segment_path(stream_path, expected_index).name:
            raise AuditStreamError("Audit segment manifest filename does not match its index")
        for field_name in (
            "content_sha256", "previous_segment_hash", "first_sequence",
            "last_sequence", "record_count", "closed_at",
        ):
            if field_name not in segment:
                raise AuditStreamError(f"Audit segment manifest is missing {field_name}")
        if not isinstance(segment["closed_at"], str) or not segment["closed_at"].strip():
            raise AuditStreamError("Audit segment manifest close time is invalid")
        for field_name in ("first_sequence", "last_sequence", "record_count"):
            if (
                isinstance(segment[field_name], bool)
                or not isinstance(segment[field_name], int)
                or segment[field_name] <= 0
            ):
                raise AuditStreamError(f"Audit segment manifest {field_name} is invalid")
        if segment["first_sequence"] > segment["last_sequence"]:
            raise AuditStreamError("Audit segment manifest sequence range is invalid")
        if segment["record_count"] != segment["last_sequence"] - segment["first_sequence"] + 1:
            raise AuditStreamError("Audit segment manifest record count is invalid")
        if (
            not isinstance(segment["content_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", segment["content_sha256"])
        ):
            raise AuditStreamError("Audit segment manifest content hash is invalid")
        previous = segment["previous_segment_hash"]
        if previous is not None and (
            not isinstance(previous, str) or not re.fullmatch(r"[0-9a-f]{64}", previous)
        ):
            raise AuditStreamError("Audit segment manifest previous hash is invalid")
    return dict(value)


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
    manifest_path = _audit_manifest_path(stream_path)
    source_paths: list[tuple[str, Path, Mapping[str, Any] | None]] = []
    manifest: dict[str, Any] | None = None
    if manifest_path.exists():
        try:
            manifest = _read_audit_manifest(manifest_path, stream_path)
        except AuditStreamError as exc:
            errors.append(str(exc))
            return report
        if manifest["hash_chain"] is not hash_chain:
            errors.append("audit segment manifest hash-chain mode does not match policy")
            hash_failures += 1
        prior_segment_hash: str | None = None
        listed_segment_names: set[str] = set()
        for segment in manifest["segments"]:
            segment_path = stream_path.parent / str(segment["file_name"])
            listed_segment_names.add(segment_path.name)
            if segment["previous_segment_hash"] != prior_segment_hash:
                errors.append(
                    f"{segment_path.name}: previous-segment hash does not match manifest"
                )
                hash_failures += 1
            try:
                actual_segment_hash = hashlib.sha256(segment_path.read_bytes()).hexdigest()
            except OSError as exc:
                errors.append(f"{segment_path.name}: audit segment cannot be read: {exc}")
                hash_failures += 1
                actual_segment_hash = None
            if actual_segment_hash != segment["content_sha256"]:
                errors.append(f"{segment_path.name}: audit segment content hash does not match")
                hash_failures += 1
            source_paths.append((segment_path.name, segment_path, segment))
            prior_segment_hash = str(segment["content_sha256"])
        if manifest["active_previous_segment_hash"] != prior_segment_hash:
            errors.append("audit segment manifest active previous hash does not match")
            hash_failures += 1
        for extra in stream_path.parent.glob(f"{stream_path.name}.segment-*"):
            if extra.name not in listed_segment_names:
                errors.append(f"unlisted audit segment: {extra.name}")
                hash_failures += 1
    elif any(stream_path.parent.glob(f"{stream_path.name}.segment-*")):
        errors.append("audit segments exist without a segment manifest")
        hash_failures += 1
    source_paths.append((stream_path.name, stream_path, None))
    if not stream_path.is_file():
        errors.append("audit stream does not exist")
        hash_failures += 1

    for label, source_path, descriptor in source_paths:
        if not source_path.is_file():
            hash_failures += 1
            continue
        file_event_count = 0
        file_first_sequence: int | None = None
        file_last_sequence: int | None = None
        try:
            stream = source_path.open("rb")
        except OSError as exc:
            errors.append(f"{label}: audit stream cannot be read: {exc}")
            hash_failures += 1
            continue
        with stream:
            for line_number, line in enumerate(stream, start=1):
                location = f"{label} line {line_number}"
                if len(line) > maximum_event_bytes:
                    errors.append(f"{location}: audit record exceeds maximum_event_bytes")
                    hash_failures += 1
                    continue
                if not line.endswith(b"\n"):
                    errors.append(f"{location}: incomplete final audit record")
                    hash_failures += 1
                    break
                try:
                    event = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    errors.append(f"{location}: malformed audit record: {exc}")
                    hash_failures += 1
                    continue
                if not isinstance(event, Mapping):
                    errors.append(f"{location}: audit record is not an object")
                    hash_failures += 1
                    continue
                sequence = event.get("stream_sequence")
                if not isinstance(sequence, int) or sequence != previous_sequence + 1:
                    errors.append(f"{location}: audit stream sequence is not contiguous")
                    hash_failures += 1
                else:
                    previous_sequence = sequence
                    file_event_count += 1
                    file_first_sequence = sequence if file_first_sequence is None else file_first_sequence
                    file_last_sequence = sequence
                    report["event_count"] += 1
                    if report["first_sequence"] is None:
                        report["first_sequence"] = sequence
                    report["last_sequence"] = sequence
                integrity = event.get("integrity")
                if not isinstance(integrity, Mapping):
                    errors.append(f"{location}: audit record has no integrity object")
                    hash_failures += 1
                    continue
                if "hash_chain" in integrity and integrity.get("hash_chain") is not hash_chain:
                    errors.append(f"{location}: audit hash-chain mode does not match policy")
                    hash_failures += 1
                if hash_chain and integrity.get("previous_event_hash") != previous_hash:
                    errors.append(f"{location}: previous-event hash does not match")
                    hash_failures += 1
                body = dict(event)
                body.pop("integrity", None)
                expected_content = hashlib.sha256(_canonical(body)).hexdigest()
                if integrity.get("content_sha256") != expected_content:
                    errors.append(f"{location}: audit record content hash does not match")
                    hash_failures += 1
                else:
                    previous_hash = expected_content

                signature_value = integrity.get("artifact_signature")
                if not isinstance(signature_value, Mapping):
                    report["unsigned_event_count"] += 1
                    if require_signatures:
                        signature_failures += 1
                        errors.append(f"{location}: required audit signature is missing")
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
                    errors.append(f"{location}: malformed audit signature: {exc}")
                    continue
                fingerprint = artifact.public_key_fingerprint
                key = keys.get(fingerprint) if fingerprint else None
                if key is None:
                    signature_unavailable += 1
                    if require_signatures:
                        signature_failures += 1
                        errors.append(f"{location}: public key is unavailable")
                    continue
                if isinstance(key, str):
                    try:
                        key = base64.b64decode(key)
                    except Exception as exc:
                        signature_failures += 1
                        errors.append(f"{location}: public key is malformed: {exc}")
                        continue
                try:
                    verified = verify_signed_artifact(artifact, key)
                except Exception as exc:
                    verified = False
                    errors.append(f"{location}: signature verification failed: {exc}")
                if not verified:
                    signature_failures += 1
                    errors.append(f"{location}: audit signature is invalid")
        if descriptor is not None:
            if file_event_count != descriptor["record_count"]:
                errors.append(f"{label}: audit segment record count does not match manifest")
                hash_failures += 1
            if file_first_sequence != descriptor["first_sequence"]:
                errors.append(f"{label}: audit segment first sequence does not match manifest")
                hash_failures += 1
            if file_last_sequence != descriptor["last_sequence"]:
                errors.append(f"{label}: audit segment last sequence does not match manifest")
                hash_failures += 1

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
        self.manifest_path = _audit_manifest_path(self.path)
        self.delivery_queue_path = self.path.with_name(
            f"{self.path.name}.delivery.queue"
        )
        self._lock = threading.RLock()
        self._closed = False
        self._sequence = 0
        self._previous_hash: str | None = None
        self._segment_index = 0
        self._segment_descriptors: list[dict[str, Any]] = []
        self._segment_first_sequence: int | None = None
        self._segment_record_count = 0
        self._segment_opened_at = datetime.now(timezone.utc)
        self._rotating = False
        self._recovered_truncated_bytes = 0
        self._pending_loss_count = 0
        self._pending_loss_priorities: dict[str, int] = {}
        self._external_sink = external_sink
        self._external_delivered_events = 0
        self._external_failed_events = 0
        self._external_last_error: str | None = None
        self._external_delivery_degraded = False
        self._last_delivery_state: str | None = None
        self._emitting_delivery_status = False
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
        self._last_delivery_state = self._delivery_state()

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
            state = self._delivery_state(pending_records=pending_records)
            sink_id = self._sink_id()
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

    def _sink_id(self) -> str | None:
        sink = self._external_sink
        if sink is None:
            return None
        return str(
            getattr(sink, "sink_id", None) or type(sink).__name__
        )[:128]

    def _delivery_state(self, *, pending_records: list[bytes] | None = None) -> str:
        if self._external_sink is None:
            return "LOCAL_ONLY"
        if pending_records is None:
            pending_records = self._read_delivery_queue()
        return "DEGRADED" if self._external_delivery_degraded or pending_records else "ACTIVE"

    def _emit_delivery_status_transition(self, state: str) -> None:
        """Persist and queue one delivery-state transition without recursion.

        Delivery status is itself audit evidence. When delivery is already
        degraded, the transition is queued directly instead of attempting the
        failed sink again; otherwise the status record could recursively create
        more failure records and obscure the original delivery failure.
        """
        if self._emitting_delivery_status or self._closed or self._file is None:
            return
        if state == self._last_delivery_state:
            return
        self._emitting_delivery_status = True
        try:
            details = {
                "sink_id": self._sink_id() or "local-file",
                "state": state,
                "external_delivery": self._external_sink is not None,
                "acknowledgement_required": bool(
                    getattr(self.policy, "external_delivery_require_ack", False)
                ),
                "failed_events": self._external_failed_events,
                "pending_records": len(self._read_delivery_queue()),
                "last_error_type": self._external_last_error,
            }
            event = self._write_event(
                "AUDIT_DELIVERY_STATUS",
                actor={"type": "system", "id": "audit-delivery"},
                outcome={"state": state},
                details=details,
                priority=EvidencePriority.IMPORTANT,
                deliver_external=False,
            )
            encoded = _canonical(event) + b"\n"
            try:
                if state == "DEGRADED":
                    self._queue_external(encoded)
                else:
                    self._deliver_to_sink(encoded)
                    self._external_delivered_events += 1
            except Exception as exc:
                self._external_failed_events += 1
                self._external_last_error = type(exc).__name__
                try:
                    self._queue_external(encoded)
                except Exception:
                    # The local status record remains authoritative even when
                    # the bounded retry queue is exhausted.
                    pass
                if getattr(self.policy, "external_delivery_required", False):
                    raise AuditStreamError(
                        "required external audit delivery status could not be delivered"
                    ) from exc
            self._last_delivery_state = self._delivery_state()
        finally:
            self._emitting_delivery_status = False

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
        for name in ("maximum_segment_bytes", "maximum_segment_seconds"):
            value = getattr(self.policy, name, None)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or value <= 0
            ):
                raise AuditStreamError(
                    f"logging.audit.{name} must be greater than zero when configured"
                )
        maximum_event_bytes = getattr(self.policy, "maximum_event_bytes", 0)
        maximum_segment_bytes = getattr(self.policy, "maximum_segment_bytes", None)
        if maximum_segment_bytes is not None and maximum_segment_bytes < maximum_event_bytes:
            raise AuditStreamError(
                "logging.audit.maximum_segment_bytes cannot be less than maximum_event_bytes"
            )

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

    def _scan_existing_file(
        self,
        path: Path,
        *,
        previous_sequence: int,
        previous_hash: str | None,
        allow_incomplete_tail: bool,
    ) -> tuple[int, int, str | None, int | None, int]:
        """Validate one audit file and return its recovery boundary."""
        last_valid_offset = 0
        last_sequence = previous_sequence
        last_hash = previous_hash
        first_sequence: int | None = None
        record_count = 0
        with path.open("rb") as stream:
            while True:
                line_start = stream.tell()
                line = stream.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    if not allow_incomplete_tail:
                        raise AuditStreamError(
                            f"Incomplete audit record in closed segment at byte {line_start}"
                        )
                    break
                try:
                    event = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise AuditStreamError(
                        f"Malformed complete audit record at byte {line_start}"
                    ) from exc
                self._validate_existing(event, last_sequence, last_hash)
                sequence = int(event["stream_sequence"])
                if first_sequence is None:
                    first_sequence = sequence
                record_count += 1
                last_valid_offset = stream.tell()
                last_sequence = sequence
                last_hash = str(event["integrity"]["content_sha256"])
        return last_valid_offset, last_sequence, last_hash, first_sequence, record_count

    def _write_segment_manifest(self) -> None:
        previous_hash = (
            self._segment_descriptors[-1]["content_sha256"]
            if self._segment_descriptors
            else None
        )
        _write_atomic_json(
            self.manifest_path,
            {
                "schema_version": AUDIT_SEGMENT_MANIFEST_SCHEMA_VERSION,
                "stream_file": self.path.name,
                "active_file": self.path.name,
                "hash_chain": bool(self.policy.hash_chain),
                "active_previous_segment_hash": previous_hash,
                "segments": [dict(item) for item in self._segment_descriptors],
            },
        )

    def _describe_closed_segment(self, path: Path, index: int) -> dict[str, Any]:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise AuditStreamError("Unable to read closed audit segment") from exc
        if not raw or not raw.endswith(b"\n"):
            raise AuditStreamError("Closed audit segment is empty or incomplete")
        events: list[Mapping[str, Any]] = []
        for line in raw.splitlines():
            try:
                event = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise AuditStreamError("Closed audit segment is malformed") from exc
            if not isinstance(event, Mapping):
                raise AuditStreamError("Closed audit segment contains a non-object record")
            events.append(event)
        first_sequence = events[0].get("stream_sequence")
        last_sequence = events[-1].get("stream_sequence")
        if (
            isinstance(first_sequence, bool)
            or not isinstance(first_sequence, int)
            or isinstance(last_sequence, bool)
            or not isinstance(last_sequence, int)
            or first_sequence <= 0
            or last_sequence < first_sequence
            or len(events) != last_sequence - first_sequence + 1
        ):
            raise AuditStreamError("Closed audit segment sequence range is invalid")
        previous_segment_hash = (
            self._segment_descriptors[-1]["content_sha256"]
            if self._segment_descriptors
            else None
        )
        return {
            "segment_id": f"segment-{index:020d}",
            "file_name": path.name,
            "content_sha256": hashlib.sha256(raw).hexdigest(),
            "previous_segment_hash": previous_segment_hash,
            "first_sequence": first_sequence,
            "last_sequence": last_sequence,
            "record_count": len(events),
            "closed_at": datetime.now(timezone.utc).isoformat(),
        }

    def _should_rotate(self) -> bool:
        if self._rotating or self._file is None or self._segment_first_sequence is None:
            return False
        maximum_bytes = getattr(self.policy, "maximum_segment_bytes", None)
        if maximum_bytes is not None:
            try:
                if self.path.stat().st_size >= int(maximum_bytes):
                    return True
            except OSError as exc:
                raise AuditStreamError("Unable to inspect audit segment size") from exc
        maximum_seconds = getattr(self.policy, "maximum_segment_seconds", None)
        if maximum_seconds is not None:
            age = (datetime.now(timezone.utc) - self._segment_opened_at).total_seconds()
            if age >= float(maximum_seconds):
                return True
        return False

    def _rotate_segment(self) -> dict[str, Any] | None:
        if self._file is None or self._segment_first_sequence is None:
            return None
        self._file.flush()
        os.fsync(self._file.fileno())
        self._file.close()
        self._file = None
        segment_path = _audit_segment_path(self.path, self._segment_index)
        if segment_path.exists():
            raise AuditStreamError("Audit segment destination already exists")
        try:
            self.path.replace(segment_path)
        except OSError as exc:
            raise AuditStreamError("Unable to close audit segment") from exc
        descriptor = self._describe_closed_segment(segment_path, self._segment_index)
        self._segment_descriptors.append(descriptor)
        self._segment_index += 1
        self._segment_first_sequence = None
        self._segment_record_count = 0
        self._segment_opened_at = datetime.now(timezone.utc)
        try:
            self._file = self.path.open("ab", buffering=0)
            self._write_segment_manifest()
        except OSError as exc:
            raise AuditStreamError("Unable to open new audit segment") from exc
        self._rotating = True
        try:
            return self._write_event(
                "AUDIT_STREAM_ROTATED",
                details={
                    "segment_id": descriptor["segment_id"],
                    "file_name": descriptor["file_name"],
                    "content_sha256": descriptor["content_sha256"],
                    "first_sequence": descriptor["first_sequence"],
                    "last_sequence": descriptor["last_sequence"],
                    "record_count": descriptor["record_count"],
                    "manifest_file": self.manifest_path.name,
                    "authority_granted": False,
                },
                priority=EvidencePriority.IMPORTANT,
            )
        finally:
            self._rotating = False

    def rotate(self) -> dict[str, Any] | None:
        """Close the current segment and begin a manifest-backed segment."""
        with self._lock:
            if self._closed or self._file is None:
                return None
            return self._rotate_segment()

    def _recover_existing(self) -> None:
        if self.manifest_path.exists():
            manifest = _read_audit_manifest(self.manifest_path, self.path)
            if manifest["hash_chain"] is not bool(self.policy.hash_chain):
                raise AuditStreamError(
                    "Audit segment manifest hash-chain mode does not match policy"
                )
            self._segment_descriptors = [dict(item) for item in manifest["segments"]]
            previous_sequence = 0
            previous_hash: str | None = None
            previous_segment_hash: str | None = None
            for descriptor in self._segment_descriptors:
                segment_path = self.path.parent / str(descriptor["file_name"])
                if descriptor["previous_segment_hash"] != previous_segment_hash:
                    raise AuditStreamError("Audit segment manifest chain is not contiguous")
                try:
                    actual_hash = hashlib.sha256(segment_path.read_bytes()).hexdigest()
                except OSError as exc:
                    raise AuditStreamError(
                        "Audit segment cannot be read during recovery"
                    ) from exc
                if actual_hash != descriptor["content_sha256"]:
                    raise AuditStreamError("Audit segment content hash does not match manifest")
                _, previous_sequence, previous_hash, first, count = self._scan_existing_file(
                    segment_path,
                    previous_sequence=previous_sequence,
                    previous_hash=previous_hash,
                    allow_incomplete_tail=False,
                )
                if (
                    first != descriptor["first_sequence"]
                    or previous_sequence != descriptor["last_sequence"]
                    or count != descriptor["record_count"]
                ):
                    raise AuditStreamError("Audit segment records do not match manifest")
                previous_segment_hash = actual_hash
            if manifest["active_previous_segment_hash"] != previous_segment_hash:
                raise AuditStreamError("Audit active segment predecessor does not match manifest")
            self._segment_index = len(self._segment_descriptors)
            self._sequence = previous_sequence
            self._previous_hash = previous_hash
        elif any(self.path.parent.glob(f"{self.path.name}.segment-*")):
            raise AuditStreamError("Audit segments exist without a segment manifest")

        if not self.path.exists():
            if self._segment_descriptors:
                raise AuditStreamError("Audit active segment is missing")
            return
        (
            last_valid_offset,
            last_sequence,
            last_hash,
            first_sequence,
            record_count,
        ) = self._scan_existing_file(
            self.path,
            previous_sequence=self._sequence,
            previous_hash=self._previous_hash,
            allow_incomplete_tail=True,
        )
        file_size = self.path.stat().st_size
        if last_valid_offset != file_size:
            self._recovered_truncated_bytes = file_size - last_valid_offset
            with self.path.open("r+b") as stream:
                stream.truncate(last_valid_offset)
        self._sequence = last_sequence
        self._previous_hash = last_hash
        self._segment_first_sequence = first_sequence
        self._segment_record_count = record_count
        try:
            self._segment_opened_at = datetime.fromtimestamp(
                self.path.stat().st_mtime, timezone.utc
            )
        except OSError:
            self._segment_opened_at = datetime.now(timezone.utc)

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
        for field_name in ("maximum_segment_bytes", "maximum_segment_seconds"):
            if getattr(policy, field_name) != getattr(self.policy, field_name):
                warnings.append(
                    f"logging.audit.{field_name} is run-bound; the existing segment bound remains active"
                )
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
        deliver_external: bool = True,
    ) -> dict[str, Any]:
        """Write one already-validated retained event while holding the lock."""
        if self._closed or self._file is None:
            raise AuditStreamError("Audit stream is not open")
        with self._lock:
            if (
                event_type != "AUDIT_STREAM_ROTATED"
                and not self._rotating
                and self._should_rotate()
            ):
                self._rotate_segment()
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
            if self._segment_first_sequence is None:
                self._segment_first_sequence = self._sequence
            self._segment_record_count += 1
            if deliver_external:
                self._deliver_external(encoded)
            return event

    def _deliver_external(self, encoded: bytes) -> None:
        sink = self._external_sink
        if sink is None:
            return
        previous_state = self._delivery_state()
        if not self._drain_external_queue():
            try:
                self._queue_external(encoded)
            except Exception:
                self._emit_delivery_status_transition(self._delivery_state())
                raise
            self._emit_delivery_status_transition(self._delivery_state())
            if getattr(self.policy, "external_delivery_required", False):
                raise AuditStreamError(
                    "required external audit delivery remains unavailable"
                )
            return
        self._external_delivery_degraded = False
        try:
            self._deliver_to_sink(encoded)
        except Exception as exc:
            self._external_failed_events += 1
            self._external_last_error = type(exc).__name__
            self._external_delivery_degraded = True
            self._queue_external(encoded)
            self._emit_delivery_status_transition(self._delivery_state())
            if getattr(self.policy, "external_delivery_required", False):
                raise AuditStreamError(
                    "required external audit delivery failed after local persistence"
                ) from exc
            return
        self._external_delivered_events += 1
        current_state = self._delivery_state()
        if current_state != previous_state:
            self._emit_delivery_status_transition(current_state)

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
                self._external_delivery_degraded = True
                return False
            self._external_delivered_events += 1
            remaining.pop(0)
            self._rewrite_delivery_queue(remaining)
        self._external_delivery_degraded = False
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
        previous_state = self._delivery_state()
        if not self._drain_external_queue():
            self._emit_delivery_status_transition(self._delivery_state())
            if getattr(self.policy, "external_delivery_required", False):
                raise AuditStreamError("required external audit delivery remains unavailable")
            return
        self._external_delivery_degraded = False
        try:
            sink.flush()
        except Exception as exc:
            self._external_failed_events += 1
            self._external_last_error = type(exc).__name__
            self._external_delivery_degraded = True
            self._emit_delivery_status_transition(self._delivery_state())
            if getattr(self.policy, "external_delivery_required", False):
                raise AuditStreamError("required external audit flush failed") from exc
            return
        current_state = self._delivery_state()
        if current_state != previous_state:
            self._emit_delivery_status_transition(current_state)

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
