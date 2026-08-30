"""Fail-safe inspection of persisted Repair work after a process restart.

The current application-scoped recovery contract does not reactivate an in-memory
replacement. This module produces an explicit recovery plan for incomplete
attempts so an operator or future supervisor can reconcile them without treating
an interrupted transaction as successful work.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import Enum, auto
import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

from .domain import RepairAttemptOutcome, RepairAttemptStage, utcnow


RECOVERY_PLAN_SCHEMA_VERSION = 1


class RecoveryAction(Enum):
    """Policy-selected response vocabulary for interrupted Repair work."""

    CONTINUE_DEGRADED = auto()
    GENERATE_INCIDENT = auto()
    REPLACE_WORKER = auto()
    STOP_APPLICATION = auto()
    ROLLBACK_TO_DEPLOYED_CODE = auto()


@dataclass(frozen=True, slots=True)
class RepairRecoveryPolicy:
    """Policy controls for restart and failed-worker recovery.

    The action vocabulary is broader than the current executor. Until worker
    replacement and application shutdown orchestration are implemented, the
    recovery planner remains fail-safe and never performs those actions.
    """

    enabled: bool = True
    interrupted_transaction_action: RecoveryAction = RecoveryAction.ROLLBACK_TO_DEPLOYED_CODE
    worker_failure_action: RecoveryAction = RecoveryAction.GENERATE_INCIDENT
    critical_evidence_action: RecoveryAction = RecoveryAction.STOP_APPLICATION
    approval_packet_ttl_seconds: int = 3600
    suggested_change_packet_ttl_seconds: int = 60
    clock_skew_tolerance_seconds: float = 30.0
    require_full_worker_postmortem_for_critical_evidence: bool = True
    allow_candidate_reactivation_after_restart: bool = False


@dataclass(frozen=True, slots=True)
class RecoveryAuthorityPacket:
    """Immutable supervisor-issued worker state, not an authority grant."""

    packet_id: UUID
    issuer_role: str
    target_id: str
    generation_id: str
    code_hash: str
    policy_fingerprint: str
    authority_policy_generation: str
    authority_policy_fingerprint: str
    issued_at: datetime
    expires_at: datetime
    capabilities: tuple[str, ...]
    policy_state: Mapping[str, Any]
    approvals: Mapping[str, Any]
    content_sha256: str
    schema_version: int = 1


def _packet_payload(packet: RecoveryAuthorityPacket) -> dict[str, Any]:
    return {
        "packet_id": str(packet.packet_id),
        "issuer_role": packet.issuer_role,
        "target_id": packet.target_id,
        "generation_id": packet.generation_id,
        "code_hash": packet.code_hash,
        "policy_fingerprint": packet.policy_fingerprint,
        "authority_policy_generation": packet.authority_policy_generation,
        "authority_policy_fingerprint": packet.authority_policy_fingerprint,
        "issued_at": packet.issued_at.isoformat(),
        "expires_at": packet.expires_at.isoformat(),
        "capabilities": list(packet.capabilities),
        "policy_state": packet.policy_state,
        "approvals": packet.approvals,
        "schema_version": packet.schema_version,
    }


def _packet_hash(packet: RecoveryAuthorityPacket) -> str:
    encoded = json.dumps(
        _packet_payload(packet),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def create_recovery_authority_packet(
    *,
    target_id: str,
    generation_id: str,
    code_hash: str,
    policy_fingerprint: str,
    authority_policy_generation: str,
    authority_policy_fingerprint: str,
    capabilities: tuple[str, ...] = (),
    policy_state: Mapping[str, Any] | None = None,
    approvals: Mapping[str, Any] | None = None,
    supervisor_time: datetime,
    suggested_change: bool = False,
    policy: RepairRecoveryPolicy | None = None,
) -> RecoveryAuthorityPacket:
    """Create a bounded state packet whose authority remains external to it."""
    recovery_policy = policy or RepairRecoveryPolicy()
    lifetime = (
        recovery_policy.suggested_change_packet_ttl_seconds
        if suggested_change
        else recovery_policy.approval_packet_ttl_seconds
    )
    if lifetime <= 0:
        raise ValueError("authority packet lifetime must be greater than zero")
    normalized_capabilities = tuple(sorted({str(item) for item in capabilities}))
    packet = RecoveryAuthorityPacket(
        packet_id=uuid4(),
        issuer_role="SUPERVISOR",
        target_id=str(target_id),
        generation_id=str(generation_id),
        code_hash=str(code_hash),
        policy_fingerprint=str(policy_fingerprint),
        authority_policy_generation=str(authority_policy_generation),
        authority_policy_fingerprint=str(authority_policy_fingerprint),
        issued_at=supervisor_time,
        expires_at=supervisor_time + timedelta(seconds=lifetime),
        capabilities=normalized_capabilities,
        policy_state=dict(policy_state or {}),
        approvals=dict(approvals or {}),
        content_sha256="",
    )
    return replace(packet, content_sha256=_packet_hash(packet))


def verify_recovery_authority_packet(
    packet: RecoveryAuthorityPacket,
    *,
    supervisor_time: datetime,
    target_id: str,
    generation_id: str,
    code_hash: str,
    policy_fingerprint: str,
    authority_policy_generation: str,
    authority_policy_fingerprint: str,
    allowed_capabilities: set[str] | frozenset[str] = frozenset(),
    policy: RepairRecoveryPolicy | None = None,
) -> dict[str, Any]:
    """Verify packet integrity, expiry, and exact supervisor context."""
    recovery_policy = policy or RepairRecoveryPolicy()
    failures: list[str] = []
    if packet.schema_version != 1:
        failures.append("UNSUPPORTED_PACKET_SCHEMA")
    if packet.issuer_role != "SUPERVISOR":
        failures.append("UNTRUSTED_PACKET_ISSUER")
    if _packet_hash(packet) != packet.content_sha256:
        failures.append("PACKET_CONTENT_HASH_MISMATCH")
    expiry = validate_authority_expiry(
        packet.expires_at,
        supervisor_time=supervisor_time,
    )
    if not expiry["valid"]:
        failures.append(str(expiry["failure"]))
    future_seconds = (packet.issued_at - supervisor_time).total_seconds()
    if future_seconds > recovery_policy.clock_skew_tolerance_seconds:
        failures.append("CLOCK_SKEW_EXCEEDED")
    expected = {
        "target_id": str(target_id),
        "generation_id": str(generation_id),
        "code_hash": str(code_hash),
        "policy_fingerprint": str(policy_fingerprint),
        "authority_policy_generation": str(authority_policy_generation),
        "authority_policy_fingerprint": str(authority_policy_fingerprint),
    }
    for name, value in expected.items():
        if getattr(packet, name) != value:
            failures.append(f"CONTEXT_MISMATCH:{name}")
    unexpected = sorted(set(packet.capabilities) - set(allowed_capabilities))
    if unexpected:
        failures.append("CAPABILITY_NOT_ALLOWED:" + ",".join(unexpected))
    return {
        "valid": not failures,
        "packet_id": str(packet.packet_id),
        "expires_at": packet.expires_at.isoformat(),
        "remaining_seconds": expiry["remaining_seconds"],
        "failures": failures,
        "authority_granted_by_packet": False,
    }


def validate_supervisor_time(
    supervisor_time: datetime,
    local_time: datetime,
    *,
    tolerance_seconds: float,
) -> dict[str, Any]:
    """Validate a worker timestamp against supervisor time with bounded drift."""
    if tolerance_seconds <= 0:
        raise ValueError("tolerance_seconds must be greater than zero")
    skew_seconds = (local_time - supervisor_time).total_seconds()
    absolute_skew_seconds = abs(skew_seconds)
    valid = absolute_skew_seconds <= tolerance_seconds
    return {
        "valid": valid,
        "supervisor_time": supervisor_time.isoformat(),
        "local_time": local_time.isoformat(),
        "skew_seconds": skew_seconds,
        "absolute_skew_seconds": absolute_skew_seconds,
        "tolerance_seconds": float(tolerance_seconds),
        "failure": None if valid else "CLOCK_SKEW_EXCEEDED",
    }


def validate_authority_expiry(
    expires_at: datetime,
    *,
    supervisor_time: datetime,
) -> dict[str, Any]:
    """Validate an authority packet's expiry using supervisor time."""
    remaining_seconds = (expires_at - supervisor_time).total_seconds()
    valid = remaining_seconds > 0
    return {
        "valid": valid,
        "expires_at": expires_at.isoformat(),
        "supervisor_time": supervisor_time.isoformat(),
        "remaining_seconds": remaining_seconds,
        "failure": None if valid else "AUTHORITY_EXPIRED",
    }


@dataclass(frozen=True, slots=True)
class RepairRecoveryRecord:
    """Durable acknowledgement that one interrupted attempt was reconciled."""

    recovery_id: UUID
    attempt_id: str
    episode_id: str
    incident_id: str
    target_id: str
    observed_at: datetime
    last_milestone: str
    persisted_outcome: str
    recovery_action: str
    authority_action: str
    reason: str


def _recovered_attempt_ids(store: Any) -> set[str]:
    if not hasattr(store, "all_recoveries"):
        return set()
    return {
        str(_field(item, "attempt_id", ""))
        for item in store.all_recoveries()
        if _field(item, "attempt_id")
    }


def _field(record: Any, name: str, default: Any = None) -> Any:
    if isinstance(record, Mapping):
        return record.get(name, default)
    return getattr(record, name, default)


def _enum_name(value: Any) -> str:
    return str(getattr(value, "name", value or ""))


def _attempts(store: Any, target_id: str | None) -> tuple[Any, ...]:
    if target_id is not None:
        return tuple(store.attempts_for_target(target_id))
    if hasattr(store, "all_attempts"):
        return tuple(store.all_attempts())
    return ()


def build_repair_recovery_plan(
    store: Any,
    *,
    target_id: str | None = None,
    now: datetime | None = None,
    policy: RepairRecoveryPolicy | None = None,
) -> dict[str, Any]:
    """Return a fail-safe plan for attempts interrupted by process loss.

    Completed attempts are omitted. An attempt with no completion timestamp or
    a pending outcome is an interrupted transaction, including a transaction
    whose last durable milestone was ``COMPLETE`` but whose final write was not
    durable. The plan is advisory and read-only: it never changes a store,
    activates a candidate, or assumes an approval survives restart.
    """
    recovery_policy = policy or RepairRecoveryPolicy()
    if recovery_policy.allow_candidate_reactivation_after_restart:
        raise ValueError(
            "candidate reactivation after restart is not implemented and cannot be enabled"
        )
    if recovery_policy.approval_packet_ttl_seconds <= 0:
        raise ValueError("approval_packet_ttl_seconds must be greater than zero")
    if recovery_policy.suggested_change_packet_ttl_seconds <= 0:
        raise ValueError("suggested_change_packet_ttl_seconds must be greater than zero")
    if recovery_policy.clock_skew_tolerance_seconds <= 0:
        raise ValueError("clock_skew_tolerance_seconds must be greater than zero")
    observed_at = (now or utcnow()).isoformat()
    decisions: list[dict[str, Any]] = []
    recovered_attempt_ids = _recovered_attempt_ids(store)
    for attempt in _attempts(store, target_id):
        attempt_id = str(_field(attempt, "attempt_id", ""))
        if attempt_id in recovered_attempt_ids:
            continue
        completed_at = _field(attempt, "completed_at")
        outcome = _enum_name(_field(attempt, "outcome"))
        stage = _enum_name(_field(attempt, "stage"))
        if completed_at is not None and outcome != RepairAttemptOutcome.PENDING.name:
            continue
        decisions.append({
            "attempt_id": attempt_id,
            "episode_id": str(_field(attempt, "episode_id", "")),
            "incident_id": str(_field(attempt, "incident_id", "")),
            "target_id": str(_field(attempt, "target_id", "")),
            "candidate_id": str(_field(attempt, "candidate_id", "")),
            "attempt_number": _field(attempt, "attempt_number"),
            "last_milestone": stage or RepairAttemptStage.CREATED.name,
            "persisted_outcome": outcome or RepairAttemptOutcome.PENDING.name,
            "transaction_state": "INTERRUPTED",
            "recovery_action": "ROLLBACK_TO_DEPLOYED_CODE",
            "policy_requested_action": recovery_policy.interrupted_transaction_action.name,
            "policy_action_status": "PLANNED_ONLY",
            "authority_action": "REVALIDATE_BEFORE_ANY_CONTINUATION",
            "candidate_reactivation_allowed": False,
            "approval_survives_restart": False,
            "reason": (
                "Repair transaction did not durably complete; treat it as rolled back "
                "and do not reactivate an in-memory replacement"
            ),
        })
    return {
        "schema_version": RECOVERY_PLAN_SCHEMA_VERSION,
        "observed_at": observed_at,
        "target_id": target_id,
        "restart_policy": "DEPLOYED_CODE_ONLY",
        "read_only": True,
        "automatic_reactivation": False,
        "policy": {
            "enabled": recovery_policy.enabled,
            "interrupted_transaction_action": recovery_policy.interrupted_transaction_action.name,
            "worker_failure_action": recovery_policy.worker_failure_action.name,
            "critical_evidence_action": recovery_policy.critical_evidence_action.name,
            "approval_packet_ttl_seconds": recovery_policy.approval_packet_ttl_seconds,
            "suggested_change_packet_ttl_seconds": recovery_policy.suggested_change_packet_ttl_seconds,
            "clock_skew_tolerance_seconds": recovery_policy.clock_skew_tolerance_seconds,
            "require_full_worker_postmortem_for_critical_evidence": (
                recovery_policy.require_full_worker_postmortem_for_critical_evidence
            ),
        },
        "incomplete_attempt_count": len(decisions),
        "decisions": decisions,
    }


def apply_repair_recovery_plan(
    store: Any,
    plan: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Durably acknowledge rollback decisions without rewriting source evidence.

    This operation does not activate, delete, or rewrite a candidate, attempt,
    incident, or policy record. Reapplying the same plan is idempotent by
    ``attempt_id``. A future policy-aware recovery controller can use these
    records when deciding whether to replace workers or create an incident.
    """
    if plan.get("schema_version") != RECOVERY_PLAN_SCHEMA_VERSION:
        raise ValueError("unsupported Repair recovery plan schema version")
    if not bool(plan.get("read_only")):
        raise ValueError("Repair recovery plan must be a read-only inspection plan")
    decisions = plan.get("decisions")
    if not isinstance(decisions, list):
        raise ValueError("Repair recovery plan decisions must be a list")
    existing = _recovered_attempt_ids(store)
    observed_at = now or utcnow()
    applied = 0
    skipped = 0
    for decision in decisions:
        if not isinstance(decision, Mapping):
            raise ValueError("Repair recovery decision must be an object")
        attempt_id = str(decision.get("attempt_id") or "")
        if not attempt_id:
            raise ValueError("Repair recovery decision requires attempt_id")
        if attempt_id in existing:
            skipped += 1
            continue
        record = RepairRecoveryRecord(
            recovery_id=uuid4(),
            attempt_id=attempt_id,
            episode_id=str(decision.get("episode_id") or ""),
            incident_id=str(decision.get("incident_id") or ""),
            target_id=str(decision.get("target_id") or ""),
            observed_at=observed_at,
            last_milestone=str(decision.get("last_milestone") or "CREATED"),
            persisted_outcome=str(decision.get("persisted_outcome") or "PENDING"),
            recovery_action=str(decision.get("recovery_action") or "ROLLBACK_TO_DEPLOYED_CODE"),
            authority_action=str(
                decision.get("authority_action") or "REVALIDATE_BEFORE_ANY_CONTINUATION"
            ),
            reason=str(decision.get("reason") or "interrupted Repair transaction"),
        )
        store.record_recovery(record)
        existing.add(attempt_id)
        applied += 1
    return {
        "schema_version": RECOVERY_PLAN_SCHEMA_VERSION,
        "applied_count": applied,
        "already_recorded_count": skipped,
        "read_only": False,
        "source_evidence_modified": False,
        "automatic_reactivation": False,
    }
