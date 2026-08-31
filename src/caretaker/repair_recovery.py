"""Fail-safe inspection of persisted Repair work after a process restart.

The current application-scoped recovery contract does not reactivate an in-memory
replacement. This module produces an explicit recovery plan for incomplete
attempts so an operator or future supervisor can reconcile them without treating
an interrupted transaction as successful work.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import Enum, auto
import hashlib
import json
import math
from typing import Any, Callable
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from .domain import RepairAttemptOutcome, RepairAttemptStage, RepairEpisodeOutcome, utcnow


RECOVERY_PLAN_SCHEMA_VERSION = 1
OBSERVATION_RECOVERY_SCHEMA_VERSION = 1
WORKER_POSTMORTEM_SCHEMA_VERSION = 1
WORKER_POSTMORTEM_MAX_BYTES = 1_048_576
WORKER_FAILURE_SCOPE_MAX_CHARS = 256
WORKER_FAILURE_STATUS_MAX_LIMIT = 500
_WORKER_POSTMORTEM_REQUIRED_EVIDENCE = (
    "milestone",
    "partial_queue",
    "policy_state",
)


class RecoveryAction(Enum):
    """Policy-selected response vocabulary for interrupted Repair work."""

    CONTINUE_DEGRADED = auto()
    GENERATE_INCIDENT = auto()
    REPLACE_WORKER = auto()
    STOP_APPLICATION = auto()
    ROLLBACK_TO_DEPLOYED_CODE = auto()


@dataclass(frozen=True, slots=True)
class WorkerAcceptanceOverride:
    """Optional replacement-worker counter overrides for one target."""

    probation_successful_executions: int | None = None
    probation_failure_budget: int | None = None
    acceptance_successful_executions: int | None = None
    acceptance_failure_budget: int | None = None


@dataclass(frozen=True, slots=True)
class WorkerAcceptanceThresholds:
    """Resolved counters used for one replacement-worker target."""

    probation_successful_executions: int
    probation_failure_budget: int
    acceptance_successful_executions: int
    acceptance_failure_budget: int


@dataclass(frozen=True, slots=True)
class WorkerAcceptancePolicy:
    """Policy defaults and target-specific overrides for worker acceptance.

    The defaults are an intentionally conservative guideline: a replacement
    must complete 1,000 successful executions in probation and 1,000 successful
    executions before acceptance, with no failures unless a policy explicitly
    permits them. These counters are observations, not authority; packet
    verification and policy approval remain independent gates.
    """

    probation_successful_executions: int = 1_000
    probation_failure_budget: int = 0
    acceptance_successful_executions: int = 1_000
    acceptance_failure_budget: int = 0
    per_target_overrides: Mapping[str, WorkerAcceptanceOverride] = field(default_factory=dict)

    def thresholds_for(self, target_id: str | None) -> WorkerAcceptanceThresholds:
        override = self.per_target_overrides.get(str(target_id)) if target_id is not None else None
        return WorkerAcceptanceThresholds(
            probation_successful_executions=(
                self.probation_successful_executions
                if override is None or override.probation_successful_executions is None
                else override.probation_successful_executions
            ),
            probation_failure_budget=(
                self.probation_failure_budget
                if override is None or override.probation_failure_budget is None
                else override.probation_failure_budget
            ),
            acceptance_successful_executions=(
                self.acceptance_successful_executions
                if override is None or override.acceptance_successful_executions is None
                else override.acceptance_successful_executions
            ),
            acceptance_failure_budget=(
                self.acceptance_failure_budget
                if override is None or override.acceptance_failure_budget is None
                else override.acceptance_failure_budget
            ),
        )


def validate_worker_acceptance_policy(policy: WorkerAcceptancePolicy) -> None:
    """Reject counters that could silently accept a replacement too early."""
    defaults = (
        ("probation_successful_executions", policy.probation_successful_executions),
        ("probation_failure_budget", policy.probation_failure_budget),
        ("acceptance_successful_executions", policy.acceptance_successful_executions),
        ("acceptance_failure_budget", policy.acceptance_failure_budget),
    )
    for name, value in defaults:
        if value < 0:
            raise ValueError(f"worker acceptance {name} cannot be negative")
    if policy.acceptance_successful_executions < policy.probation_successful_executions:
        raise ValueError(
            "worker acceptance_successful_executions cannot be lower than "
            "probation_successful_executions"
        )
    for target_id, override in policy.per_target_overrides.items():
        if not str(target_id):
            raise ValueError("worker acceptance override target IDs cannot be empty")
        if not isinstance(override, WorkerAcceptanceOverride):
            raise ValueError(
                f"worker acceptance override for {target_id!s} has an unsupported type"
            )
        values = (
            ("probation_successful_executions", override.probation_successful_executions),
            ("probation_failure_budget", override.probation_failure_budget),
            ("acceptance_successful_executions", override.acceptance_successful_executions),
            ("acceptance_failure_budget", override.acceptance_failure_budget),
        )
        for name, value in values:
            if value is not None and value < 0:
                raise ValueError(f"worker acceptance override {name} cannot be negative")
        thresholds = policy.thresholds_for(str(target_id))
        if thresholds.acceptance_successful_executions < thresholds.probation_successful_executions:
            raise ValueError(
                f"worker acceptance override for {target_id!s} lowers acceptance below probation"
            )


def evaluate_worker_acceptance(
    *,
    target_id: str,
    successful_executions: int,
    failed_executions: int,
    policy: WorkerAcceptancePolicy | None = None,
) -> dict[str, Any]:
    """Evaluate counters without mutating state or granting worker authority."""
    if successful_executions < 0 or failed_executions < 0:
        raise ValueError("worker acceptance counters cannot be negative")
    acceptance_policy = policy or WorkerAcceptancePolicy()
    validate_worker_acceptance_policy(acceptance_policy)
    thresholds = acceptance_policy.thresholds_for(target_id)
    probation_complete = (
        successful_executions >= thresholds.probation_successful_executions
        and failed_executions <= thresholds.probation_failure_budget
    )
    accepted = (
        probation_complete
        and successful_executions >= thresholds.acceptance_successful_executions
        and failed_executions <= thresholds.acceptance_failure_budget
    )
    failed = (
        failed_executions > thresholds.probation_failure_budget
        or (
            successful_executions >= thresholds.acceptance_successful_executions
            and failed_executions > thresholds.acceptance_failure_budget
        )
    )
    override = acceptance_policy.per_target_overrides.get(str(target_id))
    return {
        "target_id": str(target_id),
        "successful_executions": successful_executions,
        "failed_executions": failed_executions,
        "probation_complete": probation_complete,
        "accepted": accepted,
        "failed": failed,
        "authority_granted": False,
        "uses_target_override": override is not None,
        "thresholds": {
            "probation_successful_executions": thresholds.probation_successful_executions,
            "probation_failure_budget": thresholds.probation_failure_budget,
            "acceptance_successful_executions": thresholds.acceptance_successful_executions,
            "acceptance_failure_budget": thresholds.acceptance_failure_budget,
        },
    }


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
    worker_acceptance: WorkerAcceptancePolicy = field(default_factory=WorkerAcceptancePolicy)


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


@dataclass(frozen=True, slots=True)
class WorkerReplacementRequest:
    """Supervisor handoff for an authorized replacement worker.

    The request carries the packet that a replacement must present during
    admission. It is a routing/provenance record, not an authority grant; the
    registry verifies the packet and the current supervisor context again.
    """

    request_id: UUID
    failed_worker_id: UUID
    worker_kind: str
    issued_at: datetime
    authority_packet: RecoveryAuthorityPacket
    reason: str

    def summary(self) -> dict[str, Any]:
        """Return bounded metadata suitable for logs and incident evidence."""
        return {
            "request_id": str(self.request_id),
            "failed_worker_id": str(self.failed_worker_id),
            "worker_kind": self.worker_kind,
            "issued_at": self.issued_at.isoformat(),
            "authority_packet_id": str(self.authority_packet.packet_id),
            "authority_packet_expires_at": self.authority_packet.expires_at.isoformat(),
            "reason": self.reason[:256],
        }


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
    incomplete_records: tuple[Mapping[str, Any], ...] = ()
    policy_action: Mapping[str, Any] = field(default_factory=dict)
    action_execution: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class WorkerFailureRecord:
    """Durable evidence record for one failed application-scoped worker."""

    failure_id: UUID
    worker_id: str
    worker_kind: str
    observed_at: datetime
    detail_level: str
    transaction_state: str
    envelope: Mapping[str, Any]
    critical_evidence: bool = False
    postmortem_status: str = "NOT_REQUESTED"
    postmortem_packet: Mapping[str, Any] = field(default_factory=dict)
    postmortem_errors: tuple[str, ...] = ()
    reconciliation_scope: str = ""


@dataclass(frozen=True, slots=True)
class WorkerPostmortemPacket:
    """Complete, individual evidence packet supplied for one failed worker.

    The packet is data only. It proves that the required evidence fields were
    supplied and bounded for storage; it does not authorize replacement,
    policy changes, or any other recovery action.
    """

    packet_id: UUID
    worker_id: str
    worker_kind: str
    captured_at: datetime
    transaction_state: str
    failure_envelope: Mapping[str, Any]
    evidence: Mapping[str, Any]
    content_sha256: str
    schema_version: int = WORKER_POSTMORTEM_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class WorkerPostmortemConflictReport:
    """Durable report retaining divergent worker evidence for investigation."""

    report_id: UUID
    scope: str
    observed_at: datetime
    reason: str
    record_ids: tuple[str, ...]
    packet_hashes: tuple[str, ...]
    packets: tuple[Mapping[str, Any], ...]
    content_sha256: str
    schema_version: int = WORKER_POSTMORTEM_SCHEMA_VERSION
    incomplete_records: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class WorkerFailureRecoveryRecord:
    """Durable, data-only action decision for one reconciled failure scope."""

    recovery_id: UUID
    scope: str
    target_id: str
    observed_at: datetime
    action: str
    critical_evidence_conflict: bool
    policy_action: Mapping[str, Any]
    reconciliation_summary: Mapping[str, Any]
    action_execution: Mapping[str, Any]


def select_recovery_action(
    action: RecoveryAction,
    *,
    enabled: bool,
) -> dict[str, Any]:
    """Resolve a policy action without performing application orchestration."""
    if not isinstance(action, RecoveryAction):
        raise TypeError("recovery action must be a RecoveryAction")
    return {
        "requested_action": action.name,
        "selected_action": action.name if enabled else None,
        "policy_enabled": enabled,
        "status": "PLANNED_ONLY" if enabled else "DISABLED_BY_POLICY",
        "runtime_fallback": RecoveryAction.ROLLBACK_TO_DEPLOYED_CODE.name,
        "requires_application_orchestration": action
        not in {
            RecoveryAction.ROLLBACK_TO_DEPLOYED_CODE,
            RecoveryAction.CONTINUE_DEGRADED,
        },
        "authority_granted": False,
    }


def dispatch_recovery_action(
    decision: Mapping[str, Any],
    *,
    handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]] | None = None,
) -> dict[str, Any]:
    """Dispatch one selected recovery action to an application-owned handler.

    The plan remains the policy input, while the callback is the application
    boundary that owns incident creation, worker replacement, or shutdown.
    A callback must explicitly acknowledge the action with ``accepted=True``;
    that acknowledgement is recorded as execution evidence, not as a Caretaker
    authority grant.
    """
    policy_action = decision.get("policy_action")
    if not isinstance(policy_action, Mapping):
        return {
            "status": "INVALID_PLAN",
            "action": None,
            "authority_granted": False,
            "reason": "recovery decision has no policy action",
        }
    selected = policy_action.get("selected_action")
    if selected is None:
        return {
            "status": "DISABLED_BY_POLICY",
            "action": None,
            "authority_granted": False,
        }
    selected = str(selected)
    requested = str(policy_action.get("requested_action") or "")
    try:
        selected_action = RecoveryAction[selected]
    except KeyError:
        return {
            "status": "INVALID_PLAN",
            "action": selected,
            "authority_granted": False,
            "reason": "recovery decision names an unsupported action",
        }
    if requested != selected_action.name or not bool(policy_action.get("policy_enabled")):
        return {
            "status": "INVALID_PLAN",
            "action": selected_action.name,
            "authority_granted": False,
            "reason": "recovery action is inconsistent with its policy decision",
        }
    if selected in {
        RecoveryAction.ROLLBACK_TO_DEPLOYED_CODE.name,
        RecoveryAction.CONTINUE_DEGRADED.name,
    }:
        return {
            "status": "FALLBACK_ONLY",
            "action": selected,
            "authority_granted": False,
        }
    handler = (handlers or {}).get(selected)
    if handler is None:
        return {
            "status": "NOT_CONFIGURED",
            "action": selected,
            "authority_granted": False,
        }
    try:
        result = handler(decision)
    except Exception as exc:
        return {
            "status": "FAILED",
            "action": selected,
            "authority_granted": False,
            "error": f"{type(exc).__name__}: {exc}"[:256],
        }
    if not isinstance(result, Mapping) or not bool(result.get("accepted")):
        return {
            "status": "REJECTED_BY_HANDLER",
            "action": selected,
            "authority_granted": False,
            "handler_result": dict(result) if isinstance(result, Mapping) else None,
        }
    required_gates: dict[str, str] = {
        RecoveryAction.GENERATE_INCIDENT.name: "incident_id",
        RecoveryAction.STOP_APPLICATION.name: "shutdown_requested",
    }
    if selected == RecoveryAction.REPLACE_WORKER.name:
        missing = [
            name for name in (
                "failed_worker_id",
                "replacement_worker_id",
                "authority_packet_id",
                "authority_packet_verified",
                "acceptance_state",
                "authority_packet_expires_at",
            )
            if not result.get(name)
        ]
        if result.get("acceptance_state") not in {"PROBATION", "ACCEPTED"}:
            missing.append("acceptance_state:PROBATION_OR_ACCEPTED")
    else:
        gate = required_gates.get(selected)
        missing = [gate] if gate and not result.get(gate) else []
    if missing:
        return {
            "status": "REJECTED_BY_HANDLER",
            "action": selected,
            "authority_granted": False,
            "required_gates": missing,
            "handler_result": dict(result),
        }
    return {
        "status": "EXECUTED",
        "action": selected,
        "authority_granted": False,
        "handler_result": dict(result),
    }


def resolve_worker_failure_scope(
    envelope: Mapping[str, Any],
    *,
    scope: str | None = None,
    failure_id: UUID | str | None = None,
) -> str:
    """Assign a bounded, non-authorizing scope to one worker failure.

    An embedding application may provide an explicit scope when it knows that
    several workers belong to one transaction. Otherwise Caretaker uses the
    narrowest durable context available: an explicitly carried reconciliation
    scope, transaction ID, or incident ID. A failure without any such context
    is isolated by its failure ID; target identity alone is intentionally not
    enough to merge unrelated failures.
    """
    if not isinstance(envelope, Mapping):
        raise TypeError("worker failure envelope must be a mapping")

    def normalize(value: Any, *, label: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError(f"worker failure {label} cannot be empty")
        if len(text) > WORKER_FAILURE_SCOPE_MAX_CHARS:
            raise ValueError(
                f"worker failure {label} cannot exceed "
                f"{WORKER_FAILURE_SCOPE_MAX_CHARS} characters"
            )
        return text

    if scope is not None:
        return normalize(scope, label="scope")

    carried_scope = envelope.get("reconciliation_scope")
    if carried_scope:
        return normalize(carried_scope, label="scope")

    for field_name, prefix in (
        ("transaction_id", "transaction"),
        ("repair_transaction_id", "transaction"),
        ("incident_id", "incident"),
    ):
        value = envelope.get(field_name)
        if value:
            return normalize(f"{prefix}:{value}", label="scope")

    fallback = str(failure_id or uuid4())
    return normalize(f"worker-failure:{fallback}", label="scope")


def create_worker_failure_record(
    envelope: Mapping[str, Any],
    *,
    observed_at: datetime | None = None,
    critical_evidence: bool = False,
    postmortem_evidence: Mapping[str, Any] | None = None,
    postmortem_error: str | None = None,
    require_complete_postmortem: bool = False,
    scope: str | None = None,
) -> WorkerFailureRecord:
    """Create a durable record from a bounded failure envelope.

    A critical-evidence caller must provide a complete post-mortem packet (or
    the record explicitly remains ``INCOMPLETE``). Missing packet data never
    causes a failure record to disappear; the incompleteness is retained for
    the policy-selected response and later investigation.
    """
    if not isinstance(envelope, Mapping):
        raise TypeError("worker failure envelope must be a mapping")
    worker_id = str(envelope.get("worker_id") or "")
    worker_kind = str(envelope.get("worker_kind") or "")
    if not worker_id or not worker_kind:
        raise ValueError("worker failure envelope requires worker identity")
    failure_id = uuid4()
    reconciliation_scope = resolve_worker_failure_scope(
        envelope,
        scope=scope,
        failure_id=failure_id,
    )
    errors: list[str] = []
    packet_payload: Mapping[str, Any] = {}
    postmortem_status = "NOT_REQUESTED"
    if postmortem_error:
        errors.append(str(postmortem_error)[:256])
        postmortem_status = "INCOMPLETE" if critical_evidence else "INVALID"
    elif postmortem_evidence is not None:
        try:
            packet = create_worker_postmortem_packet(
                envelope,
                evidence=postmortem_evidence,
                captured_at=observed_at,
            )
            packet_payload = {
                "packet_id": str(packet.packet_id),
                "worker_id": packet.worker_id,
                "worker_kind": packet.worker_kind,
                "captured_at": packet.captured_at.isoformat(),
                "transaction_state": packet.transaction_state,
                "failure_envelope": dict(packet.failure_envelope),
                "evidence": dict(packet.evidence),
                "content_sha256": packet.content_sha256,
                "schema_version": packet.schema_version,
            }
            postmortem_status = "COMPLETE"
        except (TypeError, ValueError) as exc:
            errors.append(f"{type(exc).__name__}: {exc}"[:256])
            postmortem_status = "INCOMPLETE" if critical_evidence else "INVALID"
    if critical_evidence and require_complete_postmortem and postmortem_status != "COMPLETE":
        if not errors:
            errors.append("critical evidence requires a complete worker post-mortem packet")
        postmortem_status = "INCOMPLETE"
    return WorkerFailureRecord(
        failure_id=failure_id,
        worker_id=worker_id,
        worker_kind=worker_kind,
        observed_at=observed_at or utcnow(),
        detail_level=str(envelope.get("detail_level") or "STANDARD"),
        transaction_state=str(envelope.get("transaction_state") or "ROLLED_BACK"),
        envelope=dict(envelope),
        critical_evidence=bool(critical_evidence),
        postmortem_status=postmortem_status,
        postmortem_packet=packet_payload,
        postmortem_errors=tuple(errors),
        reconciliation_scope=reconciliation_scope,
    )


def create_worker_postmortem_packet(
    envelope: Mapping[str, Any],
    *,
    evidence: Mapping[str, Any],
    captured_at: datetime | None = None,
) -> WorkerPostmortemPacket:
    """Validate and hash one complete individual worker post-mortem packet.

    The application/worker supplies JSON-shaped evidence. The required
    milestone, partial queue, and policy-state fields make the packet useful
    for rollback reconciliation without treating arbitrary diagnostic data as
    authority. A one-megabyte serialized limit prevents a diagnostic packet
    from exhausting the recovery store.
    """
    if not isinstance(envelope, Mapping):
        raise TypeError("worker failure envelope must be a mapping")
    if not isinstance(evidence, Mapping):
        raise TypeError("worker post-mortem evidence must be a mapping")
    worker_id = str(envelope.get("worker_id") or "")
    worker_kind = str(envelope.get("worker_kind") or "")
    if not worker_id or not worker_kind:
        raise ValueError("worker failure envelope requires worker identity")
    if str(envelope.get("transaction_state") or "ROLLED_BACK") != "ROLLED_BACK":
        raise ValueError("worker post-mortem envelope must be marked ROLLED_BACK")
    missing = [name for name in _WORKER_POSTMORTEM_REQUIRED_EVIDENCE if name not in evidence]
    if missing:
        raise ValueError(
            "worker post-mortem evidence is missing required fields: "
            + ", ".join(missing)
        )
    packet = WorkerPostmortemPacket(
        packet_id=uuid4(),
        worker_id=worker_id,
        worker_kind=worker_kind,
        captured_at=captured_at or utcnow(),
        transaction_state=str(envelope.get("transaction_state") or "ROLLED_BACK"),
        failure_envelope=dict(envelope),
        evidence=dict(evidence),
        content_sha256="",
    )
    payload = {
        "packet_id": str(packet.packet_id),
        "worker_id": packet.worker_id,
        "worker_kind": packet.worker_kind,
        "captured_at": packet.captured_at.isoformat(),
        "transaction_state": packet.transaction_state,
        "failure_envelope": packet.failure_envelope,
        "evidence": packet.evidence,
        "schema_version": packet.schema_version,
    }
    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("worker post-mortem evidence must be JSON-shaped") from exc
    if len(encoded) > WORKER_POSTMORTEM_MAX_BYTES:
        raise ValueError(
            f"worker post-mortem packet exceeds {WORKER_POSTMORTEM_MAX_BYTES} bytes"
        )
    return replace(packet, content_sha256=hashlib.sha256(encoded).hexdigest())


def verify_worker_postmortem_packet(
    packet: Mapping[str, Any],
    *,
    envelope: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify stored post-mortem structure, identity, required evidence, and hash."""
    failures: list[str] = []
    if not isinstance(packet, Mapping):
        return {
            "valid": False,
            "failures": ["PACKET_NOT_MAPPING"],
            "authority_granted": False,
        }
    required = (
        "packet_id",
        "worker_id",
        "worker_kind",
        "captured_at",
        "transaction_state",
        "failure_envelope",
        "evidence",
        "content_sha256",
        "schema_version",
    )
    failures.extend(f"MISSING:{name}" for name in required if name not in packet)
    if packet.get("schema_version") != WORKER_POSTMORTEM_SCHEMA_VERSION:
        failures.append("UNSUPPORTED_PACKET_SCHEMA")
    failure_envelope = packet.get("failure_envelope")
    evidence = packet.get("evidence")
    if not isinstance(failure_envelope, Mapping):
        failures.append("FAILURE_ENVELOPE_NOT_MAPPING")
    if not isinstance(evidence, Mapping):
        failures.append("EVIDENCE_NOT_MAPPING")
    else:
        failures.extend(
            f"MISSING_EVIDENCE:{name}"
            for name in _WORKER_POSTMORTEM_REQUIRED_EVIDENCE
            if name not in evidence
        )
    if isinstance(failure_envelope, Mapping):
        if str(failure_envelope.get("worker_id") or "") != str(packet.get("worker_id") or ""):
            failures.append("IDENTITY_MISMATCH:worker_id")
        if str(failure_envelope.get("worker_kind") or "") != str(packet.get("worker_kind") or ""):
            failures.append("IDENTITY_MISMATCH:worker_kind")
        if envelope is not None:
            for name in ("worker_id", "worker_kind"):
                if str(envelope.get(name) or "") != str(packet.get(name) or ""):
                    failures.append(f"CONTEXT_MISMATCH:{name}")
    hash_input = dict(packet)
    supplied_hash = str(hash_input.pop("content_sha256", "") or "")
    try:
        encoded = json.dumps(
            hash_input,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        if len(encoded) > WORKER_POSTMORTEM_MAX_BYTES:
            failures.append("PACKET_TOO_LARGE")
        elif hashlib.sha256(encoded).hexdigest() != supplied_hash:
            failures.append("PACKET_CONTENT_HASH_MISMATCH")
    except (TypeError, ValueError):
        failures.append("PACKET_NOT_JSON_SHAPED")
    return {
        "valid": not failures,
        "packet_id": str(packet.get("packet_id") or ""),
        "worker_id": str(packet.get("worker_id") or ""),
        "failures": failures,
        "authority_granted": False,
    }


def reconcile_worker_postmortems(
    records: tuple[WorkerFailureRecord | Mapping[str, Any], ...] | list[WorkerFailureRecord | Mapping[str, Any]],
    *,
    scope: str,
    store: Any | None = None,
    minimum_sample_count: int = 30,
    z_threshold: float = 3.0,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Deduplicate and compare individual worker post-mortem evidence.

    ``scope`` is supplied by the caller that knows which workers belong to one
    failed transaction or incident. Exact packet hashes are deduplicated, but
    every source record remains represented. Distinct packets are combined
    only when each supplies a sufficiently large, compatible
    ``behavior_signature`` with metric means and standard deviations. Any
    divergent or non-comparable set is retained in a durable conflict report
    when a store is supplied.
    """
    normalized_scope = str(scope or "").strip()
    if not normalized_scope or len(normalized_scope) > 256:
        raise ValueError("post-mortem reconciliation scope must contain 1..256 characters")
    if minimum_sample_count <= 0:
        raise ValueError("minimum_sample_count must be greater than zero")
    if not math.isfinite(z_threshold) or z_threshold <= 0:
        raise ValueError("z_threshold must be finite and greater than zero")
    unique_packets: dict[str, dict[str, Any]] = {}
    record_ids_by_hash: dict[str, list[str]] = {}
    invalid_records: list[dict[str, Any]] = []
    not_requested_records: list[dict[str, Any]] = []
    target_contexts: set[str] = set()
    missing_target_context = False
    for index, record in enumerate(records):
        if isinstance(record, Mapping):
            record_id = str(record.get("failure_id") or f"record-{index}")
            envelope = record.get("envelope")
            packet = record.get("postmortem_packet")
            status = str(record.get("postmortem_status") or "")
        else:
            record_id = str(record.failure_id)
            envelope = record.envelope
            packet = record.postmortem_packet
            status = record.postmortem_status
        if status == "NOT_REQUESTED":
            not_requested_records.append({
                "record_id": record_id,
                "status": status,
                "reason": "worker post-mortem was not requested by policy",
            })
            continue
        if isinstance(envelope, Mapping) and envelope.get("target_id"):
            target_contexts.add(str(envelope["target_id"]))
        else:
            missing_target_context = True
        if status != "COMPLETE" or not isinstance(packet, Mapping):
            invalid_records.append({
                "record_id": record_id,
                "status": status or "MISSING",
                "reason": "post-mortem packet is not complete",
            })
            continue
        verification = verify_worker_postmortem_packet(
            packet,
            envelope=envelope if isinstance(envelope, Mapping) else None,
        )
        if not verification["valid"]:
            invalid_records.append({
                "record_id": record_id,
                "status": "INVALID",
                "reason": "post-mortem packet verification failed",
                "failures": list(verification["failures"]),
            })
            continue
        packet_hash = str(packet["content_sha256"])
        unique_packets.setdefault(packet_hash, dict(packet))
        record_ids_by_hash.setdefault(packet_hash, []).append(record_id)

    packet_items = list(unique_packets.items())
    duplicate_count = sum(max(0, len(ids) - 1) for ids in record_ids_by_hash.values())
    worker_ids = {
        str(packet.get("worker_id") or "")
        for _, packet in packet_items
    }
    same_worker_conflict = len(worker_ids) < len(packet_items)
    comparison: dict[str, Any] = {
        "status": "DEDUPLICATED" if len(packet_items) <= 1 else "RETAINED_NOT_COMBINED",
        "minimum_sample_count": minimum_sample_count,
        "z_threshold": float(z_threshold),
        "metrics": {},
    }
    conflict_reason: str | None = None
    signatures: list[tuple[str, Mapping[str, Any], int, Mapping[str, Any]]] = []
    for packet_hash, packet in packet_items:
        signature = (packet.get("evidence") or {}).get("behavior_signature")
        if not isinstance(signature, Mapping):
            continue
        sample_count = signature.get("sample_count")
        metrics = signature.get("metrics")
        if isinstance(sample_count, bool) or not isinstance(sample_count, int) or sample_count < minimum_sample_count:
            continue
        if not isinstance(metrics, Mapping) or not metrics:
            continue
        valid_metrics = True
        for metric in metrics.values():
            if not isinstance(metric, Mapping):
                valid_metrics = False
                break
            mean = metric.get("mean")
            standard_deviation = metric.get("standard_deviation")
            if (
                isinstance(mean, bool)
                or not isinstance(mean, (int, float))
                or not math.isfinite(float(mean))
                or isinstance(standard_deviation, bool)
                or not isinstance(standard_deviation, (int, float))
                or not math.isfinite(float(standard_deviation))
                or float(standard_deviation) < 0
            ):
                valid_metrics = False
                break
        if valid_metrics:
            signatures.append((packet_hash, signature, sample_count, metrics))
    if len(packet_items) > 1:
        if len(target_contexts) > 1 or (target_contexts and missing_target_context):
            conflict_reason = "worker post-mortem records have different or missing target identities"
        elif same_worker_conflict:
            conflict_reason = "one worker supplied divergent post-mortem packet hashes"
        elif len(signatures) != len(packet_items):
            conflict_reason = "worker post-mortem behavior signatures are missing or insufficient"
        else:
            metric_names = set(signatures[0][3])
            if any(set(metrics) != metric_names for _, _, _, metrics in signatures[1:]):
                conflict_reason = "worker post-mortem behavior signatures have different metrics"
            else:
                combined_metrics: dict[str, dict[str, float | int]] = {}
                outliers: list[dict[str, Any]] = []
                for metric_name in sorted(metric_names):
                    observations = [
                        (sample_count, float(metrics[metric_name]["mean"]), float(metrics[metric_name]["standard_deviation"]), packet_hash)
                        for packet_hash, _, sample_count, metrics in signatures
                    ]
                    total = sum(item[0] for item in observations)
                    combined_mean = sum(count * mean for count, mean, _, _ in observations) / total
                    combined_variance = sum(
                        count * (standard_deviation**2 + (mean - combined_mean) ** 2)
                        for count, mean, standard_deviation, _ in observations
                    ) / total
                    combined_metrics[metric_name] = {
                        "sample_count": total,
                        "mean": combined_mean,
                        "standard_deviation": combined_variance**0.5,
                    }
                    for count, mean, standard_deviation, packet_hash in observations:
                        other_count = total - count
                        if other_count <= 0:
                            continue
                        other_mean = sum(
                            other_count_item * other_mean_item
                            for other_count_item, other_mean_item, _, other_hash in observations
                            if other_hash != packet_hash
                        ) / other_count
                        other_variance = sum(
                            other_count_item * (other_std**2 + (other_mean_item - other_mean) ** 2)
                            for other_count_item, other_mean_item, other_std, other_hash in observations
                            if other_hash != packet_hash
                        ) / other_count
                        standard_error = (
                            standard_deviation**2 / count
                            + other_variance / other_count
                        ) ** 0.5
                        z_score = abs(mean - other_mean) / max(standard_error, 1e-9)
                        if z_score > z_threshold:
                            outliers.append({
                                "packet_hash": packet_hash,
                                "metric": metric_name,
                                "z_score": z_score,
                                "z_threshold": float(z_threshold),
                                "sample_count": count,
                                "comparison_sample_count": other_count,
                            })
                if outliers:
                    conflict_reason = "worker post-mortem behavior signatures differ beyond the configured threshold"
                else:
                    comparison["status"] = "COMBINED"
                    comparison["metrics"] = combined_metrics
                comparison["outliers"] = outliers
    if len(packet_items) == 1 and not invalid_records:
        comparison["status"] = "DEDUPLICATED" if duplicate_count else "SINGLE_PACKET"
    elif not packet_items and invalid_records:
        comparison["status"] = "INCOMPLETE_EVIDENCE"
    elif not packet_items and not_requested_records:
        comparison["status"] = "NO_POSTMORTEM_REQUESTED"
    if invalid_records:
        comparison["status"] = "INCOMPLETE_EVIDENCE"
    if invalid_records and conflict_reason is None:
        conflict_reason = "one or more worker post-mortem packets are incomplete or invalid"
    report: WorkerPostmortemConflictReport | None = None
    if conflict_reason is not None and (packet_items or invalid_records):
        report_payload = {
            "scope": normalized_scope,
            "reason": conflict_reason,
            "record_ids": tuple(
                [record_id for ids in record_ids_by_hash.values() for record_id in ids]
                + [item["record_id"] for item in invalid_records]
            ),
            "packet_hashes": tuple(packet_hash for packet_hash, _ in packet_items),
            "packets": tuple(packet for _, packet in packet_items),
            "incomplete_records": tuple(invalid_records),
        }
        encoded = json.dumps(
            report_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        report = WorkerPostmortemConflictReport(
            report_id=uuid5(
                NAMESPACE_URL,
                "caretaker:worker-postmortem-conflict:" + hashlib.sha256(encoded).hexdigest(),
            ),
            scope=normalized_scope,
            observed_at=observed_at or utcnow(),
            reason=conflict_reason,
            record_ids=tuple(report_payload["record_ids"]),
            packet_hashes=tuple(report_payload["packet_hashes"]),
            packets=tuple(report_payload["packets"]),
            content_sha256=hashlib.sha256(encoded).hexdigest(),
            incomplete_records=tuple(report_payload["incomplete_records"]),
        )
        if store is not None:
            recorder = getattr(store, "record_worker_postmortem_conflict", None)
            if not callable(recorder):
                raise TypeError("store does not support worker post-mortem conflict reports")
            recorder(report)
    return {
        "schema_version": WORKER_POSTMORTEM_SCHEMA_VERSION,
        "scope": normalized_scope,
        "target_ids": tuple(sorted(target_contexts)),
        "input_count": len(records),
        "complete_record_count": sum(len(ids) for ids in record_ids_by_hash.values()),
        "unique_packet_count": len(packet_items),
        "duplicate_count": duplicate_count,
        "invalid_records": invalid_records,
        "not_requested_records": not_requested_records,
        "comparison": comparison,
        "conflict": report is not None,
        "conflict_report": report,
        "retained_packets": tuple(packet for _, packet in packet_items),
        "authority_granted": False,
    }


def reconcile_worker_failure_records(
    store: Any,
    *,
    scope: str | None = None,
    minimum_sample_count: int = 30,
    z_threshold: float = 3.0,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Coordinate stored worker-failure evidence by its assigned scope.

    Every stored failure is assigned to exactly one scope. A caller may limit
    reconciliation to one validated scope, but does not need to assemble the
    worker list manually. Records from older stores without a scope are
    isolated using their durable failure ID, preserving the safety rule that
    target identity alone cannot merge unrelated failures.

    This function performs evidence reconciliation only. It never changes
    policy, authority, worker state, or recovery action selection.
    """
    if not hasattr(store, "all_worker_failures"):
        raise TypeError("store does not support worker failure records")
    selected_scope = (
        resolve_worker_failure_scope({}, scope=scope)
        if scope is not None
        else None
    )
    grouped: dict[tuple[str, str], list[Any]] = {}
    for record in store.all_worker_failures():
        envelope = _field(record, "envelope", {})
        assigned_scope = _field(record, "reconciliation_scope", "")
        if not assigned_scope:
            assigned_scope = resolve_worker_failure_scope(
                envelope if isinstance(envelope, Mapping) else {},
                failure_id=_field(record, "failure_id", ""),
            )
        if selected_scope is not None and assigned_scope != selected_scope:
            continue
        target_id = str(_field(envelope, "target_id", "") or "") if isinstance(envelope, Mapping) else ""
        grouped.setdefault((str(assigned_scope), target_id), []).append(record)

    reconciliations = tuple(
        reconcile_worker_postmortems(
            tuple(records),
            scope=group_scope,
            store=store,
            minimum_sample_count=minimum_sample_count,
            z_threshold=z_threshold,
            observed_at=observed_at,
        )
        for (group_scope, target_id), records in sorted(grouped.items())
    )
    output = {
        "schema_version": WORKER_POSTMORTEM_SCHEMA_VERSION,
        "scope": selected_scope,
        "group_count": len(reconciliations),
        "record_count": sum(len(records) for records in grouped.values()),
        "reconciliations": tuple(
            {
                **reconciliation,
                "target_id": target_id or None,
            }
            for reconciliation, ((_, target_id), _) in zip(
                reconciliations,
                sorted(grouped.items()),
            )
        ),
        "authority_granted": False,
    }
    return output


def worker_failure_recovery_status(
    store: Any,
    *,
    limit: int = 100,
) -> dict[str, Any]:
    """Return bounded, read-only summaries of persisted worker recovery state.

    Worker failure envelopes and post-mortem packets can contain sensitive
    diagnostic evidence. The status surface therefore exposes identity,
    scope, evidence state, conflict references, and action checkpoint state,
    but never returns those payloads. This is an inspection projection only;
    it cannot authorize, retry, or execute a recovery action.
    """
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise TypeError("worker failure status limit must be an integer")
    if limit <= 0 or limit > WORKER_FAILURE_STATUS_MAX_LIMIT:
        raise ValueError(
            "worker failure status limit must be between 1 and "
            f"{WORKER_FAILURE_STATUS_MAX_LIMIT}"
        )
    required_methods = (
        "all_worker_failures",
        "all_worker_failure_recoveries",
        "all_worker_postmortem_conflicts",
    )
    missing = [name for name in required_methods if not callable(getattr(store, name, None))]
    if missing:
        raise TypeError(
            "store does not support worker failure status: " + ", ".join(missing)
        )

    def bounded(value: Any, maximum: int = WORKER_FAILURE_SCOPE_MAX_CHARS) -> str:
        return str(value or "")[:maximum]

    def timestamp(value: Any) -> str | None:
        if value is None:
            return None
        return bounded(value, 64)

    def failure_summary(record: Any) -> dict[str, Any]:
        envelope = _field(record, "envelope", {})
        envelope = envelope if isinstance(envelope, Mapping) else {}
        errors = _field(record, "postmortem_errors", ())
        if isinstance(errors, str):
            errors = (errors,)
        elif not isinstance(errors, Sequence):
            errors = ()
        return {
            "failure_id": bounded(_field(record, "failure_id", ""), 64),
            "worker_id": bounded(_field(record, "worker_id", "")),
            "worker_kind": bounded(_field(record, "worker_kind", "")),
            "observed_at": timestamp(_field(record, "observed_at")),
            "detail_level": bounded(_field(record, "detail_level", "STANDARD")),
            "transaction_state": bounded(
                _field(record, "transaction_state", "ROLLED_BACK")
            ),
            "reconciliation_scope": bounded(
                _field(record, "reconciliation_scope", "")
            ),
            "target_id": bounded(envelope.get("target_id")),
            "critical_evidence": bool(_field(record, "critical_evidence", False)),
            "postmortem_status": bounded(
                _field(record, "postmortem_status", "NOT_REQUESTED")
            ),
            "postmortem_error_count": len(errors),
            "postmortem_error": bounded(errors[0]) if errors else None,
            "packet_present": bool(_field(record, "postmortem_packet", {})),
        }

    def recovery_summary(record: Any) -> dict[str, Any]:
        policy_action = _field(record, "policy_action", {})
        action_execution = _field(record, "action_execution", {})
        reconciliation = _field(record, "reconciliation_summary", {})
        policy_action = policy_action if isinstance(policy_action, Mapping) else {}
        action_execution = (
            action_execution if isinstance(action_execution, Mapping) else {}
        )
        reconciliation = reconciliation if isinstance(reconciliation, Mapping) else {}
        return {
            "recovery_id": bounded(_field(record, "recovery_id", ""), 64),
            "scope": bounded(_field(record, "scope", "")),
            "target_id": bounded(_field(record, "target_id", "")),
            "observed_at": timestamp(_field(record, "observed_at")),
            "action": bounded(_field(record, "action", "")),
            "critical_evidence_conflict": bool(
                _field(record, "critical_evidence_conflict", False)
            ),
            "policy_action": {
                key: policy_action.get(key)
                for key in (
                    "requested_action",
                    "selected_action",
                    "policy_enabled",
                    "status",
                    "requires_application_orchestration",
                )
                if key in policy_action
            },
            "reconciliation": {
                key: reconciliation.get(key)
                for key in (
                    "input_count",
                    "complete_record_count",
                    "unique_packet_count",
                    "duplicate_count",
                    "comparison_status",
                    "invalid_record_count",
                    "conflict_report_hash",
                )
                if key in reconciliation
            },
            "action_execution": {
                key: action_execution.get(key)
                for key in ("status", "accepted", "reason", "checkpoint_error")
                if key in action_execution
            },
        }

    def conflict_summary(record: Any) -> dict[str, Any]:
        incomplete = _field(record, "incomplete_records", ())
        if not isinstance(incomplete, Sequence) or isinstance(incomplete, str):
            incomplete = ()
        return {
            "report_id": bounded(_field(record, "report_id", ""), 64),
            "scope": bounded(_field(record, "scope", "")),
            "observed_at": timestamp(_field(record, "observed_at")),
            "reason": bounded(_field(record, "reason", "")),
            "record_ids": [bounded(item, 64) for item in (_field(record, "record_ids", ()) or ())],
            "packet_hashes": [bounded(item, 64) for item in (_field(record, "packet_hashes", ()) or ())],
            "incomplete_records": [
                {
                    "record_id": bounded(item.get("record_id"), 64),
                    "status": bounded(item.get("status")),
                    "reason": bounded(item.get("reason")),
                }
                for item in incomplete
                if isinstance(item, Mapping)
            ],
            "content_sha256": bounded(_field(record, "content_sha256", ""), 64),
        }

    failures = tuple(store.all_worker_failures())
    recoveries = tuple(store.all_worker_failure_recoveries())
    conflicts = tuple(store.all_worker_postmortem_conflicts())
    return {
        "schema_version": WORKER_POSTMORTEM_SCHEMA_VERSION,
        "read_only": True,
        "authority_granted": False,
        "bounded": True,
        "failure_count": len(failures),
        "recovery_count": len(recoveries),
        "conflict_count": len(conflicts),
        "failures": [failure_summary(item) for item in failures[-limit:]],
        "recoveries": [recovery_summary(item) for item in recoveries[-limit:]],
        "conflicts": [conflict_summary(item) for item in conflicts[-limit:]],
    }


def create_worker_failure_recovery_record(
    decision: Mapping[str, Any],
    *,
    action_execution: Mapping[str, Any],
    observed_at: datetime | None = None,
) -> WorkerFailureRecoveryRecord:
    """Create an idempotently identifiable action checkpoint.

    The identity covers the evidence set and selected policy action, but not
    handler output or observation time. A retry therefore resolves to the
    same record before an application-owned side effect is attempted again.
    """
    scope = str(decision.get("scope") or "").strip()
    if not scope or len(scope) > WORKER_FAILURE_SCOPE_MAX_CHARS:
        raise ValueError("worker failure recovery decision requires a bounded scope")
    policy_action = decision.get("policy_action")
    reconciliation = decision.get("reconciliation")
    if not isinstance(policy_action, Mapping) or not isinstance(reconciliation, Mapping):
        raise ValueError("worker failure recovery decision is missing policy or evidence")
    target_id = str(decision.get("target_id") or "").strip()
    if len(target_id) > WORKER_FAILURE_SCOPE_MAX_CHARS:
        raise ValueError("worker failure recovery decision target_id is too long")
    report = reconciliation.get("conflict_report")
    report_hash = str(
        getattr(report, "content_sha256", "")
        or (report.get("content_sha256") if isinstance(report, Mapping) else "")
        or ""
    )
    summary = {
        "scope": scope,
        "target_id": target_id or None,
        "input_count": int(reconciliation.get("input_count") or 0),
        "complete_record_count": int(reconciliation.get("complete_record_count") or 0),
        "unique_packet_count": int(reconciliation.get("unique_packet_count") or 0),
        "duplicate_count": int(reconciliation.get("duplicate_count") or 0),
        "comparison_status": str(
            (reconciliation.get("comparison") or {}).get("status")
            if isinstance(reconciliation.get("comparison"), Mapping)
            else ""
        ),
        "invalid_record_ids": tuple(
            str(item.get("record_id") or "")
            for item in reconciliation.get("invalid_records") or ()
            if isinstance(item, Mapping)
        ),
        "conflict_report_hash": report_hash,
    }
    identity_payload = {
        "scope": scope,
        "target_id": target_id,
        "critical_evidence_conflict": bool(decision.get("critical_evidence_conflict")),
        "policy_action": dict(policy_action),
        "reconciliation_summary": summary,
    }
    encoded = json.dumps(
        identity_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return WorkerFailureRecoveryRecord(
        recovery_id=uuid5(
            NAMESPACE_URL,
            "caretaker:worker-failure-recovery:" + hashlib.sha256(encoded).hexdigest(),
        ),
        scope=scope,
        target_id=target_id,
        observed_at=observed_at or utcnow(),
        action=str(policy_action.get("selected_action") or ""),
        critical_evidence_conflict=bool(decision.get("critical_evidence_conflict")),
        policy_action=dict(policy_action),
        reconciliation_summary=summary,
        action_execution=dict(action_execution),
    )


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


def _records_by_id(store: Any, method_name: str, id_field: str) -> dict[str, Any]:
    if not hasattr(store, method_name):
        return {}
    return {
        str(_field(item, id_field, "")): item
        for item in getattr(store, method_name)()
        if _field(item, id_field)
    }


def recover_candidate_observation_state(
    store: Any,
    *,
    target_id: str | None = None,
    candidate_id: str | None = None,
    function_version: int | None = None,
) -> dict[str, Any]:
    """Reconstruct persisted candidate counters without replaying observations.

    Observation records are evidence, not an authority grant. The returned
    counters are safe to inspect after restart because each observation ID is
    counted at most once. A caller still has to bind the result to a live
    candidate, policy, and authority before it can continue a Repair workflow.
    """
    if function_version is not None and function_version < 0:
        raise ValueError("function_version cannot be negative")
    records = tuple(store.all_observations()) if hasattr(store, "all_observations") else ()
    selected: list[Any] = []
    for record in records:
        if target_id is not None and str(_field(record, "target_id", "")) != str(target_id):
            continue
        if candidate_id is not None and str(_field(record, "candidate_id", "")) != str(candidate_id):
            continue
        if (
            function_version is not None
            and _field(record, "function_version") != function_version
        ):
            continue
        selected.append(record)

    seen: dict[str, str] = {}
    duplicate_count = 0
    conflicting_ids: list[str] = []
    valid: list[Any] = []
    for record in selected:
        observation_id = str(_field(record, "observation_id", ""))
        payload = json.dumps(
            {
                "target_id": _field(record, "target_id", ""),
                "candidate_id": _field(record, "candidate_id", ""),
                "function_version": _field(record, "function_version"),
                "call_id": _field(record, "call_id", ""),
                "occurred_at": _field(record, "occurred_at", ""),
                "counted_as_success": bool(_field(record, "counted_as_success", False)),
                "counted_as_failure": bool(_field(record, "counted_as_failure", False)),
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        if observation_id in seen:
            duplicate_count += 1
            if seen[observation_id] != payload:
                conflicting_ids.append(observation_id)
            continue
        seen[observation_id] = payload
        valid.append(record)

    def occurred_at(record: Any) -> str | None:
        value = _field(record, "occurred_at")
        return value.isoformat() if isinstance(value, datetime) else str(value) if value else None

    timestamps = [item for item in (occurred_at(record) for record in valid) if item is not None]
    successes = sum(bool(_field(record, "counted_as_success", False)) for record in valid)
    failures = sum(bool(_field(record, "counted_as_failure", False)) for record in valid)
    has_conflicts = bool(conflicting_ids)
    return {
        "schema_version": OBSERVATION_RECOVERY_SCHEMA_VERSION,
        "read_only": True,
        "authority_granted": False,
        "target_id": str(target_id) if target_id is not None else None,
        "candidate_id": str(candidate_id) if candidate_id is not None else None,
        "function_version": function_version,
        "state": "CONFLICTING_EVIDENCE" if has_conflicts else (
            "PERSISTED_EVIDENCE_READY" if valid else "NO_PERSISTED_OBSERVATIONS"
        ),
        "observation_count": len(valid),
        "successful_executions": successes,
        "failed_executions": failures,
        "first_observed_at": min(timestamps) if timestamps else None,
        "last_observed_at": max(timestamps) if timestamps else None,
        "duplicate_observation_count": duplicate_count,
        "conflicting_observation_ids": sorted(set(conflicting_ids)),
        "double_count_protection": "OBSERVATION_ID_UNIQUENESS",
        "continuation_requires_live_revalidation": True,
    }


def validate_recovery_candidate_binding(
    attempt: Any,
    candidate: Any,
    *,
    current_target_id: str | None = None,
    current_code_hash: str | None = None,
    persisted_policy_fingerprint: str | None = None,
    current_policy_fingerprint: str | None = None,
    current_authority_policy_generation: int | str | None = None,
    current_authority_policy_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Check persisted candidate identity and optionally supplied live context.

    Persisted records can show what a repair was evaluated against, but they
    cannot re-authorize it after restart. When live values are omitted this
    function reports the exact revalidation requirements and remains invalid
    for execution purposes.
    """
    failures: list[str] = []
    for name in ("candidate_id", "episode_id", "incident_id", "target_id"):
        attempt_value = str(_field(attempt, name, ""))
        candidate_value = str(_field(candidate, name, ""))
        if not attempt_value or attempt_value != candidate_value:
            failures.append(f"PERSISTED_CONTEXT_MISMATCH:{name}")
    attempt_source_hash = _field(attempt, "base_source_hash")
    candidate_source_hash = _field(candidate, "base_source_hash")
    if (
        not attempt_source_hash
        or not candidate_source_hash
        or attempt_source_hash != candidate_source_hash
    ):
        failures.append("PERSISTED_CONTEXT_MISMATCH:base_source_hash")
    for name in ("authority_policy_generation", "authority_policy_fingerprint"):
        if _field(attempt, name) != _field(candidate, name):
            failures.append(f"PERSISTED_CONTEXT_MISMATCH:{name}")

    if not persisted_policy_fingerprint:
        failures.append("PERSISTED_POLICY_SNAPSHOT_UNAVAILABLE")
    required_live_context = {
        "target_id": current_target_id,
        "code_hash": current_code_hash,
        "policy_fingerprint": current_policy_fingerprint,
        "authority_policy_generation": current_authority_policy_generation,
        "authority_policy_fingerprint": current_authority_policy_fingerprint,
    }
    missing_live_context = [name for name, value in required_live_context.items() if value is None]
    live_failures: list[str] = []
    if current_target_id is not None and str(current_target_id) != str(_field(attempt, "target_id", "")):
        live_failures.append("LIVE_CONTEXT_MISMATCH:target_id")
    if current_code_hash is not None and current_code_hash != _field(attempt, "base_source_hash"):
        live_failures.append("LIVE_CONTEXT_MISMATCH:code_hash")
    if (
        current_policy_fingerprint is not None
        and persisted_policy_fingerprint is not None
        and current_policy_fingerprint != persisted_policy_fingerprint
    ):
        live_failures.append("LIVE_CONTEXT_MISMATCH:policy_fingerprint")
    if (
        current_authority_policy_generation is not None
        and str(current_authority_policy_generation)
        != str(_field(attempt, "authority_policy_generation"))
    ):
        live_failures.append("LIVE_CONTEXT_MISMATCH:authority_policy_generation")
    if (
        current_authority_policy_fingerprint is not None
        and current_authority_policy_fingerprint
        != _field(attempt, "authority_policy_fingerprint")
    ):
        live_failures.append("LIVE_CONTEXT_MISMATCH:authority_policy_fingerprint")
    return {
        "persisted_binding_valid": not failures,
        "live_context_valid": not live_failures and not missing_live_context,
        "execution_valid": not failures and not live_failures and not missing_live_context,
        "failures": failures + live_failures,
        "missing_live_context": missing_live_context,
        "policy_snapshot_id": str(_field(attempt, "policy_snapshot_id", "")),
        "persisted_policy_fingerprint": persisted_policy_fingerprint,
        "policy_snapshot_revalidation_required": (
            not persisted_policy_fingerprint or current_policy_fingerprint is None
        ),
        "authority_granted": False,
    }


def _candidate_binding_for_attempt(
    store: Any,
    attempt: Any,
    *,
    live_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    candidates = _records_by_id(store, "all_candidates", "candidate_id")
    candidate = candidates.get(str(_field(attempt, "candidate_id", "")))
    if candidate is not None:
        context = dict(live_context or {})
        policies = _records_by_id(store, "all_policies", "policy_snapshot_id")
        policy = policies.get(str(_field(attempt, "policy_snapshot_id", "")))
        return validate_recovery_candidate_binding(
            attempt,
            candidate,
            current_target_id=context.get("target_id"),
            current_code_hash=context.get("code_hash"),
            persisted_policy_fingerprint=(
                _field(policy, "fingerprint") if policy is not None else None
            ),
            current_policy_fingerprint=context.get("policy_fingerprint"),
            current_authority_policy_generation=context.get("authority_policy_generation"),
            current_authority_policy_fingerprint=context.get("authority_policy_fingerprint"),
        )
    return {
        "persisted_binding_valid": False,
        "live_context_valid": False,
        "execution_valid": False,
        "failures": ["CANDIDATE_RECORD_UNAVAILABLE"],
        "missing_live_context": [
            "target_id",
            "code_hash",
            "policy_fingerprint",
            "authority_policy_generation",
            "authority_policy_fingerprint",
        ],
        "policy_snapshot_id": str(_field(attempt, "policy_snapshot_id", "")),
        "policy_snapshot_revalidation_required": True,
        "authority_granted": False,
    }


def _incomplete_lifecycle_records(store: Any, attempt: Any) -> tuple[dict[str, Any], ...]:
    """Project linked lifecycle state without mutating source evidence."""
    records: list[dict[str, Any]] = []
    incident_id = str(_field(attempt, "incident_id", ""))
    if incident_id:
        records.append({
            "record_type": "incident",
            "record_id": incident_id,
            "state": "INCOMPLETE_REPAIR",
            "reason": "linked Repair attempt did not durably complete",
        })

    episode_id = str(_field(attempt, "episode_id", ""))
    episodes = _records_by_id(store, "all_episodes", "episode_id")
    episode = episodes.get(episode_id)
    if episode_id:
        records.append({
            "record_type": "episode",
            "record_id": episode_id,
            "state": "INCOMPLETE_REPAIR",
            "completed_at": (
                _field(episode, "completed_at").isoformat()
                if isinstance(_field(episode, "completed_at"), datetime)
                else _field(episode, "completed_at")
            ) if episode is not None else None,
            "source_present": episode is not None,
        })
    approval_pending = (
        _enum_name(_field(attempt, "outcome")) == RepairAttemptOutcome.AWAITING_APPROVAL.name
        or (
            episode is not None
            and _enum_name(_field(episode, "outcome"))
            == RepairEpisodeOutcome.AWAITING_APPROVAL.name
        )
    )
    if approval_pending:
        records.append({
            "record_type": "approval",
            "record_id": episode_id or str(_field(attempt, "attempt_id", "")),
            "state": "STALE_AFTER_RESTART",
            "candidate_id": str(_field(attempt, "candidate_id", "")),
            "reason": (
                "Pending approval was process-local and must be reviewed again "
                "in a new transaction"
            ),
        })

    candidate_id = str(_field(attempt, "candidate_id", ""))
    candidates = _records_by_id(store, "all_candidates", "candidate_id")
    candidate = candidates.get(candidate_id)
    generation_id = str(_field(candidate, "generation_id", "")) if candidate is not None else ""
    generations = _records_by_id(store, "all_generations", "generation_id")
    generation = generations.get(generation_id)
    if generation_id:
        records.append({
            "record_type": "generation",
            "record_id": generation_id,
            "state": "INCOMPLETE_REPAIR",
            "completed_at": (
                _field(generation, "completed_at").isoformat()
                if isinstance(_field(generation, "completed_at"), datetime)
                else _field(generation, "completed_at")
            ) if generation is not None else None,
            "source_present": generation is not None,
        })

    stage = _enum_name(_field(attempt, "stage"))
    validation_stages = {
        RepairAttemptStage.VALIDATION.name,
        RepairAttemptStage.SCORING.name,
        RepairAttemptStage.ACTIVATION.name,
        RepairAttemptStage.RETRY.name,
        RepairAttemptStage.OBSERVATION.name,
    }
    records.append({
        "record_type": "validation",
        "record_id": str(_field(attempt, "attempt_id", "")),
        "state": "INCOMPLETE" if stage in validation_stages else "NOT_STARTED",
        "last_milestone": stage or RepairAttemptStage.CREATED.name,
        "persisted_check_count": len(_field(attempt, "validation_results", ()) or ()),
    })
    return tuple(records)


def build_repair_recovery_plan(
    store: Any,
    *,
    target_id: str | None = None,
    now: datetime | None = None,
    policy: RepairRecoveryPolicy | None = None,
    live_context_by_target: Mapping[str, Mapping[str, Any]] | None = None,
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
    validate_worker_acceptance_policy(recovery_policy.worker_acceptance)
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
        incomplete_records = _incomplete_lifecycle_records(store, attempt)
        candidate_binding = _candidate_binding_for_attempt(
            store,
            attempt,
            live_context=(
                live_context_by_target or {}
            ).get(str(_field(attempt, "target_id", ""))),
        )
        observation_recovery = recover_candidate_observation_state(
            store,
            target_id=str(_field(attempt, "target_id", "")),
            candidate_id=str(_field(attempt, "candidate_id", "")),
        )
        policy_action = select_recovery_action(
            recovery_policy.interrupted_transaction_action,
            enabled=recovery_policy.enabled,
        )
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
            "policy_action_status": policy_action["status"],
            "policy_action": policy_action,
            "authority_action": "REVALIDATE_BEFORE_ANY_CONTINUATION",
            "candidate_reactivation_allowed": False,
            "approval_survives_restart": False,
            "candidate_binding": candidate_binding,
            "approval_state": (
                "STALE_AFTER_RESTART"
                if any(item.get("record_type") == "approval" for item in incomplete_records)
                else "NOT_PENDING"
            ),
            "incomplete_records": list(incomplete_records),
            "observation_recovery": observation_recovery,
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
            "worker_acceptance": {
                "probation_successful_executions": (
                    recovery_policy.worker_acceptance.probation_successful_executions
                ),
                "probation_failure_budget": (
                    recovery_policy.worker_acceptance.probation_failure_budget
                ),
                "acceptance_successful_executions": (
                    recovery_policy.worker_acceptance.acceptance_successful_executions
                ),
                "acceptance_failure_budget": (
                    recovery_policy.worker_acceptance.acceptance_failure_budget
                ),
                "per_target_overrides": {
                    str(target): {
                        "probation_successful_executions": override.probation_successful_executions,
                        "probation_failure_budget": override.probation_failure_budget,
                        "acceptance_successful_executions": override.acceptance_successful_executions,
                        "acceptance_failure_budget": override.acceptance_failure_budget,
                    }
                    for target, override in recovery_policy.worker_acceptance.per_target_overrides.items()
                },
            },
        },
        "incomplete_attempt_count": len(decisions),
        "incomplete_lifecycle_record_count": sum(
            len(decision["incomplete_records"]) for decision in decisions
        ),
        "decisions": decisions,
    }


def apply_repair_recovery_plan(
    store: Any,
    plan: Mapping[str, Any],
    *,
    now: datetime | None = None,
    handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]] | None = None,
) -> dict[str, Any]:
    """Acknowledge recovery decisions and optionally dispatch app callbacks.

    This operation does not activate, delete, or rewrite a candidate, attempt,
    incident, or policy record. Reapplying the same plan is idempotent by
    ``attempt_id``. Handlers are application-owned callbacks and must return
    ``{"accepted": True}`` before a dispatched action is recorded as executed;
    missing or rejected handlers remain explicit evidence in the record.
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
    action_results: list[dict[str, Any]] = []
    for decision in decisions:
        if not isinstance(decision, Mapping):
            raise ValueError("Repair recovery decision must be an object")
        attempt_id = str(decision.get("attempt_id") or "")
        if not attempt_id:
            raise ValueError("Repair recovery decision requires attempt_id")
        if attempt_id in existing:
            skipped += 1
            continue
        action_execution = dispatch_recovery_action(decision, handlers=handlers)
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
            incomplete_records=tuple(
                item for item in (decision.get("incomplete_records") or ())
                if isinstance(item, Mapping)
            ),
            policy_action=(
                dict(decision.get("policy_action"))
                if isinstance(decision.get("policy_action"), Mapping)
                else {}
            ),
            action_execution=action_execution,
        )
        store.record_recovery(record)
        existing.add(attempt_id)
        applied += 1
        action_results.append({
            "attempt_id": attempt_id,
            **action_execution,
        })
    return {
        "schema_version": RECOVERY_PLAN_SCHEMA_VERSION,
        "applied_count": applied,
        "already_recorded_count": skipped,
        "read_only": False,
        "source_evidence_modified": False,
        "automatic_reactivation": False,
        "action_results": action_results,
    }
