"""Fail-safe inspection of persisted Repair work after a process restart.

The current application-scoped recovery contract does not reactivate an in-memory
replacement. This module produces an explicit recovery plan for incomplete
attempts so an operator or future supervisor can reconcile them without treating
an interrupted transaction as successful work.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import Enum, auto
import hashlib
import json
from typing import Any, Callable
from uuid import UUID, uuid4

from .domain import RepairAttemptOutcome, RepairAttemptStage, RepairEpisodeOutcome, utcnow


RECOVERY_PLAN_SCHEMA_VERSION = 1


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
    return {
        "status": "EXECUTED",
        "action": selected,
        "authority_granted": False,
        "handler_result": dict(result),
    }


def create_worker_failure_record(
    envelope: Mapping[str, Any],
    *,
    observed_at: datetime | None = None,
) -> WorkerFailureRecord:
    """Create a data-only durable record from a bounded failure envelope."""
    if not isinstance(envelope, Mapping):
        raise TypeError("worker failure envelope must be a mapping")
    worker_id = str(envelope.get("worker_id") or "")
    worker_kind = str(envelope.get("worker_kind") or "")
    if not worker_id or not worker_kind:
        raise ValueError("worker failure envelope requires worker identity")
    return WorkerFailureRecord(
        failure_id=uuid4(),
        worker_id=worker_id,
        worker_kind=worker_kind,
        observed_at=observed_at or utcnow(),
        detail_level=str(envelope.get("detail_level") or "STANDARD"),
        transaction_state=str(envelope.get("transaction_state") or "ROLLED_BACK"),
        envelope=dict(envelope),
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
