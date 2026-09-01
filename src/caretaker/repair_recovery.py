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
RECOVERY_LIFECYCLE_SCHEMA_VERSION = 1
WORKER_POSTMORTEM_MAX_BYTES = 1_048_576
WORKER_FAILURE_SCOPE_MAX_CHARS = 256
WORKER_FAILURE_STATUS_MAX_LIMIT = 500
COMPARISON_WORKER_ASSIGNMENT_MAX_BYTES = 64 * 1024
COMPARISON_WORKER_EVIDENCE_MAX_BYTES = 256 * 1024
COMPARISON_WORKER_MAX_EVIDENCE_REFS = 64
COMPARISON_WORKER_MAX_EVIDENCE_REF_CHARS = 256
COMPARISON_WORKER_MAX_KIND_CHARS = 64
COMPARISON_WORKER_MAX_BASELINE_SIGNATURES = 128
COMPARISON_WORKER_MAX_METRICS = 64
COMPARISON_WORKER_MAX_RECONCILIATION_REPORTS = 128
WORKER_EVIDENCE_JOIN_MAX_RECORDS = 256
_WORKER_POSTMORTEM_REQUIRED_EVIDENCE = (
    "milestone",
    "partial_queue",
    "policy_state",
)
_WORKER_POSTMORTEM_CONTEXT_FIELDS = (
    "worker_kind",
    "target_id",
    "transaction_id",
    "episode_id",
    "attempt_id",
    "generation_id",
    "code_hash",
    "policy_fingerprint",
    "authority_policy_generation",
    "authority_policy_fingerprint",
    "transaction_state",
)


class RecoveryAction(Enum):
    """Policy-selected response vocabulary for interrupted Repair work."""

    CONTINUE_DEGRADED = auto()
    GENERATE_INCIDENT = auto()
    REPLACE_WORKER = auto()
    STOP_APPLICATION = auto()
    ROLLBACK_TO_DEPLOYED_CODE = auto()


class RecoveryPlanStaleError(ValueError):
    """Raised when an acknowledgement plan no longer matches its source."""


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


@dataclass(frozen=True, slots=True)
class ComparisonWorkerAssignment:
    """Bounded supervisor work assignment for an independent evidence check.

    The assignment is evidence routing, not an authority grant. The worker
    must receive and independently verify the referenced
    ``RecoveryAuthorityPacket`` before doing any work. Its expiry is never
    later than that packet's expiry.
    """

    assignment_id: UUID
    scope: str
    target_id: str
    generation_id: str
    code_hash: str
    policy_fingerprint: str
    authority_policy_generation: str
    authority_policy_fingerprint: str
    worker_kind: str
    authority_packet_id: UUID
    evidence_refs: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    content_sha256: str
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class ComparisonWorkerResult:
    """Content-addressed, non-authoritative evidence from a comparison worker."""

    result_id: UUID
    assignment_id: UUID
    worker_id: str
    status: str
    evidence: Mapping[str, Any]
    observed_at: datetime
    content_sha256: str
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class ComparisonWorkerComparisonReport:
    """Read-only statistical comparison of one worker result and its peers."""

    comparison_id: UUID
    assignment_id: UUID
    result_id: UUID
    scope: str
    status: str
    baseline_count: int
    source_ids: tuple[str, ...]
    minimum_sample_count: int
    z_threshold: float
    metrics: Mapping[str, Any]
    outliers: tuple[Mapping[str, Any], ...]
    reasons: tuple[str, ...]
    compared_at: datetime
    content_sha256: str
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class ComparisonWorkerReconciliationReport:
    """Read-only consolidation of independently produced comparisons.

    This report summarizes reports without merging their already-aggregated
    metrics. Independent reports may share the same baseline, so averaging
    their metrics here would double-count evidence. Context validation is
    therefore required before the reports are classified as agreement or
    conflict.
    """

    reconciliation_id: UUID
    scope: str
    assignment_ids: tuple[str, ...]
    report_ids: tuple[str, ...]
    result_ids: tuple[str, ...]
    status: str
    report_count: int
    unique_report_count: int
    conflict_report_count: int
    incomplete_report_count: int
    metric_names: tuple[str, ...]
    outliers: tuple[Mapping[str, Any], ...]
    reasons: tuple[str, ...]
    reconciled_at: datetime
    content_sha256: str
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class WorkerEvidenceJoinReport:
    """Evidence-only join between post-mortem and comparison reconciliation."""

    join_id: UUID
    scope: str
    target_ids: tuple[str, ...]
    postmortem_record_ids: tuple[str, ...]
    postmortem_packet_hashes: tuple[str, ...]
    comparison_report_ids: tuple[str, ...]
    comparison_result_ids: tuple[str, ...]
    postmortem_status: str
    comparison_status: str
    status: str
    postmortem_conflict: bool
    comparison_conflict: bool
    reasons: tuple[str, ...]
    joined_at: datetime
    content_sha256: str
    schema_version: int = 1


def _comparison_assignment_payload(
    assignment: ComparisonWorkerAssignment | Mapping[str, Any],
) -> dict[str, Any]:
    def value(name: str, default: Any = None) -> Any:
        return assignment.get(name, default) if isinstance(assignment, Mapping) else getattr(assignment, name, default)

    return {
        "assignment_id": str(value("assignment_id")),
        "scope": str(value("scope")),
        "target_id": str(value("target_id")),
        "generation_id": str(value("generation_id")),
        "code_hash": str(value("code_hash")),
        "policy_fingerprint": str(value("policy_fingerprint")),
        "authority_policy_generation": str(value("authority_policy_generation")),
        "authority_policy_fingerprint": str(value("authority_policy_fingerprint")),
        "worker_kind": str(value("worker_kind")),
        "authority_packet_id": str(value("authority_packet_id")),
        "evidence_refs": [str(item) for item in (value("evidence_refs", ()) or ())],
        "issued_at": (
            value("issued_at").isoformat()
            if isinstance(value("issued_at"), datetime)
            else str(value("issued_at"))
        ),
        "expires_at": (
            value("expires_at").isoformat()
            if isinstance(value("expires_at"), datetime)
            else str(value("expires_at"))
        ),
        "schema_version": int(value("schema_version", 1)),
    }


def _comparison_result_payload(
    result: ComparisonWorkerResult | Mapping[str, Any],
) -> dict[str, Any]:
    def value(name: str, default: Any = None) -> Any:
        return result.get(name, default) if isinstance(result, Mapping) else getattr(result, name, default)

    return {
        "result_id": str(value("result_id")),
        "assignment_id": str(value("assignment_id")),
        "worker_id": str(value("worker_id")),
        "status": str(value("status")),
        "evidence": value("evidence", {}),
        "observed_at": (
            value("observed_at").isoformat()
            if isinstance(value("observed_at"), datetime)
            else str(value("observed_at"))
        ),
        "schema_version": int(value("schema_version", 1)),
    }


def _comparison_report_payload(
    report: ComparisonWorkerComparisonReport,
) -> dict[str, Any]:
    return {
        "comparison_id": str(report.comparison_id),
        "assignment_id": str(report.assignment_id),
        "result_id": str(report.result_id),
        "scope": report.scope,
        "status": report.status,
        "baseline_count": report.baseline_count,
        "source_ids": list(report.source_ids),
        "minimum_sample_count": report.minimum_sample_count,
        "z_threshold": report.z_threshold,
        "metrics": report.metrics,
        "outliers": list(report.outliers),
        "reasons": list(report.reasons),
        "compared_at": report.compared_at.isoformat(),
        "schema_version": report.schema_version,
    }


def _comparison_report_value(
    report: ComparisonWorkerComparisonReport | Mapping[str, Any],
    name: str,
    default: Any = None,
) -> Any:
    if isinstance(report, Mapping):
        return report.get(name, default)
    return getattr(report, name, default)


def _comparison_report_payload_from_value(
    report: ComparisonWorkerComparisonReport | Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "comparison_id": str(_comparison_report_value(report, "comparison_id", "")),
        "assignment_id": str(_comparison_report_value(report, "assignment_id", "")),
        "result_id": str(_comparison_report_value(report, "result_id", "")),
        "scope": str(_comparison_report_value(report, "scope", "")),
        "status": str(_comparison_report_value(report, "status", "")),
        "baseline_count": int(_comparison_report_value(report, "baseline_count", 0) or 0),
        "source_ids": list(_comparison_report_value(report, "source_ids", ()) or ()),
        "minimum_sample_count": int(
            _comparison_report_value(report, "minimum_sample_count", 0) or 0
        ),
        "z_threshold": float(_comparison_report_value(report, "z_threshold", 0.0) or 0.0),
        "metrics": _comparison_report_value(report, "metrics", {}),
        "outliers": list(_comparison_report_value(report, "outliers", ()) or ()),
        "reasons": list(_comparison_report_value(report, "reasons", ()) or ()),
        "compared_at": (
            _comparison_report_value(report, "compared_at").isoformat()
            if isinstance(_comparison_report_value(report, "compared_at"), datetime)
            else str(_comparison_report_value(report, "compared_at", ""))
        ),
        "schema_version": int(_comparison_report_value(report, "schema_version", 1)),
    }


def _comparison_reconciliation_content_payload(
    report: ComparisonWorkerReconciliationReport,
) -> dict[str, Any]:
    return {
        "reconciliation_id": str(report.reconciliation_id),
        "scope": report.scope,
        "assignment_ids": list(report.assignment_ids),
        "report_ids": list(report.report_ids),
        "result_ids": list(report.result_ids),
        "status": report.status,
        "report_count": report.report_count,
        "unique_report_count": report.unique_report_count,
        "conflict_report_count": report.conflict_report_count,
        "incomplete_report_count": report.incomplete_report_count,
        "metric_names": list(report.metric_names),
        "outliers": list(report.outliers),
        "reasons": list(report.reasons),
        "reconciled_at": report.reconciled_at.isoformat(),
        "schema_version": report.schema_version,
    }


def verify_comparison_worker_reconciliation_report(
    report: ComparisonWorkerReconciliationReport | Mapping[str, Any],
) -> dict[str, Any]:
    """Verify one consolidated comparison report as evidence only."""
    failures: list[str] = []
    reconciliation_id = str(
        _comparison_report_value(report, "reconciliation_id", "")
    )
    stored_hash = str(_comparison_report_value(report, "content_sha256", ""))
    try:
        UUID(reconciliation_id)
    except (ValueError, AttributeError):
        failures.append("RECONCILIATION_ID_INVALID")
    if not stored_hash or len(stored_hash) != 64:
        failures.append("RECONCILIATION_CONTENT_HASH_MISSING")
    try:
        value = lambda name, default=None: _comparison_report_value(
            report, name, default
        )
        encoded = _comparison_json_bytes(
            {
                "reconciliation_id": reconciliation_id,
                "scope": str(value("scope", "")),
                "assignment_ids": list(value("assignment_ids", ()) or ()),
                "report_ids": list(value("report_ids", ()) or ()),
                "result_ids": list(value("result_ids", ()) or ()),
                "status": str(value("status", "")),
                "report_count": int(value("report_count", 0) or 0),
                "unique_report_count": int(value("unique_report_count", 0) or 0),
                "conflict_report_count": int(value("conflict_report_count", 0) or 0),
                "incomplete_report_count": int(value("incomplete_report_count", 0) or 0),
                "metric_names": list(value("metric_names", ()) or ()),
                "outliers": list(value("outliers", ()) or ()),
                "reasons": list(value("reasons", ()) or ()),
                "reconciled_at": (
                    value("reconciled_at").isoformat()
                    if isinstance(value("reconciled_at"), datetime)
                    else str(value("reconciled_at", ""))
                ),
                "schema_version": int(value("schema_version", 1)),
            },
            limit=COMPARISON_WORKER_EVIDENCE_MAX_BYTES,
            label="comparison reconciliation report",
        )
        calculated_hash = hashlib.sha256(encoded).hexdigest()
    except (TypeError, ValueError):
        calculated_hash = ""
        failures.append("RECONCILIATION_CONTENT_INVALID")
    if stored_hash and calculated_hash and stored_hash != calculated_hash:
        failures.append("RECONCILIATION_CONTENT_HASH_MISMATCH")
    return {
        "valid": not failures,
        "authority_granted": False,
        "reconciliation_id": reconciliation_id,
        "scope": str(_comparison_report_value(report, "scope", "")),
        "status": str(_comparison_report_value(report, "status", "")),
        "content_sha256": stored_hash,
        "failures": tuple(dict.fromkeys(failures)),
    }


def verify_comparison_worker_comparison_report(
    report: ComparisonWorkerComparisonReport | Mapping[str, Any],
) -> dict[str, Any]:
    """Verify one stored comparison report without treating it as authority."""
    failures: list[str] = []
    report_id = str(_comparison_report_value(report, "comparison_id", ""))
    stored_hash = str(_comparison_report_value(report, "content_sha256", ""))
    if not report_id:
        failures.append("COMPARISON_ID_MISSING")
    try:
        UUID(report_id)
    except (ValueError, AttributeError):
        failures.append("COMPARISON_ID_INVALID")
    if not stored_hash or len(stored_hash) != 64:
        failures.append("COMPARISON_CONTENT_HASH_MISSING")
    try:
        encoded = _comparison_json_bytes(
            _comparison_report_payload_from_value(report),
            limit=COMPARISON_WORKER_EVIDENCE_MAX_BYTES,
            label="comparison report",
        )
        calculated_hash = hashlib.sha256(encoded).hexdigest()
    except (TypeError, ValueError):
        calculated_hash = ""
        failures.append("COMPARISON_CONTENT_INVALID")
    if stored_hash and calculated_hash and stored_hash != calculated_hash:
        failures.append("COMPARISON_CONTENT_HASH_MISMATCH")
    return {
        "valid": not failures,
        "authority_granted": False,
        "comparison_id": report_id,
        "assignment_id": str(_comparison_report_value(report, "assignment_id", "")),
        "result_id": str(_comparison_report_value(report, "result_id", "")),
        "scope": str(_comparison_report_value(report, "scope", "")),
        "status": str(_comparison_report_value(report, "status", "")),
        "content_sha256": stored_hash,
        "failures": tuple(dict.fromkeys(failures)),
    }


def reconcile_comparison_worker_reports(
    reports: Sequence[ComparisonWorkerComparisonReport | Mapping[str, Any]],
    *,
    assignment_contexts: Sequence[ComparisonWorkerAssignment | Mapping[str, Any]] = (),
    reconciled_at: datetime | None = None,
) -> ComparisonWorkerReconciliationReport:
    """Consolidate independent comparison reports without double-counting.

    Reports from distinct assignments may only be combined when their supplied
    assignment contexts agree on target, generation, code, policy, authority,
    worker kind, and scope. A missing context is incomplete evidence rather
    than an implicit match. The resulting report is evidence only.
    """
    if isinstance(reports, (str, bytes)) or not isinstance(reports, Sequence):
        raise TypeError("comparison reports must be a sequence")
    if len(reports) > COMPARISON_WORKER_MAX_RECONCILIATION_REPORTS:
        raise ValueError(
            "comparison reports cannot contain more than "
            f"{COMPARISON_WORKER_MAX_RECONCILIATION_REPORTS} items"
        )
    if isinstance(assignment_contexts, (str, bytes)) or not isinstance(
        assignment_contexts, Sequence
    ):
        raise TypeError("assignment_contexts must be a sequence")

    reasons: list[str] = []
    valid_reports: list[ComparisonWorkerComparisonReport | Mapping[str, Any]] = []
    report_hashes: dict[str, str] = {}
    for index, report in enumerate(reports):
        if not isinstance(report, (ComparisonWorkerComparisonReport, Mapping)):
            reasons.append(f"report-{index}: report is not a mapping")
            continue
        verification = verify_comparison_worker_comparison_report(report)
        report_id = verification["comparison_id"]
        report_hash = verification["content_sha256"]
        if not verification["valid"]:
            reasons.extend(
                f"report-{index}: {failure}" for failure in verification["failures"]
            )
            continue
        previous_hash = report_hashes.get(report_id)
        if previous_hash is not None:
            if previous_hash != report_hash:
                reasons.append(f"report-{index}: duplicate ID has divergent content")
            continue
        report_hashes[report_id] = report_hash
        valid_reports.append(report)

    def context_value(context: ComparisonWorkerAssignment | Mapping[str, Any], name: str) -> Any:
        if isinstance(context, Mapping):
            return context.get(name)
        return getattr(context, name, None)

    context_by_assignment: dict[str, ComparisonWorkerAssignment | Mapping[str, Any]] = {}
    for index, context in enumerate(assignment_contexts):
        if not isinstance(context, (ComparisonWorkerAssignment, Mapping)):
            reasons.append(f"assignment-{index}: context is not a mapping")
            continue
        assignment_id = str(context_value(context, "assignment_id") or "")
        if not assignment_id:
            reasons.append(f"assignment-{index}: assignment ID is missing")
            continue
        if assignment_id in context_by_assignment:
            reasons.append(f"assignment-{index}: duplicate assignment context")
            continue
        context_by_assignment[assignment_id] = context

    report_ids = tuple(
        str(_comparison_report_value(report, "comparison_id", ""))
        for report in valid_reports
    )
    result_ids = tuple(
        str(_comparison_report_value(report, "result_id", ""))
        for report in valid_reports
    )
    assignment_ids = tuple(
        dict.fromkeys(
            str(_comparison_report_value(report, "assignment_id", ""))
            for report in valid_reports
        )
    )
    scopes = {
        str(_comparison_report_value(report, "scope", "")) for report in valid_reports
    }
    scope = next(iter(scopes), "")
    not_comparable = False
    if len(scopes) > 1:
        reasons.append("comparison reports have different reconciliation scopes")
        not_comparable = True

    comparable_context: tuple[Any, ...] | None = None
    for assignment_id in assignment_ids:
        context = context_by_assignment.get(assignment_id)
        if context is None:
            if len(assignment_ids) > 1:
                reasons.append(
                    f"assignment {assignment_id}: context is required for multi-assignment reconciliation"
                )
            continue
        context_scope = str(context_value(context, "scope") or "")
        if context_scope != scope:
            reasons.append(f"assignment {assignment_id}: scope does not match report")
            not_comparable = True
        context_identity = tuple(
            str(context_value(context, name) or "")
            for name in (
                "target_id",
                "generation_id",
                "code_hash",
                "policy_fingerprint",
                "authority_policy_generation",
                "authority_policy_fingerprint",
                "worker_kind",
                "scope",
            )
        )
        if comparable_context is None:
            comparable_context = context_identity
        elif context_identity != comparable_context:
            reasons.append(
                f"assignment {assignment_id}: target or authority context differs"
            )
            not_comparable = True

    statuses = {
        str(_comparison_report_value(report, "status", "")).upper()
        for report in valid_reports
    }
    conflict_reports = sum(
        1 for report in valid_reports
        if str(_comparison_report_value(report, "status", "")).upper() == "CONFLICT"
    )
    incomplete_reports = sum(
        1
        for report in valid_reports
        if str(_comparison_report_value(report, "status", "")).upper()
        in {"INCOMPLETE_EVIDENCE", "NOT_COMPARABLE"}
    )
    metric_names = tuple(
        sorted(
            {
                str(metric)
                for report in valid_reports
                for metric in (
                    _comparison_report_value(report, "metrics", {}) or {}
                )
                if isinstance(_comparison_report_value(report, "metrics", {}), Mapping)
            }
        )
    )
    outliers: list[Mapping[str, Any]] = []
    for report in valid_reports:
        report_id = str(_comparison_report_value(report, "comparison_id", ""))
        report_outliers = _comparison_report_value(report, "outliers", ()) or ()
        if isinstance(report_outliers, Sequence) and not isinstance(report_outliers, (str, bytes)):
            outliers.extend(
                {"comparison_id": report_id, **item}
                for item in report_outliers
                if isinstance(item, Mapping)
            )
    outliers = outliers[:COMPARISON_WORKER_MAX_BASELINE_SIGNATURES]

    if not valid_reports:
        status = "INCOMPLETE_EVIDENCE"
        reasons.append("no valid comparison reports were supplied")
    elif len(valid_reports) < 2:
        status = "INCOMPLETE_EVIDENCE"
        reasons.append("at least two valid comparison reports are required")
    elif len(assignment_ids) < 2:
        status = "INCOMPLETE_EVIDENCE"
        reasons.append("comparison reports must come from at least two assignments")
    elif not_comparable:
        status = "NOT_COMPARABLE"
    elif reasons:
        status = "INCOMPLETE_EVIDENCE"
    elif conflict_reports or "CONFLICT" in statuses:
        status = "CONFLICT"
    elif incomplete_reports or statuses - {"COMBINED"}:
        status = "INCOMPLETE_EVIDENCE"
        reasons.append("all reports must be COMBINED for agreement")
    else:
        status = "AGREEMENT"

    reconciliation_time = reconciled_at or utcnow()
    payload = {
        "scope": scope[:WORKER_FAILURE_SCOPE_MAX_CHARS],
        "assignment_ids": list(assignment_ids),
        "report_ids": list(report_ids),
        "result_ids": list(result_ids),
        "status": status,
        "report_count": len(reports),
        "unique_report_count": len(valid_reports),
        "conflict_report_count": conflict_reports,
        "incomplete_report_count": incomplete_reports,
        "metric_names": list(metric_names),
        "outliers": outliers,
        "reasons": list(dict.fromkeys(reason[:256] for reason in reasons))[:32],
        "reconciled_at": reconciliation_time.isoformat(),
    }
    encoded = _comparison_json_bytes(
        payload,
        limit=COMPARISON_WORKER_EVIDENCE_MAX_BYTES,
        label="comparison reconciliation report",
    )
    reconciliation_id = uuid5(
        NAMESPACE_URL,
        "caretaker:comparison-worker-reconciliation:" + hashlib.sha256(encoded).hexdigest(),
    )
    report = ComparisonWorkerReconciliationReport(
        reconciliation_id=reconciliation_id,
        scope=payload["scope"],
        assignment_ids=tuple(payload["assignment_ids"]),
        report_ids=tuple(payload["report_ids"]),
        result_ids=tuple(payload["result_ids"]),
        status=status,
        report_count=payload["report_count"],
        unique_report_count=payload["unique_report_count"],
        conflict_report_count=conflict_reports,
        incomplete_report_count=incomplete_reports,
        metric_names=tuple(metric_names),
        outliers=tuple(outliers),
        reasons=tuple(payload["reasons"]),
        reconciled_at=reconciliation_time,
        content_sha256="",
    )
    report_encoded = _comparison_json_bytes(
        _comparison_reconciliation_content_payload(report),
        limit=COMPARISON_WORKER_EVIDENCE_MAX_BYTES,
        label="comparison reconciliation report",
    )
    return replace(report, content_sha256=hashlib.sha256(report_encoded).hexdigest())


def _comparison_json_bytes(payload: Mapping[str, Any], *, limit: int, label: str) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be JSON-shaped") from exc
    if len(encoded) > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")
    return encoded


def create_comparison_worker_assignment(
    packet: RecoveryAuthorityPacket,
    *,
    scope: str,
    evidence_refs: Sequence[str] = (),
    supervisor_time: datetime,
    worker_kind: str = "REPAIR_ANALYZER",
    policy: RepairRecoveryPolicy | None = None,
) -> ComparisonWorkerAssignment:
    """Issue a bounded comparison assignment under an existing worker packet."""

    if not isinstance(packet, RecoveryAuthorityPacket):
        raise TypeError("comparison assignment requires a RecoveryAuthorityPacket")
    normalized_scope = str(scope or "").strip()
    if not normalized_scope or len(normalized_scope) > WORKER_FAILURE_SCOPE_MAX_CHARS:
        raise ValueError("comparison assignment scope must contain 1..256 characters")
    normalized_kind = str(worker_kind or "").strip()
    if not normalized_kind or len(normalized_kind) > COMPARISON_WORKER_MAX_KIND_CHARS:
        raise ValueError(
            "comparison assignment worker_kind must contain 1..64 characters"
        )
    if isinstance(evidence_refs, (str, bytes)):
        raise TypeError("comparison assignment evidence_refs must be a sequence")
    if len(evidence_refs) > COMPARISON_WORKER_MAX_EVIDENCE_REFS:
        raise ValueError(
            f"comparison assignment cannot reference more than {COMPARISON_WORKER_MAX_EVIDENCE_REFS} items"
        )
    normalized_refs: list[str] = []
    for ref in evidence_refs:
        value = str(ref or "").strip()
        if not value or len(value) > COMPARISON_WORKER_MAX_EVIDENCE_REF_CHARS:
            raise ValueError("comparison assignment evidence references must be bounded")
        if value in normalized_refs:
            raise ValueError("comparison assignment evidence references must be unique")
        normalized_refs.append(value)
    packet_check = verify_recovery_authority_packet(
        packet,
        supervisor_time=supervisor_time,
        target_id=packet.target_id,
        generation_id=packet.generation_id,
        code_hash=packet.code_hash,
        policy_fingerprint=packet.policy_fingerprint,
        authority_policy_generation=packet.authority_policy_generation,
        authority_policy_fingerprint=packet.authority_policy_fingerprint,
        allowed_capabilities=set(packet.capabilities),
        policy=policy,
    )
    if not packet_check["valid"]:
        raise PermissionError(
            "comparison assignment packet rejected: "
            + ", ".join(str(item) for item in packet_check["failures"])
        )
    assignment = ComparisonWorkerAssignment(
        assignment_id=uuid4(),
        scope=normalized_scope,
        target_id=packet.target_id,
        generation_id=packet.generation_id,
        code_hash=packet.code_hash,
        policy_fingerprint=packet.policy_fingerprint,
        authority_policy_generation=packet.authority_policy_generation,
        authority_policy_fingerprint=packet.authority_policy_fingerprint,
        worker_kind=normalized_kind,
        authority_packet_id=packet.packet_id,
        evidence_refs=tuple(normalized_refs),
        issued_at=supervisor_time,
        expires_at=packet.expires_at,
        content_sha256="",
    )
    encoded = _comparison_json_bytes(
        _comparison_assignment_payload(assignment),
        limit=COMPARISON_WORKER_ASSIGNMENT_MAX_BYTES,
        label="comparison assignment",
    )
    return replace(assignment, content_sha256=hashlib.sha256(encoded).hexdigest())


def verify_comparison_worker_assignment(
    assignment: ComparisonWorkerAssignment | Mapping[str, Any],
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
    """Verify assignment integrity, exact context, packet identity, and expiry."""

    failures: list[str] = []
    payload = _comparison_assignment_payload(assignment)
    supplied_hash = str(
        assignment.get("content_sha256", "")
        if isinstance(assignment, Mapping)
        else getattr(assignment, "content_sha256", "")
    )
    encoded = _comparison_json_bytes(
        payload,
        limit=COMPARISON_WORKER_ASSIGNMENT_MAX_BYTES,
        label="comparison assignment",
    )
    if payload.get("schema_version") != 1:
        failures.append("UNSUPPORTED_ASSIGNMENT_SCHEMA")
    if hashlib.sha256(encoded).hexdigest() != supplied_hash:
        failures.append("ASSIGNMENT_CONTENT_HASH_MISMATCH")
    value = lambda name: assignment.get(name) if isinstance(assignment, Mapping) else getattr(assignment, name)
    for name, expected in {
        "target_id": str(target_id),
        "generation_id": str(generation_id),
        "code_hash": str(code_hash),
        "policy_fingerprint": str(policy_fingerprint),
        "authority_policy_generation": str(authority_policy_generation),
        "authority_policy_fingerprint": str(authority_policy_fingerprint),
    }.items():
        if str(value(name)) != expected:
            failures.append(f"CONTEXT_MISMATCH:{name}")
    if str(value("authority_packet_id")) != str(packet.packet_id):
        failures.append("AUTHORITY_PACKET_ID_MISMATCH")
    if str(value("worker_kind") or "").strip() == "":
        failures.append("WORKER_KIND_MISSING")
    refs = value("evidence_refs") or ()
    if not isinstance(refs, Sequence) or isinstance(refs, (str, bytes)):
        failures.append("EVIDENCE_REFS_INVALID")
    else:
        if len(refs) > COMPARISON_WORKER_MAX_EVIDENCE_REFS:
            failures.append("EVIDENCE_REFS_TOO_MANY")
        if len({str(item) for item in refs}) != len(refs):
            failures.append("EVIDENCE_REFS_NOT_UNIQUE")
    try:
        expires_at = value("expires_at")
        issued_at = value("issued_at")
        if not isinstance(expires_at, datetime):
            expires_at = datetime.fromisoformat(str(expires_at))
        if not isinstance(issued_at, datetime):
            issued_at = datetime.fromisoformat(str(issued_at))
        if expires_at > packet.expires_at:
            failures.append("ASSIGNMENT_EXPIRES_AFTER_PACKET")
        if issued_at < packet.issued_at:
            failures.append("ASSIGNMENT_ISSUED_BEFORE_PACKET")
        if issued_at > expires_at:
            failures.append("ASSIGNMENT_TIME_RANGE_INVALID")
        recovery_policy = policy or RepairRecoveryPolicy()
        if (issued_at - supervisor_time).total_seconds() > recovery_policy.clock_skew_tolerance_seconds:
            failures.append("CLOCK_SKEW_EXCEEDED")
        expiry = validate_authority_expiry(expires_at, supervisor_time=supervisor_time)
        if not expiry["valid"]:
            failures.append(str(expiry["failure"]))
    except (TypeError, ValueError):
        failures.append("ASSIGNMENT_TIME_INVALID")
    packet_check = verify_recovery_authority_packet(
        packet,
        supervisor_time=supervisor_time,
        target_id=target_id,
        generation_id=generation_id,
        code_hash=code_hash,
        policy_fingerprint=policy_fingerprint,
        authority_policy_generation=authority_policy_generation,
        authority_policy_fingerprint=authority_policy_fingerprint,
        allowed_capabilities=allowed_capabilities,
        policy=policy,
    )
    if not packet_check["valid"]:
        failures.extend(str(item) for item in packet_check["failures"])
    return {
        "valid": not failures,
        "assignment_id": str(value("assignment_id") or ""),
        "authority_packet_id": str(value("authority_packet_id") or ""),
        "expires_at": str(value("expires_at") or ""),
        "failures": tuple(dict.fromkeys(failures)),
        "authority_granted": False,
    }


def create_comparison_worker_result(
    assignment: ComparisonWorkerAssignment,
    *,
    worker_id: str,
    evidence: Mapping[str, Any],
    status: str = "COMPLETED",
    observed_at: datetime | None = None,
) -> ComparisonWorkerResult:
    """Create bounded, content-addressed evidence for one assignment."""

    if not isinstance(assignment, ComparisonWorkerAssignment):
        raise TypeError("comparison result requires a ComparisonWorkerAssignment")
    normalized_worker_id = str(worker_id or "").strip()
    if not normalized_worker_id or len(normalized_worker_id) > 256:
        raise ValueError("comparison result worker_id must contain 1..256 characters")
    normalized_status = str(status or "").strip().upper()
    if normalized_status not in {"COMPLETED", "FAILED", "INCOMPLETE"}:
        raise ValueError("comparison result status is unsupported")
    if not isinstance(evidence, Mapping):
        raise TypeError("comparison result evidence must be a mapping")
    result = ComparisonWorkerResult(
        result_id=uuid4(),
        assignment_id=assignment.assignment_id,
        worker_id=normalized_worker_id,
        status=normalized_status,
        evidence=dict(evidence),
        observed_at=observed_at or utcnow(),
        content_sha256="",
    )
    encoded = _comparison_json_bytes(
        _comparison_result_payload(result),
        limit=COMPARISON_WORKER_EVIDENCE_MAX_BYTES,
        label="comparison result evidence",
    )
    return replace(result, content_sha256=hashlib.sha256(encoded).hexdigest())


def verify_comparison_worker_result(
    result: ComparisonWorkerResult | Mapping[str, Any],
    *,
    assignment: ComparisonWorkerAssignment | Mapping[str, Any],
    worker_id: str | None = None,
    supervisor_time: datetime | None = None,
    policy: RepairRecoveryPolicy | None = None,
) -> dict[str, Any]:
    """Verify result structure and identity without treating evidence as authority."""

    failures: list[str] = []
    payload = _comparison_result_payload(result)
    supplied_hash = str(
        result.get("content_sha256", "")
        if isinstance(result, Mapping)
        else getattr(result, "content_sha256", "")
    )
    try:
        encoded = _comparison_json_bytes(
            payload,
            limit=COMPARISON_WORKER_EVIDENCE_MAX_BYTES,
            label="comparison result evidence",
        )
    except ValueError as exc:
        failures.append(str(exc))
        encoded = b""
    if payload.get("schema_version") != 1:
        failures.append("UNSUPPORTED_RESULT_SCHEMA")
    if encoded and hashlib.sha256(encoded).hexdigest() != supplied_hash:
        failures.append("RESULT_CONTENT_HASH_MISMATCH")
    assignment_id = assignment.get("assignment_id") if isinstance(assignment, Mapping) else assignment.assignment_id
    result_assignment_id = result.get("assignment_id") if isinstance(result, Mapping) else result.assignment_id
    if str(result_assignment_id) != str(assignment_id):
        failures.append("ASSIGNMENT_ID_MISMATCH")
    result_worker_id = str(result.get("worker_id") if isinstance(result, Mapping) else result.worker_id)
    if worker_id is not None and result_worker_id != str(worker_id):
        failures.append("WORKER_ID_MISMATCH")
    if not result_worker_id.strip() or len(result_worker_id) > 256:
        failures.append("WORKER_ID_INVALID")
    if str(payload.get("status") or "").upper() not in {"COMPLETED", "FAILED", "INCOMPLETE"}:
        failures.append("RESULT_STATUS_INVALID")
    evidence = payload.get("evidence")
    if not isinstance(evidence, Mapping):
        failures.append("RESULT_EVIDENCE_NOT_MAPPING")
    if supervisor_time is not None:
        try:
            observed_at = result.get("observed_at") if isinstance(result, Mapping) else result.observed_at
            if not isinstance(observed_at, datetime):
                observed_at = datetime.fromisoformat(str(observed_at))
            assignment_expires_at = (
                assignment.get("expires_at")
                if isinstance(assignment, Mapping)
                else assignment.expires_at
            )
            if not isinstance(assignment_expires_at, datetime):
                assignment_expires_at = datetime.fromisoformat(str(assignment_expires_at))
            assignment_issued_at = (
                assignment.get("issued_at")
                if isinstance(assignment, Mapping)
                else assignment.issued_at
            )
            if not isinstance(assignment_issued_at, datetime):
                assignment_issued_at = datetime.fromisoformat(str(assignment_issued_at))
            if observed_at < assignment_issued_at:
                failures.append("RESULT_OBSERVED_BEFORE_ASSIGNMENT")
            if observed_at > assignment_expires_at:
                failures.append("RESULT_OBSERVED_AFTER_ASSIGNMENT_EXPIRY")
            recovery_policy = policy or RepairRecoveryPolicy()
            if (observed_at - supervisor_time).total_seconds() > recovery_policy.clock_skew_tolerance_seconds:
                failures.append("CLOCK_SKEW_EXCEEDED")
        except (TypeError, ValueError):
            failures.append("RESULT_TIME_INVALID")
    return {
        "valid": not failures,
        "result_id": str(result.get("result_id") if isinstance(result, Mapping) else result.result_id),
        "assignment_id": str(result_assignment_id),
        "worker_id": result_worker_id,
        "status": str(payload.get("status") or ""),
        "failures": tuple(dict.fromkeys(failures)),
        "authority_granted": False,
    }


def compare_comparison_worker_result(
    result: ComparisonWorkerResult | Mapping[str, Any],
    *,
    assignment: ComparisonWorkerAssignment | Mapping[str, Any],
    baseline_signatures: Sequence[Mapping[str, Any]],
    minimum_sample_count: int = 30,
    z_threshold: float = 3.0,
    compared_at: datetime | None = None,
) -> ComparisonWorkerComparisonReport:
    """Compare a worker signature with bounded peer signatures.

    This is an evidence operation only. It never chooses a recovery action or
    changes policy. A signature is comparable only when every source has the
    same finite metric set and at least ``minimum_sample_count`` observations.
    """

    if isinstance(minimum_sample_count, bool) or not isinstance(minimum_sample_count, int):
        raise TypeError("minimum_sample_count must be an integer")
    if minimum_sample_count <= 0:
        raise ValueError("minimum_sample_count must be greater than zero")
    if isinstance(z_threshold, bool) or not isinstance(z_threshold, (int, float)):
        raise TypeError("z_threshold must be numeric")
    if not math.isfinite(float(z_threshold)) or float(z_threshold) <= 0:
        raise ValueError("z_threshold must be finite and greater than zero")
    result_check = verify_comparison_worker_result(
        result,
        assignment=assignment,
    )
    result_id = UUID(str(result_check["result_id"])) if result_check["result_id"] else uuid4()
    assignment_id = UUID(str(result_check["assignment_id"])) if result_check["assignment_id"] else uuid4()
    scope = str(
        assignment.get("scope") if isinstance(assignment, Mapping) else assignment.scope
    )
    worker_id = str(result_check["worker_id"])
    reasons: list[str] = []
    sources: list[tuple[str, int, Mapping[str, Any]]] = []

    if not result_check["valid"]:
        reasons.append("comparison worker result failed structural verification")
    result_evidence = (
        result.get("evidence", {})
        if isinstance(result, Mapping)
        else result.evidence
    )
    result_signature = (
        result_evidence.get("behavior_signature")
        if isinstance(result_evidence, Mapping)
        else None
    )
    if str(result_check["status"]).upper() != "COMPLETED":
        reasons.append("comparison worker result is not complete")
    if not isinstance(result_signature, Mapping):
        reasons.append("comparison worker result has no behavior_signature")
    else:
        sources.append((f"comparison:{worker_id}", 0, result_signature))

    if isinstance(baseline_signatures, (str, bytes)):
        raise TypeError("baseline_signatures must be a sequence of mappings")
    if len(baseline_signatures) > COMPARISON_WORKER_MAX_BASELINE_SIGNATURES:
        raise ValueError(
            f"baseline_signatures cannot contain more than {COMPARISON_WORKER_MAX_BASELINE_SIGNATURES} items"
        )
    for index, baseline in enumerate(baseline_signatures):
        if not isinstance(baseline, Mapping):
            reasons.append(f"baseline-{index}: signature source is not a mapping")
            continue
        signature = baseline.get("behavior_signature", baseline)
        if not isinstance(signature, Mapping):
            reasons.append(f"baseline-{index}: behavior_signature is missing")
            continue
        source_id = str(
            baseline.get("source_id")
            or baseline.get("worker_id")
            or f"baseline:{index}"
        ).strip()
        sources.append((source_id[:256], index + 1, signature))

    def valid_signature(signature: Mapping[str, Any], source_id: str) -> tuple[int, Mapping[str, Any]] | None:
        sample_count = signature.get("sample_count")
        metrics = signature.get("metrics")
        if isinstance(sample_count, bool) or not isinstance(sample_count, int) or sample_count < minimum_sample_count:
            reasons.append(f"{source_id}: insufficient sample_count")
            return None
        if not isinstance(metrics, Mapping) or not metrics or len(metrics) > COMPARISON_WORKER_MAX_METRICS:
            reasons.append(f"{source_id}: metrics are missing or exceed the bound")
            return None
        for metric_name, metric in metrics.items():
            if not isinstance(metric_name, str) or not metric_name.strip() or not isinstance(metric, Mapping):
                reasons.append(f"{source_id}: metric definition is invalid")
                return None
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
                reasons.append(f"{source_id}: metric {metric_name!r} is invalid")
                return None
        return sample_count, metrics

    valid_sources: list[tuple[str, int, Mapping[str, Any]]] = []
    for source_id, source_index, signature in sources:
        valid = valid_signature(signature, source_id)
        if valid is not None:
            valid_sources.append((source_id, valid[0], valid[1]))
    metric_names = (
        set(valid_sources[0][2])
        if valid_sources
        else set()
    )
    if valid_sources and any(set(metrics) != metric_names for _, _, metrics in valid_sources[1:]):
        reasons.append("behavior signatures have different metric sets")
    comparable = (
        not reasons
        and len(valid_sources) >= 2
        and bool(metric_names)
        and all(set(metrics) == metric_names for _, _, metrics in valid_sources)
    )
    combined_metrics: dict[str, dict[str, float | int]] = {}
    outliers: list[Mapping[str, Any]] = []
    if comparable:
        for metric_name in sorted(metric_names):
            observations = [
                (source_id, count, float(metrics[metric_name]["mean"]), float(metrics[metric_name]["standard_deviation"]))
                for source_id, count, metrics in valid_sources
            ]
            total = sum(item[1] for item in observations)
            combined_mean = sum(count * mean for _, count, mean, _ in observations) / total
            combined_variance = sum(
                count * (standard_deviation**2 + (mean - combined_mean) ** 2)
                for _, count, mean, standard_deviation in observations
            ) / total
            combined_metrics[metric_name] = {
                "sample_count": total,
                "mean": combined_mean,
                "standard_deviation": combined_variance**0.5,
            }
            for source_id, count, mean, standard_deviation in observations:
                other_count = total - count
                if other_count <= 0:
                    continue
                other_mean = sum(
                    other_count_item * other_mean_item
                    for other_source, other_count_item, other_mean_item, _ in observations
                    if other_source != source_id
                ) / other_count
                other_variance = sum(
                    other_count_item * (other_std**2 + (other_mean_item - other_mean) ** 2)
                    for other_source, other_count_item, other_mean_item, other_std in observations
                    if other_source != source_id
                ) / other_count
                standard_error = (
                    standard_deviation**2 / count + other_variance / other_count
                ) ** 0.5
                z_score = abs(mean - other_mean) / max(standard_error, 1e-9)
                if z_score > float(z_threshold):
                    outliers.append({
                        "source_id": source_id,
                        "metric": metric_name,
                        "z_score": z_score,
                        "z_threshold": float(z_threshold),
                        "sample_count": count,
                        "comparison_sample_count": other_count,
                    })
        status = "CONFLICT" if outliers else "COMBINED"
    else:
        status = "INCOMPLETE_EVIDENCE" if reasons else "NOT_COMPARABLE"
        if not reasons:
            reasons.append("at least two comparable signatures are required")

    assignment_id = UUID(str(
        assignment.get("assignment_id") if isinstance(assignment, Mapping) else assignment.assignment_id
    ))
    payload = {
        "assignment_id": str(assignment_id),
        "result_id": str(result_id),
        "scope": scope,
        "status": status,
        "baseline_count": max(0, len(valid_sources) - 1),
        "source_ids": [source_id for source_id, _, _ in valid_sources],
        "minimum_sample_count": minimum_sample_count,
        "z_threshold": float(z_threshold),
        "metrics": combined_metrics,
        "outliers": outliers[:COMPARISON_WORKER_MAX_BASELINE_SIGNATURES],
        "reasons": list(dict.fromkeys(reason[:256] for reason in reasons))[:32],
    }
    encoded = _comparison_json_bytes(payload, limit=COMPARISON_WORKER_EVIDENCE_MAX_BYTES, label="comparison report")
    comparison_id = uuid5(
        NAMESPACE_URL,
        "caretaker:comparison-worker-report:" + hashlib.sha256(encoded).hexdigest(),
    )
    report = ComparisonWorkerComparisonReport(
        comparison_id=comparison_id,
        assignment_id=assignment_id,
        result_id=result_id,
        scope=scope[:WORKER_FAILURE_SCOPE_MAX_CHARS],
        status=status,
        baseline_count=payload["baseline_count"],
        source_ids=tuple(payload["source_ids"]),
        minimum_sample_count=minimum_sample_count,
        z_threshold=float(z_threshold),
        metrics=combined_metrics,
        outliers=tuple(outliers[:COMPARISON_WORKER_MAX_BASELINE_SIGNATURES]),
        reasons=tuple(payload["reasons"]),
        compared_at=compared_at or utcnow(),
        content_sha256="",
    )
    report_encoded = _comparison_json_bytes(
        _comparison_report_payload(report),
        limit=COMPARISON_WORKER_EVIDENCE_MAX_BYTES,
        label="comparison report",
    )
    return replace(report, content_sha256=hashlib.sha256(report_encoded).hexdigest())


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
class RepairRecoveryLifecycleMark:
    """Immutable evidence that one linked Repair record is incomplete.

    Lifecycle marks are a recovery ledger, not updates to the source records.
    They make the interrupted state durable for a restarted process while
    preserving the source attempt, incident, and policy evidence exactly as it
    was written.  A mark is content-addressed so a retry cannot create a
    second state transition for the same interrupted record.
    """

    marker_id: UUID
    attempt_id: str
    record_type: str
    record_id: str
    state: str
    last_milestone: str
    observed_at: datetime
    reason: str
    source_sha256: str
    schema_version: int = RECOVERY_LIFECYCLE_SCHEMA_VERSION


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


def _postmortem_context_comparison(
    packet_items: Sequence[tuple[str, Mapping[str, Any]]],
) -> dict[str, Any]:
    """Compare shared packet context without copying values into reports."""
    contexts: list[tuple[str, Mapping[str, Any]]] = []
    for packet_hash, packet in packet_items:
        envelope = packet.get("failure_envelope")
        if isinstance(envelope, Mapping):
            contexts.append((packet_hash, envelope))
    compared: dict[str, dict[str, str]] = {}
    differences: list[dict[str, Any]] = []
    for field_name in _WORKER_POSTMORTEM_CONTEXT_FIELDS:
        values: list[tuple[str, str]] = []
        for packet_hash, context in contexts:
            value = context.get(field_name)
            if value is None or value == "":
                values = []
                break
            try:
                encoded = json.dumps(
                    value,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            except (TypeError, ValueError):
                values = []
                break
            values.append((packet_hash, hashlib.sha256(encoded).hexdigest()))
        if not values:
            continue
        compared[field_name] = {packet_hash: value_hash for packet_hash, value_hash in values}
        if len({value_hash for _, value_hash in values}) > 1:
            differences.append(
                {
                    "field": field_name,
                    "packet_hashes": tuple(packet_hash for packet_hash, _ in values),
                    "value_hashes": tuple(value_hash for _, value_hash in values),
                }
            )
    return {
        "status": "CONFLICT" if differences else ("COMPARED" if compared else "NOT_COMPARABLE"),
        "fields": compared,
        "differences": differences,
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
    packet_context = _postmortem_context_comparison(packet_items)
    comparison["packet_context"] = packet_context
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
        elif packet_context["status"] == "CONFLICT":
            conflict_reason = "worker post-mortem packets have conflicting transaction context"
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
        "record_ids": tuple(
            [record_id for ids in record_ids_by_hash.values() for record_id in ids]
            + [item["record_id"] for item in invalid_records]
        ),
        "packet_hashes": tuple(packet_hash for packet_hash, _ in packet_items),
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


def join_worker_evidence_reconciliations(
    postmortem_reconciliation: Mapping[str, Any],
    comparison_reconciliation: ComparisonWorkerReconciliationReport | Mapping[str, Any],
    *,
    assignment_contexts: Sequence[ComparisonWorkerAssignment | Mapping[str, Any]] = (),
    joined_at: datetime | None = None,
) -> WorkerEvidenceJoinReport:
    """Join worker post-mortem and comparison evidence without merging it.

    The join is valid only when both reconcilers describe the same scope and
    the comparison assignments resolve to the post-mortem target identities.
    It retains references to both evidence sets; it never treats agreement as
    authority or combines their statistics a second time.
    """
    if not isinstance(postmortem_reconciliation, Mapping):
        raise TypeError("post-mortem reconciliation must be a mapping")
    comparison_check = verify_comparison_worker_reconciliation_report(
        comparison_reconciliation
    )
    reasons: list[str] = list(comparison_check["failures"])
    postmortem_scope = str(postmortem_reconciliation.get("scope") or "")
    comparison_scope = str(comparison_check.get("scope") or "")
    scope = postmortem_scope[:WORKER_FAILURE_SCOPE_MAX_CHARS]
    if not postmortem_scope:
        reasons.append("post-mortem reconciliation scope is missing")
    if not comparison_scope:
        reasons.append("comparison reconciliation scope is missing")
    if postmortem_scope != comparison_scope:
        reasons.append("post-mortem and comparison scopes differ")

    def value(record: Any, name: str, default: Any = None) -> Any:
        if isinstance(record, Mapping):
            return record.get(name, default)
        return getattr(record, name, default)

    def bounded_ids(values: Any) -> tuple[str, ...]:
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
            return ()
        return tuple(dict.fromkeys(str(item)[:256] for item in values if str(item)))[:WORKER_EVIDENCE_JOIN_MAX_RECORDS]

    target_ids = bounded_ids(postmortem_reconciliation.get("target_ids", ()))
    record_ids = bounded_ids(
        postmortem_reconciliation.get("record_ids", ())
    )
    packet_hashes = bounded_ids(
        postmortem_reconciliation.get("packet_hashes", ())
    )
    if not record_ids:
        conflict = postmortem_reconciliation.get("conflict_report")
        record_ids = bounded_ids(value(conflict, "record_ids", ()))
    if not packet_hashes:
        conflict = postmortem_reconciliation.get("conflict_report")
        packet_hashes = bounded_ids(value(conflict, "packet_hashes", ()))

    comparison_assignment_ids = bounded_ids(
        value(comparison_reconciliation, "assignment_ids", ())
    )
    comparison_report_ids = bounded_ids(
        value(comparison_reconciliation, "report_ids", ())
    )
    comparison_result_ids = bounded_ids(
        value(comparison_reconciliation, "result_ids", ())
    )
    if not assignment_contexts:
        reasons.append(
            "assignment contexts are required to bind comparison evidence to targets"
        )
    context_by_assignment: dict[str, Any] = {}
    for index, context in enumerate(assignment_contexts):
        if not isinstance(context, (ComparisonWorkerAssignment, Mapping)):
            reasons.append(f"assignment-{index}: context is not a mapping")
            continue
        assignment_id = str(value(context, "assignment_id") or "")
        if not assignment_id or assignment_id not in comparison_assignment_ids:
            reasons.append(f"assignment-{index}: context is not referenced by comparison")
            continue
        if assignment_id in context_by_assignment:
            reasons.append(f"assignment-{index}: duplicate assignment context")
            continue
        context_by_assignment[assignment_id] = context
        if str(value(context, "scope") or "") != comparison_scope:
            reasons.append(f"assignment {assignment_id}: scope does not match")
        context_target = str(value(context, "target_id") or "")
        if context_target and context_target not in target_ids:
            reasons.append(f"assignment {assignment_id}: target is not in post-mortem evidence")

    for assignment_id in comparison_assignment_ids:
        if assignment_id not in context_by_assignment:
            reasons.append(f"assignment {assignment_id}: context is missing")

    postmortem_comparison = postmortem_reconciliation.get("comparison", {})
    if not isinstance(postmortem_comparison, Mapping):
        postmortem_comparison = {}
    postmortem_status = str(postmortem_comparison.get("status") or "UNKNOWN")
    comparison_status = str(value(comparison_reconciliation, "status") or "UNKNOWN")
    postmortem_conflict = bool(postmortem_reconciliation.get("conflict"))
    comparison_conflict = comparison_status == "CONFLICT"
    if not comparison_check["valid"]:
        status = "INCOMPLETE_EVIDENCE"
    elif any(
        reason in {
            "post-mortem and comparison scopes differ",
        }
        or "target is not" in reason
        or "scope does not match" in reason
        for reason in reasons
    ):
        status = "NOT_COMPARABLE"
    elif postmortem_conflict or comparison_conflict:
        status = "CONFLICT"
    elif reasons:
        status = "INCOMPLETE_EVIDENCE"
    elif postmortem_status != "COMBINED":
        status = "INCOMPLETE_EVIDENCE"
        reasons.append("post-mortem evidence is not statistically combined")
    elif comparison_status != "AGREEMENT":
        status = "INCOMPLETE_EVIDENCE"
        reasons.append("comparison evidence is not in agreement")
    else:
        status = "AGREEMENT"

    joined_time = joined_at or utcnow()
    payload = {
        "scope": scope,
        "target_ids": list(target_ids),
        "postmortem_record_ids": list(record_ids),
        "postmortem_packet_hashes": list(packet_hashes),
        "comparison_report_ids": list(comparison_report_ids),
        "comparison_result_ids": list(comparison_result_ids),
        "postmortem_status": postmortem_status,
        "comparison_status": comparison_status,
        "status": status,
        "postmortem_conflict": postmortem_conflict,
        "comparison_conflict": comparison_conflict,
        "reasons": list(dict.fromkeys(reason[:256] for reason in reasons))[:32],
        "joined_at": joined_time.isoformat(),
    }
    encoded = _comparison_json_bytes(
        payload,
        limit=COMPARISON_WORKER_EVIDENCE_MAX_BYTES,
        label="worker evidence join report",
    )
    join_id = uuid5(
        NAMESPACE_URL,
        "caretaker:worker-evidence-join:" + hashlib.sha256(encoded).hexdigest(),
    )
    report = WorkerEvidenceJoinReport(
        join_id=join_id,
        scope=scope,
        target_ids=target_ids,
        postmortem_record_ids=record_ids,
        postmortem_packet_hashes=packet_hashes,
        comparison_report_ids=comparison_report_ids,
        comparison_result_ids=comparison_result_ids,
        postmortem_status=postmortem_status,
        comparison_status=comparison_status,
        status=status,
        postmortem_conflict=postmortem_conflict,
        comparison_conflict=comparison_conflict,
        reasons=tuple(payload["reasons"]),
        joined_at=joined_time,
        content_sha256="",
    )
    report_encoded = _comparison_json_bytes(
        {
            "join_id": str(report.join_id),
            **payload,
            "schema_version": report.schema_version,
        },
        limit=COMPARISON_WORKER_EVIDENCE_MAX_BYTES,
        label="worker evidence join report",
    )
    return replace(report, content_sha256=hashlib.sha256(report_encoded).hexdigest())


def verify_worker_evidence_join_report(
    report: WorkerEvidenceJoinReport | Mapping[str, Any],
) -> dict[str, Any]:
    """Verify a stored worker-evidence join report as read-only evidence."""
    value = lambda name, default=None: _comparison_report_value(report, name, default)
    join_id = str(value("join_id", ""))
    stored_hash = str(value("content_sha256", ""))
    failures: list[str] = []
    try:
        UUID(join_id)
    except (ValueError, AttributeError):
        failures.append("JOIN_ID_INVALID")
    if len(stored_hash) != 64:
        failures.append("JOIN_CONTENT_HASH_MISSING")
    try:
        encoded = _comparison_json_bytes(
            {
                "join_id": join_id,
                "scope": str(value("scope", "")),
                "target_ids": list(value("target_ids", ()) or ()),
                "postmortem_record_ids": list(value("postmortem_record_ids", ()) or ()),
                "postmortem_packet_hashes": list(value("postmortem_packet_hashes", ()) or ()),
                "comparison_report_ids": list(value("comparison_report_ids", ()) or ()),
                "comparison_result_ids": list(value("comparison_result_ids", ()) or ()),
                "postmortem_status": str(value("postmortem_status", "")),
                "comparison_status": str(value("comparison_status", "")),
                "status": str(value("status", "")),
                "postmortem_conflict": bool(value("postmortem_conflict", False)),
                "comparison_conflict": bool(value("comparison_conflict", False)),
                "reasons": list(value("reasons", ()) or ()),
                "joined_at": (
                    value("joined_at").isoformat()
                    if isinstance(value("joined_at"), datetime)
                    else str(value("joined_at", ""))
                ),
                "schema_version": int(value("schema_version", 1)),
            },
            limit=COMPARISON_WORKER_EVIDENCE_MAX_BYTES,
            label="worker evidence join report",
        )
        calculated_hash = hashlib.sha256(encoded).hexdigest()
    except (TypeError, ValueError):
        calculated_hash = ""
        failures.append("JOIN_CONTENT_INVALID")
    if stored_hash and calculated_hash and stored_hash != calculated_hash:
        failures.append("JOIN_CONTENT_HASH_MISMATCH")
    return {
        "valid": not failures,
        "authority_granted": False,
        "join_id": join_id,
        "scope": str(value("scope", "")),
        "status": str(value("status", "")),
        "content_sha256": stored_hash,
        "failures": tuple(dict.fromkeys(failures)),
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

    def comparison_assignment_summary(record: Any) -> dict[str, Any]:
        refs = _field(record, "evidence_refs", ()) or ()
        return {
            "assignment_id": bounded(_field(record, "assignment_id", ""), 64),
            "scope": bounded(_field(record, "scope", "")),
            "target_id": bounded(_field(record, "target_id", "")),
            "worker_kind": bounded(_field(record, "worker_kind", ""), 64),
            "authority_packet_id": bounded(
                _field(record, "authority_packet_id", ""), 64
            ),
            "issued_at": timestamp(_field(record, "issued_at")),
            "expires_at": timestamp(_field(record, "expires_at")),
            "evidence_ref_count": len(refs) if isinstance(refs, Sequence) else 0,
            "content_sha256": bounded(_field(record, "content_sha256", ""), 64),
        }

    def comparison_result_summary(record: Any) -> dict[str, Any]:
        return {
            "result_id": bounded(_field(record, "result_id", ""), 64),
            "assignment_id": bounded(_field(record, "assignment_id", ""), 64),
            "worker_id": bounded(_field(record, "worker_id", "")),
            "status": bounded(_field(record, "status", ""), 32),
            "observed_at": timestamp(_field(record, "observed_at")),
            "content_sha256": bounded(_field(record, "content_sha256", ""), 64),
        }

    def comparison_report_summary(record: Any) -> dict[str, Any]:
        outliers = _field(record, "outliers", ()) or ()
        return {
            "comparison_id": bounded(_field(record, "comparison_id", ""), 64),
            "assignment_id": bounded(_field(record, "assignment_id", ""), 64),
            "result_id": bounded(_field(record, "result_id", ""), 64),
            "scope": bounded(_field(record, "scope", "")),
            "status": bounded(_field(record, "status", ""), 32),
            "baseline_count": int(_field(record, "baseline_count", 0) or 0),
            "source_count": len(_field(record, "source_ids", ()) or ()),
            "outlier_count": len(outliers) if isinstance(outliers, Sequence) else 0,
            "compared_at": timestamp(_field(record, "compared_at")),
            "content_sha256": bounded(_field(record, "content_sha256", ""), 64),
        }

    def comparison_reconciliation_summary(record: Any) -> dict[str, Any]:
        outliers = _field(record, "outliers", ()) or ()
        return {
            "reconciliation_id": bounded(
                _field(record, "reconciliation_id", ""), 64
            ),
            "scope": bounded(_field(record, "scope", "")),
            "status": bounded(_field(record, "status", ""), 32),
            "report_count": int(_field(record, "report_count", 0) or 0),
            "unique_report_count": int(
                _field(record, "unique_report_count", 0) or 0
            ),
            "conflict_report_count": int(
                _field(record, "conflict_report_count", 0) or 0
            ),
            "incomplete_report_count": int(
                _field(record, "incomplete_report_count", 0) or 0
            ),
            "assignment_count": len(_field(record, "assignment_ids", ()) or ()),
            "result_count": len(_field(record, "result_ids", ()) or ()),
            "metric_count": len(_field(record, "metric_names", ()) or ()),
            "outlier_count": len(outliers) if isinstance(outliers, Sequence) else 0,
            "reconciled_at": timestamp(_field(record, "reconciled_at")),
            "content_sha256": bounded(_field(record, "content_sha256", ""), 64),
        }

    def worker_evidence_join_summary(record: Any) -> dict[str, Any]:
        return {
            "join_id": bounded(_field(record, "join_id", ""), 64),
            "scope": bounded(_field(record, "scope", "")),
            "status": bounded(_field(record, "status", ""), 32),
            "postmortem_status": bounded(
                _field(record, "postmortem_status", ""), 32
            ),
            "comparison_status": bounded(
                _field(record, "comparison_status", ""), 32
            ),
            "target_count": len(_field(record, "target_ids", ()) or ()),
            "postmortem_record_count": len(
                _field(record, "postmortem_record_ids", ()) or ()
            ),
            "comparison_report_count": len(
                _field(record, "comparison_report_ids", ()) or ()
            ),
            "postmortem_conflict": bool(
                _field(record, "postmortem_conflict", False)
            ),
            "comparison_conflict": bool(
                _field(record, "comparison_conflict", False)
            ),
            "joined_at": timestamp(_field(record, "joined_at")),
            "content_sha256": bounded(_field(record, "content_sha256", ""), 64),
        }

    failures = tuple(store.all_worker_failures())
    recoveries = tuple(store.all_worker_failure_recoveries())
    conflicts = tuple(store.all_worker_postmortem_conflicts())
    assignment_reader = getattr(store, "all_comparison_worker_assignments", None)
    result_reader = getattr(store, "all_comparison_worker_results", None)
    assignments = tuple(assignment_reader()) if callable(assignment_reader) else ()
    results = tuple(result_reader()) if callable(result_reader) else ()
    comparison_reader = getattr(store, "all_comparison_worker_comparisons", None)
    comparisons = tuple(comparison_reader()) if callable(comparison_reader) else ()
    reconciliation_reader = getattr(
        store, "all_comparison_worker_reconciliations", None
    )
    reconciliations = (
        tuple(reconciliation_reader())
        if callable(reconciliation_reader)
        else ()
    )
    join_reader = getattr(store, "all_worker_evidence_joins", None)
    joins = tuple(join_reader()) if callable(join_reader) else ()
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
        "comparison_assignment_count": len(assignments),
        "comparison_result_count": len(results),
        "comparison_report_count": len(comparisons),
        "comparison_reconciliation_count": len(reconciliations),
        "worker_evidence_join_count": len(joins),
        "comparison_assignments": [
            comparison_assignment_summary(item) for item in assignments[-limit:]
        ],
        "comparison_results": [
            comparison_result_summary(item) for item in results[-limit:]
        ],
        "comparison_reports": [
            comparison_report_summary(item) for item in comparisons[-limit:]
        ],
        "comparison_reconciliations": [
            comparison_reconciliation_summary(item)
            for item in reconciliations[-limit:]
        ],
        "worker_evidence_joins": [
            worker_evidence_join_summary(item) for item in joins[-limit:]
        ],
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


_RECOVERY_LIFECYCLE_RECORD_TYPES = frozenset(
    {"attempt", "incident", "episode", "generation", "validation", "approval"}
)
_RECOVERY_LIFECYCLE_STATES = frozenset(
    {"INCOMPLETE_REPAIR", "INCOMPLETE", "NOT_STARTED", "STALE_AFTER_RESTART"}
)


def create_recovery_lifecycle_mark(
    decision: Mapping[str, Any],
    lifecycle_record: Mapping[str, Any],
    *,
    observed_at: datetime | None = None,
) -> RepairRecoveryLifecycleMark:
    """Create one deterministic, bounded marker for interrupted lifecycle state."""
    if not isinstance(decision, Mapping) or not isinstance(lifecycle_record, Mapping):
        raise TypeError("recovery lifecycle inputs must be mappings")
    attempt_id = str(decision.get("attempt_id") or "").strip()
    record_type = str(lifecycle_record.get("record_type") or "").strip()
    record_id = str(lifecycle_record.get("record_id") or "").strip()
    state = str(lifecycle_record.get("state") or "").strip()
    milestone = str(
        lifecycle_record.get("last_milestone")
        or decision.get("last_milestone")
        or "CREATED"
    ).strip()
    reason = str(lifecycle_record.get("reason") or "interrupted Repair transaction").strip()
    if not attempt_id or len(attempt_id) > WORKER_FAILURE_SCOPE_MAX_CHARS:
        raise ValueError("recovery lifecycle marker requires a bounded attempt ID")
    if record_type not in _RECOVERY_LIFECYCLE_RECORD_TYPES:
        raise ValueError(f"unsupported recovery lifecycle record type: {record_type!r}")
    if not record_id or len(record_id) > WORKER_FAILURE_SCOPE_MAX_CHARS:
        raise ValueError("recovery lifecycle marker requires a bounded record ID")
    if state not in _RECOVERY_LIFECYCLE_STATES:
        raise ValueError(f"unsupported recovery lifecycle state: {state!r}")
    if not milestone or len(milestone) > WORKER_FAILURE_SCOPE_MAX_CHARS:
        raise ValueError("recovery lifecycle marker milestone is not bounded")
    if not reason or len(reason) > WORKER_FAILURE_SCOPE_MAX_CHARS:
        raise ValueError("recovery lifecycle marker reason is not bounded")

    source = {
        "attempt_id": attempt_id,
        "record_type": record_type,
        "record_id": record_id,
        "state": state,
        "last_milestone": milestone,
        "reason": reason,
    }
    source_sha256 = hashlib.sha256(_recovery_json(source).encode("utf-8")).hexdigest()
    marker_id = uuid5(
        NAMESPACE_URL,
        "caretaker:repair-recovery-lifecycle:" + source_sha256,
    )
    return RepairRecoveryLifecycleMark(
        marker_id=marker_id,
        attempt_id=attempt_id,
        record_type=record_type,
        record_id=record_id,
        state=state,
        last_milestone=milestone,
        observed_at=observed_at or utcnow(),
        reason=reason,
        source_sha256=source_sha256,
    )


def _incomplete_lifecycle_records(store: Any, attempt: Any) -> tuple[dict[str, Any], ...]:
    """Project linked lifecycle state without mutating source evidence."""
    records: list[dict[str, Any]] = []
    attempt_id = str(_field(attempt, "attempt_id", ""))
    stage = _enum_name(_field(attempt, "stage"))
    records.append({
        "record_type": "attempt",
        "record_id": attempt_id,
        "state": "INCOMPLETE_REPAIR",
        "last_milestone": stage or RepairAttemptStage.CREATED.name,
        "reason": "Repair attempt did not durably complete",
    })
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

    validation_stages = {
        RepairAttemptStage.VALIDATION.name,
        RepairAttemptStage.SCORING.name,
        RepairAttemptStage.ACTIVATION.name,
        RepairAttemptStage.RETRY.name,
        RepairAttemptStage.OBSERVATION.name,
    }
    records.append({
        "record_type": "validation",
        "record_id": attempt_id,
        "state": "INCOMPLETE" if stage in validation_stages else "NOT_STARTED",
        "last_milestone": stage or RepairAttemptStage.CREATED.name,
        "persisted_check_count": len(_field(attempt, "validation_results", ()) or ()),
    })
    return tuple(records)


def _recovery_json(value: Any) -> str:
    """Serialize bounded recovery evidence for an exact stale-plan check."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    )


def _validate_recovery_decision_source(store: Any, decision: Mapping[str, Any]) -> None:
    """Verify that a plan decision still describes the persisted attempt."""
    attempt_id = str(decision.get("attempt_id") or "")
    attempts = _records_by_id(store, "all_attempts", "attempt_id")
    attempt = attempts.get(attempt_id)
    if attempt is None:
        raise RecoveryPlanStaleError(
            f"recovery plan is stale: attempt {attempt_id or '<missing>'} is unavailable"
        )

    for field_name in ("episode_id", "incident_id", "target_id", "candidate_id"):
        planned = str(decision.get(field_name) or "")
        persisted = str(_field(attempt, field_name, "") or "")
        if planned != persisted:
            raise RecoveryPlanStaleError(
                f"recovery plan is stale: {field_name} no longer matches attempt"
            )

    persisted_outcome = _enum_name(_field(attempt, "outcome"))
    persisted_stage = _enum_name(_field(attempt, "stage"))
    if (
        _field(attempt, "completed_at") is not None
        and persisted_outcome != RepairAttemptOutcome.PENDING.name
    ):
        raise RecoveryPlanStaleError(
            f"recovery plan is stale: attempt {attempt_id} has completed"
        )
    if str(decision.get("persisted_outcome") or "") != persisted_outcome:
        raise RecoveryPlanStaleError(
            "recovery plan is stale: persisted attempt outcome changed"
        )
    if str(decision.get("last_milestone") or "") != persisted_stage:
        raise RecoveryPlanStaleError(
            "recovery plan is stale: persisted attempt milestone changed"
        )

    planned_records = decision.get("incomplete_records")
    if not isinstance(planned_records, list):
        raise RecoveryPlanStaleError(
            "recovery plan is stale: incomplete lifecycle evidence is malformed"
        )
    current_records = list(_incomplete_lifecycle_records(store, attempt))
    if _recovery_json(planned_records) != _recovery_json(current_records):
        raise RecoveryPlanStaleError(
            "recovery plan is stale: linked lifecycle evidence changed"
        )


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
    seen_attempt_ids: set[str] = set()
    validated_decisions: list[Mapping[str, Any]] = []
    observed_at = now or utcnow()
    applied = 0
    skipped = 0
    action_results: list[dict[str, Any]] = []
    lifecycle_mark_count = 0
    for decision in decisions:
        if not isinstance(decision, Mapping):
            raise ValueError("Repair recovery decision must be an object")
        attempt_id = str(decision.get("attempt_id") or "")
        if not attempt_id:
            raise ValueError("Repair recovery decision requires attempt_id")
        if attempt_id in seen_attempt_ids:
            raise RecoveryPlanStaleError(
                f"recovery plan contains duplicate attempt {attempt_id}"
            )
        seen_attempt_ids.add(attempt_id)
        if attempt_id in existing:
            skipped += 1
            continue
        _validate_recovery_decision_source(store, decision)
        validated_decisions.append(decision)

    lifecycle_writer = getattr(store, "record_recovery_lifecycle_mark", None)
    if validated_decisions and not callable(lifecycle_writer):
        raise RuntimeError(
            "recovery store does not provide durable lifecycle marking"
        )

    # Validate every source before dispatching any application-owned handler or
    # writing a recovery record. A stale decision later in the batch must not
    # leave an earlier decision partially applied. Lifecycle marks are written
    # before a callback so a callback never runs without durable interrupted
    # state.
    for decision in validated_decisions:
        attempt_id = str(decision.get("attempt_id") or "")
        lifecycle_records = tuple(
            item
            for item in (decision.get("incomplete_records") or ())
            if isinstance(item, Mapping)
        )
        for lifecycle_record in lifecycle_records:
            lifecycle_writer(
                create_recovery_lifecycle_mark(
                    decision,
                    lifecycle_record,
                    observed_at=observed_at,
                )
            )
            lifecycle_mark_count += 1
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
        "lifecycle_mark_count": lifecycle_mark_count,
        "action_results": action_results,
    }
