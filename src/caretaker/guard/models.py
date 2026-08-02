from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Mapping
from uuid import UUID, uuid4

from ..evidence.models import (
    BehaviorEvent,
    BehaviorWindow,
    CodeIdentity,
    DependencyChange,
    ResourceSummary,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class GuardMode(Enum):
    DISABLED = auto()
    LEARN = auto()
    AUDIT = auto()
    RESEARCH = auto()
    FORENSIC = auto()
    ENFORCE = auto()


class InspectionLevel(Enum):
    IDENTITY_ONLY = auto()
    LOAD_TIME = auto()
    PERIODIC = auto()
    CALL_CORRELATED = auto()
    RESEARCH = auto()
    FORENSIC = auto()


class BaselineState(Enum):
    CANDIDATE = auto()
    OBSERVING = auto()
    REVIEW_REQUIRED = auto()
    ACCEPTED = auto()
    SUPERSEDED = auto()
    REJECTED = auto()


class DeviationCategory(Enum):
    NEW_NETWORK_DESTINATION = auto()
    NEW_FILESYSTEM_ROOT = auto()
    NEW_SUBPROCESS = auto()
    NEW_IMPORT = auto()
    NEW_DYNAMIC_CODE = auto()
    RATE_INCREASE = auto()
    RATE_DECREASE = auto()
    LOAD_TIME_SIDE_EFFECT = auto()
    RUNTIME_CODE_CHANGE = auto()
    DEPENDENCY_CHANGE = auto()
    OUTPUT_BEHAVIOR_CHANGE = auto()
    EXPLICIT_POLICY_VIOLATION = auto()
    OTHER = auto()


class AssessmentSeverity(Enum):
    INFORMATIONAL = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class GuardAction(Enum):
    ALLOW = auto()
    RECORD = auto()
    ALERT = auto()
    ESCALATE_INSTRUMENTATION = auto()
    REQUIRE_APPROVAL = auto()
    QUARANTINE = auto()
    DENY_OPERATION = auto()
    TERMINATE_PROCESS = auto()
    OPEN_REPAIR_EPISODE = auto()
    ROLLBACK_REPAIR = auto()


class GuardDeviationAction(Enum):
    RECORD_ONLY = auto()
    ALERT = auto()
    OPEN_INCIDENT = auto()
    OPEN_REPAIR_EPISODE = auto()
    ROLLBACK_ACTIVE_CANDIDATE = auto()
    QUARANTINE_TARGET = auto()


@dataclass(frozen=True, slots=True)
class BehaviorProfile:
    event_kind_counts: Mapping[str, int]
    resource_counts: Mapping[str, int]
    call_count: int
    event_count: int
    network_destinations: tuple[str, ...] = ()
    filesystem_roots: tuple[str, ...] = ()
    subprocesses: tuple[str, ...] = ()
    imports: tuple[str, ...] = ()
    dynamic_code_operations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BehaviorProfileSummary:
    subject: CodeIdentity
    window_count: int
    call_count: int
    event_count: int
    event_kind_counts: Mapping[str, int]
    network_destinations: tuple[str, ...]
    filesystem_roots: tuple[str, ...]
    subprocesses: tuple[str, ...]
    imports: tuple[str, ...]
    dynamic_code_operations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BehaviorBaseline:
    baseline_id: UUID
    subject: CodeIdentity
    workload_label: str | None
    environment_fingerprint: str | None
    created_at: datetime
    accepted_at: datetime | None
    observations: int
    profile: BehaviorProfile
    state: BaselineState


@dataclass(frozen=True, slots=True)
class EvidenceSummary:
    description: str
    values: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class BehaviorDeviation:
    deviation_id: UUID
    baseline_id: UUID
    observation_window_id: UUID
    subject: CodeIdentity
    category: DeviationCategory
    expected: EvidenceSummary
    observed: EvidenceSummary
    novelty_score: float
    magnitude_score: float
    sensitivity_score: float
    confidence_score: float
    persistence_score: float
    significance_score: float
    explanation: str
    supporting_event_ids: tuple[UUID, ...] = ()
    created_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True, slots=True)
class GuardEvidenceBundle:
    subject: CodeIdentity
    baseline_summary: BehaviorProfileSummary | None
    observation_summary: BehaviorProfileSummary | None
    deviations: tuple[BehaviorDeviation, ...]
    representative_events: tuple[BehaviorEvent, ...]
    dependency_changes: tuple[DependencyChange, ...] = ()
    integrity_status: Mapping[str, Any] | None = None
    correlated_log_summaries: tuple[str, ...] = ()
    omitted_event_count: int = 0
    evidence_hash: str = ""


@dataclass(frozen=True, slots=True)
class BehaviorAssessment:
    assessment_id: UUID
    subject: CodeIdentity
    baseline_id: UUID | None
    deviation_ids: tuple[UUID, ...]
    severity: AssessmentSeverity
    confidence: float
    significant_changes: tuple[str, ...]
    suspicious_patterns: tuple[str, ...]
    plausible_benign_explanations: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    requested_additional_evidence: tuple[str, ...]
    provider_name: str
    model_name: str | None
    prompt_version: str
    response_hash: str
    created_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True, slots=True)
class GuardDecision:
    decision_id: UUID
    subject: CodeIdentity
    deviation_ids: tuple[UUID, ...]
    assessment_id: UUID | None
    action: GuardAction
    reason: str
    deterministic_policy_ids: tuple[str, ...]
    requires_human_review: bool
    created_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True, slots=True)
class BehavioralCandidateScore:
    candidate_id: UUID | None
    baseline_compatibility: float
    new_capability_risk: float
    prohibited_operation_count: int
    unexplained_deviation_count: int
    eligible: bool
    rejection_reasons: tuple[str, ...] = ()
    detected_capabilities: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class InstrumentationLease:
    lease_id: UUID
    subject_key: str
    mode: GuardMode
    execution_count: int
    reason: str
    created_at: datetime
    remaining_executions: int

    @classmethod
    def create(
        cls,
        *,
        subject_key: str,
        mode: GuardMode,
        execution_count: int,
        reason: str,
    ) -> "InstrumentationLease":
        return cls(
            lease_id=uuid4(),
            subject_key=subject_key,
            mode=mode,
            execution_count=execution_count,
            reason=reason,
            created_at=utcnow(),
            remaining_executions=execution_count,
        )


@dataclass(frozen=True, slots=True)
class ModuleVariant:
    variant_id: str
    import_name: str
    distribution_name: str | None
    distribution_version: str | None
    source_location: str
    source_hash: str | None
    integrity_state: str
    behavior_baseline_id: UUID | None
    priority: int = 0


@dataclass(frozen=True, slots=True)
class ModuleRoutePolicy:
    import_name: str
    preferred_variant_id: str
    fallback_variant_ids: tuple[str, ...] = ()
    substitution_allowed: bool = True
    require_signed_variant: bool = True
    require_accepted_baseline: bool = False
    restart_required: bool = True


@dataclass(frozen=True, slots=True)
class ImportRouteDecision:
    decision_id: UUID
    import_name: str
    requested_variant_id: str | None
    selected_variant_id: str | None
    action: str
    reason: str
    triggering_signal_ids: tuple[UUID, ...]
    policy_fingerprint: str
    created_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True, slots=True)
class DependencyComparisonSession:
    session_id: UUID
    baseline_environment: str
    candidate_environment: str
    workload_id: str
    functional_differences: tuple[str, ...]
    behavioral_deviations: tuple[BehaviorDeviation, ...]
    llm_assessment_id: UUID | None
    created_at: datetime = field(default_factory=utcnow)
