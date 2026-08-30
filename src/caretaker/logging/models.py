from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Mapping
from uuid import UUID, uuid4


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class LoggingMode(Enum):
    APPLICATION = auto()
    DIAGNOSTIC = auto()
    GUARD = auto()
    REPAIR = auto()
    RESEARCH = auto()
    FORENSIC = auto()
    BASELINE = auto()


class LoggingCapability(Enum):
    APPLICATION_LOGS = auto()
    WARNINGS = auto()
    STDOUT = auto()
    STDERR = auto()
    EXCEPTIONS = auto()
    CALL_CORRELATION = auto()
    EXCEPTION_FINGERPRINTS = auto()
    FUNCTION_TIMING = auto()
    FUNCTION_INPUTS = auto()
    FUNCTION_RESULTS = auto()
    BEHAVIOR_EVENT_REFERENCES = auto()
    IMPORT_IDENTITY = auto()
    DEPENDENCY_SNAPSHOTS = auto()
    GUARD_DECISIONS = auto()
    REPAIR_EPISODES = auto()
    CANDIDATE_VALIDATION = auto()
    ACTIVATION_AND_ROLLBACK = auto()
    DETAILED_CALL_TRACES = auto()
    REPRESENTATIVE_STATE_SAMPLES = auto()
    OUTLIER_FEATURES = auto()
    POLICY_CHANGE_RECORDS = auto()
    HIGH_PRIORITY_EVIDENCE_CHANNEL = auto()
    SYSTEM_RECORDS = auto()
    SYSTEM_METRICS = auto()


class RequirementStrength(Enum):
    REQUIRED = auto()
    RECOMMENDED = auto()
    OPTIONAL = auto()


class PolicyConflictAction(Enum):
    APPLY_REQUIRED_OVERRIDES = auto()
    REFUSE_HIGHER_MODE = auto()
    FALL_BACK_TO_APPLICATION_LOGGING = auto()
    REQUIRE_INTERACTIVE_APPROVAL = auto()


class ModeTransitionResult(Enum):
    ACTIVATE_WITH_OVERRIDES = auto()
    REFUSE_REQUESTED_MODE = auto()
    DEACTIVATE_HIGHER_MODE = auto()
    RETAIN_PREVIOUS_EFFECTIVE_POLICY = auto()
    TERMINATE_APPLICATION = auto()


class BackpressureAction(Enum):
    BLOCK = auto()
    DROP_DEBUG = auto()
    SAMPLE = auto()
    DROP_OLDEST = auto()
    EMERGENCY_SYNC_WRITE = auto()
    BYPASS_LOGGING = auto()
    STOP_APPLICATION = auto()


class RequiredCapabilityFailureAction(Enum):
    CONTINUE_DEGRADED = auto()
    DISABLE_COMPONENT = auto()
    REFUSE_MODE_TRANSITION = auto()
    STOP_APPLICATION = auto()


class StorageHealth(Enum):
    NORMAL = auto()
    PRESSURE = auto()
    EMERGENCY = auto()
    UNAVAILABLE = auto()


class EmergencyAction(Enum):
    THROTTLE_APPLICATION = auto()
    BLOCK = auto()
    DROP_LOW_PRIORITY = auto()
    SWITCH_TO_EMERGENCY_STORAGE = auto()
    STOP_LOGGING = auto()
    STOP_ANALYSIS = auto()
    STOP_APPLICATION = auto()


class LogChannel(Enum):
    APPLICATION = auto()
    CARETAKER_INTERNAL = auto()
    REPAIR = auto()
    GUARD = auto()
    INTEGRITY = auto()
    AUDIT = auto()
    EMERGENCY = auto()
    SYSTEM = auto()


class CompressionAlgorithm(Enum):
    NONE = auto()
    GZIP = auto()


class RuntimeRecordIntegrityMode(Enum):
    HASH_CHAINED = auto()
    EPHEMERAL_SIGNED = auto()
    EXTERNAL_SIGNED = auto()


class RuntimeIdentityAnchoringState(Enum):
    SELF_RECORDED = auto()
    OPERATOR_EXPORTED = auto()
    EXTERNALLY_WITNESSED = auto()
    EXTERNALLY_SIGNED = auto()


class AnchorFailureAction(Enum):
    CONTINUE_SELF_RECORDED = auto()
    REFUSE_SIGNED_MODE = auto()
    STOP_APPLICATION = auto()


class AttachmentOverloadAction(Enum):
    PRESERVE_ALL = auto()
    PROBABILISTIC_SAMPLE = auto()
    DROP_ORDINARY = auto()
    STOP_APPLICATION = auto()


class AttachmentSamplingDecision(Enum):
    STORED = auto()
    SAMPLED_OUT = auto()
    DISABLED = auto()
    TOO_LARGE = auto()


class EvidencePriority(Enum):
    DEBUG = auto()
    ORDINARY = auto()
    IMPORTANT = auto()
    CRITICAL = auto()


class SignatureStatus(Enum):
    UNSIGNED = auto()
    HASHED_AND_CHAINED = auto()
    EPHEMERAL_SIGNED = auto()
    EXTERNAL_SIGNED = auto()
    INVALID = auto()


class BaselineScope(Enum):
    APPLICATION = auto()
    DISTRIBUTION = auto()
    MODULE = auto()
    FUNCTION = auto()


class BaselineState(Enum):
    GENERATED = auto()
    OPERATOR_REVIEWED = auto()
    ACCEPTED = auto()
    SUPERSEDED = auto()
    REJECTED = auto()


class RootCauseConfidence(Enum):
    OBSERVED_SEQUENCE = auto()
    STATISTICAL_ASSOCIATION = auto()
    PROBABLE_CAUSAL_CONTRIBUTION = auto()
    CONFIRMED = auto()


class WorkerKind(Enum):
    SUPERVISOR = auto()
    WRITER = auto()
    EVENT_SERVER = auto()
    CONTROL_SERVER = auto()
    SYSTEM_COLLECTOR = auto()
    GUARD_ANALYZER = auto()
    REPAIR_ANALYZER = auto()
    INTERROGATION = auto()
    SIGNER = auto()


class WorkerState(Enum):
    STARTING = auto()
    HEALTHY = auto()
    DEGRADED = auto()
    STOPPING = auto()
    FAILED = auto()
    UNAUTHORIZED = auto()


class WorkerAcceptanceState(Enum):
    UNTRACKED = auto()
    PROBATION = auto()
    ACCEPTED = auto()
    FAILED = auto()


class WorkerFailureAction(Enum):
    CONTINUE_DEGRADED = auto()
    DISABLE_COMPONENT = auto()
    STOP_APPLICATION = auto()


class RepairAuthority(Enum):
    ANALYZE_ONLY = auto()
    PROPOSE_ONLY = auto()
    REQUIRE_OPERATOR_APPROVAL = auto()
    AUTOMATIC_ELIGIBLE_REPAIRS = auto()


class WorkState(Enum):
    PLANNED = auto()
    ACTIVE = auto()
    WAITING_REVIEW = auto()
    COMPLETED = auto()
    ABORTED = auto()
    FAILED = auto()


class CaretakerComponent(Enum):
    LOGGING = auto()
    GUARD = auto()
    REPAIR = auto()
    INTEGRITY = auto()
    SYSTEM = auto()
    INTERROGATION = auto()


@dataclass(frozen=True, slots=True)
class LoggingPolicyOverride:
    field_path: str
    operator_value: Any
    effective_value: Any
    required_by_modes: tuple[LoggingMode, ...]
    required_capabilities: tuple[LoggingCapability, ...]
    reason: str
    operational_effect: str
    estimated_cost: str | None = None


@dataclass(frozen=True, slots=True)
class LoggingPolicySnapshot:
    snapshot_id: UUID
    loaded_at: datetime
    source_path: str | None
    content_hash: str
    canonical_policy: Mapping[str, Any]
    human_readable_policy: str
    file_owner: str | None = None
    file_permissions: str | None = None
    policy_version: str | None = None


@dataclass(frozen=True, slots=True)
class EffectiveLoggingPolicy:
    operator_policy_snapshot_id: UUID
    mode_requirements_version: str
    requested_modes: tuple[LoggingMode, ...]
    effective_modes: tuple[LoggingMode, ...]
    effective_policy: Any
    overrides: tuple[LoggingPolicyOverride, ...]
    warnings: tuple[str, ...]
    conflict_action: PolicyConflictAction
    generation: int
    created_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True, slots=True)
class ModeLease:
    lease_id: UUID
    requested_mode: LoggingMode
    scope: str
    requested_by: str
    requested_at: datetime
    reason: str
    expires_at: datetime | None
    release_condition: str | None
    policy_generation_before: int
    effective_policy_generation: int
    required_overrides: tuple[LoggingPolicyOverride, ...]
    work_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class LogEnvelope:
    schema_version: int
    writer_version: str
    record_id: UUID
    occurred_at: datetime
    monotonic_ns: int
    process_start_id: UUID
    sequence_number: int
    channel: LogChannel
    severity: int
    logger_name: str
    message_template: str | None
    formatted_message: str | None
    fields: Mapping[str, Any]
    process_id: int
    thread_id: int
    task_id: str | None
    run_id: UUID | None
    call_id: UUID | None
    target_id: str | None
    function_version: int | None
    incident_id: UUID | None
    guard_deviation_ids: tuple[UUID, ...] = ()
    behavior_event_ids: tuple[UUID, ...] = ()
    attachment_ids: tuple[UUID, ...] = ()
    origin: str = "application"


@dataclass(frozen=True, slots=True)
class AttachmentReference:
    attachment_id: UUID
    event_id: UUID
    event_sequence: int
    content_type: str
    schema_version: int
    uncompressed_bytes: int
    compressed_bytes: int
    compression: CompressionAlgorithm
    content_hash: str
    compressed_hash: str
    attachment_segment_id: UUID | None
    segment_offset: int | None
    stored: bool
    sampling_decision: AttachmentSamplingDecision
    signature_status: SignatureStatus
    signature_reference: str | None = None


@dataclass(frozen=True, slots=True)
class RuntimeSigningIdentity:
    identity_id: UUID
    application_id: str
    run_id: UUID
    process_start_id: UUID
    algorithm: str
    public_key: bytes
    public_key_fingerprint: str
    generated_at: datetime
    first_event_sequence: int
    key_epoch: int
    anchoring_state: RuntimeIdentityAnchoringState
    anchor_references: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class KeyTransition:
    from_epoch: int
    to_epoch: int
    old_public_key_fingerprint: str
    new_public_key: bytes
    new_public_key_fingerprint: str
    created_at: datetime
    signature: bytes
    next_event_sequence: int = 0


@dataclass(frozen=True, slots=True)
class RuntimeSignedManifest:
    manifest_id: UUID
    runtime_identity_id: UUID
    key_epoch: int
    segment_id: UUID
    segment_hash: str
    previous_segment_hash: str | None
    first_event_sequence: int
    last_event_sequence: int
    event_count: int
    attachment_manifest_hash: str | None
    signed_at: datetime
    signature: bytes


@dataclass(frozen=True, slots=True)
class RuntimeSignedArtifact:
    """Domain-separated signature over a runtime artifact commitment.

    The artifact body remains outside this structure.  ``content_hash`` binds the
    signature to that body while ``artifact_kind`` prevents a signature created
    for one Caretaker artifact class from being replayed as another.
    """

    artifact_id: UUID
    artifact_kind: str
    application_id: str
    run_id: UUID
    process_start_id: UUID
    signer_identity_id: str
    signer_mode: RuntimeRecordIntegrityMode
    public_key_fingerprint: str | None
    key_epoch: int | None
    content_hash: str
    previous_artifact_hash: str | None
    context: Mapping[str, Any]
    signed_at: datetime
    signature: bytes


@dataclass(frozen=True, slots=True)
class BaselineKey:
    application_id: str
    application_version: str | None
    environment_id: str | None
    target_id: str | None
    function_version: int | None
    population_designator: str | None
    workload_label: str | None


@dataclass(frozen=True, slots=True)
class MetricSummary:
    count: int
    minimum: float | None
    maximum: float | None
    mean: float | None
    total: float | None


@dataclass(frozen=True, slots=True)
class FunctionLoggingBaseline:
    target_id: str
    function_version: int | None
    population_designator: str | None
    call_count: int
    success_rate: float
    exception_rate: float
    duration_summary: MetricSummary
    log_rate_summary: MetricSummary
    log_template_distribution: Mapping[str, float]
    exception_fingerprints: Mapping[str, float]
    behavior_profile_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class ApplicationLoggingBaseline:
    baseline_id: UUID
    key: BaselineKey
    period_start: datetime
    period_end: datetime
    dependency_snapshot_id: UUID | None
    integrity_manifest_hash: str | None
    functions: tuple[FunctionLoggingBaseline, ...]
    application_metrics: Mapping[str, MetricSummary]
    behavior_profile_id: UUID | None
    state: BaselineState
    content_hash: str
    created_at: datetime = field(default_factory=utcnow)
    accepted_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class TrendFinding:
    metric: str
    slope_per_day: float
    relative_change: float | None
    unit_of_work_change: float | None
    explanation: str


@dataclass(frozen=True, slots=True)
class BaselineChange:
    category: str
    subject: str
    old_value: Any
    new_value: Any
    absolute_change: float | None
    relative_change: float | None
    per_unit_change: float | None
    significance: float


@dataclass(frozen=True, slots=True)
class BaselineComparison:
    comparison_id: UUID
    baseline_a_id: UUID
    baseline_b_id: UUID
    significant_changes: tuple[BaselineChange, ...]
    gradual_trends: tuple[TrendFinding, ...]
    new_capabilities: tuple[str, ...]
    removed_capabilities: tuple[str, ...]
    overall_change_score: float
    slow_drift_score: float
    llm_assessment_id: UUID | None = None
    created_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True, slots=True)
class RootCauseHypothesis:
    statement: str
    confidence: float
    confidence_kind: RootCauseConfidence
    supporting_evidence: tuple[UUID, ...]
    contradicting_evidence: tuple[UUID, ...] = ()
    missing_evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RootCauseAssessment:
    assessment_id: UUID
    subject: str
    period_start: datetime
    period_end: datetime
    primary_hypothesis: RootCauseHypothesis | None
    alternative_hypotheses: tuple[RootCauseHypothesis, ...]
    significant_outliers: tuple[str, ...]
    causal_sequence: tuple[str, ...]
    affected_targets: tuple[str, ...]
    affected_modules: tuple[str, ...]
    supporting_log_ids: tuple[UUID, ...]
    supporting_behavior_event_ids: tuple[UUID, ...]
    supporting_deviation_ids: tuple[UUID, ...]
    confidence: float
    missing_evidence: tuple[str, ...]
    recommended_next_actions: tuple[str, ...]
    provider_name: str | None
    model_name: str | None
    prompt_version: str | None
    created_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True, slots=True)
class WorkerHealth:
    worker_id: UUID
    worker_kind: WorkerKind
    process_id: int
    process_start_id: UUID
    started_at: datetime
    last_heartbeat_at: datetime
    state: WorkerState
    current_work_ids: tuple[UUID, ...]
    queue_depth: int
    last_completed_sequence: int | None
    restart_count: int
    last_error_fingerprint: str | None
    authority_packet_id: UUID | None = None
    authority_packet_expires_at: datetime | None = None
    replaced_worker_id: UUID | None = None
    target_id: str | None = None
    acceptance_state: WorkerAcceptanceState = WorkerAcceptanceState.UNTRACKED
    acceptance_successful_executions: int = 0
    acceptance_failed_executions: int = 0


@dataclass(frozen=True, slots=True)
class ActiveWork:
    work_id: UUID
    component: CaretakerComponent
    work_kind: str
    scope: str
    started_at: datetime
    expected_completion_at: datetime | None
    current_state: WorkState
    expected_code_fingerprints: Mapping[str, str]
    parent_work_id: UUID | None
    root_signal_id: UUID
    recently_changed_until: datetime | None = None


@dataclass(frozen=True, slots=True)
class AdministrativeAction:
    action_id: UUID
    peer_uid: int
    peer_gid: int
    peer_pid: int
    command: str
    scope: str
    reason: str
    requested_at: datetime
    result: str
    policy_generation_before: int
    policy_generation_after: int | None


@dataclass(frozen=True, slots=True)
class EvidenceCapabilityStatus:
    capability: LoggingCapability
    state: str
    unavailable_since: datetime | None
    reason: str | None


def new_record_id() -> UUID:
    return uuid4()
