from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum, auto
from pathlib import Path
from typing import Any, Mapping
from uuid import UUID, uuid4


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RepairMode(Enum):
    AUTOMATIC = auto()
    DIAGNOSE = auto()
    OBSERVE = auto()


class ValidatorErrorBehavior(Enum):
    FAIL_CLOSED = auto()
    FAIL_OPEN = auto()


class ValidationIsolationLevel(IntEnum):
    PROCESS = 1
    CONTAINER = 2
    VM = 3
    EXTERNAL = 4


class ValidationBackendUnavailableAction(Enum):
    FAIL_REPAIR = auto()
    PROPOSE_ONLY = auto()
    REQUIRE_OPERATOR_APPROVAL = auto()


class TimeoutMode(Enum):
    SOFT = "soft"


class TriggerKind(Enum):
    EXCEPTION = auto()
    TIMEOUT = auto()
    INVALID_OUTPUT = auto()
    MANUAL = auto()
    UNHANDLED_EXCEPTION = auto()
    DIFFERENTIAL_MISMATCH = auto()


class CallableKind(Enum):
    FUNCTION = auto()
    INSTANCE_METHOD = auto()
    CLASS_METHOD = auto()
    STATIC_METHOD = auto()
    COROUTINE = auto()
    GENERATOR = auto()
    ASYNC_GENERATOR = auto()


class ReplaySafety(Enum):
    NEVER = auto()
    UNKNOWN = auto()
    PURE = auto()
    IDEMPOTENT = auto()
    TRANSACTIONAL = auto()
    APPLICATION_MANAGED = auto()


class SideEffectClass(Enum):
    """Application-declared side-effect boundary for a registered function."""

    UNKNOWN = auto()
    PURE = auto()
    READ_ONLY = auto()
    IDEMPOTENT = auto()
    SIDE_EFFECTING = auto()


class SnapshotStrategy(Enum):
    DEEPCOPY = auto()
    PICKLE = auto()
    JSON = auto()
    CUSTOM = auto()


class SlotState(Enum):
    HEALTHY = auto()
    REPAIRING = auto()
    CANDIDATE_ACTIVE = auto()
    INITIALLY_VALIDATED = auto()
    LONG_TERM_ACCEPTED = auto()
    QUARANTINED = auto()
    DISABLED = auto()


class CandidateState(Enum):
    GENERATED = auto()
    SANDBOX_VALIDATED = auto()
    ACTIVE_PROBATION = auto()
    INITIALLY_VALIDATED = auto()
    LONG_TERM_ACCEPTED = auto()
    DEGRADED = auto()
    REJECTED = auto()
    ROLLED_BACK = auto()
    QUARANTINED = auto()
    SUPERSEDED = auto()


class IntegrityRepairDisposition(Enum):
    AUTOMATIC = auto()
    DIAGNOSTIC_ONLY = auto()
    PROHIBITED = auto()


class TargetCapability(Enum):
    REPAIRABLE = auto()
    DIAGNOSTIC_ONLY = auto()
    UNSUPPORTED = auto()


class FailureDomain(Enum):
    APPLICATION = auto()
    CARETAKER_INTERNAL = auto()
    VALIDATION_WORKER = auto()
    PROVIDER = auto()
    STORAGE = auto()


class ChangeKind(Enum):
    ADDED = auto()
    REMOVED = auto()
    REPLACED = auto()
    MUTATED = auto()
    UNKNOWN = auto()


class RepairArtifactKind(Enum):
    FUNCTION_REPLACEMENT = auto()
    FUNCTION_SET = auto()
    MODULE_PATCH = auto()
    PACKAGE_PATCH = auto()
    CONFIGURATION_CHANGE = auto()


class CandidateGeneratorKind(Enum):
    LLM = auto()
    DETERMINISTIC = auto()
    RULE_ENGINE = auto()
    STATIC_ANALYZER = auto()
    HUMAN = auto()
    HISTORICAL_REUSE = auto()
    CONSOLIDATION = auto()


class CandidateGenerationOutcome(Enum):
    PENDING = auto()
    SUCCEEDED = auto()
    NO_CANDIDATES = auto()
    FAILED = auto()
    TIMED_OUT = auto()
    INVALID_RESPONSE = auto()


class RepairEpisodeOutcome(Enum):
    PENDING = auto()
    REPAIRED = auto()
    REPAIRED_NOT_RETRIED = auto()
    NO_ACCEPTABLE_CANDIDATE = auto()
    REPAIR_PROHIBITED = auto()
    RETRY_FAILED = auto()
    INTERNAL_FAILURE = auto()
    ABANDONED = auto()
    AWAITING_APPROVAL = auto()
    STALE_POLICY = auto()


class RepairAttemptStage(Enum):
    CREATED = auto()
    CONTEXT_ASSEMBLY = auto()
    PROVIDER_INVOCATION = auto()
    CANDIDATE_PARSING = auto()
    VALIDATION = auto()
    SCORING = auto()
    ACTIVATION = auto()
    RETRY = auto()
    OBSERVATION = auto()
    COMPLETE = auto()


class RepairAttemptOutcome(Enum):
    PENDING = auto()
    SUCCEEDED = auto()
    PROVIDER_FAILED = auto()
    RESPONSE_INVALID = auto()
    CANDIDATE_REJECTED = auto()
    VALIDATION_FAILED = auto()
    ACTIVATION_CONFLICT = auto()
    ACTIVATION_FAILED = auto()
    RETRY_FAILED = auto()
    OBSERVATION_FAILED = auto()
    ROLLED_BACK = auto()
    ABANDONED = auto()
    CANCELLED = auto()
    INTERNAL_ERROR = auto()
    AWAITING_APPROVAL = auto()
    STALE_POLICY = auto()


class ValidationCheckKind(Enum):
    RESPONSE_STRUCTURE = auto()
    AST_PARSE = auto()
    FUNCTION_NAME = auto()
    SIGNATURE = auto()
    CALLABLE_KIND = auto()
    COMPILE = auto()
    STATIC_POLICY = auto()
    REGISTERED_TESTS = auto()
    GENERATED_TESTS = auto()
    FAILED_CALL_REPLAY = auto()
    OUTPUT_VALIDATION = auto()
    PERFORMANCE = auto()
    AUXILIARY_VALID_EXAMPLES = auto()
    AUXILIARY_INVALID_EXAMPLES = auto()


class CheckOutcome(Enum):
    PASSED = auto()
    FAILED = auto()
    SKIPPED = auto()
    ERROR = auto()


class CandidateSelectionMode(Enum):
    HIGHEST_SCORE = auto()
    FIRST_ACCEPTABLE = auto()
    CONSOLIDATE_TOP_CANDIDATES = auto()
    CUSTOM = auto()


class DifferentialExecutionMode(Enum):
    DISABLED = auto()
    PURE_FUNCTION = auto()
    SNAPSHOT_ISOLATED = auto()
    TRANSACTION_ISOLATED = auto()
    CUSTOM = auto()


class AuxiliaryArtifactKind(Enum):
    OUTPUT_VALIDATOR = auto()
    OUTPUT_COMPARATOR = auto()
    STATE_COMPARATOR = auto()
    SNAPSHOTTER = auto()
    RESTORER = auto()
    INPUT_NORMALIZER = auto()
    TEST_FIXTURE_FACTORY = auto()


class SlotRole(Enum):
    TARGET_IMPLEMENTATION = auto()
    OUTPUT_VALIDATOR = auto()
    OUTPUT_COMPARATOR = auto()
    SNAPSHOTTER = auto()
    RESTORER = auto()


@dataclass(frozen=True, slots=True)
class ValidationResult:
    valid: bool
    reason: str = ""
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    equivalent: bool
    reason: str = ""
    confidence: float = 1.0
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ValueSnapshot:
    type_name: str
    representation: str
    value_hash: str | None = None
    truncated: bool = False
    redacted: bool = False
    size_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class StateDifference:
    path: str
    change: ChangeKind
    before: ValueSnapshot | None
    after: ValueSnapshot | None
    restorable: bool
    restored: bool = False
    restoration_error: str | None = None


@dataclass(frozen=True, slots=True)
class TracebackFrameSnapshot:
    filename: str
    line_number: int
    function_name: str
    source_line: str | None
    locals: Mapping[str, ValueSnapshot]


@dataclass(frozen=True, slots=True)
class ExceptionEvidence:
    exception_module: str
    exception_type: str
    message: str
    arguments: tuple[ValueSnapshot, ...]
    traceback: tuple[TracebackFrameSnapshot, ...]


@dataclass(frozen=True, slots=True)
class TimeoutEvidence:
    configured_seconds: float
    elapsed_seconds: float
    mode: str
    execution_interrupted: bool


@dataclass(frozen=True, slots=True)
class OutputValidationEvidence:
    validator_name: str
    reason: str
    output: ValueSnapshot


@dataclass(frozen=True, slots=True)
class DifferentialEvidence:
    original_succeeded: bool
    candidate_succeeded: bool
    original_output: ValueSnapshot | None
    candidate_output: ValueSnapshot | None
    original_exception: ExceptionEvidence | None
    candidate_exception: ExceptionEvidence | None
    comparison_reason: str


FailureEvidence = ExceptionEvidence | TimeoutEvidence | OutputValidationEvidence | DifferentialEvidence


@dataclass(frozen=True, slots=True)
class CallSnapshot:
    started_at: datetime
    elapsed_seconds: float
    bound_arguments: Mapping[str, ValueSnapshot]
    process_id: int
    thread_id: int
    task_name: str | None
    call_attempt: int
    replayable: bool
    replay_block_reason: str | None = None


@dataclass(frozen=True, slots=True)
class IncidentTargetReference:
    target_id: str | None
    module_name: str | None
    qualified_name: str | None
    filename: str | None
    line_number: int | None
    function_version: int | None
    source_hash: str | None


@dataclass(frozen=True, slots=True)
class LogEventSnapshot:
    timestamp: datetime
    level: str
    logger_name: str
    message: str
    target_id: str | None = None
    call_id: UUID | None = None
    incident_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    policy_snapshot_id: UUID
    policy_schema_version: int
    fingerprint: str
    canonical_policy: Mapping[str, Any]
    human_readable_policy: str
    created_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True, slots=True)
class Incident:
    incident_id: UUID
    run_id: UUID
    call_id: UUID
    occurred_at: datetime
    trigger: TriggerKind
    target: IncidentTargetReference
    call: CallSnapshot
    failure: FailureEvidence
    policy_snapshot_id: UUID
    policy_fingerprint: str
    state_differences: tuple[StateDifference, ...] = ()
    logs: tuple[LogEventSnapshot, ...] = ()
    repair_depth: int = 0
    fingerprint: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    authority_policy_generation: int = 0
    authority_policy_fingerprint: str = "unconfigured"


@dataclass(frozen=True, slots=True)
class RepairEpisode:
    episode_id: UUID
    incident_id: UUID
    target_id: str
    created_at: datetime
    completed_at: datetime | None
    policy_snapshot_id: UUID
    outcome: RepairEpisodeOutcome
    selected_candidate_id: UUID | None = None
    selected_attempt_id: UUID | None = None
    final_function_version: int | None = None
    summary: str | None = None
    authority_policy_generation: int = 0
    authority_policy_fingerprint: str = "unconfigured"


@dataclass(frozen=True, slots=True)
class ProviderInvocation:
    provider_name: str
    model_name: str | None
    request_started_at: datetime
    request_finished_at: datetime | None
    prompt_version: str
    prompt_hash: str
    response_hash: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    error_type: str | None = None
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class CandidateGeneration:
    generation_id: UUID
    episode_id: UUID
    incident_id: UUID
    target_id: str
    generator_kind: CandidateGeneratorKind
    generator_name: str
    provider_name: str | None
    model_name: str | None
    started_at: datetime
    completed_at: datetime | None
    outcome: CandidateGenerationOutcome
    prompt_version: str | None
    prompt_hash: str | None
    candidate_ids: tuple[UUID, ...] = ()
    error_type: str | None = None
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class ArtifactFile:
    relative_path: str
    operation: str
    content: str
    content_hash: str


@dataclass(frozen=True, slots=True)
class RepairArtifact:
    kind: RepairArtifactKind
    files: tuple[ArtifactFile, ...]
    entrypoint: str | None
    artifact_hash: str
    metadata: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GeneratedTest:
    name: str
    source: str


@dataclass(frozen=True, slots=True)
class CandidateLineage:
    parent_candidate_ids: tuple[UUID, ...]
    mechanism: str
    generation_id: UUID


@dataclass(frozen=True, slots=True)
class RepairCandidate:
    candidate_id: UUID
    generation_id: UUID
    episode_id: UUID
    incident_id: UUID
    target_id: str
    created_at: datetime
    base_function_version: int
    base_source_hash: str | None
    artifact: RepairArtifact
    explanation: str
    assumptions: tuple[str, ...] = ()
    generated_tests: tuple[GeneratedTest, ...] = ()
    generator_kind: CandidateGeneratorKind = CandidateGeneratorKind.LLM
    generator_name: str = "unknown"
    provider_name: str | None = None
    model_name: str | None = None
    lineage: CandidateLineage | None = None
    state: CandidateState = CandidateState.GENERATED
    authority_policy_generation: int = 0
    authority_policy_fingerprint: str = "unconfigured"


@dataclass(frozen=True, slots=True)
class ValidationCheckResult:
    kind: ValidationCheckKind
    outcome: CheckOutcome
    started_at: datetime
    finished_at: datetime
    summary: str
    details: Mapping[str, Any] = field(default_factory=dict)
    error_type: str | None = None
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class ScorePenalty:
    category: str
    points: float
    reason: str


@dataclass(frozen=True, slots=True)
class CandidateScoreCard:
    candidate_id: UUID
    scoring_profile_id: str
    scoring_profile_version: int
    eligible: bool
    total_score: float
    correctness_score: float
    contract_score: float
    safety_score: float
    performance_score: float
    evidence_score: float
    maintainability_score: float
    disqualifications: tuple[str, ...] = ()
    penalties: tuple[ScorePenalty, ...] = ()
    measurements: Mapping[str, float] = field(default_factory=dict)
    calculated_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True, slots=True)
class ActivationResult:
    attempted: bool
    succeeded: bool
    previous_version: int
    activated_version: int | None
    activated_at: datetime | None = None
    conflict: bool = False
    error: str | None = None


@dataclass(frozen=True, slots=True)
class RetryResult:
    attempted: bool
    permitted: bool
    state_restore_required: bool
    state_restore_succeeded: bool | None
    succeeded: bool | None
    elapsed_seconds: float | None
    exception_type: str | None = None
    exception_message: str | None = None
    output_snapshot: ValueSnapshot | None = None
    attempts_made: int = 0
    failure_summaries: tuple[str, ...] = ()
    contract_validated: bool | None = None
    contract_failure_reason: str | None = None


@dataclass(frozen=True, slots=True)
class RegressionCase:
    case_id: UUID
    target_id: str
    name: str
    args: tuple[Any, ...]
    kwargs: Mapping[str, Any]
    expected: Any
    source_incident_id: UUID | None
    source_candidate_id: UUID | None
    created_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True, slots=True)
class RepairAttempt:
    attempt_id: UUID
    episode_id: UUID
    incident_id: UUID
    candidate_id: UUID
    target_id: str
    attempt_number: int
    created_at: datetime
    completed_at: datetime | None
    policy_snapshot_id: UUID
    validation_profile_id: str
    base_function_version: int
    base_source_hash: str | None
    stage: RepairAttemptStage
    outcome: RepairAttemptOutcome
    validation_results: tuple[ValidationCheckResult, ...] = ()
    score_card: CandidateScoreCard | None = None
    activation: ActivationResult | None = None
    retry: RetryResult | None = None
    rollback_performed: bool = False
    rollback_reason: str | None = None
    error_type: str | None = None
    error_message: str | None = None
    authority_policy_generation: int = 0
    authority_policy_fingerprint: str = "unconfigured"
    validation_backend_name: str | None = None
    validation_isolation_level: ValidationIsolationLevel | None = None
    validation_backend_details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RepairEvent:
    event_id: UUID
    timestamp: datetime
    event_type: str
    target_id: str
    incident_id: UUID | None = None
    episode_id: UUID | None = None
    attempt_id: UUID | None = None
    candidate_id: UUID | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, event_type: str, target_id: str, **kwargs: Any) -> "RepairEvent":
        return cls(event_id=uuid4(), timestamp=utcnow(), event_type=event_type, target_id=target_id, **kwargs)


@dataclass(frozen=True, slots=True)
class ObservationRecord:
    observation_id: UUID
    target_id: str
    candidate_id: UUID
    function_version: int
    call_id: UUID
    occurred_at: datetime
    mode: str
    original_outcome: Mapping[str, Any] | None
    candidate_outcome: Mapping[str, Any]
    comparison: Mapping[str, Any] | None
    counted_as_success: bool
    counted_as_failure: bool
    decision_reason: str
    rollout_id: UUID | None = None
    routing_decision_hash: str | None = None


@dataclass(frozen=True, slots=True)
class SourceLocation:
    module_name: str
    qualified_name: str
    filename: Path | None
    first_line_number: int | None


@dataclass(frozen=True, slots=True)
class CallableContract:
    kind: CallableKind
    signature_text: str
    is_async: bool
    is_generator: bool
    is_async_generator: bool
    annotations: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class TargetSupportAssessment:
    capability: TargetCapability
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RegisteredCase:
    name: str
    args: tuple[Any, ...] = ()
    kwargs: Mapping[str, Any] = field(default_factory=dict)
    expected: Any = None
    expected_exception: str | None = None
    repeat: int = 1


@dataclass(frozen=True, slots=True)
class InternalIncident:
    internal_incident_id: UUID
    occurred_at: datetime
    component: str
    operation: str
    active_target_id: str | None
    active_incident_id: UUID | None
    active_episode_id: UUID | None
    active_attempt_id: UUID | None
    active_candidate_id: UUID | None
    exception: ExceptionEvidence
    slot_states: tuple[Mapping[str, Any], ...]
    active_context: Mapping[str, ValueSnapshot]
    recent_events: tuple[RepairEvent, ...]
    recent_logs: tuple[LogEventSnapshot, ...]
    original_application_incident_id: UUID | None
    original_application_exception: ExceptionEvidence | None
    post_mortem_complete: bool
    post_mortem_errors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuxiliaryArtifact:
    artifact_id: UUID
    registry_id: str
    target_id: str
    kind: AuxiliaryArtifactKind
    version: int
    source: str
    source_hash: str
    entrypoint: str
    generation_id: UUID | None
    parent_artifact_ids: tuple[UUID, ...]
    validation_profile_id: str
    created_at: datetime
    accepted_at: datetime | None
    state: CandidateState
