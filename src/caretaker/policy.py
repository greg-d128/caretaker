from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
from uuid import uuid4

from .acceptance import AcceptanceCriteria
from .contracts import Comparator, Validator
from .guard.policy import CandidateGuardPolicy, GuardBinding
from .logging.policy import LoggingBinding
from .logging.models import RepairAuthority
from .repair_recovery import RepairRecoveryPolicy, validate_worker_acceptance_policy
from .repair_rollout import RepairRolloutPolicy
from .validation_primitives import exact_bool, finite_number, integer
from .domain import (
    CandidateSelectionMode,
    DifferentialExecutionMode,
    PolicySnapshot,
    RepairMode,
    ReplaySafety,
    SnapshotStrategy,
    ValidatorErrorBehavior,
    TimeoutMode,
    ValidationBackendUnavailableAction,
    ValidationIsolationLevel,
)


class PolicyConfigurationError(ValueError):
    """Raised when a policy requests behavior unavailable in this release."""


class StateResourceSpec(Protocol):
    name: str

    def capture(self, call: Any) -> object: ...
    def compare(self, before: object, after: object) -> object: ...
    def restore(self, snapshot: object, call: Any) -> None: ...


@dataclass(frozen=True, slots=True)
class ExceptionTrigger:
    include: tuple[type[BaseException], ...] = (Exception,)
    exclude: tuple[type[BaseException], ...] = (
        KeyboardInterrupt,
        SystemExit,
        GeneratorExit,
    )


@dataclass(frozen=True, slots=True)
class TimeoutTrigger:
    seconds: float
    mode: TimeoutMode = TimeoutMode.SOFT

    def __post_init__(self) -> None:
        if isinstance(self.mode, str):
            object.__setattr__(self, "mode", TimeoutMode(self.mode.lower()))


@dataclass(frozen=True, slots=True)
class OutputValidationTrigger:
    validator: Validator | None = None
    validator_id: str | None = None
    name: str = "output-validator"
    on_validator_error: ValidatorErrorBehavior = ValidatorErrorBehavior.FAIL_CLOSED

    def __post_init__(self) -> None:
        if (self.validator is None) == (self.validator_id is None):
            raise ValueError("Specify exactly one of validator or validator_id")


TriggerSpec = ExceptionTrigger | TimeoutTrigger | OutputValidationTrigger


@dataclass(frozen=True, slots=True)
class StatePolicy:
    capture_arguments: bool = True
    capture_failure_locals: bool = False
    capture_instance_state: bool = False
    snapshot_arguments: bool = False
    snapshot_instance: bool = False
    snapshot_globals: tuple[str, ...] = ()
    strategy: SnapshotStrategy = SnapshotStrategy.DEEPCOPY
    detect_mutations: bool = True
    include_diff_in_incident: bool = True
    restore_for_validation: bool = True
    restore_before_retry: bool = False
    restore_live_environment: bool = False
    restore_external_side_effects: bool = False
    max_snapshot_bytes: int = 10_000_000
    max_diff_entries: int = 200
    resources: tuple[StateResourceSpec, ...] = ()


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 0
    safety: ReplaySafety = ReplaySafety.UNKNOWN
    require_successful_state_restore: bool = True
    retry_original_exception_only: bool = True
    backoff_seconds: float = 0.0


@dataclass(frozen=True, slots=True)
class ValidationPolicy:
    profile_id: str = "strict-function-replacement-v1"
    require_ast_parse: bool = True
    require_compilation: bool = True
    preserve_name: bool = True
    preserve_signature: bool = True
    preserve_callable_kind: bool = True
    run_registered_tests: bool = True
    replay_failed_call: bool = False
    run_generated_tests: bool = False
    isolate_validation: bool = True
    minimum_isolation: ValidationIsolationLevel = ValidationIsolationLevel.PROCESS
    require_resource_control: bool = False
    backend_unavailable_action: ValidationBackendUnavailableAction = (
        ValidationBackendUnavailableAction.FAIL_REPAIR
    )
    validation_timeout_seconds: float = 30.0
    allow_imports: bool = False
    allow_network: bool = False
    allow_subprocesses: bool = False
    allow_filesystem_writes: bool = False
    accepted_artifact_kinds: tuple[str, ...] = ("FUNCTION_REPLACEMENT",)
    require_result_authentication: bool = False


@dataclass(frozen=True, slots=True)
class DifferentialExecutionPolicy:
    mode: DifferentialExecutionMode = DifferentialExecutionMode.DISABLED
    pure_function_confirmed: bool = False
    observation_executions: int = 0
    comparator: Comparator | None = None
    comparator_id: str | None = None
    return_candidate_on_equivalence: bool = True
    return_original_if_candidate_fails: bool = True
    reject_on_output_difference: bool = True
    require_equivalent_state_changes: bool = True


@dataclass(frozen=True, slots=True)
class ObservationPolicy(AcceptanceCriteria):
    rollback_during_probation: bool = True
    rollback_after_acceptance: bool = False
    differential_execution: DifferentialExecutionPolicy = field(
        default_factory=DifferentialExecutionPolicy
    )


@dataclass(frozen=True, slots=True)
class CandidateSynthesisPolicy:
    enabled: bool = False
    minimum_parent_candidates: int = 2
    maximum_parent_candidates: int = 3
    use_only_eligible_candidates: bool = True
    minimum_parent_score: float = 70.0
    require_score_improvement: bool = True
    minimum_improvement: float = 1.0


@dataclass(frozen=True, slots=True)
class CandidateSelectionPolicy:
    mode: CandidateSelectionMode = CandidateSelectionMode.HIGHEST_SCORE
    minimum_total_score: float = 75.0
    maximum_candidates_to_evaluate: int = 5
    tie_breakers: tuple[str, ...] = (
        "safety_score",
        "correctness_score",
        "performance_score",
        "maintainability_score",
    )
    synthesis: CandidateSynthesisPolicy = field(default_factory=CandidateSynthesisPolicy)


@dataclass(frozen=True, slots=True)
class ScoringPolicy:
    profile_id: str = "default-v1"
    profile_version: int = 1
    correctness_weight: float = 0.40
    contract_weight: float = 0.20
    safety_weight: float = 0.20
    performance_weight: float = 0.10
    evidence_weight: float = 0.05
    maintainability_weight: float = 0.05


@dataclass(frozen=True, slots=True)
class ActivationPolicy:
    activate_in_memory: bool = True
    rollback_on_retry_failure: bool = True


@dataclass(frozen=True, slots=True)
class ContextPolicy:
    include_source: bool = True
    include_traceback: bool = True
    include_state_diff: bool = True
    previous_calls: int = 3
    previous_incidents: int = 0
    maximum_log_records: int = 200
    maximum_context_characters: int = 100_000
    send_argument_values: bool = False
    send_local_values: bool = False


@dataclass(frozen=True, slots=True)
class RepairLimits:
    maximum_repair_depth: int = 1
    maximum_candidates_per_incident: int = 5
    maximum_repairs_per_target: int = 5
    cooldown_seconds: float = 60.0
    structural_review_after_repairs: int | None = None


@dataclass(frozen=True, slots=True)
class StabilityPolicy:
    detect_oscillation: bool = True
    oscillation_window_versions: int = 5
    oscillation_window_incidents: int | None = None
    prevent_reactivation_of_failed_version: bool = True
    require_regression_replay_before_reactivation: bool = False


@dataclass(frozen=True, slots=True)
class IntegrityRepairPolicy:
    allow_protected_automatic_repair: bool = False


@dataclass(frozen=True, slots=True)
class RepairRetentionPolicy:
    """Policy for bounded, archive-before-delete Repair retention runs."""

    allow_automatic_compaction: bool = False
    maximum_records_per_run: int = 1000
    maximum_reference_scan_records: int = 10_000


@dataclass(frozen=True, slots=True)
class RepairPolicy:
    triggers: tuple[TriggerSpec, ...] = field(
        default_factory=lambda: (ExceptionTrigger(),)
    )
    state: StatePolicy = field(default_factory=StatePolicy)
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    validation: ValidationPolicy = field(default_factory=ValidationPolicy)
    observation: ObservationPolicy = field(default_factory=ObservationPolicy)
    selection: CandidateSelectionPolicy = field(default_factory=CandidateSelectionPolicy)
    scoring: ScoringPolicy = field(default_factory=ScoringPolicy)
    activation: ActivationPolicy = field(default_factory=ActivationPolicy)
    context: ContextPolicy = field(default_factory=ContextPolicy)
    limits: RepairLimits = field(default_factory=RepairLimits)
    stability: StabilityPolicy = field(default_factory=StabilityPolicy)
    integrity: IntegrityRepairPolicy = field(default_factory=IntegrityRepairPolicy)
    retention: RepairRetentionPolicy = field(default_factory=RepairRetentionPolicy)
    recovery: RepairRecoveryPolicy = field(default_factory=RepairRecoveryPolicy)
    rollout: RepairRolloutPolicy = field(default_factory=RepairRolloutPolicy)
    logging: LoggingBinding = field(default_factory=LoggingBinding)
    guard: GuardBinding = field(default_factory=GuardBinding)
    candidate_guard: CandidateGuardPolicy = field(default_factory=CandidateGuardPolicy)
    mode: RepairMode = RepairMode.AUTOMATIC
    authority: RepairAuthority = RepairAuthority.REQUIRE_OPERATOR_APPROVAL
    enabled: bool = True

    @classmethod
    def automatic(cls, **changes: Any) -> "RepairPolicy":
        """Construct a policy that explicitly opts into automatic activation."""
        return cls(
            authority=RepairAuthority.AUTOMATIC_ELIGIBLE_REPAIRS,
            **changes,
        )

    def snapshot(self) -> PolicySnapshot:
        canonical = _canonicalize(self)
        encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        fingerprint = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        return PolicySnapshot(
            policy_snapshot_id=uuid4(),
            policy_schema_version=2,
            fingerprint=fingerprint,
            canonical_policy=canonical,
            human_readable_policy=_human_readable(self),
        )


def validate_repair_retention_policy(policy: RepairRetentionPolicy) -> None:
    if not isinstance(policy, RepairRetentionPolicy):
        raise PolicyConfigurationError("retention policy must be a RepairRetentionPolicy")
    errors: list[str] = []
    if not isinstance(policy.allow_automatic_compaction, bool):
        errors.append("retention.allow_automatic_compaction must be a boolean")
    if (
        isinstance(policy.maximum_records_per_run, bool)
        or not isinstance(policy.maximum_records_per_run, int)
        or policy.maximum_records_per_run <= 0
    ):
        errors.append("retention.maximum_records_per_run must be a positive integer")
    if (
        isinstance(policy.maximum_reference_scan_records, bool)
        or not isinstance(policy.maximum_reference_scan_records, int)
        or policy.maximum_reference_scan_records <= 0
    ):
        errors.append("retention.maximum_reference_scan_records must be a positive integer")
    if errors:
        raise PolicyConfigurationError("Invalid Caretaker retention policy:\n- " + "\n- ".join(errors))


def validate_policy(policy: RepairPolicy) -> None:
    """Validate policy semantics at decoration time.

    Security-critical V1 requirements are deliberately not configurable. A setting
    that would silently have no effect raises PolicyConfigurationError instead.
    """

    if not isinstance(policy, RepairPolicy):
        raise PolicyConfigurationError("policy must be a RepairPolicy")
    errors: list[str] = []

    # Nested policy objects are part of the public construction surface.  Do
    # this check before reading their fields so malformed input fails with a
    # stable configuration error instead of an AttributeError (or, worse,
    # being partially accepted by a supervisor bootstrap path).
    nested_policy_types = {
        "state": StatePolicy,
        "retry": RetryPolicy,
        "validation": ValidationPolicy,
        "observation": ObservationPolicy,
        "selection": CandidateSelectionPolicy,
        "scoring": ScoringPolicy,
        "activation": ActivationPolicy,
        "context": ContextPolicy,
        "limits": RepairLimits,
        "stability": StabilityPolicy,
        "integrity": IntegrityRepairPolicy,
        "retention": RepairRetentionPolicy,
        "recovery": RepairRecoveryPolicy,
        "rollout": RepairRolloutPolicy,
        "logging": LoggingBinding,
        "guard": GuardBinding,
        "candidate_guard": CandidateGuardPolicy,
    }
    for name, expected in nested_policy_types.items():
        if not isinstance(getattr(policy, name), expected):
            errors.append(f"{name} must be a {expected.__name__}")
    if errors:
        raise PolicyConfigurationError("Invalid Caretaker policy:\n- " + "\n- ".join(errors))

    enum_policy_fields = (
        ("mode", RepairMode, policy.mode),
        ("authority", RepairAuthority, policy.authority),
        ("state.strategy", SnapshotStrategy, policy.state.strategy),
        ("retry.safety", ReplaySafety, policy.retry.safety),
        ("validation.minimum_isolation", ValidationIsolationLevel, policy.validation.minimum_isolation),
        ("validation.backend_unavailable_action", ValidationBackendUnavailableAction, policy.validation.backend_unavailable_action),
        ("selection.mode", CandidateSelectionMode, policy.selection.mode),
        ("observation.differential_execution.mode", DifferentialExecutionMode, policy.observation.differential_execution.mode),
    )
    for name, expected, value in enum_policy_fields:
        if not isinstance(value, expected):
            errors.append(f"{name} must be a {expected.__name__}")
    for index, trigger in enumerate(policy.triggers):
        if not isinstance(trigger, (ExceptionTrigger, TimeoutTrigger, OutputValidationTrigger)):
            errors.append(f"triggers[{index}] is not a supported trigger")
        elif isinstance(trigger, TimeoutTrigger) and not isinstance(trigger.mode, TimeoutMode):
            errors.append(f"triggers[{index}].mode must be a TimeoutMode")
        elif isinstance(trigger, OutputValidationTrigger) and not isinstance(
            trigger.on_validator_error, ValidatorErrorBehavior
        ):
            errors.append(
                f"triggers[{index}].on_validator_error must be a ValidatorErrorBehavior"
            )
    if errors:
        raise PolicyConfigurationError("Invalid Caretaker policy:\n- " + "\n- ".join(errors))

    def check(name: str, validator, value: Any) -> None:
        try:
            validator(value, name=name)
        except ValueError as exc:
            errors.append(str(exc))

    for name, value in (
        ("state.capture_arguments", policy.state.capture_arguments),
        ("state.capture_failure_locals", policy.state.capture_failure_locals),
        ("state.capture_instance_state", policy.state.capture_instance_state),
        ("state.snapshot_arguments", policy.state.snapshot_arguments),
        ("state.snapshot_instance", policy.state.snapshot_instance),
        ("state.detect_mutations", policy.state.detect_mutations),
        ("state.include_diff_in_incident", policy.state.include_diff_in_incident),
        ("state.restore_for_validation", policy.state.restore_for_validation),
        ("state.restore_before_retry", policy.state.restore_before_retry),
        ("state.restore_live_environment", policy.state.restore_live_environment),
        ("state.restore_external_side_effects", policy.state.restore_external_side_effects),
        ("retry.require_successful_state_restore", policy.retry.require_successful_state_restore),
        ("retry.retry_original_exception_only", policy.retry.retry_original_exception_only),
        ("validation.require_ast_parse", policy.validation.require_ast_parse),
        ("validation.require_compilation", policy.validation.require_compilation),
        ("validation.preserve_name", policy.validation.preserve_name),
        ("validation.preserve_signature", policy.validation.preserve_signature),
        ("validation.preserve_callable_kind", policy.validation.preserve_callable_kind),
        ("validation.run_registered_tests", policy.validation.run_registered_tests),
        ("validation.run_generated_tests", policy.validation.run_generated_tests),
        ("validation.isolate_validation", policy.validation.isolate_validation),
        ("validation.allow_imports", policy.validation.allow_imports),
        ("validation.allow_network", policy.validation.allow_network),
        ("validation.allow_subprocesses", policy.validation.allow_subprocesses),
        ("validation.allow_filesystem_writes", policy.validation.allow_filesystem_writes),
        ("activation.activate_in_memory", policy.activation.activate_in_memory),
        ("activation.rollback_on_retry_failure", policy.activation.rollback_on_retry_failure),
        ("observation.rollback_during_probation", policy.observation.rollback_during_probation),
        ("observation.rollback_after_acceptance", policy.observation.rollback_after_acceptance),
        ("stability.detect_oscillation", policy.stability.detect_oscillation),
        ("stability.prevent_reactivation_of_failed_version", policy.stability.prevent_reactivation_of_failed_version),
        ("stability.require_regression_replay_before_reactivation", policy.stability.require_regression_replay_before_reactivation),
        ("recovery.enabled", policy.recovery.enabled),
        ("recovery.require_full_worker_postmortem_for_critical_evidence", policy.recovery.require_full_worker_postmortem_for_critical_evidence),
        ("recovery.allow_candidate_reactivation_after_restart", policy.recovery.allow_candidate_reactivation_after_restart),
        ("enabled", policy.enabled),
    ):
        check(name, exact_bool, value)
    for name, value, minimum in (
        ("retry.backoff_seconds", policy.retry.backoff_seconds, 0.0),
        ("validation.validation_timeout_seconds", policy.validation.validation_timeout_seconds, 0.0),
        ("observation.long_term_failure_rate", policy.observation.long_term_failure_rate, 0.0),
        ("selection.minimum_total_score", policy.selection.minimum_total_score, 0.0),
        ("selection.synthesis.minimum_parent_score", policy.selection.synthesis.minimum_parent_score, 0.0),
        ("selection.synthesis.minimum_improvement", policy.selection.synthesis.minimum_improvement, 0.0),
        ("limits.cooldown_seconds", policy.limits.cooldown_seconds, 0.0),
        ("scoring.correctness_weight", policy.scoring.correctness_weight, 0.0),
        ("scoring.contract_weight", policy.scoring.contract_weight, 0.0),
        ("scoring.safety_weight", policy.scoring.safety_weight, 0.0),
        ("scoring.performance_weight", policy.scoring.performance_weight, 0.0),
        ("scoring.evidence_weight", policy.scoring.evidence_weight, 0.0),
        ("scoring.maintainability_weight", policy.scoring.maintainability_weight, 0.0),
        ("recovery.clock_skew_tolerance_seconds", policy.recovery.clock_skew_tolerance_seconds, 0.0),
    ):
        check(name, lambda value, *, name: finite_number(value, name=name, minimum=minimum), value)
    for name, value, minimum in (
        ("state.max_snapshot_bytes", policy.state.max_snapshot_bytes, 1),
        ("state.max_diff_entries", policy.state.max_diff_entries, 0),
        ("context.previous_calls", policy.context.previous_calls, 0),
        ("context.previous_incidents", policy.context.previous_incidents, 0),
        ("context.maximum_log_records", policy.context.maximum_log_records, 0),
        ("context.maximum_context_characters", policy.context.maximum_context_characters, 1),
        ("retry.max_attempts", policy.retry.max_attempts, 0),
        ("selection.maximum_candidates_to_evaluate", policy.selection.maximum_candidates_to_evaluate, 1),
        ("limits.maximum_repair_depth", policy.limits.maximum_repair_depth, 1),
        ("limits.maximum_candidates_per_incident", policy.limits.maximum_candidates_per_incident, 1),
        ("limits.maximum_repairs_per_target", policy.limits.maximum_repairs_per_target, 1),
        ("observation.initial_successful_executions", policy.observation.initial_successful_executions, 0),
        ("observation.long_term_successful_executions", policy.observation.long_term_successful_executions, 0),
        ("observation.probation_failure_budget", policy.observation.probation_failure_budget, 0),
        ("observation.long_term_maximum_failures", policy.observation.long_term_maximum_failures, 0),
        ("selection.synthesis.minimum_parent_candidates", policy.selection.synthesis.minimum_parent_candidates, 1),
        ("selection.synthesis.maximum_parent_candidates", policy.selection.synthesis.maximum_parent_candidates, 1),
        ("recovery.approval_packet_ttl_seconds", policy.recovery.approval_packet_ttl_seconds, 1),
        ("recovery.suggested_change_packet_ttl_seconds", policy.recovery.suggested_change_packet_ttl_seconds, 1),
    ):
        check(name, lambda value, *, name: integer(value, name=name, minimum=minimum), value)
    if errors:
        raise PolicyConfigurationError("Invalid Caretaker policy:\n- " + "\n- ".join(errors))
    try:
        validate_repair_retention_policy(policy.retention)
    except PolicyConfigurationError as exc:
        errors.extend(
            line[2:] if line.startswith("- ") else line
            for line in str(exc).splitlines()[1:]
        )
    recovery = policy.recovery
    if recovery.approval_packet_ttl_seconds <= 0:
        errors.append("recovery.approval_packet_ttl_seconds must be greater than zero")
    if recovery.suggested_change_packet_ttl_seconds <= 0:
        errors.append("recovery.suggested_change_packet_ttl_seconds must be greater than zero")
    if recovery.clock_skew_tolerance_seconds <= 0:
        errors.append("recovery.clock_skew_tolerance_seconds must be greater than zero")
    try:
        validate_worker_acceptance_policy(recovery.worker_acceptance)
    except ValueError as exc:
        errors.append(str(exc))
    if recovery.allow_candidate_reactivation_after_restart:
        errors.append(
            "recovery.allow_candidate_reactivation_after_restart is not implemented"
        )
    if not policy.triggers:
        errors.append("at least one trigger is required")
    for trigger in policy.triggers:
        if isinstance(trigger, TimeoutTrigger):
            if trigger.seconds <= 0:
                errors.append("timeout seconds must be greater than zero")
            if trigger.mode is not TimeoutMode.SOFT:
                errors.append(f"timeout mode {trigger.mode!r} is unsupported; only SOFT is available")
    if policy.context.previous_calls < 0:
        errors.append("context.previous_calls cannot be negative")
    if policy.context.maximum_log_records < 0:
        errors.append("context.maximum_log_records cannot be negative")
    if policy.context.maximum_context_characters <= 0:
        errors.append("context.maximum_context_characters must be greater than zero")
    if policy.retry.max_attempts < 0:
        errors.append("retry.max_attempts cannot be negative")
    if policy.retry.backoff_seconds < 0:
        errors.append("retry.backoff_seconds cannot be negative")
    if policy.retry.max_attempts > 0 and policy.retry.safety in {ReplaySafety.UNKNOWN, ReplaySafety.NEVER}:
        errors.append("retry requires an explicit replay safety classification other than UNKNOWN or NEVER")
    if policy.state.strategy is not SnapshotStrategy.DEEPCOPY:
        errors.append("only SnapshotStrategy.DEEPCOPY is implemented in 0.3.0a3")
    if policy.state.resources:
        errors.append("custom StatePolicy.resources are reserved for a later release")
    if policy.state.restore_external_side_effects:
        errors.append("external side-effect rollback is not implemented; state restoration covers captured in-process Python state only")
    if policy.state.max_snapshot_bytes <= 0:
        errors.append("state.max_snapshot_bytes must be greater than zero")
    if policy.state.max_diff_entries < 0:
        errors.append("state.max_diff_entries cannot be negative")
    if not policy.state.restore_for_validation:
        errors.append("isolated validation always requires restored validation state in this release")
    if not policy.validation.require_ast_parse:
        errors.append("AST parsing is a mandatory security gate and cannot be disabled")
    if not policy.validation.require_compilation:
        errors.append("candidate compilation is mandatory and cannot be disabled")
    if not policy.validation.preserve_name:
        errors.append("function-name preservation is mandatory for function replacement")
    if not policy.validation.preserve_signature:
        errors.append("signature preservation is mandatory for function replacement")
    if not policy.validation.preserve_callable_kind:
        errors.append("callable-kind preservation is mandatory for function replacement")
    if policy.validation.replay_failed_call:
        errors.append(
            "validation.replay_failed_call is superseded by the regression corpus and is not separately configurable"
        )
    if not policy.validation.isolate_validation:
        errors.append("candidate validation must remain isolated")
    if policy.validation.validation_timeout_seconds <= 0:
        errors.append("validation timeout must be greater than zero")
    unsupported_artifacts = set(policy.validation.accepted_artifact_kinds) - {"FUNCTION_REPLACEMENT"}
    if unsupported_artifacts:
        errors.append(
            "unsupported validation artifact kinds: " + ", ".join(sorted(unsupported_artifacts))
        )
    if not policy.activation.activate_in_memory:
        errors.append("non-activating candidate workflows are not implemented in this release")
    if policy.selection.mode is CandidateSelectionMode.CUSTOM:
        errors.append("custom candidate selection is reserved for a later release")
    if (
        policy.selection.mode is CandidateSelectionMode.CONSOLIDATE_TOP_CANDIDATES
        and not policy.selection.synthesis.enabled
    ):
        errors.append("CONSOLIDATE_TOP_CANDIDATES requires synthesis.enabled=True")
    if policy.selection.maximum_candidates_to_evaluate <= 0:
        errors.append("selection.maximum_candidates_to_evaluate must be greater than zero")
    synthesis = policy.selection.synthesis
    if synthesis.minimum_parent_candidates < 1:
        errors.append("selection.synthesis.minimum_parent_candidates must be at least one")
    if synthesis.maximum_parent_candidates < synthesis.minimum_parent_candidates:
        errors.append("selection.synthesis.maximum_parent_candidates cannot be lower than minimum_parent_candidates")
    if not 0 <= synthesis.minimum_parent_score <= 100:
        errors.append("selection.synthesis.minimum_parent_score must be between 0 and 100")
    if synthesis.minimum_improvement < 0:
        errors.append("selection.synthesis.minimum_improvement cannot be negative")
    if not 0 <= policy.selection.minimum_total_score <= 100:
        errors.append("selection.minimum_total_score must be between 0 and 100")
    if policy.observation.initial_successful_executions < 0:
        errors.append("initial observation threshold cannot be negative")
    if policy.observation.long_term_successful_executions < policy.observation.initial_successful_executions:
        errors.append("long-term success threshold cannot be lower than the initial threshold")
    if policy.observation.probation_failure_budget < 0:
        errors.append("probation failure budget cannot be negative")
    if policy.observation.long_term_maximum_failures < 0:
        errors.append("long-term failure budget cannot be negative")
    if not 0 <= policy.observation.long_term_failure_rate <= 1:
        errors.append("long-term failure rate must be between 0 and 1")
    differential = policy.observation.differential_execution
    if differential.mode not in {
        DifferentialExecutionMode.DISABLED,
        DifferentialExecutionMode.PURE_FUNCTION,
    }:
        errors.append("only DISABLED and PURE_FUNCTION differential modes are implemented")
    if differential.mode is DifferentialExecutionMode.PURE_FUNCTION and not differential.pure_function_confirmed:
        errors.append("PURE_FUNCTION differential execution requires pure_function_confirmed=True because both implementations may execute")
    if differential.comparator is not None and differential.comparator_id is not None:
        errors.append("specify at most one differential comparator or comparator_id")
    weights = policy.scoring
    total_weight = sum(
        (
            weights.correctness_weight,
            weights.contract_weight,
            weights.safety_weight,
            weights.performance_weight,
            weights.evidence_weight,
            weights.maintainability_weight,
        )
    )
    if any(weight < 0 for weight in (
        weights.correctness_weight,
        weights.contract_weight,
        weights.safety_weight,
        weights.performance_weight,
        weights.evidence_weight,
        weights.maintainability_weight,
    )):
        errors.append("scoring weights cannot be negative")
    if abs(total_weight - 1.0) > 1e-9:
        errors.append(f"scoring weights must sum to 1.0; received {total_weight:g}")
    if policy.limits.maximum_repair_depth <= 0:
        errors.append("maximum repair depth must be greater than zero")
    if policy.limits.maximum_candidates_per_incident <= 0:
        errors.append("maximum candidates per incident must be greater than zero")
    if policy.limits.maximum_repairs_per_target <= 0:
        errors.append("maximum repairs per target must be greater than zero")
    if policy.limits.cooldown_seconds < 0:
        errors.append("repair cooldown cannot be negative")
    if policy.context.previous_incidents != 0:
        errors.append(
            "context.previous_incidents is reserved; incident-history retrieval is not implemented"
        )
    if policy.limits.structural_review_after_repairs is not None:
        errors.append(
            "limits.structural_review_after_repairs is reserved; structural-review scheduling is not implemented"
        )
    if policy.stability.oscillation_window_incidents is not None:
        errors.append(
            "stability.oscillation_window_incidents is reserved; incident-window oscillation detection is not implemented"
        )
    if policy.stability.require_regression_replay_before_reactivation:
        errors.append(
            "stability.require_regression_replay_before_reactivation=True is reserved; "
            "automatic regression replay before failed-version reactivation is not implemented"
        )
    if policy.guard.baseline_name is not None:
        errors.append("guard.baseline_name is reserved; named Guard baselines are not implemented")
    if policy.guard.enabled and not any((
        policy.guard.observe_network,
        policy.guard.observe_filesystem,
        policy.guard.observe_subprocesses,
        policy.guard.observe_imports,
        policy.guard.include_guard_context_in_repair,
        policy.guard.validate_candidate_behavior,
        policy.guard.monitor_during_probation,
    )):
        errors.append("guard.enabled requires at least one Guard behavior or integration option")
    for name in (
        "maximum_new_network_destinations",
        "maximum_new_filesystem_roots",
        "maximum_new_subprocesses",
    ):
        value = getattr(policy.candidate_guard, name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            errors.append(f"candidate_guard.{name} must be a non-negative integer")
    if errors:
        raise PolicyConfigurationError("Invalid Caretaker policy:\n- " + "\n- ".join(errors))


def _callable_reference(value: Callable[..., Any]) -> Mapping[str, Any]:
    try:
        source = inspect.getsource(value)
        source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    except (OSError, TypeError):
        source_hash = None
    return {
        "module": getattr(value, "__module__", None),
        "qualname": getattr(value, "__qualname__", getattr(value, "__name__", type(value).__name__)),
        "source_hash": source_hash,
    }


def _canonicalize(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {
            item.name: _canonicalize(getattr(value, item.name))
            for item in dataclasses.fields(value)
        }
    if isinstance(value, tuple):
        return [_canonicalize(item) for item in value]
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, Mapping):
        return {
            str(key): _canonicalize(item)
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, type) and issubclass(value, BaseException):
        return {"exception": f"{value.__module__}.{value.__qualname__}"}
    if callable(value):
        return {"callable": _callable_reference(value)}
    from enum import Enum
    if isinstance(value, Enum):
        return value.name
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return {"type": f"{type(value).__module__}.{type(value).__qualname__}", "repr": repr(value)}


def _human_readable(policy: RepairPolicy) -> str:
    lines: list[str] = ["Caretaker effective repair policy", "================================"]
    lines.append(f"Mode: {policy.mode.name}")
    lines.append(f"Enabled: {policy.enabled}")
    lines.append("Triggers:")
    for trigger in policy.triggers:
        if isinstance(trigger, ExceptionTrigger):
            include = ", ".join(exc.__name__ for exc in trigger.include)
            exclude = ", ".join(exc.__name__ for exc in trigger.exclude)
            lines.extend([f"  - Exceptions: {include}", f"    Excluded: {exclude}"])
        elif isinstance(trigger, TimeoutTrigger):
            lines.append(f"  - Timeout: {trigger.seconds:g}s ({trigger.mode.value})")
        else:
            validator = trigger.validator_id or (
                f"{trigger.validator.__module__}:{trigger.validator.__qualname__}"
                if trigger.validator else "unknown"
            )
            lines.append(
                f"  - Output validation: {trigger.name} [{validator}], "
                f"validator errors={trigger.on_validator_error.name}"
            )
    lines.extend(
        [
            "State:",
            f"  capture arguments: {policy.state.capture_arguments}",
            f"  capture failure locals: {policy.state.capture_failure_locals}",
            f"  capture instance state: {policy.state.capture_instance_state}",
            f"  snapshot arguments: {policy.state.snapshot_arguments}",
            f"  snapshot instance: {policy.state.snapshot_instance}",
            f"  snapshot globals: {', '.join(policy.state.snapshot_globals) or '(none)'}",
            f"  maximum snapshot bytes: {policy.state.max_snapshot_bytes}",
            f"  restore captured Python state before retry: {policy.state.restore_before_retry}",
            f"  restore external side effects: {policy.state.restore_external_side_effects}",
            f"  restore live environment: {policy.state.restore_live_environment}",
            "Retry:",
            f"  maximum attempts: {policy.retry.max_attempts}",
            f"  backoff seconds: {policy.retry.backoff_seconds:g}",
            f"  replay safety: {policy.retry.safety.name}",
            f"  require successful restore: {policy.retry.require_successful_state_restore}",
            f"  retry original exception only: {policy.retry.retry_original_exception_only}",
            "Repair rollout:",
            f"  enabled: {policy.rollout.enabled}",
            f"  shadow stage: {policy.rollout.allow_shadow_stage}",
            f"  canary stage: {policy.rollout.allow_canary_stage}",
            f"  shadow sample: {policy.rollout.routing.shadow_sample_percentage}%",
            f"  canary percentage: {policy.rollout.routing.canary_percentage}%",
            f"  active candidate percentage: {policy.rollout.routing.active_candidate_percentage}%",
            f"  candidate mirror percentage: {policy.rollout.routing.candidate_mirror_percentage}%",
            f"  candidate failure action: {policy.rollout.candidate_failure_action.value}",
            f"  read-only candidate fallback: {policy.rollout.allow_read_only_candidate_fallback}",
            f"  operator routing changes: {policy.rollout.allow_operator_routing_changes}",
            f"  operator routing increases: {policy.rollout.allow_operator_routing_increases}",
            f"  readiness required for routing increase: {policy.rollout.require_readiness_for_routing_increase}",
            f"  rollout readiness thresholds configured: {policy.rollout.readiness.configured}",
            f"  direct field activation: {policy.rollout.allow_direct_field_activation}",
            f"  deployment authority required for permanence: {policy.rollout.require_deployment_authority_for_permanent}",
            "Validation:",
            f"  profile: {policy.validation.profile_id}",
            f"  isolated: {policy.validation.isolate_validation}",
            f"  minimum isolation: {policy.validation.minimum_isolation.name}",
            f"  resource control required: {policy.validation.require_resource_control}",
            f"  backend unavailable: {policy.validation.backend_unavailable_action.name}",
            f"  result authentication required: {policy.validation.require_result_authentication}",
            f"  registered tests: {policy.validation.run_registered_tests}",
            f"  generated tests: {policy.validation.run_generated_tests}",
            "Selection:",
            f"  mode: {policy.selection.mode.name}",
            f"  minimum score: {policy.selection.minimum_total_score:g}",
            f"  synthesis enabled: {policy.selection.synthesis.enabled}",
            "Observation:",
            f"  initial successful executions: {policy.observation.initial_successful_executions}",
            f"  probation failure budget: {policy.observation.probation_failure_budget}",
            f"  long-term successful executions: {policy.observation.long_term_successful_executions}",
            f"  long-term maximum failures: {policy.observation.long_term_maximum_failures}",
            f"  long-term failure rate: {policy.observation.long_term_failure_rate:g}",
            f"  long-term minimum duration: {policy.observation.long_term_minimum_duration_seconds:g}s",
            f"  differential mode: {policy.observation.differential_execution.mode.name}",
            "Integrity:",
            f"  protected automatic repair: {policy.integrity.allow_protected_automatic_repair}",
            "Retention:",
            f"  automatic compaction: {policy.retention.allow_automatic_compaction}",
            f"  maximum records per run: {policy.retention.maximum_records_per_run}",
            f"  maximum reference scan records: {policy.retention.maximum_reference_scan_records}",
            "Guard integration:",
            f"  enabled: {policy.guard.enabled}",
            f"  include Guard context in repair: {policy.guard.include_guard_context_in_repair}",
            f"  validate candidate behavior: {policy.guard.validate_candidate_behavior}",
            f"  monitor candidate probation: {policy.guard.monitor_during_probation}",
            f"  allow new capabilities: {policy.candidate_guard.allow_new_capabilities}",
        ]
    )
    return "\n".join(lines)


DEFAULT_POLICY = RepairPolicy()
