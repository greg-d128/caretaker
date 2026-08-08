from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
from uuid import uuid4

from .contracts import Comparator, Validator
from .guard.policy import CandidateGuardPolicy, GuardBinding
from .logging.policy import LoggingBinding
from .logging.models import RepairAuthority
from .domain import (
    CandidateSelectionMode,
    DifferentialExecutionMode,
    PolicySnapshot,
    RepairMode,
    ReplaySafety,
    SnapshotStrategy,
    ValidatorErrorBehavior,
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
    mode: str = "soft"


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
    capture_failure_locals: bool = True
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
    validation_timeout_seconds: float = 30.0
    allow_imports: bool = False
    accepted_artifact_kinds: tuple[str, ...] = ("FUNCTION_REPLACEMENT",)


@dataclass(frozen=True, slots=True)
class DifferentialExecutionPolicy:
    mode: DifferentialExecutionMode = DifferentialExecutionMode.DISABLED
    observation_executions: int = 0
    comparator: Comparator | None = None
    comparator_id: str | None = None
    return_candidate_on_equivalence: bool = True
    return_original_if_candidate_fails: bool = True
    reject_on_output_difference: bool = True
    require_equivalent_state_changes: bool = True


@dataclass(frozen=True, slots=True)
class ObservationPolicy:
    initial_successful_executions: int = 3
    long_term_successful_executions: int = 100
    long_term_minimum_duration_seconds: float = 3600.0
    probation_failure_budget: int = 0
    long_term_maximum_failures: int = 1
    long_term_failure_rate: float = 0.001
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
    previous_incidents: int = 3
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
    structural_review_after_repairs: int = 5


@dataclass(frozen=True, slots=True)
class StabilityPolicy:
    detect_oscillation: bool = True
    oscillation_window_versions: int = 5
    oscillation_window_incidents: int = 20
    prevent_reactivation_of_failed_version: bool = True
    require_regression_replay_before_reactivation: bool = True


@dataclass(frozen=True, slots=True)
class IntegrityRepairPolicy:
    allow_protected_automatic_repair: bool = False


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


def validate_policy(policy: RepairPolicy) -> None:
    """Validate policy semantics at decoration time.

    Security-critical V1 requirements are deliberately not configurable. A setting
    that would silently have no effect raises PolicyConfigurationError instead.
    """

    errors: list[str] = []
    if not policy.triggers:
        errors.append("at least one trigger is required")
    for trigger in policy.triggers:
        if isinstance(trigger, TimeoutTrigger):
            if trigger.seconds <= 0:
                errors.append("timeout seconds must be greater than zero")
            if trigger.mode != "soft":
                errors.append(f"timeout mode {trigger.mode!r} is unsupported; only 'soft' is available")
    if policy.retry.max_attempts < 0:
        errors.append("retry.max_attempts cannot be negative")
    if policy.retry.backoff_seconds < 0:
        errors.append("retry.backoff_seconds cannot be negative")
    if policy.state.strategy is not SnapshotStrategy.DEEPCOPY:
        errors.append("only SnapshotStrategy.DEEPCOPY is implemented in 0.3.0a3")
    if policy.state.resources:
        errors.append("custom StatePolicy.resources are reserved for a later release")
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
    if policy.candidate_guard.maximum_new_network_destinations < 0:
        errors.append("candidate_guard.maximum_new_network_destinations cannot be negative")
    if policy.candidate_guard.maximum_new_filesystem_roots < 0:
        errors.append("candidate_guard.maximum_new_filesystem_roots cannot be negative")
    if policy.candidate_guard.maximum_new_subprocesses < 0:
        errors.append("candidate_guard.maximum_new_subprocesses cannot be negative")
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
            lines.append(f"  - Timeout: {trigger.seconds:g}s ({trigger.mode})")
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
            f"  restore before retry: {policy.state.restore_before_retry}",
            f"  restore live environment: {policy.state.restore_live_environment}",
            "Retry:",
            f"  maximum attempts: {policy.retry.max_attempts}",
            f"  backoff seconds: {policy.retry.backoff_seconds:g}",
            f"  replay safety: {policy.retry.safety.name}",
            f"  require successful restore: {policy.retry.require_successful_state_restore}",
            f"  retry original exception only: {policy.retry.retry_original_exception_only}",
            "Validation:",
            f"  profile: {policy.validation.profile_id}",
            f"  isolated: {policy.validation.isolate_validation}",
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
