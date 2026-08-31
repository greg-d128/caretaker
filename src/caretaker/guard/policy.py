from __future__ import annotations

import math
from dataclasses import dataclass, field

from .models import GuardDeviationAction, GuardMode, InspectionLevel
from ..logging.models import RequiredCapabilityFailureAction


@dataclass(frozen=True, slots=True)
class CollectorPolicy:
    audit_hooks: bool = True
    # When false, global CPython audit events are ignored unless a Caretaker
    # runtime target context is active. This is the normal choice for adaptive
    # lightweight instrumentation because sampled calls establish that context
    # explicitly and unrelated process-wide activity should stay off the hot path.
    unattributed_events: bool = True
    imports: bool = True
    network: bool = True
    filesystem: bool = True
    subprocesses: bool = True
    dynamic_code: bool = True
    environment_reads: bool = False
    function_calls: bool = False


@dataclass(frozen=True, slots=True)
class AttributionPolicy:
    capture_stack: bool = True
    maximum_stack_frames: int = 12
    skip_infrastructure_modules: tuple[str, ...] = (
        "socket",
        "urllib",
        "urllib3",
        "requests",
        "http.client",
        "pathlib",
        "os",
    )


@dataclass(frozen=True, slots=True)
class SamplingPolicy:
    event_sample_rate: float = 1.0
    stack_sample_rate: float = 0.1
    always_capture_novel_resources: bool = True
    maximum_events_per_second: int = 10_000


@dataclass(frozen=True, slots=True)
class AggregationPolicy:
    close_after_events: int = 500
    close_after_calls: int = 100
    close_after_seconds: float = 600.0
    representative_events: int = 20


@dataclass(frozen=True, slots=True)
class BaselinePolicy:
    minimum_windows: int = 3
    automatic_candidate_creation: bool = True
    automatic_acceptance: bool = False
    environment_fingerprint: str | None = None
    workload_label: str | None = None


@dataclass(frozen=True, slots=True)
class BehaviorSnapshotPolicy:
    """Bounded online statistics, snapshots, and operator collection scheduling."""

    enabled: bool = True
    statistics_target: int = 1000
    maximum_resources: int = 1000
    maximum_return_categories: int = 32
    maximum_return_shapes: int = 32
    checkpoint_every_samples: int = 25
    materialize_after_samples: int = 100
    maximum_snapshot_age_seconds: float = 3600.0
    automatic_materialization: bool = True
    randomized_epoch_boundaries: bool = False
    randomized_epoch_min_samples: int = 50
    randomized_epoch_max_samples: int = 200
    randomized_epoch_seed: int | None = None
    collection_max_active: int = 1
    collection_max_pending: int = 256
    collection_max_calls: int = 1000
    # Optional application-wide wall-clock budgets for scheduled collection.
    # The default remains unlimited for the least-friction profile.
    collection_soft_budget_seconds_per_minute: float | None = None
    collection_hard_budget_seconds_per_minute: float | None = None
    collection_auto_promote: bool = False
    collection_auto_max_promoted: int = 1
    collection_auto_max_waiting: int = 4


@dataclass(frozen=True, slots=True)
class DeviationPolicy:
    significance_threshold: float = 60.0
    high_significance_threshold: float = 80.0
    network_allowlist: tuple[str, ...] = ()
    filesystem_roots: tuple[str, ...] = ()
    subprocess_allowlist: tuple[str, ...] = ()
    deny_new_network_capability: bool = False
    deny_new_subprocess_capability: bool = False
    maximum_rate_multiplier: float = 10.0
    maximum_duration_p95_multiplier: float = 2.0
    minimum_duration_samples: int = 20


@dataclass(frozen=True, slots=True)
class LLMReviewPolicy:
    enabled: bool = False
    minimum_significance: float = 70.0
    maximum_deviations: int = 20
    maximum_representative_events: int = 20
    advisory_only: bool = True


@dataclass(frozen=True, slots=True)
class GuardActionPolicy:
    deviation_action: GuardDeviationAction = GuardDeviationAction.ALERT
    quarantine_on_explicit_violation: bool = True
    open_repair_for_application_code: bool = True
    rollback_repair_on_candidate_deviation: bool = True


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    raw_event_seconds: float | None = None
    aggregate_seconds: float | None = None
    maximum_raw_events: int = 100_000


@dataclass(frozen=True, slots=True)
class PeriodicInspectionPolicy:
    enabled: bool = True
    interval_seconds: float = 600.0
    execution_window: int | None = None
    verify_source_hash: bool = True
    verify_runtime_fingerprints: bool = True
    compare_behavior: bool = False
    escalate_on_change: bool = True


@dataclass(frozen=True, slots=True)
class GuardTargetPolicy:
    module_pattern: str
    function_patterns: tuple[str, ...] = ()
    inspection_level: InspectionLevel = InspectionLevel.PERIODIC
    periodic: PeriodicInspectionPolicy = field(default_factory=PeriodicInspectionPolicy)
    baseline_name: str | None = None


@dataclass(frozen=True, slots=True)
class GuardPolicy:
    mode: GuardMode = GuardMode.AUDIT
    collectors: CollectorPolicy = field(default_factory=CollectorPolicy)
    attribution: AttributionPolicy = field(default_factory=AttributionPolicy)
    sampling: SamplingPolicy = field(default_factory=SamplingPolicy)
    aggregation: AggregationPolicy = field(default_factory=AggregationPolicy)
    baseline: BaselinePolicy = field(default_factory=BaselinePolicy)
    snapshots: BehaviorSnapshotPolicy = field(default_factory=BehaviorSnapshotPolicy)
    deviations: DeviationPolicy = field(default_factory=DeviationPolicy)
    llm_review: LLMReviewPolicy = field(default_factory=LLMReviewPolicy)
    actions: GuardActionPolicy = field(default_factory=GuardActionPolicy)
    retention: RetentionPolicy = field(default_factory=RetentionPolicy)
    targets: tuple[GuardTargetPolicy, ...] = ()
    logging_failure_action: RequiredCapabilityFailureAction = RequiredCapabilityFailureAction.CONTINUE_DEGRADED


@dataclass(frozen=True, slots=True)
class GuardBinding:
    enabled: bool = False
    observe_network: bool = False
    observe_filesystem: bool = False
    observe_subprocesses: bool = False
    observe_imports: bool = False
    baseline_name: str | None = None
    include_guard_context_in_repair: bool = True
    validate_candidate_behavior: bool = True
    monitor_during_probation: bool = True
    deviation_action: GuardDeviationAction = GuardDeviationAction.ALERT

    @property
    def observed_resource_categories(self) -> tuple[str, ...]:
        categories = []
        if self.observe_network:
            categories.append("network")
        if self.observe_filesystem:
            categories.append("filesystem")
        if self.observe_subprocesses:
            categories.append("subprocesses")
        if self.observe_imports:
            categories.append("imports")
        return tuple(categories)


@dataclass(frozen=True, slots=True)
class CandidateGuardPolicy:
    compare_to_original_baseline: bool = True
    allow_new_capabilities: bool = False
    maximum_new_network_destinations: int = 0
    maximum_new_filesystem_roots: int = 0
    maximum_new_subprocesses: int = 0
    rollback_on_significant_deviation: bool = True


class GuardPolicyConfigurationError(ValueError):
    """Raised when Guard policy requests semantics this runtime cannot honor."""


def validate_guard_policy(policy: GuardPolicy) -> None:
    """Fail closed for unsupported or internally inconsistent Guard settings.

    Public policy is an assurance surface.  A non-default value is rejected when
    the corresponding runtime behavior is not implemented rather than being
    silently accepted.
    """

    errors: list[str] = []
    if not 0.0 <= policy.sampling.event_sample_rate <= 1.0:
        errors.append("sampling.event_sample_rate must be between 0 and 1")
    if not 0.0 <= policy.sampling.stack_sample_rate <= 1.0:
        errors.append("sampling.stack_sample_rate must be between 0 and 1")
    if policy.sampling.maximum_events_per_second <= 0:
        errors.append("sampling.maximum_events_per_second must be greater than zero")
    if policy.attribution.maximum_stack_frames < 0:
        errors.append("attribution.maximum_stack_frames cannot be negative")
    if policy.collectors.environment_reads:
        errors.append("collectors.environment_reads is reserved; environment-read attribution is not implemented")
    if policy.collectors.function_calls:
        errors.append("collectors.function_calls is reserved; general function-call collection is not implemented")
    if policy.deviations.maximum_rate_multiplier <= 0:
        errors.append("deviations.maximum_rate_multiplier must be greater than zero")
    if policy.deviations.maximum_duration_p95_multiplier <= 1.0:
        errors.append("deviations.maximum_duration_p95_multiplier must be greater than 1")
    if policy.deviations.minimum_duration_samples < 1:
        errors.append("deviations.minimum_duration_samples must be at least one")
    if policy.retention.maximum_raw_events <= 0:
        errors.append("retention.maximum_raw_events must be greater than zero")
    snapshots = policy.snapshots
    if snapshots.statistics_target <= 0:
        errors.append("snapshots.statistics_target must be greater than zero")
    if snapshots.maximum_resources <= 0:
        errors.append("snapshots.maximum_resources must be greater than zero")
    if snapshots.maximum_return_categories <= 0:
        errors.append("snapshots.maximum_return_categories must be greater than zero")
    if snapshots.maximum_return_shapes <= 0:
        errors.append("snapshots.maximum_return_shapes must be greater than zero")
    if snapshots.randomized_epoch_min_samples <= 0:
        errors.append("snapshots.randomized_epoch_min_samples must be greater than zero")
    if snapshots.randomized_epoch_max_samples < snapshots.randomized_epoch_min_samples:
        errors.append("snapshots.randomized_epoch_max_samples must be at least the minimum")
    if isinstance(snapshots.randomized_epoch_seed, bool):
        errors.append("snapshots.randomized_epoch_seed must be an integer or null")
    if snapshots.collection_max_active <= 0:
        errors.append("snapshots.collection_max_active must be greater than zero")
    if snapshots.collection_max_pending <= 0:
        errors.append("snapshots.collection_max_pending must be greater than zero")
    if snapshots.collection_max_calls <= 0:
        errors.append("snapshots.collection_max_calls must be greater than zero")
    if snapshots.collection_max_calls > 1000:
        errors.append("snapshots.collection_max_calls must not exceed 1000")
    for name in (
        "collection_soft_budget_seconds_per_minute",
        "collection_hard_budget_seconds_per_minute",
    ):
        value = getattr(snapshots, name)
        if value is not None:
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or value <= 0
            ):
                errors.append(f"snapshots.{name} must be greater than zero when configured")
    if (
        snapshots.collection_soft_budget_seconds_per_minute is not None
        and snapshots.collection_hard_budget_seconds_per_minute is not None
        and snapshots.collection_soft_budget_seconds_per_minute
        > snapshots.collection_hard_budget_seconds_per_minute
    ):
        errors.append(
            "snapshots.collection_soft_budget_seconds_per_minute cannot exceed "
            "collection_hard_budget_seconds_per_minute"
        )
    if not isinstance(snapshots.collection_auto_promote, bool):
        errors.append("snapshots.collection_auto_promote must be a boolean")
    if snapshots.collection_auto_max_promoted <= 0:
        errors.append("snapshots.collection_auto_max_promoted must be greater than zero")
    if snapshots.collection_auto_max_waiting <= 0:
        errors.append("snapshots.collection_auto_max_waiting must be greater than zero")
    if policy.retention.raw_event_seconds is not None:
        errors.append("retention.raw_event_seconds is reserved; durable time-based raw-event pruning is not implemented")
    if policy.retention.aggregate_seconds is not None:
        errors.append("retention.aggregate_seconds is reserved; aggregate time-based retention is not implemented")
    if policy.actions.deviation_action is GuardDeviationAction.OPEN_INCIDENT:
        errors.append("actions.deviation_action=OPEN_INCIDENT is reserved; use ALERT or OPEN_REPAIR_EPISODE")

    for index, target in enumerate(policy.targets):
        prefix = f"targets[{index}]"
        if target.function_patterns:
            errors.append(f"{prefix}.function_patterns is reserved; module targets are the implemented policy surface")
        if target.inspection_level is not InspectionLevel.PERIODIC:
            errors.append(f"{prefix}.inspection_level={target.inspection_level.name} is reserved; only PERIODIC is implemented")
        if target.baseline_name is not None:
            errors.append(f"{prefix}.baseline_name is reserved; named Guard baselines are not implemented")
        periodic = target.periodic
        if periodic.execution_window is not None:
            errors.append(f"{prefix}.periodic.execution_window is reserved; execution-window scheduling is not implemented")
        if not periodic.verify_source_hash:
            errors.append(f"{prefix}.periodic.verify_source_hash=False is unsupported; identity inspection always verifies source identity")
        if not periodic.verify_runtime_fingerprints:
            errors.append(f"{prefix}.periodic.verify_runtime_fingerprints=False is unsupported; runtime fingerprints are always verified")
        if periodic.compare_behavior:
            errors.append(f"{prefix}.periodic.compare_behavior=True is reserved; periodic integrity inspection does not independently compare behavior")
        if not periodic.escalate_on_change:
            errors.append(f"{prefix}.periodic.escalate_on_change=False is unsupported; detected integrity changes remain signal-producing")

    if errors:
        raise GuardPolicyConfigurationError("Invalid Guard policy:\n- " + "\n- ".join(errors))
