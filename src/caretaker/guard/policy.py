from __future__ import annotations

from dataclasses import dataclass, field

from .models import GuardDeviationAction, GuardMode, InspectionLevel
from ..logging.models import RequiredCapabilityFailureAction


@dataclass(frozen=True, slots=True)
class CollectorPolicy:
    audit_hooks: bool = True
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
class DeviationPolicy:
    significance_threshold: float = 60.0
    high_significance_threshold: float = 80.0
    network_allowlist: tuple[str, ...] = ()
    filesystem_roots: tuple[str, ...] = ()
    subprocess_allowlist: tuple[str, ...] = ()
    deny_new_network_capability: bool = False
    deny_new_subprocess_capability: bool = False
    maximum_rate_multiplier: float = 10.0


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
    raw_event_seconds: float = 86_400.0
    aggregate_seconds: float = 2_592_000.0
    maximum_raw_events: int = 100_000


@dataclass(frozen=True, slots=True)
class PeriodicInspectionPolicy:
    enabled: bool = True
    interval_seconds: float = 600.0
    execution_window: int = 100
    verify_source_hash: bool = True
    verify_runtime_fingerprints: bool = True
    compare_behavior: bool = True
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
    deviation_action: GuardDeviationAction = GuardDeviationAction.OPEN_REPAIR_EPISODE


@dataclass(frozen=True, slots=True)
class CandidateGuardPolicy:
    compare_to_original_baseline: bool = True
    allow_new_capabilities: bool = False
    maximum_new_network_destinations: int = 0
    maximum_new_filesystem_roots: int = 0
    maximum_new_subprocesses: int = 0
    rollback_on_significant_deviation: bool = True
