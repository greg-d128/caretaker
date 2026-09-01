from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from collections import OrderedDict, defaultdict, deque
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from typing import Any
from uuid import UUID, uuid4

from ..authority import get_authority_runtime_context
from ..domain import ValueSnapshot
from ..control_plane import (
    RuntimeAction,
    RuntimeActionKind,
    RuntimeControlPlane,
    RuntimeSignal,
    SignalDomain,
    SignalSeverity,
)
from ..llm import LLMRequestGate
from ..evidence.identity import identify_function
from ..evidence.models import (
    BehaviorEvent,
    BehaviorEventKind,
    CodeIdentity,
    EventOutcome,
    InspectionKind,
    ResourceIdentity,
    RuntimeInspection,
    utcnow,
)
from ..evidence.store import EvidenceStore, InMemoryEvidenceStore
from ..execution import (
    EffectObservation,
    FunctionExecutionContract,
    ShadowEligibility,
    assess_shadow_eligibility,
)
from ..runtime import snapshot_context
from ..behavior import (
    BehaviorCollectionScheduler,
    BehaviorSnapshotStore,
    BehaviorStatisticsRepository,
    behavior_generation_id,
    compare_snapshots,
    monitoring_configuration_fingerprint,
    observed_return_category,
    observed_return_shape,
)
from ..logging.models import LoggingCapability, LoggingMode, RequiredCapabilityFailureAction
from ..logging.policy import mode_requirements
from .analytics import (
    BaselineManager,
    BehaviorAggregator,
    DeviationDetector,
    StaticCandidateBehaviorAnalyzer,
    evidence_hash,
    sensitive_file_network_sequences as correlate_sensitive_file_network_sequences,
)
from .collectors import AuditEventCollector, DependencyCollector
from .facade import GuardFacade
from .imports import CaretakerModuleFinder, ModuleRouter
from .hooks import GuardHookManager
from .introspection import PeriodicInspector, RuntimeInspector
from .models import (
    AssessmentSeverity,
    BaselineAcceptanceRecord,
    BaselineState,
    BehaviorAssessment,
    BehaviorBaseline,
    BehaviorDeviation,
    BehavioralCandidateScore,
    BehaviorProfile,
    BehaviorProfileSummary,
    GuardAction,
    GuardDecision,
    GuardEvidenceBundle,
    GuardMode,
    InstrumentationLease,
)
from .policy import CandidateGuardPolicy, GuardBinding, GuardPolicy, validate_guard_policy
from .provider import BehaviorAssessmentProvider, BehaviorAssessmentRequest


_GUARD_EVENT_CACHE_LIMIT = 10_000
_GUARD_DEVIATION_CACHE_LIMIT = 2_000
_GUARD_ASSESSMENT_CACHE_LIMIT = 1_000
_GUARD_DECISION_CACHE_LIMIT = 1_000
_NO_RETURN_OBSERVATION = object()


def _tail(items, limit: int):
    if limit <= 0:
        return ()
    values = tuple(items)
    return values[-limit:]


def _configuration_value(value):
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, dict):
        return {str(key): _configuration_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_configuration_value(item) for item in value]
    return value


@dataclass
class _TargetBinding:
    function: Callable
    binding: GuardBinding
    identity: CodeIdentity
    function_resolver: Callable[[], Callable] | None = None
    monitoring_configuration: Mapping[str, object] | None = None


class GuardEngine(GuardFacade):
    def __init__(
        self,
        *,
        policy: GuardPolicy | None = None,
        store: EvidenceStore | None = None,
        control_plane: RuntimeControlPlane | None = None,
        provider: BehaviorAssessmentProvider | None = None,
        run_id: UUID | None = None,
        work_registry: object | None = None,
    ) -> None:
        self._declared_policy = policy or GuardPolicy()
        self.policy = get_authority_runtime_context().apply(
            self._declared_policy, prefix="guard"
        )
        validate_guard_policy(self.policy)
        self.store = store or InMemoryEvidenceStore(
            event_limit=self.policy.retention.maximum_raw_events
        )
        self.control_plane = control_plane or RuntimeControlPlane()
        self.provider = provider
        self._llm_gate = LLMRequestGate(self.policy.llm_review.usage)
        self.run_id = run_id or uuid4()
        self.work_registry = work_registry
        self.aggregator = BehaviorAggregator(self.store, self.policy.aggregation)
        self.baselines = BaselineManager(self.policy.baseline)
        data_root = os.environ.get("CARETAKER_DATA_DIR")
        self.behavior_statistics = (
            BehaviorStatisticsRepository.from_guard_policy(
                data_root,
                self.policy.snapshots,
                environment_fingerprint=self.policy.baseline.environment_fingerprint,
                workload_label=self.policy.baseline.workload_label,
            )
            if data_root and self.policy.snapshots.enabled
            else None
        )
        self.behavior_snapshot_store = (BehaviorSnapshotStore(data_root) if data_root else None)
        self.behavior_collection_scheduler = (
            BehaviorCollectionScheduler(
                data_root,
                maximum_active=self.policy.snapshots.collection_max_active,
                maximum_pending=self.policy.snapshots.collection_max_pending,
                maximum_calls=self.policy.snapshots.collection_max_calls,
                soft_budget_seconds_per_minute=self.policy.snapshots.collection_soft_budget_seconds_per_minute,
                hard_budget_seconds_per_minute=self.policy.snapshots.collection_hard_budget_seconds_per_minute,
                soft_budget_calls_per_minute=self.policy.snapshots.collection_soft_budget_calls_per_minute,
                hard_budget_calls_per_minute=self.policy.snapshots.collection_hard_budget_calls_per_minute,
                soft_budget_process_memory_bytes=self.policy.snapshots.collection_soft_budget_process_memory_bytes,
                hard_budget_process_memory_bytes=self.policy.snapshots.collection_hard_budget_process_memory_bytes,
            )
            if data_root and self.policy.snapshots.enabled
            else None
        )
        self._sealed_baseline_ids: set[UUID] = set()
        self._baseline_acceptances: dict[str, BaselineAcceptanceRecord] = {}
        self.detector = DeviationDetector(self.policy.deviations)
        self.inspector = RuntimeInspector(self.store)
        self.periodic = PeriodicInspector(self.inspector, on_inspection=self._on_inspection)
        self.dependencies = DependencyCollector()
        self.router = ModuleRouter()
        observed_modules = tuple(target.module_pattern for target in self.policy.targets)
        self.finder = CaretakerModuleFinder(
            router=self.router,
            inspector=self.inspector,
            run_id=self.run_id,
            control_plane=self.control_plane,
            observed_modules=observed_modules,
        )
        self.audit_collector = AuditEventCollector(
            run_id=self.run_id,
            sink=self.record_event,
            collectors=self.policy.collectors,
            attribution=self.policy.attribution,
            sampling=self.policy.sampling,
        )
        self.hooks = GuardHookManager(
            run_id=self.run_id,
            control_plane=self.control_plane,
            inspector=self.inspector,
        )
        self._periodic_enabled = False
        self._targets: dict[str, _TargetBinding] = {}
        # These structures are read-through operational caches, not the durable
        # evidence record. Keep them bounded independently of store retention so a
        # long-running process cannot grow without limit merely because Guard stays
        # enabled for months.
        event_cache_limit = min(
            _GUARD_EVENT_CACHE_LIMIT,
            max(1, self.policy.retention.maximum_raw_events),
        )
        self._events_by_target: dict[str, deque[BehaviorEvent]] = defaultdict(
            lambda: deque(maxlen=event_cache_limit)
        )
        self._deviations_by_target: dict[str, deque[BehaviorDeviation]] = defaultdict(
            lambda: deque(maxlen=_GUARD_DEVIATION_CACHE_LIMIT)
        )
        self._assessments: OrderedDict[UUID, BehaviorAssessment] = OrderedDict()
        self._decisions: deque[GuardDecision] = deque(maxlen=_GUARD_DECISION_CACHE_LIMIT)
        self._leases: dict[str, InstrumentationLease] = {}
        self._candidate_deviations: set[UUID] = set()
        self._candidate_policies: dict[UUID, CandidateGuardPolicy] = {}
        self._quarantined_targets: set[str] = set()
        self._repair_opener: Callable[[str, tuple[BehaviorDeviation, ...]], None] | None = None
        self._candidate_rollback: Callable[[UUID, str], None] | None = None
        self._lock = threading.RLock()
        self._missing_logging_capabilities: frozenset[LoggingCapability] = frozenset()
        self.control_plane.register_handler(RuntimeActionKind.OPEN_REPAIR_EPISODE, self._handle_open_repair)
        self.control_plane.register_handler(RuntimeActionKind.ROLLBACK_REPAIR, self._handle_rollback)
        self.control_plane.register_handler(RuntimeActionKind.QUARANTINE_MODULE, self._handle_quarantine)
        from ..operator import register_guard_engine
        register_guard_engine(self)

    def refresh_authority_policy(self) -> None:
        """Reapply the process authority policy to Guard's declared policy."""
        self.policy = get_authority_runtime_context().apply(
            self._declared_policy, prefix="guard"
        )
        validate_guard_policy(self.policy)
        self.aggregator.policy = self.policy.aggregation
        self.baselines.policy = self.policy.baseline
        data_root = os.environ.get("CARETAKER_DATA_DIR")
        if data_root and self.policy.snapshots.enabled:
            self.behavior_statistics = BehaviorStatisticsRepository.from_guard_policy(
                data_root,
                self.policy.snapshots,
                environment_fingerprint=self.policy.baseline.environment_fingerprint,
                workload_label=self.policy.baseline.workload_label,
            )
            self.behavior_snapshot_store = BehaviorSnapshotStore(data_root)
            self.behavior_collection_scheduler = BehaviorCollectionScheduler(
                data_root,
                maximum_active=self.policy.snapshots.collection_max_active,
                maximum_pending=self.policy.snapshots.collection_max_pending,
                maximum_calls=self.policy.snapshots.collection_max_calls,
                soft_budget_seconds_per_minute=self.policy.snapshots.collection_soft_budget_seconds_per_minute,
                hard_budget_seconds_per_minute=self.policy.snapshots.collection_hard_budget_seconds_per_minute,
                soft_budget_calls_per_minute=self.policy.snapshots.collection_soft_budget_calls_per_minute,
                hard_budget_calls_per_minute=self.policy.snapshots.collection_hard_budget_calls_per_minute,
                soft_budget_process_memory_bytes=self.policy.snapshots.collection_soft_budget_process_memory_bytes,
                hard_budget_process_memory_bytes=self.policy.snapshots.collection_hard_budget_process_memory_bytes,
            )
        elif not self.policy.snapshots.enabled:
            self.behavior_statistics = None
            self.behavior_collection_scheduler = None
        self.detector.policy = self.policy.deviations
        self.audit_collector.collectors = self.policy.collectors
        self.audit_collector.attribution = self.policy.attribution
        self.audit_collector.sampling = self.policy.sampling

    def registered_target_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._targets))

    def recent_events(self, target_id: str, *, limit: int = 100) -> tuple[object, ...]:
        return tuple(self.store.recent_behavior_events(target_id=target_id, limit=limit))

    def sensitive_file_network_sequences(
        self,
        target_id: str,
        *,
        limit: int = 100,
        window_seconds: float = 60.0,
    ) -> tuple[dict[str, Any], ...]:
        """Return bounded sensitive-file/outbound-network evidence for a target."""
        if target_id not in self._targets:
            return ()
        bounded_limit = max(1, min(int(limit), 500))
        return correlate_sensitive_file_network_sequences(
            self.recent_events(target_id, limit=bounded_limit),
            maximum=min(bounded_limit, 128),
            window_seconds=window_seconds,
        )

    def recent_deviations(self, target_id: str, *, limit: int = 50) -> tuple[BehaviorDeviation, ...]:
        with self._lock:
            return _tail(self._deviations_by_target.get(target_id, ()), limit)

    def recent_target_inspections(self, target_id: str, *, limit: int = 20) -> tuple[object, ...]:
        with self._lock:
            binding = self._targets.get(target_id)
        if binding is None:
            return ()
        inspections = self.store.recent_inspections(binding.identity.module_name, limit=max(limit * 4, 50))
        qualified_names = {binding.identity.qualified_name}
        if binding.function_resolver is not None:
            try:
                current = binding.function_resolver()
            except Exception:
                current = None
            if current is not None:
                qualified_names.add(getattr(current, "__qualname__", binding.identity.qualified_name))
        return tuple(
            item for item in inspections
            if getattr(getattr(item, "subject", None), "qualified_name", None) in qualified_names
        )[-limit:]

    def _control_context(self) -> dict[str, object]:
        context: dict[str, object] = {"guard": self}
        if self.work_registry is not None:
            context["work_registry"] = self.work_registry
        return context

    def install(
        self,
        *,
        audit_hooks: bool = True,
        import_hook: bool = True,
        periodic: bool = True,
        system_hooks: bool = True,
    ) -> None:
        if self.policy.mode is GuardMode.DISABLED:
            self._periodic_enabled = False
            return
        if audit_hooks and self.policy.collectors.audit_hooks:
            self.audit_collector.install()
        if import_hook:
            self.finder.install()
        if system_hooks:
            self.hooks.install()
        self._periodic_enabled = periodic
        if periodic:
            for target in self.policy.targets:
                if target.periodic.enabled:
                    self.periodic.register_module(
                        target.module_pattern.removesuffix(".*"),
                        interval_seconds=target.periodic.interval_seconds,
                    )
            if self.policy.targets or self._targets:
                self.periodic.start()

    def close(self) -> None:
        self.audit_collector.disable()
        self.finder.uninstall()
        self.hooks.uninstall()
        self.periodic.stop()
        self._periodic_enabled = False

    @property
    def missing_logging_capabilities(self) -> frozenset[LoggingCapability]:
        return self._missing_logging_capabilities

    def update_logging_capabilities(
        self,
        available: frozenset[LoggingCapability],
    ) -> frozenset[LoggingCapability]:
        required = mode_requirements((LoggingMode.GUARD,))
        missing = required - available
        self._missing_logging_capabilities = frozenset(missing)
        if not missing:
            return frozenset()
        signal = RuntimeSignal.create(
            domain=SignalDomain.INTERNAL, kind="guard.logging_capability_missing",
            severity=SignalSeverity.HIGH, run_id=self.run_id,
            source_component="guard.engine",
            attributes={"missing": [item.name for item in sorted(missing, key=lambda item: item.name)]},
        )
        self.control_plane.submit(signal, context=self._control_context())
        action = self.policy.logging_failure_action
        if action is RequiredCapabilityFailureAction.DISABLE_COMPONENT:
            self.close()
        elif action is RequiredCapabilityFailureAction.REFUSE_MODE_TRANSITION:
            raise RuntimeError("Guard cannot activate because required logging capabilities are unavailable")
        elif action is RequiredCapabilityFailureAction.STOP_APPLICATION:
            raise SystemExit("Strict Guard policy requested application shutdown because required logging is unavailable")
        return self._missing_logging_capabilities

    def configure_repair_callbacks(
        self,
        *,
        open_repair: Callable[[str, tuple[BehaviorDeviation, ...]], None] | None = None,
        rollback_candidate: Callable[[UUID, str], None] | None = None,
    ) -> None:
        self._repair_opener = open_repair
        self._candidate_rollback = rollback_candidate

    def monitoring_configuration(self, target_id: str) -> dict[str, object]:
        binding = self._targets.get(target_id)
        binding_value = asdict(binding.binding) if binding is not None else {}
        snapshots = self.policy.snapshots
        configuration = {
            "guard_mode": self.policy.mode.name,
            "collectors": asdict(self.policy.collectors),
            "attribution": asdict(self.policy.attribution),
            "sampling": asdict(self.policy.sampling),
            "aggregation": asdict(self.policy.aggregation),
            # Only statistical settings that change the meaning/coverage of the
            # accumulated data are generation-breaking. Materialization cadence
            # changes when artifacts are sealed, not what an observation means.
            "statistics": {
                "statistics_target": snapshots.statistics_target,
                "maximum_resources": snapshots.maximum_resources,
                "maximum_return_categories": snapshots.maximum_return_categories,
                "maximum_return_shapes": snapshots.maximum_return_shapes,
                "randomized_epoch_boundaries": snapshots.randomized_epoch_boundaries,
                "randomized_epoch_min_samples": snapshots.randomized_epoch_min_samples,
                "randomized_epoch_max_samples": snapshots.randomized_epoch_max_samples,
                "randomized_epoch_seed_commitment": (
                    hashlib.sha256(str(snapshots.randomized_epoch_seed).encode("ascii")).hexdigest()
                    if snapshots.randomized_epoch_seed is not None
                    else None
                ),
            },
            "binding": binding_value,
            "target_monitoring": dict(binding.monitoring_configuration or {}) if binding is not None else {},
        }
        return _configuration_value(configuration)

    def monitoring_fingerprint(self, target_id: str) -> str:
        return monitoring_configuration_fingerprint(self.monitoring_configuration(target_id))

    def _restore_accepted_baseline(self, target_id: str, identity: CodeIdentity) -> None:
        if self.behavior_snapshot_store is None:
            return
        code_hash = identity.source_hash or identity.bytecode_hash
        restored = self.behavior_snapshot_store.load_accepted_guard_baseline(
            target_id,
            code_hash=code_hash,
            monitoring_fingerprint=self.monitoring_fingerprint(target_id),
        )
        if restored is None:
            return
        record, envelope = restored
        snapshot = envelope["snapshot"]
        profile_value = dict(snapshot.get("profile") or {})
        baseline = BehaviorBaseline(
            baseline_id=UUID(str(record["baseline_id"])),
            subject=identity,
            workload_label=snapshot.get("workload_label"),
            environment_fingerprint=snapshot.get("environment_fingerprint"),
            created_at=datetime.fromisoformat(str(snapshot["created_at"])),
            accepted_at=datetime.fromisoformat(str(record["accepted_at"])),
            observations=max(1, int(profile_value.get("window_count") or 0)),
            profile=BehaviorProfile(
                event_kind_counts=dict(profile_value.get("event_kind_counts") or {}),
                resource_counts=dict(profile_value.get("resource_counts") or {}),
                call_count=int(profile_value.get("call_count") or 0),
                event_count=int(profile_value.get("event_count") or 0),
                network_destinations=tuple(profile_value.get("network_destinations") or ()),
                filesystem_roots=tuple(profile_value.get("filesystem_roots") or ()),
                subprocesses=tuple(profile_value.get("subprocesses") or ()),
                imports=tuple(profile_value.get("imports") or ()),
                dynamic_code_operations=tuple(profile_value.get("dynamic_code_operations") or ()),
                success_count=int(profile_value.get("success_count") or 0),
                failure_count=int(profile_value.get("failure_count") or 0),
                return_category_counts=dict(profile_value.get("return_category_counts") or {}),
                return_shape_counts=dict(profile_value.get("return_shape_counts") or {}),
                return_observations_available=bool(
                    profile_value.get("return_observations_available", False)
                ),
                statistics=dict(profile_value.get("statistics") or {}),
                sampling_provenance=dict(profile_value.get("sampling_provenance") or {}),
            ),
            state=BaselineState.ACCEPTED,
            generation_id=str(record.get("generation_id") or "") or None,
        )
        self.baselines.restore(baseline)
        self._sealed_baseline_ids.add(baseline.baseline_id)
        self.store.record_guard_baseline(baseline)

    def _enrich_accepted_baseline_statistics(
        self, target_id: str, baseline: BehaviorBaseline
    ) -> BehaviorBaseline:
        if self.behavior_statistics is None:
            return baseline
        capture = self.behavior_statistics.current_capture(target_id)
        if capture is None:
            return baseline
        identity = baseline.subject
        code_hash = identity.source_hash or identity.bytecode_hash
        if capture.get("code_hash") != code_hash:
            return baseline
        if capture.get("monitoring_fingerprint") != self.monitoring_fingerprint(target_id):
            return baseline
        profile_value = dict(capture.get("profile") or {})
        enriched = replace(
            baseline,
            profile=replace(
                baseline.profile,
                success_count=int(profile_value.get("success_count") or baseline.profile.success_count),
                failure_count=int(profile_value.get("failure_count") or baseline.profile.failure_count),
                statistics=dict(profile_value.get("statistics") or baseline.profile.statistics),
                sampling_provenance=dict(
                    profile_value.get("sampling_provenance") or baseline.profile.sampling_provenance
                ),
            ),
        )
        self.baselines.restore(enriched)
        return enriched

    def _queue_accepted_baseline_snapshot(
        self, target_id: str, baseline: BehaviorBaseline
    ) -> None:
        if self.behavior_statistics is None or baseline.baseline_id in self._sealed_baseline_ids:
            return
        identity = baseline.subject
        profile = baseline.profile
        code_hash = identity.source_hash or identity.bytecode_hash
        monitoring_configuration = self.monitoring_configuration(target_id)
        monitoring_fingerprint = monitoring_configuration_fingerprint(monitoring_configuration)
        baseline_profile = {
            "window_count": baseline.observations,
            "call_count": profile.call_count,
            "event_count": profile.event_count,
            "event_kind_counts": dict(profile.event_kind_counts),
            "resource_counts": dict(profile.resource_counts),
            "network_destinations": list(profile.network_destinations),
            "filesystem_roots": list(profile.filesystem_roots),
            "subprocesses": list(profile.subprocesses),
            "imports": list(profile.imports),
            "dynamic_code_operations": list(profile.dynamic_code_operations),
            "resource_coverage_complete": True,
            "distinct_resource_count": len(profile.resource_counts),
            "success_count": profile.success_count,
            "failure_count": profile.failure_count,
            "return_category_counts": dict(profile.return_category_counts),
            "return_shape_counts": dict(profile.return_shape_counts),
            "return_observations_available": profile.return_observations_available,
            "statistics": dict(profile.statistics),
            "sampling_provenance": dict(profile.sampling_provenance),
        }
        active_capture = self.behavior_statistics.current_capture(target_id)
        active_generation_id = None
        active_behavior_revision = 0
        if (
            active_capture is not None
            and active_capture.get("code_hash") == code_hash
            and active_capture.get("monitoring_fingerprint") == monitoring_fingerprint
        ):
            active_generation_id = str(active_capture.get("generation_id") or "") or None
            active_behavior_revision = int(active_capture.get("behavior_revision") or 0)
            active_profile = dict(active_capture.get("profile") or {})
            # Guard remains authoritative for the accepted categorical behavior
            # profile.  The statistical accumulator contributes distribution and
            # sampling provenance from the same compatible generation.
            baseline_profile.update(
                {
                    "statistics": dict(active_profile.get("statistics") or {}),
                    "sampling_provenance": dict(active_profile.get("sampling_provenance") or {}),
                    "success_count": int(active_profile.get("success_count") or 0),
                    "failure_count": int(active_profile.get("failure_count") or 0),
                }
            )
        self.behavior_statistics.queue_guard_baseline(
            target_id=target_id,
            subject={
                "target_id": target_id,
                "module_name": identity.module_name,
                "qualified_name": identity.qualified_name,
                "source_path": identity.source_path,
            },
            code_hash=code_hash,
            code_hash_kind=(
                "function-source-sha256" if identity.source_hash else "function-bytecode-sha256"
            ),
            monitoring_configuration=monitoring_configuration,
            profile=baseline_profile,
            baseline_id=baseline.baseline_id,
            generation_id=active_generation_id or baseline.generation_id,
            behavior_revision=active_behavior_revision,
        )
        self._sealed_baseline_ids.add(baseline.baseline_id)

    def register_target(
        self,
        target_id: str,
        function: Callable,
        binding: GuardBinding,
        function_resolver: Callable[[], Callable] | None = None,
        *,
        periodic: bool = True,
        monitoring_configuration: Mapping[str, object] | None = None,
    ) -> None:
        identity = identify_function(function)
        with self._lock:
            self._targets[target_id] = _TargetBinding(
                function, binding, identity, function_resolver, monitoring_configuration
            )
        self.store.record_code_identity(identity)
        if self.policy.mode is GuardMode.DISABLED:
            return
        self._restore_accepted_baseline(target_id, identity)
        self.inspector.inspect_function(function, kind=InspectionKind.POST_LOAD)
        if binding.enabled and periodic:
            if function_resolver is not None:
                self.periodic.register_function_resolver(
                    f"target:{target_id}",
                    function_resolver,
                )
            else:
                self.periodic.register_function(function)
            if self._periodic_enabled:
                self.periodic.start()

    def before_call(
        self,
        target_id: str,
        function: Callable,
        call_id: UUID,
        *,
        candidate_id: UUID | None,
    ) -> None:
        if self.policy.mode is GuardMode.DISABLED:
            return
        if target_id in self._quarantined_targets:
            raise PermissionError(f"Guard quarantined target {target_id}")
        binding = self._targets.get(target_id)
        if binding is None or not binding.binding.enabled:
            return
        identity = identify_function(function)
        event = BehaviorEvent.create(
            event_kind=BehaviorEventKind.FUNCTION_CALL,
            operation="function.call.started",
            code_identity=identity,
            run_id=self.run_id,
            call_id=call_id,
            target_id=target_id,
            process_id=os.getpid(),
            thread_id=threading.get_ident(),
            attributes={
                "observation_stage": snapshot_context().get("observation_stage") or ("POST_REPAIR_BEHAVIOR" if candidate_id else "GUARD"),
                "monitoring_fingerprint": snapshot_context().get("monitoring_fingerprint"),
            },
            outcome=EventOutcome.OBSERVED,
        )
        self.record_event(event)
        lease = self._leases.get(target_id)
        if lease is not None and lease.remaining_executions > 0:
            with self._lock:
                self._leases[target_id] = replace(
                    lease,
                    remaining_executions=lease.remaining_executions - 1,
                )

    def after_call(
        self,
        target_id: str,
        function: Callable,
        call_id: UUID,
        *,
        candidate_id: UUID | None,
        succeeded: bool,
        elapsed_seconds: float,
        result: Any = _NO_RETURN_OBSERVATION,
    ) -> None:
        if self.policy.mode is GuardMode.DISABLED:
            return
        binding = self._targets.get(target_id)
        if binding is None or not binding.binding.enabled:
            return
        identity = identify_function(function)
        attributes = {
            "observation_stage": snapshot_context().get("observation_stage") or ("POST_REPAIR_BEHAVIOR" if candidate_id else "GUARD"),
            "monitoring_fingerprint": snapshot_context().get("monitoring_fingerprint"),
        }
        if succeeded and result is not _NO_RETURN_OBSERVATION:
            attributes["return_category"] = ValueSnapshot(
                type_name="caretaker.return-category",
                representation=observed_return_category(result),
            )
            attributes["return_shape"] = ValueSnapshot(
                type_name="caretaker.return-shape",
                representation=observed_return_shape(result),
            )
        event = BehaviorEvent.create(
            event_kind=BehaviorEventKind.FUNCTION_CALL,
            operation="function.call.completed",
            code_identity=identity,
            run_id=self.run_id,
            call_id=call_id,
            target_id=target_id,
            process_id=os.getpid(),
            thread_id=threading.get_ident(),
            duration_seconds=elapsed_seconds,
            outcome=EventOutcome.SUCCEEDED if succeeded else EventOutcome.FAILED,
            attributes=attributes,
        )
        self.record_event(event)
        inspection = self.inspector.inspect_function(
            function,
            kind=(InspectionKind.CANDIDATE_PROBATION if candidate_id else InspectionKind.FUNCTION_CALL),
            reference_id=(f"candidate:{candidate_id}" if candidate_id else None),
        )
        if inspection.differences_from_load:
            self._signal_inspection(inspection, target_id=target_id, candidate_id=candidate_id)

    def record_event(self, event: BehaviorEvent) -> None:
        if self.policy.mode is GuardMode.DISABLED:
            return
        if not self._event_in_scope(event):
            return
        self.store.record_code_identity(event.code_identity)
        self.store.append_behavior_event(event)
        if event.target_id is not None:
            with self._lock:
                self._events_by_target[event.target_id].append(event)
            if self.behavior_statistics is not None and event.target_id in self._targets:
                try:
                    self.behavior_statistics.observe_event(
                        event,
                        monitoring_configuration=self.monitoring_configuration(event.target_id),
                    )
                except Exception:
                    # Statistical snapshotting is evidence infrastructure. It must
                    # fail contained rather than changing application behavior.
                    pass
        window = self.aggregator.consume(event)
        if window is not None:
            self._process_window(window, target_id=event.target_id)

    def _event_in_scope(self, event: BehaviorEvent) -> bool:
        if event.target_id is not None and event.target_id in self._targets:
            binding = self._targets[event.target_id].binding
            if event.event_kind in {BehaviorEventKind.NETWORK_DNS, BehaviorEventKind.NETWORK_CONNECT, BehaviorEventKind.NETWORK_SEND}:
                return binding.observe_network
            if event.event_kind in {BehaviorEventKind.FILE_OPEN, BehaviorEventKind.FILE_READ, BehaviorEventKind.FILE_WRITE, BehaviorEventKind.DIRECTORY_LIST, BehaviorEventKind.DIRECTORY_WALK}:
                return binding.observe_filesystem
            if event.event_kind is BehaviorEventKind.SUBPROCESS:
                return binding.observe_subprocesses
            if event.event_kind is BehaviorEventKind.IMPORT:
                return binding.observe_imports
            return True
        if event.target_id is None and not self.policy.collectors.unattributed_events:
            return False
        if not self.policy.targets:
            return True
        module_name = event.code_identity.module_name
        return any(
            module_name == target.module_pattern
            or (target.module_pattern.endswith(".*") and module_name.startswith(target.module_pattern[:-1]))
            for target in self.policy.targets
        )

    def close_target_window(self, target_id: str):
        binding = self._targets.get(target_id)
        if binding is None:
            return None
        window = self.aggregator.close_window(binding.identity)
        if window is not None:
            self._process_window(window, target_id=target_id)
        return window

    def accept_baseline(
        self,
        target_id: str,
        *,
        actor_type: str = "application",
        actor_id: str = "application-local",
        reason: str = "direct Guard API request",
    ) -> BehaviorBaseline:
        """Accept a runtime baseline through Guard's single authority path.

        ``BaselineManager`` remains an in-memory analytics primitive.  This
        method is the consequential operation: it persists the accepted
        baseline and a separate authority record containing the actor,
        effective policy, and authority generation.
        """
        actor_type = str(actor_type).strip()
        actor_id = str(actor_id).strip()
        reason = str(reason).strip()
        if not actor_type or len(actor_type) > 64:
            raise ValueError("baseline acceptance actor_type must be 1-64 characters")
        if not actor_id or len(actor_id) > 256:
            raise ValueError("baseline acceptance actor_id must be 1-256 characters")
        if not reason or len(reason) > 500:
            raise ValueError("baseline acceptance reason must be 1-500 characters")
        binding = self._targets[target_id]
        active_capture = (
            self.behavior_statistics.current_capture(target_id)
            if self.behavior_statistics is not None
            else None
        )
        behavior_revision = (
            int(active_capture.get("behavior_revision") or 0)
            if active_capture is not None
            else 0
        )
        if behavior_revision > 0 and active_capture is not None:
            baseline = self.baselines.accept_statistics(
                binding.identity,
                profile=dict(active_capture.get("profile") or {}),
                generation_id=str(active_capture.get("generation_id") or ""),
            )
        else:
            baseline = self.baselines.accept(binding.identity)
        baseline = self._enrich_accepted_baseline_statistics(target_id, baseline)
        self.store.record_guard_baseline(baseline)
        authority = get_authority_runtime_context().effective
        policy_payload = json.dumps(
            asdict(self.policy),
            sort_keys=True,
            separators=(",", ":"),
            default=lambda value: value.name if isinstance(value, Enum) else str(value),
        ).encode("utf-8")
        acceptance = BaselineAcceptanceRecord(
            acceptance_id=uuid4(),
            baseline_id=baseline.baseline_id,
            target_id=target_id,
            scope="function",
            actor_type=actor_type,
            actor_id=actor_id,
            reason=reason,
            policy_generation=authority.generation,
            policy_fingerprint=hashlib.sha256(policy_payload).hexdigest(),
            authority_generation=authority.generation,
            authority_fingerprint=authority.fingerprint,
            accepted_at=baseline.accepted_at or utcnow(),
        )
        self.store.record_baseline_acceptance(acceptance)
        with self._lock:
            self._baseline_acceptances[target_id] = acceptance
        self._queue_accepted_baseline_snapshot(target_id, baseline)
        return baseline

    def baseline_acceptance(self, target_id: str) -> BaselineAcceptanceRecord | None:
        """Return the latest authority record for a target, if one exists."""
        with self._lock:
            return self._baseline_acceptances.get(target_id)

    def seal_behavior_snapshot(self, target_id: str, *, reason: str) -> object | None:
        """Queue the current statistical behavior generation at a lifecycle boundary."""
        if self.behavior_statistics is None:
            return None
        return self.behavior_statistics.seal_target(target_id, reason=reason)

    def recent_summary(self, target_id: str, *, calls: int = 20) -> BehaviorProfileSummary | None:
        binding = self._targets.get(target_id)
        if binding is None:
            return None
        baseline = self.baselines.summary(binding.identity)
        if baseline is not None:
            return baseline
        events = _tail(self._events_by_target.get(target_id, ()), max(1, calls * 10))
        if not events:
            return None
        kinds: dict[str, int] = defaultdict(int)
        network: set[str] = set()
        filesystem: set[str] = set()
        subprocesses: set[str] = set()
        imports: set[str] = set()
        dynamic: set[str] = set()
        call_ids = set()
        for event in events:
            kinds[event.event_kind.name] += 1
            if event.call_id:
                call_ids.add(event.call_id)
            if event.resource:
                if event.resource.kind == "network":
                    network.add(event.resource.value)
                elif event.resource.kind in {"file", "directory"}:
                    filesystem.add(event.resource.value)
                elif event.resource.kind == "subprocess":
                    subprocesses.add(event.resource.value)
                elif event.resource.kind == "import":
                    imports.add(event.resource.value)
                elif event.resource.kind == "dynamic-code":
                    dynamic.add(event.resource.value)
        return BehaviorProfileSummary(
            subject=binding.identity,
            window_count=0,
            call_count=len(call_ids),
            event_count=len(events),
            event_kind_counts=dict(kinds),
            network_destinations=tuple(sorted(network)),
            filesystem_roots=tuple(sorted(filesystem)),
            subprocesses=tuple(sorted(subprocesses)),
            imports=tuple(sorted(imports)),
            dynamic_code_operations=tuple(sorted(dynamic)),
        )

    def execution_effect_observation(
        self, target_id: str, *, calls: int = 20
    ) -> EffectObservation | None:
        """Summarize bounded Guard events for a rollout safety decision.

        The in-process event cache is intentionally reported as incomplete: it
        may be sampled or bounded, and therefore cannot establish that no effect
        occurred. A trusted complete observation must come from a dedicated
        collector or isolation adapter.
        """

        if target_id not in self._targets:
            return None
        events = _tail(self._events_by_target.get(target_id, ()), max(1, calls * 10))
        return EffectObservation.from_events(events, complete=False)

    def assess_shadow_eligibility(
        self,
        target_id: str,
        contract: FunctionExecutionContract,
        *,
        calls: int = 20,
    ) -> ShadowEligibility:
        observation = self.execution_effect_observation(target_id, calls=calls)
        return assess_shadow_eligibility(contract, observation)

    def current_behavior_summary(
        self, target_id: str, *, calls: int = 50
    ) -> BehaviorProfileSummary | None:
        """Return observed behavior for the target's current code generation.

        Unlike ``recent_summary``, this method never substitutes an accepted Guard
        baseline. It is intended for operator snapshots and comparisons.
        """
        binding = self._targets.get(target_id)
        if binding is None:
            return None
        function = binding.function
        if binding.function_resolver is not None:
            try:
                function = binding.function_resolver()
            except Exception:
                function = binding.function
        identity = identify_function(function)
        events = [
            event
            for event in self._events_by_target.get(target_id, ())
            if event.code_identity.module_name == identity.module_name
            and event.code_identity.qualified_name == identity.qualified_name
            and (identity.source_hash is None or event.code_identity.source_hash == identity.source_hash)
            and (identity.bytecode_hash is None or event.code_identity.bytecode_hash == identity.bytecode_hash)
        ][-max(1, calls * 10):]
        if not events:
            return BehaviorProfileSummary(
                subject=identity,
                window_count=0,
                call_count=0,
                event_count=0,
                event_kind_counts={},
                network_destinations=(),
                filesystem_roots=(),
                subprocesses=(),
                imports=(),
                dynamic_code_operations=(),
            )
        kinds: dict[str, int] = defaultdict(int)
        return_category_counts: dict[str, int] = defaultdict(int)
        return_shape_counts: dict[str, int] = defaultdict(int)
        return_observations_available = False
        success_count = 0
        failure_count = 0
        network: set[str] = set()
        filesystem: set[str] = set()
        subprocesses: set[str] = set()
        imports: set[str] = set()
        dynamic: set[str] = set()
        call_ids = set()
        for event in events:
            kinds[event.event_kind.name] += 1
            if event.call_id:
                call_ids.add(event.call_id)
            if event.event_kind is BehaviorEventKind.FUNCTION_CALL and event.outcome is EventOutcome.SUCCEEDED:
                if event.operation == "function.call.completed":
                    success_count += 1
                for name, counts in (
                    ("return_category", return_category_counts),
                    ("return_shape", return_shape_counts),
                ):
                    value = (event.attributes or {}).get(name)
                    value = getattr(value, "representation", value)
                    if value is not None and str(value).strip():
                        return_observations_available = True
                        counts[str(value).strip()] += 1
            elif (
                event.event_kind is BehaviorEventKind.FUNCTION_CALL
                and event.operation == "function.call.completed"
                and event.outcome is EventOutcome.FAILED
            ):
                failure_count += 1
            if event.resource:
                if event.resource.kind == "network":
                    network.add(event.resource.value)
                elif event.resource.kind in {"file", "directory"}:
                    filesystem.add(event.resource.value)
                elif event.resource.kind == "subprocess":
                    subprocesses.add(event.resource.value)
                elif event.resource.kind == "import":
                    imports.add(event.resource.value)
                elif event.resource.kind == "dynamic-code":
                    dynamic.add(event.resource.value)
        return BehaviorProfileSummary(
            subject=identity,
            window_count=0,
            call_count=len(call_ids),
            event_count=len(events),
            event_kind_counts=dict(kinds),
            network_destinations=tuple(sorted(network)),
            filesystem_roots=tuple(sorted(filesystem)),
            subprocesses=tuple(sorted(subprocesses)),
            imports=tuple(sorted(imports)),
            dynamic_code_operations=tuple(sorted(dynamic)),
            return_category_counts=dict(return_category_counts),
            return_shape_counts=dict(return_shape_counts),
            return_observations_available=return_observations_available,
            success_count=success_count,
            failure_count=failure_count,
        )

    def behavior_capture(self, target_id: str, *, calls: int = 50) -> dict[str, object]:
        if self.behavior_statistics is not None:
            capture = self.behavior_statistics.cut_capture(target_id)
            if capture is not None:
                return capture
        summary = self.current_behavior_summary(target_id, calls=calls)
        if summary is None:
            raise KeyError(f"Unknown Guard target {target_id}")
        identity = summary.subject
        code_hash = identity.source_hash or identity.bytecode_hash
        code_hash_kind = (
            "function-source-sha256" if identity.source_hash else "function-bytecode-sha256"
        )
        return {
            "scope": "function",
            "subject_key": f"function:{target_id}",
            "subject": {
                "target_id": target_id,
                "module_name": identity.module_name,
                "qualified_name": identity.qualified_name,
                "source_path": identity.source_path,
            },
            "code_hash": code_hash,
            "code_hash_kind": code_hash_kind,
            "monitoring_configuration": self.monitoring_configuration(target_id),
            "monitoring_fingerprint": self.monitoring_fingerprint(target_id),
            "statistics_schema_version": 1,
            "environment_fingerprint": self.policy.baseline.environment_fingerprint,
            "workload_label": self.policy.baseline.workload_label,
            "profile": {
                "window_count": summary.window_count,
                "call_count": summary.call_count,
                "event_count": summary.event_count,
                "event_kind_counts": dict(summary.event_kind_counts),
                "network_destinations": list(summary.network_destinations),
                "filesystem_roots": list(summary.filesystem_roots),
                "subprocesses": list(summary.subprocesses),
                "imports": list(summary.imports),
                "dynamic_code_operations": list(summary.dynamic_code_operations),
                "return_category_counts": dict(summary.return_category_counts),
                "return_shape_counts": dict(summary.return_shape_counts),
                "return_observations_available": summary.return_observations_available,
            },
            "children": [],
        }

    def schedule_behavior_collection(
        self,
        *,
        scope: str,
        subject: str,
        calls: int,
        requested_by: str,
        reason: str,
        operation: Callable[[], Mapping[str, Any]],
        priority: int = 0,
        deadline: str | None = None,
        requested_generation: str | None = None,
    ) -> dict[str, Any]:
        """Run an operator collection through the policy-governed scheduler."""
        def operation_with_generation() -> dict[str, Any]:
            capture = dict(operation())
            if not str(capture.get("generation_id") or "").strip():
                subject_key = str(capture.get("subject_key") or f"{scope}:{subject}")
                code_hash = str(capture.get("code_hash") or "") or None
                monitoring_fingerprint = (
                    str(capture.get("monitoring_fingerprint") or "") or None
                )
                try:
                    statistics_schema_version = int(
                        capture.get("statistics_schema_version") or 1
                    )
                except (TypeError, ValueError) as exc:
                    raise ValueError(
                        "behavior capture has an invalid statistics schema version"
                    ) from exc
                capture["generation_id"] = behavior_generation_id(
                    subject_key=subject_key,
                    code_hash=code_hash,
                    monitoring_fingerprint=monitoring_fingerprint,
                    statistics_schema_version=statistics_schema_version,
                )
            return capture

        scheduler = self.behavior_collection_scheduler
        if scheduler is None:
            capture = operation_with_generation()
            if requested_generation is not None and str(capture.get("generation_id") or "") != str(
                requested_generation
            ).strip():
                raise ValueError(
                    "behavior collection generation does not match requested generation"
                )
            return capture
        capture, _request = scheduler.execute(
            scope=scope,
            subject=subject,
            requested_calls=calls,
            requested_by=requested_by,
            reason=reason,
            priority=priority,
            deadline=deadline,
            requested_generation=requested_generation,
            authority_policy_generation=str(
                get_authority_runtime_context().effective.generation
            ),
            authority_policy_fingerprint=get_authority_runtime_context().effective.fingerprint,
            operation=operation_with_generation,
        )
        return capture

    def behavior_collection_status(self) -> dict[str, Any]:
        scheduler = self.behavior_collection_scheduler
        if scheduler is None:
            return {
                "enabled": False,
                "reason": "Guard behavior snapshots are disabled or have no data root",
            }
        return {
            "enabled": True,
            "automatic_promotion": self.policy.snapshots.collection_auto_promote,
            "automatic_max_promoted": self.policy.snapshots.collection_auto_max_promoted,
            "automatic_max_waiting": self.policy.snapshots.collection_auto_max_waiting,
            "automatic_prioritize_signals": self.policy.snapshots.collection_auto_prioritize_signals,
            "automatic_stale_after_seconds": self.policy.snapshots.collection_auto_stale_after_seconds,
            **scheduler.status(),
        }

    def behavior_collection_backlog(self, *, limit: int = 500) -> dict[str, Any]:
        """Describe current-generation behavior coverage without scheduling work."""
        if self.behavior_statistics is None or self.behavior_snapshot_store is None:
            return {
                "enabled": False,
                "reason": "Guard behavior snapshots are disabled or have no data root",
                "items": [],
                "counts": {},
            }
        scheduler = self.behavior_collection_scheduler
        scheduler_status = scheduler.status() if scheduler is not None else {}
        resource_budget = dict(scheduler_status.get("resource_budget") or {})
        subject_costs = {
            f"{item.get('scope')}:{item.get('subject')}": item
            for item in resource_budget.get("recent_subject_costs", ())
            if isinstance(item, Mapping)
        }
        summaries = {
            (str(item.get("subject_key") or ""), str(item.get("generation_id") or "")): item
            for item in self.behavior_snapshot_store.list_summaries(limit=500)
            if item.get("verified") is not False
        }
        requests = {
            (str(item.get("scope") or ""), str(item.get("subject") or "")): item
            for item in self.behavior_collection_requests(limit=500)
            if str(item.get("status") or "") in {"QUEUED", "ACTIVE", "FAILED", "EXPIRED", "CANCELLED"}
        }
        items: list[dict[str, Any]] = []
        prioritize_signals = self.policy.snapshots.collection_auto_prioritize_signals
        stale_after = float(self.policy.snapshots.collection_auto_stale_after_seconds)
        now = utcnow()
        with self._lock:
            target_ids = tuple(sorted(self._targets))
        for target_id in target_ids:
            binding = self._targets[target_id]
            function = binding.function
            if binding.function_resolver is not None:
                try:
                    function = binding.function_resolver()
                except Exception:
                    function = binding.function
            identity = identify_function(function)
            code_hash = identity.source_hash or identity.bytecode_hash
            subject_key = f"function:{target_id}"
            generation_id = behavior_generation_id(
                subject_key=subject_key,
                code_hash=code_hash,
                monitoring_fingerprint=self.monitoring_fingerprint(target_id),
            )
            capture = self.behavior_statistics.current_capture(target_id)
            active_calls = int((capture or {}).get("profile", {}).get("call_count") or 0)
            summary = summaries.get((subject_key, generation_id))
            snapshot_calls = int(
                ((summary or {}).get("profile") or {}).get("coverage_call_count")
                or ((summary or {}).get("profile") or {}).get("call_count")
                or 0
            )
            request = requests.get(("function", target_id))
            if request is not None:
                requested_generation = str(request.get("requested_generation") or "")
                if requested_generation and requested_generation != generation_id:
                    # Retain old-generation work in the scheduler, but do not
                    # let it classify or suppress coverage for this generation.
                    request = None
            priority = 0
            priority_reasons: list[str] = []
            snapshot_age_seconds: float | None = None
            if summary is not None:
                created_at = str(summary.get("created_at") or "")
                try:
                    created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                    if created.tzinfo is not None:
                        snapshot_age_seconds = max(0.0, (now - created.astimezone(timezone.utc)).total_seconds())
                except (TypeError, ValueError, OverflowError):
                    snapshot_age_seconds = None
            if prioritize_signals:
                if snapshot_age_seconds is not None and snapshot_age_seconds >= stale_after:
                    priority = max(priority, 100)
                    priority_reasons.append("stale_snapshot")
                current_identity = identity
                current_code_hash = code_hash
                suspicious = any(
                    deviation.subject.module_name == current_identity.module_name
                    and deviation.subject.qualified_name == current_identity.qualified_name
                    and (deviation.subject.source_hash or deviation.subject.bytecode_hash) == current_code_hash
                    and deviation.significance_score >= self.policy.deviations.significance_threshold
                    for deviation in self.recent_deviations(target_id, limit=20)
                )
                if suspicious:
                    priority = max(priority, 200)
                    priority_reasons.append("recent_significant_deviation")
            if request is not None and request.get("status") in {"QUEUED", "ACTIVE"}:
                status = "queued" if request["status"] == "QUEUED" else "actively_collecting"
                reason = f"operator request is {str(request['status']).lower()}"
            elif request is not None and request.get("status") in {"FAILED", "EXPIRED"}:
                status = "failed"
                reason = str(request.get("error") or request.get("outcome") or "collection request failed")
            elif request is not None and request.get("status") == "CANCELLED":
                status = "deferred"
                reason = str(request.get("error") or "operator cancelled collection")
            elif summary is not None and snapshot_calls > 0:
                if "recent_significant_deviation" in priority_reasons:
                    status = "suspicious"
                    reason = "current generation has a recent significant Guard deviation"
                elif "stale_snapshot" in priority_reasons:
                    status = "stale"
                    reason = f"verified snapshot is older than {stale_after:g} seconds"
                else:
                    status = "sufficiently_covered"
                    reason = "verified snapshot covers the current code and monitoring generation"
            elif active_calls > 0:
                status = "actively_collecting"
                reason = "current generation has completed calls but no useful verified snapshot"
            else:
                status = "armed_waiting"
                reason = "current generation has no completed calls"
            items.append(
                {
                    "target_id": target_id,
                    "subject_key": subject_key,
                    "generation_id": generation_id,
                    "status": status,
                    "reason": reason,
                    "active_calls": active_calls,
                    "snapshot_calls": snapshot_calls,
                    "snapshot_id": (summary or {}).get("snapshot_id"),
                    "request_id": (request or {}).get("request_id"),
                    "priority": priority,
                    "priority_reasons": priority_reasons,
                    "snapshot_age_seconds": snapshot_age_seconds,
                    "recent_collection_cost": subject_costs.get(
                        f"function:{target_id}"
                    ),
                }
            )
        bounded = items[: max(1, min(int(limit), 500))]
        counts: dict[str, int] = {}
        for item in items:
            status = str(item["status"])
            counts[status] = counts.get(status, 0) + 1
        return {
            "enabled": True,
            "items": bounded,
            "counts": counts,
            "total": len(items),
            "resource_budget": resource_budget,
            "queue_pressure": dict(scheduler_status.get("queue_pressure") or {}),
        }

    def behavior_collection_requests(self, *, limit: int = 100) -> tuple[dict[str, Any], ...]:
        scheduler = self.behavior_collection_scheduler
        if scheduler is None:
            return ()
        return scheduler.list_requests(limit=limit)

    def automatic_behavior_collection_cycle(self) -> dict[str, Any]:
        """Promote a bounded number of missing adaptive generations.

        The cycle is intentionally separate from application calls and is
        disabled by default. It only promotes current-generation targets that
        the read-only backlog classifies as ``armed_waiting``; existing adaptive
        policies continue to govern Behavior sampling and any later repair gate.
        """
        snapshots = self.policy.snapshots
        if not snapshots.collection_auto_promote:
            return {
                "enabled": False,
                "promoted": [],
                "reason": "automatic behavior collection promotion is disabled by policy",
            }
        if self.behavior_collection_scheduler is None:
            return {
                "enabled": False,
                "promoted": [],
                "reason": "Guard behavior collection scheduling is unavailable",
            }

        from ..adaptive import get_adaptive_controller

        backlog = self.behavior_collection_backlog(limit=500)
        with self._lock:
            controllers = {
                target_id: get_adaptive_controller(target_id)
                for target_id in self._targets
            }
        outcomes: list[dict[str, Any]] = []
        for item in backlog.get("items", ()):
            target_id = str(item.get("target_id") or "")
            controller = controllers.get(target_id)
            if controller is None:
                continue
            state = controller.state
            if (
                state.promotion_requested_by != "caretaker:auto"
                or state.promotion_outcome not in {None, "ACTIVE"}
            ):
                continue
            backlog_status = str(item.get("status") or "")
            outcome = {
                "sufficiently_covered": "CAPTURED",
                "failed": "FAILED",
                "deferred": "DEFERRED",
            }.get(backlog_status)
            if outcome is None:
                continue
            if not controller.record_behavior_promotion_outcome(
                outcome,
                snapshot_id=str(item.get("snapshot_id") or "") or None,
            ):
                continue
            outcomes.append(
                {
                    "target_id": target_id,
                    "generation_id": item.get("generation_id"),
                    "outcome": outcome,
                    "snapshot_id": item.get("snapshot_id"),
                    "state": controller.state.public_dict(),
                }
            )
        automatic_controllers = tuple(
            controller
            for controller in controllers.values()
            if controller is not None
            and str(controller.state.level.name) == "BEHAVIOR"
            and str(controller.state.promotion_reason or "").startswith(
                "automatic coverage backlog promotion"
            )
            and controller.state.promotion_outcome in {None, "ACTIVE"}
        )
        active_automatic = len(automatic_controllers)
        collecting_automatic = sum(
            1
            for controller in automatic_controllers
            if int(controller.state.behavior_observation_calls or 0) > 0
        )
        waiting_automatic = max(0, active_automatic - collecting_automatic)
        waiting_available = max(
            0, snapshots.collection_auto_max_waiting - waiting_automatic
        )
        promoted: list[dict[str, Any]] = []
        if waiting_available:
            waiting_items = [
                item for item in backlog.get("items", ())
                if item.get("status") in {"armed_waiting", "stale", "suspicious"}
            ]
            priorities = {
                str(item.get("target_id") or ""): int(item.get("priority") or 0)
                for item in waiting_items
            }
            selected_targets = set(
                self.behavior_collection_scheduler.select_fair_automatic_subjects(
                    (
                        str(item.get("target_id") or "")
                        for item in waiting_items
                    ),
                    limit=waiting_available,
                    priorities=priorities,
                )
            )
            for item in waiting_items:
                if waiting_available <= 0:
                    break
                target_id = str(item.get("target_id") or "")
                if target_id not in selected_targets:
                    continue
                controller = controllers.get(target_id)
                if controller is None:
                    continue
                reason = (
                    "automatic coverage backlog promotion "
                    f"for generation {item.get('generation_id') or 'unknown'}"
                )
                if not controller.request_behavior_promotion(
                    reason,
                    requested_by="caretaker:auto",
                ):
                    continue
                promoted.append(
                    {
                        "target_id": target_id,
                        "generation_id": item.get("generation_id"),
                        "requested_by": "caretaker:auto",
                        "reason": reason,
                        "state": controller.state.public_dict(),
                    }
                )
                waiting_available -= 1
        active_after = active_automatic + len(promoted)
        waiting_after = waiting_automatic + len(promoted)
        return {
            "enabled": True,
            "promoted": promoted,
            "outcomes": outcomes,
            "active_automatic": active_after,
            "collecting_automatic": collecting_automatic,
            "waiting_automatic": waiting_after,
            "maximum_automatic": snapshots.collection_auto_max_promoted,
            "maximum_automatic_waiting": snapshots.collection_auto_max_waiting,
            "prioritize_signals": snapshots.collection_auto_prioritize_signals,
            "stale_after_seconds": snapshots.collection_auto_stale_after_seconds,
            "backlog_counts": dict(backlog.get("counts") or {}),
        }

    def cancel_behavior_collection(
        self,
        request_id: str,
        *,
        reason: str = "operator cancelled collection",
    ) -> dict[str, Any]:
        scheduler = self.behavior_collection_scheduler
        if scheduler is None:
            raise ValueError("Guard behavior collection scheduling is unavailable")
        return scheduler.cancel(request_id, reason=reason)

    def evidence_bundle(self, target_id: str, *, calls: int = 20) -> GuardEvidenceBundle | None:
        binding = self._targets.get(target_id)
        if binding is None:
            return None
        baseline = self.baselines.summary(binding.identity)
        observed = self.recent_summary(target_id, calls=calls)
        maximum_events = max(0, self.policy.llm_review.maximum_representative_events)
        events = (
            _tail(self._events_by_target.get(target_id, ()), maximum_events)
            if maximum_events
            else ()
        )
        maximum_deviations = max(0, self.policy.llm_review.maximum_deviations)
        deviations = (
            _tail(self._deviations_by_target.get(target_id, ()), maximum_deviations)
            if maximum_deviations
            else ()
        )
        payload = {
            "subject": binding.identity.logical_name,
            "baseline": repr(baseline),
            "observed": repr(observed),
            "deviations": [repr(item) for item in deviations],
            "events": [str(item.event_id) for item in events],
        }
        return GuardEvidenceBundle(
            subject=binding.identity,
            baseline_summary=baseline,
            observation_summary=observed,
            deviations=deviations,
            representative_events=events,
            omitted_event_count=max(0, len(self._events_by_target.get(target_id, ())) - len(events)),
            evidence_hash=evidence_hash(payload),
        )

    def request_instrumentation(
        self,
        target_id: str,
        mode: GuardMode,
        *,
        execution_count: int,
        reason: str,
    ) -> InstrumentationLease:
        lease = InstrumentationLease.create(
            subject_key=target_id,
            mode=mode,
            execution_count=max(1, execution_count),
            reason=reason,
        )
        with self._lock:
            self._leases[target_id] = lease
        return lease

    def promote_behavior_target(
        self,
        target_id: str,
        *,
        requested_by: str,
        reason: str,
    ) -> dict[str, Any]:
        """Authorize an operator-directed promotion of one adaptive target.

        Guard owns the application target boundary. The adaptive controller owns
        the lifecycle transition and can only be asked for the fixed
        lightweight-to-Behavior transition here; no caller can request Repair
        through this operation.
        """
        with self._lock:
            binding = self._targets.get(target_id)
        if binding is None:
            raise KeyError(f"No Guard target found for {target_id}")
        if not binding.binding.enabled:
            raise PermissionError(f"Guard observation is disabled for {target_id}")

        from ..adaptive import get_adaptive_controller

        controller = get_adaptive_controller(target_id)
        if controller is None:
            raise ValueError(
                f"Target {target_id} is not an installed adaptive target; "
                "operator promotion requires an adaptive wrapper"
            )
        normalized_reason = str(reason).strip()
        if not normalized_reason:
            raise ValueError("behavior promotion requires a reason")
        if len(normalized_reason) > 500:
            raise ValueError("behavior promotion reason exceeds 500 characters")
        normalized_requester = str(requested_by).strip()
        if not normalized_requester:
            raise ValueError("behavior promotion requires requested_by")
        if len(normalized_requester) > 200:
            raise ValueError("behavior promotion requested_by exceeds 200 characters")

        promoted = bool(
            controller.request_behavior_promotion(
                normalized_reason,
                requested_by=normalized_requester,
            )
        )
        authority = get_authority_runtime_context().effective
        return {
            "target_id": target_id,
            "promoted": promoted,
            "requested_by": normalized_requester,
            "reason": normalized_reason,
            "state": controller.state.public_dict(),
            "authority_policy_generation": authority.generation,
            "authority_policy_fingerprint": authority.fingerprint,
        }

    def evaluate_candidate(
        self,
        target_id: str,
        candidate_source: str,
        *,
        candidate_id: UUID | None = None,
        policy: CandidateGuardPolicy | None = None,
        behavior_capture: Mapping[str, Any] | None = None,
        behavior_capture_complete: bool = False,
    ) -> BehavioralCandidateScore:
        binding = self._targets.get(target_id)
        candidate_policy = policy or CandidateGuardPolicy()
        baseline = (
            self.recent_summary(target_id)
            if binding is not None and candidate_policy.compare_to_original_baseline
            else None
        )
        if candidate_id is not None:
            with self._lock:
                self._candidate_policies[candidate_id] = candidate_policy
        return StaticCandidateBehaviorAnalyzer.evaluate(
            candidate_source,
            baseline=baseline,
            allow_new_capabilities=candidate_policy.allow_new_capabilities,
            candidate_id=candidate_id,
            behavior_capture=behavior_capture,
            behavior_capture_complete=behavior_capture_complete,
            resource_budgets={
                "maximum_new_network_destinations": candidate_policy.maximum_new_network_destinations,
                "maximum_new_filesystem_roots": candidate_policy.maximum_new_filesystem_roots,
                "maximum_new_subprocesses": candidate_policy.maximum_new_subprocesses,
            },
        )

    def candidate_deviated(self, candidate_id: UUID) -> bool:
        with self._lock:
            return candidate_id in self._candidate_deviations

    def assess_target(self, target_id: str) -> BehaviorAssessment | None:
        if self.provider is None or not self.policy.llm_review.enabled:
            return None
        bundle = self.evidence_bundle(target_id)
        if bundle is None or not bundle.deviations:
            return None
        maximum = self.policy.llm_review.maximum_deviations
        bundle = replace(bundle, deviations=bundle.deviations[:maximum])
        if max(item.significance_score for item in bundle.deviations) < self.policy.llm_review.minimum_significance:
            return None
        with self._llm_gate.request():
            assessment = self.provider.assess(
                BehaviorAssessmentRequest(
                    evidence=bundle,
                    policy_summary=self._policy_summary(),
                )
            )
        with self._lock:
            self._assessments[assessment.assessment_id] = assessment
            self._assessments.move_to_end(assessment.assessment_id)
            while len(self._assessments) > _GUARD_ASSESSMENT_CACHE_LIMIT:
                self._assessments.popitem(last=False)
        self.store.record_guard_assessment(assessment)
        return assessment

    def _process_window(self, window, *, target_id: str | None) -> None:
        baseline = self.baselines.observe(window)
        if baseline is None:
            return
        if target_id is not None and baseline.state is BaselineState.ACCEPTED:
            baseline = self._enrich_accepted_baseline_statistics(target_id, baseline)
        self.store.record_guard_baseline(baseline)
        if target_id is not None and baseline.state is BaselineState.ACCEPTED:
            self._queue_accepted_baseline_snapshot(target_id, baseline)
        if self.policy.mode is GuardMode.LEARN:
            return
        if baseline.state is not BaselineState.ACCEPTED:
            return
        deviations = self.detector.compare(baseline, window)
        if not deviations:
            return
        for deviation in deviations:
            self.store.record_guard_deviation(deviation)
        if target_id is not None:
            with self._lock:
                self._deviations_by_target[target_id].extend(deviations)
        significant = tuple(
            item
            for item in deviations
            if item.significance_score >= self.policy.deviations.significance_threshold
        )
        if not significant:
            return
        candidate_id = snapshot_context().get("candidate_id")
        if isinstance(candidate_id, UUID):
            with self._lock:
                self._candidate_deviations.add(candidate_id)
        highest = max(item.significance_score for item in significant)
        severity = SignalSeverity.HIGH if highest >= self.policy.deviations.high_significance_threshold else SignalSeverity.MEDIUM
        explicit = any(item.category.name == "EXPLICIT_POLICY_VIOLATION" for item in significant)
        requested_action = self._requested_deviation_action(
            target_id=target_id,
            candidate_id=candidate_id if isinstance(candidate_id, UUID) else None,
            explicit_policy_violation=explicit,
        )
        signal = RuntimeSignal.create(
            domain=SignalDomain.BEHAVIOR,
            kind="behavior-deviation",
            severity=severity,
            run_id=self.run_id,
            source_component="guard.analytics",
            target_id=target_id,
            module_identity=window.subject,
            evidence_refs=tuple(item.deviation_id for item in significant),
            attributes={
                "maximum_significance": highest,
                "explicit_policy_violation": explicit,
                "candidate_id": str(candidate_id) if isinstance(candidate_id, UUID) else None,
                "variant_id": (
                    self.router.active_variant(window.subject.module_name).variant_id
                    if self.router.active_variant(window.subject.module_name) is not None
                    else None
                ),
                "requested_action": requested_action,
            },
        )
        runtime_decision = self.control_plane.submit(signal, context=self._control_context())
        action_name = signal.attributes.get("requested_action", "ALERT")
        action = GuardAction.__members__.get(
            {
                "OPEN_REPAIR_EPISODE": "OPEN_REPAIR_EPISODE",
                "ROLLBACK_ACTIVE_CANDIDATE": "ROLLBACK_REPAIR",
                "QUARANTINE_TARGET": "QUARANTINE",
                "ALERT": "ALERT",
                "RECORD_ONLY": "RECORD",
            }.get(str(action_name), "ALERT"),
            GuardAction.ALERT,
        )
        assessment = self.assess_target(target_id) if target_id is not None else None
        decision = GuardDecision(
            decision_id=uuid4(),
            subject=window.subject,
            deviation_ids=tuple(item.deviation_id for item in significant),
            assessment_id=assessment.assessment_id if assessment else None,
            action=action,
            reason=runtime_decision.reason,
            deterministic_policy_ids=(runtime_decision.policy_id,),
            requires_human_review=runtime_decision.requires_human_review,
        )
        with self._lock:
            self._decisions.append(decision)
        self.store.record_guard_decision(decision)

    def _on_inspection(self, inspection: RuntimeInspection) -> None:
        target_id = self._inspection_target_id(inspection)
        behavior_comparison = None
        generation_rotation = None
        if target_id is not None and self._periodic_behavior_enabled(target_id, inspection):
            behavior_comparison = self._compare_periodic_behavior(target_id, inspection)
            if (
                isinstance(behavior_comparison, Mapping)
                and behavior_comparison.get("state") == "changed"
                and self._periodic_behavior_rotation_enabled(target_id, inspection)
                and self.behavior_statistics is not None
            ):
                generation_rotation = self.behavior_statistics.rotate_generation(
                    target_id,
                    reason="periodic behavior comparison detected a same-code change",
                )
                if generation_rotation is not None:
                    behavior_comparison = {
                        **behavior_comparison,
                        "generation_rotated": True,
                        "previous_generation_id": generation_rotation[
                            "previous_generation_id"
                        ],
                        "new_generation_id": generation_rotation["generation_id"],
                        "behavior_revision": generation_rotation["behavior_revision"],
                    }
            inspection = replace(inspection, behavior_comparison=behavior_comparison)
            # RuntimeInspector records before invoking this callback. Replace
            # that record so SQLite and in-memory consumers see the comparison
            # as part of the same immutable inspection evidence.
            self.store.record_inspection(inspection)

        behavior_changed = bool(
            isinstance(behavior_comparison, Mapping)
            and behavior_comparison.get("state") == "changed"
        )
        if inspection.differences_from_load or behavior_changed:
            self._signal_inspection(inspection, target_id=target_id, candidate_id=None)

    def _inspection_target_id(self, inspection: RuntimeInspection) -> str | None:
        """Resolve a periodic function inspection to its registered target."""
        with self._lock:
            bindings = tuple(self._targets.items())
        for target_id, binding in bindings:
            current_identity = binding.identity
            if binding.function_resolver is not None:
                try:
                    current_identity = identify_function(binding.function_resolver())
                except Exception:
                    current_identity = binding.identity
            if current_identity.logical_name == inspection.subject.logical_name:
                return target_id
        return None

    @staticmethod
    def _module_policy_matches(pattern: str, module_name: str) -> bool:
        return pattern == module_name or (
            pattern.endswith(".*") and module_name.startswith(pattern[:-1])
        )

    def _periodic_behavior_enabled(
        self, target_id: str, inspection: RuntimeInspection
    ) -> bool:
        return self._periodic_behavior_policy(target_id, inspection) is not None

    def _periodic_behavior_policy(
        self, target_id: str, inspection: RuntimeInspection
    ) -> Any | None:
        binding = self._targets.get(target_id)
        if binding is None or inspection.function_state_summary is None:
            return None
        for target in self.policy.targets:
            if (
                target.periodic.enabled
                and target.periodic.compare_behavior
                and self._module_policy_matches(
                    target.module_pattern, inspection.subject.module_name
                )
            ):
                return target.periodic
        return None

    def _periodic_behavior_rotation_enabled(
        self, target_id: str, inspection: RuntimeInspection
    ) -> bool:
        periodic_policy = self._periodic_behavior_policy(target_id, inspection)
        return bool(
            periodic_policy is not None
            and periodic_policy.rotate_generation_on_behavior_change
        )

    @staticmethod
    def _baseline_snapshot(
        target_id: str,
        baseline: BehaviorBaseline,
        *,
        schema_version: int,
        monitoring_fingerprint: str,
    ) -> dict[str, Any]:
        profile = baseline.profile
        return {
            "snapshot_id": f"baseline:{baseline.baseline_id}",
            "created_at": (
                baseline.accepted_at or baseline.created_at
            ).isoformat(),
            "subject_key": f"function:{target_id}",
            "generation_id": (
                baseline.generation_id
                or behavior_generation_id(
                    subject_key=f"function:{target_id}",
                    code_hash=baseline.subject.source_hash or baseline.subject.bytecode_hash,
                    monitoring_fingerprint=monitoring_fingerprint,
                    statistics_schema_version=schema_version,
                )
            ),
            "code_hash": baseline.subject.source_hash or baseline.subject.bytecode_hash,
            "monitoring_fingerprint": monitoring_fingerprint,
            "statistics_schema_version": schema_version,
            "profile": {
                "window_count": baseline.observations,
                "call_count": profile.call_count,
                "event_count": profile.event_count,
                "event_kind_counts": dict(profile.event_kind_counts),
                "network_destinations": list(profile.network_destinations),
                "filesystem_roots": list(profile.filesystem_roots),
                "subprocesses": list(profile.subprocesses),
                "imports": list(profile.imports),
                "dynamic_code_operations": list(profile.dynamic_code_operations),
                "resource_counts": dict(profile.resource_counts),
                "resource_coverage_complete": True,
                "success_count": profile.success_count,
                "failure_count": profile.failure_count,
                "return_categories": dict(profile.return_category_counts),
                "return_shapes": dict(profile.return_shape_counts),
                "return_category_coverage_complete": True,
                "return_shape_coverage_complete": True,
                "return_observations_available": profile.return_observations_available,
                "statistics": dict(profile.statistics),
                "sampling_provenance": dict(profile.sampling_provenance),
            },
        }

    def _compare_periodic_behavior(
        self, target_id: str, inspection: RuntimeInspection
    ) -> dict[str, Any]:
        """Compare current same-generation statistics with accepted evidence.

        This method intentionally produces evidence only. It never accepts a
        baseline, changes policy, or grants authority. An enabled caller may
        rotate the statistics generation after this comparison returns a
        verified same-code behavior change.
        """
        unavailable = {
            "state": "unavailable",
            "evidence_only": True,
            "authority_granted": False,
            "generation_rotated": False,
            "target_id": target_id,
        }
        if self.behavior_statistics is None:
            return {**unavailable, "reason": "behavior-statistics-unavailable"}

        binding = self._targets.get(target_id)
        if binding is None:
            return {**unavailable, "reason": "target-not-registered"}
        baseline = self.baselines.get(binding.identity)
        if baseline is None or baseline.state is not BaselineState.ACCEPTED:
            return {**unavailable, "reason": "no-accepted-baseline"}
        capture = self.behavior_statistics.current_capture(target_id)
        if capture is None:
            return {**unavailable, "reason": "current-behavior-capture-unavailable"}

        profile = dict(capture.get("profile") or {})
        observed_calls = max(0, int(profile.get("call_count") or 0))
        observed_code_hash = capture.get("code_hash")
        observed_monitoring = capture.get("monitoring_fingerprint")
        expected_code_hash = binding.identity.source_hash or binding.identity.bytecode_hash
        expected_monitoring = self.monitoring_fingerprint(target_id)
        schema_version = max(1, int(capture.get("statistics_schema_version") or 1))
        behavior_revision = max(0, int(capture.get("behavior_revision") or 0))
        expected_generation = behavior_generation_id(
            subject_key=f"function:{target_id}",
            code_hash=expected_code_hash,
            monitoring_fingerprint=expected_monitoring,
            statistics_schema_version=schema_version,
            behavior_revision=behavior_revision,
        )
        context = {
            "target_id": target_id,
            "baseline_id": str(baseline.baseline_id),
            "generation_id": str(capture.get("generation_id") or ""),
            "code_hash": observed_code_hash,
            "monitoring_fingerprint": observed_monitoring,
            "observed_calls": observed_calls,
            "behavior_revision": behavior_revision,
        }
        if (
            str(capture.get("subject_key") or "") != f"function:{target_id}"
            or observed_code_hash != expected_code_hash
            or observed_monitoring != expected_monitoring
            or str(capture.get("generation_id") or "") != expected_generation
        ):
            return {
                **unavailable,
                "state": "incomparable",
                "reason": "current-capture-context-mismatch",
                **context,
                "expected_generation_id": expected_generation,
                "expected_code_hash": expected_code_hash,
                "expected_monitoring_fingerprint": expected_monitoring,
            }
        baseline_generation_id = str(getattr(baseline, "generation_id", "") or "")
        if behavior_revision > 0 and baseline_generation_id != str(
            capture.get("generation_id") or ""
        ):
            return {
                **unavailable,
                "state": "insufficient-evidence",
                "reason": "behavior-generation-awaiting-baseline",
                **context,
            }
        if observed_calls <= 0:
            return {
                **unavailable,
                "state": "insufficient-evidence",
                "reason": "no-observed-calls",
                **context,
            }
        baseline_calls = max(0, int(baseline.profile.call_count or 0))
        if observed_calls <= baseline_calls:
            return {
                **unavailable,
                "state": "insufficient-evidence",
                "reason": "no-calls-observed-after-baseline",
                **context,
                "baseline_calls": baseline_calls,
            }

        baseline_snapshot = self._baseline_snapshot(
            target_id,
            baseline,
            schema_version=schema_version,
            monitoring_fingerprint=expected_monitoring,
        )
        # Active captures use the generation start as ``created_at``. For this
        # transient comparison operand, the last observed update is the
        # freshness boundary; the persisted capture itself is not rewritten.
        current_snapshot = dict(capture)
        current_snapshot["snapshot_id"] = (
            f"active:{target_id}:{capture.get('last_sample_sequence') or observed_calls}"
        )[:256]
        current_snapshot["created_at"] = str(
            capture.get("observation_ended_at") or capture.get("created_at") or ""
        )
        periodic_policy = self._periodic_behavior_policy(target_id, inspection)
        comparison = compare_snapshots(
            baseline_snapshot,
            current_snapshot,
            minimum_duration_distribution_samples=(
                periodic_policy.duration_distribution_minimum_samples
                if periodic_policy is not None
                else 20
            ),
            duration_distribution_sigma_threshold=(
                periodic_policy.duration_distribution_sigma_threshold
                if periodic_policy is not None
                else 3.0
            ),
        )
        semantic_changes = [
            item
            for item in comparison.get("semantic_changes") or ()
            if item.get("change") == "started"
        ][:64]
        new_event_kinds = [
            item
            for item in comparison.get("event_kind_changes") or ()
            if int(item.get("before") or 0) == 0 and int(item.get("after") or 0) > 0
        ][:64]
        return_novelty = dict(comparison.get("return_novelty") or {})
        duration_distribution = dict(
            comparison.get("duration_distribution") or {}
        )
        failure_change = dict((comparison.get("outcomes") or {}).get("failure") or {})
        reasons: list[str] = []
        if semantic_changes:
            reasons.append("new-resource-capability")
        if new_event_kinds:
            reasons.append("new-event-kind")
        if return_novelty.get("state") == "new-observations":
            reasons.append("new-return-observation")
        if duration_distribution.get("state") == "shift-signal":
            reasons.append("duration-distribution-shift")
        if int(failure_change.get("absolute") or 0) > 0:
            reasons.append("additional-failures")
        return {
            "comparison_id": comparison.get("comparison_id"),
            "state": "changed" if reasons else "unchanged",
            "evidence_only": True,
            "authority_granted": False,
            "generation_rotated": False,
            "target_id": target_id,
            "baseline_id": str(baseline.baseline_id),
            "generation_id": str(capture.get("generation_id")),
            "code_hash": observed_code_hash,
            "monitoring_fingerprint": observed_monitoring,
            "baseline_calls": baseline_calls,
            "observed_calls": observed_calls,
            "observed_at": current_snapshot["created_at"],
            "change_reasons": reasons,
            "new_resource_capabilities": semantic_changes,
            "new_event_kinds": new_event_kinds,
            "return_novelty": {
                "state": return_novelty.get("state"),
                "reason": return_novelty.get("reason"),
                "new_categories": list(return_novelty.get("new_categories") or ())[:64],
                "new_shapes": list(return_novelty.get("new_shapes") or ())[:64],
            },
            "duration_distribution": duration_distribution,
            "failure_change": {
                "before": int(failure_change.get("before") or 0),
                "after": int(failure_change.get("after") or 0),
                "absolute": int(failure_change.get("absolute") or 0),
            },
        }

    def _signal_inspection(
        self,
        inspection: RuntimeInspection,
        *,
        target_id: str | None,
        candidate_id: UUID | None,
    ) -> None:
        requested_action = self._requested_deviation_action(
            target_id=target_id,
            candidate_id=candidate_id,
            explicit_policy_violation=False,
        )
        signal = RuntimeSignal.create(
            domain=SignalDomain.BEHAVIOR,
            kind="runtime-introspection-change",
            severity=SignalSeverity.HIGH,
            run_id=self.run_id,
            source_component="guard.introspection",
            target_id=target_id,
            module_identity=inspection.subject,
            evidence_refs=(inspection.inspection_id,),
            attributes={
                "difference_count": len(inspection.differences_from_load),
                "candidate_id": str(candidate_id) if candidate_id else None,
                "variant_id": (
                    self.router.active_variant(inspection.subject.module_name).variant_id
                    if self.router.active_variant(inspection.subject.module_name) is not None
                    else None
                ),
                "requested_action": requested_action,
            },
        )
        if candidate_id is not None:
            with self._lock:
                self._candidate_deviations.add(candidate_id)
        self.control_plane.submit(signal, context=self._control_context())

    def _requested_deviation_action(
        self,
        *,
        target_id: str | None,
        candidate_id: UUID | None,
        explicit_policy_violation: bool,
    ) -> str:
        if candidate_id is not None:
            candidate_policy = self._candidate_policies.get(candidate_id)
            rollback = (
                candidate_policy.rollback_on_significant_deviation
                if candidate_policy is not None
                else self.policy.actions.rollback_repair_on_candidate_deviation
            )
            if rollback:
                return "ROLLBACK_ACTIVE_CANDIDATE"
        if explicit_policy_violation and self.policy.actions.quarantine_on_explicit_violation:
            return "QUARANTINE_TARGET"
        if target_id is not None:
            binding = self._targets.get(target_id)
            if binding is not None:
                action = binding.binding.deviation_action
                if (
                    action.name == "OPEN_REPAIR_EPISODE"
                    and not self.policy.actions.open_repair_for_application_code
                ):
                    return "ALERT"
                return action.name
        action = self.policy.actions.deviation_action
        if (
            action.name == "OPEN_REPAIR_EPISODE"
            and not self.policy.actions.open_repair_for_application_code
        ):
            return "ALERT"
        return action.name

    def _handle_open_repair(self, action: RuntimeAction, signal: RuntimeSignal) -> None:
        if signal.target_id is None or self._repair_opener is None:
            return
        deviations = _tail(self._deviations_by_target.get(signal.target_id, ()), 20)
        self._repair_opener(signal.target_id, deviations)

    def _handle_rollback(self, action: RuntimeAction, signal: RuntimeSignal) -> None:
        candidate_text = signal.attributes.get("candidate_id")
        if not candidate_text or self._candidate_rollback is None:
            return
        try:
            candidate_id = UUID(str(candidate_text))
        except ValueError:
            return
        self._candidate_rollback(candidate_id, action.reason)

    def _handle_quarantine(self, action: RuntimeAction, signal: RuntimeSignal) -> None:
        if signal.target_id:
            with self._lock:
                self._quarantined_targets.add(signal.target_id)
        variant_id = signal.attributes.get("variant_id")
        if variant_id:
            self.router.quarantine(str(variant_id))

    def is_target_quarantined(self, target_id: str) -> bool:
        with self._lock:
            return target_id in self._quarantined_targets

    def _policy_summary(self) -> str:
        return (
            f"Guard mode={self.policy.mode.name}; significance threshold="
            f"{self.policy.deviations.significance_threshold:g}; LLM advisory="
            f"{self.policy.llm_review.advisory_only}; new network denied="
            f"{self.policy.deviations.deny_new_network_capability}; new subprocess denied="
            f"{self.policy.deviations.deny_new_subprocess_capability}"
        )

    @property
    def decisions(self) -> tuple[GuardDecision, ...]:
        with self._lock:
            return tuple(self._decisions)
