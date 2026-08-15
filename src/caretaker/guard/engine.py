from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections import OrderedDict, defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, replace
from uuid import UUID, uuid4

from ..authority import get_authority_runtime_context
from ..control_plane import (
    RuntimeAction,
    RuntimeActionKind,
    RuntimeControlPlane,
    RuntimeSignal,
    SignalDomain,
    SignalSeverity,
)
from ..evidence.identity import identify_function
from ..evidence.models import (
    BehaviorEvent,
    BehaviorEventKind,
    CodeIdentity,
    EventOutcome,
    InspectionKind,
    ResourceIdentity,
    RuntimeInspection,
)
from ..evidence.store import EvidenceStore, InMemoryEvidenceStore
from ..runtime import snapshot_context
from ..logging.models import LoggingCapability, LoggingMode, RequiredCapabilityFailureAction
from ..logging.policy import mode_requirements
from .analytics import (
    BaselineManager,
    BehaviorAggregator,
    DeviationDetector,
    StaticCandidateBehaviorAnalyzer,
    evidence_hash,
)
from .collectors import AuditEventCollector, DependencyCollector
from .facade import GuardFacade
from .imports import CaretakerModuleFinder, ModuleRouter
from .hooks import GuardHookManager
from .introspection import PeriodicInspector, RuntimeInspector
from .models import (
    AssessmentSeverity,
    BaselineState,
    BehaviorAssessment,
    BehaviorBaseline,
    BehaviorDeviation,
    BehavioralCandidateScore,
    BehaviorProfileSummary,
    GuardAction,
    GuardDecision,
    GuardEvidenceBundle,
    GuardMode,
    InstrumentationLease,
)
from .policy import CandidateGuardPolicy, GuardBinding, GuardPolicy
from .provider import BehaviorAssessmentProvider, BehaviorAssessmentRequest


_GUARD_EVENT_CACHE_LIMIT = 10_000
_GUARD_DEVIATION_CACHE_LIMIT = 2_000
_GUARD_ASSESSMENT_CACHE_LIMIT = 1_000
_GUARD_DECISION_CACHE_LIMIT = 1_000


def _tail(items, limit: int):
    if limit <= 0:
        return ()
    values = tuple(items)
    return values[-limit:]


@dataclass
class _TargetBinding:
    function: Callable
    binding: GuardBinding
    identity: CodeIdentity
    function_resolver: Callable[[], Callable] | None = None


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
        self.store = store or InMemoryEvidenceStore(
            event_limit=self.policy.retention.maximum_raw_events
        )
        self.control_plane = control_plane or RuntimeControlPlane()
        self.provider = provider
        self.run_id = run_id or uuid4()
        self.work_registry = work_registry
        self.aggregator = BehaviorAggregator(self.store, self.policy.aggregation)
        self.baselines = BaselineManager(self.policy.baseline)
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
        self.aggregator.policy = self.policy.aggregation
        self.baselines.policy = self.policy.baseline
        self.detector.policy = self.policy.deviations
        self.audit_collector.collectors = self.policy.collectors
        self.audit_collector.attribution = self.policy.attribution
        self.audit_collector.sampling = self.policy.sampling

    def registered_target_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._targets))

    def recent_events(self, target_id: str, *, limit: int = 100) -> tuple[object, ...]:
        return tuple(self.store.recent_behavior_events(target_id=target_id, limit=limit))

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

    def register_target(
        self,
        target_id: str,
        function: Callable,
        binding: GuardBinding,
        function_resolver: Callable[[], Callable] | None = None,
        *,
        periodic: bool = True,
    ) -> None:
        identity = identify_function(function)
        with self._lock:
            self._targets[target_id] = _TargetBinding(function, binding, identity, function_resolver)
        self.store.record_code_identity(identity)
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
            attributes={},
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
    ) -> None:
        binding = self._targets.get(target_id)
        if binding is None or not binding.binding.enabled:
            return
        identity = identify_function(function)
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
            attributes={},
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
        if not self._event_in_scope(event):
            return
        self.store.record_code_identity(event.code_identity)
        self.store.append_behavior_event(event)
        if event.target_id is not None:
            with self._lock:
                self._events_by_target[event.target_id].append(event)
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

    def accept_baseline(self, target_id: str) -> BehaviorBaseline:
        binding = self._targets[target_id]
        baseline = self.baselines.accept(binding.identity)
        self.store.record_guard_baseline(baseline)
        return baseline

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
        )

    def behavior_capture(self, target_id: str, *, calls: int = 50) -> dict[str, object]:
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
            },
            "children": [],
        }

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

    def evaluate_candidate(
        self,
        target_id: str,
        candidate_source: str,
        *,
        candidate_id: UUID | None = None,
    ) -> BehavioralCandidateScore:
        binding = self._targets.get(target_id)
        baseline = self.recent_summary(target_id) if binding is not None else None
        return StaticCandidateBehaviorAnalyzer.evaluate(
            candidate_source,
            baseline=baseline,
            allow_new_capabilities=False,
            candidate_id=candidate_id,
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
        self.store.record_guard_baseline(baseline)
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
                "requested_action": (
                    "ROLLBACK_ACTIVE_CANDIDATE"
                    if isinstance(candidate_id, UUID) and self.policy.actions.rollback_repair_on_candidate_deviation
                    else self.policy.actions.deviation_action.name
                ),
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
        if inspection.differences_from_load:
            target_id = next(
                (
                    key
                    for key, binding in self._targets.items()
                    if binding.identity.logical_name == inspection.subject.logical_name
                ),
                None,
            )
            self._signal_inspection(inspection, target_id=target_id, candidate_id=None)

    def _signal_inspection(
        self,
        inspection: RuntimeInspection,
        *,
        target_id: str | None,
        candidate_id: UUID | None,
    ) -> None:
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
                "requested_action": (
                    "ROLLBACK_ACTIVE_CANDIDATE"
                    if candidate_id is not None and self.policy.actions.rollback_repair_on_candidate_deviation
                    else self.policy.actions.deviation_action.name
                ),
            },
        )
        if candidate_id is not None:
            with self._lock:
                self._candidate_deviations.add(candidate_id)
        self.control_plane.submit(signal, context=self._control_context())

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
        variant_id = signal.attributes.get("variant_id")
        if variant_id:
            self.router.quarantine(str(variant_id))

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
