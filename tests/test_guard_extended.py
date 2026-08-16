from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from caretaker import (
    CandidateProposal,
    ExceptionTrigger,
    GuardBinding,
    GuardEngine,
    GuardMode,
    GuardPolicy,
    ObservationPolicy,
    RepairEngine,
    RepairPolicy,
    ReplaySafety,
    RetryPolicy,
    SQLiteEvidenceStore,
    StatePolicy,
    StaticRepairProvider,
    repair,
)
from caretaker.evidence import (
    BehaviorEvent,
    BehaviorEventKind,
    EventOutcome,
    ResourceIdentity,
    identify_function,
)
from caretaker.guard.models import (
    AssessmentSeverity,
    BehaviorAssessment,
    GuardDeviationAction,
    ModuleRoutePolicy,
    ModuleVariant,
)
from caretaker.guard.policy import (
    AggregationPolicy,
    BaselinePolicy,
    CandidateGuardPolicy,
    DeviationPolicy,
    GuardActionPolicy,
    LLMReviewPolicy,
)
from caretaker.provider import CandidateBatch, RepairRequest
from caretaker.policy import ContextPolicy
from tests.guard_targets import failing


def _event(target_id: str, resource: str) -> BehaviorEvent:
    return BehaviorEvent.create(
        event_kind=BehaviorEventKind.NETWORK_CONNECT,
        operation="socket.connect",
        code_identity=identify_function(failing),
        run_id=uuid4(),
        call_id=uuid4(),
        target_id=target_id,
        process_id=os.getpid(),
        thread_id=threading.get_ident(),
        resource=ResourceIdentity("network", resource),
        outcome=EventOutcome.SUCCEEDED,
    )


class CapturingAssessmentProvider:
    name = "capture-guard"
    model_name = None

    def __init__(self) -> None:
        self.requests = []

    def assess(self, request):
        self.requests.append(request)
        return BehaviorAssessment(
            assessment_id=uuid4(),
            subject=request.evidence.subject,
            baseline_id=request.evidence.deviations[0].baseline_id,
            deviation_ids=tuple(item.deviation_id for item in request.evidence.deviations),
            severity=AssessmentSeverity.HIGH,
            confidence=0.9,
            significant_changes=("new network destination",),
            suspicious_patterns=("unexpected outbound access",),
            plausible_benign_explanations=("new telemetry",),
            recommended_actions=("review destination",),
            requested_additional_evidence=("capture stack",),
            provider_name=self.name,
            model_name=None,
            prompt_version="capture-v1",
            response_hash="abc",
        )


class CapturingRepairProvider:
    name = "capture-repair"
    model_name = None
    supports_synthesis = False

    def __init__(self) -> None:
        self.request: RepairRequest | None = None

    def generate(self, request: RepairRequest) -> CandidateBatch:
        self.request = request
        return CandidateBatch(
            provider_name=self.name,
            model_name=None,
            prompt_version="capture-v1",
            prompt_text="capture",
            candidates=(
                CandidateProposal(
                    source="def failing(value: int) -> int:\n    return value\n",
                    explanation="fix",
                ),
            ),
        )

    def synthesize(self, request, candidates):
        raise NotImplementedError


def _guard_policy(*, llm: bool = False) -> GuardPolicy:
    return GuardPolicy(
        mode=GuardMode.AUDIT,
        aggregation=AggregationPolicy(close_after_events=1, close_after_calls=1, close_after_seconds=999),
        baseline=BaselinePolicy(minimum_windows=1),
        deviations=DeviationPolicy(significance_threshold=0, high_significance_threshold=0),
        llm_review=LLMReviewPolicy(enabled=llm, minimum_significance=0),
        actions=GuardActionPolicy(deviation_action=GuardDeviationAction.ALERT),
    )


def _repair_policy() -> RepairPolicy:
    return RepairPolicy.automatic(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
        observation=ObservationPolicy(initial_successful_executions=5),
        guard=GuardBinding(
            enabled=True,
            observe_network=True,
            include_guard_context_in_repair=True,
            validate_candidate_behavior=True,
            monitor_during_probation=True,
        ),
    )


def test_llm_assessment_runs_after_deterministic_deviation_extraction() -> None:
    provider = CapturingAssessmentProvider()
    guard = GuardEngine(policy=_guard_policy(llm=True), provider=provider)
    guard.register_target("tests.guard_targets:failing", failing, _repair_policy().guard)
    guard.record_event(_event("tests.guard_targets:failing", "api.example:443"))
    guard.accept_baseline("tests.guard_targets:failing")
    guard.record_event(_event("tests.guard_targets:failing", "unexpected.example:443"))

    assert provider.requests
    assert guard.decisions
    assert provider.requests[0].evidence.deviations[0].observed.values["value"] == "unexpected.example:443"


def test_guard_analytics_are_persisted_for_querying(tmp_path: Path) -> None:
    store = SQLiteEvidenceStore(tmp_path / "guard.sqlite")
    guard = GuardEngine(policy=_guard_policy(), store=store)
    target_id = "tests.guard_targets:failing"
    guard.register_target(target_id, failing, _repair_policy().guard)
    guard.record_event(_event(target_id, "api.example:443"))
    guard.accept_baseline(target_id)
    guard.record_event(_event(target_id, "unexpected.example:443"))

    deviations = store.query("SELECT category, significance_score FROM guard_deviations")
    decisions = store.query("SELECT action FROM guard_decisions")
    assert deviations and deviations[0]["category"] == "NEW_NETWORK_DESTINATION"
    assert decisions and decisions[0]["action"] == "ALERT"


def test_repair_provider_receives_guard_evidence() -> None:
    guard = GuardEngine(policy=_guard_policy())
    provider = CapturingRepairProvider()
    engine = RepairEngine(provider=provider, guard=guard)
    wrapped = repair(policy=_repair_policy(), engine=engine)(failing)
    target_id = wrapped.__caretaker_target__.target_id
    guard.record_event(_event(target_id, "unusual.example:443"))

    assert wrapped(2) == 2
    assert provider.request is not None
    assert "unusual.example:443" in provider.request.guard_summary


def test_repair_context_policy_omits_protected_llm_context() -> None:
    provider = CapturingRepairProvider()
    engine = RepairEngine(provider=provider)
    policy = replace(
        _repair_policy(),
        context=ContextPolicy(
            include_source=False,
            include_traceback=False,
            include_state_diff=False,
            send_argument_values=False,
            send_local_values=False,
        ),
    )
    wrapped = repair(policy=policy, engine=engine)(failing)

    assert wrapped(123456789) == 123456789
    assert provider.request is not None
    assert provider.request.original_source == "Source omitted by repair context policy."
    assert provider.request.traceback_summary == "Traceback omitted by repair context policy."
    assert provider.request.state_summary == "State differences omitted by repair context policy."
    assert "123456789" not in provider.request.incident_summary
    assert "broken" not in provider.request.incident_summary


def test_module_variant_with_wrong_hash_is_quarantined(tmp_path: Path) -> None:
    source = tmp_path / "variant.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    guard = GuardEngine()
    guard.router.register_variant(
        ModuleVariant(
            variant_id="bad-hash",
            import_name="example_variant",
            distribution_name=None,
            distribution_version=None,
            source_location=str(source),
            source_hash="0" * 64,
            integrity_state="TRUSTED",
            behavior_baseline_id=None,
        )
    )
    guard.router.register_policy(
        ModuleRoutePolicy(import_name="example_variant", preferred_variant_id="bad-hash")
    )
    selected, decision = guard.router.select("example_variant")
    assert selected is None
    assert decision.action == "DENY_IMPORT"
    assert guard.router.is_quarantined("bad-hash")


def test_guard_policy_is_in_human_readable_repair_snapshot() -> None:
    snapshot = _repair_policy().snapshot()
    assert "Guard integration:" in snapshot.human_readable_policy
    assert "validate candidate behavior: True" in snapshot.human_readable_policy


def test_periodic_inspector_resolves_current_function_slot() -> None:
    guard = GuardEngine(policy=_guard_policy())
    engine = RepairEngine(
        provider=StaticRepairProvider(
            [CandidateProposal(source="def failing(value: int) -> int:\n    return value * 3\n", explanation="fix")]
        ),
        guard=guard,
    )
    wrapped = repair(policy=_repair_policy(), engine=engine)(failing)
    assert wrapped(3) == 9
    current = wrapped.__caretaker_target__.slot.load()
    inspections = guard.periodic.inspect_now()
    target_inspection = next(item for item in inspections if item.subject.qualified_name == "failing")
    assert target_inspection.function_state_summary.bytecode_hash == identify_function(current.implementation).bytecode_hash


def test_guard_operational_event_cache_is_bounded(monkeypatch) -> None:
    import caretaker.guard.engine as guard_engine_module

    monkeypatch.setattr(guard_engine_module, "_GUARD_EVENT_CACHE_LIMIT", 3)
    guard = GuardEngine(policy=_guard_policy())
    target_id = "tests.guard_targets:bounded-cache"
    for index in range(5):
        guard.record_event(_event(target_id, f"cache-{index}.example:443"))

    cached = tuple(guard._events_by_target[target_id])
    assert len(cached) == 3
    assert cached[0].resource.value == "cache-2.example:443"
    assert cached[-1].resource.value == "cache-4.example:443"


def test_guard_disabled_is_a_true_noop_for_behavior_events() -> None:
    guard = GuardEngine(policy=GuardPolicy(mode=GuardMode.DISABLED))
    target_id = "tests.guard_targets:failing"
    guard.register_target(target_id, failing, _repair_policy().guard)
    guard.record_event(_event(target_id, "unexpected.example:443"))
    assert guard.recent_events(target_id) == ()
    assert guard.decisions == ()


def test_legacy_research_modes_are_audit_aliases() -> None:
    assert GuardMode.RESEARCH is GuardMode.AUDIT
    assert GuardMode.FORENSIC is GuardMode.AUDIT
    assert GuardMode.ENFORCE is GuardMode.AUDIT


def test_binding_deviation_action_overrides_global_guard_action() -> None:
    guard = GuardEngine(policy=_guard_policy())
    target_id = "tests.guard_targets:failing"
    binding = replace(
        _repair_policy().guard,
        deviation_action=GuardDeviationAction.QUARANTINE_TARGET,
    )
    guard.register_target(target_id, failing, binding)
    guard.record_event(_event(target_id, "api.example:443"))
    guard.accept_baseline(target_id)
    guard.record_event(_event(target_id, "unexpected.example:443"))

    assert guard.is_target_quarantined(target_id)


def test_candidate_guard_allow_new_capabilities_is_honored() -> None:
    guard = GuardEngine(policy=_guard_policy())
    target_id = "tests.guard_targets:failing"
    guard.register_target(target_id, failing, _repair_policy().guard)
    source = "def failing(value):\n    import socket\n    return value\n"

    denied = guard.evaluate_candidate(
        target_id,
        source,
        policy=CandidateGuardPolicy(allow_new_capabilities=False),
    )
    allowed = guard.evaluate_candidate(
        target_id,
        source,
        policy=CandidateGuardPolicy(allow_new_capabilities=True),
    )
    assert denied.eligible is False
    assert allowed.eligible is True
