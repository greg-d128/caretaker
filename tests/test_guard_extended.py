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
    BehaviorProfileSummary,
    GuardDeviationAction,
    ModuleRoutePolicy,
    ModuleVariant,
)
from caretaker.guard.analytics import StaticCandidateBehaviorAnalyzer
from caretaker.guard.policy import (
    AggregationPolicy,
    BaselinePolicy,
    CandidateGuardPolicy,
    DeviationPolicy,
    GuardActionPolicy,
    LLMReviewPolicy,
    GuardTargetPolicy,
    PeriodicInspectionPolicy,
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


def test_repair_wrapper_passes_successful_results_to_guard_behavior_capture() -> None:
    guard = GuardEngine(policy=_guard_policy())
    engine = RepairEngine(guard=guard)
    policy = replace(
        RepairPolicy(),
        guard=GuardBinding(
            enabled=True,
            observe_network=True,
            include_guard_context_in_repair=True,
        ),
    )

    def returns_text(value: int) -> str:
        return "value:" + str(value)

    wrapped = repair(policy=policy, engine=engine, target_id="tests:return-text")(returns_text)

    assert wrapped(7) == "value:7"
    summary = guard.current_behavior_summary("tests:return-text")
    assert summary is not None
    assert summary.success_count == 1
    assert summary.return_observations_available is True
    assert summary.return_category_counts == {"text:builtins.str": 1}
    assert summary.return_shape_counts == {"text:length-medium": 1}


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


def test_periodic_behavior_comparison_records_change_as_evidence(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CARETAKER_DATA_DIR", str(tmp_path))
    base = _guard_policy()
    policy = replace(
        base,
        aggregation=AggregationPolicy(close_after_events=100, close_after_calls=100, close_after_seconds=999),
        targets=(
            GuardTargetPolicy(
                module_pattern="tests.guard_targets",
                periodic=PeriodicInspectionPolicy(compare_behavior=True),
            ),
        ),
    )
    guard = GuardEngine(policy=policy)
    target_id = "tests.guard_targets:failing"
    guard.register_target(
        target_id,
        failing,
        replace(_repair_policy().guard, observe_network=True),
        periodic=False,
    )

    for _ in range(2):
        call_id = uuid4()
        guard.before_call(target_id, failing, call_id, candidate_id=None)
        guard.after_call(
            target_id,
            failing,
            call_id,
            candidate_id=None,
            succeeded=True,
            elapsed_seconds=0.001,
            result=1,
        )
    guard.close_target_window(target_id)
    baseline = guard.accept_baseline(target_id)

    guard.record_event(_event(target_id, "new.example:443"))
    call_id = uuid4()
    guard.before_call(target_id, failing, call_id, candidate_id=None)
    guard.after_call(
        target_id,
        failing,
        call_id,
        candidate_id=None,
        succeeded=True,
        elapsed_seconds=0.001,
        result=1,
    )
    inspection = guard.inspector.inspect_function(failing)
    guard._on_inspection(inspection)

    comparison = guard.store.inspections[inspection.inspection_id].behavior_comparison
    assert baseline.state.name == "ACCEPTED"
    assert comparison is not None
    assert comparison["state"] == "changed"
    assert comparison["evidence_only"] is True
    assert comparison["authority_granted"] is False
    assert "new-resource-capability" in comparison["change_reasons"]
    assert guard.control_plane.signals[-1].target_id == target_id


def test_periodic_behavior_change_can_start_a_new_generation(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CARETAKER_DATA_DIR", str(tmp_path))
    base = _guard_policy()
    policy = replace(
        base,
        aggregation=AggregationPolicy(
            close_after_events=100,
            close_after_calls=100,
            close_after_seconds=999,
        ),
        targets=(
            GuardTargetPolicy(
                module_pattern="tests.guard_targets",
                periodic=PeriodicInspectionPolicy(
                    compare_behavior=True,
                    rotate_generation_on_behavior_change=True,
                ),
            ),
        ),
    )
    guard = GuardEngine(policy=policy)
    target_id = "tests.guard_targets:failing"
    guard.register_target(
        target_id,
        failing,
        replace(_repair_policy().guard, observe_network=True),
        periodic=False,
    )

    for _ in range(2):
        call_id = uuid4()
        guard.before_call(target_id, failing, call_id, candidate_id=None)
        guard.after_call(
            target_id,
            failing,
            call_id,
            candidate_id=None,
            succeeded=True,
            elapsed_seconds=0.001,
            result=1,
        )
    guard.close_target_window(target_id)
    guard.accept_baseline(target_id)
    before = guard.behavior_statistics.current_capture(target_id)
    assert before is not None
    before_generation = before["generation_id"]

    guard.record_event(_event(target_id, "new.example:443"))
    call_id = uuid4()
    guard.before_call(target_id, failing, call_id, candidate_id=None)
    guard.after_call(
        target_id,
        failing,
        call_id,
        candidate_id=None,
        succeeded=True,
        elapsed_seconds=0.001,
        result=1,
    )
    inspection = guard.inspector.inspect_function(failing)
    guard._on_inspection(inspection)

    comparison = guard.store.inspections[inspection.inspection_id].behavior_comparison
    after = guard.behavior_statistics.current_capture(target_id)
    assert comparison is not None
    assert comparison["state"] == "changed"
    assert comparison["generation_rotated"] is True
    assert comparison["previous_generation_id"] == before_generation
    assert comparison["new_generation_id"] == after["generation_id"]
    assert comparison["behavior_revision"] == 1
    assert after["behavior_revision"] == 1
    assert after["code_hash"] == before["code_hash"]
    assert after["profile"]["call_count"] == 0
    assert guard.behavior_statistics.pending_count() >= 1

    next_call_id = uuid4()
    guard.before_call(target_id, failing, next_call_id, candidate_id=None)
    guard.after_call(
        target_id,
        failing,
        next_call_id,
        candidate_id=None,
        succeeded=True,
        elapsed_seconds=0.001,
        result=1,
    )
    next_inspection = guard.inspector.inspect_function(failing)
    guard._on_inspection(next_inspection)
    next_comparison = guard.store.inspections[next_inspection.inspection_id].behavior_comparison
    assert next_comparison["state"] == "insufficient-evidence"
    assert next_comparison["reason"] == "behavior-generation-awaiting-baseline"
    assert next_comparison["generation_rotated"] is False

    accepted = guard.accept_baseline(target_id)
    assert accepted.generation_id == after["generation_id"]
    final_call_id = uuid4()
    guard.before_call(target_id, failing, final_call_id, candidate_id=None)
    guard.after_call(
        target_id,
        failing,
        final_call_id,
        candidate_id=None,
        succeeded=True,
        elapsed_seconds=0.001,
        result=1,
    )
    final_inspection = guard.inspector.inspect_function(failing)
    guard._on_inspection(final_inspection)
    final_comparison = guard.store.inspections[final_inspection.inspection_id].behavior_comparison
    assert final_comparison["state"] == "unchanged"
    assert final_comparison["generation_id"] == after["generation_id"]


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


def test_candidate_guard_enforces_observed_resource_budgets() -> None:
    guard = GuardEngine(policy=_guard_policy())
    target_id = "tests.guard_targets:failing"
    guard.register_target(target_id, failing, _repair_policy().guard)
    source = "def failing(value):\n    import socket\n    return value\n"
    policy = CandidateGuardPolicy(
        allow_new_capabilities=True,
        maximum_new_network_destinations=1,
    )

    within_budget = guard.evaluate_candidate(
        target_id,
        source,
        policy=policy,
        behavior_capture={
            "profile": {"network_destinations": ["api.example:443"]}
        },
        behavior_capture_complete=True,
    )
    over_budget = guard.evaluate_candidate(
        target_id,
        source,
        policy=policy,
        behavior_capture={
            "profile": {
                "network_destinations": [
                    "api.example:443",
                    "telemetry.example:443",
                ]
            }
        },
        behavior_capture_complete=True,
    )

    assert within_budget.eligible is True
    assert within_budget.resource_budget_status == "ASSESSED"
    assert within_budget.resource_budget_counts["maximum_new_network_destinations"] == 1
    assert over_budget.eligible is False
    assert over_budget.resource_budget_status == "REJECTED"
    assert over_budget.resource_budget_counts["maximum_new_network_destinations"] == 2
    assert over_budget.resource_budget_violations == (
        "candidate introduces 2 new network destinations (maximum 1)",
    )


def test_candidate_guard_does_not_treat_incomplete_resource_capture_as_safe() -> None:
    guard = GuardEngine(policy=_guard_policy())
    target_id = "tests.guard_targets:failing"
    guard.register_target(target_id, failing, _repair_policy().guard)
    score = guard.evaluate_candidate(
        target_id,
        "def failing(value):\n    import socket\n    return value\n",
        policy=CandidateGuardPolicy(
            allow_new_capabilities=True,
            maximum_new_network_destinations=1,
        ),
        behavior_capture={"profile": {"network_destinations": ["api.example:443"]}},
        behavior_capture_complete=False,
    )

    assert score.eligible is False
    assert score.resource_budget_status == "REJECTED"
    assert "incomplete" in score.resource_budget_violations[0]


def test_candidate_guard_counts_only_resources_new_to_the_baseline() -> None:
    baseline = BehaviorProfileSummary(
        subject=identify_function(failing),
        window_count=1,
        call_count=10,
        event_count=1,
        event_kind_counts={},
        network_destinations=("api.example:443",),
        filesystem_roots=(),
        subprocesses=(),
        imports=(),
        dynamic_code_operations=(),
    )
    score = StaticCandidateBehaviorAnalyzer.evaluate(
        "def failing(value):\n    import socket\n    return value\n",
        baseline=baseline,
        allow_new_capabilities=True,
        behavior_capture={
            "profile": {
                "network_destinations": [
                    "api.example:443",
                    "telemetry.example:443",
                ]
            }
        },
        behavior_capture_complete=True,
        resource_budgets={"maximum_new_network_destinations": 1},
    )

    assert score.eligible is True
    assert score.resource_budget_status == "ASSESSED"
    assert score.resource_budget_counts["maximum_new_network_destinations"] == 1


def test_repair_context_character_budget_applies_to_complete_llm_request() -> None:
    provider = CapturingRepairProvider()
    engine = RepairEngine(provider=provider)
    policy = replace(
        _repair_policy(),
        context=ContextPolicy(
            maximum_context_characters=160,
            maximum_log_records=200,
            previous_calls=3,
        ),
    )
    wrapped = repair(policy=policy, engine=engine)(failing)

    assert wrapped(999999) == 999999
    assert provider.request is not None
    request = provider.request
    total = sum(
        len(value)
        for value in (
            request.original_source,
            request.incident_summary,
            request.traceback_summary,
            request.state_summary,
            request.policy_summary,
            request.registered_cases_summary,
            request.logs_summary,
            request.guard_summary,
        )
    )
    assert total <= 160
