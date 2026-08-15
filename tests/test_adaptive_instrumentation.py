from __future__ import annotations

from datetime import datetime, timezone
import time

import pytest

from caretaker import (
    AcceptanceState,
    AuthorityKind,
    BehaviorSamplingPolicy,
    ExceptionPromotionPolicy,
    InstrumentationDemotionPolicy,
    InstrumentationLevel,
    LightweightPolicy,
    PolicyAuthorityLayer,
    RepairEvidencePolicy,
    PolicyAuthoritySupervisor,
    PolicySetting,
    SoftTimingPromotionPolicy,
    get_adaptive_state,
    get_authority_runtime_context,
    lightweight,
    lightweight_dependency,
)
from caretaker.guard.policy import GuardBinding


class _FakeGuard:
    def __init__(self) -> None:
        self.registered: list[str] = []
        self.leases: list[tuple[str, object, int, str]] = []
        self.before: list[str] = []
        self.after: list[tuple[str, bool]] = []

    def register_target(self, target_id, function, binding, function_resolver=None):
        self.registered.append(target_id)

    def request_instrumentation(self, target_id, mode, *, execution_count, reason):
        self.leases.append((target_id, mode, execution_count, reason))
        return object()

    def before_call(self, target_id, function, call_id, *, candidate_id):
        self.before.append(target_id)

    def after_call(
        self,
        target_id,
        function,
        call_id,
        *,
        candidate_id,
        succeeded,
        elapsed_seconds,
    ):
        self.after.append((target_id, succeeded))


class _FakeEngine:
    def __init__(self, guard=None) -> None:
        self.guard = guard


@pytest.fixture(autouse=True)
def _restore_authority_context():
    context = get_authority_runtime_context()
    previous = context.effective.snapshot_dict()
    context.update_from_snapshot(
        {
            "generation": 0,
            "fingerprint": "unconfigured",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "layers": [],
            "verifications": [],
            "runtime_leases": [],
            "violations": [],
        }
    )
    yield
    context.update_from_snapshot(previous)


def test_exception_repair_request_observes_behavior_before_full_repair(monkeypatch, tmp_path) -> None:
    original_calls = 0
    managed_calls = 0
    guard = _FakeGuard()

    def fragile() -> str:
        nonlocal original_calls
        original_calls += 1
        raise ValueError("first failures are intentionally not captured in detail")

    policy = LightweightPolicy(
        exception=ExceptionPromotionPolicy(
            occurrences=2,
            window_seconds=3600,
            promote_to=InstrumentationLevel.REPAIR,
        ),
        sampling=BehaviorSamplingPolicy(
            lightweight_every_calls=0,
            behavior_every_calls=1,
            randomize_initial_offset=False,
        ),
        repair_evidence=RepairEvidencePolicy(
            minimum_behavior_samples=1,
            minimum_observation_calls=1,
            minimum_duration_seconds=0,
            require_problem_reproduction=True,
        ),
        demotion=InstrumentationDemotionPolicy(enabled=False),
    )
    wrapped = lightweight(
        policy=policy,
        engine=_FakeEngine(guard),
        behavior_binding=GuardBinding(enabled=True, observe_filesystem=True),
        target_id="test.adaptive.exception",
        state_directory=tmp_path,
    )(fragile)

    with pytest.raises(ValueError):
        wrapped()
    assert get_adaptive_state("test.adaptive.exception")["level"] == "LIGHTWEIGHT"

    with pytest.raises(ValueError):
        wrapped()
    promoted = get_adaptive_state("test.adaptive.exception")
    assert promoted["level"] == "BEHAVIOR"
    assert promoted["repair_requested"] is True
    assert promoted["repair_evidence_samples"] == 0
    assert promoted["recent_diagnostics"] == []

    with pytest.raises(ValueError):
        wrapped()
    evidence_state = get_adaptive_state("test.adaptive.exception")
    assert evidence_state["level"] == "REPAIR"
    assert evidence_state["repair_evidence_samples"] == 1
    assert evidence_state["problem_reproductions"] >= 1
    assert guard.before == ["test.adaptive.exception"]

    def fake_repair(*, policy, engine, target_id):
        def decorate(function):
            def managed(*args, **kwargs):
                nonlocal managed_calls
                managed_calls += 1
                return "managed-result"
            return managed
        return decorate

    import caretaker.decorators.api as decorator_api

    monkeypatch.setattr(decorator_api, "repair", fake_repair)
    assert wrapped() == "managed-result"
    assert original_calls == 3
    assert managed_calls == 1


def test_soft_timing_promotes_to_behavior_and_guard_begins_on_next_call(tmp_path) -> None:
    guard = _FakeGuard()
    engine = _FakeEngine(guard)
    policy = LightweightPolicy(
        exception=ExceptionPromotionPolicy(enabled=False),
        soft_timing=SoftTimingPromotionPolicy(
            enabled=True,
            seconds=0.001,
            occurrences=2,
            window_seconds=60,
            promote_to=InstrumentationLevel.BEHAVIOR,
        ),
        sampling=BehaviorSamplingPolicy(
            lightweight_every_calls=0,
            behavior_every_calls=1,
            randomize_initial_offset=False,
        ),
    )

    @lightweight(
        policy=policy,
        engine=engine,
        target_id="test.adaptive.timing",
        behavior_binding=GuardBinding(enabled=True, observe_filesystem=True),
        state_directory=tmp_path,
    )
    def slow() -> str:
        time.sleep(0.003)
        return "ok"

    assert slow() == "ok"
    assert slow() == "ok"
    assert get_adaptive_state("test.adaptive.timing")["level"] == "BEHAVIOR"
    assert guard.before == []

    assert slow() == "ok"
    assert guard.registered == ["test.adaptive.timing"]
    assert guard.before == ["test.adaptive.timing"]
    assert guard.after == [("test.adaptive.timing", True)]
    assert len(guard.leases) == 1


def test_policy_controlled_demotion_requires_short_and_long_term_acceptance(tmp_path) -> None:
    policy = LightweightPolicy(
        exception=ExceptionPromotionPolicy(enabled=False),
        soft_timing=SoftTimingPromotionPolicy(enabled=False),
        initial_level=InstrumentationLevel.BEHAVIOR,
        demotion=InstrumentationDemotionPolicy(
            enabled=True,
            initial_successful_executions=2,
            long_term_successful_executions=3,
            long_term_minimum_duration_seconds=0,
            probation_failure_budget=0,
            long_term_maximum_failures=0,
            long_term_failure_rate=0,
            stepwise=False,
        ),
    )

    @lightweight(
        policy=policy,
        engine=_FakeEngine(),
        target_id="test.adaptive.demote",
        behavior_binding=GuardBinding(enabled=False),
        state_directory=tmp_path,
    )
    def healthy() -> int:
        return 42

    assert healthy() == 42
    assert get_adaptive_state("test.adaptive.demote")["acceptance"] == AcceptanceState.PROBATION.value
    assert healthy() == 42
    assert get_adaptive_state("test.adaptive.demote")["acceptance"] == AcceptanceState.SHORT_TERM_ACCEPTED.value
    assert healthy() == 42

    state = get_adaptive_state("test.adaptive.demote")
    assert state["level"] == "LIGHTWEIGHT"
    assert state["acceptance"] == AcceptanceState.NONE.value
    assert state["promotion_reason"] == "policy-controlled demotion after long-term acceptance"


def test_long_term_acceptance_does_not_demote_when_policy_disables_it(tmp_path) -> None:
    policy = LightweightPolicy(
        exception=ExceptionPromotionPolicy(enabled=False),
        soft_timing=SoftTimingPromotionPolicy(enabled=False),
        initial_level=InstrumentationLevel.BEHAVIOR,
        demotion=InstrumentationDemotionPolicy(
            enabled=False,
            initial_successful_executions=2,
            long_term_successful_executions=3,
            long_term_minimum_duration_seconds=0,
            probation_failure_budget=0,
            long_term_maximum_failures=0,
            long_term_failure_rate=0,
        ),
    )

    @lightweight(
        policy=policy,
        engine=_FakeEngine(),
        target_id="test.adaptive.no-demote",
        behavior_binding=GuardBinding(enabled=False),
        state_directory=tmp_path,
    )
    def healthy() -> int:
        return 7

    healthy()
    healthy()
    healthy()
    state = get_adaptive_state("test.adaptive.no-demote")
    assert state["level"] == "BEHAVIOR"
    assert state["acceptance"] == AcceptanceState.LONG_TERM_ACCEPTED.value


def test_code_hash_change_starts_a_new_adaptive_generation(tmp_path) -> None:
    policy = LightweightPolicy(
        exception=ExceptionPromotionPolicy(occurrences=1, window_seconds=60),
        demotion=InstrumentationDemotionPolicy(enabled=False),
    )

    def first_version() -> None:
        raise RuntimeError("v1")

    first = lightweight(
        policy=policy,
        target_id="test.adaptive.generation",
        state_directory=tmp_path,
    )(first_version)
    with pytest.raises(RuntimeError):
        first()
    first_state = dict(get_adaptive_state("test.adaptive.generation"))
    assert first_state["level"] == "BEHAVIOR"
    assert first_state["repair_requested"] is True

    def second_version() -> str:
        return "v2"

    second = lightweight(
        policy=policy,
        target_id="test.adaptive.generation",
        state_directory=tmp_path,
    )(second_version)
    second_state = get_adaptive_state("test.adaptive.generation")
    assert second_state["level"] == "LIGHTWEIGHT"
    assert second_state["code_hash"] != first_state["code_hash"]
    assert second() == "v2"


def test_deployment_authority_can_control_lightweight_demotion(tmp_path) -> None:
    deployment = PolicyAuthorityLayer(
        schema_version=1,
        authority_id="test-deployment",
        kind=AuthorityKind.DEPLOYMENT,
        generation=1,
        created_at=datetime.now(timezone.utc).isoformat(),
        settings=(
            PolicySetting("lightweight.demotion.enabled", True, target="test.authority.*"),
            PolicySetting("lightweight.demotion.initial_successful_executions", 1, target="test.authority.*"),
            PolicySetting("lightweight.demotion.long_term_successful_executions", 2, target="test.authority.*"),
            PolicySetting("lightweight.demotion.long_term_minimum_duration_seconds", 0, target="test.authority.*"),
            PolicySetting("lightweight.demotion.long_term_maximum_failures", 0, target="test.authority.*"),
            PolicySetting("lightweight.demotion.long_term_failure_rate", 0, target="test.authority.*"),
            PolicySetting("lightweight.demotion.stepwise", False, target="test.authority.*"),
        ),
    )
    supervisor = PolicyAuthoritySupervisor((deployment,))
    get_authority_runtime_context().update_from_snapshot(supervisor.effective.snapshot_dict())

    @lightweight(
        policy=LightweightPolicy(
            exception=ExceptionPromotionPolicy(enabled=False),
            soft_timing=SoftTimingPromotionPolicy(enabled=False),
            initial_level=InstrumentationLevel.BEHAVIOR,
            demotion=InstrumentationDemotionPolicy(enabled=False),
        ),
        engine=_FakeEngine(),
        target_id="test.authority.target",
        behavior_binding=GuardBinding(enabled=False),
        state_directory=tmp_path,
    )
    def healthy() -> str:
        return "ok"

    assert healthy() == "ok"
    assert get_adaptive_state("test.authority.target")["level"] == "BEHAVIOR"
    assert healthy() == "ok"
    assert get_adaptive_state("test.authority.target")["level"] == "LIGHTWEIGHT"


def test_repeated_soft_timing_breaches_block_demotion(tmp_path) -> None:
    policy = LightweightPolicy(
        exception=ExceptionPromotionPolicy(enabled=False),
        soft_timing=SoftTimingPromotionPolicy(
            enabled=True,
            seconds=0.001,
            occurrences=2,
            window_seconds=60,
            promote_to=InstrumentationLevel.BEHAVIOR,
        ),
        initial_level=InstrumentationLevel.BEHAVIOR,
        demotion=InstrumentationDemotionPolicy(
            enabled=True,
            initial_successful_executions=1,
            long_term_successful_executions=2,
            long_term_minimum_duration_seconds=0,
            probation_failure_budget=0,
            long_term_maximum_failures=0,
            long_term_failure_rate=0,
            stepwise=False,
        ),
    )

    @lightweight(
        policy=policy,
        engine=_FakeEngine(),
        target_id="test.adaptive.slow-stays-promoted",
        behavior_binding=GuardBinding(enabled=False),
        state_directory=tmp_path,
    )
    def slow() -> str:
        time.sleep(0.003)
        return "ok"

    for _ in range(4):
        assert slow() == "ok"

    state = get_adaptive_state("test.adaptive.slow-stays-promoted")
    assert state["level"] == "BEHAVIOR"
    assert state["acceptance"] == AcceptanceState.PROBATION.value


def test_runtime_code_object_change_starts_new_generation(tmp_path) -> None:
    policy = LightweightPolicy(
        exception=ExceptionPromotionPolicy(occurrences=1, window_seconds=60),
        demotion=InstrumentationDemotionPolicy(enabled=False),
    )

    def target() -> str:
        raise RuntimeError("old implementation")

    def replacement() -> str:
        return "new implementation"

    wrapped = lightweight(
        policy=policy,
        target_id="test.adaptive.runtime-code-change",
        state_directory=tmp_path,
    )(target)

    with pytest.raises(RuntimeError):
        wrapped()
    old_state = dict(get_adaptive_state("test.adaptive.runtime-code-change"))
    assert old_state["level"] == "BEHAVIOR"
    assert old_state["repair_requested"] is True

    target.__code__ = replacement.__code__
    assert wrapped() == "new implementation"
    new_state = get_adaptive_state("test.adaptive.runtime-code-change")
    assert new_state["level"] == "LIGHTWEIGHT"
    assert new_state["code_hash"] != old_state["code_hash"]



def test_dependency_behavior_instrumentation_has_reentrant_escape_path() -> None:
    nested_results: list[str] = []
    wrapped = None

    class _RecursiveGuard(_FakeGuard):
        def before_call(self, target_id, function, call_id, *, candidate_id):
            super().before_call(target_id, function, call_id, candidate_id=candidate_id)
            if len(self.before) == 1:
                assert wrapped is not None
                nested_results.append(wrapped("inner"))

    guard = _RecursiveGuard()
    policy = LightweightPolicy(
        exception=ExceptionPromotionPolicy(enabled=False),
        soft_timing=SoftTimingPromotionPolicy(enabled=False),
        sampling=BehaviorSamplingPolicy(
            lightweight_every_calls=0,
            behavior_every_calls=1,
            randomize_initial_offset=False,
        ),
        demotion=InstrumentationDemotionPolicy(enabled=False),
        initial_level=InstrumentationLevel.BEHAVIOR,
        persist_state=False,
    )

    def dependency(value: str) -> str:
        return f"dependency:{value}"

    wrapped = lightweight_dependency(
        policy=policy,
        target_id="test.dependency.reentrant",
        engine=_FakeEngine(guard),
    )(dependency)

    assert wrapped("outer") == "dependency:outer"
    assert nested_results == ["dependency:inner"]
    assert guard.before == ["test.dependency.reentrant"]
    assert guard.after == [("test.dependency.reentrant", True)]


def test_core_dependency_boundaries_use_lightweight_instrumentation() -> None:
    from caretaker.behavior import OllamaBehaviorSnapshotAnalyst
    from caretaker.evidence.store import SQLiteEvidenceStore
    from caretaker.guard.provider import OllamaBehaviorAssessmentProvider
    from caretaker.logging.interrogation import OllamaRootCauseProvider
    from caretaker.provider import OllamaRepairProvider
    from caretaker.store import SQLiteRepairStore
    from caretaker.validation import SubprocessValidationBackend

    boundaries = (
        OllamaRepairProvider._chat,
        OllamaBehaviorAssessmentProvider._chat,
        OllamaRootCauseProvider.assess,
        OllamaBehaviorSnapshotAnalyst._assess_evidence,
        SQLiteRepairStore._connect,
        SQLiteEvidenceStore._connect,
        SubprocessValidationBackend._run_worker,
    )
    assert all(hasattr(item, "__caretaker_adaptive__") for item in boundaries)


def test_call_count_sampling_collects_periodic_behavior_without_promotion(tmp_path) -> None:
    guard = _FakeGuard()
    policy = LightweightPolicy(
        exception=ExceptionPromotionPolicy(enabled=False),
        soft_timing=SoftTimingPromotionPolicy(enabled=False),
        sampling=BehaviorSamplingPolicy(
            lightweight_every_calls=3,
            behavior_every_calls=1,
            randomize_initial_offset=False,
        ),
        demotion=InstrumentationDemotionPolicy(enabled=False),
    )

    @lightweight(
        policy=policy,
        engine=_FakeEngine(guard),
        target_id="test.adaptive.periodic-sampling",
        behavior_binding=GuardBinding(enabled=True, observe_filesystem=True),
        state_directory=tmp_path,
    )
    def healthy(value: int) -> int:
        return value + 1

    assert healthy(1) == 2
    assert healthy(2) == 3
    state = get_adaptive_state("test.adaptive.periodic-sampling")
    assert state["sampling_call_counter"] == 2
    assert state["behavior_samples"] == 0
    assert guard.before == []

    assert healthy(3) == 4
    state = get_adaptive_state("test.adaptive.periodic-sampling")
    assert state["level"] == "LIGHTWEIGHT"
    assert state["sampling_call_counter"] == 0
    assert state["behavior_samples"] == 1
    assert guard.before == ["test.adaptive.periodic-sampling"]

    healthy(4)
    healthy(5)
    healthy(6)
    state = get_adaptive_state("test.adaptive.periodic-sampling")
    assert state["behavior_samples"] == 2
    assert guard.before == [
        "test.adaptive.periodic-sampling",
        "test.adaptive.periodic-sampling",
    ]


def test_soft_timing_can_request_repair_but_must_gather_behavior_first(tmp_path) -> None:
    guard = _FakeGuard()
    policy = LightweightPolicy(
        exception=ExceptionPromotionPolicy(enabled=False),
        soft_timing=SoftTimingPromotionPolicy(
            enabled=True,
            seconds=0.001,
            occurrences=1,
            window_seconds=60,
            promote_to=InstrumentationLevel.REPAIR,
        ),
        sampling=BehaviorSamplingPolicy(
            lightweight_every_calls=0,
            behavior_every_calls=1,
            randomize_initial_offset=False,
        ),
        repair_evidence=RepairEvidencePolicy(
            minimum_behavior_samples=1,
            minimum_observation_calls=1,
            minimum_duration_seconds=0,
            require_problem_reproduction=True,
        ),
        demotion=InstrumentationDemotionPolicy(enabled=False),
    )

    @lightweight(
        policy=policy,
        engine=_FakeEngine(guard),
        target_id="test.adaptive.soft-timing-repair",
        behavior_binding=GuardBinding(enabled=True, observe_filesystem=True),
        state_directory=tmp_path,
    )
    def slow() -> str:
        time.sleep(0.003)
        return "ok"

    assert slow() == "ok"
    state = get_adaptive_state("test.adaptive.soft-timing-repair")
    assert state["level"] == "BEHAVIOR"
    assert state["repair_requested"] is True
    assert state["repair_evidence_samples"] == 0

    assert slow() == "ok"
    state = get_adaptive_state("test.adaptive.soft-timing-repair")
    assert state["level"] == "REPAIR"
    assert state["repair_evidence_samples"] == 1
    assert state["problem_reproductions"] >= 1


def test_sampling_counter_resets_for_new_code_generation(tmp_path) -> None:
    guard = _FakeGuard()
    policy = LightweightPolicy(
        exception=ExceptionPromotionPolicy(enabled=False),
        soft_timing=SoftTimingPromotionPolicy(enabled=False),
        sampling=BehaviorSamplingPolicy(
            lightweight_every_calls=3,
            behavior_every_calls=1,
            randomize_initial_offset=False,
        ),
        demotion=InstrumentationDemotionPolicy(enabled=False),
    )

    def target() -> str:
        return "old"

    def replacement() -> str:
        return "new"

    wrapped = lightweight(
        policy=policy,
        engine=_FakeEngine(guard),
        target_id="test.adaptive.sample-generation",
        behavior_binding=GuardBinding(enabled=True),
        state_directory=tmp_path,
    )(target)

    assert wrapped() == "old"
    assert wrapped() == "old"
    assert get_adaptive_state("test.adaptive.sample-generation")["sampling_call_counter"] == 2

    target.__code__ = replacement.__code__
    assert wrapped() == "new"
    state = get_adaptive_state("test.adaptive.sample-generation")
    assert state["sampling_call_counter"] == 1
    assert state["behavior_samples"] == 0
    assert guard.before == []


def test_deployment_authority_can_control_sampling_and_repair_evidence(tmp_path) -> None:
    deployment = PolicyAuthorityLayer(
        schema_version=1,
        authority_id="test-sampling-deployment",
        kind=AuthorityKind.DEPLOYMENT,
        generation=1,
        created_at=datetime.now(timezone.utc).isoformat(),
        settings=(
            PolicySetting("lightweight.sampling.lightweight_every_calls", 2, target="test.sampling.*"),
            PolicySetting("lightweight.sampling.randomize_initial_offset", False, target="test.sampling.*"),
            PolicySetting("lightweight.repair_evidence.minimum_behavior_samples", 3, target="test.sampling.*"),
        ),
    )
    supervisor = PolicyAuthoritySupervisor((deployment,))
    get_authority_runtime_context().update_from_snapshot(supervisor.effective.snapshot_dict())
    guard = _FakeGuard()

    @lightweight(
        policy=LightweightPolicy(
            exception=ExceptionPromotionPolicy(enabled=False),
            soft_timing=SoftTimingPromotionPolicy(enabled=False),
            sampling=BehaviorSamplingPolicy(
                lightweight_every_calls=10_000,
                behavior_every_calls=10,
                randomize_initial_offset=True,
            ),
            repair_evidence=RepairEvidencePolicy(minimum_behavior_samples=20),
            demotion=InstrumentationDemotionPolicy(enabled=False),
        ),
        engine=_FakeEngine(guard),
        target_id="test.sampling.target",
        behavior_binding=GuardBinding(enabled=True),
        state_directory=tmp_path,
    )
    def healthy() -> str:
        return "ok"

    assert healthy() == "ok"
    assert guard.before == []
    assert healthy() == "ok"
    assert guard.before == ["test.sampling.target"]
    controller = healthy.__caretaker_adaptive__
    assert controller.policy.repair_evidence.minimum_behavior_samples == 3


def test_threshold_call_cannot_count_as_post_promotion_problem_reproduction(tmp_path) -> None:
    policy = LightweightPolicy(
        exception=ExceptionPromotionPolicy(
            occurrences=1,
            window_seconds=60,
            promote_to=InstrumentationLevel.REPAIR,
        ),
        soft_timing=SoftTimingPromotionPolicy(
            enabled=True,
            seconds=0.001,
            occurrences=1,
            window_seconds=60,
            promote_to=InstrumentationLevel.REPAIR,
        ),
        sampling=BehaviorSamplingPolicy(
            lightweight_every_calls=0,
            behavior_every_calls=1,
            randomize_initial_offset=False,
        ),
        repair_evidence=RepairEvidencePolicy(
            minimum_behavior_samples=0,
            minimum_observation_calls=0,
            minimum_duration_seconds=0,
            require_problem_reproduction=True,
        ),
        demotion=InstrumentationDemotionPolicy(enabled=False),
    )

    @lightweight(
        policy=policy,
        target_id="test.adaptive.same-call-signal",
        state_directory=tmp_path,
    )
    def slow_failure() -> None:
        time.sleep(0.003)
        raise RuntimeError("both exception and timing signal occur on the threshold call")

    with pytest.raises(RuntimeError):
        slow_failure()

    state = get_adaptive_state("test.adaptive.same-call-signal")
    assert state["level"] == "BEHAVIOR"
    assert state["repair_requested"] is True
    assert state["problem_reproductions"] == 0
