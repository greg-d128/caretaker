from caretaker import (
    CandidateProposal,
    DifferentialExecutionMode,
    DifferentialExecutionPolicy,
    ExceptionTrigger,
    ObservationPolicy,
    RegisteredCase,
    RepairEngine,
    RepairPolicy,
    ReplaySafety,
    RetryPolicy,
    StatePolicy,
    repair,
)
from caretaker.domain import DifferentialEvidence
from caretaker.provider import CandidateBatch
from caretaker.store import InMemoryRepairStore
from tests.sample_targets import broken_divide


class SequentialProvider:
    name = "sequential-test"
    model_name = None
    supports_synthesis = False

    def __init__(self) -> None:
        self.calls = 0

    def generate(self, request):
        self.calls += 1
        if self.calls == 1:
            proposal = CandidateProposal(
                source="""
def broken_divide(total: float, count: int) -> float:
    if count == 0:
        return 0.0
    return abs(total / count)
""",
                explanation="Fixes zero division but incorrectly changes negative results.",
            )
        else:
            proposal = CandidateProposal(
                source="""
def broken_divide(total: float, count: int) -> float:
    return 0.0 if count == 0 else total / count
""",
                explanation="Preserve signs while handling zero division.",
            )
        return CandidateBatch(
            provider_name=self.name,
            model_name=None,
            prompt_version=f"test-{self.calls}",
            prompt_text="test",
            candidates=(proposal,),
        )

    def synthesize(self, request, candidates):
        raise NotImplementedError


def test_differential_mismatch_submits_both_versions_for_another_repair() -> None:
    store = InMemoryRepairStore()
    provider = SequentialProvider()
    engine = RepairEngine(provider=provider, store=store)
    policy = RepairPolicy(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
        observation=ObservationPolicy(
            initial_successful_executions=5,
            long_term_successful_executions=20,
            long_term_minimum_duration_seconds=0,
            differential_execution=DifferentialExecutionPolicy(
                mode=DifferentialExecutionMode.PURE_FUNCTION,
                observation_executions=5,
            ),
        ),
    )
    healed = repair(
        policy=policy,
        engine=engine,
        cases=(
            RegisteredCase("zero", args=(4.0, 0), expected=0.0),
            RegisteredCase("positive", args=(4.0, 2), expected=2.0),
        ),
    )(broken_divide)

    assert healed(4.0, 0) == 0.0
    assert healed(-4.0, 2) == -2.0
    assert provider.calls == 2
    assert healed.__caretaker_target__.slot.load().number == 2
    differential_incidents = [
        incident for incident in store.incidents.values()
        if isinstance(incident.failure, DifferentialEvidence)
    ]
    assert len(differential_incidents) == 1
    assert differential_incidents[0].failure.original_output is not None
    assert differential_incidents[0].failure.candidate_output is not None
    assert differential_incidents[0].failure.original_output.representation == "-2.0"
    assert differential_incidents[0].failure.candidate_output.representation == "2.0"
