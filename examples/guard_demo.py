"""Small Guard technology demonstration.

This example records call-correlated behavior for one repair target. It does not
claim to be a hostile-code sandbox.
"""

from caretaker import (
    CandidateGuardPolicy,
    GuardBinding,
    GuardEngine,
    GuardPolicy,
    RepairEngine,
    RepairPolicy,
    ReplaySafety,
    RetryPolicy,
    StaticRepairProvider,
    repair,
)


guard = GuardEngine(policy=GuardPolicy())
repair_engine = RepairEngine(provider=StaticRepairProvider([]), guard=guard)

policy = RepairPolicy(
    retry=RetryPolicy(max_attempts=0, safety=ReplaySafety.PURE),
    guard=GuardBinding(
        enabled=True,
        observe_filesystem=True,
        include_guard_context_in_repair=True,
        validate_candidate_behavior=True,
        monitor_during_probation=True,
    ),
    candidate_guard=CandidateGuardPolicy(allow_new_capabilities=False),
)


@repair(policy=policy, engine=repair_engine)
def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def main() -> None:
    guard.install(import_hook=False, periodic=False)
    try:
        print(read_text(__file__).splitlines()[0])
        print(f"Recorded events: {len(guard.store.recent_behavior_events(limit=100))}")
    finally:
        guard.close()


if __name__ == "__main__":
    main()
