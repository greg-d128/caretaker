# Observation, rollback, and regression

## Behavior capture epochs

Each registered function generation has one authoritative statistical
accumulator. A completed call is assigned exactly one monotonically increasing
sample sequence number. Automatic materialization or an operator-requested
function capture atomically closes the current epoch and starts a successor;
snapshot signing and storage may then proceed outside the observation lock.

A closed epoch records its generation fingerprint, epoch ID and ordinal,
first/last sample sequence, observation times, distributions, rates, resource
evidence, and monitoring strata. Generation coverage is accumulated only when
the stored epoch ranges are contiguous, non-overlapping, and agree with their
reported call counts. Otherwise the snapshot remains available as `partial`
evidence. Module summaries, active views, legacy artifacts, and externally
supplied captures are not assumed to have exclusive epoch ownership.

The same immutable epoch may be referenced by Behavior comparisons, Guard
baselines, investigations, and other consumers. Reuse does not duplicate its
calls in generation coverage. Global system counters remain contextual signals;
function-attributed duration, outcome, and resource deltas are the less noisy
inputs for per-function outlier analysis.

## Candidate observation

After activation, a candidate starts in `ACTIVE_PROBATION`. Successful executions can advance it to `INITIALLY_VALIDATED` and then `LONG_TERM_ACCEPTED`.

Failures are counted separately from successes. During probation, automatic rollback occurs only after the configured failure budget is exceeded. Long-term acceptance uses count and rate budgets and does not automatically roll back unless configured.

## Function execution contracts and effect evidence

Registered targets may declare a `FunctionExecutionContract`:

```python
from caretaker import FunctionExecutionContract, ReplaySafety, SideEffectClass

@repair(
    execution_contract=FunctionExecutionContract(
        side_effects=SideEffectClass.READ_ONLY,
        retry_safety=ReplaySafety.IDEMPOTENT,
    )
)
def lookup(value):
    ...
```

The contract is an application declaration, not proof and not an authority
grant. The effective `RepairPolicy.retry` settings still decide whether a retry
is permitted. `UNKNOWN` is the least-assumption default. `PURE_FUNCTION`
differential execution requires an explicitly pure contract; side-effecting or
unknown targets require an isolation adapter before both implementations may be
run.

Guard behavior evidence can record imports, network/DNS and socket activity,
filesystem reads and writes, subprocesses, dynamic code, and environment reads.
Managed function calls also pass successful return values through the Guard
capture path as bounded type/category and structural-shape evidence; raw return
values remain outside this signal.
`EffectObservation` summarizes those observations and
`assess_shadow_eligibility()` applies a conservative gate:

- an observed effect can disqualify a pure or read-only declaration;
- a network connection is treated as externally visible activity even when it
  is not a write;
- incomplete or sampled coverage never proves that a function is pure;
- idempotence permits a policy to consider retries, but does not by itself make
  duplicate shadow execution safe.

An operator or rollout adapter can derive the same bounded evidence directly
from a Guard behavior capture:

```python
observation = EffectObservation.from_behavior_capture(
    behavior_capture,
    complete=False,
)
decision = assess_shadow_eligibility(function_contract, observation)
```

The converter uses both event-kind counts and retained resource summaries. A
retained API/network destination, filesystem root, subprocess, import, or
dynamic-code operation is therefore enough to flag observed activity even if
the event-kind count was compacted. When filesystem event kinds are retained,
an observed `FILE_WRITE` is distinguished from proven read-only activity; an
ambiguous filesystem root remains conservatively externally visible. `complete`
must be asserted by the collector that can justify complete coverage; a normal
bounded capture must remain incomplete. This makes positive side-effect
detection partly automatic without turning absence of an observed resource into
proof of purity.

The result is rollout evidence, not authorization. A rollout policy must still
authorize the execution strategy, preserve validation and authority gates, and
record the decision.

When rollout execution is connected to `ObservationManager`, authoritative
candidate successes and failures retain the rollout ID and routing decision
hash on their `ObservationRecord`. This links acceptance and rollback evidence
to the exact policy-bound selection. Shadow executions remain comparison
evidence only and never advance candidate acceptance counters.
When an audit callback is configured, the same authoritative success or failure
also emits a bounded `REPAIR_CANDIDATE_OBSERVATION` event containing counters,
candidate state, rollback status, and rollout provenance without result values
or exception messages.

The read-only target/slot snapshot exposes the effective contract as
`execution_contract.side_effects` and `execution_contract.retry_safety`, so
operator projections can show the duplicate-execution boundary alongside the
candidate lifecycle.

## Original-authoritative shadow execution

`shadow_execute()` is a bounded evidence primitive for a future rollout adapter.
It always returns the deployed/original result; candidate output and exceptions
are evidence only. Original and candidate calls receive independent input
copies. A target with uncertain or observed externally visible effects must
provide an application-owned `ShadowIsolationAdapter` whose
`isolation_verified=True` means that candidate effects cannot escape into
authoritative application state. An adapter identity and the verified-isolation
claim are recorded in the result. An unverified adapter is rejected.

This does not make a candidate active, satisfy validation, or grant authority.
It also does not claim that a pure declaration proves the absence of hidden
effects; observed effects disqualify the unisolated path, while missing
observations remain incomplete evidence.

## Differential execution

For explicitly pure functions, Caretaker may run the previous and candidate versions against independent deep-copied arguments.

- Original fails, candidate succeeds: candidate result may be returned.
- Original succeeds, candidate fails: original result may be returned and candidate rejected.
- Both fail: both failures become evidence for another repair episode.
- Both succeed and compare equivalent: candidate may continue.
- Both succeed but differ: candidate is rejected unless a registered comparator declares semantic equivalence.

Differential execution can run both implementations. `PURE_FUNCTION` therefore requires `pure_function_confirmed=True`; do not set that acknowledgement for side-effecting functions without an isolation adapter.

## Regression corpus

When a repaired replay succeeds and the function is declared pure or idempotent, Caretaker records a bounded regression case. Future candidates must pass these cases in the validation worker.

The executable corpus remains in-memory and bounded. Deployments may opt in to a
separate persistent fixture store with `[logging.regression] enabled = true`.
Persistent fixtures are bounded JSON evidence: values are redacted and truncated,
source incident/candidate and function-version metadata is retained, and each
record has an integrity hash. They are marked `DATA_ONLY_NOT_EXECUTABLE` and are
never loaded into the validation corpus or executed. Storage is limited per target
and failures to persist do not change repair success or authority decisions.

Fixtures can be inspected read-only with `caretaker-regression-fixtures` or the
supervisor control commands `regression-fixture-list` and
`regression-fixture-get`. Incident-linked fixtures can be replayed through the
supervisor's `incident-capsule-replay` command or the
`caretaker-capsule-replay` CLI. The selected capsule and fixture must belong to
the same incident, and the result is separate from the immutable capsule. The
CLI also supports bounded, non-interactive `--scope incident` and `--scope all`
replay. The supervisor evaluates each fixture independently and returns
per-fixture outcomes, so missing capsules and failed policy or backend checks
do not discard other historical results. Batch replay remains subject to the
same source-hash, replay-safety, and isolation policy as selected replay.

The first replay contract is now explicit in the API. `IsolatedReplayCoordinator`
requires policy opt-in, a PURE or IDEMPOTENT fixture, a verified subject source,
and a configured backend meeting the policy's minimum isolation (VM by
default). Deployments can register one or more backends with the coordinator;
it selects the lowest available backend that satisfies policy. If no backend is
configured or available, replay fails closed. `RootlessPodmanReplayBackend`
provides an optional container implementation for exact-JSON fixtures; a VM
backend remains future work. The backend receives only the JSON envelope and
owns rehydration inside its boundary. There is no process-level fallback, and
replay results do not modify the Incident Capsule or repair state. Ordinary
repair validation remains PROCESS by default and does not require Podman.

## Flapping prevention

Caretaker records rolled-back source hashes, rejects their automatic reactivation, rejects candidates identical to the active implementation, and detects a basic A-B-A source transition. More advanced structural analysis across many incidents remains planned.
