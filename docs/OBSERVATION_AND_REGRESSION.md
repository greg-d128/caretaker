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
`regression-fixture-get`. Isolated replay execution, including any value
rehydration and stronger sandbox contract, remains a separate future task.

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
