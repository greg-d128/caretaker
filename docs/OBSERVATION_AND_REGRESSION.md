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

The current corpus is in-memory and bounded. A future version should persist safe replay fixtures and associate them with source versions and historical failure fingerprints.

## Flapping prevention

Caretaker records rolled-back source hashes, rejects their automatic reactivation, rejects candidates identical to the active implementation, and detects a basic A-B-A source transition. More advanced structural analysis across many incidents remains planned.
