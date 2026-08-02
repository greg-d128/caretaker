# Observation, rollback, and regression

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

Do not use differential execution for side-effecting functions without a future isolation adapter.

## Regression corpus

When a repaired replay succeeds and the function is declared pure or idempotent, Caretaker records a bounded regression case. Future candidates must pass these cases in the validation worker.

The current corpus is in-memory and bounded. A future version should persist safe replay fixtures and associate them with source versions and historical failure fingerprints.

## Flapping prevention

Caretaker records rolled-back source hashes, rejects their automatic reactivation, rejects candidates identical to the active implementation, and detects a basic A-B-A source transition. More advanced structural analysis across many incidents remains planned.
