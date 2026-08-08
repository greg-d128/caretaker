# Repair policies

`RepairPolicy` is immutable configuration. A resolved policy is persisted as canonical data, a SHA-256 fingerprint, and a human-readable description.

## Trigger policy

- `ExceptionTrigger`
- `OutputValidationTrigger`
- `TimeoutTrigger` (`mode="soft"` only)

## State policy

Failure-frame locals are not captured by default because they frequently contain secrets that were derived after function entry and therefore cannot be protected by argument masking alone. Enable `capture_failure_locals=True` only with an appropriate evidence/redaction policy.

0.3.0a3 supports bounded `copy.deepcopy` snapshots for arguments, instance state, and explicitly named globals. Mutation differences are recursive and capped by `max_diff_entries`.

Custom transaction resources and alternative serialization strategies remain reserved. `restore_before_retry` restores only captured in-process Python state. It does not roll back database commits, filesystem changes, messages, HTTP requests, subprocess effects, or other external side effects. `restore_external_side_effects=True` is rejected in this release rather than silently implying transactional rollback.

## Retry policy

- `max_attempts`
- `safety`
- `require_successful_state_restore`
- `retry_original_exception_only`
- `backoff_seconds`

Retries are permitted only when safety and state policy permit them. Any retry requires an explicit replay classification; `UNKNOWN` and `NEVER` are rejected when `max_attempts > 0`.

## Validation policy

Mandatory V1 security checks cannot be disabled. Generated tests are opt-in and advisory. Registered tests and regression cases are authoritative validation evidence.

## Observation policy

Defines:

- initial success threshold;
- long-term success threshold and minimum duration;
- probation failure budget;
- long-term failure count and rate;
- rollback behavior;
- optional differential execution.

## Stability policy

Prevents known failed source reactivation and basic A-B-A oscillation. Full historical flapping analysis remains future work.

## Integrity repair policy

Protected automatic repair is disabled by default. Sealed code cannot be auto-repaired.

## Guard integration policy

`RepairPolicy` now includes:

```python
guard: GuardBinding
candidate_guard: CandidateGuardPolicy
```

`GuardBinding` selects call-correlated observation, inclusion of Guard evidence in repair requests, candidate behavioral validation, probation monitoring, and the desired deviation action.

`CandidateGuardPolicy` defines whether a candidate may introduce new capabilities and the permitted number of new network destinations, filesystem roots, and subprocesses.

Guard policy is resolved into the same canonical and human-readable policy snapshot as the repair settings, preserving exactly which behavioral constraints influenced a decision.

## Logging binding and repair authority

`RepairPolicy` includes:

```python
logging: LoggingBinding
authority: RepairAuthority
```

`LoggingBinding` selects call, exception, timing, argument, and result evidence for the repair target. The effective operator policy can further constrain or require capture.

`RepairAuthority` has four levels:

- `ANALYZE_ONLY`
- `PROPOSE_ONLY`
- `REQUIRE_OPERATOR_APPROVAL`
- `AUTOMATIC_ELIGIBLE_REPAIRS`

`REQUIRE_OPERATOR_APPROVAL` is the default. Automatic activation must be opted into explicitly with `AUTOMATIC_ELIGIBLE_REPAIRS` (or the convenience constructor `RepairPolicy.automatic(...)`); deterministic validation and observation gates still apply after that opt-in.

## Effective policy generation

A repair episode records the effective logging-policy generation. Any policy change before activation marks the pending repair stale. Approval is refused until the candidate is evaluated under the current generation.

## Caretaker-owned targets

The registry classifies all `caretaker.*` modules as internal. They are permanently diagnostic-only for generated Repair, regardless of an application policy requesting automatic repair. Guard and Integrity may still inspect them, and the supervisor may restart a failed component.
