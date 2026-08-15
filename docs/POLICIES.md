# Repair policies

Authority-layer constraints can further restrict or deliberately override these settings. See [`POLICY_AUTHORITY.md`](POLICY_AUTHORITY.md) for supervisor-owned signed/unsigned authority stacks and runtime leases.

`RepairPolicy` is immutable configuration. A resolved policy is persisted as canonical data, a SHA-256 fingerprint, and a human-readable description.

## Lightweight adaptive instrumentation policy

`LightweightPolicy` is separate from `RepairPolicy`. It controls when a low-cost
wrapper is promoted and, independently, whether a promoted wrapper may later be
demoted. The signed authority namespace is `lightweight.*`.

Promotion policy is split by signal:

- `exception.occurrences` and `exception.window_seconds`;
- `exception.promote_to`;
- `soft_timing.seconds`;
- `soft_timing.occurrences` and `soft_timing.window_seconds`;
- `soft_timing.promote_to`.

Demotion is never implied by promotion. `InstrumentationDemotionPolicy.enabled` is
the explicit switch. Its acceptance fields deliberately mirror repaired-function
observation semantics:

- `initial_successful_executions`;
- `long_term_successful_executions`;
- `long_term_minimum_duration_seconds`;
- `probation_failure_budget`;
- `long_term_maximum_failures`;
- `long_term_failure_rate`;
- `stepwise`.

A promoted level first enters probation, then short-term acceptance, then long-term
acceptance. Only after long-term acceptance may an enabled demotion policy step the
target down. With `stepwise=True`, `REPAIR` demotes to `BEHAVIOR` first and must pass
a new acceptance cycle before returning to `LIGHTWEIGHT`. Exceptions and configured
soft-timing breaches count against acceptance; a target that remains slow cannot
demote merely because it continues to return successfully.

The lightweight policy decides *when* to promote. If promotion reaches `REPAIR`, the
ordinary `RepairPolicy` still decides what evidence, validation, authority, retry,
Guard, and activation behavior is permitted at that level.

## Trigger policy

- `ExceptionTrigger`
- `OutputValidationTrigger`
- `TimeoutTrigger` (`TimeoutMode.SOFT` only; the legacy string `"soft"` is coerced for compatibility)

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

A repair episode records both the effective logging-policy generation and the supervisor-owned authority-policy generation/fingerprint. Any relevant policy change before activation marks the pending repair stale. Approval is refused until the candidate is evaluated under the current generations.

## Caretaker-owned targets

The registry classifies all `caretaker.*` modules as internal. They are permanently diagnostic-only for generated Repair, regardless of an application policy requesting automatic repair. Guard and Integrity may still inspect them, and the supervisor may restart a failed component.
