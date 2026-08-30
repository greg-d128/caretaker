# Repair policies

Caretaker accepts a policy setting only when the running release can honor its semantics. See [`POLICY_SEMANTICS.md`](POLICY_SEMANTICS.md) for the policy-truthfulness rules, reviewed policy-surface fingerprint, and explicitly reserved settings.

Authority-layer constraints can further restrict or deliberately override these settings. See [`POLICY_AUTHORITY.md`](POLICY_AUTHORITY.md) for supervisor-owned signed/unsigned authority stacks and runtime leases.

`RepairPolicy` is immutable configuration. A resolved policy is persisted as canonical data, a SHA-256 fingerprint, and a human-readable description.

## Lightweight adaptive instrumentation policy

`LightweightPolicy` is separate from `RepairPolicy`. It controls low-cost problem
detection, behavior sampling, evidence-gated promotion, and independently controlled
demotion. The signed authority namespace is `lightweight.*`.

Signal policies include exception and soft-timing thresholds. Their `promote_to` field
expresses the desired terminal capability. `promote_to=REPAIR` is repair eligibility,
not permission to skip observation. The complete repaired-function lifecycle is
`LIGHTWEIGHT -> BEHAVIOR -> REPAIR -> BEHAVIOR -> VALIDATION -> LONG_TERM_ACCEPTANCE`.
Both exceptions and soft-timing breaches may be repair-eligible. Pre-repair BEHAVIOR
gathers diagnostic evidence; post-repair BEHAVIOR observes the activated candidate.

`BehaviorSamplingPolicy` provides generation-scoped call-count sampling:

- `enabled`;
- `lightweight_every_calls`;
- `behavior_every_calls`;
- `randomize_initial_offset`.

A zero call interval disables sampling at that level. The initial offset is randomized
once per code generation when enabled; each ordinary call then needs only an integer
increment and comparison. A sample contributes Guard behavior evidence but does not
materialize a signed behavior snapshot by itself.

`BehaviorSnapshotPolicy.randomized_epoch_boundaries` is an opt-in policy for
non-overlapping randomized behavior epochs. When enabled, each epoch chooses a
uniform target between `randomized_epoch_min_samples` and
`randomized_epoch_max_samples`; the target is bounded below one snapshot's
useful minimum and above the configured maximum. The sealed snapshot records the
algorithm, bounds, selected target, and a commitment to the effective random
seed. Supplying `randomized_epoch_seed` makes boundary selection reproducible
for controlled testing; leaving it unset uses a system random source. These
epochs change evidence partitioning only: they never automatically accept a
Guard baseline or grant Repair authority.

`BehaviorSnapshotPolicy.maximum_return_categories` bounds the number of
successful-return categories retained per generation and per observation
stratum. Categories contain only the concrete runtime type and a coarse
builtin family such as `none`, `text`, `mapping`, or `iterator`; Caretaker does
not retain exact values, call `repr`, consume containers, or advance iterators.
When the bound is reached, the snapshot records incomplete category coverage and
an overflow count. These observations are evidence only and are not used as a
failure or Repair signal.

`BehaviorSnapshotPolicy.collection_max_active`, `collection_max_pending`, and
`collection_max_calls` govern operator-directed behavior captures. Requests are
durable, bounded, ordered by operator priority and deadline, and recover from an
interrupted active request as queued work after restart. A full queue applies
explicit backpressure; it does not silently discard a request. Cancellation is
recorded, and the resulting request provenance is included in the signed behavior
snapshot when a capture completes. Scheduling is evidence collection only: it
cannot modify Guard policy, an accepted baseline, or Repair state.

`RepairEvidencePolicy` gates `BEHAVIOR -> REPAIR`:

- `enabled`;
- `minimum_behavior_samples`;
- `minimum_observation_calls`;
- `minimum_duration_seconds`;
- `require_problem_reproduction`.

Only behavior samples collected while already in BEHAVIOR count toward repair evidence.
A threshold-triggering LIGHTWEIGHT call cannot satisfy the post-promotion reproduction
requirement, even if multiple signals occur during that same execution. Disabling the
repair-evidence policy disables automatic promotion from BEHAVIOR to REPAIR. An enabled
policy cannot set every evidence requirement to zero while also disabling reproduction;
Caretaker requires a real post-promotion observation before automatic repair.

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

For a BEHAVIOR promotion that never enters repair, the adaptive controller uses these
shared criteria to decide whether observation may demote again. Once an actual repair
candidate is activated, adaptive acceptance stops: `FunctionSlot` and
`ObservationPolicy` become the single authoritative acceptance state machine. The
candidate progresses from post-repair BEHAVIOR to VALIDATION (short-term accepted) and
then LONG_TERM_ACCEPTANCE. At that point an enabled demotion policy may reduce
observation intensity to LIGHTWEIGHT without changing the accepted candidate state.
Exceptions and configured soft-timing breaches count against non-repair adaptive
acceptance; a target that remains slow cannot demote merely because it returns
successfully.

`ObservationPolicy` and `InstrumentationDemotionPolicy` now inherit the same
`AcceptanceCriteria`, so short-term/long-term thresholds have one mathematical
definition. Lifecycle-specific actions such as rollback versus observation demotion
remain separate.

Once the evidence gate reaches `REPAIR`, the ordinary `RepairPolicy` still decides
what evidence, validation, authority, retry, Guard, and activation behavior is
permitted. Candidate activation then returns the adaptive lifecycle to BEHAVIOR rather
than treating repair as acceptance.

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

When `capture_results=True`, successful return values are recorded only as
bounded, data-only snapshots containing type, representation, hash, size, and
truncation metadata. This applies to ordinary, retry, and differential return
paths; exceptions never place raw result objects in the log.

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
