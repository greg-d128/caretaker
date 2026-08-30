# Decorators

## Umbrella decorator

`@caretaker` is the preferred interface when a function uses multiple
Caretaker capabilities. It is a thin facade over `@repair`: the function
is registered through the same `RepairPolicy`, `RepairEngine`, and stable
`FunctionSlot`, and no additional runtime wrapper is introduced.

Logging, Guard, candidate-behavior checks, Integrity restrictions, and
Repair behavior are selected through the existing policy objects.

```python
@caretaker(
    policy=policy,
    engine=engine,
    target_id="optional-stable-id",
    cases=(...),
    tags=frozenset({...}),
    integrity_class=IntegrityClass.ORDINARY,
)
def function(...):
    ...
```

Use the narrower decorators when the narrower interface better describes
the intent:

- `@logged(...)` for Logging without Repair.
- `@repair(...)` for an explicitly Repair-oriented target.
- `@repair_on_exception(...)`, `@repair_on_invalid_output(...)`, and
  `@repair_on_timeout(...)` for the existing convenience forms.

`@caretaker` does not introduce a new policy type. In particular,
`RepairPolicy` remains the single policy composition used by the Repair
execution boundary.

`@repair` preserves `staticmethod`, `classmethod`, and property descriptors
when it is applied outside those decorators. Property support wraps the getter
and leaves the setter/deleter unchanged unless they are separately managed.

## Lightweight adaptive decorators

Use `@lightweight` when the normal execution path should pay only for inexpensive
problem detection plus sparse behavior sampling. Healthy LIGHTWEIGHT calls do not
capture arguments, locals, tracebacks, or Repair state. Sampling is call-count based,
so the hot path is an integer increment and comparison rather than a clock lookup.

```python
from caretaker import (
    AdaptiveAggregationPolicy,
    BehaviorSamplingPolicy,
    ExceptionPromotionPolicy,
    InstrumentationDemotionPolicy,
    InstrumentationLevel,
    LightweightPolicy,
    RepairEvidencePolicy,
    SoftTimingPromotionPolicy,
    lightweight,
)

policy = LightweightPolicy(
    exception=ExceptionPromotionPolicy(
        occurrences=2,
        window_seconds=3600,
        promote_to=InstrumentationLevel.REPAIR,
    ),
    soft_timing=SoftTimingPromotionPolicy(
        enabled=True,
        seconds=0.250,
        occurrences=5,
        window_seconds=1800,
        promote_to=InstrumentationLevel.REPAIR,
    ),
    sampling=BehaviorSamplingPolicy(
        lightweight_every_calls=10_000,
        behavior_every_calls=10,
        randomize_initial_offset=True,
    ),
    repair_evidence=RepairEvidencePolicy(
        minimum_behavior_samples=20,
        minimum_observation_calls=100,
        minimum_duration_seconds=30,
        require_problem_reproduction=True,
    ),
    demotion=InstrumentationDemotionPolicy(
        enabled=True,
        initial_successful_executions=10,
        long_term_successful_executions=100,
        long_term_minimum_duration_seconds=3600,
    ),
    # Optional: workers emit bounded evidence batches to the supervisor ledger.
    # It is disabled by default and never authorizes promotion or Repair.
    aggregation=AdaptiveAggregationPolicy(
        enabled=True,
        flush_after_observations=64,
        flush_interval_seconds=5,
        # Optional explicit population/regime identity.
        aggregation_scope="cluster:blue",
    ),
)

@lightweight(policy=policy, target_id="payments.lookup")
def lookup(...):
    ...
```

When enabled, adaptive workers write bounded pending batches under the configured
Caretaker data directory. The supervisor is the only component that merges those
batches, after checking the current generation, policy fingerprint, and authority
context. Batch failures are recorded as optional evidence failures and do not alter
the wrapped function's result. This currently aggregates evidence only; adaptive
promotion and Repair remain process-local decisions.

Caretaker exposes a single adaptive repair lifecycle to operators:

`LIGHTWEIGHT -> BEHAVIOR -> REPAIR -> BEHAVIOR -> VALIDATION -> LONG_TERM_ACCEPTANCE`

The two BEHAVIOR stages have different jobs. Before repair, BEHAVIOR increases sampling
and gathers enough evidence to justify remediation. After a candidate is activated,
BEHAVIOR observes the replacement while `FunctionSlot` remains authoritative for
rollback and candidate state. `VALIDATION` corresponds to the candidate having passed
its short-term/probation criteria; it continues operating under observation until the
existing long-term acceptance criteria are satisfied.

Instrumentation intensity is deliberately separate from lifecycle stage. A target in
post-repair `LONG_TERM_ACCEPTANCE` may return to LIGHTWEIGHT observation if demotion
policy permits it without erasing the fact that the repaired implementation completed
its acceptance lifecycle.

`promote_to=REPAIR` on an exception or soft-timing policy means that the signal is
repair-eligible. It does **not** mean LIGHTWEIGHT jumps directly to REPAIR. The
threshold first transitions the target to pre-repair BEHAVIOR and records a repair
request. `RepairEvidencePolicy` then controls when enough post-promotion evidence
exists to enter REPAIR. The policy must require at least one form of post-promotion
evidence; an all-zero evidence gate is rejected. Requiring reproduction prevents a
transient threshold from immediately triggering repair if the problem disappears
during observation.

The call that reaches a LIGHTWEIGHT promotion threshold still completes under the old
level. For example, with `occurrences=2`, the first two exceptions are not
retroactively reconstructed as full incidents. Subsequent BEHAVIOR calls collect the
evidence on which a repair can be based.

`BehaviorSamplingPolicy` controls periodic behavior contribution independently of
promotion. A `lightweight_every_calls=10_000` policy increments a generation-local
counter and observes one call when the threshold is reached, then resets the counter.
`behavior_every_calls` normally uses a much smaller value so evidence accumulates
quickly after a suspected problem. Zero disables periodic sampling at that level.
When `randomize_initial_offset=True`, one random offset is chosen only when the code
generation starts, preventing identically configured workers from sampling on the same
invocation without adding random-number overhead to ordinary calls. Behavior samples
feed Guard evidence and can therefore be incorporated into operator-created behavior
snapshots; sampling does not materialize/sign a new snapshot on every sampled call.

Convenience forms are also available:

- `@lightweight_on_exception(...)`;
- `@lightweight_on_soft_timeout(...)`;
- `@lightweight_dependency(...)` for Caretaker-owned dependency boundaries.

The soft-timeout convenience decorator is repair-eligible by default, but still passes
through BEHAVIOR and the repair-evidence gate before REPAIR.

`@lightweight_dependency` never permits generated self-repair. It may promote to
behavioral diagnostics, which avoids recursive repair loops when a dependency used
by Caretaker itself is unhealthy. Dependency observation also has a thread-local
re-entrancy escape path: telemetry calls made while observing a dependency execute
the inner dependency without adaptive instrumentation. Core Ollama, SQLite, and
validation-subprocess boundaries use this decorator by default.

### Dependency module instrumentation

`instrument_dependencies(...)` installs the same lightweight dependency boundary over
selected imported module attributes and returns reversible slot metadata. It is
intended to run during application initialization, after the Guard/Repair engines are
constructed but before Guard installs global hooks or normal application work begins.

For startup code that must instrument a dependency before application imports
capture `from module import function` references, use the explicit
`install_dependency_import_hook(...)` allowlist. The hook covers only named
modules or `module:attribute` functions and its `restore()` method removes the
finder and restores attributes it still owns.

```python
import json
import os
import subprocess

from caretaker import GuardEngine, RepairEngine, instrument_dependencies

guard = GuardEngine()
engine = RepairEngine(guard=guard)

dependencies = instrument_dependencies(
    modules=(json,),
    functions=(
        (os, "walk"),
        subprocess.run,
    ),
    engine=engine,
    target_prefix="myapp.dependency",
    prepare_guard=True,
)

guard.install()
try:
    run_application()
finally:
    guard.close()
    dependencies.restore()
```

A bare module instruments public Python/builtin functions whose `__module__` matches
the supplied module. This avoids silently wrapping imported aliases and classes.
Explicit entries in `functions=` can instrument re-exported or C-backed functions and
accept a callable, `(module, attribute_name)`, or `"module:attribute"` reference.
Already adaptive/dependency-instrumented callables are skipped rather than wrapped a
second time.

Each `LightweightDependencySlot` retains the module, attribute name, original callable,
wrapper, adaptive controller, and stable target ID. `DependencyInstrumentation.restore()`
restores only attributes still owned by its wrapper, so it does not overwrite a later
application monkey patch. Dependency slots remain repair-disabled: they can escalate
from LIGHTWEIGHT to BEHAVIOR and contribute evidence about a failing application path,
but Caretaker does not generate replacement source for Python/third-party dependency
functions themselves.

`prepare_guard=True` pre-registers the original callable with Guard for post-load code
identity and inspection. Dependency preparation deliberately does not add the callable
to Guard's periodic-inspection scheduler, request a Guard research lease, or cause every
dependency call to be observed. The lightweight/behavior sampling policy remains the gate for per-call Guard
observation. For this model, configure Guard with
`CollectorPolicy(unattributed_events=False)` so unrelated process-wide CPython audit
events cannot bypass the adaptive sampler merely because the global audit hook is
installed.

Module patching affects future lookups such as `module.function(...)`. A callable copied
before initialization with `from module import function` cannot be rewritten by changing
the module attribute, which is another reason to perform dependency instrumentation as
early as practical during program initialization.

Adaptive state is keyed by target ID and function code hash. Re-decoration with new
code, or replacement of the live function `__code__`, starts a new adaptive generation
and resets the sampling counter rather than inheriting escalation or sampling state
from older code. Persisted adaptive state is additionally bound to the effective
lightweight-policy fingerprint and authority fingerprint. State written under an older
authority/policy generation is not allowed to restore escalation, repair eligibility,
or acceptance counters under a new one. An already-active repair candidate remains
owned by `FunctionSlot`/`RepairEngine`; only its adaptive pre-repair trigger/evidence
state is discarded when authority changes.

Rolling threshold state is persisted only on noteworthy events; healthy LIGHTWEIGHT
calls do not perform Caretaker adaptive-state file writes.
Promoted-state progress is also checkpointed in batches rather than fsynced after every
successful execution. Threshold violations and lifecycle transitions remain immediate
durable writes; routine behavior/acceptance progress is checkpointed periodically.

When soft timing is disabled, the ordinary lightweight wrapper does not read a
performance clock merely to support unused timing policy.

## Repair decorator

```python
@repair(
    policy=policy,
    engine=engine,
    target_id="optional-stable-id",
    cases=(...),
    tags=frozenset({...}),
    integrity_class=IntegrityClass.ORDINARY,
)
def function(...):
    ...
```

The wrapper preserves function metadata with `functools.wraps` and dispatches through a stable `FunctionSlot`.

## Convenience decorators

### `repair_on_exception`

Configures one exception trigger and optional repaired-call retries.

```python
@repair_on_exception(
    exceptions=(ValueError, KeyError),
    retry=1,
    replay_safety=ReplaySafety.IDEMPOTENT,
)
def load(...):
    ...
```

### `repair_on_invalid_output`

```python
@repair_on_invalid_output(
    validate_result,
    retry=1,
    replay_safety=ReplaySafety.PURE,
)
def calculate(...):
    ...
```

The validator can return a Boolean or `ValidationResult`.

### `repair_on_soft_timeout`

```python
@repair_on_soft_timeout(0.100)
def operation(...):
    ...
```

This is an elapsed-time contract: the original invocation must finish before the violation can be detected. It does not interrupt a running function. `repair_on_timeout` remains as a deprecated compatibility alias.

### `repair_and_retry`

A convenience form of exception repair with one retry by default. Replay safety must now be declared explicitly; the default is `ReplaySafety.UNKNOWN`, which is rejected when retry is enabled.

### `diagnose_only`

Captures incidents and evidence but does not generate or activate a repair.

### `observe_only`

Evaluates configured output/timing contracts and records incidents but does not generate or activate a repair.

## Unsupported callable forms

This alpha rejects or does not normalize:

- closures and nested functions;
- coroutines and generators;
- built-in and extension functions;
- unsupported descriptor forms without a callable getter.

These limitations are detected through target-support assessment where possible.

## Guard-aware decorators

All policy-driven decorators can bind a function to Guard through `RepairPolicy.guard`.

```python
from caretaker import (
    CandidateGuardPolicy,
    GuardBinding,
    RepairPolicy,
    repair,
)

policy = RepairPolicy(
    guard=GuardBinding(
        enabled=True,
        observe_network=True,
        observe_filesystem=True,
        include_guard_context_in_repair=True,
        validate_candidate_behavior=True,
        monitor_during_probation=True,
    ),
    candidate_guard=CandidateGuardPolicy(
        allow_new_capabilities=False,
        rollback_on_significant_deviation=True,
    ),
)

@repair(policy=policy, engine=engine)
def transform(path: str):
    ...
```

The wrapper establishes target and call correlation before invoking the active `FunctionSlot` implementation. Guard records start/completion events, resource activity emitted by hooks, execution timing, and a candidate-probation inspection where appropriate.

The decorator receives only the Guard facade through `RepairEngine`. It does not expose raw audit-hook internals to application or generated code.

## Logging decorator

```python
@logged(
    timing=True,
    exceptions=True,
    arguments=False,
    result=False,
    mask=None,
    baseline_dimensions=(),
    population_key=None,
)
def function(...):
    ...
```

`@logged` uses the same call context as Guard and Repair. It can record start, completion, failure, elapsed time, population designator, and masked argument/result evidence.

## Masking

Every application-facing Caretaker decorator supports an optional masking function. Caretaker maintains three views:

1. the execution view containing original values;
2. a trusted local validation view containing original values where explicitly permitted; and
3. the evidence view containing masked values for logging, persistence, Guard, and LLM analysis.

A `MaskingResult` may preserve structural metadata such as length, character class, checksum validity, or format while replacing the secret itself. Masking occurs before values enter an IPC queue or persistent store.

A masking failure follows operator policy and must never silently fall back to writing the unmasked value.

## Baseline populations

`baseline_dimensions` names bound arguments whose masked values distinguish analytical populations. `population_key` supplies a more general callable for classification, such as an amount range or workload type.

The decorator author defines useful populations; the operator decides whether generated baselines are accepted.
