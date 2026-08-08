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

### `repair_on_timeout`

```python
@repair_on_timeout(0.100)
def operation(...):
    ...
```

The current implementation is a soft timeout: the original invocation must finish before the elapsed-time violation can be detected.

### `repair_and_retry`

A convenience form of exception repair with one retry by default.

### `diagnose_only`

Captures incidents and evidence but does not generate or activate a repair.

### `observe_only`

Evaluates configured output/timing contracts and records incidents but does not generate or activate a repair.

## Unsupported callable forms

This alpha rejects or does not normalize:

- closures and nested functions;
- coroutines and generators;
- built-in and extension functions;
- classmethod/staticmethod descriptor orderings;
- properties.

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
