# Configure policy

## Task

Create an immutable, policy-constrained Repair configuration.

## Audience

Programmers and operators responsible for application behavior.

## Status

Implemented.

## Supported package versions

Caretaker `0.6.5`, contract line `caretaker-0.6.5`.

## Use when

Choosing triggers, validation, context privacy, retries, observation, or
authority for a Repair integration.

## Do not use when

Assuming that serialization or a valid signature proves a setting is enforced,
or using policy as a substitute for independent recovery.

## Prerequisites

Define the function's correctness contract, acceptable side effects, recovery
path, and available validation backend.

## Minimal command or code

```python
from caretaker import RepairPolicy, ValidationPolicy, ValidationIsolationLevel

policy = RepairPolicy(
    validation=ValidationPolicy(
        minimum_isolation=ValidationIsolationLevel.PROCESS,
        allow_network=False,
        allow_subprocesses=False,
        allow_filesystem_writes=False,
    )
)
```

## Required configuration

Review `RepairPolicy` sections for state, retry, validation, context, limits,
stability, integrity, recovery, rollout, logging, and Guard bindings. Keep
`authority=REQUIRE_OPERATOR_APPROVAL` unless an explicit authority decision
supports another mode.

## Expected result

The effective policy rejects unsupported requests before the affected subsystem
starts. Its canonical snapshot has a fingerprint and human-readable meaning.

## Verification

Call documented policy validation, run behavioral tests for changed settings,
and inspect the effective policy/audit record. A requested backend shortfall is
handled by `backend_unavailable_action`.

## Common failures

Requesting reserved semantics, setting an invalid enum/value, or expecting
operator approval to override required isolation.

## Security and scope limitations

Policy expresses constraints; it cannot create authority, contain a hostile
interpreter, or make LLM output authoritative.

## Related tasks

`tasks.configure-repair`, `tasks.enable-guard`, `tasks.select-a-profile`.

## Canonical documentation

`docs/POLICIES.md`, `docs/POLICY_SEMANTICS.md`, and `docs/VALIDATION_AND_SECURITY.md`.
