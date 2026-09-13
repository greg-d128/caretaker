# Decorate a function

## Task

Attach documented Caretaker observation or Repair behavior to a Python function.

## Audience

Python programmers.

## Status

Implemented.

## Supported package versions

Caretaker `0.6.5`, contract line `caretaker-0.6.5`.

## Use when

You need `logged` for evidence, `repair` for an explicitly Repair-oriented
target, or `caretaker` when one function uses several supported capabilities.

## Do not use when

You need to decorate Caretaker's own implementation, grant provider output
authority, or monitor a host boundary.

## Prerequisites

For logging, configure a logging runtime. For Repair, construct or select a
policy and engine that match the function contract.

## Minimal command or code

```python
from caretaker import RepairEngine, RepairPolicy, repair

policy = RepairPolicy()
engine = RepairEngine()

@repair(policy=policy, engine=engine, target_id="payments.authorize")
def authorize(amount: int) -> bool:
    return amount >= 0
```

Use `@logged(...)` for logging-only instrumentation, or `@caretaker(...)` for
the documented umbrella form. Convenience forms include
`repair_on_exception`, `repair_on_invalid_output`, and `repair_on_timeout`.

## Required configuration

Set explicit triggers, validation, authority, and recovery policy before
activating Repair. A stable `target_id` helps correlate evidence.

## Expected result

The function is registered through the configured public policy and engine. The
decorator does not create authority or bypass validation.

## Verification

Run the function's tests, inspect the resulting evidence, and verify validation
and approval state before any activation.

## Common failures

Using a missing engine/policy, an incompatible validator, or a trigger that the
policy rejects. Descriptor behavior such as properties has specific documented
rules.

## Security and scope limitations

Repair changes are temporary in-memory replacements until separately exported,
reviewed, and signed. LLM assessments remain advisory.

## Related tasks

`tasks.configure-policy`, `tasks.configure-repair`, `tasks.logging-quickstart`.

## Canonical documentation

`docs/DECORATORS.md` and `docs/PUBLIC_API.md`.
