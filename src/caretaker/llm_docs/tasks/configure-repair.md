# Configure policy-constrained Repair

## Task

Construct a Repair engine that validates candidate function replacements before
any policy-permitted activation.

## Audience

Programmers and operators enabling experimental self-repair.

## Status

Experimental.

## Supported package versions

Caretaker `0.6.5a0`, contract line `caretaker-0.6.5`.

## Use when

You have a stable function contract, tests, bounded evidence, and an external
recovery path for a failed candidate.

## Do not use when

You need Caretaker to repair itself, deploy signed release code automatically,
or activate a candidate without the requested validation tier.

## Prerequisites

Use `RepairPolicy` and `RepairEngine`; provide validators/tests and select an
available validation backend. Start with operator approval.

## Minimal command or code

```python
from caretaker import RepairEngine, RepairPolicy

policy = RepairPolicy()
engine = RepairEngine()
```

Pass the engine and policy to `repair(...)`. Use `RepairPolicy.automatic(...)`
only after explicitly reviewing the authority decision and deployment risks.

## Required configuration

Set triggers, context privacy, candidate selection, validation, observation,
activation, stability, and recovery. `ValidationPolicy` can require PROCESS,
CONTAINER, VM, or EXTERNAL isolation. Set `require_resource_control=True` only
when the backend can externally enforce resource limits.

## Expected result

Candidates are proposed, checked, and observed under policy. Failed validation
cannot authorize Repair; unavailable backends follow the configured unavailable
action.

## Verification

Run registered tests and inspect `ValidationResult`, evidence, policy snapshot,
authority state, and probation/rollback outcome before accepting a repair.

## Common failures

Unsupported policy semantics, missing tests, insufficient isolation, provider
output that fails validation, or an operator action without required review.

## Security and scope limitations

Generated repairs are ephemeral and are not signed release code. Side effects
outside captured state need application or isolation boundaries.

## Related tasks

`tasks.decorate-a-function`, `tasks.configure-policy`, `tasks.inspect-evidence`.

## Canonical documentation

`docs/POLICIES.md`, `docs/VALIDATION_AND_SECURITY.md`, and
`docs/REPAIR_ROLLOUT.md`.
