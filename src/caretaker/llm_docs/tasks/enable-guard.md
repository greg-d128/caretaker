# Enable Guard observation

## Task

Enable application-scoped Guard observation and deviation reporting.

## Audience

Programmers and operators who understand the application's resource behavior.

## Status

Experimental.

## Supported package versions

Caretaker `0.6.5`, contract line `caretaker-0.6.5`.

## Use when

You need selected import, filesystem, network, subprocess, runtime-code, or
behavior-baseline evidence around application targets.

## Do not use when

You require a host security boundary, automatic quarantine of arbitrary native
code, or a baseline that has not received operator review.

## Prerequisites

Configure logging/evidence first. Identify target module patterns, function
patterns, workload, and the permissions of the application process.

## Minimal command or code

```python
from caretaker import GuardEngine, GuardPolicy, GuardMode

policy = GuardPolicy(
    enabled=True,
    mode=GuardMode.AUDIT,
    observe_imports=True,
    observe_filesystem=True,
)
guard = GuardEngine(policy=policy)
guard.install()
```

## Required configuration

Use `DISABLED`, `LEARN`, or `AUDIT` deliberately. Configure collectors,
sampling, targets, baselines, deviations, and action policy. Automatic baseline
acceptance is false by default; an accepted baseline is an operator action.

## Expected result

Guard records bounded observations and deviations according to policy. LLM
review, when enabled, remains advisory.

## Verification

Inspect Guard status and evidence, then review and accept a baseline only through
the authenticated documented operator workflow.

## Common failures

No target, missing logging capability, unreadable source, stale/incompatible
baseline, or assuming `AUDIT` means prevention.

## Security and scope limitations

Guard observation does not contain native extensions, a compromised interpreter,
or a hostile host. It does not grant Repair or policy authority.

## Related tasks

`tasks.configure-policy`, `tasks.inspect-evidence`, `tasks.configure-repair`.

## Canonical documentation

`docs/GUARD_ARCHITECTURE.md`, `docs/GUARD_POLICIES.md`, and
`docs/POLICY_SEMANTICS.md`.
