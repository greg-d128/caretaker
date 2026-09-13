# Troubleshoot startup

## Task

Diagnose a failed or degraded Caretaker startup without weakening policy.

## Audience

Programmers and operators.

## Status

Implemented.

## Supported package versions

Caretaker `0.6.5`, contract line `caretaker-0.6.5`.

## Use when

`caretaker-run` exits nonzero, reports unavailable capability, or starts with a
degraded evidence or authority state.

## Do not use when

Suppressing a fail-closed validation/integrity error, replacing a required
backend with a weaker one, or treating a warning as proof of containment.

## Prerequisites

Capture the exact command, package version, Python version, policy/profile name,
data-directory permissions, and relevant external-tool versions.

## Minimal command or code

```console
caretaker-docs list
caretaker-docs show reference.common-errors
caretaker-profile coverage profile.json --strict
```

Then rerun the supervised command with its documented policy and application
module.

## Required configuration

Ensure the module is importable, the data directory is writable, profile trust
inputs are independently known, and the selected validation backend meets
`minimum_isolation`. Resource control is a capability, not a best-effort flag.

## Expected result

The failure remains explicit: unsupported semantics fail policy validation;
missing facilities use the configured unavailable action; integrity failures do
not silently downgrade.

## Verification

Check control-socket readiness, worker states, effective policy, profile
coverage, and cleanup of endpoints after normal or failed startup.

## Common failures

Unknown module, invalid setting, incomplete profile surface, missing signatures,
unwritable root, unavailable VM/Podman/GnuPG, or overlong socket path.

## Security and scope limitations

Do not infer host-level guarantees from a successful application startup. An
unsigned development wheel remains unsigned development material.

## Related tasks

`tasks.supervised-startup`, `tasks.select-a-profile`, `tasks.verify-integrity`.

## Canonical documentation

`README.md`, `docs/POLICY_SEMANTICS.md`, `docs/PROFILES.md`, and
`docs/INDEPENDENT_VALIDATION.md`.
