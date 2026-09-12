# Select a built-in profile

## Task

Choose a packaged framework authority profile for supervised startup.

## Audience

Operators and programmers preparing a deployment.

## Status

Environment-dependent.

## Supported package versions

Caretaker `0.6.5a0`, contract line `caretaker-0.6.5`.

## Use when

You want a named baseline for observe-only, balanced, or high-assurance startup.

## Do not use when

You need an organization-specific authority stack, or when you cannot provide
the facilities required by a strict profile.

## Prerequisites

Install the wheel and review profile scope. Production profile selection needs
the packaged signatures and, for independent bootstrap, all three trusted
primary fingerprints.

## Minimal command or code

```console
caretaker-profile list
caretaker-run --profile balanced my_application
```

## Required configuration

Use `observe-only`, `balanced`, or `high-assurance` for production choices.
`sandbox` is unsigned and non-production. `--profile` cannot be combined with
`--authority-stack`. Pinning an exact profile fingerprint is preferred where a
deployment layer is used.

## Expected result

Caretaker verifies the selected production profile before importing the
application and reports its authority/policy-surface coverage.

## Verification

Run `caretaker-profile show profile.json`, `coverage profile.json`, or
`caretaker-profile coverage profile.json --strict` as appropriate. Confirm the
lineage, revision, fingerprint, and tested Caretaker version.

## Common failures

Missing signatures, wrong trusted fingerprints, incomplete policy-surface
coverage, or unavailable VM/external facilities. Do not replace these with a
different signed profile without reviewing selection binding.

## Security and scope limitations

A profile signature proves provenance, not that this deployment selected that
profile. An unsigned sandbox profile is not production assurance.

## Related tasks

`tasks.supervised-startup`, `tasks.verify-integrity`, `tasks.troubleshoot-startup`.

## Canonical documentation

`docs/PROFILES.md` and `profiles/README.md`.
