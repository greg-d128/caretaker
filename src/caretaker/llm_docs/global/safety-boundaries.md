# Safety boundaries

## Task

Keep an integration inside Caretaker's authority and validation model.

## Audience

Programmers, operators, and coding LLMs.

## Status

Implemented safety contract.

## Supported package versions

Caretaker `0.6.5a0`, contract line `caretaker-0.6.5`.

## Use when

Designing policy, interpreting a provider result, or reviewing a proposed
Repair workflow.

## Do not use when

Using a convincing diagnosis to bypass validation, policy, or signed-artifact
checks.

## Prerequisites

Identify the application authority owner, policy, validation tier, and recovery
path before enabling consequential actions.

## Minimal command or code

Begin with `RepairPolicy()` and the default operator-approval authority. Raise
autonomy only through documented policy and authority configuration.

## Required configuration

Set explicit `ValidationPolicy` requirements for candidate checks and isolation.
If `minimum_isolation` is stronger than the available backend, choose the
documented unavailable action; approval cannot substitute for required
isolation.

## Expected result

Failed validation remains failed, provider and LLM output remains advisory, and
Repair stays constrained by the effective policy and authority boundary.

## Verification

Inspect validation results, effective policy, authority fingerprints, and the
operator audit evidence before activation.

## Common failures

Treating unsigned development material as trusted; silently falling back from
signed artifacts; or treating a profile signature as proof that this profile
was selected.

## Security and scope limitations

Caretaker cannot grant itself authority and does not create host or
infrastructure authority. Local hashes without an external commitment can be
rewritten with the corpus.

## Related tasks

`tasks.configure-repair`, `tasks.verify-integrity`, `global.scope-and-limitations`.

## Canonical documentation

`AGENTS.md`, `docs/POLICY_SEMANTICS.md`, `docs/INTEGRITY.md`, and
`docs/VALIDATION_AND_SECURITY.md`.
