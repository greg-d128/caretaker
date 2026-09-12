# Terminology

## Task

Use Caretaker terms consistently when writing code, issues, or prompts.

## Audience

Programmers and coding LLMs.

## Status

Implemented vocabulary.

## Supported package versions

Caretaker `0.6.5a0`, contract line `caretaker-0.6.5`.

## Use when

Selecting a public API or interpreting a status.

## Do not use when

Inferring support from a module-local name or from a roadmap item.

## Prerequisites

None.

## Minimal command or code

Use `caretaker-docs show global.status-vocabulary` for status meanings and
`caretaker-docs show reference.public-api` for the export inventory.

## Required configuration

None.

## Expected result

Logging records application evidence. Guard observes configured behavior and
reports deviations. Repair proposes, validates, activates, observes, and may
roll back function replacements under policy. Integrity verifies signed roots,
manifests, and artifact bytes. A profile is a named framework authority layer;
it does not create a new authority tier.

## Verification

Confirm a name is in the package-root `__all__` inventory before describing it
as a public root API.

## Common failures

Calling an advisory assessment authority, calling a profile a certificate, or
calling a successful hash check proof of first-use authenticity.

## Security and scope limitations

Policy and authority decide what may happen. Evidence, LLM reasoning, and
documentation do not grant authority.

## Related tasks

`global.safety-boundaries`, `tasks.configure-policy`, `tasks.select-a-profile`.

## Canonical documentation

`docs/PUBLIC_API.md`, `docs/PROFILES.md`, and `docs/POLICY_SEMANTICS.md`.
