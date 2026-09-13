# Status vocabulary

## Task

Interpret the status attached to a documentation card.

## Audience

Programmers and coding LLMs.

## Status

Implemented vocabulary.

## Supported package versions

Caretaker `0.6.5`, contract line `caretaker-0.6.5`.

## Use when

Deciding whether a card is suitable evidence for implementation guidance.

## Do not use when

Treating a card status as a runtime health, release-signing, or independent
validation result.

## Prerequisites

Read the card's canonical sources for the detailed claim.

## Minimal command or code

```console
caretaker-docs index --json
```

## Required configuration

None.

## Expected result

`implemented` means documented current behavior or interface. `experimental`
means available but intended for deliberate adoption. `operator-only` means a
human operator action or review is required. `environment-dependent` means
facilities such as a backend, signer, or external tool are required.

`not-guaranteed` describes a limitation or non-security guarantee. `future`
describes planned work and must not be used as current implementation guidance.

## Verification

Check package version, contract line, status, prerequisites, and canonical
sources together.

## Common failures

Confusing an experimental feature with a guarantee, or converting an unavailable
backend into a pass by omission.

## Security and scope limitations

The bundle is a retrieval aid, not an authority source. Unsigned alpha
artifacts remain `UNSIGNED_DEVELOPMENT` in release workflows.

## Related tasks

`global.terminology`, `tasks.select-a-profile`, `tasks.verify-integrity`.

## Canonical documentation

`docs/README.md`, `docs/POLICY_SEMANTICS.md`, and
`docs/RELEASE_CANDIDATE_WORKFLOW.md`.
