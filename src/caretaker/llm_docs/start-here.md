# Start here

## Task

Find the smallest Caretaker programmer document for the job at hand.

## Audience

Programmers and coding LLMs working with an installed Caretaker package.

## Status

Implemented documentation access; this bundle supplements the canonical docs.

## Supported package versions

Caretaker `0.6.5`, contract line `caretaker-0.6.5`.

## Use when

You need a focused reminder about logging, supervised startup, decorators,
policy, profiles, Guard, Repair, evidence, or integrity verification.

## Do not use when

You need a complete architecture, release approval, a security guarantee, or
an answer about a feature not stated in the selected card. Read the canonical
documentation linked by every card for those decisions.

## Prerequisites

Install Caretaker, then use its offline command:

```console
caretaker-docs list
caretaker-docs show tasks.logging-quickstart
caretaker-docs index --json
```

## Minimal command or code

Use `list` to discover cards, `show` for bounded Markdown, and `path` when a
tool needs the installed file path. IDs are exact; source paths are not IDs.

## Required configuration

None for documentation access. Runtime tasks have their own prerequisites.

## Expected result

The command prints package version and contract line, then the selected card.

## Verification

The package validates the index, safe relative paths, unique entries, and
package-version match before serving content.

## Common failures

An unknown, incomplete, ambiguous, or traversal-like ID returns a nonzero
status. A missing resource indicates a broken installation and should not be
worked around by reading the source checkout.

## Security and scope limitations

Documentation is not authority, validation, signing, or evidence. It does not
make unsigned development artifacts trusted and does not expand Caretaker from
application scope to host or infrastructure scope.

## Related tasks

`tasks.logging-quickstart`, `tasks.supervised-startup`, and
`global.scope-and-limitations`.

## Canonical documentation

`README.md`, `docs/README.md`, and `docs/PUBLIC_API.md`.
