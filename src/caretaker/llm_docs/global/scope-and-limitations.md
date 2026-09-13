# Scope and limitations

## Task

Decide whether a proposed Caretaker integration is within the supported scope.

## Audience

Programmers, operators, and coding LLMs.

## Status

Implemented scope statement.

## Supported package versions

Caretaker `0.6.5`, contract line `caretaker-0.6.5`.

## Use when

Choosing an integration boundary or explaining what a result means.

## Do not use when

Treating Caretaker as a machine-wide daemon, host security boundary,
deployment orchestrator, or external trust anchor.

## Prerequisites

Know the application process and the permissions of its account.

## Minimal command or code

Start the application through `caretaker-run` when import-time observation is
needed; otherwise use a documented logging or decorator integration.

## Required configuration

Provide an application-owned policy and writable evidence location. Optional
`/proc` and `/sys` collection remains limited to sources readable by the
application account.

## Expected result

Caretaker observes one application and its process tree. Evidence, Guard state,
and in-memory Repair state remain bounded by configured policy and process or
supervisor scope.

## Verification

Check the effective policy and evidence scope in the operator console or the
documented logging/control commands.

## Common failures

Assuming host-wide coverage, cross-host coordination, automatic deployment, or
Repair of Caretaker itself. Those claims are outside this release.

## Security and scope limitations

Python hooks do not contain native extensions, a compromised interpreter,
kernel access, or a same-user attacker with unrestricted process memory. LLM
output is advisory evidence. Caretaker does not request superuser privileges.

## Related tasks

`tasks.supervised-startup`, `tasks.configure-repair`, `tasks.verify-integrity`.

## Canonical documentation

`README.md`, `ARCHITECTURE.md`, and `docs/FUTURE_WORK.md`.
