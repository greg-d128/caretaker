# Inspect evidence

## Task

Review bounded Caretaker evidence for an application incident.

## Audience

Programmers and operators.

## Status

Implemented.

## Supported package versions

Caretaker `0.6.5`, contract line `caretaker-0.6.5`.

## Use when

You need logs, Guard deviations, behavior summaries, Repair state, or an
advisory hypothesis for a bounded incident.

## Do not use when

Treating an LLM assessment as root-cause proof, or exporting raw sensitive data
without reviewing masking and retention policy.

## Prerequisites

Have the configured Caretaker data directory and appropriate local permissions.
For live inspection, start the supervised application first.

## Minimal command or code

```console
caretaker-console --data-directory /var/lib/invoice-service/caretaker
caretaker-logging interrogate --segments /var/lib/invoice-service/caretaker/application/events --objective "explain the latency increase"
```

Add `--ollama-model MODEL` only for a bounded advisory assessment.

## Required configuration

Configure retention, masking, attachments, and logging integrity. Interrogation
receives bounded redacted summaries; it does not need or receive the full raw
corpus by default.

## Expected result

The console and commands show evidence scope, freshness, integrity, and
omissions. Reports and hypotheses remain separate from source evidence.

## Verification

Check the active policy, event/attachment references, record integrity, and
correlations. Validate any operational conclusion independently.

## Common failures

Wrong data directory, absent control socket, rotated/retained evidence, or an
unavailable local LLM provider. Preserve explicit unavailable status.

## Security and scope limitations

Evidence is application-scoped. Local hashes can be rewritten with local data;
external replication is recommended for higher assurance. LLM output cannot
approve Repair or change policy.

## Related tasks

`tasks.logging-quickstart`, `tasks.enable-guard`, `tasks.verify-integrity`.

## Canonical documentation

`README.md`, `docs/ADMIN_CONTROL.md`, and `docs/LOGGING_INTERROGATION.md`.
