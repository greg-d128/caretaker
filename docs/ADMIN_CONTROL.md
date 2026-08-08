# Local administrative control

## Authentication

The control interface uses a Unix-domain socket, filesystem permissions, and peer PID/UID/GID. The application account should not have administrative socket access unless the operator deliberately grants it.

No network listener, password database, arbitrary Python, shell command, or unrestricted path execution is provided.

## Declarative commands

The initial protocol supports status, health, effective-policy inspection, and mode lease acquisition/release. Logging CLI commands also provide offline record, baseline, and interrogation operations.

Every high-impact action should include a reason and is recorded with peer credentials and policy generations.

## Runtime escalation

An administrator can acquire Repair mode for a problem, request proposal or approval-required authority, review validation and testing evidence, deploy an approved candidate, and release the mode. Lease-specific logging overlays are reverted afterward.

## Failure and strict mode

Policy determines whether inability to preserve required evidence continues degraded, disables a component, refuses a mode transition, or terminates the application. There is no silent claim that Guard or Repair is fully operational when a required capability is unavailable.

## Live application runtime inspection

When an application is launched with `caretaker-run`, the supervisor creates a
second same-UID Unix socket for the child application's live Caretaker runtime.
RepairEngine and GuardEngine instances register themselves with a process-local
operator registry. The supervisor proxies declarative `runtime-*` requests to
that child socket.

This makes the operator interface able to inspect live application state rather
than only supervisor/logging state. Exposed information includes:

- registered Repair/Guard targets and active FunctionSlot versions;
- active Repair incidents and candidate validation work;
- repairs awaiting operator approval;
- Guard events, deviations, runtime inspections, decisions, and summaries;
- accepted baselines and configured Repair policies;
- optional Guard LLM assessments when an advisory provider is configured.

Approval/rejection and baseline acceptance remain typed declarative operations.
The runtime socket does not accept arbitrary Python, shell commands, or source
text from the operator console.
