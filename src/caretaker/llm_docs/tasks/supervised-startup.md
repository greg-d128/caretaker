# Start a supervised application

## Task

Start Caretaker before an application module loads.

## Audience

Programmers and operators deploying one application or service.

## Status

Implemented.

## Supported package versions

Caretaker `0.6.5`, contract line `caretaker-0.6.5`.

## Use when

You need import-time observation, module routing, a local control socket, or
supervisor-managed evidence.

## Do not use when

You need a machine-wide daemon, cross-host orchestration, or automatic process
management outside the application process tree.

## Prerequisites

The application must be importable from the working environment. Prepare an
operator policy and ensure its data directory is writable.

## Minimal command or code

```console
caretaker-run --policy /etc/caretaker/invoice-service.toml invoice_service
```

The module is the final positional application target. `python -m caretaker.run`
is the equivalent documented entry point.

## Required configuration

Use an application ID and logging directory. Add `--profile balanced` only when
the packaged profile and its trust bootstrap are appropriate; `--profile` and
`--authority-stack` are mutually exclusive.

## Expected result

Caretaker starts before the application import, supervises its application
scope, and exposes authenticated local events/control sockets under the run
directory. Normal application exit cleans up those endpoints.

## Verification

Query the local control socket with the documented logging control command or
attach `caretaker-console`. Record worker readiness and the application result.

## Common failures

An unimportable module, missing policy, unavailable profile/backend, or a socket
path/permission error returns nonzero. Startup does not silently grant a higher
authority or isolation tier.

## Security and scope limitations

The supervisor is application-scoped and does not require superuser privileges.
Its control protocol does not accept shell commands, Python, or arbitrary paths.

## Related tasks

`tasks.select-a-profile`, `tasks.logging-quickstart`, `tasks.troubleshoot-startup`.

## Canonical documentation

`README.md`, `docs/RUNTIME_CONTROL_PLANE.md`, and `docs/INDEPENDENT_VALIDATION.md`.
