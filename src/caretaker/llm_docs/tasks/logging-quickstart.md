# Start with application logging

## Task

Capture ordinary application logging as bounded Caretaker evidence.

## Audience

Python programmers integrating the logging subsystem.

## Status

Implemented.

## Supported package versions

Caretaker `0.6.5`, contract line `caretaker-0.6.5`.

## Use when

You want evidence without adding Repair or Guard behavior to a function.

## Do not use when

You need host-wide collection, an external log trust anchor, or an automatic
root-cause decision.

## Prerequisites

Install Caretaker and choose an application-owned writable data directory. A
TOML operator policy is recommended for repeatable deployments.

## Minimal command or code

```python
import logging
from caretaker.logging import CaretakerLogHandler, configure_from_operator_policy

runtime = configure_from_operator_policy(
    application_id="invoice-service",
    path="/etc/caretaker/invoice-service.toml",
)
handler = CaretakerLogHandler(runtime)
logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.info("invoice processing started")
```

## Required configuration

Configure `[logging]` with `application_id` and `directory`; configure rotation,
compression, retention, and signing only when their documented facilities are
available. The convenience `get_logger()` form does not replace policy setup.

## Expected result

Records are written to append-only framed segments and indexed in the configured
Caretaker data directory. Large evidence uses bounded attachments.

## Verification

Use the documented `caretaker-logging` commands or the operator console to
inspect status, records, and the effective policy. Keep an external copy for
higher assurance.

## Common failures

Missing policy, unwritable directory, oversized context, or an unavailable
signing provider. A local self-recorded identity is not independent trust.

## Security and scope limitations

Records are application evidence, not proof against a compromised host or
interpreter. Mask sensitive values before evidence leaves the application.

## Related tasks

`tasks.decorate-a-function`, `tasks.inspect-evidence`, `tasks.supervised-startup`.

## Canonical documentation

`README.md`, `docs/LOGGING_ARCHITECTURE.md`, and `docs/LOGGING_POLICY.md`.
