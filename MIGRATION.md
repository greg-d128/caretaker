# Migration to Caretaker 0.5.0a1

## Compatibility

The Repair, Guard, and Integrity APIs from 0.4.0a1 remain available. Existing applications do not begin logging automatically merely by importing Caretaker.

## New preferred startup

For load-time Guard visibility and multi-process logging, replace:

```bash
python -m your_application
```

with:

```bash
python -m caretaker.run --policy /etc/caretaker/your-application.toml your_application
```

Direct runtime configuration remains supported, but produces a warning that import-time activity before configuration was not observed.

## Operator policy

Logging policy is deliberately not covered by Caretaker release signatures. Store it in an operator-controlled path that is not writable by the application account where practical.

Run:

```bash
caretaker-logging policy explain --file /etc/caretaker/your-application.toml
caretaker-logging policy effective --file /etc/caretaker/your-application.toml
```

before deployment to review the canonical policy and required higher-mode overrides.

## Logging handlers

Existing standard logging can be connected explicitly:

```python
from caretaker.logging import configure_from_operator_policy, CaretakerLogHandler

runtime = configure_from_operator_policy(
    application_id="your-application",
    policy_path="/etc/caretaker/your-application.toml",
)
root_logger.addHandler(CaretakerLogHandler(runtime))
```

Supervised children automatically use the local event socket through the bootstrap path.

## Repair policy changes

`RepairPolicy` now includes:

- `logging: LoggingBinding`
- `authority: RepairAuthority`

The default preserves standing automatic eligible repair for compatibility. Incident-driven deployments should normally select `REQUIRE_OPERATOR_APPROVAL`.

All repair decorators accept `mask=`. Masked values enter persistent evidence and LLM requests; original values remain local to the call and trusted validators.

## Baselines

Logging baselines are separate from Guard behavior baselines. They may coexist and refer to one another. Application code cannot accept a baseline. Use the CLI or local administrative interface, including from an operator-controlled scheduled task.

## Runtime signing

The default remains `HASH_CHAINED` and requires no optional dependency. To enable ephemeral signing:

```bash
python -m pip install 'Caretaker[signing]'
```

```toml
[logging.signing]
mode = "ephemeral_signed"
key_epoch_maximum_seconds = 86400
```

Export or externally witness the runtime public-key fingerprint when stronger provenance is required. A self-recorded public key cannot by itself prevent wholesale identity replacement.

## Storage layout

New data is written below the policy directory:

```text
application/events
application/event-manifests
application/attachments
application/attachment-manifests
system/host
system/processes
index
run
baselines
```

SQLite is a derived index. Back up segment, attachment, system, manifest, and accepted baseline files as the authoritative corpus.

## Caretaker self-repair

Generated repair of `caretaker.*` is now unconditionally rejected. Operational recovery for Caretaker components is restart, degradation, external upgrade, or application termination according to policy.
