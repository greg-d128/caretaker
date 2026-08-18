# Migration to Caretaker 0.6.0a1

## Compatibility

Most 0.5 logging, Repair, Guard, Integrity, and authority APIs remain available. Caretaker 0.6 adds adaptive lightweight instrumentation, persistent behavior statistics/snapshots, runtime-artifact signing, and selectable validation-isolation backends. These features remain policy-controlled and do not silently broaden automatic repair authority. The compatibility exceptions and deactivated policy semantics below require operator review.

## Policy truthfulness changes

The 0.6 development tree now validates public policy semantics rather than silently accepting settings that are only declarative. A machine-reviewed policy-surface fingerprint in `caretaker.policy_semantics` forces explicit review whenever a public policy dataclass field, type, or default changes. See `docs/POLICY_SEMANTICS.md`.

Several previously implementation-looking defaults are now inactive because their runtime behavior is intentionally not implemented:

- `ContextPolicy.previous_incidents`: `3` -> `0`; nonzero is rejected.
- `RepairLimits.structural_review_after_repairs`: `5` -> `None`; non-`None` is rejected.
- `StabilityPolicy.oscillation_window_incidents`: `20` -> `None`; non-`None` is rejected.
- `StabilityPolicy.require_regression_replay_before_reactivation`: `True` -> `False`; `True` is rejected until replay is implemented.
- Guard `RetentionPolicy.raw_event_seconds` / `aggregate_seconds`: configured durations -> `None`; non-`None` is rejected until durable time-based pruning exists.
- `PeriodicInspectionPolicy.execution_window`: `100` -> `None`; non-`None` is rejected.
- `PeriodicInspectionPolicy.compare_behavior`: `True` -> `False`; periodic behavior comparison is not a separate implemented scheduler control. Normal Guard behavior comparison remains active through observed behavior windows.

`GuardMode.DISABLED` is now a true off state. Legacy `RESEARCH`, `FORENSIC`, and `ENFORCE` names are compatibility aliases for audit observation rather than stronger enforcement claims.

Repair LLM context controls now govern the actual provider payload, including a combined `maximum_context_characters` budget. Signed behavior artifacts also enforce the minimum integrity required by the active signing policy and cannot be accepted after signature stripping.

## Adaptive instrumentation

New `lightweight.*` policy controls govern low-cost detection, behavior sampling, evidence-gated escalation, and policy-controlled demotion. The intended repair lifecycle is:

```text
LIGHTWEIGHT -> BEHAVIOR -> REPAIR -> BEHAVIOR -> VALIDATION -> LONG_TERM_ACCEPTANCE
```

Instrumentation intensity and repair lifecycle are distinct internally. Older strict profiles created for policy surface 1 must be reviewed/continued for policy surface 2 before they can claim complete coverage of adaptive instrumentation, persistent behavior snapshots, validation-isolation requirements, and signing-identity retention.

## Behavior snapshots and Guard restart

Behavior statistics are accumulated online in bounded active snapshots. Code identity or monitoring-configuration changes seal the active generation. Sealed snapshots are immutable; accepted Guard baselines reference a compatible sealed snapshot and can be reconstructed after restart without replaying the complete raw event history.

When runtime artifact signing is enabled, sealed behavior snapshots and behavior archives use the same runtime signing service as secure event artifacts. Ephemeral signing publishes key identities/transitions into a separately retained Signing Identity Journal; configured external signing authority is used without silent fallback to ephemeral keys.

The operator list now presents one analytical row per subject/generation rather
than one row per stored epoch. Archiving that row archives every active snapshot
in the generation and requires an operator reason. Permanent deletion is no
longer exposed by the console.

## Operator terminology and adaptive state

The console uses outcome-oriented labels such as **Activate replacement**,
**Compare with reference**, **End temporary change**, and **Analyze with local
AI**. Overview exposes FunctionSlot role and adaptive observation independently:
fully managed `@caretaker` targets report `not adaptive`, while lightweight
dependency boundaries report normal or escalated Behavior/Repair observation.
Existing control command identifiers and Python APIs are unchanged.

## Offline release signing

The ordinary signing-station workflow no longer requires typing both a key slot
and its fingerprint. `root.json` is authoritative for that mapping:

```bash
make sign-release-set KEY_SLOT=a
```

Use `make signing-status` to identify missing publication material and `make
signing-bundle PUBLIC_KEY_DIR=<directory>` to create a minimal station directory.
The older `sign`, `sign-all`, `manifests`, and `verify-all` Make targets remain as
compatibility aliases or advanced interfaces; new operator documentation uses
`sign-file`, `sign-station-bundle`, `generate-manifests`, and
`verify-publication` to make their scope explicit.

## Validation isolation

Validation policy now declares a minimum isolation capability:

```text
PROCESS < CONTAINER < VM < EXTERNAL
```

The built-in backends are the existing subprocess worker (`PROCESS`), rootless Podman (`CONTAINER`), and Multipass (`VM`). If the configured backend cannot satisfy the minimum isolation level, Caretaker follows the explicit backend-unavailable policy. `REQUIRE_OPERATOR_APPROVAL` is currently an explicit override path that can activate a candidate without the requested isolation; it records the missing backend but does not prove that required validation occurred. See `docs/ISOLATED_EXECUTION.md` for provisioning and trust-boundary details.

## Explicitly deferred work

Supervisor-owned multiprocess aggregation of adaptive counters, import-hook dependency instrumentation, and graduation of accepted runtime repairs into repository/source patches remain explicit future work. See `docs/FUTURE_WORK.md`.

---

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
    path="/etc/caretaker/your-application.toml",
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
