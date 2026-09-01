# Logging architecture

## Purpose

Caretaker Logging serves two purposes:

1. a lightweight replacement or destination for conventional application logging; and
2. the historical, correlated evidence layer used by Guard, Repair, Research, Forensic, and baseline analysis.

It is intentionally usable without the other subsystems.

## Fast path and analysis path

```text
Fast path                         Analysis path
---------                         -------------
normalize                         query closed segments
mask/redact                       correlate calls and signals
queue or local IPC                detect templates and outliers
append framed record              build baselines
update derived index              compare long-term drift
                                  construct LLM evidence bundle
```

Analysis is never performed synchronously in an ordinary logging call.

The supervised status response exposes bounded logging-path overhead evidence:
submitted and accepted records, drops and write failures, queue depth and
capacity, and flush counts and wall-clock durations. These measurements are
observational only; they are not a complete CPU-cost measurement and do not
change backpressure or policy decisions.

## Multiprocess model

Each application process uses a lightweight emitter. One supervised service owns the event segment writer and SQLite index. Unix-domain sockets preserve local-only deployment and allow the operating-system credential model to authenticate emitters and administrators.

Caretaker treats `<data-directory>/run/*.sock` as logical socket paths. If the absolute pathname would exceed the platform Unix-domain socket limit, only the ephemeral socket is mapped to a deterministic private per-user runtime directory under `$XDG_RUNTIME_DIR` or the system temporary directory. Persistent logs, evidence, indexes, and attachments remain in the configured data directory. Caretaker clients and consoles perform the same mapping automatically.

The application lifecycle controls Caretaker's lifecycle. A supervised
application is launched in a dedicated session/process group. Normal lifecycle
completion follows the application root; policy-directed `STOP_APPLICATION`
shutdown signals and, after a bounded grace period, force-stops that complete
application group without signalling Caretaker or unrelated same-user
processes. Caretaker then exits after flushing complete records where possible.

Application composition enters through `ApplicationRuntimeSupervisor` in the
application package. During the compatibility extraction phase it delegates
to the historical logging supervisor; logging remains an observability
dependency, and this delegation does not add host-level authority.

The application package owns the runtime `WorkRegistry`, `WorkerRegistry`, and
`Watchdog` implementations. The logging package re-exports those classes
temporarily so existing integrations continue to work while
worker admission, health state, control, queue coordination, and shutdown are
extracted in later slices. The
application package also owns adaptive aggregation queue bindings; logging
supervision retains only the compatibility-facing orchestration method. Queue
binding limits and worker identity checks remain application-runtime policy
behavior; this extraction does not grant authority to a queue or worker.

Worker admission and authority verification are implemented by the application
runtime registry. A small logging-package compatibility wrapper preserves the
historical public import and verifier test seam while delegating all lifecycle
state and checks to that registry.

`ApplicationWorkerLifecycle` is also implemented in the application-runtime
package. Its logging import is a compatibility re-export; process creation and
cleanup remain callbacks owned by the embedding application.

The bounded supervisor control-cycle implementation is likewise owned by the
application package. The legacy supervisor method delegates to it, and
`ApplicationRuntimeSupervisor.run_control_cycle()` exposes the runtime seam
directly; expiry and cycle callbacks remain application-owned and cannot grant
authority.

Failure evidence capture is likewise application-runtime behavior: rollback
envelopes, optional diagnostic detail, post-mortem collection, and persistence
are handled by the runtime package before policy-selected recovery actions.

Failed-worker cohort handling is also runtime-owned. The runtime validates the
bounded cohort, persists each rollback envelope under one explicit scope, and
then invokes the existing reconciliation boundary. Recovery handlers remain
application-owned; cohort handling never creates replacement authority or
starts a process by itself.

Expired-worker validation and handoff use the same runtime boundary. The
authoritative supervisor clock, registered process-start identity, and
`UNAUTHORIZED` state are checked before an expired worker enters cohort
recovery; an untrusted or stale snapshot is rejected.

Application monitoring and application-boundary shutdown are also implemented
in the application-runtime package. The legacy logging supervisor delegates to
those functions, and the runtime owner exposes them directly while preserving
the existing process-group boundary and graceful/forced-stop behavior.

## Channels

- `APPLICATION`
- `CARETAKER_INTERNAL`
- `REPAIR`
- `GUARD`
- `INTEGRITY`
- `AUDIT`
- `EMERGENCY`

Channels are independent of Python logger names. Higher-mode evidence does not require changing all application loggers to DEBUG.

## Startup modes

### Supervised

```bash
python -m caretaker.run --policy POLICY MODULE
```

Installs logging and relevant hooks before the application module executes.

### Late attachment

An application calls `configure_from_operator_policy()`. Caretaker records that pre-initialization imports and behavior were not observed and includes the preferred supervised command.

## Policy boundary

The operator policy is unsigned. It controls capture, sampling, storage, rotation, compression, retention, emergency actions, attachments, runtime signing, system collection, interrogation, and baselines.

Caretaker's signed implementation controls the semantics of those options and the minimum evidence requirements of higher modes.

## Failure behavior

Backpressure and storage failure are policy-driven. Possible behavior includes blocking, throttling, sampling, dropping low priorities, emergency synchronous writes, bypassing logging, stopping analysis, or terminating the application.

Guard and Repair receive capability-health information. They may continue in degraded mode or enforce a stricter policy; they do not silently claim full confidence when required evidence is unavailable.


## Worker restart exhaustion

After the configured restart budget is exhausted, the default action is now `DISABLE_COMPONENT` rather than silently continuing in a degraded state. Deployments that prefer availability over evidence completeness can explicitly select `CONTINUE_DEGRADED`.

When `STOP_APPLICATION` is selected, the supervisor records the exhaustion
reason and shutdown outcome, and terminates the dedicated application process
group. This boundary covers descendants that remain in the application's
session; daemonization or double-forking that deliberately escapes the session
requires a stronger isolation backend.
