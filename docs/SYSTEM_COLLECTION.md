# Application-scoped system-data collection

## Boundary

The collector supports one application and its process tree. It runs with the application account and never invokes `sudo`. Host-wide capture is optional and is appropriate when the machine primarily exists to support the application.

## Process selection

The default selector captures the supervised root PID and descendants. Optional command regular expressions, executable paths, explicit PIDs, exclusions, and future cgroup selection are available.

PID and `/proc/<pid>/stat` start ticks form the stable process identity, avoiding confusion after PID reuse.

## Synchronized cycles

One cycle ID, sequence, UTC timestamp, and process clock value are assigned to all files collected in a cycle. Optional read-start and read-completion offsets retain additional timing without defeating coarse correlation.

## Raw preservation

Source bodies are intentionally stored nearly unchanged beneath a Caretaker header. This supports existing specialized parsers and defers semantic interpretation.

## Output separation

System records live in separate host and per-process trees. They have independent rotation, compression, retention, source selection, failure, and masking policies. Application event records can reference system cycle IDs without duplicating the bodies.

## Privileged sources

Sources unavailable to the application account are recorded as unavailable. `/proc/slabinfo`, machine-wide `perf`, or similar privileged interfaces are not silently escalated. A future provider may add process-scoped performance data without changing the collector contract.

## Process metrics

`ProcessMetricsProvider` is an optional, non-privileged provider for a bounded
snapshot of one process. It reads process-scoped `/proc/<pid>/stat`,
`/status`, and optional `/io` values, and treats unavailable optional sources
as missing samples. `MonitoringStreamWriter.emit_samples()` can publish those
samples through the same bounded, output-only stream contract used for
Caretaker overhead metrics. It never escalates privileges and an absent source
is not evidence that no activity occurred.

Automatic policy-driven metrics correlation remains reserved: enabling
`logging.metrics.enabled` is still rejected until sampling, retention,
redaction, and system-cycle correlation semantics are reviewed.


## Process command lines

Process command lines are no longer persisted by default because arguments commonly contain passwords, tokens, DSNs, and other credentials. Set `redaction.capture_cmdline=True` explicitly to retain them. When enabled, `mask_cmdline` is applied both to raw `/proc/<pid>/cmdline` records and to the persisted process identity summary.
