# Future work

## Logging and storage

- Extract the writer, attachment store, and system collector into independently restartable worker processes while preserving the current IPC and evidence contracts.
- Add external `LogSink` implementations and reliable store-and-forward delivery to independent log collection systems.
- Add signed or witnessed public-key anchoring services for ephemeral runtime identities.
- Evaluate a formal forward-secure signature construction beyond epoch key evolution.
- Add Zstandard and MessagePack as optional codecs without changing the standard-library default.
- Add attachment checkpoint binding at every event-segment rotation, not only final graceful closure.
- Add distributed multi-host ordering and clock-quality evidence.
- Add index migrations and faster columnar analytical exports.

## System evidence and metrics

- Integrate the user's advanced lightweight system-metrics provider through `MetricsProvider`.
- Add specialized parsers for collected `/proc` and `/sys` bodies.
- Add process-scoped performance tracing that does not require privilege escalation.
- Add cgroup-aware application process selection.
- Correlate system cycles with Guard windows, calls, incidents, and baseline units of work.

## Baselines and analysis

- Automated operator-owned monthly baseline generation and acceptance workflows.
- Same-month prior-year and rolling annual comparison orchestration.
- Richer distribution-shift, seasonality, and workload-normalization analysis.
- HTML and static-site reports for baseline change and root-cause evidence.
- Persistent log-template identities and cross-version template evolution.
- Causal graph construction that retains supporting and contradicting evidence.

## Guard

- Wider audit-event normalization and platform-specific tests.
- Sensitive-file to outbound-network sequence analysis.
- Persistent aggregation rollups and database migrations.
- Full old-versus-new dependency environment runner.
- Adaptive instrumentation escalation.
- Native-extension and operating-system event attribution.

## Decorators and Repair

- Descriptor-aware classmethod, staticmethod, and property support.
- Async functions, validators, retries, and event-loop hooks.
- Hard timeout modes using subprocess or cooperative cancellation.
- Custom transactional resources such as database savepoints and filesystem transactions.
- Per-call disable, diagnose, and approval contexts.
- Multiple Repair providers and historical model selection.
- Review bundles and persistent source-patch export.
- Function-set, module, and package repair artifacts.

## Stronger isolation and enforcement

- Dedicated unprivileged validation worker.
- Network-denied execution and read-only source mounts.
- CPU, memory, process, and output limits.
- seccomp, Landlock, and namespace experiments.
- Native audit hooks installed before interpreter initialization.

## Integrity

- Verified import loader fully coupled to signed function fingerprints.
- Signed or externally witnessed accepted baseline chronology.
- Fleet aggregation for probabilistic verification.
- Public transparency logs for releases, roots, baselines, and runtime identity anchors.
