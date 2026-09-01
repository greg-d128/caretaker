# Caretaker public API inventory

This document classifies the names exported by `caretaker`. The authoritative
membership list remains `src/caretaker/__init__.py::__all__`; every name in
that list is intentionally importable from the package root. This document
does not remove, rename, or deprecate an export.

## Stability classes

### Stable integration

These are the application-facing entry points intended for ordinary Caretaker
integration:

- `caretaker`, `repair`, `repair_and_retry`, `repair_on_exception`,
  `repair_on_invalid_output`, `repair_on_soft_timeout`, and
  `repair_on_timeout`;
- `configure_default_engine`, `get_default_engine`, `configure_logging`,
  `configure_from_operator_policy`, and `get_logger`;
- `RepairEngine`, `RepairResolution`, `ResolutionKind`, `RepairPolicy`, and
  the policy/domain/validation value objects used to configure them;
- `IncidentCapsule`, `IncidentCapsuleStore`, `IncidentCapsulePolicy`,
  `CommunicationRecord`, and the incident-capsule validation helpers;
- `OperationContext` and `ProvenanceEnvelope` for immutable operation and
  common provenance projections;
- `ApplicationRuntimeSupervisor`, `ApplicationLocalQueueTransport`, and
  `ApplicationTransportError`;
- the primary observation, behavior, shadow-execution, and store interfaces
  used by an application-scoped deployment.

Stable does not mean that serialized records may change without migration.
Public classes that carry signed or persisted data retain their existing
schema/version and compatibility rules.

### Advanced application capabilities

These exports are supported application-scoped capabilities, but should be
adopted deliberately because they expose more policy, evidence, or operational
surface:

- adaptive instrumentation and aggregation, including `lightweight`,
  `AdaptiveAggregationPolicy`, `AdaptiveObservationBatcher`, queue stores,
  population comparison, and transition verification;
- Guard, runtime inspection, baselines, candidate assessment, and the bounded
  LLM assessment/provider interfaces;
- incident-capsule assistance, `LLMRequestGate`, `LLMUsagePolicy`, and
  communication-draft policy helpers;
- rollout, recovery, worker authority/acceptance, comparison-worker evidence,
  post-mortem, and packet transport types and helpers;
- integrity verification, signed publication monitoring, isolated replay, and
  regression-corpus interfaces;
- logging policy, audit delivery, monitoring streams, metrics providers, and
  system-collection policy.

Advanced exports remain application-scoped. They do not imply Host Caretaker,
Infrastructure Caretaker, fleet authority, hostile-code containment, or an
external trust anchor.

### Compatibility surface

These names remain exported to avoid breaking existing integrations while
implementation ownership is consolidated:

- `CaretakerApplicationSupervisor`;
- logging-package `WorkRegistry`, `Watchdog`, `WorkerRegistry`, and
  `ApplicationWorkerLifecycle` imports;
- historical logging configuration and baseline names retained by
  `caretaker.logging`.

Compatibility names are not a promise that new functionality belongs in the
logging module. New application-runtime integrations should use
`ApplicationRuntimeSupervisor` and the runtime-owned interfaces documented in
`docs/LOGGING_ARCHITECTURE.md`.

### Internal and module-local names

Names not present in the package root `__all__`, including private helpers and
module-local constants, are implementation details. Consumers must not infer
stability from an incidental module import. Their presence, signature, and
location may change without a package-root compatibility guarantee.

## Inventory and compatibility rule

The package root `__all__` is the machine-readable inventory for this release.
Before changing it:

1. search the repository and sibling consumers for the name;
2. classify the name here and in release notes;
3. preserve a compatibility alias or provide a migration path where needed;
4. do not alter signed or persisted bytes solely to improve naming; and
5. add an API-compatibility test for the intended change.

The provenance-envelope proposal in `docs/FUTURE_WORK.md` remains separate
from this classification. Existing family-specific provenance fields and
signed bytes must not be rewritten until legacy readers and compatibility
fixtures exist.
