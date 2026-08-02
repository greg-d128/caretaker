# Guard introspection

Guard preserves inspection at load time, during selected calls, periodically after load, during candidate probation, and after significant global/system-hook events.

## Load-time inspection

The import loader records a pre-load identity before executing the selected module variant and a post-load identity afterward.

It can highlight:

- unexpected source or loader identity;
- source-hash mismatch;
- additional imports;
- network or DNS activity during import;
- file or directory access during import;
- subprocess creation;
- dynamic code execution;
- functions or classes added at load time.

Import-time side effects receive special significance because normal application work has not yet begun.

## Function inspection

Function fingerprints may include:

- source and bytecode hashes;
- defaults and keyword defaults;
- annotations;
- closure shape where available;
- referenced-global identities;
- active `FunctionSlot` version;
- candidate and repair provenance.

Guard compares current state with the load-time baseline, prior inspection, or candidate-specific reference.

## Module inspection

Module inspection may summarize:

- source file and loader;
- distribution identity;
- functions and classes;
- module globals;
- replaced dependencies;
- source hash;
- newly introduced objects.

This can detect ordinary monkeypatching and runtime replacement of a Python function's `__code__` object.

## Periodic inspection

`PeriodicInspector` stores module names or function resolvers and repeats inspection at configured intervals. Repair targets use a resolver so the currently active `FunctionSlot` implementation is inspected rather than only the original callable.

Periodic inspection does not re-import modules. It compares current runtime state.

## Event-driven inspection

Immediate inspection may be triggered by:

- unhandled exception;
- unraisable exception;
- thread exception;
- integrity mismatch;
- significant behavior deviation;
- new sensitive destination or path;
- unexpected subprocess;
- candidate activation or failure;
- import-route decision.

System hooks capture and record evidence before normal exception propagation. They do not attempt arbitrary stack resurrection.

## Audit-hook limitation

CPython audit hooks installed with `sys.addaudithook` cannot be unregistered. `GuardEngine.close()` disables Caretaker's collector, but the dormant callback remains in the interpreter. Install one long-lived Guard engine rather than repeatedly creating and discarding engines.

## Native-code limitation

Native extensions and `ctypes` may operate below Python-level observability. A future stronger implementation may correlate Python evidence with interpreter-native hooks, operating-system tracing, containers, seccomp, Landlock, eBPF, or hardware-backed evidence.
