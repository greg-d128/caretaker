# Caretaker Bugfix Backlog

This file records confirmed defects and narrowly scoped corrective work intended
for later implementation batches. An entry describes desired behavior, not
implemented behavior. Remove or mark an entry resolved only after the code,
regression tests, and affected documentation are complete.

## Resolved: `caretaker-run` exposes traceback for invalid external signer references

### Classification

- Area: supervised CLI configuration and external runtime signing
- Severity: diagnostic quality and limited information disclosure
- Authority impact: no observed authority bypass
- Current implementation status: resolved
- Release-blocking status: does not block the current Phase 3 lifecycle invariant,
  but should be resolved before describing the CLI as production-polished

### Reproduction

```bash
caretaker-run \
  --external-signer invalid-reference \
  validation_apps.runtime_lifecycle
```

External signer references are required to use `module:attribute` syntax.
Caretaker correctly rejects the malformed reference, exits nonzero, does not
launch the application, and does not accept or downgrade the invalid signer.

The undesirable behavior is that the configuration exception escapes the CLI and
prints a complete Python traceback ending with:

```text
ValueError: external signer must use module:attribute syntax
```

The traceback reveals internal paths, module names, line numbers, and call
structure that are unnecessary for an ordinary configuration error.

### Required behavior

`caretaker-run` should convert external-signer loading and contract-validation
failures into concise command-line errors, for example:

```text
caretaker-run: error: external signer must use module:attribute syntax
```

The command must exit nonzero without printing a Python traceback.

### Recommended implementation

Catch expected external-signer reference, import, attribute-resolution,
construction, and contract-validation exceptions at the CLI boundary in
`caretaker.run.main()` and convert them to the existing argparse-style error
path.

Keep the catch narrow enough that unexpected internal defects remain
distinguishable from user configuration errors. Preserve detailed diagnostic
information only through an explicitly enabled diagnostic channel if the CLI
already provides one; ordinary stderr must remain concise.

### Required regression tests

Add black-box negative CLI tests for:

- a reference without `module:attribute` syntax;
- an empty module or attribute component;
- a nonexistent module;
- a module whose import fails;
- a missing attribute;
- an attribute with the wrong object type;
- a signer missing `public_identity()`;
- a signer missing both `sign_artifact()` and `sign_manifest()`;
- signer construction or contract validation failure;
- an unexpected internal failure, to ensure it is not mislabeled as an ordinary
  user configuration error.

For every expected configuration-error case, assert that:

- the exit status is nonzero;
- stderr contains a concise actionable error;
- stderr does not contain `Traceback (most recent call last)`;
- the target application is not imported or launched;
- no signer is accepted;
- no fallback to an ephemeral or other internal signer occurs;
- no runtime application evidence is created as though startup succeeded.

Also retain positive tests for a valid `module:attribute` signer reference and
for the documented backward-compatible signer contract where applicable.

### Downstream coordination

- Caretaker Validation should retain the observed malformed-reference case and
  update its expected diagnostic after the fix.
- Caretaker Crucible may treat traceback suppression as diagnostic hardening,
  while continuing to test that invalid signer configuration cannot cause signer
  downgrade, application launch, or authority expansion.
- Website documentation requires no feature claim change, but CLI examples and
  production-readiness wording should not imply polished diagnostic behavior
  until this entry is resolved.

## Open: restart exhaustion can orphan application descendants

### Classification

- Area: supervised runtime lifecycle and worker-failure policy
- Severity: high operational assurance failure
- Authority impact: application work can survive outside Caretaker's active
  control and evidence boundary
- Current implementation status: open in the validated 0.6.1 wheel
- Release-blocking status: blocks Caretaker Validation Phase 3 acceptance

### Reproduction

Run `caretaker-run` around an application that creates a long-lived descendant.
Enable system collection with a mandatory source that is unavailable, allow one
collector restart, and configure both collection failure and restart exhaustion
to stop the application:

```toml
[logging.worker_restart]
enabled = true
maximum_restarts = 1
restart_window_seconds = 60
initial_backoff_seconds = 0.05
maximum_backoff_seconds = 0.05
exhaustion_action = "stop_application"

[system_data]
enabled = true
interval_seconds = 0.05
host_sources = ["/path/that-does-not-exist"]
process_sources = []
unavailable_source_action = "stop_application"
failure_action = "stop_application"
```

The supervisor exposes the collector restart count. When the second failure
exhausts the restart budget, `caretaker-run` exits nonzero and removes its
control socket. The supervised application root exits, but its descendant
remains alive.

Caretaker Validation reproduces this independently in `RUN-002` using installed
commands, process IDs, `/proc` liveness, exit status, and socket state. The
validator terminates the orphan during fixture cleanup.

### Required behavior

`STOP_APPLICATION` must stop the complete supervised application boundary. No
application descendant may continue after Caretaker exits because a required
worker exhausted its restart policy.

Shutdown must remain application-scoped and must not acquire host-management or
elevated authority.

### Recommended implementation

Establish and track a dedicated application process group or an equivalent
explicit descendant boundary when launching the bootstrap process. On
failure-policy shutdown:

- terminate the complete boundary gracefully;
- wait for every tracked member to exit;
- escalate termination only within that boundary after a bounded timeout;
- handle descendants created concurrently with shutdown;
- avoid signaling Caretaker itself or unrelated same-UID processes;
- preserve explicit evidence of the exhaustion reason and shutdown outcome.

The process boundary should be created before application code can spawn
children. Process-group reuse, daemonization, double-forking, and PID reuse need
careful treatment; a cgroup-based boundary may be stronger where available, but
must not become a new privilege requirement.

### Required regression tests

Add installed-runtime tests covering:

- a direct child of the application root;
- a grandchild and a descendant created during shutdown;
- graceful descendant exit and forced termination after timeout;
- an already-exited application root with a surviving descendant;
- restart exhaustion for `STOP_APPLICATION`;
- ordinary application completion through the same process boundary;
- proof that unrelated same-UID processes survive;
- control/runtime socket cleanup and nonzero exhaustion exit;
- retained worker-health and exhaustion evidence;
- repeated runs to detect process-group or PID-reuse races.

### Downstream coordination

- Caretaker Validation must rerun `RUN-002` against a newly built wheel and mark
  `findings/0.6.1-restart-exhaustion-orphans-descendant.md` resolved only after
  the complete process tree is gone.
- Caretaker Crucible should add supervisor `SIGKILL`, application `SIGKILL`,
  daemonization/double-fork, and concurrent descendant-creation cases.
- Documentation describing `STOP_APPLICATION` or application-scoped shutdown
  must not imply complete process-tree termination until the fix is validated.
