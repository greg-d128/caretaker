# Failure corpus

Caretaker includes a small reviewed scenario manifest at
[`examples/failure_corpus/manifest.json`](../examples/failure_corpus/manifest.json).
It is a bounded inventory of failure conditions for test planning and
historical evidence review. The manifest currently covers exceptions, timeouts,
invalid output, dependency and configuration changes, resource pressure,
worker failure, failed validation, malicious evidence, and unavailable LLM
services.

## Safety contract

The manifest is metadata only. It contains a human-readable stimulus and the
expected signal, policy action, authority effect, and minimum isolation level;
it contains no Python module, callable, entrypoint, shell command, URL, or
network instruction. Loading it with `FailureCorpus.load()` parses and validates
bounded JSON and never executes a scenario.

```python
from caretaker.failure_corpus import FailureCorpus

corpus = FailureCorpus.load("examples/failure_corpus/manifest.json")
for scenario in corpus.list_summaries(category="worker"):
    print(scenario["scenario_id"], scenario["expected_signal"])
```

A trusted test harness may map a scenario ID to code in its own test suite.
That mapping is outside the manifest and must remain subject to the harness's
normal policy, isolation, authority, and cleanup rules. A corpus declaration is
not proof that its stimulus has been executed, and its expected action is not
an instruction to Caretaker.

For deterministic trusted tests, `FailureCorpusHarness` accepts that mapping
explicitly:

```python
from caretaker.failure_corpus import FailureCorpus, FailureCorpusHarness

corpus = FailureCorpus.load("examples/failure_corpus/manifest.json")
harness = FailureCorpusHarness(
    corpus,
    runners={"exception.unhandled": run_exception_case},
    isolation="PROCESS",
)
observation = harness.run("exception.unhandled")
```

The harness invokes only the supplied callable and only after checking its
declared isolation against the scenario minimum. It does not provide a
sandbox, timeout, process lifecycle, or cleanup guarantee. An unavailable
mapping or insufficient isolation is recorded without invoking user code.
Observed results are bounded JSON and are classified separately from expected
metadata as `MATCHED`, `MISMATCHED`, `INVALID_RESULT`, `ERROR`, `NOT_MAPPED`, or
`ISOLATION_UNAVAILABLE`. A `POLICY_DISABLED` result records that execution was
intentionally disabled without invoking a runner.

The harness accepts an optional `FailureCorpusExecutionPolicy`. Its default is
enabled `PROCESS` execution for the least-friction local start. A deployment
can require `CONTAINER` or `VM`; the runner is not called unless both the
scenario minimum and policy minimum are met. The policy is a gate only and
does not create a sandbox or grant authority:

```python
from caretaker.failure_corpus import FailureCorpusExecutionPolicy

harness = FailureCorpusHarness(
    corpus,
    runners={"worker.failed": run_worker_case},
    isolation="CONTAINER",
policy=FailureCorpusExecutionPolicy(minimum_isolation="CONTAINER"),
)
```

For a concrete process-level lifecycle, trusted infrastructure can use
`FailureCorpusProcessRunner` with an explicit argument vector for each mapped
scenario. The command is never taken from the manifest, is run without a
shell, receives a single scenario-summary JSON request, and must return a
single bounded JSON observation object. Each invocation gets a temporary
workspace that is removed after completion; timeouts terminate the process
group. This provides process isolation and cleanup boundaries only. It does
not provide container/VM sandboxing, hard resource quotas, or hostile-code
containment, and a policy requiring `CONTAINER` or `VM` refuses to launch it.

```python
from caretaker.failure_corpus import FailureCorpusProcessRunner

runner = FailureCorpusProcessRunner(
    corpus,
    {"exception.unhandled": ["/path/to/trusted-runner", "--json"]},
    policy=FailureCorpusExecutionPolicy(minimum_isolation="PROCESS"),
    timeout_seconds=30,
)
observation = runner.run("exception.unhandled")
```

The command mapping is trusted test infrastructure and must be reviewed and
managed separately from corpus data. Caretaker does not treat a successful
observation as authority, validation, or permission to change an application.

When container isolation is required, `FailureCorpusPodmanRunner` accepts an
explicit local image and command mapping. It verifies rootless Podman and
local image presence before each mapped run and never pulls an image. The
container is launched with no network, a read-only root filesystem, dropped
capabilities, `no-new-privileges`, bounded PID/CPU/memory settings, `keep-id`,
and a private no-execute temporary filesystem. No host workspace or Caretaker
credentials are mounted. A `VM` policy requirement refuses this container
runner because a container does not prove a separate kernel.

The image must already contain the trusted runner command. This keeps the
image and executable mapping outside the metadata-only manifest:

```python
from caretaker.failure_corpus import FailureCorpusPodmanRunner

runner = FailureCorpusPodmanRunner(
    corpus,
    "localhost/caretaker-replay-base:0.6.1",
    {"exception.unhandled": ["trusted-runner", "--json"]},
    policy=FailureCorpusExecutionPolicy(minimum_isolation="CONTAINER"),
)
observation = runner.run("exception.unhandled")
```

If Podman is unavailable, not rootless, or the image is absent locally, the
observation is `ISOLATION_UNAVAILABLE` and the command is not launched.

Trusted test infrastructure can persist those observations for later review
without persisting a runner or executable instruction:

```python
from caretaker.failure_corpus import FailureCorpusObservationStore

store = FailureCorpusObservationStore("caretaker-data")
record = store.record(
    observation,
    corpus_id=corpus.corpus_id,
    environment_id="process-linux",
    incident_id="incident-123",
)
```

Each record is a bounded JSON envelope under
`failure-corpus-observations/`, written atomically with restrictive local file
permissions. Its `content_sha256` covers the record payload, allowing the
loader to reject accidental corruption or an inconsistent envelope. The hash
is not an authenticity mechanism: an attacker able to rewrite both the record
and hash can replace it. Use signed or externally shipped audit evidence when
that threat matters. Invalid records are rejected by `load()` and omitted by
`list_summaries()`; loading and listing never execute runner code or grant
authority.

For review dashboards or release checks, `build_outcome_report()` creates a
deterministic bounded summary of retained records. It reports status, scenario,
and environment counts, marks whether the selected records were truncated,
counts corrupt records, and includes each included record's ID and content hash
as provenance. It intentionally omits full observed details and is not an
authorization or validation result.

The same report is available as the read-only
`caretaker-failure-corpus-report` command. It reads the local observation store
and emits JSON; `--persist` additionally retains the report by its content
hash:

```sh
caretaker-failure-corpus-report \
  --data-directory ./caretaker-data \
  --corpus-id caretaker-default-failure-corpus-v1 \
  --persist
```

The command never discovers or invokes a runner, contacts a supervisor, or
changes capsule, policy, repair, or authority state.

## Current status and next work

The loader, manifest, explicit trusted harness, bounded observation store, and
deterministic outcome report provide the initial reviewable contract.
Executable launch/reset/destroy tooling, isolated scenario runners, captured
incident fixtures, and cross-version/adversarial execution reports remain
future work. A policy gate does not replace repository-owned isolated
launch/reset/destroy tooling.
Those additions must record actual observed outcomes separately from expected
metadata and must not turn a corpus file into an execution or authority
channel.
