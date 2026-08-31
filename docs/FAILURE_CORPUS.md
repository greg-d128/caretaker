# Failure corpus

Caretaker includes a small reviewed scenario manifest at
[`examples/failure_corpus/manifest.json`](../examples/failure_corpus/manifest.json).
It is a bounded inventory of failure conditions for test planning and
historical evidence review. The manifest currently covers exceptions, timeouts,
invalid output, dependency and configuration changes, corruption, concurrency,
deployment regressions, intermittent behavior, resource pressure, worker
failure, failed validation, secondary repair failure, malicious evidence, and
unavailable LLM services.

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

The repository also includes explicit oracle mappings in
[`examples/failure_corpus/trusted_mappings.py`](../examples/failure_corpus/trusted_mappings.py).
They cover every scenario in the reviewed default manifest and return the
declared expected observation so the harness, isolation gates, and reporting
pipeline can be regression-tested together. They do not perform the stated
stimuli and must not be counted as observed application coverage; real
scenario runners remain separately reviewed test infrastructure.

The process-tier application laboratory in
[`application_laboratory.py`](../examples/failure_corpus/application_laboratory.py)
is a separate executable fixture. It performs bounded local stimuli for ten
scenarios—including exception, soft timeout, invalid output, configuration and
intermittent behavior, storage pressure, worker failure, repair failures, and
LLM unavailability—and returns the resulting bounded observation details. It
does not contact the network, load production application code, or claim to
reproduce a historical incident. The remaining higher-isolation scenarios
must be run through the Podman or Multipass runners.

The example [`trusted_runner.py`](../examples/failure_corpus/trusted_runner.py)
executes those oracle mappings through the process runner's JSON protocol. It
is a lifecycle and protocol fixture, not an application simulator: process
policy can exercise the ten scenarios whose declared minimum is `PROCESS`,
while the seven `CONTAINER`/`VM` scenarios are recorded as
`ISOLATION_UNAVAILABLE`. This deliberate split makes a report honest about
which isolation tiers were actually exercised.

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

When a real Incident Capsule is available, use
`FailureCorpusObservationStore.record_incident_fixture()`. It loads the
selected capsule through `IncidentCapsuleStore`, which verifies its immutable
revision chain, and records only the capsule ID, incident ID, revision, and
verified content hash beside the observation. The capsule is not modified and
the corpus observation remains separate evidence; a missing or corrupt capsule
prevents the fixture from being written.

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

For a separate-kernel boundary, `FailureCorpusMultipassRunner` reuses the
existing pre-provisioned Multipass validation contract. It can restore a clean
snapshot or use a disposable clone, transfers each request into the guest,
passes the request path as the final argument to the trusted command, captures
bounded JSON stdout, and removes the transferred request. It inherits guest
mount refusal and, when enabled, root-owned network-isolation attestation. It
does not create a VM, install software, or obtain credentials automatically;
the guest must be provisioned separately.

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

The `caretaker-failure-corpus-run` command provides the execution entrypoint.
It defaults to the repository application laboratory and `PROCESS` policy,
accepts repeated `--scenario-id` filters, records each bounded observation,
and emits the resulting report. `--isolation CONTAINER` requires `--image` and
either an explicit `--runner-command` or `--application-laboratory`, which uses
the fixed `/opt/caretaker/application_laboratory.py` path in the repository
image. `--isolation VM` requires an explicit guest `--runner-command` and a
pre-provisioned Multipass guest. The command does not infer or execute
commands from the manifest, and `--persist-report` retains the report by
content hash:

```sh
caretaker-failure-corpus-run \
  --manifest examples/failure_corpus/manifest.json \
  --data-directory ./caretaker-data \
  --scenario-id exception.unhandled \
  --persist-report
```

The process default is intended for quick starts and local application
laboratory work. Select a stronger tier when the scenario or threat model
requires it; unavailable prerequisites remain explicit evidence rather than a
silent downgrade.

## Current status and next work

The loader, manifest, explicit trusted harness, bounded observation store,
deterministic outcome report, trusted process runner, application laboratory,
and policy-gated Podman/VM runner contracts provide the current reviewable
execution path. Live higher-isolation execution depends on the operator's
pre-provisioned runtime and image/guest, and broader captured-incident,
cross-version, adversarial, and automatic launch/reset/destroy workflows remain
future work. A policy gate does not replace repository-owned isolated
launch/reset/destroy tooling.
Those additions must record actual observed outcomes separately from expected
metadata and must not turn a corpus file into an execution or authority
channel.
