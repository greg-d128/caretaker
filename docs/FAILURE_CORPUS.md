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
`ISOLATION_UNAVAILABLE`.

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

## Current status and next work

The loader, manifest, explicit trusted harness, and bounded observation store
provide the initial reviewable contract. Executable launch/reset/destroy
tooling, isolated scenario runners, captured incident fixtures, and
cross-version/adversarial execution reports remain future work.
Those additions must record actual observed outcomes separately from expected
metadata and must not turn a corpus file into an execution or authority
channel.
