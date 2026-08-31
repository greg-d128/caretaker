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

## Current status and next work

The loader and manifest provide the initial reviewable contract. Executable
launch/reset/destroy tooling, isolated scenario runners, captured incident
fixtures, and cross-version/adversarial execution reports remain future work.
Those additions must record actual observed outcomes separately from expected
metadata and must not turn a corpus file into an execution or authority
channel.
