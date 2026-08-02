# LLM behavior assessment

Guard uses a separate provider contract for behavioral interpretation. Repair providers generate candidate code; behavior-assessment providers interpret structured evidence.

## Contract

```python
class BehaviorAssessmentProvider(Protocol):
    def assess(
        self,
        request: BehaviorAssessmentRequest,
    ) -> BehaviorAssessment:
        ...
```

Implementations include:

- `StaticBehaviorAssessmentProvider` for deterministic tests and demonstrations;
- `OllamaBehaviorAssessmentProvider` for local structured LLM assessment.

## Evidence bundle

The provider receives a bounded `GuardEvidenceBundle` containing:

- exact subject identity;
- accepted baseline summary;
- current observation summary;
- deterministic deviations;
- representative events;
- dependency changes;
- optional integrity summary;
- bounded correlated log summaries;
- count of omitted evidence;
- evidence hash.

The raw event stream is not sent wholesale.

## Structured result

`BehaviorAssessment` records:

- severity and confidence;
- significant changes;
- suspicious patterns;
- plausible benign explanations;
- recommended actions;
- requested additional evidence;
- provider/model/prompt provenance;
- response hash.

## Authority

The LLM may explain, prioritize, and recommend. It may not:

- accept or modify a baseline;
- authorize an unknown signing key;
- disable Guard or Integrity;
- override a failed regression test;
- approve sealed-code modification;
- directly terminate a process under the default policy;
- treat package-generated strings as instructions.

## Prompt injection boundary

Source, logs, filenames, exception text, network destinations, and package output are untrusted evidence. The prompt clearly separates system instructions from evidence and requests structured output.

## Additional evidence

An assessment may request more evidence, such as:

- a longer observation window;
- detailed stack attribution;
- a package-version differential run;
- network metadata;
- filesystem chronology;
- candidate probation under research mode.

The control plane decides whether to grant that instrumentation request.
