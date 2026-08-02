# Logging interrogation and root-cause analysis

Interrogation reads stored evidence outside the logging fast path.

## Pipeline

1. Select a time range, targets, calls, modules, or incidents.
2. Read relevant segments and evidence references.
3. Normalize message templates.
4. Correlate calls, exceptions, behavior deviations, dependencies, and integrity findings.
5. Identify deterministic temporal and statistical outliers.
6. Build a bounded representative timeline.
7. Optionally request an LLM assessment.
8. Produce hypotheses, confidence, missing evidence, and recommended next actions.

## Evidence authority

`LoggingEvidenceBundle` includes an evidence hash and omitted-record count. Log content and application values are untrusted evidence, not prompt instructions.

The LLM may rank anomalies, propose explanations, comment on reports, and identify missing evidence. It cannot accept baselines, alter retention, approve policy overlays, or declare a root cause confirmed.

## Root-cause language

Caretaker distinguishes:

- observed sequence;
- statistical association;
- probable causal contribution;
- administrator-confirmed root cause.

The built-in result is a `RootCauseAssessment` containing primary and alternative hypotheses, confidence, supporting evidence, contradicting evidence, and missing evidence.
