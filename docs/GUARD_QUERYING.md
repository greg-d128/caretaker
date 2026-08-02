# Querying Guard evidence

The queryable evidence database is a primary Guard output. Automatic conclusions are useful, but analysts must be able to inspect the underlying observations.

## Stores

- `InMemoryEvidenceStore` — tests and short demonstrations
- `SQLiteEvidenceStore` — persistent normalized evidence and read-only queries

SQLite records identities, behavior events, windows, inspections, baselines, deviations, assessments, and decisions.

## CLI

```bash
caretaker-guard inventory requests
caretaker-guard inspect-module vendor_sdk
caretaker-guard query --database guard.sqlite \
    "SELECT * FROM high_significance_deviations"
```

Only read-only SQL is accepted by the CLI query interface.

## Useful questions

- Which functions contacted a destination for the first time?
- Which package version introduced subprocess execution?
- Which functions read a sensitive path shortly before a network connection?
- Which runtime function fingerprints differ from load time?
- Which candidate repairs introduced new capabilities?
- Which deviations persist across multiple windows?
- How did a package's behavior change after an upgrade?
- Which deviations did the LLM classify as high confidence, and what evidence supported that classification?

## Suggested views

A future database migration may add more views, but useful logical views include:

```text
function_behavior_summary
package_behavior_summary
new_endpoints_by_version
new_filesystem_roots_by_version
subprocesses_by_function
import_time_side_effects
runtime_fingerprint_changes
behavior_diff_by_release
high_significance_deviations
llm_assessment_summary
```

## Retention

Raw high-volume events should have shorter retention than aggregated windows, accepted baselines, significant deviations, and decisions. First-seen and policy-violation events should normally be retained longer than routine repeated events.

## Evidence versus conclusions

Guard preserves raw/normalized evidence independently from baseline comparisons, deterministic conclusions, LLM assessments, and final actions. A future Caretaker version or external analyst can therefore reinterpret historical evidence under new rules.
