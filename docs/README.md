# Caretaker documentation

Caretaker is active research software. These documents describe current design intent, implemented and tested behavior, known limitations, and future work; they do not guarantee availability, correctness, recovery, containment, or security in a particular environment.

## Start here

- `../README.md` — installation, supervised startup, and examples
- `../ARCHITECTURE.md` — complete application-scoped architecture
- `LOGGING_ARCHITECTURE.md` — logging fast path, storage, and multiprocess model
- `LOGGING_POLICY.md` — operator authority, mode requirements, leases, and reload
- `LOGGING_RECORD_FORMAT.md` — 4 KiB extensible records and attachments
- `LOGGING_INTEGRITY.md` — hash chains, ephemeral signatures, key evolution, and external collection
- `SYSTEM_COLLECTION.md` — raw `/proc` and `/sys` collection
- `LOGGING_BASELINES.md` — population baselines and slow drift
- `LOGGING_INTERROGATION.md` — outliers, hypotheses, and LLM authority
- `ADMIN_CONTROL.md` — local socket authentication, operator console workflow, tab semantics, and mode control
- `POLICY_AUTHORITY.md` — signed authority layers, constraints, overrides, and runtime leases
- `PROFILES.md` — named/versioned profiles, policy-surface coverage, comparison, pinning, and the Profile Editor 
- `POLICY_SEMANTICS.md` — executable policy support, reserved settings, and semantic surface review
- `ISOLATED_EXECUTION.md` — deployment and validation-backend isolation guidance

## Shared runtime and Guard

- `RUNTIME_CONTROL_PLANE.md`
- `GUARD_ARCHITECTURE.md`
- `GUARD_POLICIES.md`
- `GUARD_INTROSPECTION.md`
- `GUARD_IMPORT_ROUTING.md`
- `GUARD_LLM_ASSESSMENT.md`
- `GUARD_QUERYING.md`
- `GUARD_SECURITY.md`

## Repair

- `DECORATORS.md`
- `POLICIES.md`
- `VALIDATION_AND_SECURITY.md`
- `OBSERVATION_AND_REGRESSION.md`
- `INCIDENT_CAPSULES.md` — bounded incident records, operator-view artifacts, and communication-history contract

## Integrity

- `INTEGRITY.md`
- `OPENPGP_VERIFICATION.md`
- `PROBABILISTIC_VERIFICATION.md`
- `SIGNING_STATION.md`
- `THREAT_MODEL.md`

## Planning and releases

- `FUTURE_WORK.md`
- `INTERACTIVE_ISOLATION_TESTING.md` — controlled interactive isolation experiments
- `../MIGRATION.md`
- `../CHANGELOG.md`
- `../VERIFICATION.txt` — current verification status followed by historical reports
- `../SECURITY.md` — vulnerability reporting, supported research versions, and platform scope
