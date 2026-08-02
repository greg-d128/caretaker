# Changelog

## 0.5.0a1

### Logging subsystem

- Add a lightweight standard-library-compatible logging subsystem deployable without Guard or Repair.
- Add `CaretakerLogHandler`, direct and remote runtimes, `get_logger()`, and `@logged`.
- Add shared call correlation, decorator timing, exception fingerprints, optional input/result capture, population designators, and masking functions.
- Add operator-controlled TOML policy with explicit security and permission warnings.
- Add complete policy reconciliation, immutable effective-policy generations, temporary mode leases, and reversible higher-mode overlays.
- Add policy hot reload for safe runtime settings and explicit reporting of startup-bound changes.

### Storage and multiprocessing

- Add bounded asynchronous buffering, configurable backpressure, free-space thresholds, emergency actions, and high-priority evidence handling.
- Add a versioned extensible TLV record format limited to 4096 bytes.
- Add append-only rotating event segments, optional GZIP compression, hash chaining, recovery of complete records before a truncated final frame, and a rebuildable SQLite index.
- Add local Unix-domain event ingestion for multiple application processes and peer-credential checks.
- Add an application-scoped supervisor, control socket, worker/work registries, watchdog contracts, and preferred `python -m caretaker.run` startup.
- Add explicit late-start warnings containing the preferred supervised command.

### Supplemental attachments and runtime signing

- Add a separate compressed attachment stream linked by event ID, global event sequence, hashes, and segment location.
- Add independent attachment rotation, retention, size limits, rate limits, and policy-driven probabilistic sampling.
- Add hash-chained, ephemeral-signed, and external-signed runtime integrity modes.
- Add Ed25519 runtime identities, public-key publication, signed closed manifests, signed key transitions, and policy-controlled key evolution with a one-day default epoch.
- Preserve the no-private-release-key rule and provide a narrow external signer contract.

### System records

- Add an optional same-privilege `/proc` and `/sys` collection agent.
- Follow the supervised application PID and descendants while handling PID reuse through process start ticks.
- Add synchronized collection-cycle timestamps and nearly raw source bodies for later specialized parsers.
- Separate system-data rotation, compression, retention, output, and masking policy from application logs.
- Leave semantic system parsers and the advanced metrics provider intentionally open.

### Analysis and baselines

- Add deterministic log interrogation and structured advisory Ollama root-cause assessment.
- Add function and application baseline generation, external acceptance, multiple simultaneous accepted baselines, population partitioning, and content-addressed storage.
- Add baseline comparison separating absolute, relative, and per-unit-of-work change, plus gradual trend and slow-drift scoring.
- Add `caretaker-logging` commands for policies, records, control, baseline generation/list/accept/compare, and interrogation.

### Repair and Guard integration

- Add logging bindings and masking to Repair decorators.
- Add manual, proposal-only, approval-required, and standing automatic Repair authority modes.
- Mark pending repairs stale when the effective policy changes before deployment.
- Add active-work correlation, duplicate suppression, cycle/rate limits, and Guard interrogation of overlapping work.
- Add degraded Guard behavior when required logging capabilities become unavailable.
- Prohibit generated repair of all Caretaker-owned modules.

### Documentation and security

- Document that operator logging policy is unsigned and outside Caretaker's release-signature authority.
- Document explicit higher-mode overrides and lease reversion.
- Document ephemeral signing, key-erasure limitations, public-key anchoring, and one-day default key evolution.
- Recommend independent external logging agents and collection systems for stronger tamper resistance.

## 0.4.0a1

- Add the Guard subsystem, shared evidence, runtime control plane, load-time and periodic introspection, module routing, behavior baselines, and bidirectional Guard–Repair integration.

## 0.3.0a3

- Enforce repaired-call contracts, real retry loops, generated-test preservation, log context, hard candidate gates, observation budgets, regression replay, decorator conveniences, integrity-aware repair eligibility, and SQLite queryability.

## 0.3.0a2

- Add full and probabilistic OpenPGP verification, three-key publication policy, selected-signature mappings, and staggered key-rotation metadata.

## 0.3.0a1

- Add public-key-only integrity manifests, threshold verification, root transitions, anti-rollback state, runtime fingerprints, and independent GPG instructions.

## 0.2.0a1

- Initial policy-driven self-repair vertical slice.
