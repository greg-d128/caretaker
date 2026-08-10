# Changelog

## 0.6.0a1

### Policy authority

- Add supervisor-owned framework, optional application-owner, deployment, and temporary runtime authority layers.
- Add canonical signed/unsigned policy manifests containing settings, constraints, explicit overrides, parent fingerprints, generations, and provenance.
- Reuse Caretaker's external GPG verifier and trust-role model for signed policy layers; unsigned operation remains supported and explicitly reported.
- Require lower static layers and signed runtime leases to bind to the exact active upstream policy fingerprints.
- Add conflict reconciliation in which lower authorities may deliberately override higher constraints while invalidating, rather than impersonating, the higher guarantee.
- Add targeted runtime policy leases, unsigned by default, with a policy option requiring signed leases for higher-assurance environments.
- Bind Repair incidents, candidates, attempts, validation work, and approvals to the effective authority generation/fingerprint so policy changes make pending work stale.
- Add supervisor/application policy-fingerprint comparison, transactional child reconciliation, runtime tamper reporting, and automatic restoration attempts.
- Add a Textual Policy view showing authority layers, signatures, guarantees, violations, runtime leases, and operator lease controls.
- Document independent external GPG verification as the high-assurance trust anchor; policy authority does not claim to prevent a host owner from modifying open-source software.

### Policy profiles

- Add named, descriptive, versioned framework profiles with stable lineage IDs, exact predecessor fingerprints, and explicit `based_on` provenance for organizational derivatives.
- Add a policy-surface capability catalog so older profiles can report newly introduced policy-controlled Caretaker functionality that they have not reviewed.
- Add strict profile controls that can refuse startup when policy-surface coverage is incomplete or when a high-assurance profile was not reviewed for the exact running Caretaker version.
- Reserve a delegated `profile-signing` role for official profile provenance, separate from Caretaker's core/release signing identities; profile signing remains external/offline.
- Add semantic `caretaker-profile show`, `compare`, `coverage`, `catalog`, and `pin` commands. Profile selection pins reuse the existing deployment-layer `parents.framework` fingerprint binding.
- Add a Textual Profile Editor, available as `caretaker-profile` or `make profile`, for creating/continuing profiles, editing settings/constraints, reviewing new capabilities, comparing semantic consequences, and writing canonical unsigned output for external signing.

### Operator console usability

- Add a Repair approval source viewer that renders the proposed replacement as syntax-highlighted Python with line numbers and toggles back to the full JSON approval payload.
- Show a per-target lifecycle status in Overview. Active post-repair candidate probation is labeled `VALIDATING`, while exact FunctionSlot and candidate states remain available in target details.
- Add compact Overview target filtering with free-text search and `target:`, `status:`, `state:`, `mode:`, `authority:`, `guard:`, and `version:` selectors.
- Refresh the target snapshot immediately after approving or rejecting a Repair so lifecycle changes are visible without leaving the Repair workflow.

### Diagnostic robustness

- Fix live operator Repair event ordering to use `RepairEvent.timestamp` rather than the unrelated `created_at` field used by Guard decisions.
- Return structured runtime-control failure diagnostics with component/operation, exception identity, Repair correlation fields, authority generation/fingerprint, peer credentials, and a diagnostic ID.
- Emit unexpected child-runtime control failures on the `CARETAKER_INTERNAL` channel when durable logging remains available; optional bounded traceback/request-key detail is enabled only by `CARETAKER_DIAGNOSTIC_DEBUG` and may be stored as DEBUG-priority attachment evidence.
- Preserve structured control errors in `caretaker-console` and query Repair events and pending approvals independently so an event-history failure cannot hide an actionable approval.
- Avoid recursive diagnostic logging when the logging path itself fails; propagate persistence status through the control response and use a best-effort stderr fallback.

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
