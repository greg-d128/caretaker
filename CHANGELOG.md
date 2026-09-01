# Changelog

## 0.6.5a

### Pre-version-1 application scope

- Accept the bounded application-local supervisor scope for adaptive
  aggregation, policy-bound Repair rollout, and Repair recovery.
- Add Incident Capsule side artifacts, operator-view capture, read-only
  Incident Explorer replay, non-interactive historical replay, and advisory
  LLM assistance without allowing capsule or authority mutation.
- Add policy-governed incident communication drafts and local review records;
  external delivery remains intentionally deferred.
- Add bounded behavior distribution-shift evidence with policy-configurable
  minimum samples and sigma thresholds, including console visibility.
- Document the remaining fleet, deployment, external-assurance, and Crucible
  boundaries explicitly for the pre-version-1 release.

## 0.6.1

### Authority verification

- Bind every signed authority-layer kind to its permitted signing role before
  signature verification, preventing a valid signature for one role from being
  substituted for another authority kind.
- Require runtime authority layers and signed runtime leases to use the
  designated `runtime-policy` role, including when a signer is authorized for
  multiple roles.

## 0.6.0

### Public research release assurance

- Prompt attended signing workflows for missing public key slots and manifest
  versions; resolve each authorized primary fingerprint from `root.json`, retain
  fail-fast non-interactive behavior, and print concrete next steps.
- State the current supply-chain scope explicitly: runtime evidence, Caretaker OpenPGP manifests, dependency behavior, import routing, and temporary function repair are implemented research areas; SBOM/advisory ingestion, registry monitoring, upgrade orchestration, modern provenance ecosystems, deployment, and external incident integrations remain roadmap work.
- Publish the validation, isolation, same-UID control, VM-attestation, policy-truthfulness, multiprocess, and Repair restart debts in the future-work ledger.
- Add a private vulnerability-reporting policy, supported Python/Linux scope, a current development verification report, and Forgejo CI for CPython 3.11 through 3.13.
- Correct the Guard security description of policy-enabled automatic baseline acceptance and convert its strict expected-failure regression into a passing documentation-conformance test.
- Add a small reviewable `scripts/sign-code.sh` GnuPG wrapper. The ordinary station
  workflow uses `make sign-release-set KEY_SLOT=<slot>`; advanced single-file use
  remains available through `make sign-file`.
- Group Make commands by coordinator/station role, add publication status reporting,
  and create non-overwriting minimal offline signing bundles containing reviewed
  artifacts, public certificates, station tools, instructions, and `SHA256SUMS`.

### Policy truthfulness and enforcement

- Make accepted policy an executable contract: unsupported non-default semantics fail policy validation instead of being accepted as no-ops.
- Add a machine-reviewed policy dataclass surface fingerprint and explicit reserved-setting catalog so new policy fields require a semantic review and behavioral tests.
- Make Guard `DISABLED` a true off state; collapse stronger-sounding legacy mode names into audit compatibility aliases and separate observation from deterministic policy response.
- Enforce deterministic Guard network/subprocess/filesystem policy violations, target-binding response precedence, candidate Guard controls, and statistical p95 timing deviations.
- Enforce Repair LLM privacy/context controls at request construction and apply `maximum_context_characters` to the complete textual provider context.
- Reject or deactivate previously declarative Repair/Guard scheduling and retention settings until their semantics are implemented.
- Enforce signature-integrity minimums for behavior snapshots/baselines/archives so signed artifacts cannot be downgraded by stripping their signatures.
- Honor compression algorithm/rotation/buffering/interrogation/system-redaction controls that were previously declarative, and make unsupported logging/system values fail explicitly.
- Add capability-based selection across multiple configured validation backends and supervised `--external-signer module:attribute` configuration.
- Drain active logging IPC handlers during shutdown before the writer is closed.

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

- Collapse the Behavior list to one preferred analytical snapshot per subject/generation before
  applying its row limit; sort by subject/newest generation and expose first/last
  seen, cumulative evidence coverage, and bounded hourly call-activity bars.
- Label non-cumulative Behavior coverage as `partial` rather than the ambiguous
  `window`; show ordinary verified generation coverage as the uncluttered count.
- Keep zero-call generations as event-only forensic evidence but hide
  them from the default analytical list behind an explicit visibility control.
- Open on a unified Attention queue, retain shared target/incident/call context
  across all eight tabs, and report evidence freshness, source, and bounded scope.
- Make Overview and Guard issue-first, add direct evidence/investigation links,
  and distinguish no evidence, learning, healthy, and deviation states.
- Replace Behavior A/B operands with green subject-scoped references, a selected
  comparison generation, and the direct **Set Reference** / **Compare with reference** workflow;
  clarify code generations, active unsaved observations,
  collection coverage, integrity/provenance, resource changes, and advisory limits.
- Put waiting Repair decisions first, expose candidate source and evidence gaps,
  and link episodes to triggering Logs, Guard evidence, and Investigation.
- Add previewable policy presets and explicit scope/impact acknowledgements;
  make Behavior removal generation-scoped and archive-only, require an archive
  reason, and retain verification/restoration metadata in the archive manifest.
- Require confirmations for Behavior archiving, Repair decisions, signed policy
  changes, and ending temporary policy changes, plus reasons for rejection and
  policy application.
- Make Investigation scope and candidate rationale visible, and document that
  Logs correlation is identifier-based with live/persisted source semantics.
- Add a Repair approval source viewer that renders the proposed replacement as syntax-highlighted Python with line numbers and toggles back to the full JSON approval payload.
- Show a per-target lifecycle status in Overview. Active post-repair candidate probation is labeled `VALIDATING`, while exact FunctionSlot and candidate states remain available in target details.
- Add compact Overview target filtering with free-text search and `target:`, `status:`, `state:`, `mode:`, `authority:`, `guard:`, and `version:` selectors.
- Refresh the target snapshot immediately after approving or rejecting a Repair so lifecycle changes are visible without leaving the Repair workflow.
- Add slot role and adaptive-observation state to Overview. Fully managed targets
  report `not adaptive`; dependency boundaries report normal or explicitly
  escalated Behavior/Repair observation, lifecycle, and escalation reason.
- Add a private plain-text **Save Report** export for every console tab, including
  visible summaries, filters, table rows, and detail panels for ticket handoff.
- Make stale DataTable selection events harmless after refresh/archive operations.

### Diagnostic robustness

- Fix live operator Repair event ordering to use `RepairEvent.timestamp` rather than the unrelated `created_at` field used by Guard decisions.
- Return structured runtime-control failure diagnostics with component/operation, exception identity, Repair correlation fields, authority generation/fingerprint, peer credentials, and a diagnostic ID.
- Emit unexpected child-runtime control failures on the `CARETAKER_INTERNAL` channel when durable logging remains available; optional bounded traceback/request-key detail is enabled only by `CARETAKER_DIAGNOSTIC_DEBUG` and may be stored as DEBUG-priority attachment evidence.
- Preserve structured control errors in `caretaker-console` and query Repair events and pending approvals independently so an event-history failure cannot hide an actionable approval.
- Avoid recursive diagnostic logging when the logging path itself fails; propagate persistence status through the control response and use a best-effort stderr fallback.

### Adaptive behavior and persistent baselines

- Make registered-function capture a singular sequence of atomic, non-overlapping
  epochs. Manual capture closes the active epoch, installs a successor, and records
  generation-scoped sample ranges that are validated before cumulative coverage.
- Prefer proven cumulative epoch evidence in each Behavior generation row so a
  later legacy, module, or overlapping partial cannot mask useful analysis.
- Show the three newest generations per function by default and allocate bounded
  summary capacity across subjects before admitting fourth and older generations.
- Add lightweight adaptive instrumentation with policy-controlled promotion through pre-repair BEHAVIOR evidence collection and policy-controlled demotion after accepted repair lifecycle stages.
- Separate repair lifecycle from observation intensity and use `LIGHTWEIGHT -> BEHAVIOR -> REPAIR -> BEHAVIOR -> VALIDATION -> LONG_TERM_ACCEPTANCE` as the operator lifecycle.
- Add generation-scoped call-count behavior sampling, bounded online duration statistics, reservoir-backed p10/p50/p90/p95/p99 estimates, sampling-stage provenance, and automatic snapshot materialization.
- Rotate behavior generations when code or monitoring semantics change while retaining LIGHTWEIGHT/BEHAVIOR observations as strata under one compatible configured generation.
- Persist accepted Guard baselines as immutable references to sealed behavior snapshots and reconstruct exact compatible baselines after restart without replaying raw audit events.
- Add the Behavior console view for snapshot history, comparison, statistical changes, resource novelty, archive management, and advisory LLM analysis.

### Runtime artifact signing

- Reuse runtime event signing for domain-separated behavior snapshots, accepted-baseline references, and behavior archives.
- Refuse silent fallback from configured external signing to ephemeral signing.
- Add an independent hash-chained Signing Identity Journal with separate retention, public ephemeral identities, exact signed key-transition sequence metadata, and identity-chain verification.
- Include required public identity records in behavior archives and add archive verification and safe snapshot restoration.

### Validation isolation

- Add a common validation-backend capability contract and policy-controlled minimum isolation levels: PROCESS, CONTAINER, VM, and EXTERNAL.
- Preserve the existing subprocess validator as the PROCESS backend.
- Add a rootless Podman CONTAINER backend with no network, read-only root filesystem, dropped capabilities, `no-new-privileges`, user namespaces, resource limits, and explicit read-only source mounts.
- Add a Multipass VM backend that refuses host mounts, transfers validation artifacts explicitly, supports clean-snapshot restoration, and can use disposable clones for higher-risk validation.
- Make insufficient/unavailable isolation fail, remain proposal-only, or require explicit operator approval according to policy; never silently downgrade.

### Dependency instrumentation and consolidation

- Add reversible module/function dependency instrumentation through lightweight dependency slots, including Guard-aware initialization and self-instrumentation re-entrancy protection.
- Consolidate shared acceptance criteria, renewable behavior leases, policy-bound adaptive state, bounded Guard caches, early event sampling/rate limiting, and scoped unattributed-audit collection.
- Record supervisor-owned multiprocess adaptive aggregation and runtime-repair graduation into source patches as explicit future work.

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
