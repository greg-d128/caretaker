# Caretaker acceptance gates

This document defines the named acceptance gates for Caretaker changes and
release handoffs. It is an acceptance checklist, not a claim that the current
checkout has passed every gate. A gate result must identify the exact source
revision, artifacts, commands, environment, and any skipped or unavailable
capability.

The gates are ordered: feature completeness comes first, candidate readiness
supports independent testing, and publication integrity applies only to the
final signed publication.

## `caretaker-feature-completeness-gate`

- All requested functionality is implemented.
- Public APIs, CLI paths, configuration, and provider paths are consistent.
- Unit, integration, negative, and compatibility tests exist.
- Documentation and examples match actual behavior.
- No unrelated functional changes are included.
- Builds are deterministic and reproducible.

Required evidence includes the changed-file review, public API and CLI
inventory, test commands and results, documentation/example review, and a
reproducibility result from the intended build environment.

## `caretaker-candidate-readiness-gate`

- The alpha candidate is built from a clean, identified source revision.
- Wheel, sdist, source, manifests, catalogs, profiles, and package metadata
  agree.
- Candidate hashes are recorded for every artifact handed to downstream
  projects.
- No functional changes remain after the candidate freeze.
- Release-only changes are explicitly identified.
- The candidate is ready for Validator and Crucible testing.

Candidate readiness does not require release signing. Development candidates
must remain clearly labelled as unsigned development material and must not be
presented as trusted releases. The downstream handoff must use the exact files
whose hashes are recorded; a similarly named artifact from another revision is
not a substitute.

## `caretaker-publication-integrity-gate`

- The final wheel and sdist are built from the intended revision.
- Final metadata and version are correct.
- Signatures and manifests cover the exact published artifacts.
- Installation from both wheel and sdist succeeds.
- Final artifacts match the frozen candidate except for approved release-only
  changes.
- Publication contents contain no stale or unintended files.

This gate also requires successful installed-layout verification and final
publication verification. Unsigned candidate evidence cannot satisfy this
gate.

## Required Caretaker artifact handoff

For every candidate or final gate evaluation, Caretaker should produce a
portable evidence bundle. The bundle may be a directory or archive, but its
contents must be immutable or content-addressed after handoff. Recommended
stable names are shown below.

### Identity and environment

- `source-identity.json`: repository, branch or tag, full source revision,
  clean-worktree result, contract line, package version, and source inventory
  hash.
- `environment.json`: Python implementation and version, operating system,
  build tool versions, dependency/backend versions, relevant container or
  isolation backend versions, and reproducibility inputs such as
  `SOURCE_DATE_EPOCH`.
- `commands.txt` or `commands.json`: exact commands run and their working
  directories, environment selections, and exit results.

### Source, package, and contract material

- The exact wheel and sdist handed to downstream projects.
- `artifacts.json`: relative path, size, SHA-256, package version, and artifact
  type for each handed-off file.
- `source-inventory.json`, `wheel-inventory.json`, and `sdist-inventory.json`:
  canonical payload inventories and their aggregate hashes.
- `artifact-parity.json`: source-to-sdist and source-to-wheel inclusion and
  parity results.
- The applicable release, protected, and installed-layout manifests, with
  their hashes and manifest versions.
- The versioned policy catalogs, reserved-settings catalog, profiles, and
  their fingerprints or hashes.
- `candidate-input.json`: the candidate record, including source revision,
  environment, contract inputs, artifact hashes, and development status.
- `candidate-freeze.json`, when independent review has occurred, including
  hashes of Validator, Crucible, and other required review evidence.

### Verification and downstream handoff

- `test-results.txt` or a structured equivalent containing the internal test,
  compilation, package, parity, and installed-wheel results.
- Retained logs for failed, skipped, or environment-dependent checks, with the
  reason and whether the result is a blocker.
- `downstream-handoff.md` or `downstream-handoff.json`: exact artifact
  identities, contract line, expected public behavior, required profiles and
  catalogs, test commands, known limitations, and explicit Validator/Crucible
  notes.
- For a final publication only: `finalization.json`, `signing-inputs.json`,
  detached signatures, and `publication-verification.json`.

Do not include private keys, bearer tokens, API keys, client certificate
contents, or other secrets. Paths alone may be recorded when needed to explain
configuration, subject to the same sensitivity review.

## Reusable cross-project gate contract

Other project gates may consume the Caretaker handoff without importing the
Caretaker source tree. They should require at minimum:

1. An exact source revision and contract line.
2. Exact artifact paths and SHA-256 hashes.
3. A machine-readable environment and command record.
4. Payload parity and manifest results.
5. Internal pass/fail/skip results with retained evidence.
6. Explicit status for unsigned, unavailable, skipped, or environment-
   dependent checks.

Downstream projects must make their own pass/fail decisions. Caretaker's
reported status and test results are evidence, not an external certification.

## Using the gate names

When a future task asks Caretaker to “meet” one of these gates, evaluate the
named gate against the current revision and produce the artifact handoff above.
Report `pass`, `fail`, or `blocked`; treat missing evidence as unresolved rather
than silently treating it as a pass. A later gate cannot compensate for a
 failed earlier gate.
