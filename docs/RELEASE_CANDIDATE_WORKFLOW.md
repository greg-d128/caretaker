# Release-candidate workflow

Caretaker owns the package build, source and package inventories, publication
manifests, and the handoff to independent validation. Validator owns
cross-repository candidate equivalence. Caretaker does not infer equivalence
from a package version and does not sign candidate artifacts.

## Development candidate

Start from a clean committed revision and build into a new disposable
directory:

```bash
make candidate-build CANDIDATE_VERSION=0.6.5a0 \
  CANDIDATE_OUTPUT_DIR=/tmp/caretaker-0.6.5a0-candidate
```

The command refuses a dirty revision, an existing output directory, stale
distribution files, and private-key material. It sets a fixed source-date
epoch from the commit and records the interpreter, platform, build tools,
source revision, contract inputs, wheel and sdist hashes, and canonical
wheel/sdist/source payload inventories. The resulting record is marked
`UNSIGNED_DEVELOPMENT` with `release_eligible: false`. Candidate wheels do not
contain the installed publication bundle, so they cannot be presented as
trusted releases.

After independent Validator, Crucible, and Architect review, freeze the record:

```bash
make candidate-freeze \
  CANDIDATE_RECORD=/tmp/caretaker-0.6.5a0-candidate/candidate-input.json \
  CANDIDATE_FREEZE_RECORD=/tmp/caretaker-0.6.5a0-candidate/candidate-freeze.json \
  VALIDATOR_RESULT=/path/to/validator-result.json \
  CRUCIBLE_RESULT=/path/to/crucible-result.json \
  ARCHITECT_AUDIT=/path/to/architect-audit.json
```

The freeze is an immutable new record; it does not rewrite the candidate
input. It preserves the candidate identity and records hashes of supplied
external evidence. Missing evidence may be recorded as `null` for development
coordination, but it is not a release acceptance decision.

## Finalization and signing

Select the final package version and perform the release-only transformation in
the source revision. The Caretaker finalizer permits only exact substitutions
of the development package version in its explicit release metadata allowlist;
functional source, profile, policy, schema, dependency, fixture, or other
inputs invalidate the candidate. Validator must supply an accepted equivalence
handoff; Caretaker records and hash-checks that handoff but does not implement
its cross-repository comparison.

The final sequence is:

```text
final version selection
  -> policy/catalog generation
  -> one fresh wheel and sdist build
  -> package and canonical parity checks
  -> publication manifest generation
  -> Validator equivalence handoff
  -> immutable signing bundle
  -> detached offline signing
  -> publication verification
```

The `release-final` target composes these gates. Its signing step still
requires the separately administered signing station and key slot. The signing
bundle copies the finalization record and package artifacts into an immutable
station directory and writes `signing-inputs.json`. Station checks reject
missing or changed manifests, artifacts, finalization bytes, and other
approved inputs. A new final artifact set requires a new candidate finalization
and signing round.

Detached signatures continue to apply to the approved root, manifests,
profiles, and installed-layout publication material. Caretaker runtime code
does not load private keys or sign its own source. Unsigned development output
must remain labelled development evidence and is never a trusted release.

## Final-version preparation

For the 0.6.5 final-version transition, update the committed package metadata
and version-facing documentation first, then verify the selected version:

```bash
make final-version-selection FINAL_VERSION=0.6.5
make policy-catalogs PACKAGE_VERSION=0.6.5
make wheel-manifests PACKAGE_VERSION=0.6.5 FORCE=1
```

Build the unsigned final-version distributions into a new directory outside
`dist/`, then run exact payload parity and package checks:

```bash
make build PACKAGE_VERSION=0.6.5 BUILD_OUTPUT_DIR=/tmp/caretaker-0.6.5-final
make artifact-parity-existing PACKAGE_VERSION=0.6.5 \
  BUILD_OUTPUT_DIR=/tmp/caretaker-0.6.5-final
make package-check-existing PACKAGE_VERSION=0.6.5 \
  BUILD_OUTPUT_DIR=/tmp/caretaker-0.6.5-final
```

This preparation produces reviewable unsigned artifacts. Root publication
manifests, finalization, the signing bundle, detached signatures, and
publication verification remain subsequent controlled release steps. The
development candidate examples above intentionally retain the `0.6.5a0`
version used for independent pre-final testing.
