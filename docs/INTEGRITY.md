# Caretaker integrity subsystem

Caretaker provides public-key-only integrity verification as part of its research into release provenance, threshold authorization, randomized fleet verification, self-verification, root rotation, rollback protection, and tamper evidence.

The runtime project has **no private-key interface**. It cannot load a release private key, request a signature, or sign an artifact. Signing is performed by a separate offline procedure that is intentionally outside this repository.

## Three signer identities

A signed `root.json` defines three authorized OpenPGP primary certificate fingerprints. Root schema V2 separates authorization, publication, and runtime verification:

| Role | Authorization threshold | Published signatures | Runtime sample | Purpose |
|---|---:|---:|---:|---|
| `release` | 1 of 3 | 3 of 3 | random 1 of 3 | Ordinary Caretaker code and release artifacts |
| `protected` | 2 of 3 | 3 of 3 | random 2 of 3 | Integrity, activation, validation, and other security-sensitive code |
| `root` | 2 of 3 | 3 of 3 | random 2 of 3 | Public keys, thresholds, protected paths, rotation, and trust policy |

Thresholds count **distinct primary certificate fingerprints**. Two signing subkeys belonging to the same primary certificate count as one signer.

All three signatures are expected on published manifests. Full verification checks all three. Randomized runtime verification checks only the unpredictable subset encoded in the signed root policy. See [`PROBABILISTIC_VERIFICATION.md`](PROBABILISTIC_VERIFICATION.md).

## Signed objects

Caretaker uses detached OpenPGP signatures over canonical JSON documents:

- `root.json`
- `release-manifest.json`
- `protected-manifest.json`

A published manifest normally has three signatures:

```text
release-manifest.json
release-manifest.json.key-a.asc
release-manifest.json.key-b.asc
release-manifest.json.key-c.asc
```

Signature filenames are not trusted identities. Caretaker obtains the signing and primary certificate fingerprints from GnuPG machine-status output.

A manifest lists exact SHA-256 hashes and byte lengths for files relative to an artifact root. The signature authenticates the manifest; the manifest authenticates the code.

## Canonical metadata

Caretaker canonical JSON V1 is:

- UTF-8;
- sorted object keys;
- compact separators;
- no floating-point values;
- one trailing newline.

The exact bytes are signed. Semantically equivalent JSON with different formatting is rejected.

## Manifest generation

Manifest generation requires no private key:

```bash
caretaker-integrity generate-manifest \
  --root-dir . \
  --output release-manifest.json \
  --project caretaker \
  --package-version 0.3.0a3 \
  --manifest-type release \
  --manifest-version 1 \
  --root-version 1 \
  --root-policy root.json \
  --include 'src/caretaker/**/*.py' \
  --exclude 'src/caretaker/integrity/**'
```

The canonical document is transferred to the separate signing environment and signed with keys A, B, and C.

## Full publication verification

The CLI defaults to full publication verification:

```bash
caretaker-integrity verify \
  --root root.json \
  --root-signature root.json.key-a.asc \
  --root-signature root.json.key-b.asc \
  --root-signature root.json.key-c.asc \
  --trusted-fingerprint FULL_PRIMARY_FINGERPRINT_A \
  --trusted-fingerprint FULL_PRIMARY_FINGERPRINT_B \
  --trusted-fingerprint FULL_PRIMARY_FINGERPRINT_C \
  --manifest release-manifest.json \
  --signature release-manifest.json.key-a.asc \
  --signature release-manifest.json.key-b.asc \
  --signature release-manifest.json.key-c.asc \
  --public-key caretaker-key-a.asc \
  --public-key caretaker-key-b.asc \
  --public-key caretaker-key-c.asc \
  --artifact-root .
```

The verifier:

1. imports only supplied public certificates into an isolated temporary GnuPG home;
2. disables automatic key retrieval and embedded-key import;
3. verifies detached signatures through GnuPG status records;
4. resolves signing subkeys to primary certificate fingerprints;
5. rejects unauthorized, duplicate, expired, revoked, missing, or invalid signers;
6. applies the selected verification mode;
7. validates canonical metadata and root-controlled path classifications;
8. checks file size and SHA-256;
9. optionally checks and advances anti-rollback state;
10. records selected identities, warnings, and failures.

The CLI also supports explicit modes:

```bash
caretaker-integrity verify ... \
  --verification-mode full-publication

caretaker-integrity verify ... \
  --verification-mode randomized-runtime
```

Randomized mode is intended for runtime cost reduction and population-level detection, not release acceptance.

## Runtime bootstrap

`bootstrap_integrity()` uses `RANDOMIZED_RUNTIME` by default. The initial root is still anchored using independently published fingerprints and the configured root threshold. The verified manifest and artifact hashes then govern module checks.

Applications requiring maximum local assurance may pass `SignatureVerificationMode.FULL_PUBLICATION`.

The supervised runner can perform this check before launching the application and
publish the distinct result to the operator console:

```bash
python -m caretaker.run \
  --integrity-publication-directory /opt/caretaker/publication \
  --integrity-artifact-root /opt/caretaker/source \
  --integrity-trusted-fingerprint FULL_PRIMARY_FINGERPRINT_A \
  --integrity-trusted-fingerprint FULL_PRIMARY_FINGERPRINT_B \
  --integrity-trusted-fingerprint FULL_PRIMARY_FINGERPRINT_C \
  your.application
```

The fingerprints are deliberately not inferred from `root.json`; obtain and
configure them through independent trusted channels. Configured verification is
fail-closed. Without these options, the console reports release integrity as
`NOT_CONFIGURED`. This result is separate from policy-authority, log-integrity,
and behavior-evidence signing.

For the included source-tree laboratory, the Makefile provides the equivalent
shortcut using the published Caretaker fingerprints recorded as overridable
Make defaults:

```bash
make lab-verified
```

For first-use bootstrap, high-assurance operation, or a fork with its own root,
override those defaults with fingerprints obtained independently:

```bash
make lab-verified \
  TRUSTED_FINGERPRINTS="FULL_FINGERPRINT_A FULL_FINGERPRINT_B FULL_FINGERPRINT_C"
```

The configured values are checked against the public certificates, root
signatures, signer authorization, and manifest signatures. A wrong override
fails startup. Defaults stored in the same repository provide convenience and
consistency after a trusted checkout; they cannot independently authenticate a
checkout that may already have been replaced.

This verifies the source tree described by the manifests. An installed wheel
has a different filesystem layout and needs a publication manifest generated
for that installed artifact tree; pointing a source-tree manifest at
`site-packages` will correctly fail rather than imply coverage.

## External trust bootstrap

Caretaker can verify continuity from a trusted root, but cannot prove the authenticity of the first local root by inspecting itself. Initial primary fingerprints must be confirmed independently through sources such as the project website, Web Key Directory, keyservers, or separately controlled release announcements.

```bash
caretaker-integrity verify-initial-root \
  --root root.json \
  --signature root.json.key-a.asc \
  --signature root.json.key-b.asc \
  --signature root.json.key-c.asc \
  --public-key caretaker-key-a.asc \
  --public-key caretaker-key-b.asc \
  --public-key caretaker-key-c.asc \
  --trusted-fingerprint FULL_PRIMARY_FINGERPRINT_A \
  --trusted-fingerprint FULL_PRIMARY_FINGERPRINT_B \
  --trusted-fingerprint FULL_PRIMARY_FINGERPRINT_C \
  --threshold 2
```

Providing all three root signatures causes all supplied signatures to be checked even though root authorization remains 2-of-3.

## Rolling rotation schedule

Root schema V2 assigns the three current primary identities to slots A, B, and C. The default signed rotation policy specifies:

- one scheduled slot rotation every 730 days;
- sequence A, then B, then C;
- one complete three-key cycle every 2,190 days, approximately six years;
- an advisory warning window before the next due date.

The `generation` field records completed scheduled rotations. The next expected slot and due date are displayed by `caretaker-integrity inspect` and included as verification warnings when near or past due.

The schedule does not replace cryptographic continuity. Replacing certificate C with D still requires a sequential root transition satisfying both the old and new 2-of-3 root policies:

```text
old root: A, B, C
new root: A, B, D
```

Emergency rotation remains an operational procedure; the fixed schedule is intended to limit long-lived exposure and make unexpected identity changes easier to notice.

## Anti-rollback state

A valid signature does not prove that a release is current. Retain the highest accepted root and manifest versions:

```bash
caretaker-integrity verify ... \
  --state-file ~/.local/state/caretaker/integrity.json \
  --accept-state
```

Later verification rejects older root or manifest versions. This local state is not resistant to an attacker who can replace both the verifier and the state file.

## Signed release code and generated repairs

Caretaker distinguishes:

- signed release code;
- generated ephemeral repair code with recorded provenance;
- unsigned and untracked code.

Generated repairs may be activated through a `FunctionSlot` after isolated validation, but they do not become signed release code. Promotion requires export, review, a new manifest, and the separate offline signatures.

## Protected and sealed components

The root metadata declares path patterns for protected and sealed components. These should include anything capable of weakening verification or activation, including canonicalization, root validation, anti-rollback state, candidate compilation, validation-worker launch, and enforcement-disable paths.

The two-signature root, not an ordinary release manifest, controls these classifications. Verification rejects downgrades, protected-path omissions, and unlisted files covered by signed coverage patterns.

## Public-key-only enforcement

Before import, supplied certificate files are inspected and files containing OpenPGP secret-key packets are rejected. Public certificates are imported into a temporary GnuPG home with minimal import options and removed after verification.

## Event storage

Integrity verifications and incidents are separate streams from repair incidents. A verification record contains:

- verification mode;
- selected and valid primary fingerprints;
- root and manifest versions;
- artifact results;
- rotation warnings;
- trust-anchor status.

This allows probabilistic results to be evaluated across a population without claiming that one sampled verification proves all three publication signatures.
