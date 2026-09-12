# Verify integrity

## Task

Verify signed Caretaker roots, manifests, and installed artifact bytes.

## Audience

Operators and release engineers.

## Status

Environment-dependent.

## Supported package versions

Caretaker `0.6.5a0`, contract line `caretaker-0.6.5`.

## Use when

Bootstrapping trust from an independently obtained fingerprint set or checking
an installed wheel's signed publication bundle.

## Do not use when

Calling an unsigned alpha artifact trusted, inferring initial authenticity from
the repository itself, or treating randomized runtime sampling as release proof.

## Prerequisites

Have GnuPG, the published root/manifest/signatures and public certificates, and
trusted primary fingerprints obtained through an independent channel.

## Minimal command or code

```console
caretaker-integrity verify-install
```

For a source publication use `caretaker-integrity verify` with `--root`,
`--manifest`, repeated `--signature`, `--public-key`, and
`--trusted-fingerprint` options, plus `--artifact-root`.

## Required configuration

Use full publication verification for release acceptance. Provide a state file
and `--accept-state` when anti-rollback continuity is required. External-signed
runtime records require an approved external signer; they do not fall back to
ephemeral signing.

## Expected result

The verifier checks signer identity, threshold, canonical JSON, path classes,
size, SHA-256, and optional anti-rollback state. Invalid or missing trust data
fails closed.

## Verification

Record selected fingerprints, root/manifest versions, artifact results, mode,
warnings, and exact hashes. Compare with the release candidate record.

## Common failures

Missing GnuPG, signatures/certificates, wrong fingerprints, stale state, bad
canonical bytes, or changed artifacts. Obtain trust anchors independently.

## Security and scope limitations

Manifest signatures authenticate listed bytes, not the first local root. The
runtime has no private-key interface and cannot sign releases.

## Related tasks

`tasks.select-a-profile`, `tasks.supervised-startup`, `global.safety-boundaries`.

## Canonical documentation

`docs/INTEGRITY.md`, `docs/OPENPGP_VERIFICATION.md`, and
`docs/RELEASE_CANDIDATE_WORKFLOW.md`.
