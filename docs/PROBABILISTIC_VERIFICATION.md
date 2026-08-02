# Probabilistic runtime verification

Caretaker release manifests are expected to carry detached OpenPGP signatures from all three authorized primary certificate identities. Independent release verification checks all three signatures. Runtime verification may instead select an unpredictable subset of those identities to reduce repeated verification cost and to distribute detection across a population of Caretaker installations.

This is an experimental fleet-detection mechanism. It is not stronger than full verification for an individual process.

## Signed-root policy

Root schema V2 separates three values for each role:

| Value | Meaning |
|---|---|
| `threshold` | Minimum authorization threshold used for root continuity and explicit threshold workflows |
| `publication_threshold` | Number of distinct signatures expected on a published manifest; Caretaker V2 requires all 3 |
| `runtime_sample_size` | Number of randomly selected identities verified at runtime |

The default V2 policy is:

| Role | Authorization | Publication | Runtime sample |
|---|---:|---:|---:|
| `release` | 1 of 3 | 3 of 3 | 1 of 3 |
| `protected` | 2 of 3 | 3 of 3 | 2 of 3 |
| `root` | 2 of 3 | 3 of 3 | 2 of 3 |

Protected and root runtime verification may not reduce the sample below the 2-of-3 authorization threshold.

## Verification modes

`SignatureVerificationMode` provides three explicit modes:

- `FULL_PUBLICATION`: verify all three published signatures. This is the default for the `caretaker-integrity verify` CLI and should be used for release acceptance, CI, forensic analysis, and manual verification.
- `AUTHORIZATION_THRESHOLD`: verify the role's minimum authorization threshold. This is used for root continuity and compatibility with schema V1.
- `RANDOMIZED_RUNTIME`: select identities with `secrets.SystemRandom` and verify only the role's runtime sample. `bootstrap_integrity` uses this mode by default.

Every verification record stores the mode and the selected primary fingerprints.

## Detection probabilities

For ordinary release code, one identity is selected uniformly:

| Compromised signing identities | Probability one runtime check accepts a forged manifest |
|---:|---:|
| 1 of 3 | 1/3 |
| 2 of 3 | 2/3 |
| 3 of 3 | 1 |

For protected or root code, two distinct identities are selected:

| Compromised signing identities | Probability one runtime check accepts a forged manifest |
|---:|---:|
| 1 of 3 | 0 |
| 2 of 3 | 1/3 |
| 3 of 3 | 1 |

If `N` installations make independent selections, the probability that all of them accept is the single-installation probability raised to `N`. Independence depends on uncompromised random selection and separate runtime environments.

These probabilities do not protect an installation whose verifier, random source, root metadata, or operating system has already been replaced by a privileged attacker.

## Signature-file handling

Randomized verification requires at least the signed root's `publication_threshold` number of detached signature files. It chooses expected primary fingerprints from the authenticated root, then searches the supplied signatures for a valid signature from each selected identity.

This prevents an attacker with key A from copying an A signature into all three signature filenames and automatically passing every check. Such a replacement passes only when the random selection consists entirely of compromised identities.

The unselected signatures are not asserted to be valid by a randomized verification result. Use full publication verification to establish that all three signatures are valid.

## Recommended use

- Perform full publication verification when accepting or installing a release.
- Persist the accepted root and manifest versions for rollback detection.
- Use randomized verification at process startup or controlled import boundaries where repeated full verification is considered too expensive.
- Periodically perform full verification even in runtime environments.
- Aggregate selected-identity and failure events across deployments without exposing private operational information.

Randomized verification should remain selectable. Applications requiring maximum local assurance should use `FULL_PUBLICATION` at runtime.

## Efficient signature mapping

For exact runtime cost, pass signatures as a mapping from authenticated primary fingerprint to detached signature path:

```python
signature_paths = {
    FINGERPRINT_A: "release-manifest.json.key-a.asc",
    FINGERPRINT_B: "release-manifest.json.key-b.asc",
    FINGERPRINT_C: "release-manifest.json.key-c.asc",
}
```

Caretaker requires the mapping to cover exactly the three authorized identities. It then performs exactly one signature verification for an ordinary runtime sample or two for a protected/root sample. The verified signature must resolve back to the fingerprint used as the mapping key.

A plain sequence remains supported for compatibility. With a sequence, Caretaker may need to probe several signatures to locate the randomly selected identity, which reduces the performance benefit.
