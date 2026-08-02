# Independent OpenPGP verification

Caretaker verification must not require trusting Caretaker's own verifier. The project therefore uses standard detached OpenPGP signatures and can print a shell procedure using independently downloaded public certificates.

## Print commands

```bash
caretaker-integrity instructions \
  --root root.json \
  --manifest release-manifest.json \
  --root-signature root.json.key-a.asc \
  --root-signature root.json.key-b.asc \
  --root-signature root.json.key-c.asc \
  --trusted-fingerprint FULL_PRIMARY_FINGERPRINT_A \
  --trusted-fingerprint FULL_PRIMARY_FINGERPRINT_B \
  --trusted-fingerprint FULL_PRIMARY_FINGERPRINT_C \
  --signature release-manifest.json.key-a.asc \
  --signature release-manifest.json.key-b.asc \
  --signature release-manifest.json.key-c.asc \
  --public-key caretaker-key-a.asc \
  --public-key caretaker-key-b.asc \
  --public-key caretaker-key-c.asc \
  --artifact-root .
```

The output creates a temporary GnuPG home, imports only the supplied certificates, displays full fingerprints, verifies detached signatures, and checks every manifest hash with `sha256sum`.

## Manual outline

```bash
GNUPGHOME="$(mktemp -d)"
chmod 700 "$GNUPGHOME"

# Public certificates should be downloaded independently of the code archive.
gpg --homedir "$GNUPGHOME" --batch --no-auto-key-retrieve \
  --import caretaker-key-a.asc caretaker-key-b.asc caretaker-key-c.asc

# Compare all displayed primary fingerprints with independently published values.
gpg --homedir "$GNUPGHOME" --with-colons --fingerprint --list-keys

# Verify the exact detached signature and manifest pair.
gpg --homedir "$GNUPGHOME" --batch --no-auto-key-retrieve \
  --status-fd=1 --verify release-manifest.json.key-a.asc release-manifest.json
```

For a published Caretaker manifest, repeat `gpg --verify` for all three detached signatures and confirm that they resolve to the three authorized primary fingerprints. The protected and root authorization threshold remains 2-of-3 for continuity and rotation, but the publication procedure deliberately produces all three signatures.

The signature authenticates the manifest. To verify the code independently, convert manifest entries to GNU `sha256sum` format:

```bash
python3 - release-manifest.json <<'PY' | sha256sum --check -
import json, pathlib, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for item in manifest["artifacts"]:
    path = item["path"]
    if "\n" in path or "\r" in path:
        raise SystemExit("unsafe newline in artifact path")
    print(f"{item['sha256']}  {path}")
PY
```

## Why full fingerprints matter

Do not authorize signatures using names, email addresses, short key IDs, or signature filenames. The role policy contains full primary certificate fingerprints.

When a signing subkey is used, GnuPG reports both the signing fingerprint and the primary certificate fingerprint. Caretaker counts the primary certificate identity toward the threshold.

## GPG and GPGV

`gpg --verify` is used by the Caretaker verifier because it provides detailed status about expired and revoked keys. `gpgv` is also useful for independent cryptographic verification against an explicitly supplied trusted keyring, but it treats keys in that keyring as trusted and does not by itself implement Caretaker's project thresholds, rotation state, or anti-rollback policy.

## No automatic key retrieval

Verification disables automatic key retrieval. This prevents an untrusted signature or network source from silently choosing the public certificate used for authorization. Obtain certificates independently and pass them explicitly.

## Executable threshold script

The generated `instructions` output is not merely a list of individual `gpg --verify` examples. It includes a shell function that:

- extracts the primary fingerprint from `VALIDSIG` status records;
- checks it against an explicit authorized fingerprint set;
- deduplicates repeated signatures from the same primary identity;
- enforces the external root threshold and the manifest's full publication signature requirement;
- then checks all signed SHA-256 values.

The script is intended to be inspected before execution. It does not retrieve keys from the network.

## Runtime sampling is different

The generated independent script always performs full publication verification. It does not emulate Caretaker's randomized runtime mode. Runtime sampling verifies only identities selected from the authenticated root and records those identities in the verification event. See `PROBABILISTIC_VERIFICATION.md`.
