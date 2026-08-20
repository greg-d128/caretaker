# Separate offline signing station

Release-signing authority and private-key handling remain outside the Caretaker runtime. The inventory-driven `scripts/sign-artifacts.py` helper delegates detached signatures to GnuPG; it contains no key import, passphrase, private-key storage, or cryptographic implementation.

## Short, ordinary workflow

On the coordinator, place the three public certificates under their conventional
names, generate the manifests, inspect them, and create the minimal station bundle:

```bash
make generate-manifests RELEASE_MANIFEST_VERSION=1 PROTECTED_MANIFEST_VERSION=1
make inspect-integrity
make signing-bundle PUBLIC_KEY_DIR=release-keys SIGNING_BUNDLE_DIR=station-input
```

Transfer `station-input` to one signing station. After comparing its
`SHA256SUMS` and artifact hashes with the coordinator, use that station's slot:

```bash
cd station-input
make status
make check KEY_SLOT=a
make sign-check
make sign-all KEY_SLOT=a
```

Repeat in the independent B and C environments. The key fingerprint does not need
to be typed: `root.json` maps each slot to its authorized primary fingerprint, and
the check fails unless the station has a usable secret signing subkey for that
identity. Make never asks for a private key or OpenPGP passphrase; GnuPG owns any
passphrase interaction.

Root signatures are separate authorization artifacts, but no separate command
is needed. `sign-all` keeps a valid root signature and signs it only when the
selected slot is missing or no longer matches the current `root.json`.

Framework policy is another separately signed artifact. The current Caretaker
root authorizes it through the existing `protected` role, so no root change is
needed. After creating and reviewing a canonical framework authority layer, each
station signs the exact same file:

```bash
make sign-all KEY_SLOT=a
```

Repeat for B and C. Detached signatures are written beside each profile as `.key-a.asc`,
`.key-b.asc`, and `.key-c.asc`. Configure the
authority stack with `role = "protected"`, `verification_mode =
"full-publication"`, and all three signature paths. The command rejects
non-canonical JSON, a non-framework layer, an unknown role, an unauthorized
slot and an unavailable secret signing subkey. It
does not create or decide the contents of the framework policy.

For the three reviewed profiles shipped in the wheel, one station can sign its
entire profile set with a single slot selection:

```bash
make sign-all KEY_SLOT=a
```

After A, B, and C profile signatures return to the coordinator, the coordinator
runs `make wheel-manifests`. Each station then signs the two installed-layout
manifests:

```bash
make sign-all KEY_SLOT=a
```

The wheel build refuses to proceed until the root, production profiles, and both
wheel manifests have all expected signatures. Sandbox remains deliberately
unsigned and is not part of `sign-all`.

`MANIFEST.in` is Python packaging metadata and is not the canonical integrity
manifest. Do not sign it as a substitute for `release-manifest.json`.

`sign-check` verifies every conventional slot signature over root, both source
manifests, the three production profiles, and both wheel manifests. It reports
`VALID`, `MISSING`, or `STALE/INVALID`; `KEY MISMATCH` identifies a public
certificate that disagrees with `root.json`, and wheel manifests are `PENDING`
until generated. `sign-all` keeps valid signatures and atomically replaces a stale
signature only after the new signature verifies. It displays the artifact
SHA-256 before signing.

Run the target separately for keys A, B, and C, preferably in independent signing environments as described below. The Make target is convenience, not a replacement for manifest review or threshold independence.

## Reviewable Make workflow

The coordinator validates the finalized public root and generates both manifests:

```bash
make root-check PUBLIC_KEY_DIR=release-keys
make release-check PUBLIC_KEY_DIR=release-keys
make generate-manifests RELEASE_MANIFEST_VERSION=1 PROTECTED_MANIFEST_VERSION=1
make inspect-integrity
make signing-status PUBLICATION_DIR=.
```

The attended equivalent prompts for the two version numbers:

```text
$ make generate-manifests
Release manifest version (positive integer): 1
Protected manifest version (positive integer): 1
```

For automation, keep inputs explicit:

```bash
make generate-manifests \
  RELEASE_MANIFEST_VERSION=1 \
  PROTECTED_MANIFEST_VERSION=1
```

`root-check` rejects placeholder or duplicate primary fingerprints, role/slot
mismatches, non-canonical JSON, unmatched protected paths, secret material in a
supplied certificate, and certificates without usable signing subkeys.
Manifest targets refuse to replace an existing manifest unless the operator
explicitly supplies `FORCE=1` after deciding that regeneration is intended.
Generation excludes Python bytecode and `__pycache__` contents automatically;
these interpreter-specific build artifacts must never enter a source manifest.
It does not run `make clean` or otherwise delete files from the source tree.

On signing station A, after independently comparing the document hashes:

```bash
make signing-check KEY_SLOT=a
make sign-check
make sign-all KEY_SLOT=a
```

Or allow the attended command to request the public identifiers once:

```text
$ make sign-all
Key slot (a, b, or c): a
```

Stations B and C use their own slot and primary fingerprint. `signing-check`
requires the slot to match `root.json` and requires a usable secret signing
subkey. The certification-only primary identity need not perform the signature.

After collecting the three public certificates and all detached signatures in
one directory, perform complete publication verification:

```bash
make verify-publication PUBLICATION_DIR=.
```

By default, publication verification reads public certificates from
`release-keys/`. Set `PUBLIC_KEY_DIR` explicitly when they are stored elsewhere.

For a single detached signature already known to the local GnuPG keyring:

```bash
make verify-signature \
  MANIFEST=release-manifest.json \
  SIGNATURE=release-manifest.json.key-a.asc
```

## Next steps printed by the commands

The quality-of-life targets finish with an explicit **Next steps** block:

- manifest generation directs the coordinator to inspect the canonical JSON,
  record its hash, and transfer the reviewed files to signing stations;
- `signing-check` identifies the corresponding `sign-all` invocation;
- signing directs the station operator to export only `.asc` files, return them
  with the reviewed hashes, and repeat independently for the remaining slots;
- after A, B, and C signatures are collected, run `make verify-publication
  PUBLICATION_DIR=.` on the complete public directory.

Example complete station workflow:

```bash
make sign-check
make sign-all KEY_SLOT=c
# Return every .key-c.asc file reported as created or replaced.
```

Do not run `FORCE=1` merely because a manifest or signature already exists.
First determine whether it is the already-reviewed artifact. `sign-all` replaces
only signatures that fail to match their current artifact.

A dedicated Raspberry Pi can be used as a medium-assurance research signing environment when it is narrowly configured and normally offline.

## Recommended role

```text
Dedicated Raspberry Pi
├── minimal operating system
├── GnuPG
├── independent signing coordinator
├── manifest and diff inspection tools
├── public Caretaker certificates
├── no Caretaker runtime
├── no browser, email, IDE, or general development use
├── no persistent release private keys
└── no routine network connection
```

## Signing session

1. Build an unsigned canonical manifest on the development system.
2. Transfer the manifest, release artifacts, and a review report to the signing station.
3. Display the manifest SHA-256, root version, release version, changed paths, and protected-path changes.
4. Compare these values with the expected release information.
5. Introduce exactly one encrypted private-key export for the current session.
6. Produce one detached OpenPGP signature.
7. Verify the signature locally with the public certificate.
8. Export only the detached signature and a verification report.
9. Terminate the dedicated `gpg-agent` and remove temporary key material.
10. Repeat in separate sessions for keys B and C so the publication has all three signatures.
11. Perform full three-signature verification before release.
12. Power off the station.

## Piping from `pass`

A direct pipe is preferable to placing a private key on the desktop clipboard or in a command-line argument:

```bash
set -o pipefail
pass show caretaker/signing/key-a | /opt/caretaker-sign/bin/caretaker-sign \
  --manifest protected-manifest.json \
  --output protected-manifest.json.key-a.asc
```

The separate coordinator should route standard input directly into GnuPG import. It should not read the complete private key into a Python `str`, print it, log it, place it in an environment variable, or accept it as a command-line option.

The imported private key should itself remain passphrase encrypted. Protection by the password store and protection by the OpenPGP key passphrase should use independent credentials where practical.

## Temporary GnuPG home

Use an isolated temporary GnuPG home, preferably on memory-backed storage:

```bash
GNUPGHOME="$(mktemp -d /dev/shm/caretaker-sign.XXXXXX)"
chmod 700 "$GNUPGHOME"
export GNUPGHOME
```

After signing:

```bash
gpgconf --homedir "$GNUPGHOME" --kill gpg-agent
rm -rf -- "$GNUPGHOME"
unset GNUPGHOME
```

This reduces persistent-disk exposure but is not a secure enclave. Secret material still temporarily exists in process memory, kernel pipe buffers, GnuPG, and the temporary agent environment.

## Threshold independence

Three cryptographic keys provide limited benefit if all three are exposed through one machine, account, vault credential, and session.

Every published manifest is expected to receive signatures from A, B, and C. Each signature should be created in a separate clean session, with the exact same manifest hash reviewed before signing. Protected and root authorization still requires only two identities for continuity and key rotation, but publication verification checks all three signatures.

Recommended sequence:

- sign with key A in one clean session;
- destroy that session's temporary key material;
- independently review the same manifest hash;
- sign with key B in a separate session;
- destroy that session;
- review the same hash again and sign with key C;
- preferably use more than one device or independently administered environment across the three sessions.

Loading two threshold keys into one operating-system session materially weakens the threshold model.

A practical initial arrangement is:

```text
Key A: signing vault and station A
Key B: independently administered signing environment B
Key C: recovery-oriented vault and separate signing session C
```

## Raspberry Pi hardening

Recommended controls include:

- Raspberry Pi OS Lite or another minimal image;
- dedicated unprivileged signing account;
- SSH disabled after provisioning;
- Wi-Fi and Bluetooth disabled;
- Ethernet physically disconnected during signing;
- direct console access;
- core dumps disabled;
- shell tracing disabled;
- no unrelated services;
- `tmpfs` for session data;
- high-quality storage and a documented rebuild procedure;
- periodic reimaging from a reviewed image;
- an offline hash of the accepted station image.

Secure boot and hardware tokens may be added later. A hardware token should not be the only recoverable copy of a root identity; an encrypted offline recovery procedure should exist.

## Common failure domain warning

A single dedicated Pi is substantially better than signing on the development workstation. It is not equivalent to two independent signing environments. The strongest practical improvement to the 2-of-3 model is operational independence between the two signers used for protected changes.
