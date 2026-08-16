# Separate offline signing station

Release-signing authority and private-key handling remain outside the Caretaker runtime. The repository includes a small `scripts/sign-code.sh` convenience wrapper that delegates one detached signature to GnuPG; it contains no key import, passphrase, private-key storage, or cryptographic implementation.

## Simple manifest signing

After generating and reviewing a canonical manifest, sign it with one full primary fingerprint and an explicit output path:

```bash
make sign \
  MANIFEST=release-manifest.json \
  SIGNING_KEY=FULL_PRIMARY_FINGERPRINT_A \
  SIGNATURE=release-manifest.json.key-a.asc
```

The target displays the manifest SHA-256, asks the configured GnuPG environment to create an armored detached signature, and immediately runs `gpg --verify`. It refuses to overwrite an existing signature. The script does not generate a manifest, select a key, import private material, or decide that the reviewed bytes are suitable for release.

Run the target separately for keys A, B, and C, preferably in independent signing environments as described below. The Make target is convenience, not a replacement for manifest review or threshold independence.

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
