# Runtime logging integrity

## Hash chaining

The minimum mode hashes each closed segment and commits to the previous segment hash. This detects accidental damage and modification when an original commitment is known. A fully local attacker able to rewrite the entire corpus can recalculate an unanchored chain.

## Ephemeral signing

In `EPHEMERAL_SIGNED` mode, Caretaker generates an Ed25519 runtime identity. The private key is never intentionally persisted, logged, attached, sent to an LLM, or returned over the control interface.

Closed manifests are signed. The public identity is logged and available to local control clients.

### Key evolution

The signing key evolves under policy, every 86,400 seconds by default. Before replacing an epoch key, the old key signs a transition committing to the new public key and epoch metadata. The old key is then released and zeroized to the extent supported by the selected cryptographic backend.

Later compromise should not automatically permit forging earlier epochs if old key material was successfully discarded.

### Limitations

Python cannot prove that all memory copies have been overwritten. Crash dumps, swap, process inspection, allocator behavior, native-library copies, or a same-user attacker may expose key material.

A self-recorded public key establishes internal consistency but not independent provenance. Export the fingerprint, witness it externally, or use an external signer to prevent wholesale replacement of both corpus and identity.

## External signing

The external signer protocol accepts only a manifest commitment and metadata. Persistent private keys remain outside Caretaker. This is stronger than runtime ephemeral signing when the signer is independently protected.

## External log collection

A separate logging agent and independent collection server materially improve security. An attacker must compromise or intercept both the application-side evidence and the external copy. Caretaker's future sink interface is designed for such replication, while the alpha keeps the built-in writer local-only.
