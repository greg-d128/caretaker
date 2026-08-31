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


## Assurance reporting

Runtime status now reports the record-integrity mode separately from identity anchoring. A healthy hash chain is not reported as corpus-replacement resistant. Only externally anchored/signed configurations claim that stronger property.

### Supervised external signer configuration

The normal supervisor entry point can load an operator-provided signer without placing persistent private-key configuration in application code:

```bash
python -m caretaker.run \
  --policy /etc/caretaker/application.toml \
  --external-signer organization.signing:caretaker_signer \
  application.module
```

The referenced attribute may be a signer instance, class, or zero-argument factory and must expose `public_identity()` plus `sign_artifact()` (or the legacy `sign_manifest()`). In `EXTERNAL_SIGNED` mode an absent/invalid signer fails rather than falling back to ephemeral signing.

`publish_public_key_to_control_clients` controls whether the current public signing identity is returned by supervisor status/health requests. The independently retained Signing Identity Journal remains the durable verification source for ephemeral artifact history.

## Audit-stream signing policy

The `caretaker_audit.log` local stream currently uses canonical JSON and a
policy-controlled hash chain. Per-event signing uses the same canonicalization
and signer interfaces as runtime artifact manifests, with the decision
controlled by `logging.audit.sign_events`. A least-friction deployment may use
a local stream with checksums; a reviewed deployment may require a hash chain
and `EPHEMERAL_SIGNED`; a high-assurance deployment may require an external
signer. These modes are assurance choices, not authority grants.

When `sign_events = true`, every newly written event carries an
`artifact_signature` whose `artifact_kind` is `caretaker-audit-event` and whose
context binds the event ID, event type, and stream sequence. The writer verifies
retained signatures during restart recovery using the public signing-identity
journal. Missing, malformed, mismatched, or unverifiable signatures fail
recovery; no signed configuration silently falls back to hash-only output.
The default is `sign_events = false` and `signing.mode = HASH_CHAINED`.

The current console records a UUID-scoped invocation, OS UID/GID, and peer
process identity in the audit stream so an action can be attributed to a
console session. When the signing extra is available, it also creates an
ephemeral, memory-only console signing key, publishes the public-key
fingerprint, and stores the public identity in the supervisor's
`security/console-identities.sqlite` journal. Such a key authenticates session
attribution; it does not authorize a
deployment-layer change. Permanent deployment changes continue to require the
configured `policy-deployment` authority and its independently verifiable
credentials. A deployment-aware console may present or request that credential,
but must not derive it from a console key.

Hash chaining detects alteration of a retained stream but does not prevent
wholesale replacement of an unanchored local stream. The external sink should
therefore receive critical audit events in real time, with bounded local
store-and-forward for outages. The sink is a security boundary and must never be
treated as a command channel. A full implementation still requires an external
security review covering injection, replay, key lifecycle, redaction, delivery
failure, and local-disk exhaustion.
