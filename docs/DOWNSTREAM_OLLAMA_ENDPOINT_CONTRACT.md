# Downstream contract notes: Ollama endpoint security

These notes are for Validator and Crucible maintainers. They do not modify or
claim conformance for either repository.

Caretaker 0.6.5 defines one endpoint policy with modes `local_only`,
`remote_unverified`, `remote_server_verified`, and `remote_attested`. The
default is `local_only`; the deprecated `allow_remote_endpoint=True` shim maps
to explicitly warned `remote_unverified`.

Downstream checks should treat `REMOTE_UNVERIFIED`,
`REMOTE_SERVER_VERIFIED`, and `REMOTE_ATTESTED` as distinct statuses. TLS
server verification proves the HTTPS endpoint identity only. Attested mode is
an operator-signed, time-bounded assertion binding endpoint, certificate or
SPKI fingerprint, deployment, model identity, provider purpose, and operator;
it is not a hardware-runtime-attestation claim.

Every Ollama consumer uses bounded strict JSON transport, timeout enforcement,
model response checks, same-origin redirect rejection, and advisory-only
output. Remote model output must not satisfy deterministic validation,
authority, publication, policy, or trust decisions.

Validator should preserve these statuses and warnings in external validation
evidence without converting them into release trust. Crucible should test all
consumer paths against the same policy and should update the ordinary-provider
expectation to the explicit fail-closed response contract (or record a
separate advisory-only compatibility expectation). Neither downstream suite
should require a real external Ollama service; local HTTP/TLS fakes are enough.
