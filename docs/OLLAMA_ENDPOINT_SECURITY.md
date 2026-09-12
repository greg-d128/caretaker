# Ollama endpoint security

Caretaker uses one explicit `OllamaEndpointPolicy` for every Ollama-backed
provider. The default is `local_only`. This policy controls endpoint transport
only; it never gives model output authority to approve Repair, change policy,
publish artifacts, or make an integrity decision.

## Modes

| Mode | Transport | Meaning |
| --- | --- | --- |
| `local_only` | loopback HTTP or HTTPS | Default. Non-loopback hosts are rejected. |
| `remote_unverified` | explicitly selected HTTP or HTTPS | Requires `accept_remote_risk=true`; reports `REMOTE_UNVERIFIED` and warns that the service may be impersonated, modified, monitored, or unavailable. |
| `remote_server_verified` | HTTPS only | Uses normal certificate-chain and hostname verification, the system trust store or `ca_bundle`, and optional certificate/SPKI pins. Reports `REMOTE_SERVER_VERIFIED`. |
| `remote_attested` | HTTPS only | Adds a signed, time-bounded operator attestation and fails closed on any mismatch. Reports `REMOTE_ATTESTED`. |

The old `allow_remote_endpoint=True` argument remains only as a deprecated
compatibility shim and maps to `remote_unverified` with risk acknowledgement.
New code should pass `OllamaEndpointPolicy` explicitly.

## Configuration

For a supervised application, place this section in the TOML policy:

```toml
[logging.ollama]
endpoint_mode = "remote_server_verified"
endpoint = "https://ollama.example.internal/api/generate"
ca_bundle = "/etc/caretaker/ollama-ca.pem"
spki_pins = ["sha256:<new-pin>", "sha256:<old-pin>"] # overlap during rotation
client_cert = "/etc/caretaker/client.crt" # optional mTLS
client_key = "/etc/caretaker/client.key"   # never printed in status
```

Python callers pass the same object to each provider:

```python
from caretaker import OllamaEndpointMode, OllamaEndpointPolicy, OllamaRepairProvider

endpoint_policy = OllamaEndpointPolicy(
    mode=OllamaEndpointMode.REMOTE_SERVER_VERIFIED,
    ca_bundle="/etc/caretaker/ollama-ca.pem",
)
provider = OllamaRepairProvider(
    "model-name", base_url="https://ollama.example.internal",
    endpoint_policy=endpoint_policy,
)
```

Equivalent environment variables are available for deployments that already
manage configuration through the environment: `CARETAKER_OLLAMA_ENDPOINT_MODE`,
`CARETAKER_OLLAMA_CA_BUNDLE`, `CARETAKER_OLLAMA_SPKI_PINS`,
`CARETAKER_OLLAMA_CERTIFICATE_PINS`, `CARETAKER_OLLAMA_CLIENT_CERT`,
`CARETAKER_OLLAMA_CLIENT_KEY`, `CARETAKER_OLLAMA_ATTESTATION`,
`CARETAKER_OLLAMA_ATTESTATION_PUBLIC_KEY`,
`CARETAKER_OLLAMA_ACCEPT_REMOTE_RISK`, and
`CARETAKER_OLLAMA_INSECURE_TLS`. Pin lists are comma-separated.

The direct provider CLIs expose equivalent `--ollama-*` options. The supervised
runtime uses its loaded `[logging.ollama]` policy as authoritative; a control
request with a different policy is rejected rather than silently weakening the
runtime decision. `ollama-security-status` returns machine-readable status.

## TLS and deployment guidance

Use a reverse proxy with a stable HTTPS name and a private CA for private
deployments. A custom CA enables chain validation; it does not disable hostname
verification. Certificate/SPKI pins are optional. During rotation configure
both the old and new pin, deploy the new certificate, then remove the old pin
after all clients have rotated. Cross-origin redirects are rejected and
credentials in endpoint URLs are rejected.

mTLS can be configured with a client certificate and private key. Caretaker
does not include key paths' contents, bearer tokens, or API keys in diagnostics.

`remote_unverified` is intended for explicit testing or a consciously accepted
risk. HTTP is permitted only there. `insecure_tls=true` is permitted only in
that mode and produces an additional warning; it is never implicit.

TLS certificate verification establishes the HTTPS endpoint identity. It does
not prove that the endpoint runs the intended Ollama process or model. Attested
mode is operator attestation, not hardware-backed or cryptographic runtime
attestation.

## Attestation format

The attestation is a JSON object signed with Ed25519 over canonical JSON
(sorted keys, compact separators, UTF-8) with `signature` removed. It must
contain `format_version`, `endpoint`, `deployment_id`, `model`, either
`model_digest` or immutable `model_identity`, `provider_purpose`,
`attesting_operator`, `issued_at`, `expires_at`, and base64 `signature`.
`certificate_sha256` and/or `spki_sha256` bind it to the observed TLS peer when
present. Caretaker verifies the signature, time window, endpoint, deployment,
model, provider purpose, certificate/fingerprint, and model digest when the
service returns one. The trusted Ed25519 public key is configured separately.

Attestations are operator assertions. They do not authorize a repair and do not
replace Caretaker's deterministic policy, validation, authority, or integrity
gates.

## Migration

Replace:

```python
OllamaRepairProvider("model", base_url=url, allow_remote_endpoint=True)
```

with an explicit mode and acknowledgement:

```python
OllamaRepairProvider(
    "model", base_url=url,
    endpoint_policy=OllamaEndpointPolicy(
        mode="remote_unverified", accept_remote_risk=True,
    ),
)
```

Prefer `remote_server_verified` or `remote_attested` for production. Keep
`local_only` for the default and for local testing.
