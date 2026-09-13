# Configure Ollama endpoint security

## Task

Choose the endpoint security mode shared by every Caretaker Ollama provider.

## Audience

Programmer or operator integrating an Ollama-backed provider.

## Status

Implemented; remote modes are environment-dependent.

## Supported package versions

Caretaker 0.6.5 on contract line `caretaker-0.6.5`.

## Use when

An Ollama endpoint is used for Repair, Guard behavior assessment, behavior
analysis, root-cause interrogation, capsule assistance, or communication
tailoring.

## Do not use when

You need model output to authorize Repair, change policy, publish artifacts, or
make a trust decision. Those decisions remain deterministic and policy-bound.

## Prerequisites

Caretaker is installed; the endpoint, model, and application policy are known.
Remote verified modes additionally require HTTPS and a trusted CA; attested
mode requires an operator-signed attestation and trusted Ed25519 public key.

## Minimal command or code

```python
from caretaker import OllamaEndpointPolicy, OllamaRepairProvider

security = OllamaEndpointPolicy(mode="remote_server_verified", ca_bundle="ca.pem")
provider = OllamaRepairProvider("model", base_url="https://ollama.example", endpoint_policy=security)
```

## Required configuration

Use `local_only` by default. `remote_unverified` requires
`accept_remote_risk=True` and warns that the service may be impersonated,
modified, monitored, or unavailable. Server-verified and attested modes require
HTTPS; configure optional certificate/SPKI pins, mTLS files, or attestation
fields as documented.

## Expected result

The selected policy is enforced before requests. Status is `LOCAL_ONLY`,
`REMOTE_UNVERIFIED`, `REMOTE_SERVER_VERIFIED`, or `REMOTE_ATTESTED`.

## Verification

Inspect the provider `endpoint_security_status` or the supervised
`ollama-security-status` control response. Confirm that the endpoint is
canonical, credentials are absent, and warnings match the selected mode.

## Common failures

Remote endpoints fail under `local_only`; HTTP fails under verified modes;
missing risk acknowledgement, invalid TLS, pin mismatch, and missing or
mismatched attestations fail closed.

## Security and scope limitations

TLS proves HTTPS endpoint identity, not the Ollama process or model. Attestation
is an operator assertion, not hardware-backed runtime attestation. Remote model
output is bounded, untrusted advisory input.

## Related tasks

`tasks.supervised-startup`, `tasks.configure-repair`, `tasks.inspect-evidence`.

## Canonical documentation

`docs/OLLAMA_ENDPOINT_SECURITY.md` and `docs/POLICY_SEMANTICS.md`.
