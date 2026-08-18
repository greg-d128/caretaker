# Policy authority and signed guarantee layers

Caretaker separates **effective behavior** from **claims about who authorized that behavior**.
A machine owner or deployment administrator can ultimately modify an open-source Python
application. Caretaker therefore does not pretend that a policy can make the machine owner
physically unable to change software. Instead, policy authority makes weakening or overriding
higher-level guarantees explicit, attributable, and cryptographically verifiable when signing is
configured.

The central rule is:

> A lower authority may override a higher authority's constraint, but it cannot continue to claim
> that the higher authority's guarantee is satisfied.

This is different from a traditional configuration lock. A deployment remains operable during an
incident, while the console and evidence record make the resulting assurance level visible.

## Authority stack

The supervisor owns the authoritative policy stack in this order:

1. **Framework authority** — normally the Caretaker project/distribution authority.
2. **Application authority** — optional application-owner values and constraints.
3. **Deployment authority** — site/release/deployment selections and constraints.
4. **Runtime leases** — temporary, narrowly scoped operator overlays.

The application-author layer may be omitted. A deployment can also run with all authority layers
unsigned. Signing raises assurance; it is not required for ordinary Caretaker operation unless a
higher layer explicitly requires it.

Each static authority layer is immutable canonical JSON and may contain:

- **settings** — values selected by that authority;
- **constraints** — conditions that must remain true for that authority's guarantee to remain
  satisfied;
- **parent fingerprints** — exact SHA-256 fingerprints of every loaded higher authority layer;
- generation, creation/expiration timestamps, authority identity, and metadata.

The deployment stack descriptor is TOML. It locates layers, detached signatures, trust roots, and
public certificates. The descriptor itself is not the trust anchor; the signed canonical layer and
its authorized signer identity are.

## Settings, constraints, and overrides

A setting selects behavior:

```json
{"path":"repair.authority","target":"billing.*","value":"REQUIRE_OPERATOR_APPROVAL"}
```

A constraint defines a guarantee:

```json
{"operator":"allowed-values","path":"repair.authority","target":"billing.*","value":["ANALYZE_ONLY","PROPOSE_ONLY","REQUIRE_OPERATOR_APPROVAL"]}
```

A lower authority that intentionally exceeds that guarantee must say so explicitly:

```json
{
  "override_constraints": true,
  "path": "repair.authority",
  "reason": "Emergency unattended recovery approved by deployment owner",
  "target": "billing.charge",
  "value": "AUTOMATIC_ELIGIBLE_REPAIRS"
}
```

Without `override_constraints=true`, Caretaker rejects the conflicting effective policy and
explains the conflicting authority, path, constraint, and observed value. Explicit overrides
remain operationally valid but mark the higher guarantee `VIOLATED`.

An explicit override always requires a reason.

## Parent binding and substitution resistance

Every lower static layer must reference the exact fingerprint of every higher loaded layer. For
example, with framework + application + deployment layers, the deployment layer contains both:

```json
"parents": {
  "framework": "<framework-policy-sha256>",
  "application": "<application-policy-sha256>"
}
```

The application layer references the framework layer. If the application-author layer is omitted,
the deployment layer references only the framework layer.

Caretaker refuses to reconcile a stack whose parent fingerprints are missing or do not match.
This prevents an old or unrelated lower policy from being silently combined with a different
higher authority generation.

## Signing and trust

Authority signing reuses Caretaker's existing external OpenPGP verifier. Caretaker does not add a
second private-key or cryptographic implementation.

A stack descriptor can define default trust material:

```toml
schema_version = 1

[trust]
root = "/etc/caretaker/authority-root.json"
public_keys = [
  "/etc/caretaker/keys/project.asc",
  "/etc/caretaker/keys/application.asc",
  "/etc/caretaker/keys/deployment.asc",
]

[[layers]]
kind = "framework"
path = "framework-policy.json"
role = "policy-framework"
signatures = ["framework-policy.json.asc"]
require_signature = true
verification_mode = "authorization-threshold"

[[layers]]
kind = "application"
path = "application-policy.json"
role = "policy-application"
signatures = ["application-policy.json.asc"]
require_signature = true
verification_mode = "authorization-threshold"

[[layers]]
kind = "deployment"
path = "deployment-policy.json"
role = "policy-deployment"
signatures = ["deployment-policy.json.asc"]
require_signature = true
verification_mode = "authorization-threshold"
```

The application section may be omitted completely.

If a layer has no signatures and signing is not required, its state is `UNSIGNED`. If signatures
are present but invalid, unauthorized, or cannot be verified, the state is **not** treated as
unsigned: stack loading fails. `INVALID`, `UNAVAILABLE`, and `UNSIGNED` are intentionally distinct.

Policy authority does not replace Caretaker distribution verification. In a high-assurance
deployment, the Caretaker release/root material and policy signatures must be independently
validated using external `gpg`/`sha256sum` procedures before trusting the running verifier. See
`OPENPGP_VERIFICATION.md`.

A modified fork may use its own authority root and signatures. What it cannot do is produce a
signature from the official Caretaker private identities. The official-distribution claim therefore
continues to depend on independently anchored public fingerprints and external GPG verification.

### External GPG validation

For every signed policy layer, use an independently obtained certificate and verify the detached
signature outside Caretaker:

```bash
GNUPGHOME="$(mktemp -d)"
chmod 700 "$GNUPGHOME"

gpg --homedir "$GNUPGHOME" --batch --no-auto-key-retrieve \
  --import application-owner.asc

gpg --homedir "$GNUPGHOME" --with-colons --fingerprint --list-keys

gpg --homedir "$GNUPGHOME" --batch --no-auto-key-retrieve \
  --status-fd=1 --verify application-policy.json.asc application-policy.json
```

Then confirm the reported **primary fingerprint** is authorized for the role in the independently
trusted root. `gpg --verify` proves the signature; authorization still requires checking the signer
against the trusted role definition. The same principle applies to framework and deployment
layers.

Caretaker policy manifests must be canonical JSON before signing. Reformatting signed JSON changes
the signed bytes and invalidates the detached signature.

## Starting with an authority stack

```bash
python -m caretaker.run \
  --policy /etc/caretaker/invoice-service.toml \
  --authority-stack /etc/caretaker/policy-authority/stack.toml \
  invoice_service
```

The supervisor:

1. loads and verifies static authority layers;
2. verifies exact parent fingerprints;
3. reconciles authority settings with the ordinary Caretaker configuration;
4. refuses unresolved conflicts;
5. creates an immutable effective authority generation and fingerprint;
6. writes a canonical effective snapshot under `policy/authority-effective.json`;
7. gives the application process that generation;
8. continuously compares the application's reported generation/fingerprint with the supervisor's
   authoritative value.

The effective snapshot is runtime state, not a new trust anchor. The original signed layers and
external root remain authoritative.

## Runtime leases and incident escalation

Temporary incident escalation is represented by a **runtime authority lease**, not by editing a
signed static layer.

By default, runtime leases may be unsigned. This is deliberate: an operator who already has full
administrative access to the running application should not be blocked from restoring service
because a signing station is unavailable. The tradeoff is visible in assurance reporting.

A runtime lease records:

- lease ID;
- requesting local UID;
- reason;
- start and expiration time;
- exact setting(s) changed;
- target selector where applicable;
- whether higher constraints were intentionally overridden;
- signature state and signed-source fingerprint when applicable.

All acquisitions, releases, expirations, generation changes, and detected runtime-policy mismatches
are written to Caretaker evidence.

Temporary `repair.*` and `lightweight.*` leases require an explicit target ID or glob. They cannot silently escalate
all Repair targets. Some startup-bound settings, including `system.*` and `logging.directory`, are
not accepted as runtime leases; make those changes in a deployment layer and restart Caretaker.

Example unsigned incident lease in the console:

```text
target:  billing.charge
path:    repair.authority
value:   AUTOMATIC_ELIGIBLE_REPAIRS
duration: 1800
reason:  incident INC-142 - temporary unattended recovery
```

Load a common Repair-authority preset or enter the advanced path/value, then
select **Preview change**. Review the exact scope, duration, reason, and guarantee
impact; acknowledge **I reviewed scope and guarantee impact** before applying.
Changing any input invalidates the preview. Ending a selected temporary change
with **End temporary change** requires the separate **Confirm release** acknowledgement.

If the change violates an application-owner constraint, select **Allow constraint override**. The repair can
proceed, but the application-owner guarantee becomes `VIOLATED` for that effective generation.

### Requiring signed temporary leases

Any higher authority layer may set:

```json
{"path":"authority.runtime.require_signed_leases","value":true}
```

Once effective, an unsigned lease is rejected. A signed runtime lease is represented by a canonical
`kind: "runtime"` authority layer with an `expires_at` timestamp and exact parent fingerprints. It
may contain settings but cannot introduce new constraints.

Place its small TOML descriptor and referenced materials under the deployment's policy area and use
the console's **Apply signed lease** action. Enter an operator/incident reason and
acknowledge **I reviewed signed scope** before applying. Signed runtime lease descriptors accepted through the
control plane live below:

```text
<caretaker-data>/policy/runtime-leases/
```

A signed runtime layer must reference the exact currently active framework/application/deployment
fingerprints. A lease signed against an older policy generation is rejected.

## Policy generations and Repair

Every Repair incident, candidate, attempt, approval, and active validation is bound to the effective
authority generation/fingerprint that existed when the work began.

If authority policy changes before activation, the candidate becomes stale. It cannot silently
activate under the new authority generation. Operator approval also rejects a candidate whose
authority generation no longer matches.

This applies to temporary escalation too. A narrow runtime lease can permit the incident-specific
operation, but expiration or release of that lease creates a new effective generation. Work from the
lease generation must be reevaluated before activation.

## Supervisor versus application process

The supervisor owns the authoritative stack. The application receives a serialized effective
snapshot and applies it to Repair, Guard, Logging, and supported system policy.

The supervisor compares the application's reported authority generation/fingerprint with its own.
A mismatch is reported as runtime policy tampering and logged at critical severity. The supervisor
also attempts to restore its authoritative generation.

This is a detection and attribution boundary, not a claim that Python can prevent arbitrary native
memory modification. Code with unrestricted execution inside the application process can modify
application memory, monkey-patch Python, or replace functions directly. Caretaker cannot make that
impossible. The security property is that such runtime state no longer matches the supervisor-owned
policy guarantee and cannot honestly be reported as an unmodified authority chain.

The application-side policy update is transactional: if any Repair, Guard, or Logging component
cannot reconcile the new generation, Caretaker restores the previous effective generation across
components and reports the failure.

## Console assurance states

The Policy tab presents static authority layers as policy sources and runtime leases as temporary
changes. It shows signatures, assurance/guarantee state,
violations, and detailed provenance. The status line includes the overall authority state.

Important overall states include:

- `UNCONFIGURED` — no static authority stack is configured;
- `PARTIAL_OR_UNSIGNED` — at least one configured static layer is unsigned;
- `VERIFIED_AUTHORITY_CHAIN` — configured static layers verify and no guarantee is violated;
- `UNSIGNED_RUNTIME_OVERRIDE` — a verified static chain currently has an unsigned runtime lease;
- `GUARANTEE_VIOLATED` — an explicit lower-authority override exceeds a higher constraint;
- `INVALID_AUTHORITY_CHAIN` — a loaded authority has become invalid/expired;
- `RUNTIME_TAMPER` — console status when the application-reported policy fingerprint differs from
  the supervisor's authoritative generation.

A guarantee state describes provenance and constraint satisfaction. It is not a claim that the host
or interpreter is uncompromised.

## Key authorization, rotation, and revocation

Policy signatures use roles defined by the configured higher-level trust root. Key authorization,
rotation, revocation, and root transitions therefore remain part of the existing Integrity/external
key-authority model rather than being reimplemented in policy authority.

For the official Caretaker distribution, the framework policy role should be rooted in the same
independently verified project authority used to identify official releases. Applications and
deployments may use separate external roots or roles appropriate to their organizations.

## Supported policy namespaces

V1 authority paths are limited to:

```text
authority.*
repair.*
lightweight.*
guard.*
logging.*
system.*
```

Target selectors are currently supported for `repair.*` and `lightweight.*` paths; per-target Guard
bindings remain under `repair.guard.*`. This allows deployment authority to constrain adaptive
promotion/demotion, call-count sampling (`lightweight.sampling.*`), and repair-evidence
gates (`lightweight.repair_evidence.*`) independently for individual functions or target globs. Unknown top-level
namespaces are rejected so a misspelled security policy cannot silently become a no-op.

Static layers are applied at startup. Runtime leases are intentionally narrower. Some policy fields
represent construction-time topology and require a restart; Caretaker rejects known restart-bound
fields in a temporary lease rather than pretending the live system changed completely.
