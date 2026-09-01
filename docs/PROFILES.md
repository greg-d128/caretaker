# Policy profiles

Caretaker policy profiles are named, versioned **framework authority layers** intended to make the layered authority model easier to adopt and maintain. A profile does not create a new authority tier. It is ordinary canonical `PolicyAuthorityLayer` content with profile metadata, and it remains subject to the same signature verification, exact parent-fingerprint binding, constraints, overrides, expiration, and assurance reporting as any other framework layer.

The security distinction is intentional:

- a valid profile signature proves **provenance**: an authorized profile signer published these exact canonical bytes;
- a deployment parent fingerprint proves **selection**: this installation selected this exact profile fingerprint.

A valid signature on a different official profile is therefore not enough to replace a pinned profile. The deployment layer remains bound to the selected framework fingerprint.

## Profile identity and lineage

Profiles carry a stable lineage separately from their descriptive name and revision number. For example:

```text
Lineage:  caretaker.balanced
Name:     Caretaker Balanced
Version:  4
```

The lineage stays stable as Caretaker evolves. A continuation records both the previous profile version and the exact previous fingerprint. A comparison can therefore distinguish a real continuation from an unrelated artifact that happens to use a similar name.

Profile metadata uses these canonical keys:

```text
caretaker.profile.lineage
caretaker.profile.name
caretaker.profile.version
caretaker.profile.description
caretaker.profile.policy_surface_version
caretaker.profile.caretaker_minimum
caretaker.profile.caretaker_tested_through
caretaker.profile.supersedes_version
caretaker.profile.supersedes_fingerprint
caretaker.profile.based_on_lineage
caretaker.profile.based_on_version
caretaker.profile.based_on_fingerprint
caretaker.profile.signer_role
caretaker.profile.require_complete_surface
caretaker.profile.require_current_caretaker_version
caretaker.profile.origin
```

A custom organization profile derived from an official profile should normally use its own lineage and the `based_on_*` fields. It must not present itself as a continuation of the official lineage.

## Policy-surface coverage

Package version, authority-manifest schema, profile version, and **policy-surface version** are separate concepts.

The policy-surface generation advances when Caretaker introduces new policy-controlled functionality that an older profile could not have reviewed. Caretaker maintains a catalog of capabilities with stable IDs, their introduction version, affected policy paths, and a review explanation.

Caretaker 0.6.5a advances the policy surface to generation 11. The new review capabilities cover adaptive `lightweight.*` instrumentation, persistent Guard behavior snapshots, opt-in randomized behavior snapshot boundaries, bounded return-behavior categories and policy-gated live return novelty, policy-governed operator behavior collection scheduling, minimum Repair validation-isolation requirements, retention of the runtime signing-identity journal, opt-in persistent adaptive-policy acceptance, policy-bound Repair rollout authority, the optional output-only monitoring stream, and optional manifest-backed audit segment rotation. A strict surface-1, surface-2, surface-3, surface-4, surface-5, surface-6, surface-7, surface-8, surface-9, or surface-10 profile must therefore be reviewed and continued before it can claim complete coverage under 0.6.5a.

This makes the following state detectable:

```text
Profile signature: VALID
Selection pin:     MATCHED
Profile lineage:   caretaker.balanced v3
Policy surface:    1 / 2
Coverage:          REVIEW REQUIRED

New capability:
  repair.generated_dependency_policy
  Introduced: Caretaker 0.7
  Meaning: ...
  Review: ...
```

An available newer profile by itself does **not** invalidate a valid pinned profile. The important question is whether the running Caretaker version exposes policy-controlled capability that the profile has never reviewed.

Profiles may set `caretaker.profile.require_complete_surface=true`. When this is set, Caretaker refuses to load the profile if the running policy surface contains capabilities introduced after the profile's declared surface. This is intended for high-assurance deployments where implicit use of newly introduced policy behavior is unacceptable.

A second optional maintenance control, `caretaker.profile.require_current_caretaker_version=true`, requires `caretaker.profile.caretaker_tested_through` to exactly match the running Caretaker version. This deliberately forces a profile-lineage review on every Caretaker upgrade even when the policy surface did not change.

## Official Caretaker profiles and signing

Caretaker 0.6 signs its first official profiles with the existing high-value
`protected` role:

```text
protected
```

A future root may delegate a narrower `profile-signing` role because profiles are
expected to change more frequently than core code. That delegation does not exist
in the current root and must not be claimed or selected before a valid root
transition authorizes it.

The profile signer is authorized through the existing Caretaker trust-root/role machinery. Caretaker does not contain a private-key interface and the Profile Editor does not sign files. Official and organizational profile signing remains an external/offline operation over the canonical JSON bytes.

A profile may record the signer role it expects in `caretaker.profile.signer_role`. If present, the authority-stack role used to verify the profile must match that declaration.

Organizations remain free to create their own profile lineages, signing roles, roots, and framework policies. Official Caretaker profiles are a convenience and provenance option, not an exclusive certificate authority for policy.

## Profiles shipped with Caretaker

List the installed profiles:

```bash
caretaker-profile list
```

The production choices are `observe-only`, `balanced`, and `high-assurance`.
Selection verifies all three packaged signatures under the root's `protected`
role before importing the application. `sandbox` is deliberately unsigned and
is identified as non-production.

Select a profile explicitly at supervised startup:

```bash
caretaker-run --profile balanced my_application
```

The convenient form anchors the packaged root to its embedded fingerprint set.
For initial trust, repeat `--profile-trusted-fingerprint` with all three values
obtained independently. A mismatch fails before the application is imported.

`--profile` and `--authority-stack` are mutually exclusive. Use an authority
stack when application or deployment layers and exact parent pins are required.
Built-in selection supplies only the framework layer; it does not invent lower
authority policy.

## Pinning a profile selection

Create a deployment layer that binds the exact framework fingerprint:

```bash
caretaker-profile pin caretaker-balanced-v4.json \
  --output production-profile-selection.json \
  --authority-id production-profile-selection
```

The generated layer is an ordinary deployment authority layer containing:

```json
"parents": {
  "framework": "<exact-profile-fingerprint>"
}
```

If an application authority layer is present, include it too:

```bash
caretaker-profile pin caretaker-balanced-v4.json \
  --application application-policy.json \
  --output production-profile-selection.json
```

The pin records profile lineage/version/fingerprint as descriptive metadata, but the existing `parents.framework` fingerprint is the actual authority binding. Replacing a pinned profile with another legitimately signed profile causes the existing authority parent-chain check to fail.

The generated deployment layer is unsigned until the deployment owner signs it. An unsigned deployment pin is still useful for consistency and accidental-substitution detection, but it does not create cryptographic deployment-selection assurance. High-assurance deployments should protect/sign the deployment layer through their own authority role.

## Viewing and comparing profiles

Show one profile or ordinary authority policy:

```bash
caretaker-profile show profile.json
```

Inspect machine-readable output:

```bash
caretaker-profile show profile.json --json
```

Compare two profiles or authority policies:

```bash
caretaker-profile compare old.json new.json
```

The comparison is semantic rather than a raw JSON diff. It reports setting and constraint additions, removals and changes, target scope, old/new values, the policy capability affected, and an operational/security consequence. For example, changing:

```text
REQUIRE_OPERATOR_APPROVAL
    -> AUTOMATIC_ELIGIBLE_REPAIRS
```

is described as an increase in Repair autonomy rather than merely two changed strings.

When both inputs are named profiles, comparison also reports whether they share a lineage and whether the newer profile contains an exact predecessor version/fingerprint continuation binding.

## Checking upgrade coverage

```bash
caretaker-profile coverage profile.json
```

Use `--strict` in automation when incomplete coverage should produce a non-zero status:

```bash
caretaker-profile coverage profile.json --strict
```

The capability catalog can be inspected independently:

```bash
caretaker-profile catalog
```

When a new policy-controlled capability is added to Caretaker, its implementation must add a stable capability entry and increment the current policy-surface generation. This makes older profiles visibly incomplete instead of silently treating a new default as though the older profile had reviewed it.

## Profile Editor

Run the Textual editor from a source checkout:

```bash
make profile
```

or from an installed package:

```bash
caretaker-profile
```

To continue an existing profile:

```bash
caretaker-profile edit caretaker-balanced-v3.json
```

The editor provides separate views for profile identity/lineage, settings, constraints, and review. Opening an existing profile starts a new revision of the same lineage by default and records the exact predecessor fingerprint. If the lineage is changed, the editor records a `based_on_*` relationship instead of claiming a continuation.

Before saving, the Review view can:

- compare the draft semantically with an existing profile;
- show policy-controlled capabilities introduced since the base profile's surface;
- preview canonical profile metadata/settings/constraints;
- save canonical unsigned JSON for external review/signing.

The editor intentionally does not contain private-key material or a Sign button.

## Upgrade workflow for high-assurance deployments

A typical strict workflow is:

1. Verify the new Caretaker release independently.
2. Open the currently pinned profile in the Profile Editor.
3. Review the **Coverage** view for policy-controlled capabilities introduced since the prior profile.
4. Use **Compare** to review every setting/constraint change and its described consequence.
5. Continue the profile lineage with a new version and updated `caretaker_tested_through` value.
6. Review and sign the new canonical profile using the authorized profile-signing role (or the organization's equivalent).
7. Update the deployment selection layer so `parents.framework` pins the new exact fingerprint.
8. Review/sign the deployment layer under deployment authority where cryptographic selection assurance is required.
9. Restart Caretaker and verify signature state, parent binding, policy-surface coverage, and overall authority assurance.

This maintenance cost is deliberate in strict mode. Caretaker should not silently broaden a high-assurance policy merely because new product functionality was installed.
