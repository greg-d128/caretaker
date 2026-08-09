# Policy authority example

These files demonstrate the policy-authority data model without requiring signing keys.
They are **not** official Caretaker project policy and intentionally produce
`PARTIAL_OR_UNSIGNED` assurance.

Run an application with the sample stack by adding:

```bash
python -m caretaker.run \
  --authority-stack examples/policy_authority/stack-unsigned.toml \
  your_application_module
```

The three canonical JSON layers show:

- framework values and constraints;
- application-owner target constraints;
- deployment values bound to the exact framework/application fingerprints.

Because a layer fingerprint includes its complete canonical content, editing an upstream
file requires regenerating the parent fingerprints in every lower layer.

For a signed deployment, add a `[trust]` section plus `role`, `signatures`, and
`require_signature = true` to each stack entry. Do not use the example authority IDs or
unsigned files as evidence of official project provenance. See
`../../docs/POLICY_AUTHORITY.md` for the signed format, external GPG verification, runtime
leases, and guarantee semantics.
