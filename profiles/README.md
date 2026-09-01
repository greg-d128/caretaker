# Caretaker framework policy profiles

The production canonical JSON files are the previously signed profile
revisions and remain review candidates for Caretaker 0.6.5a. Their metadata
currently targets policy surface 11 and Caretaker 0.6.1, so they require a new
profile revision and fresh signatures before claiming complete 0.6.5a
coverage. The current unsigned sandbox revision is `caretaker-sandbox-v2.json`;
it is intentionally unsigned and carries the reviewed 0.6.5a surface. The
current capability and reserved-setting catalogs are in
`../catalogs/`; run `make policy-catalogs` to regenerate them. A profile is not
a trusted 0.6.5a publication artifact until its exact reviewed bytes are
signed by the identities authorized for the `protected` role in `root.json`.

- `caretaker-observe-only-v1.json` is the conservative adoption profile. Repair may analyze incidents but cannot propose or activate replacements.
- `caretaker-balanced-v1.json` is the recommended general-purpose starting point. Repair may prepare work, but activation requires operator approval.
- `caretaker-high-assurance-v1.json` is the strict profile. It requires signed runtime leases, VM-level validation isolation, and externally signed runtime records; deployments must provide those facilities or fail closed.
- `caretaker-sandbox-v2.json` is the current non-production laboratory profile. It preserves each lab target's deliberately different Repair authority while enabling common evidence facilities and explicitly keeps automatic Repair retention compaction disabled. `sandbox-stack.toml` selects it automatically for `make lab` and `make lab-verified`. The v1 profile remains as the predecessor for lineage review.

Inspect a profile with:

```bash
PYTHONPATH=src venv/bin/python -m caretaker.profile_cli show profiles/caretaker-balanced-v1.json
```

Validate its canonical form and current signing role with:

```bash
PYTHONPATH=src venv/bin/python scripts/check-framework-policy.py profiles/caretaker-balanced-v1.json root.json protected
```

After review, sign the unchanged file independently in each signing environment:

```bash
make sign-framework-policy FRAMEWORK_POLICY=profiles/caretaker-balanced-v1.json KEY_SLOT=a
```

Repeat for slots B and C. Any edit or reformatting after signing invalidates the detached signatures.

Installed users can run `caretaker-profile list` and select one before application
import with `caretaker-run --profile PROFILE MODULE`. Production selection fails
closed unless A, B, and C signatures verify under the packaged root's `protected`
role. Sandbox is the sole unsigned built-in profile.
