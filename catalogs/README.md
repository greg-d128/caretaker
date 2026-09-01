# Caretaker policy catalogs

These machine-readable catalogs describe the policy surface reviewed for the
source release. They are generated from the runtime definitions with:

```bash
make policy-catalogs
```

The capability catalog identifies stable policy capability IDs, introduction
versions, affected paths, and review notes. The reserved-setting catalog lists
public policy names that remain deliberately inactive or unsupported so they
cannot be mistaken for implemented behavior.

The catalogs are descriptive review artifacts. They do not grant authority,
replace signed policy profiles, or replace signed release/protected manifests.
