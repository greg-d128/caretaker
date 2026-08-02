# Guard import routing

Guard can route selected imports to pre-registered approved variants. This is intended for quarantine, rollback, compatibility fallbacks, and controlled dependency experiments.

## Principal models

```python
ModuleVariant
ModuleRoutePolicy
ImportRouteDecision
ModuleRouter
CaretakerModuleFinder
GuardedLoader
CaretakerSupervisor
```

## Variant

A `ModuleVariant` records:

- variant ID;
- import name;
- distribution and version;
- source location;
- optional source hash;
- integrity state;
- optional accepted behavior-baseline ID;
- route priority.

## Route policy

A route policy identifies the preferred variant and ordered fallbacks. It can require a signed variant and an accepted behavior baseline.

```python
ModuleRoutePolicy(
    import_name="vendor_sdk",
    preferred_variant_id="vendor-sdk-4.2",
    fallback_variant_ids=("vendor-sdk-4.1", "vendor-sdk-disabled"),
    substitution_allowed=True,
    require_signed_variant=True,
    require_accepted_baseline=True,
    restart_required=True,
)
```

## Quarantine

A significant deviation or integrity failure may quarantine one exact variant. Future imports select an approved fallback or fail closed according to policy.

Quarantine does not rewrite references already held by application code.

## Pre-import reliability

Import substitution is dependable before the module has been executed. Once code has used:

```python
from vendor_sdk import send_request
```

changing `sys.modules["vendor_sdk"]` does not replace the existing `send_request` reference.

The recommended response to abnormal behavior in an already imported dependency is:

1. record and quarantine the variant;
2. persist an approved route decision;
3. stop accepting new work;
4. restart through a supervisor boundary;
5. load the fallback under pre-load and post-load inspection;
6. observe the fallback in probation.

## Supervisor

`CaretakerSupervisor` is an in-process technology-demonstration boundary. A production design should normally use an external service manager or parent process capable of terminating and starting a fresh interpreter.

## Security rules

Guard does not import arbitrary LLM-proposed module paths. A substitute must be pre-registered and satisfy route policy, source/integrity checks, and any required baseline acceptance.
