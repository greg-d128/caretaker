# Logging baselines and slow drift

## Scope and populations

Baselines can cover an application, distribution, module, or function. `BaselineKey` includes application version, environment, function version, workload label, and optional population designator.

Decorators can use `baseline_dimensions=` or a `population_key=` function to separate behavior that legitimately differs according to selected inputs. Population values are masked before persistence.

## Lifecycle

```text
GENERATED → REVIEWED → ACCEPTED → SUPERSEDED
```

Application code cannot accept or supersede a baseline. An administrator can do so through the CLI or a local scheduled task. Multiple accepted baselines can coexist.

## Long-term comparisons

A monthly baseline may be compared against:

- the previous month;
- the latest accepted baseline;
- a rolling annual profile;
- the same month in earlier years;
- a three-year or other long-term anchor.

Reports separate total growth from changes in resource or failure rates per unit of work. This distinguishes application growth from declining efficiency while preserving both as useful signals.

## Slow drift

Comparisons retain trend slopes, relative changes, per-unit changes, capability additions/removals, an overall change score, and a slow-drift score. Baselines are immutable derived artifacts and retain content hashes.
