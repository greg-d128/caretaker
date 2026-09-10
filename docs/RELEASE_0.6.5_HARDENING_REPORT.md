# Caretaker 0.6.5 hardening progress

Updated 2026-09-09. The changes below are pushed to `main`. The final
repository check passed with 1,029 tests and Python compilation.

## Remaining-gap closure

The five issues in the next 0.6.5 hardening goal are closed:

| Remaining issue | Status | Implementation evidence |
| --- | --- | --- |
| Behavior snapshot list limits coerce malformed values | Complete | Snapshot summary and pending-materialization limits require exact positive integers. |
| Pending behavior statistics with unsupported schemas are promoted | Complete | Pending record and statistics schema versions are checked before `BehaviorSnapshotStore.create`; invalid records remain pending. |
| Communication history accepts malformed hashes and loses tight-ID identity | Complete | Communication content hashes require lowercase SHA-256; canonical UUID communication IDs and hashes bypass generic text truncation; verification validates stored records. |
| Non-restartable worker roles can be directly restarted | Complete | Direct restart and replacement admission reject roles outside the explicit restartable worker set. |
| Container validation does not enforce `--pull=never` | Complete | Podman and Docker validation commands include `--pull=never`; local-image availability remains required. Command-boundary tests pass without a validator image. |

| Reported gap | Status | Implementation evidence |
| --- | --- | --- |
| Capsule and artifact stores accept symlinked paths | Complete | Capsule roots and stored reads reject symlinked paths; container mount sources also reject symlink components. |
| Capsule and artifact loads accept oversized stored content | Complete | Descriptor-relative reads enforce the configured capsule/artifact byte limits before JSON parsing. |
| Capsule artifact identity mismatches are accepted | Complete | Artifact incident, capsule, reference path, metadata, kind, source, timestamp, and content hash must agree. |
| Durable stores coerce boolean, fractional, or string limits | Complete | Strict limit validation was added across capsule, communication, failure-corpus, adaptive, transport, replay, regression, behavior, Guard, and repair stores. |
| Behavior snapshots/statistics accept unsupported schemas or foreign checkpoints | Complete | Snapshot/statistics schema and generation provenance are validated; restart ignores rehashed foreign checkpoints. |
| Adaptive aggregation accepts malformed resource/list limits | Complete | Resource values, counters, queue/list limits, batching thresholds, and supervisor retention settings reject coercive input. |
| Worker restart validation permits invalid configurations | Complete | Full restart configuration is validated at the runtime decision boundary, including policy-like inputs. |
| Rollout enum input leaks `KeyError` | Complete | Rollout enum helpers raise bounded `RepairRolloutError` values. |
| Typed authority settings accept string values | Complete | Authority schema/generation/boolean/text/enum settings use strict type validation. |
| Communication and failure-corpus limit validation is coercive | Complete | Draft, audience, corpus, observation, runner, and execution limits are strict. |
| Container mount-path validation is incomplete | Complete | Workspace and additional read-only mount sources must be existing directories without symlinked components; container resource-size settings are validated. |
| External resource enforcement is incomplete | Deployment-owned boundary remains | Caller-provided external validators cannot have their kernel/resource controls independently attested by Caretaker. The external backend reports `resource_control=False` and caller-supplied isolation attestation, so selection does not claim a guarantee that Caretaker cannot enforce. |

## Pushed commits

- `7e0385a` Harden capsule and artifact loading
- `a33f665` Reject coercive communication and corpus limits
- `2df7313` Harden adaptive aggregation boundaries
- `fdb7eb7` Bind behavior checkpoints to provenance
- `e336c7b` Harden authority rollout and restart validation
- `71972ff` Harden container validation mounts
- `943ae97` Reject coercive durable store limits
- `db56548` Harden remaining durable list limits
- `f69c711` Preserve minimal behavior snapshot fixtures
- `0832f53` Reject symlinked capsule roots
- `8b6b598` Harden behavior snapshot promotion boundaries
- `997e2ba` Preserve and validate communication identities
- `df42925` Block direct restart of nonrestartable workers
- `dbb62a2` Require local images for container validation

The remaining external-resource item needs a deployment-specific validator
contract or independently controlled service; no Caretaker-only change can
prove resource enforcement inside that caller-owned environment.
