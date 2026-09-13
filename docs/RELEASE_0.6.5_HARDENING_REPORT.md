# Caretaker 0.6.5 hardening progress

Updated 2026-09-13 for final-version preparation on the Caretaker 0.6.5
release branch. The repository check passed with 1,072 tests and Python
compilation before the final-version metadata transition.

The release-readiness follow-up also proves the real `caretaker.run` process
boundary: `tests/test_run_entrypoint.py` reaches supervisor readiness, observes
the expected workers and configured application identity, and verifies endpoint
cleanup after both normal exit and application-startup failure. The follow-up
was pushed as `0e62d8f` and `867354a`.

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

## Development campaign finding closure

The following findings were rechecked against `412a149` before the candidate
freeze:

| Finding | Caretaker result |
| --- | --- |
| Supervisor bootstrap could not use `RepairPolicy.rollout` | The rollout surface is present and supervisor bootstrap tests pass. Policy validation now rejects a missing or wrongly typed rollout component before bootstrap can partially proceed. |
| Non-finite post-mortem evidence | Rejected by both durable-store and emergency JSON conversion paths. |
| Invalid worker roles, PIDs, restart limits, and heartbeat timeouts | Rejected at worker-health construction, registry admission, and restart-policy validation. Supervisor remains explicitly non-restartable. |
| Hostile system source IDs and output-root symlinks | Safe source IDs, typed source fields, rooted writes, and symlink checks remain fail-closed. |
| Invalid policy input types | Nested public policy components and key enum surfaces are type-checked before semantic field access. |
| Provider malformed data, non-finite JSON, oversized responses, redirects, and model mismatches | Shared Ollama transport keeps strict JSON, bounded reads, timeout validation, same-origin redirect checks, TLS/attestation checks, and model checks. |
| Capsule artifact references truncated by text bounds | Artifact identity fields, including paths, remain lossless; payload and capsule byte limits still apply. |
| Durable job summaries/progress containing NaN | Runtime job persistence and related record, IPC, metrics, and handler JSON writers use strict JSON serialization. |
| Rootless resource-control enforcement | Environment-dependent: the local `localhost/caretaker-replay-base:0.6.5` image is provisioned and `make podman-verify` passes, but the Caretaker probe reports `resource_control=False` because the rootless environment exposes unlimited (`max`) cgroup values without delegated enforcement. |

This closure records Caretaker-side evidence only. Validator and Crucible must
rerun their downstream checks against the frozen candidate and may retain a
separate finding where their environment or contract requires a stronger
claim.

## Release-readiness handoff

The stale 0.6.5 roadmap status has been corrected in `docs/FUTURE_WORK.md`.
Installed command names, supervisor invocation, and cleanup behavior are
documented in `docs/INTERACTIVE_ISOLATION_TESTING.md`. The exact-artifact
procedure for independent Validator and Crucible runs is in
`docs/INDEPENDENT_VALIDATION.md`.

The current Caretaker tree has not been represented as independently certified:
the final 0.6.5 artifacts are being prepared for signing and signed wheel
manifests remain a release-station task. Validator and Crucible must identify
the exact final artifacts in their handoff records before publication.
