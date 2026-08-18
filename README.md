# Caretaker 0.6.0

Caretaker is a Python 3.11+ research framework for application-scoped logging, behavioral analysis, guarded self-repair, and publicly verifiable code integrity.

Caretaker is active research software. Its documented behavior describes current design goals and tested behavior, not a warranty or guarantee of availability, correctness, containment, recovery, or security. It is being developed toward useful operational workflows, but operators must independently validate it for their environment and retain external recovery and verification paths.

Version 0.6.0 combines lightweight adaptive instrumentation with persistent behavioral statistics, signed behavior snapshots, restartable Guard baselines, and capability-based validation isolation. Logging can still be deployed independently and remains the evidence foundation for Guard and Repair.

## Subsystems

- **Logging** is the lowest-cost subsystem. It accepts ordinary `logging` records, structured Caretaker events, decorator call evidence, and optional system records. It writes append-only, framed records to rotating segments and builds a rebuildable SQLite index.
- **Guard** observes selected imports, filesystem, network, subprocess, and runtime-code behavior; constructs explicit baselines; detects significant deviations; and can influence module routing or Repair decisions.
- **Repair** generates, validates, activates, retries, observes, accepts, or rolls back function replacements under explicit policy.
- **Integrity** verifies signed release and source manifests using public OpenPGP identities, threshold rules, anti-rollback state, and runtime fingerprints.

Supporting infrastructure includes the runtime control plane, shared evidence identities, an application-scoped supervisor, a local administrative socket, optional `/proc` and `/sys` collection, supplemental evidence attachments, and an advisory LLM interrogation interface.

## Current supply-chain scope

Caretaker currently researches Python runtime evidence, signed source/release manifests, dependency identity and behavior, controlled import routing, and temporary in-memory function repair. It is not yet a general software-supply-chain management platform. In particular, this release does not ingest SBOMs or vulnerability feeds, monitor package registries, resolve dependency upgrades, verify Sigstore/SLSA/in-toto provenance, rebuild or deploy releases, or notify external incident-management systems. Those capabilities are roadmap items rather than implied features; see [`docs/FUTURE_WORK.md`](docs/FUTURE_WORK.md).

## Application scope

Caretaker supports one application or service and its process tree. It is not a machine-wide management daemon and does not request privilege escalation. Host-wide `/proc` or `/sys` collection can be enabled when the machine primarily exists to serve the supervised application, but collection still runs with the application account's permissions.

Observation can cover a process tree, but adaptive thresholds, Repair engines, runtime replacements, pending approvals, and acceptance state are currently process-local unless an embedding application supplies additional coordination. Caretaker does not yet provide application-wide atomic Repair coordination across multiple workers.

Caretaker terminates when the application terminates. Caretaker may inspect and restart its own worker components, but **Repair is prohibited from modifying Caretaker's own code**.

## Preferred startup

```bash
python -m caretaker.run \
  --policy /etc/caretaker/invoice-service.toml \
  --authority-stack /etc/caretaker/policy-authority/stack.toml \
  invoice_service
```

This starts Caretaker before the application module loads, allowing import-time observation and module routing. If Caretaker is configured after application initialization, it records and emits a warning containing the preferred command so operators do not need to infer it.

The console-script equivalent is:

```bash
caretaker-run --policy /etc/caretaker/invoice-service.toml invoice_service
```

## Adaptive instrumentation and behavior snapshots

Caretaker can start selected application functions and dependency boundaries with low-cost instrumentation and escalate observation when policy detects repeated exceptions or soft-timing breaches:

```text
LIGHTWEIGHT → BEHAVIOR → REPAIR → BEHAVIOR → VALIDATION → LONG_TERM_ACCEPTANCE
```

The lifecycle stage and observation intensity are separate. Repair cannot skip the pre-repair BEHAVIOR evidence gate, and an accepted repaired function may later return to LIGHTWEIGHT observation without losing its accepted lifecycle state.

Behavior samples update one bounded epoch accumulator per function generation.
Automatic materialization and operator capture atomically close that epoch and
start a disjoint successor; generation-scoped sample ranges prevent calls from
being counted twice. Code or monitoring-semantic changes seal the active epoch
and start another generation. Sealed snapshots contain online statistics and
bounded distribution samples, including p10/p50/p90/p95/p99 duration summaries,
hourly call activity, sampling-stage provenance, resource observations, code
identity, monitoring fingerprints, and epoch boundaries. Accepted Guard baselines
reference immutable sealed snapshots and can be reconstructed after restart
without replaying all raw events.

When secure runtime signing is configured, snapshots and behavior archives use the same runtime artifact signer as secure event manifests. External-signed mode never silently falls back to ephemeral signing. Ephemeral public identities and signed key transitions are retained in a separate Signing Identity Journal with independent retention.

## Validation isolation backends

Repair validation is capability-based. `ValidationPolicy.minimum_isolation` can require PROCESS, CONTAINER, VM, or EXTERNAL isolation. The current development tree provides PROCESS, rootless Podman CONTAINER, and Multipass VM backends:

```python
from caretaker import RepairEngine, ValidationIsolationLevel, ValidationPolicy
from caretaker.validation import MultipassValidationBackend, RootlessPodmanValidationBackend

podman = RootlessPodmanValidationBackend(
    "caretaker-validator:local",
    workspace="/srv/my-application",
)

vm = MultipassValidationBackend(
    instance_name="caretaker-validator",
    clean_snapshot="caretaker-clean",
)

engine = RepairEngine(validation_backend=vm)
```

Caretaker reports when a configured backend cannot meet the required isolation level. Depending on `backend_unavailable_action`, it fails the repair, retains a proposal, or asks for an explicit operator override. In the current implementation, approving that override can activate a candidate that did not receive the requested isolation; approval must not be interpreted as successful validation at that level. See [`docs/ISOLATED_EXECUTION.md`](docs/ISOLATED_EXECUTION.md) for the rootless-container and Multipass provisioning model and for the distinction between candidate validation and whole-subject isolation.

## Operator console

Caretaker includes a Textual operator console for live inspection and explicit
operator actions. Start the application with `caretaker-run`, then attach from a
second terminal:

```bash
caretaker-console --data-directory /var/lib/invoice-service/caretaker
```

The console opens on an **Attention** queue for active incidents, Guard findings,
waiting Repair work, policy violations, and degraded capabilities. A shared
target/incident/call context follows selections between tabs, while source and
freshness labels distinguish live runtime data from retained or persisted
fallback evidence. **Overview**, **Guard**, **Behavior**, **Repair**, **Policy**,
**Investigate**, and **Logs** provide issue-first inspection and direct links to
related evidence without requiring operators to copy internal IDs.

Consequential actions fail closed. Guard baseline acceptance, Behavior generation
archiving, Repair activation/rejection, unsigned or signed policy application,
and ending a temporary policy change require an explicit review acknowledgement. Repair
rejection, Behavior generation archiving, and policy application also require an
operator reason. Archiving a Behavior row packages and removes every active
snapshot in that subject/generation while retaining the reason in the archive
manifest. Behavior and local-AI comparisons are advisory evidence rather than
correctness guarantees; the UI
shows collection coverage, generation, integrity, evidence scope, and omissions.
The Behavior list prefers cumulative epoch evidence and displays the newest three
generations per subject by default, sorted by subject and newest generation, with
first/last-seen times and bounded hourly call-activity bars. Summary capacity is
allocated across subjects before older generations, so hot or frequently changed
functions do not crowd rare functions out of view. Exceptional evidence whose
exclusive sample range cannot be proven is labeled `partial`.
Each subject's newest analytical generation is its default green comparison
reference. Operators select another generation and use **Compare with reference**,
or use **Set Reference** to change only that subject's reference.

The persistent **Save Report** button exports the active tab's visible summaries,
table rows, inputs, and detail panels as a private plain-text file under
`<data-directory>/reports/`, suitable for review before attaching to a ticket.

The console uses the same authenticated local Unix control plane as the
supervisor. It does not expose arbitrary shell commands or Python execution.
See [`docs/ADMIN_CONTROL.md`](docs/ADMIN_CONTROL.md) for the first-response
workflow and a tab-by-tab description.

## Logging-only use

Existing application logging calls continue to work:

```python
import logging
from caretaker.logging import CaretakerLogHandler, configure_from_operator_policy

runtime = configure_from_operator_policy(
    application_id="invoice-service",
    path="/etc/caretaker/invoice-service.toml",
)

logger = logging.getLogger(__name__)
logger.addHandler(CaretakerLogHandler(runtime))
logger.setLevel(logging.INFO)
logger.info("invoice processing started", extra={"invoice_id": "INV-1042"})
```

Or use the convenience logger:

```python
from caretaker.logging import get_logger

logger = get_logger(__name__)
logger.info("invoice processing started")
```

## Shared decorators and masking

```python
from caretaker.logging import logged, MaskingResult


def mask_payment(bound):
    arguments = dict(bound.arguments)
    card = str(arguments.get("card_number", ""))
    arguments["card_number"] = f"XXXX-XXXX-XXXX-{card[-4:]}" if len(card) >= 4 else "<masked>"
    return MaskingResult(
        masked_args=(),
        masked_kwargs=arguments,
        structural_metadata={"card_length": len(card), "digit_only": card.isdigit()},
        stable_tokens={},
        fully_removed_fields=(),
        format_preserved_fields=("card_number",),
    )


@logged(
    timing=True,
    exceptions=True,
    arguments=True,
    mask=mask_payment,
    baseline_dimensions=("payment_type",),
)
def authorize_payment(payment_type, card_number, amount):
    ...
```

Original values remain available to the function and explicitly trusted local validators. Only the masked evidence view is written, analyzed, or sent to an LLM.

The same `mask=` contract is available to Repair decorators.

## Operator policy, authority layers, and higher modes

The ordinary operator policy remains usable without signatures. Deployments that need stronger provenance may add a supervisor-owned authority stack containing framework, optional application-owner, and deployment layers. Each layer can select values and constrain what lower authorities may change without invalidating its guarantee. A deployer may deliberately override a higher constraint, but the violated guarantee remains visible in the console and evidence. See [`docs/POLICY_AUTHORITY.md`](docs/POLICY_AUTHORITY.md).

In Application mode, the reconciled operator/effective policy is authoritative for execution. Guard, Repair, Research, Forensic, and Baseline modes require certain evidence capabilities. When a requested higher mode conflicts with the base logging policy, Caretaker performs explicit reconciliation according to the operator-selected conflict action:

- apply only the required overrides;
- refuse the higher mode;
- fall back to Application logging; or
- require interactive approval.

Overrides are immutable, explained, logged, visible through the control socket, and tied to a temporary **mode lease** where appropriate. Releasing a lease removes only that lease's overlays and retains unrelated policy changes made while it was active.

## Example policy

See [`examples/logging_policy.toml`](examples/logging_policy.toml). A minimal policy is:

```toml
[logging]
application_id = "invoice-service"
directory = "/var/lib/invoice-service/caretaker"
modes = ["application"]
conflict_action = "apply_required_overrides"

[logging.rotation]
maximum_segment_bytes = 134217728
maximum_segment_seconds = 3600

[logging.compression]
enabled = true
algorithm = "gzip"

[logging.signing]
mode = "ephemeral_signed"
key_epoch_maximum_seconds = 86400
```

## Record storage

The primary record envelope is limited to 4096 bytes and contains:

- record and writer format versions;
- UTC time;
- process clock value;
- process-start identity and sequence number;
- channel, severity, logger, correlations, and typed fields;
- checksums and references to supplemental evidence.

The extensible type-length-value format allows older readers to skip fields they do not understand. A truncated final record is reported as a warning; complete preceding records remain recoverable.

Large evidence uses a separate compressed attachment stream. The primary record retains event number, attachment identity, hashes, content type, size, sampling decision, and storage location. Rotation, retention, maximum size, and rate-based probabilistic sampling are independently policy-controlled.

## Runtime integrity for logs

Three runtime record-integrity modes are supported:

1. `HASH_CHAINED`: segment and attachment manifests are cryptographically hashed and chained.
2. `EPHEMERAL_SIGNED`: a runtime Ed25519 identity signs closed segment manifests. The private key is never intentionally persisted or exposed. It evolves on a policy schedule, **one day by default**, and prior epoch keys are discarded to improve forward integrity.
3. `EXTERNAL_SIGNED`: a narrow external signer interface may sign closed manifests using operator-controlled key material.

An ephemeral public key stored only with the logs is self-recorded evidence. Exporting or witnessing its fingerprint outside the mutable corpus materially strengthens it. Python cannot guarantee perfect memory zeroization, so the documentation describes the protection as best-effort key erasure rather than absolute proof.

Using a separate logging agent and sending records to an external collection system improves security further. An attacker must then compromise both the application host and the independent log destination, or interfere before the records leave the source. The local append-only store remains useful for availability, low-latency interrogation, and evidence continuity, but external replication is strongly recommended for higher-assurance deployments.

## System-data collection

The optional collector records nearly raw, timestamp-annotated data from configured `/proc` and `/sys` sources on a synchronized cycle. It follows the application root PID and descendants by default and does not assume a single-process application.

Built-in host sources include:

- `/proc/schedstat`
- `/proc/zoneinfo`
- `/proc/meminfo`
- `/proc/vmstat`
- `/proc/diskstats`
- `/proc/pressure/cpu`
- `/proc/pressure/memory`
- `/proc/pressure/io`

Built-in per-process sources include `cmdline`, `io`, `sched`, `schedstat`, `stat`, `statm`, and `status`.

System records use a separate output tree with independent rotation, compression, and retention. Semantic parsers and the advanced metrics provider are intentionally deferred; the current collector preserves source bodies for external or future parsers.

## Local administrative interface

A supervised application exposes local Unix-domain sockets under its run directory:

```text
<directory>/run/events.sock
<directory>/run/control.sock
```

These are logical paths. If an absolute socket pathname would exceed the platform `AF_UNIX` limit, Caretaker places only that ephemeral socket in a deterministic private per-user runtime directory. The configured data/evidence directory is not moved, and Caretaker clients resolve the mapping automatically.

Authentication uses file permissions and peer credentials. The protocol is declarative and does not accept Python, shell commands, or arbitrary executable paths.

```bash
caretaker-logging control /var/lib/invoice-service/caretaker/run/control.sock status
caretaker-logging control /var/lib/invoice-service/caretaker/run/control.sock mode-acquire \
  --mode repair --reason "investigate incident INC-1042"
caretaker-logging control /var/lib/invoice-service/caretaker/run/control.sock mode-release \
  --lease-id <uuid>
```

## Baselines and slow drift

```bash
caretaker-logging baseline generate \
  --segments /var/lib/invoice-service/caretaker/application/events \
  --store /var/lib/invoice-service/caretaker/baselines \
  --application-id invoice-service \
  --application-version 2026.07 \
  --environment-id production \
  --workload-label monthly \
  --accept
```

Multiple accepted baselines may coexist. Comparisons separate:

- absolute growth;
- relative growth;
- growth per unit of work;
- capability additions and removals;
- gradual trend slopes and slow-drift score.

Population designators supplied by decorators can partition one function into separate analytical populations when behavior depends materially on selected inputs.

## Interrogation and root-cause hypotheses

```bash
caretaker-logging interrogate \
  --segments /var/lib/invoice-service/caretaker/application/events \
  --objective "explain the July latency and error increase"
```

Add `--ollama-model <model>` to request an advisory structured assessment. The LLM receives bounded, redacted evidence summaries rather than the complete raw corpus. It may rank anomalies, propose hypotheses, comment on reports, and recommend additional evidence. Final root-cause determination remains with the administrator. Automatic Repair may deploy eligible fixes only when the operator has explicitly enabled standing self-repair authority.

## Installation

```bash
python -m pip install caretaker-0.6.0-py3-none-any.whl
```

Ephemeral Ed25519 signing requires the optional cryptography backend:

```bash
python -m pip install 'Caretaker[signing]'
```

Release manifests remain an offline OpenPGP workflow. The ordinary station command
is `make sign-release-set KEY_SLOT=a`; the authorized primary fingerprint is read
from `root.json`, checked against the station's usable secret signing subkey, and
passed to the small reviewable GnuPG wrapper. `make signing-bundle` creates a
minimal non-overwriting station directory, while `make signing-status` reports
missing artifacts, certificates, and signatures. `MANIFEST.in` is packaging
metadata, not the release integrity manifest. See
[`docs/SIGNING_STATION.md`](docs/SIGNING_STATION.md); Caretaker never receives or
stores the release private key.

Development:

```bash
python -m pip install -e '.[dev,signing]'
pytest
```

## Important boundaries

Caretaker is alpha research software, not an operating-system security boundary. No specific behavior is guaranteed; the properties described here are implementation targets supported to varying degrees by current code and tests.

- Python audit hooks and introspection do not contain native extensions, `ctypes`, a compromised interpreter, kernel-level access, or a same-user attacker with unrestricted process-memory access.
- Local hashes without an external commitment can be rewritten together with the corpus.
- Self-recorded ephemeral identities do not prevent wholesale public-key substitution unless the public fingerprint is independently anchored.
- Caretaker never stores private OpenPGP release keys and cannot sign release manifests.
- Caretaker does not repair its own implementation.
- System collection is limited to sources readable by the application account.
- LLM assessments are interpretations, not source evidence.

See [`ARCHITECTURE.md`](ARCHITECTURE.md), [`docs/LOGGING_INTEGRITY.md`](docs/LOGGING_INTEGRITY.md), [`docs/GUARD_SECURITY.md`](docs/GUARD_SECURITY.md), and [`docs/FUTURE_WORK.md`](docs/FUTURE_WORK.md).

Security issues should be reported according to [`SECURITY.md`](SECURITY.md). The supported research and test environments are also listed there.
