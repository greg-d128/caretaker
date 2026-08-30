# Isolated Execution for Caretaker 0.6.1

**Applies to:** Caretaker `0.6.1`
**Status:** operator, validation-backend, and research deployment guidance
**Scope:** candidate-validation isolation plus isolation of the complete application and Caretaker runtime
**Built-in validation backends:** PROCESS, rootless Podman CONTAINER, and Multipass VM. Docker-rootless and EXTERNAL adapters remain future work.

## 1. Purpose

Caretaker parses, compiles, and exercises generated candidates in a child process before activation. This protects the main interpreter from many crashes and state mutations, but it is not a hostile-code sandbox.

The child process can inherit resources available to the application account, including:

- readable files;
- writable application data;
- environment variables;
- local services;
- network access;
- process visibility;
- credentials;
- Unix-domain sockets;
- operating-system limits.

After activation, the candidate executes inside the application process and has the application's runtime objects and privileges.

There are now two distinct isolation uses:

1. **Candidate-validation isolation**, where Caretaker remains on the host/supervised application boundary and sends only a validation request into a rootless Podman container or pre-provisioned Multipass validator VM.
2. **Whole-subject isolation**, where the application, Caretaker supervisor, Guard, evidence store, and validation worker all run inside a Docker container or Multipass VM.

Docker and Multipass can still place a stronger boundary around the complete subject environment:

```text
Host or trusted controller
        |
        +-- Docker container or Multipass VM
                |
                +-- application
                +-- Caretaker supervisor
                +-- Guard
                +-- child-process validation worker
                +-- evidence storage
```

These environments reduce risk during development, research, adversarial testing, dependency comparison, and demonstration. They do not convert Caretaker into a formally verified sandbox.

## Built-in candidate-validation backends

The least-friction default is PROCESS validation. A normal `RepairEngine`
configuration uses the local subprocess backend and does not require Podman or
Multipass. Isolation is increased by policy: set
`ValidationPolicy.minimum_isolation` to `CONTAINER` or `VM`, and configure the
corresponding backend. Caretaker selects the lowest available configured
backend that satisfies that policy; it does not silently upgrade or downgrade
the requested boundary.

The repair engine accepts a validation backend implementing the common capability contract. Policy chooses a minimum isolation level rather than a product name:

```python
from caretaker import RepairEngine, ValidationIsolationLevel, ValidationPolicy
from caretaker.validation import (
    MultipassValidationBackend,
    RootlessPodmanValidationBackend,
)

podman = RootlessPodmanValidationBackend(
    "caretaker-validator:local",
    workspace="/srv/invoice-service",
)

multipass = MultipassValidationBackend(
    instance_name="caretaker-validator",
    clean_snapshot="caretaker-clean",
)

engine = RepairEngine(validation_backends=(podman, multipass))
```

When several backends are configured, Caretaker selects the lowest available isolation tier that satisfies the target policy. The legacy singular `validation_backend=` argument remains supported.

A repair policy can require the VM tier independently of which backend objects are installed:

```python
ValidationPolicy(minimum_isolation=ValidationIsolationLevel.VM)
```

If only PROCESS or CONTAINER validation is available, `backend_unavailable_action` determines whether the candidate fails, remains proposal-only, or enters explicit operator review. Required isolation is non-overridable: approval may retain a proposal for review but cannot activate the candidate without validation at the requested tier. Select `FAIL_REPAIR` when missing isolation should also avoid creating a pending review item.

Validation worker IPC uses a versioned JSON envelope and an explicit data-only
codec. Registered cases support bounded JSON-compatible primitives, tuples,
mappings with string keys, and the `RegisteredCase` record; arbitrary
application objects are rejected before the worker starts. The parent also
checks the worker result's transaction binding and mandatory evidence. The
transport is still not an authenticated, independently attested protocol for
mutually untrusted validators; external result authentication remains future
work.

`RootlessPodmanValidationBackend` requires a locally present image and verified rootless Podman. It does not pull images automatically. The validation container uses no network, a read-only root filesystem, dropped Linux capabilities, `no-new-privileges`, bounded PID/CPU/memory settings, a private writable request/result directory, and read-only source inputs.

`MultipassValidationBackend` requires a pre-provisioned validator guest and refuses instances with host-directory mounts. Request/result artifacts move with `multipass transfer`. In normal mode Caretaker can restore a configured clean snapshot before each validation. `disposable_clone=True` instead clones a stopped clean template for one validation and purges the clone afterward.

The VM backend does not infer that guest egress is safe merely because Multipass is in use. By default it requires a root-owned `/etc/caretaker/validation-network-isolated` provisioning marker and verifies that the guest has no IPv4 or IPv6 default route at validation time. Create that marker only after the guest firewall/egress policy has been installed and enabled. This route check is not a complete firewall or egress attestation.

## 2. Isolation levels

| Level | Boundary | Appropriate use |
|---|---|---|
| Child process only | Same host, account, and filesystem access | ordinary development with trusted candidates |
| Hardened Docker container | Separate process, mount, user, network, and resource namespaces; shared host kernel | routine Caretaker testing and moderately adversarial candidate testing |
| Multipass VM | Separate guest kernel with no host mount | hostile-candidate research, Guard experiments, dependency comparison, and combined internal/external observation |
| Dedicated disposable host | Separate physical system | kernel, runtime-escape, device, and host-service testing |

## 3. General rules

Apply these rules to every isolated environment:

1. Do not use production credentials, personal data, SSH keys, cloud credentials, browser profiles, or reusable secrets.
2. Do not mount the Docker socket, containerd socket, host root filesystem, SSH agent, or home directory into the subject.
3. Do not use Docker `--privileged`.
4. Do not use host PID, IPC, user, or network namespaces.
5. Install Caretaker, the application, and policy as files that the subject account cannot modify.
6. Give the subject a separate writable evidence directory.
7. Deny Internet egress unless a scenario specifically requires controlled network access.
8. Place Ollama behind a private endpoint. Do not expose Ollama publicly.
9. Keep independent test oracles and external observations outside the subject's writable boundary.
10. Destroy the environment after exporting required evidence.
11. Verify the Caretaker wheel and retained policy before installation.
12. Record the container image digest or VM image identity used for the run.
13. Record Python, Caretaker, application, dependency, model, and policy versions.
14. Treat system evidence from a container or VM as evidence about that namespace or guest, not automatically about the host.

## 4. Caretaker-specific limitations

The environment described here does not change these `0.6.1` properties:

- PROCESS candidate validation uses a subprocess; CONTAINER and VM backends provide stronger configured boundaries;
- arbitrary hard interruption remains deferred;
- `@repair_on_timeout` uses a soft timeout;
- activated candidates run in the application interpreter;
- native extensions and `ctypes` can operate below Python-level Guard visibility;
- subprocesses create a new observation and containment problem;
- generated Repair cannot modify `caretaker.*`;
- general replacement of already imported third-party modules uses quarantine plus supervised restart;
- reliable remote `LogSink` delivery remains future work;
- accepted executable regression cases are bounded and remain in memory; an
  opt-in persistent store now retains only integrity-checked, bounded,
  data-only fixture evidence marked `DATA_ONLY_NOT_EXECUTABLE`;
- historical fixture replay requires explicit policy opt-in and an isolated
  backend meeting the configured minimum (VM by default); the backend receives
  JSON-only evidence and owns rehydration inside its boundary;
- a self-recorded runtime signing identity does not prevent complete local corpus replacement;
- system collection inside Docker observes the container namespace;
- system collection inside Multipass observes the guest VM.

Historical replay is intentionally not implemented by reusing the PROCESS
candidate-validation backend. `IsolatedReplayCoordinator` verifies fixture
integrity, replay safety, source identity, and backend capability before
dispatch. A deployment can configure one or more replay backends once; the
coordinator selects the lowest available backend satisfying policy. If no
backend is configured or available, replay fails closed.

`RootlessPodmanReplayBackend` is an advanced, opt-in backend. It supports only
fixtures marked `JSON_EXACT`, runs the Caretaker worker installed in a
provisioned image, and does not mount either the live Caretaker checkout or the
application workspace. Its minimum practical policy is
`CONTAINER`; the default `VM` requirement deliberately rejects it when a VM
backend is required:

```python
from caretaker import (
    IsolatedReplayCoordinator,
    RootlessPodmanReplayBackend,
    ValidationIsolationLevel,
)

backend = RootlessPodmanReplayBackend("caretaker-replay:trusted")
# Set logging.regression.replay_minimum_isolation = "CONTAINER" only when
# container isolation is sufficient for the deployment's threat model.
coordinator = IsolatedReplayCoordinator(
    store,
    policy=policy,
    backends=(backend,),
)
result = coordinator.execute(
    fixture_id,
    entrypoint="charge",
    source=trusted_subject_source,
)
```

Passing `backend=...` directly to `execute` remains supported for one-off
dispatch and compatibility. Supplying `backends=(...)` to the coordinator is
the policy-driven path when a deployment has both container and VM options.

The container image must be provisioned and verified by the operator; Caretaker
does not pull it. A VM backend with guest attestation and disposable-state
semantics remains future work.

## 5. Recommended repository layout

```text
docs/
    ISOLATED_EXECUTION.md

isolated/
    docker/
        Dockerfile
        compose.yaml
        README.md
    podman/
        Containerfile
        README.md
        verify-rootless.sh
    multipass/
        cloud-init.yaml
        README.md

dist/
    caretaker-0.6.1-py3-none-any.whl

policy/
    application.toml

application/
    pyproject.toml
    src/
        example_application/

evidence/
    .gitkeep
```

Do not commit generated evidence, private data, model prompts containing application values, runtime signing private material, or external credentials.

# Part I: Hardened Docker environment

## 6. When to use Docker

Use the Docker setup for:

- Caretaker installation and CLI checks;
- ordinary Repair scenarios;
- Logging record, attachment, and recovery tests;
- policy and mode-lease tests;
- Guard behavior observation;
- controlled dependency experiments;
- baseline generation;
- interrogation;
- moderate fault injection;
- static or controlled Ollama provider use.

Use Multipass instead when deliberately testing native code, `ctypes`, hostile subprocesses, aggressive resource abuse, or container-boundary attacks.

## 7. Docker host preparation

Rootless Docker is preferred when available.

Confirm that:

```bash
docker info
docker version
docker compose version
```

Review the security options reported by `docker info`. Keep the default seccomp profile enabled.

Create empty evidence storage:

```bash
mkdir -p evidence
chmod 700 evidence
```

Do not place the Caretaker source tree or unrelated host files in this directory.

## 8. Example Dockerfile

Save as `isolated/docker/Dockerfile`:

```dockerfile
FROM python:3.13-slim

ARG CARETAKER_WHEEL=caretaker-0.6.1-py3-none-any.whl

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH=/opt/caretaker/venv/bin:$PATH

RUN groupadd --gid 10001 caretaker \
    && useradd --uid 10001 --gid 10001 \
       --home-dir /nonexistent --no-create-home \
       --shell /usr/sbin/nologin caretaker \
    && python -m venv /opt/caretaker/venv \
    && mkdir -p /opt/caretaker/app \
                /etc/caretaker \
                /var/lib/caretaker \
                /run/caretaker \
    && chown -R root:root /opt/caretaker /etc/caretaker \
    && chown caretaker:caretaker /var/lib/caretaker /run/caretaker \
    && chmod 0755 /opt/caretaker /opt/caretaker/app \
    && chmod 0750 /etc/caretaker \
    && chmod 0700 /var/lib/caretaker /run/caretaker

COPY dist/${CARETAKER_WHEEL} /tmp/caretaker.whl
RUN /opt/caretaker/venv/bin/pip install --no-cache-dir /tmp/caretaker.whl \
    && rm -f /tmp/caretaker.whl

COPY application/ /opt/caretaker/app/
RUN /opt/caretaker/venv/bin/pip install --no-cache-dir /opt/caretaker/app \
    && chown -R root:root /opt/caretaker/app /opt/caretaker/venv \
    && chmod -R go-w /opt/caretaker/app /opt/caretaker/venv

COPY policy/application.toml /etc/caretaker/application.toml
RUN chown root:root /etc/caretaker/application.toml \
    && chmod 0640 /etc/caretaker/application.toml

USER 10001:10001
WORKDIR /var/lib/caretaker

ENTRYPOINT [
  "/opt/caretaker/venv/bin/python",
  "-m",
  "caretaker.run",
  "--policy",
  "/etc/caretaker/application.toml",
  "example_application"
]
```

Replace `example_application` with the installed application module.

For repeatable security testing, pin the base image by digest after selecting and reviewing the intended image.

## 9. Example Compose configuration

Save as `isolated/docker/compose.yaml`:

```yaml
services:
  subject:
    build:
      context: ../..
      dockerfile: isolated/docker/Dockerfile
      args:
        CARETAKER_WHEEL: caretaker-0.6.1-py3-none-any.whl

    image: caretaker-subject:0.6.1
    container_name: caretaker-subject

    user: "10001:10001"
    read_only: true
    init: true

    cap_drop:
      - ALL

    security_opt:
      - no-new-privileges:true

    pids_limit: 128
    mem_limit: 2g
    memswap_limit: 2g
    cpus: 2.0

    ulimits:
      nofile:
        soft: 1024
        hard: 2048
      nproc:
        soft: 128
        hard: 128
      core:
        soft: 0
        hard: 0

    network_mode: none

    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777
      - /run/caretaker:rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700

    volumes:
      - caretaker-evidence:/var/lib/caretaker

    restart: "no"

volumes:
  caretaker-evidence:
```

This configuration deliberately provides no network access. Use a static provider, pre-generated candidate fixtures, or diagnostic-only operation for this profile.

## 10. Build and run

From the repository root:

```bash
docker compose \
  -f isolated/docker/compose.yaml \
  build --pull
```

Review the effective Compose configuration:

```bash
docker compose \
  -f isolated/docker/compose.yaml \
  config
```

Start the subject:

```bash
docker compose \
  -f isolated/docker/compose.yaml \
  up --abort-on-container-exit
```

Run the policy checks inside a one-off container:

```bash
docker compose \
  -f isolated/docker/compose.yaml \
  run --rm --entrypoint caretaker-logging subject \
  policy explain --file /etc/caretaker/application.toml

docker compose \
  -f isolated/docker/compose.yaml \
  run --rm --entrypoint caretaker-logging subject \
  policy effective --file /etc/caretaker/application.toml
```

## 11. Verify the effective Docker restrictions

Inspect the running container:

```bash
docker inspect caretaker-subject \
  --format 'read_only={{.HostConfig.ReadonlyRootfs}}'

docker inspect caretaker-subject \
  --format 'privileged={{.HostConfig.Privileged}}'

docker inspect caretaker-subject \
  --format 'user={{.Config.User}}'

docker inspect caretaker-subject \
  --format 'cap_drop={{json .HostConfig.CapDrop}}'

docker inspect caretaker-subject \
  --format 'security_opt={{json .HostConfig.SecurityOpt}}'

docker inspect caretaker-subject \
  --format 'pids_limit={{.HostConfig.PidsLimit}}'

docker inspect caretaker-subject \
  --format 'memory={{.HostConfig.Memory}}'

docker inspect caretaker-subject \
  --format 'network_mode={{.HostConfig.NetworkMode}}'

docker inspect caretaker-subject \
  --format 'mounts={{json .Mounts}}'
```

Expected properties:

```text
read_only=true
privileged=false
user=10001:10001
cap_drop includes ALL
security_opt includes no-new-privileges:true
pids_limit is nonzero
memory is nonzero
network_mode=none
no Docker socket mount
no host source-tree mount
```

Check from inside:

```bash
docker exec caretaker-subject id
docker exec caretaker-subject sh -c 'test ! -w /opt/caretaker/venv'
docker exec caretaker-subject sh -c 'test ! -w /opt/caretaker/app'
docker exec caretaker-subject sh -c 'test ! -w /etc/caretaker/application.toml'
docker exec caretaker-subject sh -c 'test -w /var/lib/caretaker'
```

## 12. Docker with Ollama on a private network

When Caretaker needs Ollama, run Ollama as a separate service on an internal Docker network.

The subject receives access to Ollama, but the network does not provide ordinary Internet egress.

Example addition to `compose.yaml`:

```yaml
services:
  subject:
    network_mode: null
    networks:
      - caretaker-private

  ollama:
    image: ollama/ollama:latest
    expose:
      - "11434"
    networks:
      - caretaker-private
    volumes:
      - ollama-models:/root/.ollama
    restart: "no"

networks:
  caretaker-private:
    internal: true

volumes:
  ollama-models:
```

Configure `OllamaRepairProvider`, `OllamaBehaviorAssessmentProvider`, or `OllamaRootCauseProvider` to use the private service endpoint and set `allow_remote_endpoint=True` explicitly:

```text
http://ollama:11434
```

Additional rules:

- do not publish port `11434`;
- attach GPU devices only to the Ollama service, not to the Caretaker subject;
- pre-load models before disconnecting Internet access;
- record the model name and model artifact identity;
- treat model output as untrusted;
- keep deterministic policy and validation gates authoritative.

## 13. Docker evidence export

Find the volume:

```bash
docker volume inspect caretaker-evidence
```

Export it without mounting unrelated host paths into the subject:

```bash
mkdir -p exported-evidence

docker run --rm \
  -v caretaker-evidence:/source:ro \
  -v "$PWD/exported-evidence:/destination" \
  alpine:3 \
  sh -c 'cp -a /source/. /destination/'
```

Verify record framing, segment chains, manifests, attachment references, runtime signatures, and external anchors before relying on the derived SQLite index.

## 14. Docker cleanup

```bash
docker compose \
  -f isolated/docker/compose.yaml \
  down --volumes --remove-orphans

docker image rm caretaker-subject:0.6.1
rm -rf exported-evidence
```

Retain exported evidence only when the test requires it.

# Part II: Multipass environment

## 15. Why Multipass is stronger

A Docker container shares the host kernel. A Multipass instance runs a separate Ubuntu guest kernel under the host hypervisor.

The recommended Multipass layout also avoids host directory mounts. Artifacts enter and leave through explicit file transfer.

A compromise inside the guest would still have to cross the VM boundary to affect the host. This is a substantial practical improvement for hostile-candidate research, but it is not a formal security guarantee.

Restrict access to the Multipass service to trusted host users. Control of the Multipass daemon provides control over instances and host mounts.

## 16. When to use Multipass

Use Multipass for:

- intentionally hostile candidate fixtures;
- native extension and `ctypes` experiments;
- subprocess behavior;
- multi-version supply-chain analysis;
- Guard plus external packet or process observation;
- resource-exhaustion tests;
- incident-reconstruction exercises;
- testing policy and evidence behavior after forced process failure.

Use a dedicated disposable host for testing guest-kernel or hypervisor escape behavior.

## 17. Example cloud-init

Save as `isolated/multipass/cloud-init.yaml`:

```yaml
#cloud-config

users:
  - default

  - name: caretaker-subject
    uid: 22001
    gecos: Caretaker isolated subject
    shell: /usr/sbin/nologin
    lock_passwd: true
    sudo: []
    groups: []

package_update: true
package_upgrade: true

packages:
  - python3
  - python3-venv
  - python3-pip
  - nftables
  - curl
  - ca-certificates
  - tcpdump

write_files:
  - path: /etc/nftables.conf
    owner: root:root
    permissions: "0644"
    content: |
      flush ruleset

      table inet caretaker {
        chain output {
          type filter hook output priority 0;
          policy accept;

          meta skuid 22001 ip daddr 127.0.0.0/8 accept
          meta skuid 22001 ip6 daddr ::1 accept
          meta skuid 22001 reject
        }
      }

runcmd:
  - [mkdir, -p, /opt/caretaker/app]
  - [mkdir, -p, /etc/caretaker]
  - [mkdir, -p, /var/lib/caretaker]
  - [mkdir, -p, /run/caretaker]
  - [python3, -m, venv, /opt/caretaker/venv]
  - [chown, -R, root:root, /opt/caretaker]
  - [chown, -R, root:root, /etc/caretaker]
  - [chown, -R, caretaker-subject:caretaker-subject, /var/lib/caretaker]
  - [chown, -R, caretaker-subject:caretaker-subject, /run/caretaker]
  - [chmod, "0755", /opt/caretaker]
  - [chmod, "0755", /opt/caretaker/app]
  - [chmod, "0750", /etc/caretaker]
  - [chmod, "0700", /var/lib/caretaker]
  - [chmod, "0700", /run/caretaker]
  - [systemctl, enable, --now, nftables]
  - [touch, /etc/caretaker/validation-network-isolated]
  - [chown, root:root, /etc/caretaker/validation-network-isolated]
  - [chmod, "0644", /etc/caretaker/validation-network-isolated]
```

The subject account has no password and no sudo rule.

The `nftables` policy permits loopback traffic for the subject UID and rejects other outbound traffic. This allows a local Ollama or controlled loopback service while blocking ordinary guest-network egress from the Caretaker subject. The root-owned `validation-network-isolated` file is a provisioning assertion consumed by the built-in Multipass validation backend; create it only after the firewall policy is active.

## 18. Launch the VM

```bash
multipass launch 24.04 \
  --name caretaker-lab \
  --cpus 4 \
  --memory 8G \
  --disk 40G \
  --cloud-init isolated/multipass/cloud-init.yaml
```

Wait for cloud-init:

```bash
multipass exec caretaker-lab -- \
  cloud-init status --wait
```

Review instance information:

```bash
multipass info caretaker-lab
```

Do not use `multipass mount` for the Caretaker source tree, policy, credentials, or host evidence.

## 19. Transfer and install Caretaker

Transfer the wheel:

```bash
multipass transfer \
  dist/caretaker-0.6.1-py3-none-any.whl \
  caretaker-lab:/tmp/caretaker.whl
```

Install as root into the root-owned virtual environment:

```bash
multipass exec caretaker-lab -- \
  sudo /opt/caretaker/venv/bin/pip install \
  --no-cache-dir /tmp/caretaker.whl
```

Transfer the application package or wheel:

```bash
multipass transfer \
  dist/example-application.whl \
  caretaker-lab:/tmp/example-application.whl

multipass exec caretaker-lab -- \
  sudo /opt/caretaker/venv/bin/pip install \
  --no-cache-dir /tmp/example-application.whl
```

Transfer the policy:

```bash
multipass transfer \
  policy/application.toml \
  caretaker-lab:/tmp/application.toml

multipass exec caretaker-lab -- \
  sudo install \
  -o root -g root -m 0640 \
  /tmp/application.toml \
  /etc/caretaker/application.toml
```

Remove transfer files:

```bash
multipass exec caretaker-lab -- \
  sudo rm -f \
  /tmp/caretaker.whl \
  /tmp/example-application.whl \
  /tmp/application.toml
```

## 20. Validate the guest boundary

Confirm the subject identity:

```bash
multipass exec caretaker-lab -- \
  sudo -u caretaker-subject -- id
```

Confirm the subject cannot use sudo:

```bash
multipass exec caretaker-lab -- \
  sh -c 'sudo -u caretaker-subject -- sudo -n true; test $? -ne 0'
```

Confirm Caretaker and policy are not writable:

```bash
multipass exec caretaker-lab -- \
  sudo -u caretaker-subject -- \
  test ! -w /opt/caretaker/venv

multipass exec caretaker-lab -- \
  sudo -u caretaker-subject -- \
  test ! -w /opt/caretaker/app

multipass exec caretaker-lab -- \
  sudo -u caretaker-subject -- \
  test ! -w /etc/caretaker/application.toml
```

Confirm evidence is writable:

```bash
multipass exec caretaker-lab -- \
  sudo -u caretaker-subject -- \
  test -w /var/lib/caretaker
```

Confirm non-loopback egress is denied:

```bash
multipass exec caretaker-lab -- \
  sh -c 'sudo -u caretaker-subject -- curl -fsS --max-time 5 https://example.com; test $? -ne 0'
```

## 21. Review the Caretaker policy

```bash
multipass exec caretaker-lab -- \
  sudo -u caretaker-subject -- \
  /opt/caretaker/venv/bin/caretaker-logging \
  policy explain \
  --file /etc/caretaker/application.toml

multipass exec caretaker-lab -- \
  sudo -u caretaker-subject -- \
  /opt/caretaker/venv/bin/caretaker-logging \
  policy effective \
  --file /etc/caretaker/application.toml
```

## 22. Run the application under Caretaker

```bash
multipass exec caretaker-lab -- \
  sudo -u caretaker-subject -- \
  env \
    HOME=/var/lib/caretaker \
    PYTHONUNBUFFERED=1 \
  /opt/caretaker/venv/bin/python \
  -m caretaker.run \
  --policy /etc/caretaker/application.toml \
  example_application
```

Replace `example_application` with the installed module.

## 23. Ollama placement in Multipass

The strongest practical arrangement is:

```text
Multipass guest
    |
    +-- root-controlled Ollama service on 127.0.0.1:11434
    |
    +-- unprivileged Caretaker subject
            |
            +-- allowed to reach loopback
            +-- denied non-loopback egress
```

Install Ollama only after reviewing the package and deployment method appropriate for the test host.

Bind Ollama to loopback only. Do not expose it through a bridged interface.

Configure Caretaker providers to use:

```text
http://127.0.0.1:11434
```

The model store should not be writable by `caretaker-subject`.

For tests that do not require an LLM, omit Ollama and use static providers, stored fixtures, or analysis-only modes.

## 24. Multi-version application and dependency analysis

Use a new VM or a restored clean snapshot for each version.

Recommended sequence:

1. Launch and provision the clean VM.
2. Install Caretaker `0.6.1`.
3. Install application or dependency version A.
4. Verify integrity and record exact identities.
5. Run representative workloads in Research mode.
6. Export authoritative events, Guard evidence, attachments, system records, manifests, and policy snapshots.
7. Destroy or restore the VM.
8. Install version B in a clean environment.
9. Run the identical workload.
10. Compare:
    - outputs and exceptions;
    - imports;
    - network destinations;
    - filesystem roots;
    - subprocesses;
    - dynamic-code operations;
    - runtime fingerprints;
    - import-time effects;
    - rates and timing;
    - system evidence.
11. Correlate Guard's internal attribution with an external observer.
12. Treat differences as evidence requiring interpretation, not proof of compromise.

Caretaker `0.6.1` contains the identity, baseline, deviation, inspection, and evidence contracts for this workflow. A complete automated old-versus-new environment runner remains future work.

## 25. External packet observation

Run packet capture as root so the subject account cannot administer it:

```bash
stamp="$(date -u +%Y%m%dT%H%M%SZ)"

multipass exec caretaker-lab -- \
  sudo sh -c \
  "nohup tcpdump -i lo -U -w /var/tmp/caretaker-${stamp}.pcap >/var/tmp/tcpdump-${stamp}.log 2>&1 & echo \$! >/var/tmp/tcpdump-${stamp}.pid"
```

Run the Caretaker scenario.

Stop capture:

```bash
multipass exec caretaker-lab -- \
  sudo sh -c \
  "kill \$(cat /var/tmp/tcpdump-${stamp}.pid)"
```

Export the capture:

```bash
multipass transfer \
  caretaker-lab:/var/tmp/caretaker-${stamp}.pcap \
  evidence/
```

This produces an external operating-system observation view within the guest. It remains separate from Guard's application-internal attribution.

For stronger independence, collect network and process evidence outside the guest with a trusted host or dedicated observer.

## 26. Export Caretaker evidence

Create an archive as root:

```bash
multipass exec caretaker-lab -- \
  sudo tar \
  --numeric-owner \
  -C /var/lib \
  -czf /var/tmp/caretaker-evidence.tgz \
  caretaker
```

Transfer it:

```bash
multipass transfer \
  caretaker-lab:/var/tmp/caretaker-evidence.tgz \
  evidence/
```

Record the archive hash:

```bash
sha256sum evidence/caretaker-evidence.tgz
```

Preserve external anchors and packet captures separately from the guest evidence archive.

## 27. Snapshot and reset

After provisioning and before running the subject:

```bash
multipass snapshot caretaker-lab \
  --name clean-caretaker-0.6.1
```

Restore between campaigns when supported by the installed Multipass release:

```bash
multipass restore caretaker-lab.clean-caretaker-0.6.1
```

A new VM remains preferable when testing persistence, rollback, root continuity, or suspected environment compromise.

## 28. Destroy the VM

After exporting required evidence:

```bash
multipass delete caretaker-lab
multipass purge
```

Verify that no host mount remains and remove exported evidence that is no longer required.

# Part III: Evidence and incident handling

## 29. Evidence authority

Preserve:

- primary event segments;
- attachment segments;
- system-data streams;
- closed manifests;
- hash-chain commitments;
- runtime public identities;
- key-transition records;
- accepted baselines;
- policy snapshots;
- administrative actions;
- external packet or process observations.

SQLite is a derived index and can be rebuilt.

## 30. Evidence protection profiles

### Basic

```text
HASH_CHAINED
```

Use for ordinary development and crash-recovery tests.

### Improved local post-run resistance

```text
EPHEMERAL_SIGNED
```

Install the signing extra and configure a one-day maximum epoch unless policy requires another value.

### Stronger provenance

Export the runtime public-key fingerprint or manifest commitment to a location the subject cannot modify.

### Strongest supported architecture

Use the external signer protocol or independent evidence witnessing. The built-in `0.6.1` event writer remains local, so reliable remote shipping requires an operator-supplied process or future `LogSink`.

## 31. Incident workflow in an isolated environment

1. Preserve the current VM or container state.
2. Export authoritative evidence and external observations.
3. Record the effective policy generation and active leases.
4. Verify segment and attachment commitments.
5. Verify runtime signing identities and transitions.
6. Rebuild the derived index when integrity is uncertain.
7. Interrogate the bounded timeline.
8. Escalate to Research or Forensic mode with a scoped lease.
9. Add only required evidence capabilities.
10. Promote to `PROPOSE_ONLY` or `REQUIRE_OPERATOR_APPROVAL` Repair when evidence supports it.
11. Revalidate when the policy generation changes.
12. Activate only an eligible candidate.
13. Observe candidate behavior and external effects during probation.
14. Roll back or accept.
15. Export the candidate, evidence, and durable source patch for normal review.
16. Release temporary leases and reconcile with the current base policy.
17. Destroy or archive the isolated environment according to the investigation plan.

## 32. Final checklist

Before running:

```text
[ ] Caretaker artifact verified
[ ] application and dependency identities recorded
[ ] policy reviewed with policy explain and policy effective
[ ] subject account cannot modify Caretaker, application, or policy
[ ] no production credentials present
[ ] no host source-tree mount
[ ] no Docker or Multipass control socket exposed to the subject
[ ] network policy verified
[ ] resource limits verified
[ ] evidence directory is separate and writable
[ ] external observer is outside subject control
[ ] cleanup and evidence-export procedure tested
```

After running:

```text
[ ] authoritative evidence exported
[ ] archive hashes recorded
[ ] external observations exported separately
[ ] manifests and chains verified
[ ] derived index treated as rebuildable
[ ] active repair and policy state recorded
[ ] secrets and sensitive evidence handled appropriately
[ ] container or VM destroyed when no longer required
```

## 33. Security interpretation

This guidance provides a better-than-default isolation posture for alpha research software.

It does not guarantee containment of:

- host-kernel vulnerabilities;
- container-runtime vulnerabilities;
- guest-kernel vulnerabilities;
- hypervisor vulnerabilities;
- compromised host administrators;
- compromised Multipass or Docker control services;
- malicious hardware or firmware;
- secrets deliberately introduced into the subject;
- application behavior that legitimately possesses dangerous privileges.

The most important rule is separation of trust:

```text
subject code and Caretaker
        |
        | cannot modify
        v
policy, independent oracle, external evidence, and host controller
```

Docker is the convenient default. Multipass is the recommended boundary for adversarial Caretaker research and hostile-candidate testing.
