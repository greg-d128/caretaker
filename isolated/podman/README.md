# Caretaker rootless Podman worker image

This directory defines the repository-owned worker image used by
`RootlessPodmanReplayBackend`. It is deliberately a worker image, not a
complete application image: the application, policy, evidence, and operator
credentials remain outside the image and are not mounted into replay.

The image installs Caretaker from the reviewed wheel built by this repository.
Replay then mounts only a temporary request/result directory, supplies exact
JSON fixture values, and runs with no network, a read-only root filesystem,
no Linux capabilities, bounded resources, and a non-root user. Caretaker does
not pull or trust an image automatically; the operator must review and
provision it.

## Host prerequisites

On Ubuntu, install the rootless runtime and helpers:

```sh
sudo apt-get update
sudo apt-get install -y podman uidmap fuse-overlayfs passt crun
```

Rootless Podman needs a subordinate UID and GID range for the operator account:

```sh
grep "^$(id -un):" /etc/subuid /etc/subgid
command -v newuidmap newgidmap
podman info --format json
podman run --rm --network=none alpine:latest true
```

The last command is only a rootless runtime smoke test. Caretaker images
should be provisioned from reviewed inputs; the Caretaker replay backend never
pulls an image.

## Build a local image

The ordinary Caretaker path does not require Podman. Use the process-level
validation default to get started, and add this image only when policy requires
container isolation or when an operator explicitly enables container replay.

For a quick local smoke test, build with the Makefile default:

```sh
make podman-image
```

That default follows the `python:3.13-slim` tag and is convenient for local
development. For a reviewed or production image, resolve and review the base
image digest first:

```sh
podman pull python:3.13-slim
BASE_IMAGE="$(podman image inspect python:3.13-slim \
  --format '{{index .RepoDigests 0}}')"
printf '%s\n' "$BASE_IMAGE"
make podman-image \
  PODMAN_BASE_IMAGE="$BASE_IMAGE" \
  PODMAN_IMAGE='localhost/caretaker-replay-base:0.6.1'
```

The Make target rejects the documentation placeholder `REVIEWED_DIGEST` and
warns when a tag rather than an explicit `@sha256:` digest is supplied.

The build context is deliberately `dist/`, not the repository root. If you
invoke Podman directly, use the wheel basename and finish the command with
`dist`:

Using the `BASE_IMAGE` variable from the preceding example:

```sh
podman --cgroup-manager=cgroupfs build \
  --file isolated/podman/Containerfile \
  --ignorefile isolated/podman/.containerignore \
  --build-arg "PYTHON_BASE_IMAGE=$BASE_IMAGE" \
  --build-arg "CARETAKER_WHEEL=caretaker-0.6.1-py3-none-any.whl" \
  --tag localhost/caretaker-replay-base:0.6.1 \
  dist
```

The build and replay commands default to `--cgroup-manager=cgroupfs`. This
avoids requiring a systemd user session for short-lived rootless workers. If
the host intentionally provides a working systemd user session, use
`PODMAN_CGROUP_MANAGER=systemd make podman-image` for the build,
`PODMAN_CGROUP_MANAGER=systemd sh isolated/podman/verify-rootless.sh IMAGE`
for verification, and `cgroup_manager="systemd"` when constructing the Python
replay backend.

Review the resulting image identity before using it:

```sh
podman image inspect localhost/caretaker-replay-base:0.6.1 \
  --format 'image={{.Id}}'
```

Then verify rootless execution and the installed package:

```sh
sh isolated/podman/verify-rootless.sh \
  localhost/caretaker-replay-base:0.6.1
```

Configure replay explicitly. Replay is disabled by default and has a
VM-level minimum by default; a deployment must consciously select container
isolation when it is sufficient for its threat model:

```toml
[logging.regression]
enabled = true
replay_enabled = true
replay_minimum_isolation = "CONTAINER"
replay_require_source_match = true
```

The replay path has no application-workspace mount and no live-checkout source
mount. It executes the installed wheel inside the image. Do not add sockets,
credentials, host directories, or reusable data to the container invocation.
