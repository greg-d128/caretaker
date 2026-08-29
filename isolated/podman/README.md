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

## Build a reviewed image

Build the wheel first, then supply a Python base image pinned to a reviewed
digest. The base image is a security input and therefore has no floating
default in the Makefile:

```sh
make wheel
make podman-image \
  PODMAN_BASE_IMAGE='python:3.13-slim@sha256:REVIEWED_DIGEST' \
  PODMAN_IMAGE='localhost/caretaker-replay-base:0.6.1'
```

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

Configure replay explicitly; the default minimum isolation remains VM, so a
deployment must consciously select container isolation when it is sufficient
for its threat model:

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
