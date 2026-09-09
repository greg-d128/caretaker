#!/bin/sh
set -eu

podman_command=${PODMAN:-podman}
cgroup_manager=${PODMAN_CGROUP_MANAGER:-cgroupfs}
image=${1:-}

if [ -z "$image" ]; then
    echo "usage: sh isolated/podman/verify-rootless.sh IMAGE" >&2
    exit 2
fi
case "$cgroup_manager" in
    cgroupfs|systemd) ;;
    *) echo "PODMAN_CGROUP_MANAGER must be cgroupfs or systemd" >&2; exit 2;;
esac

info=$($podman_command info --format json)
printf '%s\n' "$info" | python3 -c '
import json
import sys

payload = json.load(sys.stdin)
rootless = payload.get("host", {}).get("security", {}).get("rootless")
if rootless is not True:
    raise SystemExit("Podman is not running rootless")
'

$podman_command image exists "$image"
$podman_command --cgroup-manager="$cgroup_manager" run --rm \
    --pull=never \
    --network=none \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --userns=keep-id \
    --pids-limit=64 \
    --memory=512m \
    --cpus=1 \
    --tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m \
    "$image" \
    python -c 'import caretaker, caretaker.replay_worker; print(caretaker.__version__)'

$podman_command image inspect "$image" --format 'image={{.Id}}'
