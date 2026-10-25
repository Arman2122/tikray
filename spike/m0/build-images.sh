#!/usr/bin/env bash
# Builds the M0 prototype images for one architecture and exports them with
# `docker save` to spike/m0/out/<name>-<arch>.tar for RouterOS
# `/container/add file=`. FROM scratch + COPY only, so arm64 needs no emulation.
set -euo pipefail

arch=${1:?usage: build-images.sh <amd64|arm64>}

# RouterOS rejects archives written by Docker's containerd image store ("no
# config found in manifest"); the classic store's `docker save` output works.
if docker info 2>/dev/null | grep -q 'driver-type: io.containerd.snapshotter'; then
  echo 'build-images.sh: Docker uses the containerd image store; RouterOS cannot import its archives.' >&2
  echo 'Set {"features": {"containerd-snapshotter": false}} in /etc/docker/daemon.json and restart dockerd.' >&2
  exit 1
fi
here=$(cd "$(dirname "$0")" && pwd)
out="$here/out"
mkdir -p "$out"

for name in runnerproto ctlproto; do
  ctx=$(mktemp -d)
  trap 'rm -rf "$ctx"' EXIT
  (cd "$here" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w" -o "$ctx/$name" "./$name")
  cp "$here/images/Dockerfile.$name" "$ctx/Dockerfile"
  tag="tikray-m0/$name:$arch"
  docker build -q --platform "linux/$arch" -t "$tag" "$ctx" >/dev/null
  docker save -o "$out/$name-$arch.tar" "$tag"
  rm -rf "$ctx"
  trap - EXIT
  echo "$out/$name-$arch.tar"
done
