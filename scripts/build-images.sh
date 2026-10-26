#!/usr/bin/env bash
# Builds tikray's container images for one architecture and exports each with
# `docker save` to <outdir>/<name>-<arch>.tar, for RouterOS
# `/container/add file=`. tikray-runner is FROM scratch and tikray is on a
# pinned busybox (for /container/shell's sh); both are COPY only, with no RUN,
# so arm64 needs no emulation.
#
# usage: scripts/build-images.sh <amd64|arm64> [outdir=out]
set -euo pipefail

arch=${1:?usage: build-images.sh <amd64|arm64> [outdir=out]}
case $arch in
  amd64|arm64) ;;
  *) echo "build-images.sh: unknown architecture '$arch' (want amd64 or arm64)" >&2; exit 1 ;;
esac
outdir=${2:-out}

# The images to build, by name. Each is built from ./cmd/<name> into a
# context directory that deploy/<dockerfile> then COPYs from, together with the
# build host's CA bundle as ca-certificates.crt.
images=(
  "tikray-runner runner.Dockerfile"
  "tikray tikray.Dockerfile"
)

# Neither image has certificates of its own (busybox has none); tikray needs
# them to fetch releases and subscriptions over HTTPS.
ca_bundle=/etc/ssl/certs/ca-certificates.crt
if [[ ! -r $ca_bundle ]]; then
  echo "build-images.sh: the CA bundle $ca_bundle is missing; the tikray image copies it from the build host." >&2
  echo 'Install your distribution'"'"'s ca-certificates package (Debian and Ubuntu: apt install ca-certificates).' >&2
  exit 1
fi

# RouterOS rejects archives written by Docker's containerd image store ("no
# config found in manifest"); the classic store's `docker save` output works.
# `docker info` is captured first, not piped into `grep -q`: grep exits at the
# first match, docker then dies of SIGPIPE, and pipefail would read the match as
# no match, so the refusal would be skipped.
docker_info=$(docker info 2>/dev/null || true)
if grep -q 'driver-type: io.containerd.snapshotter' <<<"$docker_info"; then
  echo 'build-images.sh: Docker uses the containerd image store; RouterOS cannot import its archives.' >&2
  echo 'Set {"features": {"containerd-snapshotter": false}} in /etc/docker/daemon.json and restart dockerd.' >&2
  exit 1
fi

mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

for spec in "${images[@]}"; do
  read -r name dockerfile <<<"$spec"
  ctx=$(mktemp -d)
  trap 'rm -rf "$ctx"' EXIT
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w" -o "$ctx/$name" "./cmd/$name"
  cp "$ca_bundle" "$ctx/ca-certificates.crt"
  tag="tikray/$name:$arch"
  docker build -q --platform "linux/$arch" -f "deploy/$dockerfile" -t "$tag" "$ctx" >/dev/null
  docker save -o "$outdir/$name-$arch.tar" "$tag"
  rm -rf "$ctx"
  trap - EXIT
  echo "$outdir/$name-$arch.tar"
done
