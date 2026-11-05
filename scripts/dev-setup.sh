#!/usr/bin/env bash
# Sets up a Debian or Ubuntu machine, or WSL2 Ubuntu on Windows, to build and
# test tikray. It installs make, git, gcc and the C headers (for -race), and
# Go when none, or one older than 1.21, is on PATH: the distribution's
# golang-go first, else the toolchain go.mod names from go.dev, under
# /usr/local/go. Go 1.21 and later fetch go.mod's toolchain by themselves.
# Where Google's Go servers aren't reachable, as in some countries, Go modules
# then come through a mirror. Then it runs the unit tests. With --lab it also
# installs what the RouterOS lab needs (scripts/lab-deps.sh, Docker); the lab
# runs CHR under QEMU's emulation, so it needs no KVM. Safe to re-run.
set -euo pipefail
cd "$(dirname "$0")/.."

lab=false
case "${1:-}" in
  "") ;;
  --lab) lab=true ;;
  *) echo "usage: scripts/dev-setup.sh [--lab]" >&2; exit 2 ;;
esac

sudo=""
if [ "$(id -u)" -ne 0 ]; then
  sudo="sudo"
fi

# libc6-dev: with gcc there, go builds with cgo, which needs the C headers;
# Ubuntu doesn't always pull them in with gcc.
pkgs=(make git gcc libc6-dev curl ca-certificates tar)
missing=()
for p in "${pkgs[@]}"; do
  dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
done
if [ ${#missing[@]} -gt 0 ]; then
  $sudo apt-get update -qq
  DEBIAN_FRONTEND=noninteractive $sudo apt-get install -y "${missing[@]}"
fi

# Go 1.21 and later switch to go.mod's toolchain line on their own.
export PATH="$PATH:/usr/local/go/bin"
go_ok() {
  command -v go >/dev/null 2>&1 || return 1
  local v
  v=$(GOTOOLCHAIN=local go env GOVERSION 2>/dev/null) || return 1
  v=${v#go}
  local major=${v%%.*} rest=${v#*.}
  local minor=${rest%%.*}
  [ "$major" -gt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -ge 21 ]; }
}
if ! go_ok; then
  # The distribution's Go comes from the same mirror as everything else here;
  # go.dev's downloads are blocked in some countries.
  DEBIAN_FRONTEND=noninteractive $sudo apt-get install -y golang-go ||
    echo "dev-setup: no golang-go package: trying go.dev" >&2
  hash -r
fi
if ! go_ok; then
  want=$(awk '$1 == "toolchain" { sub(/^go/, "", $2); print $2 }' go.mod)
  case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) echo "dev-setup: no Go download for $(uname -m)" >&2; exit 1 ;;
  esac
  tgz="go$want.linux-$arch.tar.gz"
  echo "dev-setup: installing $tgz under /usr/local/go"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL -o "$tmp/$tgz" "https://go.dev/dl/$tgz"
  $sudo rm -rf /usr/local/go
  $sudo tar -C /usr/local -xzf "$tmp/$tgz"
  if ! grep -qs '/usr/local/go/bin' "$HOME/.profile"; then
    echo 'export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"' >>"$HOME/.profile"
  fi
fi
echo "dev-setup: $(GOTOOLCHAIN=local go version)"

# Modules, and the toolchain go.mod names, come from proxy.golang.org, which
# some countries can't reach. Then they come through goproxy.io instead. go.sum
# and the checksum database, which go reaches through the mirror, still verify
# every download. A GOPROXY someone set is left alone.
mirror=https://goproxy.io
# GOTOOLCHAIN=local: in this module, go would fetch go.mod's toolchain first.
if [ "$(GOTOOLCHAIN=local go env GOPROXY)" = "https://proxy.golang.org,direct" ] &&
  ! curl -fsS -o /dev/null --max-time 15 https://proxy.golang.org/golang.org/x/net/@v/list; then
  GOTOOLCHAIN=local go env -w GOPROXY="$mirror,direct"
  echo "dev-setup: proxy.golang.org is unreachable: Go modules now come through $mirror (go env -w GOPROXY)"
fi

if $lab; then
  scripts/lab-deps.sh
  dpkg -s docker.io >/dev/null 2>&1 || command -v docker >/dev/null 2>&1 ||
    { $sudo apt-get update -qq && DEBIAN_FRONTEND=noninteractive $sudo apt-get install -y docker.io; }
fi

make test
echo "dev-setup: done: the unit tests pass"
