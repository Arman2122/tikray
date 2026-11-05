#!/usr/bin/env bash
# Sets up a Debian or Ubuntu machine, or WSL2 Ubuntu on Windows, to build and
# test tikray. It installs make, git, gcc (for -race) and, when none or one
# older than 1.21 is on PATH, the Go toolchain go.mod names, under
# /usr/local/go. A newer Go fetches go.mod's toolchain by itself. Then it runs
# the unit tests. With --lab it also installs what the RouterOS lab needs
# (scripts/lab-deps.sh, Docker) and says whether KVM is there. Safe to re-run.
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

pkgs=(make git gcc curl ca-certificates tar)
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
echo "dev-setup: $(go version)"

if $lab; then
  scripts/lab-deps.sh
  dpkg -s docker.io >/dev/null 2>&1 || command -v docker >/dev/null 2>&1 ||
    { $sudo apt-get update -qq && DEBIAN_FRONTEND=noninteractive $sudo apt-get install -y docker.io; }
  if [ -e /dev/kvm ]; then
    echo "dev-setup: /dev/kvm is there: the x86_64 lab can run"
  else
    echo "dev-setup: no /dev/kvm: the x86_64 lab needs KVM (on WSL2, nested virtualization)" >&2
  fi
fi

make test
echo "dev-setup: done: the unit tests pass"
