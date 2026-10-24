#!/usr/bin/env bash
# Installs the host tools the RouterOS lab (test/lab, `make lab`) needs.
# Safe to re-run.
set -euo pipefail

pkgs=(qemu-system-x86 qemu-system-arm qemu-efi-aarch64 qemu-utils iproute2 iputils-ping curl dnsutils netcat-openbsd unzip)

sudo=""
if [ "$(id -u)" -ne 0 ]; then
  sudo="sudo"
fi

missing=()
for p in "${pkgs[@]}"; do
  dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
done
if [ ${#missing[@]} -eq 0 ]; then
  echo "lab-deps: all packages present"
  exit 0
fi
$sudo apt-get update -qq
DEBIAN_FRONTEND=noninteractive $sudo apt-get install -y "${missing[@]}"
