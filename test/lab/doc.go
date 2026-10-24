// Package lab is the RouterOS test lab: it fetches CHR images, builds a
// host-side fake LAN and fake internet from bridges and network namespaces,
// boots CHR in QEMU between them, and drives it over the serial console and
// SSH. Tests that need root, QEMU or network access carry the "lab" build tag;
// everything else runs under a plain `go test ./...`.
package lab
