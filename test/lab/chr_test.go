package lab

import (
	"slices"
	"testing"
)

// RouterOS 7.25's arm64 kernel hangs right after the EFI stub on QEMU's
// "max" CPU model (no console output, the guest idles); cortex-a72 reaches
// the login prompt.
func TestQEMUArgsARM64CPU(t *testing.T) {
	c := &CHR{opts: BootOptions{Arch: ArchARM64, MemoryMB: 1024, WorkDir: t.TempDir()}}
	args := c.qemuArgs()
	i := slices.Index(args, "-cpu")
	if args[0] != "qemu-system-aarch64" || i < 0 || i+1 >= len(args) || args[i+1] != "cortex-a72" {
		t.Errorf("arm64 qemu args %q, want qemu-system-aarch64 with -cpu cortex-a72", args)
	}
}
