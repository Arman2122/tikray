package lab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// readyDir caches the disks of a CHR that finished BootCHR and
// EnableContainers, per RouterOS version and arch.
func readyDir(version string, arch Arch) string {
	return filepath.Join(CacheDir(), "ready", version, string(arch))
}

// BootReadyCHR returns a CHR with containers enabled. The first call for a
// version and arch does the full BootCHR + EnableContainers, shuts the VM down
// cleanly and caches its disks; later calls boot copy-on-write overlays of
// that cache and only wait for SSH. Under emulation that saves the two
// reboots and the first boot, about 10 minutes per VM.
func BootReadyCHR(ctx context.Context, n *Network, opts BootOptions) (*CHR, error) {
	dir := readyDir(opts.Version, opts.Arch)
	if pw, err := os.ReadFile(filepath.Join(dir, "password")); err != nil || string(pw) != opts.Password {
		if err := buildReady(ctx, n, opts, dir); err != nil {
			return nil, err
		}
	}
	c, err := newCHR(opts)
	if err != nil {
		return nil, err
	}
	sys, data := c.disks()
	for overlay, base := range map[string]string{sys: filepath.Join(dir, "system.qcow2"), data: filepath.Join(dir, "data.qcow2")} {
		os.Remove(overlay)
		if err := run(ctx, "qemu-img", "create", "-q", "-f", "qcow2", "-b", base, "-F", "qcow2", overlay); err != nil {
			return nil, err
		}
	}
	if err := c.start(ctx); err != nil {
		return nil, err
	}
	c.logf("booting from ready image %s", dir)
	if err := c.waitSSH(ctx); err != nil {
		c.Shutdown()
		return nil, err
	}
	if err := c.checkWAN(ctx); err != nil {
		c.Shutdown()
		return nil, err
	}
	return c, nil
}

// buildReady prepares a CHR from scratch and stores its disks in dir. The
// password file is written last, so a half-built cache is never used.
func buildReady(ctx context.Context, n *Network, opts BootOptions, dir string) error {
	c, err := BootCHR(ctx, n, opts)
	if err != nil {
		return err
	}
	if err := c.EnableContainers(ctx); err != nil {
		c.Shutdown()
		return err
	}
	if err := c.powerOff(ctx); err != nil {
		c.Shutdown()
		return err
	}
	c.Shutdown()
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	sys, data := c.disks()
	for src, dst := range map[string]string{sys: filepath.Join(dir, "system.qcow2"), data: filepath.Join(dir, "data.qcow2")} {
		if err := run(ctx, "qemu-img", "convert", "-O", "qcow2", src, dst+".part"); err != nil {
			return err
		}
		if err := os.Rename(dst+".part", dst); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, "password"), []byte(opts.Password), 0o600)
}

// powerOff shuts RouterOS down cleanly and waits for QEMU to exit, so the
// disks are consistent.
func (c *CHR) powerOff(ctx context.Context) error {
	c.logf("power off")
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	c.Run(sctx, "/system/shutdown")
	cancel()
	c.dropClient()
	select {
	case <-c.exited:
		return nil
	case <-time.After(c.bootTimeout()):
		return errors.New("CHR did not power off")
	case <-ctx.Done():
		return fmt.Errorf("power off: %w", ctx.Err())
	}
}
