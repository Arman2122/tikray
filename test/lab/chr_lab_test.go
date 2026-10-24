//go:build lab

package lab

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var channels = []string{"stable", "long-term"}

func labArch() Arch {
	if a := os.Getenv("TIKRAY_LAB_ARCH"); a != "" {
		return Arch(a)
	}
	return ArchX86
}

// bootLab sets up the lab network and boots a provisioned CHR for channel.
// Both are torn down when the test ends.
func bootLab(t *testing.T, ctx context.Context, channel string) (*Network, *CHR, string) {
	t.Helper()
	version, err := ResolveChannel(ctx, "", channel)
	if err != nil {
		t.Fatal(err)
	}
	arch := labArch()
	art, err := FetchCHR(ctx, "", CacheDir(), version, arch)
	if err != nil {
		t.Fatal(err)
	}
	n, err := SetupNetwork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Teardown() })
	c, err := BootCHR(ctx, n, BootOptions{
		Version:   version,
		Arch:      arch,
		Artifacts: art,
		WorkDir:   t.TempDir(),
		Password:  "tikray-lab",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Shutdown() })
	return n, c, version
}

func TestBootCHR(t *testing.T) {
	for _, channel := range channels {
		t.Run(channel, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
			defer cancel()
			n, c, version := bootLab(t, ctx, channel)

			checkVersion := func() {
				t.Helper()
				got, err := c.Get(ctx, "/system/resource/get version")
				if err != nil {
					t.Fatal(err)
				}
				if !strings.HasPrefix(got, version) {
					t.Errorf("version %q, want prefix %q", got, version)
				}
			}
			checkVersion()

			arch, err := c.Get(ctx, "/system/resource/get architecture-name")
			if err != nil {
				t.Fatal(err)
			}
			if arch != string(labArch()) {
				t.Errorf("architecture-name %q, want %q", arch, labArch())
			}

			addr, err := c.Get(ctx, "/ip/address/get [find interface=ether2] address")
			if err != nil {
				t.Fatal(err)
			}
			if addr != "192.168.88.1/24" {
				t.Errorf("ether2 address %q, want 192.168.88.1/24", addr)
			}

			if b, err := n.Client(ctx, "ping", "-c1", "-W2", "192.168.88.1").CombinedOutput(); err != nil {
				t.Errorf("client ping 192.168.88.1: %v\n%s", err, b)
			}

			dir := t.TempDir()
			blob := filepath.Join(dir, "push.bin")
			if err := os.WriteFile(blob, bytes.Repeat([]byte{0xa5}, 4096), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := c.Push(ctx, blob, "lab-push.bin"); err != nil {
				t.Fatal(err)
			}
			if size, err := c.Get(ctx, `/file/get [find name="lab-push.bin"] size`); err != nil || size != "4096" {
				t.Errorf("pushed size %q (%v), want 4096", size, err)
			}

			good := filepath.Join(dir, "good.rsc")
			os.WriteFile(good, []byte("/ip/firewall/address-list/add list=lab-import address=192.0.2.1\n"), 0o644)
			if err := c.Import(ctx, good); err != nil {
				t.Fatal(err)
			}
			if got, _ := c.Get(ctx, "[:len [/ip/firewall/address-list/find list=lab-import]]"); got != "1" {
				t.Errorf("lab-import entries %q after Import, want 1", got)
			}
			bad := filepath.Join(dir, "bad.rsc")
			os.WriteFile(bad, []byte("/ip/firewall/address-list/add list=lab-import addresss=192.0.2.2\n"), 0o644)
			if err := c.Import(ctx, bad); err == nil {
				t.Error("Import of a script with a bad parameter returned nil")
			}

			if err := c.PowerCycle(ctx); err != nil {
				t.Fatal(err)
			}
			checkVersion()
		})
	}
}
