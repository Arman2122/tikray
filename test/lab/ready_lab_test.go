//go:build lab

package lab

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBootReadyCHR(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Minute)
	defer cancel()
	channel := os.Getenv("TIKRAY_LAB_CHANNEL")
	if channel == "" {
		channel = "stable"
	}
	version, err := ResolveChannel(ctx, "", channel)
	if err != nil {
		t.Fatal(err)
	}
	art, err := FetchCHR(ctx, "", CacheDir(), version, labArch())
	if err != nil {
		t.Fatal(err)
	}
	n, err := SetupNetwork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Teardown() })

	boot := func() (*CHR, string) {
		wd := workDir(t)
		c, err := BootReadyCHR(ctx, n, BootOptions{Version: version, Arch: labArch(), Artifacts: art, WorkDir: wd, Password: "tikray-lab"})
		if err != nil {
			t.Fatal(err)
		}
		return c, wd
	}
	check := func(c *CHR) {
		t.Helper()
		if got, _ := c.Get(ctx, "[:len [/system/package/find name=container]]"); got != "1" {
			t.Errorf("container packages %q, want 1", got)
		}
		if got, _ := c.Get(ctx, "/system/device-mode/get container"); got != "true" {
			t.Errorf("device-mode container %q, want true", got)
		}
		if got, _ := c.Get(ctx, "/disk/get [find slot=disk1] fs"); got != "ext4" {
			t.Errorf("disk1 fs %q, want ext4", got)
		}
	}

	c1, _ := boot()
	check(c1)
	c1.Shutdown()
	for _, f := range []string{"system.qcow2", "data.qcow2"} {
		if _, err := os.Stat(filepath.Join(readyDir(version, labArch()), f)); err != nil {
			t.Errorf("ready image %s missing: %v", f, err)
		}
	}

	c2, wd2 := boot()
	defer c2.Shutdown()
	check(c2)
	hl, _ := os.ReadFile(filepath.Join(wd2, "harness.log"))
	for _, step := range []string{"console login done", "container package installed", "device-mode container enabled"} {
		if strings.Contains(string(hl), step) {
			t.Errorf("second boot redid %q; it should start from the ready image", step)
		}
	}
}
