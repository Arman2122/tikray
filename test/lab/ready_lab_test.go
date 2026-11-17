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

// TestPrepareCHRInputs is the networked half of cold CI preparation.
func TestPrepareCHRInputs(t *testing.T) {
	resolved := os.Getenv("TIKRAY_LAB_PREPARED_XRAY")
	if resolved == "" {
		t.Skip("no requested CHR core provenance file")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Minute)
	defer cancel()
	version, err := ResolveChannel(ctx, "", os.Getenv("TIKRAY_LAB_CHANNEL"))
	if err != nil {
		t.Fatal("could not resolve CHR version")
	}
	if _, err := FetchCHR(ctx, "", CacheDir(), version, labArch()); err != nil {
		t.Fatal("could not prepare public CHR downloads")
	}
	t.Log("CHR cache phase: CHR downloaded")
	core, err := ResolveXrayVersion(ctx, LabXrayVersion())
	if err != nil {
		t.Fatal("could not resolve the pinned core for CHR")
	}
	if _, err := XrayBinaryVersion(ctx, CacheDir(), core, labArch().GOARCH()); err != nil {
		t.Fatal("could not prepare the pinned core for CHR")
	}
	t.Log("CHR cache phase: core built")
	if os.WriteFile(resolved, []byte(core+"\n"), 0644) != nil {
		t.Fatal("could not record the tested core release")
	}
}

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
	t.Log("CHR cache phase: lab network ready")
	note := func(format string, args ...any) {
		// Public CI may report these fixed milestones. Serial, SSH and
		// router-provided diagnostics stay in the private preparation log.
		if format != "%s" || len(args) != 1 {
			return
		}
		switch args[0] {
		case "serial connected":
			t.Log("CHR cache phase: serial connected")
		case "console login done":
			t.Log("CHR cache phase: serial login")
		case "ssh up":
			t.Log("CHR cache phase: SSH ready")
		case "container package installed":
			t.Log("CHR cache phase: container package ready")
		case "device-mode container enabled":
			t.Log("CHR cache phase: container mode ready")
		case "disk1 formatted ext4":
			t.Log("CHR cache phase: data disk ready")
		case "power off":
			t.Log("CHR cache phase: clean shutdown")
		}
	}

	boot := func() (*CHR, string) {
		wd := workDir(t)
		c, err := BootReadyCHR(ctx, n, BootOptions{Version: version, Arch: labArch(), Artifacts: art, WorkDir: wd, Password: "tikray-lab", Notef: note})
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
