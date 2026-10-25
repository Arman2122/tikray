//go:build lab

package lab

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func out(t *testing.T, cmd *exec.Cmd) string {
	t.Helper()
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(cmd.Args, " "), err, b)
	}
	return string(b)
}

func TestNetworkSetupTeardown(t *testing.T) {
	ctx := context.Background()

	// A leftover from a crashed run must not break setup.
	exec.Command("ip", "link", "add", "tklab-wan", "type", "bridge").Run()

	n, err := SetupNetwork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Teardown() })

	out(t, n.Inet(ctx, "ping", "-c1", "-W2", "198.51.100.1"))

	lo := out(t, n.Inet(ctx, "ip", "-4", "addr", "show", "lo"))
	for _, a := range []string{"203.0.113.10", "203.0.113.20", "203.0.113.30", "203.0.113.53", "203.0.113.54"} {
		if !strings.Contains(lo, a) {
			t.Errorf("tklab-inet lo lacks %s:\n%s", a, lo)
		}
	}

	if r := out(t, n.Client(ctx, "ip", "route")); !strings.Contains(r, "default via 192.168.88.1") {
		t.Errorf("client routes lack default via 192.168.88.1:\n%s", r)
	}

	hostRoutes := out(t, exec.Command("ip", "-4", "route"))
	for _, r := range []string{"172.31.255.0/29 via 198.51.100.2", "203.0.113.0/24 via 198.51.100.254"} {
		if !strings.Contains(hostRoutes, r) {
			t.Errorf("host routes lack %q:\n%s", r, hostRoutes)
		}
	}

	if err := n.Teardown(); err != nil {
		t.Fatal(err)
	}
	if l := out(t, exec.Command("ip", "-o", "link", "show")); strings.Contains(l, "tklab-") {
		t.Errorf("links left after teardown:\n%s", l)
	}
	if ns := out(t, exec.Command("ip", "netns", "list")); strings.Contains(ns, "tklab-") {
		t.Errorf("netns left after teardown:\n%s", ns)
	}
	hostRoutes = out(t, exec.Command("ip", "-4", "route"))
	if strings.Contains(hostRoutes, "172.31.255.0/29") || strings.Contains(hostRoutes, "203.0.113.0/24") {
		t.Errorf("host routes left after teardown:\n%s", hostRoutes)
	}
	if err := n.Teardown(); err != nil {
		t.Errorf("second Teardown: %v", err)
	}
}

func TestNetnsCommandsDropProxyEnv(t *testing.T) {
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	n := &Network{}
	for _, cmd := range []*exec.Cmd{n.Client(context.Background(), "env"), n.Inet(context.Background(), "env")} {
		for _, kv := range cmd.Env {
			if k, _, _ := strings.Cut(kv, "="); strings.EqualFold(k, "https_proxy") || strings.EqualFold(k, "http_proxy") {
				t.Errorf("%v carries %s", cmd.Args, kv)
			}
		}
		if len(cmd.Env) == 0 {
			t.Errorf("%v has an empty environment", cmd.Args)
		}
	}
}
