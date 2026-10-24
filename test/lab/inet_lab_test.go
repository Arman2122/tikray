//go:build lab

package lab

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInetFixtures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	n, err := SetupNetwork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Teardown() })
	stop, err := StartInet(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)

	if got := strings.TrimSpace(out(t, exec.CommandContext(ctx, "curl", "-s", "--max-time", "5", "http://203.0.113.30/whoami"))); got != "198.51.100.1" {
		t.Errorf("whoami from host = %q, want 198.51.100.1", got)
	}
	if got := strings.TrimSpace(out(t, exec.CommandContext(ctx, "dig", "+short", "+time=2", "@203.0.113.53", "foreign.test"))); got != "10.10.34.34" {
		t.Errorf("dig foreign.test from host = %q, want 10.10.34.34", got)
	}

	xray, err := XrayBinary(ctx, CacheDir(), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := exec.CommandContext(ctx, xray, "run", "-test", "-c", fixturePath("xray-server.json")).CombinedOutput(); err != nil {
		t.Errorf("xray -test xray-server.json: %v\n%s", err, b)
	}

	// Through the VLESS server, targets must see its egress address.
	client := filepath.Join(t.TempDir(), "client.json")
	os.WriteFile(client, []byte(`{
  "inbounds": [{"listen": "127.0.0.1", "port": 18808, "protocol": "socks", "settings": {"udp": true}}],
  "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "203.0.113.10", "port": 443,
    "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "encryption": "none"}]}]}}]
}`), 0o644)
	cl := exec.CommandContext(ctx, xray, "run", "-c", client)
	if err := cl.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Process.Kill(); cl.Wait() })
	if err := waitTCP(ctx, "127.0.0.1:18808", 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out(t, exec.CommandContext(ctx, "curl", "-s", "--max-time", "5", "--socks5-hostname", "127.0.0.1:18808", "http://203.0.113.30/whoami"))); got != "203.0.113.10" {
		t.Errorf("whoami through VLESS = %q, want 203.0.113.10", got)
	}
}
