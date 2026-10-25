//go:build lab

package lab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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
	inet, err := StartInetLab(ctx, n, InetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inet.Stop)

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
	for _, f := range []string{"xray-server.json", "xray-server-b.json"} {
		if b, err := exec.CommandContext(ctx, xray, "run", "-test", "-c", fixturePath(f)).CombinedOutput(); err != nil {
			t.Errorf("xray -test %s: %v\n%s", f, err, b)
		}
	}

	// Through a VLESS server, targets must see its egress address.
	const portA, portB = 18808, 18809
	socksClient(ctx, t, xray, portA, "203.0.113.10")
	socksClient(ctx, t, xray, portB, "203.0.113.11")
	for port, want := range map[int]string{portA: "203.0.113.10", portB: "203.0.113.11"} {
		if got := viaSocks(ctx, t, port); got != want {
			t.Errorf("whoami through VLESS server %s = %q, want %s", want, got, want)
		}
	}

	// Taking server a down closes its port and leaves b alone; bringing it back
	// opens the port again, and the same config serves as before.
	if err := inet.SetServer("a", false); err != nil {
		t.Fatal(err)
	}
	if !refuses("203.0.113.10:443") {
		t.Error("203.0.113.10:443 accepts or times out after SetServer(a, false), want connection refused")
	}
	if got := viaSocks(ctx, t, portB); got != "203.0.113.11" {
		t.Errorf("whoami through server b with a down = %q, want 203.0.113.11", got)
	}
	if got := viaSocks(ctx, t, portA); got != "" {
		t.Errorf("whoami through server a while it is down = %q", got)
	}
	if z := zombieChildren(t); len(z) > 0 {
		t.Errorf("SetServer(a, false) left zombies: %v", z)
	}
	if err := inet.SetServer("a", false); err != nil {
		t.Errorf("SetServer(a, false) again: %v", err)
	}

	if err := inet.SetServer("a", true); err != nil {
		t.Fatal(err)
	}
	if err := waitTCP(ctx, "203.0.113.10:443", time.Second); err != nil {
		t.Errorf("after SetServer(a, true): %v", err)
	}
	if got := viaSocks(ctx, t, portA); got != "203.0.113.10" {
		t.Errorf("whoami through server a after it came back = %q, want 203.0.113.10", got)
	}
	if err := inet.SetServer("a", true); err != nil {
		t.Errorf("SetServer(a, true) again: %v", err)
	}

	// The same for b, and a bad name is an error that changes nothing.
	if err := inet.SetServer("b", false); err != nil {
		t.Fatal(err)
	}
	if !refuses("203.0.113.11:443") {
		t.Error("203.0.113.11:443 accepts or times out after SetServer(b, false), want connection refused")
	}
	if err := inet.SetServer("b", true); err != nil {
		t.Fatal(err)
	}
	if got := viaSocks(ctx, t, portB); got != "203.0.113.11" {
		t.Errorf("whoami through server b after it came back = %q, want 203.0.113.11", got)
	}
	if err := inet.SetServer("c", false); err == nil {
		t.Error("SetServer(c, false) succeeded, want an error")
	}
	if z := zombieChildren(t); len(z) > 0 {
		t.Errorf("SetServer left zombies: %v", z)
	}

	// Stop stops a server that was restarted, and a second Stop (the cleanup)
	// is harmless.
	inet.Stop()
	for _, addr := range []string{"203.0.113.10:443", "203.0.113.11:443", "203.0.113.30:80"} {
		if !refuses(addr) {
			t.Errorf("%s still accepts after Stop, want connection refused", addr)
		}
	}
	if z := zombieChildren(t); len(z) > 0 {
		t.Errorf("Stop left zombies: %v", z)
	}
	if err := inet.SetServer("a", true); err == nil {
		t.Error("SetServer after Stop succeeded, want an error")
	}
	inet.Stop()
}

// socksClient runs, until the test ends, an xray client that listens for SOCKS
// on 127.0.0.1:port and sends everything to the lab VLESS server at addr.
func socksClient(ctx context.Context, t *testing.T, xray string, port int, addr string) {
	t.Helper()
	conf := filepath.Join(t.TempDir(), "client-"+strconv.Itoa(port)+".json")
	body := fmt.Sprintf(`{
  "inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "socks", "settings": {"udp": true}}],
  "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": %q, "port": 443,
    "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "encryption": "none"}]}]}}]
}`, port, addr)
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cl := exec.CommandContext(ctx, xray, "run", "-c", conf)
	if err := cl.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Process.Kill(); cl.Wait() })
	if err := waitTCP(ctx, "127.0.0.1:"+strconv.Itoa(port), 10*time.Second); err != nil {
		t.Fatal(err)
	}
}

// viaSocks is what the fake internet's whoami says to a request sent through
// the SOCKS client on port; empty when the request fails.
func viaSocks(ctx context.Context, t *testing.T, port int) string {
	t.Helper()
	b, _ := exec.CommandContext(ctx, "curl", "-s", "--max-time", "5", "--socks5-hostname", "127.0.0.1:"+strconv.Itoa(port), "http://203.0.113.30/whoami").Output()
	return strings.TrimSpace(string(b))
}

// refuses reports whether a connection to addr is refused, as it is when
// nothing listens there; a timeout is not a refusal.
func refuses(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err == nil {
		c.Close()
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

// zombieChildren lists this process's children that have exited but were not
// waited for.
func zombieChildren(t *testing.T) []string {
	t.Helper()
	stats, err := filepath.Glob("/proc/[0-9]*/stat")
	if err != nil {
		t.Fatal(err)
	}
	var zombies []string
	for _, f := range stats {
		b, err := os.ReadFile(f)
		if err != nil {
			continue // exited meanwhile
		}
		// pid (comm) state ppid ...; comm may hold spaces and parentheses.
		s := string(b)
		fields := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
		if len(fields) > 1 && fields[0] == "Z" && fields[1] == strconv.Itoa(os.Getpid()) {
			zombies = append(zombies, strings.TrimSpace(s[:strings.IndexByte(s, ')')+1]))
		}
	}
	return zombies
}
