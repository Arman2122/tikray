package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xray"
	"github.com/Arman2122/tikray/internal/xrayver"
)

// lockedBuffer is a buffer that the serving goroutine writes while the test
// reads.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// serveEnv is the environment of a tikray serve that listens on a port of its
// own, in a data root with a runner token, against a runner that reports no
// core. Nothing listens at the xray API or the SOCKS port.
func serveEnv(t *testing.T) (vars map[string]string, data string) {
	t.Helper()
	vars, data = testEnv(t, runnerapi.Status{State: runnerapi.StateEmpty})
	vars["TIKRAY_LISTEN"] = "127.0.0.1:0"
	vars["TIKRAY_XRAY_API"] = closedAddr(t)
	vars["TIKRAY_SOCKS"] = closedAddr(t)
	return vars, data
}

var startupLine = regexp.MustCompile(`tikray: serving on (\S+), certificate sha256 ([0-9a-f]{64})\n`)

// running is a tikray serve that the test started.
type running struct {
	addr, fingerprint string
	stderr            *lockedBuffer
	cancel            context.CancelFunc
	done              chan int
}

// startServe starts tikray serve with vars and waits for its startup line.
func startServe(t *testing.T, vars map[string]string) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{stderr: &lockedBuffer{}, cancel: cancel, done: make(chan int, 1)}
	go func() {
		c := &cli{getenv: envOf(vars), stdout: io.Discard, stderr: r.stderr}
		r.done <- c.run(ctx, []string{"serve"})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(15 * time.Second):
			t.Error("tikray serve did not stop")
		}
	})
	deadline := time.After(15 * time.Second)
	for {
		if m := startupLine.FindStringSubmatch(r.stderr.String()); m != nil {
			r.addr, r.fingerprint = m[1], m[2]
			return r
		}
		select {
		case code := <-r.done:
			t.Fatalf("tikray serve exited with %d before it served: %s", code, r.stderr.String())
		case <-deadline:
			t.Fatalf("tikray serve printed no startup line: %q", r.stderr.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// stop interrupts tikray serve, as SIGTERM does, and returns its exit code.
func (r *running) stop(t *testing.T) int {
	t.Helper()
	r.cancel()
	select {
	case code := <-r.done:
		r.done <- code // for the cleanup
		return code
	case <-time.After(15 * time.Second):
		t.Fatal("tikray serve did not stop")
		return -1
	}
}

func (r *running) client(t *testing.T, data string) *apiclient.Client {
	t.Helper()
	tok, err := os.ReadFile(filepath.Join(data, "state", "api.token"))
	if err != nil {
		t.Fatal(err)
	}
	return &apiclient.Client{BaseURL: "https://" + r.addr, Token: strings.TrimSpace(string(tok)), Fingerprint: r.fingerprint}
}

func TestServeStartsAndStops(t *testing.T) {
	vars, data := serveEnv(t)
	r := startServe(t, vars)

	// The startup line names the address it listens on and the fingerprint to
	// pin, and nothing secret.
	tokenBytes, err := os.ReadFile(filepath.Join(data, "state", "api.token"))
	if err != nil {
		t.Fatal(err)
	}
	token := string(tokenBytes)
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(token) {
		t.Fatalf("the token file holds %q, want 64 hex digits", token)
	}
	if strings.Contains(r.stderr.String(), token) {
		t.Errorf("stderr shows the token:\n%s", r.stderr.String())
	}
	host, port, err := net.SplitHostPort(r.addr)
	if err != nil || host != "127.0.0.1" || port == "0" || port == "" {
		t.Errorf("serving on %q, want 127.0.0.1 and the port the system chose", r.addr)
	}

	// The files are there, with the modes the API's contract gives them.
	for name, mode := range map[string]os.FileMode{"api.token": 0o600, "tls.crt": 0o644, "tls.key": 0o600} {
		fi, err := os.Stat(filepath.Join(data, "state", name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if fi.Mode().Perm() != mode {
			t.Errorf("%s has mode %v, want %v", name, fi.Mode().Perm(), mode)
		}
	}
	crt, err := os.ReadFile(filepath.Join(data, "state", "tls.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if fp, err := apiclient.FingerprintOfPEM(crt); err != nil || fp != r.fingerprint {
		t.Errorf("the certificate file has fingerprint %q (%v), the startup line says %q", fp, err, r.fingerprint)
	}

	// It serves: /healthz to anyone, the rest to the token alone.
	cl := r.client(t, data)
	if err := cl.Healthz(context.Background()); err != nil {
		t.Fatalf("healthz: %v", err)
	}
	resp, err := cl.Status(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	var st service.Status
	if err := resp.Decode(&st); err != nil || st.Revision != 0 {
		t.Errorf("status %+v (%v), want the fresh state's", st, err)
	}
	bad := *cl
	bad.Token = strings.Repeat("0", 64)
	var apiErr *apiclient.Error
	if _, err := bad.Status(context.Background()); !errors.As(err, &apiErr) || apiErr.Status != 401 {
		t.Errorf("a wrong token: %v, want 401", err)
	}

	if code := r.stop(t); code != 0 {
		t.Errorf("exit %d after the interrupt, want 0; stderr:\n%s", code, r.stderr.String())
	}
	if err := cl.Healthz(context.Background()); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("healthz after the stop: %v, want connection refused", err)
	}
	if strings.Contains(r.stderr.String(), token) {
		t.Errorf("stderr shows the token:\n%s", r.stderr.String())
	}
}

// A restart serves with the token and the certificate it made the first time:
// the clients that pinned it keep working.
func TestServeReusesTheTokenAndTheCertificate(t *testing.T) {
	vars, data := serveEnv(t)
	first := startServe(t, vars)
	token1, err := os.ReadFile(filepath.Join(data, "state", "api.token"))
	if err != nil {
		t.Fatal(err)
	}
	if code := first.stop(t); code != 0 {
		t.Fatalf("exit %d", code)
	}

	second := startServe(t, vars)
	token2, err := os.ReadFile(filepath.Join(data, "state", "api.token"))
	if err != nil {
		t.Fatal(err)
	}
	if second.fingerprint != first.fingerprint || !bytes.Equal(token1, token2) {
		t.Errorf("a restart changed the fingerprint (%s, %s) or the token", first.fingerprint, second.fingerprint)
	}
	if err := second.client(t, data).Healthz(context.Background()); err != nil {
		t.Errorf("healthz with the first run's pin: %v", err)
	}
}

// The CLI reads the files serve makes, with no variable but the data root and
// the address.
func TestServeAndTheCLIAgree(t *testing.T) {
	vars, data := serveEnv(t)
	r := startServe(t, vars)
	cli := map[string]string{"TIKRAY_DATA": data, "TIKRAY_API": "https://" + r.addr}

	if out := ok2(t, cli, "server", "list"); !strings.Contains(out, "ID") {
		t.Errorf("server list printed %q", out)
	}
	if out := ok2(t, cli, "status"); !strings.Contains(out, "revision") {
		t.Errorf("status printed %q", out)
	}
	// Add and list a device through the real service.
	ok2(t, cli, "device", "set", "192.168.88.10", "smart", "--name", "tv")
	if out := ok2(t, cli, "device", "list"); !strings.Contains(out, "192.168.88.10/32") || !strings.Contains(out, "tv") {
		t.Errorf("device list printed %q", out)
	}
	// With the daemon up, the state file is the daemon's: the CLI only asked.
	if _, err := os.Stat(filepath.Join(data, "state", "state.v1.json")); err != nil {
		t.Errorf("the daemon did not save the device: %v", err)
	}
}

// ok2 runs a command that must succeed, for a test that has no secrets to
// look for.
func ok2(t *testing.T, vars map[string]string, args ...string) string {
	t.Helper()
	code, stdout, stderr := runCLI(t, vars, args...)
	if code != 0 {
		t.Fatalf("tikray %q: exit %d, stderr %q", args, code, stderr)
	}
	return stdout
}

func TestServeFailsToStart(t *testing.T) {
	t.Run("no runner token", func(t *testing.T) {
		vars, data := serveEnv(t)
		if err := os.Remove(filepath.Join(data, "run", "runner.token")); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := runCLI(t, vars, "serve")
		if code != 1 || !strings.Contains(stderr, "runner token") {
			t.Errorf("exit %d, stderr %q; want 1 and the runner token", code, stderr)
		}
	})

	t.Run("bad listen address", func(t *testing.T) {
		vars, _ := serveEnv(t)
		vars["TIKRAY_LISTEN"] = "127.0.0.1:notaport"
		code, _, stderr := runCLI(t, vars, "serve")
		if code != 1 || !strings.Contains(stderr, "notaport") {
			t.Errorf("exit %d, stderr %q; want 1 and the address", code, stderr)
		}
	})

	t.Run("address in use", func(t *testing.T) {
		vars, _ := serveEnv(t)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		vars["TIKRAY_LISTEN"] = ln.Addr().String()
		code, _, stderr := runCLI(t, vars, "serve")
		if code != 1 || !strings.Contains(stderr, "address already in use") {
			t.Errorf("exit %d, stderr %q; want 1 and the reason", code, stderr)
		}
	})

	t.Run("unreadable state", func(t *testing.T) {
		vars, data := serveEnv(t)
		writeBad(t, data, "state.v1.json", []byte("{not json"))
		code, _, stderr := runCLI(t, vars, "serve")
		if code != 1 || !strings.Contains(stderr, "state.v1.json") {
			t.Errorf("exit %d, stderr %q; want 1 and the file", code, stderr)
		}
	})

	t.Run("unreadable index key", func(t *testing.T) {
		vars, data := serveEnv(t)
		vars["TIKRAY_INDEX_URLS"] = "https://idx.example/hashes.json"
		vars["TIKRAY_INDEX_PUBKEY_FILE"] = filepath.Join(data, "no-such-key")
		code, _, stderr := runCLI(t, vars, "serve")
		if code != 1 || !strings.Contains(stderr, "no-such-key") {
			t.Errorf("exit %d, stderr %q; want 1 and the key file", code, stderr)
		}
	})
}

// The runner client of the service has the package's timeouts, which the loop
// relies on: none is shorter, none missing.
func TestServeUsesTheRunnersDefaultTimeouts(t *testing.T) {
	_, data := serveEnv(t)
	cfg := Config{Data: data, RunnerURL: "http://127.0.0.1:1"}
	runner, err := newRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if runner.HTTP != nil {
		t.Errorf("the runner client has an HTTP client of its own: %+v", runner.HTTP)
	}
}

// --- the Updaters factory

func serveTestConfig(t *testing.T) (Config, *runnerapi.Client) {
	t.Helper()
	cfg := Config{
		Data:      t.TempDir(),
		Arch:      "amd64",
		Upstream:  "https://github.com/XTLS/Xray-core",
		Mirrors:   []string{"https://m.example/{file}"},
		IndexURLs: []string{"https://idx.example/hashes.json"},
	}
	return cfg, &runnerapi.Client{BaseURL: "http://127.0.0.1:1", Token: testToken}
}

func TestServeUpdatersFollowTheStateTheyAreGiven(t *testing.T) {
	cfg, runner := serveTestConfig(t)
	f := serveUpdaters(cfg, runner, []byte("PEM"), io.Discard)

	st := store.Default()
	withServer(&st)
	st.Health.ProbeURL = "https://one.example/204"
	u := f(st, 3)
	probe, ok := u.ProxyHealth.(artifacts.SOCKSProbe)
	if !ok || probe.URL != "https://one.example/204" || probe.Addr != "172.31.255.3:1080" {
		t.Errorf("proxy health %+v, want the state's probe URL through the runner's SOCKS port", u.ProxyHealth)
	}
	if u.Health == nil || u.Runner != runner || u.Data != cfg.Data || u.Arch != "amd64" {
		t.Errorf("updater %+v", u)
	}
	if u.Redact != nil {
		t.Error("the factory set Redact: the service sets it")
	}
	if u.NoState {
		t.Error("NoState is set at revision 3")
	}
	if !f(st, 0).NoState {
		t.Error("NoState is not set at revision 0")
	}
	got, err := u.Render(mustVersion(t, "26.10.21"), "")
	if err != nil || !bytes.Equal(got, mustRender(t, st, "26.10.21")) {
		t.Errorf("the updater renders %q (%v), want the state's", got, err)
	}

	// A change of the probe URL (PUT /v1/health) is the next updater's, with
	// no restart.
	st.Health.ProbeURL = "https://two.example/204"
	if probe := f(st, 4).ProxyHealth.(artifacts.SOCKSProbe); probe.URL != "https://two.example/204" {
		t.Errorf("after a change the probe URL is %q", probe.URL)
	}
	// TIKRAY_PROBE_URL wins over the state, as it does for the CLI.
	cfg.ProbeURL = "https://env.example/204"
	f = serveUpdaters(cfg, runner, nil, io.Discard)
	if probe := f(st, 4).ProxyHealth.(artifacts.SOCKSProbe); probe.URL != "https://env.example/204" {
		t.Errorf("with TIKRAY_PROBE_URL the probe URL is %q", probe.URL)
	}

	// No server to proxy through: no end-to-end probe, which could only fail.
	if u := f(store.Default(), 0); u.ProxyHealth != nil {
		t.Errorf("proxy health %+v for a state with no server, want none", u.ProxyHealth)
	}
}

func TestServeUpdatersShareNothingMutable(t *testing.T) {
	cfg, runner := serveTestConfig(t)
	f := serveUpdaters(cfg, runner, []byte("PEM"), io.Discard)
	st := store.Default()
	withServer(&st)

	a, b := f(st, 1), f(st, 1)
	if a == b {
		t.Fatal("the factory returned the same updater twice")
	}
	a.Fetch.Sources[0] = nil
	a.Verify.IndexURLs[0] = "mutated"
	a.Verify.IndexPub[0] = 'X'
	if b.Fetch.Sources[0] == nil || b.Verify.IndexURLs[0] != "https://idx.example/hashes.json" || string(b.Verify.IndexPub) != "PEM" {
		t.Errorf("a change to one updater reached another: %+v", b.Verify)
	}
	if cfg.IndexURLs[0] != "https://idx.example/hashes.json" {
		t.Error("a change to an updater reached the config")
	}

	// It is called from several goroutines at once (go test -race).
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u := f(st, uint64(i))
			u.Fetch.Sources[0] = nil
		}()
	}
	wg.Wait()
}

func TestServeMonitor(t *testing.T) {
	cfg, runner := serveTestConfig(t)
	cfg.Socks, cfg.XrayAPI = "172.31.255.3:1080", "172.31.255.3:10085"
	m := serveMonitor(cfg, runner)

	if m.Runner != runner {
		t.Error("the monitor asks another runner client")
	}
	if x, ok := m.Xray.(*xray.Client); !ok || x.Addr != "172.31.255.3:10085" {
		t.Errorf("the monitor's xray client is %#v, want one at the configured API address", m.Xray)
	}
	if m.State != nil {
		t.Error("the monitor has a State: the service fills it")
	}

	if p := m.Probe(store.Default()); p != nil {
		t.Errorf("probe %+v for a state with no server, want none", p)
	}
	st := store.Default()
	withServer(&st)
	st.Health.ProbeURL = "https://one.example/204"
	probe, ok := m.Probe(st).(artifacts.SOCKSProbe)
	if !ok || probe.URL != "https://one.example/204" || probe.Addr != "172.31.255.3:1080" {
		t.Errorf("probe %+v, want the state's URL through the SOCKS port", probe)
	}
	st.Health.ProbeURL = "https://two.example/204"
	if probe := m.Probe(st).(artifacts.SOCKSProbe); probe.URL != "https://two.example/204" {
		t.Errorf("after a change the probe URL is %q", probe.URL)
	}
}

func mustVersion(t *testing.T, s string) xrayver.Version {
	t.Helper()
	v, err := xrayver.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// --- the certificate's addresses

func TestCertIPs(t *testing.T) {
	ifaces := func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
			&net.IPNet{IP: net.ParseIP("172.17.0.2"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("fd00::2"), Mask: net.CIDRMask(64, 128)},
			&net.IPNet{IP: net.ParseIP("0.0.0.0"), Mask: net.CIDRMask(0, 32)},
			&net.IPNet{IP: net.ParseIP("224.0.0.1"), Mask: net.CIDRMask(4, 32)},
			&net.IPAddr{IP: net.ParseIP("172.17.0.9")},
		}, nil
	}
	failing := func() ([]net.Addr, error) { return nil, errors.New("no interfaces") }
	ips := func(ss ...string) []net.IP {
		var out []net.IP
		for _, s := range ss {
			out = append(out, net.ParseIP(s))
		}
		return out
	}
	equal := func(got, want []net.IP) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if !got[i].Equal(want[i]) {
				return false
			}
		}
		return true
	}
	for _, tc := range []struct {
		name   string
		listen string
		addrs  func() ([]net.Addr, error)
		want   []net.IP
	}{
		{"an address", "172.17.0.2:443", ifaces, ips("172.17.0.2")},
		{"an IPv6 address", "[fd00::2]:443", ifaces, ips("fd00::2")},
		{"all addresses", ":443", ifaces, ips("172.17.0.2", "fd00::2", "172.17.0.9")},
		{"0.0.0.0", "0.0.0.0:443", ifaces, ips("172.17.0.2", "fd00::2", "172.17.0.9")},
		{"::", "[::]:443", ifaces, ips("172.17.0.2", "fd00::2", "172.17.0.9")},
		{"a host name", "router.lan:443", ifaces, ips("172.17.0.2", "fd00::2", "172.17.0.9")},
		{"no address list", ":443", failing, nil},
		{"no port", "172.17.0.2", ifaces, ips("172.17.0.2", "fd00::2", "172.17.0.9")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := certIPs(tc.listen, tc.addrs); !equal(got, tc.want) {
				t.Errorf("certIPs(%q) = %v, want %v", tc.listen, got, tc.want)
			}
		})
	}
}
