package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
	return serveEnvFor(t, runnerapi.Status{State: runnerapi.StateEmpty})
}

// serveEnvFor is serveEnv against a runner that reports st.
func serveEnvFor(t *testing.T, st runnerapi.Status) (vars map[string]string, data string) {
	t.Helper()
	vars, data = testEnv(t, st)
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

// With no TIKRAY_API, the commands look for the daemon where it listens, on
// another port than 443 too: it is not taken for no daemon, and apply does not
// run in the command's own process beside it.
func TestCLIFindsServeAtItsListenAddress(t *testing.T) {
	vars, data := serveEnv(t)
	r := startServe(t, vars) // on a port of its own, which no other test can take

	cli := map[string]string{"TIKRAY_DATA": data, "TIKRAY_LISTEN": r.addr}
	if out := ok2(t, cli, "server", "list"); !strings.Contains(out, "ID") {
		t.Errorf("server list printed %q", out)
	}
	_, _, stderr := runCLI(t, cli, "apply")
	if strings.Contains(stderr, "it holds") || strings.Contains(stderr, "not running") {
		t.Errorf("apply did not reach the daemon: %q", stderr)
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

// RouterOS starts both containers together, so the runner may not have made its
// token when serve starts. serve comes up all the same: the API and /healthz
// answer, the status says what it waits for, and the runner client is
// authorised as soon as the token exists.
func TestServeWithoutTheRunnerToken(t *testing.T) {
	// Restored after the serve below has stopped: its watcher reads it.
	old := tokenPoll
	t.Cleanup(func() { tokenPoll = old })
	tokenPoll = 20 * time.Millisecond

	vars, data := serveEnvFor(t, runnerapi.Status{State: runnerapi.StateRunning, Active: &runnerapi.Selection{Core: "26.10.21", Config: testConfigRel}, RoutesOK: true, GatewayUp: true})
	tokenFile := filepath.Join(data, "run", "runner.token")
	if err := os.Remove(tokenFile); err != nil {
		t.Fatal(err)
	}
	r := startServe(t, vars)
	cl := r.client(t, data)
	if err := cl.Healthz(context.Background()); err != nil {
		t.Fatalf("healthz with no runner token: %v", err)
	}

	status := func() service.Status {
		t.Helper()
		resp, err := cl.Status(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var st service.Status
		if err := resp.Decode(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	// The monitor's first check is at start: the runner is down, and why.
	deadline := time.Now().Add(10 * time.Second)
	for st := status(); !strings.Contains(st.Health.Runner.Err, "waiting for the runner token"); st = status() {
		if time.Now().After(deadline) {
			t.Fatalf("health %+v; want level down and the runner error \"waiting for the runner token\"", st.Health)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st := status(); st.Health.Level != "down" || st.Core != "" {
		t.Errorf("level %q, core %q; want down and no core while the token is missing", st.Health.Level, st.Core)
	}
	if strings.Contains(r.stderr.String(), testToken) {
		t.Errorf("stderr shows the runner token:\n%s", r.stderr.String())
	}
	// Until then the runner can't be reached, which the calls that need it
	// answer as such (503), not as a fault of the service (500).
	for name, call := range map[string]apiCall{
		"GET /v1/core":           (*apiclient.Client).Core,
		"POST /v1/apply":         (*apiclient.Client).Apply,
		"POST /v1/core/rollback": (*apiclient.Client).CoreRollback,
		"POST /v1/core/update": func(cl *apiclient.Client, ctx context.Context) (apiclient.Response, error) {
			return cl.CoreUpdate(ctx, "26.10.21", false)
		},
	} {
		var e *apiclient.Error
		if _, err := call(cl, context.Background()); !errors.As(err, &e) || e.Status != 503 || e.Code != "runner_unavailable" {
			t.Errorf("%s without the runner token: %v, want 503 runner_unavailable", name, err)
		}
	}

	// The runner makes its token. An empty file, as a runner that has opened it
	// but not written it leaves, is not one.
	if err := os.WriteFile(tokenFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if st := status(); st.Core != "" {
		t.Errorf("core %q with an empty token file", st.Core)
	}
	if err := os.WriteFile(tokenFile, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for st := status(); st.Core != "26.10.21"; st = status() {
		if time.Now().After(deadline) {
			t.Fatalf("core %q after the token was made; want the runner's 26.10.21: the client is not authorised", st.Core)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The token is read again until it is there; a read that finds it keeps it.
func TestRunnerTokenIsWaitedFor(t *testing.T) {
	defer func(old time.Duration) { tokenPoll = old }(tokenPoll)
	tokenPoll = 10 * time.Millisecond

	srv := fakeRunner(t, runnerapi.Status{State: runnerapi.StateRunning})
	env := serveTestEnv(t)
	env.RunnerURL = srv.URL
	w := wireService(env, store.Default(), nil, io.Discard)
	ctx := context.Background()

	_, err := w.runner.Status(ctx)
	if err == nil || !strings.Contains(err.Error(), "waiting for the runner token") {
		t.Fatalf("Status without a token: %v, want an error that says it waits for one", err)
	}
	if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("a request was sent without a token: %v", err)
	}

	// A watcher finds the token and says so; a service kicks its loop then.
	wctx, stop := context.WithCancel(ctx)
	defer stop()
	found := make(chan struct{})
	watched := make(chan struct{})
	go func() {
		w.token.watch(wctx, func() { close(found) })
		close(watched)
	}()
	select {
	case <-found:
		t.Fatal("the watcher found a token that does not exist")
	case <-time.After(50 * time.Millisecond):
	}
	if err := os.MkdirAll(filepath.Join(env.Data, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.Data, "run", "runner.token"), []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-found:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher did not find the token")
	}
	select {
	case <-watched:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher goes on after it found the token")
	}
	if _, err := w.runner.Status(ctx); err != nil {
		t.Errorf("Status with the token: %v", err)
	}
	// The token read is kept: the file may go.
	if err := os.Remove(filepath.Join(env.Data, "run", "runner.token")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.runner.Status(ctx); err != nil {
		t.Errorf("Status after the file went: %v", err)
	}

	// A watcher stops with its context.
	w2 := wireService(serveTestEnv(t), store.Default(), nil, io.Discard)
	wctx2, stop2 := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w2.token.watch(wctx2, func() { t.Error("found a token that does not exist") }); close(done) }()
	stop2()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher did not stop with its context")
	}
}

// A runner that makes a new token (it writes run/runner.token again when it
// restarts) refuses the one read before. One 401 has the client read the file
// again, and the next call is authorised.
func TestRunnerTokenIsReadAgainAfterA401(t *testing.T) {
	var mu sync.Mutex
	accepted := testToken
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ok := r.Header.Get("Authorization") == "Bearer "+accepted
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"unauthorized"}`)
			return
		}
		json.NewEncoder(w).Encode(runnerapi.Status{State: runnerapi.StateRunning})
	}))
	t.Cleanup(srv.Close)
	env := serveTestEnv(t)
	env.RunnerURL = srv.URL
	tokenFile := filepath.Join(env.Data, "run", "runner.token")
	if err := os.MkdirAll(filepath.Dir(tokenFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := wireService(env, store.Default(), nil, io.Discard)
	ctx := context.Background()
	if _, err := w.runner.Status(ctx); err != nil {
		t.Fatalf("Status with the runner's token: %v", err)
	}

	// The runner restarts with a new token.
	const newToken = "new-runner-token"
	if err := os.WriteFile(tokenFile, []byte(newToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	accepted = newToken
	mu.Unlock()
	if _, err := w.runner.Status(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("Status with the token read before: %v, want a 401", err)
	}
	if _, err := w.runner.Status(ctx); err != nil {
		t.Errorf("Status after the 401: %v, want the new token read and taken", err)
	}
}

// The runner client's callers share the token, and any of them may drop it
// after a 401 while the others read it, as the monitor, the apply loop and a
// handler do when the runner makes a new token: no read may find it gone half
// way.
func TestRunnerTokenGetWhileDropped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runner.token")
	if err := os.WriteFile(path, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tok := newRunnerToken(path)
	var wg sync.WaitGroup
	panicked := make(chan any, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicked <- r
				}
			}()
			for range 5000 {
				s, err := tok.get(context.Background())
				if err != nil || s != testToken {
					t.Errorf("get = %q, %v; want the token", s, err)
					return
				}
				tok.drop(s) // the runner refused it
			}
		}()
	}
	wg.Wait()
	close(panicked)
	for r := range panicked {
		t.Fatalf("get panicked: %v", r)
	}
}

// One process owns the state. A second serve on the data root does not start,
// and the first goes on.
func TestSecondServeExits(t *testing.T) {
	vars, data := serveEnv(t)
	first := startServe(t, vars)

	// A second serve that wrongly starts would run on: the context ends it.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var errb bytes.Buffer
	code := run(ctx, []string{"serve"}, envOf(vars), io.Discard, &errb)
	if want := "tikray: another tikray serve owns " + data + "\n"; code != 1 || !strings.Contains(errb.String(), want) {
		t.Errorf("exit %d, stderr %q; want 1 and %q", code, errb.String(), want)
	}
	if err := first.client(t, data).Healthz(context.Background()); err != nil {
		t.Errorf("the first serve stopped answering: %v", err)
	}

	// The lock goes with the process: once the first stops, a new one starts.
	if code := first.stop(t); code != 0 {
		t.Fatalf("exit %d", code)
	}
	again := startServe(t, vars)
	if err := again.client(t, data).Healthz(context.Background()); err != nil {
		t.Errorf("healthz after a restart: %v", err)
	}
}

func TestLockServe(t *testing.T) {
	data := t.TempDir()
	unlock, err := lockServe(data)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(data, "state", "serve.lock"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("serve.lock: %v, %v; want a file with mode 0600", fi, err)
	}
	if _, err := lockServe(data); !errors.Is(err, errServeHeld) {
		t.Errorf("a second lock: %v, want errServeHeld", err)
	}
	unlock()
	unlock2, err := lockServe(data)
	if err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	unlock2()
	// Other data roots are other owners.
	other, err := lockServe(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other()
}

// The runner client of the service has the package's timeouts, which the loop
// relies on: none is shorter, none missing.
func TestServeUsesTheRunnersDefaultTimeouts(t *testing.T) {
	w := wireService(serveTestEnv(t), store.Default(), nil, io.Discard)
	if w.runner.HTTP != nil {
		t.Errorf("the runner client has an HTTP client of its own: %+v", w.runner.HTTP)
	}
	if w.runner.TokenFunc == nil || w.runner.Token != "" {
		t.Errorf("the runner client has a fixed token (%q) or no way to wait for one", w.runner.Token)
	}
}

// --- the wiring of the service

// serveTestEnv is the configuration serve starts from, as configFromEnv
// gives it for an environment that sets none of the runner's addresses or the
// probe URL: the latter stay empty, for the state to fill.
func serveTestEnv(t *testing.T) Config {
	t.Helper()
	return Config{
		Data:      t.TempDir(),
		Arch:      "amd64",
		Upstream:  "https://github.com/XTLS/Xray-core",
		Mirrors:   []string{"https://m.example/{file}"},
		IndexURLs: []string{"https://idx.example/hashes.json"},
	}
}

func TestServeUpdatersFollowTheStateTheyAreGiven(t *testing.T) {
	env := serveTestEnv(t)
	st := store.Default()
	withServer(&st)
	st.Health.ProbeURL = "https://one.example/204"
	w := wireService(env, st, []byte("PEM"), io.Discard)
	f := w.updaters

	u := f(st, 3)
	probe, ok := u.ProxyHealth.(artifacts.SOCKSProbe)
	if !ok || probe.URL != "https://one.example/204" || probe.Addr != "172.31.255.3:1080" {
		t.Errorf("proxy health %+v, want the state's probe URL through the runner's SOCKS port", u.ProxyHealth)
	}
	if u.Health == nil || u.Runner != w.runner || u.Data != env.Data || u.Arch != "amd64" {
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

	// No server to proxy through: no end-to-end probe, which could only fail.
	if u := f(store.Default(), 0); u.ProxyHealth != nil {
		t.Errorf("proxy health %+v for a state with no server, want none", u.ProxyHealth)
	}
}

// The probe URL of the health checks is the state's own, as of each snapshot,
// unless TIKRAY_PROBE_URL names one. A change (PUT /v1/health) therefore
// reaches the trials and the monitor without a restart, and the checks probe
// what xray's observatory, rendered from the state, probes. The wiring is
// made as serve makes it: from the environment's configuration, which has no
// probe URL of its own, and the state at start, which has one.
func TestServeProbeURLFollowsTheState(t *testing.T) {
	const (
		urlA = "https://a.example/204"
		urlB = "https://b.example/204"
		env  = "https://env.example/204"
	)
	proxyURL := func(t *testing.T, w serveWiring, st store.State) (updater, monitor string) {
		t.Helper()
		u, ok := w.updaters(st, 5).ProxyHealth.(artifacts.SOCKSProbe)
		if !ok {
			t.Fatalf("the updater's proxy health is %T", w.updaters(st, 5).ProxyHealth)
		}
		m, ok := w.monitor.Probe(st).(artifacts.SOCKSProbe)
		if !ok {
			t.Fatalf("the monitor's probe is %T", w.monitor.Probe(st))
		}
		return u.URL, m.URL
	}
	st := store.Default()
	withServer(&st)
	st.Health.ProbeURL = urlA

	t.Run("the state's", func(t *testing.T) {
		w := wireService(serveTestEnv(t), st, nil, io.Discard)
		if u, m := proxyURL(t, w, st); u != urlA || m != urlA {
			t.Errorf("at start: updater %q, monitor %q; want the state's %q", u, m, urlA)
		}
		changed := st.Clone()
		changed.Health.ProbeURL = urlB
		if u, m := proxyURL(t, w, changed); u != urlB || m != urlB {
			t.Errorf("after a change: updater %q, monitor %q; want %q, with no new wiring", u, m, urlB)
		}
	})

	t.Run("the environment's wins", func(t *testing.T) {
		e := serveTestEnv(t)
		e.ProbeURL = env
		w := wireService(e, st, nil, io.Discard)
		if u, m := proxyURL(t, w, st); u != env || m != env {
			t.Errorf("at start: updater %q, monitor %q; want TIKRAY_PROBE_URL's %q", u, m, env)
		}
		changed := st.Clone()
		changed.Health.ProbeURL = urlB
		if u, m := proxyURL(t, w, changed); u != env || m != env {
			t.Errorf("after a change: updater %q, monitor %q; want TIKRAY_PROBE_URL's %q", u, m, env)
		}
	})
}

func TestServeUpdatersShareNothingMutable(t *testing.T) {
	st := store.Default()
	withServer(&st)
	cfg := serveTestEnv(t)
	f := wireService(cfg, st, []byte("PEM"), io.Discard).updaters

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
	w := wireService(serveTestEnv(t), store.Default(), nil, io.Discard)
	m := w.monitor

	if m.Runner != w.runner {
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
