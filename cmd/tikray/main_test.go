package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
)

const testToken = "tok"

var testConfigRel = "config/" + strings.Repeat("a", 64) + ".json"

// fakeRunner serves GET /v1/status with st, behind testToken.
func fakeRunner(t *testing.T, st runnerapi.Status) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Header.Get("Authorization") != "Bearer "+testToken:
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"unauthorized"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/status":
			json.NewEncoder(w).Encode(st)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testEnv is a data root with a runner token, a runner that reports st, and
// the variables that point tikray at them. TMPDIR is restored afterwards:
// update and rollback set it.
func testEnv(t *testing.T, st runnerapi.Status) (vars map[string]string, data string) {
	t.Helper()
	data = t.TempDir()
	if err := os.MkdirAll(filepath.Join(data, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A trailing newline, as an editor leaves it: the client must trim it.
	if err := os.WriteFile(filepath.Join(data, "run", "runner.token"), []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", t.TempDir())
	srv := fakeRunner(t, st)
	return map[string]string{"TIKRAY_DATA": data, "TIKRAY_RUNNER_URL": srv.URL}, data
}

func runCLI(t *testing.T, vars map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(context.Background(), args, envOf(vars), &out, &errb)
	return code, out.String(), errb.String()
}

func TestPrepareDirs(t *testing.T) {
	data := t.TempDir()
	t.Setenv("TMPDIR", "/somewhere/else")
	if err := prepareDirs(data); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(data, "state", "tmp")
	for _, d := range []string{filepath.Join(data, "state"), tmp} {
		fi, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: mode %v, want a directory with 0700", d, fi.Mode())
		}
	}
	if fi, err := os.Stat(filepath.Join(data, "inbox")); err != nil || !fi.IsDir() {
		t.Errorf("inbox: %v, %v; want a directory", fi, err)
	}
	if got := os.Getenv("TMPDIR"); got != tmp {
		t.Errorf("TMPDIR = %q, want %q", got, tmp)
	}
	if got := os.TempDir(); got != tmp {
		t.Errorf("os.TempDir() = %q, want %q", got, tmp)
	}

	// A second call changes nothing and keeps what is in the directories.
	keep := filepath.Join(data, "inbox", "xray.zip")
	if err := os.WriteFile(keep, []byte("zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := prepareDirs(data); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("a second prepareDirs lost the inbox file: %v", err)
	}
}

func TestPrepareDirsFailure(t *testing.T) {
	data := t.TempDir()
	t.Setenv("TMPDIR", "/somewhere/else")
	// state exists as a file, so nothing can be created in it.
	if err := os.WriteFile(filepath.Join(data, "state"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareDirs(data); err == nil {
		t.Fatal("no error")
	}
	if got := os.Getenv("TMPDIR"); got != "/somewhere/else" {
		t.Errorf("TMPDIR = %q after a failure, want it untouched", got)
	}
}

func TestExitCode(t *testing.T) {
	for outcome, want := range map[string]int{
		runnerapi.OutcomeCommitted: 0,
		artifacts.OutcomeNoop:      0,
		artifacts.OutcomeRefused:   1,
		artifacts.OutcomeUnhealthy: 1,
		runnerapi.OutcomeRejected:  1,
		runnerapi.OutcomeExited:    1,
		runnerapi.OutcomeDeadline:  1,
		runnerapi.OutcomeAborted:   1,
		runnerapi.OutcomeReboot:    1,
		"":                         1,
		"something new":            1,
	} {
		if got := exitCode(artifacts.Result{Outcome: outcome}); got != want {
			t.Errorf("exitCode(%q) = %d, want %d", outcome, got, want)
		}
	}
}

func TestReportExitCodeFollowsTheOutcome(t *testing.T) {
	data := t.TempDir()
	if err := os.MkdirAll(filepath.Join(data, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Data: data}
	historyErr := errors.New("artifacts: recording the result: disk full")

	// Update returns an error for a committed core whose history line was lost.
	var out, errb bytes.Buffer
	c := &cli{stdout: &out, stderr: &errb}
	if code := c.report(cfg, artifacts.Result{To: "26.10.21", Outcome: runnerapi.OutcomeCommitted}, historyErr); code != 0 {
		t.Errorf("a committed core with an error: exit %d, want 0", code)
	}
	if !strings.Contains(errb.String(), "disk full") {
		t.Errorf("stderr %q does not carry the error", errb.String())
	}
	if got, err := os.ReadFile(filepath.Join(data, "state", "last-result.json")); err != nil || string(got) != out.String() {
		t.Errorf("last-result.json is %q (%v), want %q", got, err, out.String())
	}

	// A result that cannot be saved is a failure, whatever the outcome: the
	// file would still hold the previous run's.
	out.Reset()
	errb.Reset()
	c = &cli{stdout: &out, stderr: &errb}
	if code := c.report(Config{Data: filepath.Join(data, "missing")}, artifacts.Result{Outcome: artifacts.OutcomeNoop}, nil); code != 1 {
		t.Errorf("an unsaved result: exit %d, want 1", code)
	}
	if !strings.Contains(out.String(), `"outcome": "noop"`) || !strings.Contains(errb.String(), "saving the result") {
		t.Errorf("stdout %q, stderr %q", out.String(), errb.String())
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last-result.json")
	for _, content := range []string{"first\n", "second\n"} {
		if err := writeFileAtomic(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("read %q, %v; want %q", got, err, content)
		}
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, %v; want 0600", fi.Mode(), err)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Errorf("the directory holds %d entries, want only the file: %v", len(ents), ents)
	}
	if err := writeFileAtomic(filepath.Join(dir, "missing", "f"), nil, 0o600); err == nil {
		t.Error("writing into a missing directory gave no error")
	}
}

func TestRunUsage(t *testing.T) {
	vars := map[string]string{"TIKRAY_DATA": t.TempDir()}
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"core"},
		{"core", "bogus"},
		{"core", "update"},
		{"core", "update", "26.10.21", "extra"},
		{"core", "update", "--bogus", "26.10.21"},
		{"core", "update", "--config"},
		{"core", "rollback", "extra"},
		{"core", "list", "extra"},
		{"core", "list", "--bogus"},
		{"core", "status", "extra"},
	} {
		code, stdout, stderr := runCLI(t, vars, args...)
		if code != 2 {
			t.Errorf("tikray %q: exit %d, want 2 (stdout %q, stderr %q)", args, code, stdout, stderr)
		}
		if stdout != "" || !strings.Contains(stderr, "usage") {
			t.Errorf("tikray %q: stdout %q, stderr %q; want usage on stderr only", args, stdout, stderr)
		}
	}
	// None of those may have touched the data root.
	if ents, _ := os.ReadDir(vars["TIKRAY_DATA"]); len(ents) != 0 {
		t.Errorf("a usage error created %v in the data root", ents)
	}

	for _, args := range [][]string{{"help"}, {"-h"}, {"core", "help"}, {"core", "update", "-h"}, {"core", "list", "--help"}} {
		code, stdout, stderr := runCLI(t, vars, args...)
		if code != 0 || !strings.Contains(stdout+stderr, "usage") {
			t.Errorf("tikray %q: exit %d, stdout %q, stderr %q; want 0 and usage", args, code, stdout, stderr)
		}
	}
}

func TestRunBadEnvironment(t *testing.T) {
	code, stdout, stderr := runCLI(t, map[string]string{"TIKRAY_MIRRORS": "https://m.example/nofile"}, "core", "list")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "TIKRAY_MIRRORS") {
		t.Errorf("exit %d, stdout %q, stderr %q; want 1 and an error naming TIKRAY_MIRRORS", code, stdout, stderr)
	}
}

func TestRunRollbackRefused(t *testing.T) {
	vars, data := testEnv(t, runnerapi.Status{State: runnerapi.StateEmpty})
	code, stdout, stderr := runCLI(t, vars, "core", "rollback")
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	var res artifacts.Result
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("stdout is not a Result: %v\n%s", err, stdout)
	}
	if res.Outcome != artifacts.OutcomeRefused || !strings.Contains(res.Detail, "nothing to roll back") || res.At.IsZero() {
		t.Errorf("result %+v", res)
	}
	if !strings.Contains(stdout, "\n  \"outcome\"") {
		t.Errorf("stdout is not indented JSON:\n%s", stdout)
	}
	if !strings.Contains(stderr, "nothing to roll back") {
		t.Errorf("stderr %q does not carry the error", stderr)
	}
	saved := filepath.Join(data, "state", "last-result.json")
	got, err := os.ReadFile(saved)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != stdout {
		t.Errorf("last-result.json is\n%s\nstdout is\n%s", got, stdout)
	}
	if fi, _ := os.Stat(saved); fi.Mode().Perm() != 0o600 {
		t.Errorf("last-result.json has mode %v, want 0600", fi.Mode().Perm())
	}
	// The scratch directory exists and is what temp files use.
	if got := os.Getenv("TMPDIR"); got != filepath.Join(data, "state", "tmp") {
		t.Errorf("TMPDIR = %q", got)
	}
}

func TestRunUpdateNoop(t *testing.T) {
	vars, data := testEnv(t, runnerapi.Status{
		State:  runnerapi.StateRunning,
		Active: &runnerapi.Selection{Core: "26.10.21", Config: testConfigRel},
	})
	code, stdout, stderr := runCLI(t, vars, "core", "update", "26.10.21", "--allow-unverified")
	if code != 0 {
		t.Fatalf("exit %d, want 0; stdout %q, stderr %q", code, stdout, stderr)
	}
	var res artifacts.Result
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("stdout is not a Result: %v\n%s", err, stdout)
	}
	if res.Outcome != artifacts.OutcomeNoop || res.From != "26.10.21" || res.To != "26.10.21" {
		t.Errorf("result %+v", res)
	}
	if strings.Contains(stderr, "tikray:") { // the progress line is fine, an error is not
		t.Errorf("stderr %q carries an error for a noop", stderr)
	}
	got, err := os.ReadFile(filepath.Join(data, "state", "last-result.json"))
	if err != nil || string(got) != stdout {
		t.Errorf("last-result.json is %q (%v), want the stdout %q", got, err, stdout)
	}
}

func TestRunUpdateFlagsComeBeforeOrAfterTheVersion(t *testing.T) {
	vars, _ := testEnv(t, runnerapi.Status{
		State:  runnerapi.StateRunning,
		Active: &runnerapi.Selection{Core: "26.10.21", Config: testConfigRel},
	})
	missing := filepath.Join(t.TempDir(), "no-such-config.json")
	for _, args := range [][]string{
		{"core", "update", "26.10.21", "--config", missing},
		{"core", "update", "--config", missing, "26.10.21"},
		{"core", "update", "--config=" + missing, "26.10.21"},
	} {
		code, stdout, stderr := runCLI(t, vars, args...)
		if code != 1 || !strings.Contains(stderr, missing) {
			t.Errorf("tikray %q: exit %d, stderr %q; want 1 and the unreadable config file named", args, code, stderr)
		}
		if !strings.Contains(stdout, `"outcome": "refused"`) || !strings.Contains(stdout, `"to": "26.10.21"`) {
			t.Errorf("tikray %q: stdout %q", args, stdout)
		}
	}
}

func TestRunCoreList(t *testing.T) {
	vars, data := testEnv(t, runnerapi.Status{})
	for _, m := range []artifacts.Meta{
		{Version: "26.1.18", Source: "inbox", Verified: "unverified"},
		{Version: "26.10.21", Source: "direct", Verified: "dgst"},
	} {
		dir := filepath.Join(data, "cores", m.Version)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(m)
		if err := os.WriteFile(filepath.Join(dir, "meta.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	code, stdout, stderr := runCLI(t, vars, "core", "list")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 3 {
		t.Fatalf("want a header and two rows, got:\n%s", stdout)
	}
	for i, want := range [][]string{
		{"VERSION", "VERIFIED", "SOURCE", "INSTALLED"},
		{"26.10.21", "dgst", "direct"}, // newest first
		{"26.1.18", "unverified", "inbox"},
	} {
		got := strings.Fields(lines[i])
		if len(got) < len(want) || !reflect.DeepEqual(got[:len(want)], want) {
			t.Errorf("line %d is %q, want it to start with %q", i, lines[i], want)
		}
	}

	code, stdout, stderr = runCLI(t, vars, "core", "list", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("--json: exit %d, stderr %q", code, stderr)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
		t.Fatalf("--json: %v\n%s", err, stdout)
	}
	if len(rows) != 2 || rows[0]["version"] != "26.10.21" || rows[0]["verified"] != "dgst" || rows[0]["source"] != "direct" {
		t.Errorf("--json rows: %v", rows)
	}
	if _, ok := rows[0]["installed_at"]; !ok {
		t.Errorf("--json row has no installed_at: %v", rows[0])
	}

	// No cores is an empty list, not null.
	vars["TIKRAY_DATA"] = t.TempDir()
	code, stdout, _ = runCLI(t, vars, "core", "list", "--json")
	if code != 0 || strings.TrimSpace(stdout) != "[]" {
		t.Errorf("no cores: exit %d, stdout %q; want []", code, stdout)
	}
}

func TestRunCoreStatus(t *testing.T) {
	want := runnerapi.Status{
		State:     runnerapi.StateRunning,
		Active:    &runnerapi.Selection{Core: "26.10.21", Config: testConfigRel},
		XrayPID:   42,
		GatewayUp: true,
	}
	vars, data := testEnv(t, want)
	code, stdout, stderr := runCLI(t, vars, "core", "status")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var got runnerapi.Status
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}

	// A wrong token is the runner's 401, an error.
	if err := os.WriteFile(filepath.Join(data, "run", "runner.token"), []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runCLI(t, vars, "core", "status")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "401") {
		t.Errorf("wrong token: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	// No token file at all.
	if err := os.Remove(filepath.Join(data, "run", "runner.token")); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runCLI(t, vars, "core", "status")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "runner.token") {
		t.Errorf("no token: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestProxyHealthy(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   runnerapi.Status
		want bool
	}{
		{"running with the gateway up", runnerapi.Status{State: runnerapi.StateRunning, GatewayUp: true}, true},
		{"on trial with the gateway up", runnerapi.Status{State: runnerapi.StateTrial, GatewayUp: true}, true},
		{"running without the gateway", runnerapi.Status{State: runnerapi.StateRunning}, false},
		{"restarting", runnerapi.Status{State: runnerapi.StateRestarting, GatewayUp: true}, false},
		{"empty", runnerapi.Status{State: runnerapi.StateEmpty, GatewayUp: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeRunner(t, tc.st)
			c := &runnerapi.Client{BaseURL: srv.URL, Token: testToken}
			if got := proxyHealthy(c)(context.Background()); got != tc.want {
				t.Errorf("proxyHealthy = %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("runner unreachable", func(t *testing.T) {
		srv := fakeRunner(t, runnerapi.Status{State: runnerapi.StateRunning, GatewayUp: true})
		c := &runnerapi.Client{BaseURL: srv.URL, Token: "wrong"}
		if proxyHealthy(c)(context.Background()) {
			t.Error("healthy with a runner that refuses us")
		}
	})
}

func sourceNames(c artifacts.Chain) []string {
	var names []string
	for _, s := range c.Sources {
		names = append(names, s.Name())
	}
	return names
}

func TestNewUpdater(t *testing.T) {
	data := t.TempDir()
	keyFile := filepath.Join(data, "index.pub")
	if err := os.WriteFile(keyFile, []byte("PEM BYTES\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Data:            data,
		Arch:            "arm64",
		RunnerURL:       "http://127.0.0.1:1",
		Socks:           "127.0.0.1:1",
		Upstream:        "https://github.com/XTLS/Xray-core",
		Mirrors:         []string{"https://a.example/{file}", "https://b.example/{version}/{file}"},
		IndexURLs:       []string{"https://idx.example/hashes.json"},
		IndexPubKeyFile: keyFile,
		ProbeURL:        "https://probe.example/204",
	}
	runner := &runnerapi.Client{BaseURL: cfg.RunnerURL, Token: testToken}
	u, err := newUpdater(cfg, runner, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	// §4.2: direct, the proxy, the mirrors in order, then the inbox.
	wantFetch := []string{"direct", "proxy", "mirror a.example", "mirror b.example", "inbox"}
	if got := sourceNames(u.Fetch); !reflect.DeepEqual(got, wantFetch) {
		t.Errorf("fetch chain %q, want %q", got, wantFetch)
	}
	// §4.3: the .dgst is only ever fetched from upstream.
	if got := sourceNames(u.Verify.Upstream); !reflect.DeepEqual(got, []string{"direct", "proxy"}) {
		t.Errorf("verify chain %q, want direct and proxy", got)
	}
	if !reflect.DeepEqual(u.Verify.IndexURLs, cfg.IndexURLs) || string(u.Verify.IndexPub) != "PEM BYTES\n" {
		t.Errorf("verifier index: %q, %q", u.Verify.IndexURLs, u.Verify.IndexPub)
	}
	if u.Data != data || u.Arch != "arm64" || u.Runner != runner || u.Health == nil {
		t.Errorf("updater %+v", u)
	}

	// With no key file the index stays unused.
	cfg.IndexURLs, cfg.IndexPubKeyFile = nil, ""
	u, err = newUpdater(cfg, runner, io.Discard)
	if err != nil || len(u.Verify.IndexPub) != 0 {
		t.Errorf("without a key: %v, %q", err, u.Verify.IndexPub)
	}

	cfg.IndexPubKeyFile = filepath.Join(data, "no-such-key")
	if _, err := newUpdater(cfg, runner, io.Discard); err == nil || !strings.Contains(err.Error(), "no-such-key") {
		t.Errorf("missing key file: %v", err)
	}
}
