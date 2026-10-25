package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xrayver"
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

// seedResult leaves a previous run's last-result.json in data and returns its path.
func seedResult(t *testing.T, data string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(data, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(data, "state", "last-result.json")
	if err := os.WriteFile(path, []byte("{\n  \"to\": \"26.1.18\",\n  \"outcome\": \"committed\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A command that fails before the updater runs must not leave the previous
// run's result for a reader to take as its own.
func TestRunSetupFailureSavesARefusedResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		setup  func(vars map[string]string, data string)
		to     string
		detail string
	}{
		{"missing runner token, update", []string{"core", "update", "26.10.21"}, noToken, "26.10.21", "runner.token"},
		{"missing runner token, rollback", []string{"core", "rollback"}, noToken, "", "runner.token"},
		{"unreadable index key", []string{"core", "update", "latest"}, func(vars map[string]string, data string) {
			vars["TIKRAY_INDEX_URLS"] = "https://idx.example/hashes.json"
			vars["TIKRAY_INDEX_PUBKEY_FILE"] = filepath.Join(data, "no-such-key")
		}, "latest", "no-such-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vars, data := testEnv(t, runnerapi.Status{})
			saved := seedResult(t, data)
			tc.setup(vars, data)

			code, stdout, stderr := runCLI(t, vars, tc.args...)
			if code != 1 {
				t.Errorf("exit %d, want 1", code)
			}
			if !strings.Contains(stderr, tc.detail) {
				t.Errorf("stderr %q does not name %q", stderr, tc.detail)
			}
			got, err := os.ReadFile(saved)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != stdout {
				t.Errorf("last-result.json is\n%s\nstdout is\n%s", got, stdout)
			}
			var res artifacts.Result
			if err := json.Unmarshal(got, &res); err != nil {
				t.Fatalf("last-result.json is not a Result: %v\n%s", err, got)
			}
			if res.Outcome != artifacts.OutcomeRefused || res.To != tc.to || !strings.Contains(res.Detail, tc.detail) || res.At.IsZero() {
				t.Errorf("result %+v, want a refusal to %q naming %q", res, tc.to, tc.detail)
			}
			if fi, _ := os.Stat(saved); fi.Mode().Perm() != 0o600 {
				t.Errorf("last-result.json has mode %v, want 0600", fi.Mode().Perm())
			}
		})
	}
}

func noToken(_ map[string]string, data string) {
	os.Remove(filepath.Join(data, "run", "runner.token"))
}

// A run that dies midway (SIGKILL, out of memory) must leave no result at all,
// so the previous file has to be gone before the first call to the runner.
func TestRunRemovesThePreviousResultBeforeAnyWork(t *testing.T) {
	data := t.TempDir()
	if err := os.MkdirAll(filepath.Join(data, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "run", "runner.token"), []byte(testToken), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := seedResult(t, data)
	t.Setenv("TMPDIR", t.TempDir())

	var called, existed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		if _, err := os.Stat(saved); err == nil {
			existed.Store(true)
		}
		json.NewEncoder(w).Encode(runnerapi.Status{State: runnerapi.StateEmpty})
	}))
	t.Cleanup(srv.Close)

	vars := map[string]string{"TIKRAY_DATA": data, "TIKRAY_RUNNER_URL": srv.URL}
	if code, _, stderr := runCLI(t, vars, "core", "rollback"); code != 1 {
		t.Fatalf("exit %d, want 1 (nothing to roll back); stderr %q", code, stderr)
	}
	if !called.Load() {
		t.Fatal("the runner was never called")
	}
	if existed.Load() {
		t.Error("the previous last-result.json was still there when the runner was called")
	}
	var res artifacts.Result
	if b, err := os.ReadFile(saved); err != nil || json.Unmarshal(b, &res) != nil || res.Outcome != artifacts.OutcomeRefused {
		t.Errorf("last-result.json is %q (%v), want this run's refusal", b, err)
	}
}

// With a bad environment there is no data root to put a result in.
func TestRunBadEnvironmentLeavesTheResult(t *testing.T) {
	data := t.TempDir()
	saved := seedResult(t, data)
	before, _ := os.ReadFile(saved)
	vars := map[string]string{"TIKRAY_DATA": data, "TIKRAY_MIRRORS": "https://m.example/nofile"}
	if code, stdout, stderr := runCLI(t, vars, "core", "update", "26.10.21"); code != 1 || stdout != "" || !strings.Contains(stderr, "TIKRAY_MIRRORS") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if after, _ := os.ReadFile(saved); string(after) != string(before) {
		t.Errorf("last-result.json changed to %q", after)
	}
}

func TestRemoveFileDurably(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // the second time the file is already gone
		if err := removeFileDurably(path); err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("call %d: the file is still there: %v", i+1, err)
		}
	}
	if err := removeFileDurably(filepath.Join(dir, "no-such-dir", "f")); err == nil {
		t.Error("a missing directory gave no error")
	}
}

func TestRunUpdateNoop(t *testing.T) {
	// The runner is on the config the empty state renders for the core: an
	// update renders the config, and finds it already active.
	vars, data := testEnv(t, runnerapi.Status{
		State:  runnerapi.StateRunning,
		Active: &runnerapi.Selection{Core: "26.10.21", Config: configName(t, store.Default(), "26.10.21")},
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

// A run that is killed leaves its temporary files in state/tmp, TMPDIR; the
// next update removes them once it holds the artifacts lock.
func TestRunUpdateSweepsStateTmp(t *testing.T) {
	vars, data := testEnv(t, runnerapi.Status{
		State:  runnerapi.StateRunning,
		Active: &runnerapi.Selection{Core: "26.10.21", Config: configName(t, store.Default(), "26.10.21")},
	})
	tmp := filepath.Join(data, "state", "tmp")
	left := filepath.Join(tmp, "tikray-core-123", "Xray-linux-arm64-v8a.zip.part")
	if err := os.MkdirAll(filepath.Dir(left), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(left, []byte("half a zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := runCLI(t, vars, "core", "update", "26.10.21"); code != 0 {
		t.Fatalf("exit %d; stdout %q, stderr %q", code, stdout, stderr)
	}
	if ents, err := os.ReadDir(tmp); err != nil || len(ents) != 0 {
		t.Errorf("state/tmp holds %v (%v) after the update, want it empty", ents, err)
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
	u, err := newUpdater(cfg, runner, io.Discard, nil, true)
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
	u, err = newUpdater(cfg, runner, io.Discard, nil, true)
	if err != nil || len(u.Verify.IndexPub) != 0 {
		t.Errorf("without a key: %v, %q", err, u.Verify.IndexPub)
	}

	cfg.IndexPubKeyFile = filepath.Join(data, "no-such-key")
	if _, err := newUpdater(cfg, runner, io.Discard, nil, true); err == nil || !strings.Contains(err.Error(), "no-such-key") {
		t.Errorf("missing key file: %v", err)
	}
}

func TestNewUpdaterRenderer(t *testing.T) {
	cfg := Config{Data: t.TempDir(), Arch: "amd64", RunnerURL: "http://127.0.0.1:1", Socks: "127.0.0.1:1", XrayAPI: "127.0.0.1:2"}
	runner := &runnerapi.Client{BaseURL: cfg.RunnerURL, Token: testToken}

	u, err := newUpdater(cfg, runner, io.Discard, nil, true)
	if err != nil || u.Render != nil {
		t.Errorf("without a renderer: %v, Render %v; want none, so that --config is all there is", err, u.Render != nil)
	}

	st := store.Default()
	st.DNS.Remote = "9.9.9.9"
	u, err = newUpdater(cfg, runner, io.Discard, stateRenderer(st), false)
	if err != nil || u.Render == nil {
		t.Fatalf("with a renderer: %v, Render %v", err, u.Render != nil)
	}
	got, err := u.Render(xrayver.Version{Major: 26, Minor: 10, Patch: 21}, "")
	if err != nil || !bytes.Equal(got, mustRender(t, st, "26.10.21")) {
		t.Errorf("the updater's renderer gave %q (%v), want the state's render", got, err)
	}
}

// serverOutbound is a VLESS Reality outbound, as sharelink builds one.
const serverOutbound = `{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443,"users":[{"encryption":"none","flow":"xtls-rprx-vision","id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},"streamSettings":{"network":"tcp","realitySettings":{"fingerprint":"chrome","publicKey":"SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc","serverName":"www.example.com","shortId":"6ba85179e30d4fc2"},"security":"reality"}}`

// writeState saves into data the state that change makes of the default one,
// as the daemon would, and returns it.
func writeState(t *testing.T, data string, change func(*store.State)) store.State {
	t.Helper()
	s, err := store.Open(filepath.Join(data, "state"))
	if err != nil {
		t.Fatal(err)
	}
	st, _, err := s.Update(0, func(st *store.State) error {
		change(st)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// withServer gives a state a server and a smart default policy.
func withServer(st *store.State) {
	st.DefaultPolicy = store.Policy{Mode: store.ModeSmart}
	st.Servers = []store.Server{{ID: "a1b2c3d4", Name: "lab-a", Outbound: json.RawMessage(serverOutbound)}}
}

// dnsRemote returns a change that sets the state's remote resolver: the
// smallest change that alters the rendered config.
func dnsRemote(addr string) func(*store.State) {
	return func(st *store.State) { st.DNS.Remote = addr }
}

// mustRender is what render.Render makes of st for the core, with no geo.
func mustRender(t *testing.T, st store.State, core string) []byte {
	t.Helper()
	v, err := xrayver.Parse(core)
	if err != nil {
		t.Fatal(err)
	}
	out, err := render.Render(render.Input{State: st, Core: v})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// configName is the name under run/ of the config that st renders to for the
// core: config/<SHA-256>.json.
func configName(t *testing.T, st store.State, core string) string {
	t.Helper()
	sum := sha256.Sum256(mustRender(t, st, core))
	return "config/" + hex.EncodeToString(sum[:]) + ".json"
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func decodeResult(t *testing.T, stdout string) artifacts.Result {
	t.Helper()
	var res artifacts.Result
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("stdout is not a Result: %v\n%s", err, stdout)
	}
	return res
}

// installSlot leaves an installed core in data, as a past update would have.
func installSlot(t *testing.T, data, version string) {
	t.Helper()
	dir := filepath.Join(data, "cores", version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(artifacts.Meta{Version: version, Source: "direct", Verified: "dgst"})
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// closedAddr is a loopback address that nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// trialRunner is a fake runner that takes a trial as far as an update, a
// rollback or an apply needs: status, trial, commit, abort, and an xray API
// that always answers. A trial reads candidate.json from run, where the
// CoreUpdater put it, and records it.
type trialRunner struct {
	t   *testing.T
	run string // <data>/run
	srv *httptest.Server

	mu       sync.Mutex
	st       runnerapi.Status
	reject   bool                  // trial answers 422, as it does for a config xray run -test refuses
	cands    []runnerapi.Candidate // as each trial found candidate.json
	apiCalls [][]string            // the arguments of each call to the xray API
}

func xrayVersionLine(core string) string {
	return "Xray " + core + " (Xray, Penetrates Everything.) fake (go1.24.7 linux/amd64)"
}

func newTrialRunner(t *testing.T, run string, active *runnerapi.Selection) *trialRunner {
	t.Helper()
	r := &trialRunner{t: t, run: run, st: runnerapi.Status{State: runnerapi.StateEmpty}}
	if active != nil {
		a := *active
		r.st = runnerapi.Status{State: runnerapi.StateRunning, Active: &a, XrayPID: 42, XrayVersion: xrayVersionLine(a.Core), RoutesOK: true, GatewayUp: true}
	}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

// trialEnv is testEnv with a trialRunner, which starts on active.
func trialEnv(t *testing.T, active *runnerapi.Selection) (vars map[string]string, data string, r *trialRunner) {
	t.Helper()
	vars, data = testEnv(t, runnerapi.Status{})
	r = newTrialRunner(t, filepath.Join(data, "run"), active)
	vars["TIKRAY_RUNNER_URL"] = r.srv.URL
	return vars, data, r
}

func (r *trialRunner) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if req.Header.Get("Authorization") != "Bearer "+testToken {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"unauthorized"}`)
		return
	}
	switch req.Method + " " + req.URL.Path {
	case "GET /v1/status":
		json.NewEncoder(w).Encode(r.st)
	case "POST /v1/trial":
		r.trial(w)
	case "POST /v1/commit":
		r.end(w, runnerapi.OutcomeCommitted)
	case "POST /v1/abort":
		r.end(w, runnerapi.OutcomeAborted)
	case "POST /v1/xray-api":
		var in runnerapi.XrayAPIRequest
		if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
			r.t.Errorf("xray-api: %v", err)
		}
		r.apiCalls = append(r.apiCalls, in.Args)
		json.NewEncoder(w).Encode(runnerapi.XrayAPIResponse{})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (r *trialRunner) trial(w http.ResponseWriter) {
	var c runnerapi.Candidate
	raw, err := os.ReadFile(filepath.Join(r.run, "candidate.json"))
	if err == nil {
		err = json.Unmarshal(raw, &c)
	}
	if err == nil {
		err = c.Validate()
	}
	if err != nil {
		r.t.Errorf("trial: candidate.json: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	r.cands = append(r.cands, c)
	switch {
	case r.reject:
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, `{"error":"test_failed","detail":"xray says no"}`)
	case r.st.State == runnerapi.StateTrial:
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, `{"error":"busy"}`)
	default:
		r.st.State, r.st.Candidate = runnerapi.StateTrial, &c
		r.st.XrayPID, r.st.XrayVersion = 43, xrayVersionLine(c.Core)
		r.st.RoutesOK, r.st.GatewayUp = true, true
		w.WriteHeader(http.StatusNoContent)
	}
}

// end closes the open trial: a commit makes the candidate active, an abort
// reverts to the active selection.
func (r *trialRunner) end(w http.ResponseWriter, outcome string) {
	if r.st.State != runnerapi.StateTrial {
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, `{"error":"no_trial"}`)
		return
	}
	c := *r.st.Candidate
	if outcome == runnerapi.OutcomeCommitted {
		sel := c.Selection
		r.st.Active = &sel
	}
	r.st.State, r.st.Candidate = runnerapi.StateRunning, nil
	if r.st.Active != nil {
		r.st.XrayVersion = xrayVersionLine(r.st.Active.Core)
	}
	r.st.LastTrial = &runnerapi.TrialResult{Candidate: c, Outcome: outcome, At: time.Now()}
	os.Remove(filepath.Join(r.run, "candidate.json"))
	w.WriteHeader(http.StatusNoContent)
}

// active is the runner's active selection.
func (r *trialRunner) active() runnerapi.Selection {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.st.Active == nil {
		return runnerapi.Selection{}
	}
	return *r.st.Active
}

func (r *trialRunner) candidates() []runnerapi.Candidate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]runnerapi.Candidate(nil), r.cands...)
}

// xrayAPICalls are the arguments of the calls to the xray API so far.
func (r *trialRunner) xrayAPICalls() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]string(nil), r.apiCalls...)
}

// runFast is runCLI for a command that drives a trial: the updater waits 1 ms,
// not 10 s, before it looks at the candidate, and gives up on its health check
// after 300 ms, not 30 s.
func runFast(t *testing.T, vars map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	c := &cli{getenv: envOf(vars), stdout: &out, stderr: &errb, tune: func(u *artifacts.CoreUpdater) {
		u.EarlyExit = time.Millisecond
		u.HealthWindow = 300 * time.Millisecond
	}}
	code = c.run(context.Background(), args)
	return code, out.String(), errb.String()
}

func TestConfigRender(t *testing.T) {
	t.Run("--core", func(t *testing.T) {
		vars, data := testEnv(t, runnerapi.Status{})
		st := writeState(t, data, withServer)
		stateFile := filepath.Join(data, "state", "state.v1.json")
		before, err := os.ReadFile(stateFile)
		if err != nil {
			t.Fatal(err)
		}

		code, stdout, stderr := runCLI(t, vars, "config", "render", "--core", "26.10.21")
		if code != 0 || stderr != "" {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		if want := mustRender(t, st, "26.10.21"); stdout != string(want) {
			t.Errorf("stdout is\n%s\nwant render.Render's\n%s", stdout, want)
		}
		if !strings.Contains(stdout, "srv-a1b2c3d4") {
			t.Errorf("the config lacks the state's server:\n%s", stdout)
		}

		// A read: nothing is written to the data root.
		if after, err := os.ReadFile(stateFile); err != nil || !bytes.Equal(after, before) {
			t.Errorf("the state file changed (%v)", err)
		}
		if names := dirNames(t, filepath.Join(data, "state")); !reflect.DeepEqual(names, []string{"state.v1.json"}) {
			t.Errorf("state/ holds %v, want the state file alone", names)
		}
		if _, err := os.Stat(filepath.Join(data, "inbox")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("config render made the inbox: %v", err)
		}
	})

	t.Run("--core needs no runner", func(t *testing.T) {
		vars, data := testEnv(t, runnerapi.Status{})
		st := writeState(t, data, withServer)
		noToken(vars, data)
		vars["TIKRAY_RUNNER_URL"] = "http://" + closedAddr(t)
		code, stdout, stderr := runCLI(t, vars, "config", "render", "--core", "v26.10.21")
		if code != 0 || stderr != "" || stdout != string(mustRender(t, st, "26.10.21")) {
			t.Errorf("exit %d, stderr %q, stdout\n%s", code, stderr, stdout)
		}
	})

	t.Run("no state yet", func(t *testing.T) {
		data := t.TempDir()
		code, stdout, stderr := runCLI(t, map[string]string{"TIKRAY_DATA": data}, "config", "render", "--core", "26.10.21")
		if code != 0 || stderr != "" || stdout != string(mustRender(t, store.Default(), "26.10.21")) {
			t.Fatalf("exit %d, stderr %q, stdout\n%s", code, stderr, stdout)
		}
		// Opening the store may make state/, and nothing else.
		for _, name := range dirNames(t, data) {
			fi, err := os.Stat(filepath.Join(data, name))
			if err != nil {
				t.Fatal(err)
			}
			if name != "state" || fi.Mode().Perm() != 0o700 || len(dirNames(t, filepath.Join(data, name))) != 0 {
				t.Errorf("config render left %s (%v)", name, fi.Mode())
			}
		}
	})

	t.Run("the runner's active core", func(t *testing.T) {
		vars, data := testEnv(t, runnerapi.Status{
			State:  runnerapi.StateRunning,
			Active: &runnerapi.Selection{Core: "26.3.27", Config: testConfigRel},
		})
		st := writeState(t, data, withServer)
		code, stdout, stderr := runCLI(t, vars, "config", "render")
		if code != 0 || stderr != "" {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		if want := mustRender(t, st, "26.3.27"); stdout != string(want) {
			t.Errorf("stdout is\n%s\nwant the render for 26.3.27\n%s", stdout, want)
		}
	})

	t.Run("it is the runner's core that renders", func(t *testing.T) {
		// 26.1.17 has no TUN inbound: the render refuses it, which only
		// happens if the runner's active core was taken.
		vars, _ := testEnv(t, runnerapi.Status{
			State:  runnerapi.StateRunning,
			Active: &runnerapi.Selection{Core: "26.1.17", Config: testConfigRel},
		})
		code, stdout, stderr := runCLI(t, vars, "config", "render")
		if code != 1 || stdout != "" || !strings.Contains(stderr, "26.1.17") {
			t.Errorf("exit %d, stdout %q, stderr %q; want 1 and the old core named", code, stdout, stderr)
		}
	})

	t.Run("no active core", func(t *testing.T) {
		vars, _ := testEnv(t, runnerapi.Status{State: runnerapi.StateEmpty})
		code, stdout, stderr := runCLI(t, vars, "config", "render")
		if code != 1 || stdout != "" || !strings.Contains(stderr, "--core") {
			t.Errorf("exit %d, stdout %q, stderr %q; want 1 and --core named", code, stdout, stderr)
		}
	})

	t.Run("no runner", func(t *testing.T) {
		vars, data := testEnv(t, runnerapi.Status{})
		noToken(vars, data)
		code, stdout, stderr := runCLI(t, vars, "config", "render")
		if code != 1 || stdout != "" || !strings.Contains(stderr, "--core") || !strings.Contains(stderr, "runner.token") {
			t.Errorf("exit %d, stdout %q, stderr %q; want 1, --core and the token named", code, stdout, stderr)
		}
	})

	t.Run("unreadable state", func(t *testing.T) {
		data := t.TempDir()
		if err := os.MkdirAll(filepath.Join(data, "state"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(data, "state", "state.v1.json"), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := runCLI(t, map[string]string{"TIKRAY_DATA": data}, "config", "render", "--core", "26.10.21")
		if code != 1 || stdout != "" || !strings.Contains(stderr, "state.v1.json") {
			t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	})
}

func TestApplyCommand(t *testing.T) {
	vars, data, runner := trialEnv(t, &runnerapi.Selection{Core: "26.10.21", Config: testConfigRel})
	st := writeState(t, data, func(*store.State) {})
	stateFile := filepath.Join(data, "state", "state.v1.json")
	before, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}

	// The runner is on another config than the state renders to: a trial.
	code, stdout, stderr := runFast(t, vars, "apply")
	if code != 0 {
		t.Fatalf("exit %d, want 0; stdout %q, stderr %q", code, stdout, stderr)
	}
	res := decodeResult(t, stdout)
	if res.Outcome != runnerapi.OutcomeCommitted || res.Kind != artifacts.KindConfig || res.From != "26.10.21" || res.To != "26.10.21" {
		t.Errorf("result %+v, want a committed config for 26.10.21", res)
	}
	want := runnerapi.Selection{Core: "26.10.21", Config: configName(t, st, "26.10.21")}
	if got := runner.active(); got != want {
		t.Errorf("the runner is on %+v, want %+v", got, want)
	}
	if b, err := os.ReadFile(filepath.Join(data, "run", want.Config)); err != nil || !bytes.Equal(b, mustRender(t, st, "26.10.21")) {
		t.Errorf("the config on trial is %q (%v), want the state's render", b, err)
	}
	if saved, err := os.ReadFile(filepath.Join(data, "state", "last-result.json")); err != nil || string(saved) != stdout {
		t.Errorf("last-result.json is %q (%v), want the stdout %q", saved, err, stdout)
	}
	// The health check asked xray's API at the runner's address on the
	// state's subnet.
	if calls := runner.xrayAPICalls(); len(calls) == 0 || !reflect.DeepEqual(calls[0], []string{"statssys", "--server=172.31.255.3:10085"}) {
		t.Errorf("xray API calls %q, want statssys against 172.31.255.3:10085", calls)
	}

	// A second run finds it done.
	code, stdout, stderr = runFast(t, vars, "apply")
	if code != 0 {
		t.Fatalf("second run: exit %d, want 0; stdout %q, stderr %q", code, stdout, stderr)
	}
	if res := decodeResult(t, stdout); res.Outcome != artifacts.OutcomeNoop || res.Kind != artifacts.KindConfig {
		t.Errorf("second run: result %+v, want a config noop", res)
	}
	if n := len(runner.candidates()); n != 1 {
		t.Errorf("%d trials after a noop, want the first alone", n)
	}
	if after, err := os.ReadFile(stateFile); err != nil || !bytes.Equal(after, before) {
		t.Errorf("apply changed the state file (%v)", err)
	}

	// Once the state changes, so does the config.
	st = writeState(t, data, dnsRemote("9.9.9.9"))
	code, stdout, stderr = runFast(t, vars, "apply")
	if code != 0 {
		t.Fatalf("after a state change: exit %d, want 0; stdout %q, stderr %q", code, stdout, stderr)
	}
	if res := decodeResult(t, stdout); res.Outcome != runnerapi.OutcomeCommitted || res.Kind != artifacts.KindConfig {
		t.Errorf("after a state change: result %+v", res)
	}
	if got, want := runner.active().Config, configName(t, st, "26.10.21"); got != want || got == configName(t, store.Default(), "26.10.21") {
		t.Errorf("the runner is on %s, want the new render %s", got, want)
	}
}

func TestApplyRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		active *runnerapi.Selection
		setup  func(vars map[string]string, data string)
		detail string
	}{
		{"no active core", nil, func(map[string]string, string) {}, "no active core"},
		{"missing runner token", &runnerapi.Selection{Core: "26.10.21", Config: testConfigRel}, noToken, "runner.token"},
		{"a geo bundle", &runnerapi.Selection{Core: "26.10.21", Geo: "ir-2026", Config: testConfigRel}, func(map[string]string, string) {}, "geo bundles are not supported yet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vars, data, runner := trialEnv(t, tc.active)
			saved := seedResult(t, data)
			tc.setup(vars, data)

			code, stdout, stderr := runFast(t, vars, "apply")
			if code != 1 || !strings.Contains(stderr, tc.detail) {
				t.Errorf("exit %d, stderr %q; want 1 and %q", code, stderr, tc.detail)
			}
			res := decodeResult(t, stdout)
			if res.Outcome != artifacts.OutcomeRefused || res.Kind != artifacts.KindConfig || !strings.Contains(res.Detail, tc.detail) {
				t.Errorf("result %+v, want a refused config result naming %q", res, tc.detail)
			}
			if got, err := os.ReadFile(saved); err != nil || string(got) != stdout {
				t.Errorf("last-result.json is %q (%v), want this run's stdout", got, err)
			}
			if n := len(runner.candidates()); n != 0 {
				t.Errorf("%d trials for a refused apply", n)
			}
		})
	}
}

func TestCoreUpdateRenders(t *testing.T) {
	vars, data, runner := trialEnv(t, &runnerapi.Selection{Core: "26.3.27", Config: testConfigRel})
	installSlot(t, data, "26.10.21")
	st := writeState(t, data, func(*store.State) {})

	code, stdout, stderr := runFast(t, vars, "core", "update", "26.10.21")
	if code != 0 {
		t.Fatalf("exit %d, want 0; stdout %q, stderr %q", code, stdout, stderr)
	}
	res := decodeResult(t, stdout)
	if res.Outcome != runnerapi.OutcomeCommitted || res.From != "26.3.27" || res.To != "26.10.21" || res.Kind != "" {
		t.Errorf("result %+v, want a committed update from 26.3.27 to 26.10.21", res)
	}
	want := configName(t, st, "26.10.21")
	cands := runner.candidates()
	if len(cands) != 1 || cands[0].Core != "26.10.21" || cands[0].Config != want {
		t.Fatalf("candidates %+v, want one for 26.10.21 with the rendered config %s", cands, want)
	}
	if b, err := os.ReadFile(filepath.Join(data, "run", want)); err != nil || !bytes.Equal(b, mustRender(t, st, "26.10.21")) {
		t.Errorf("the config in the candidate is %q (%v), want the state's render", b, err)
	}

	// The same update finds nothing to do while the state stays as it was...
	code, stdout, stderr = runFast(t, vars, "core", "update", "26.10.21")
	if res := decodeResult(t, stdout); code != 0 || res.Outcome != artifacts.OutcomeNoop {
		t.Errorf("same state: exit %d, result %+v, stderr %q; want a noop", code, res, stderr)
	}

	// ...and renders and trials the new config once it changes, though the
	// core is the active one.
	st = writeState(t, data, dnsRemote("9.9.9.9"))
	code, stdout, stderr = runFast(t, vars, "core", "update", "26.10.21")
	if res := decodeResult(t, stdout); code != 0 || res.Outcome != runnerapi.OutcomeCommitted || res.From != "26.10.21" {
		t.Fatalf("changed state: exit %d, result %+v, stderr %q; want a commit", code, res, stderr)
	}
	if got, want := runner.active().Config, configName(t, st, "26.10.21"); got != want {
		t.Errorf("the runner is on %s, want the new render %s", got, want)
	}
}

func TestCoreRollbackRenders(t *testing.T) {
	vars, data, runner := trialEnv(t, &runnerapi.Selection{Core: "26.3.27", Config: testConfigRel})
	installSlot(t, data, "26.3.27")
	installSlot(t, data, "26.10.21")
	writeState(t, data, dnsRemote("9.9.9.9"))
	if code, stdout, stderr := runFast(t, vars, "core", "update", "26.10.21"); code != 0 {
		t.Fatalf("update: exit %d; stdout %q, stderr %q", code, stdout, stderr)
	}

	// The state moves on before the rollback: the core it goes back to runs the
	// config of the state as it is now, not the one it had.
	st := writeState(t, data, dnsRemote("8.8.8.8"))
	code, stdout, stderr := runFast(t, vars, "core", "rollback")
	if code != 0 {
		t.Fatalf("rollback: exit %d; stdout %q, stderr %q", code, stdout, stderr)
	}
	if res := decodeResult(t, stdout); res.Outcome != runnerapi.OutcomeCommitted || res.From != "26.10.21" || res.To != "26.3.27" {
		t.Errorf("result %+v, want a committed rollback to 26.3.27", res)
	}
	want := runnerapi.Selection{Core: "26.3.27", Config: configName(t, st, "26.3.27")}
	if got := runner.active(); got != want {
		t.Errorf("the runner is on %+v, want %+v", got, want)
	}
}

func TestCoreUpdateRefusesAGeoBundle(t *testing.T) {
	vars, data, runner := trialEnv(t, &runnerapi.Selection{Core: "26.3.27", Geo: "ir-2026", Config: testConfigRel})
	installSlot(t, data, "26.10.21")
	code, stdout, stderr := runFast(t, vars, "core", "update", "26.10.21")
	if code != 1 || !strings.Contains(stderr, "geo bundles are not supported yet") {
		t.Errorf("exit %d, stderr %q; want 1 and the geo refusal", code, stderr)
	}
	if res := decodeResult(t, stdout); res.Outcome != artifacts.OutcomeRefused {
		t.Errorf("result %+v, want a refusal", res)
	}
	if n := len(runner.candidates()); n != 0 {
		t.Errorf("%d trials for a refused update", n)
	}
}

func TestStateRenderer(t *testing.T) {
	st := store.Default()
	withServer(&st)
	rend := stateRenderer(st)
	core := xrayver.Version{Major: 26, Minor: 10, Patch: 21}

	got, err := rend(core, "")
	if err != nil || !bytes.Equal(got, mustRender(t, st, "26.10.21")) {
		t.Errorf("no geo: %q, %v; want render.Render's bytes", got, err)
	}
	if _, err := rend(core, "ir-2026"); err == nil || !strings.Contains(err.Error(), "geo bundles are not supported yet") {
		t.Errorf("a geo bundle: %v, want the refusal", err)
	}
	if _, err := rend(xrayver.Version{Major: 26, Minor: 1, Patch: 17}, ""); err == nil || !strings.Contains(err.Error(), "26.1.17") {
		t.Errorf("a core too old: %v, want render's refusal", err)
	}
}

func TestHealthFollowsServers(t *testing.T) {
	cfg := Config{Socks: "10.9.8.3:1080", ProbeURL: "https://probe.example/204", XrayAPI: "10.9.8.3:10085"}
	runner := &runnerapi.Client{BaseURL: "http://127.0.0.1:1", Token: testToken}
	wantAPI := artifacts.XrayAPIProbe{Runner: runner, Server: "10.9.8.3:10085"}
	wantSOCKS := artifacts.SOCKSProbe{Addr: "10.9.8.3:1080", URL: "https://probe.example/204", Timeout: probeTimeout}

	// With no server, socks-in goes to block and its probe could only fail.
	if got := healthChecks(cfg, runner, false); !reflect.DeepEqual(got, []artifacts.HealthChecker{wantAPI}) {
		t.Errorf("without the SOCKS probe: %#v, want the xray API probe alone", got)
	}
	// M1's order: the proxy first, then xray's API.
	if got := healthChecks(cfg, runner, true); !reflect.DeepEqual(got, []artifacts.HealthChecker{wantSOCKS, wantAPI}) {
		t.Errorf("with the SOCKS probe: %#v, want both", got)
	}
}

// The probes an update runs follow the state it renders, and all of them run
// for a config file, as in M1.
func TestHealthProbesOfACommand(t *testing.T) {
	active := &runnerapi.Selection{Core: "26.10.21", Config: testConfigRel}

	run := func(t *testing.T, change func(*store.State), args ...string) (int, artifacts.Result, *trialRunner) {
		t.Helper()
		vars, data, runner := trialEnv(t, active)
		installSlot(t, data, "26.10.21")
		// Nothing listens on the SOCKS address: its probe can only fail.
		vars["TIKRAY_SOCKS"] = closedAddr(t)
		writeState(t, data, change)
		code, stdout, _ := runFast(t, vars, args...)
		return code, decodeResult(t, stdout), runner
	}
	noServer := func(*store.State) {}

	t.Run("no server, no SOCKS probe", func(t *testing.T) {
		code, res, _ := run(t, noServer, "apply")
		if code != 0 || res.Outcome != runnerapi.OutcomeCommitted {
			t.Errorf("exit %d, result %+v; want a commit without the SOCKS probe", code, res)
		}
	})

	t.Run("a server, the SOCKS probe", func(t *testing.T) {
		code, res, _ := run(t, withServer, "apply")
		if code != 1 || res.Outcome != artifacts.OutcomeUnhealthy || !strings.Contains(res.Detail, "socks probe") {
			t.Errorf("exit %d, result %+v; want unhealthy through the SOCKS probe", code, res)
		}
	})

	t.Run("a config file, the SOCKS probe", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "xray.json")
		body := []byte(`{"inbounds":[]}` + "\n")
		if err := os.WriteFile(file, body, 0o644); err != nil {
			t.Fatal(err)
		}
		// The state has no server, so that a rendered config would skip the probe.
		code, res, runner := run(t, noServer, "core", "update", "26.10.21", "--config", file)
		if code != 1 || res.Outcome != artifacts.OutcomeUnhealthy || !strings.Contains(res.Detail, "socks probe") {
			t.Errorf("exit %d, result %+v; want unhealthy through the SOCKS probe", code, res)
		}
		sum := sha256.Sum256(body)
		if cands := runner.candidates(); len(cands) != 1 || cands[0].Config != "config/"+hex.EncodeToString(sum[:])+".json" {
			t.Errorf("candidates %+v, want the file's config and not a render", cands)
		}
	})
}

func TestRunUsageConfigAndApply(t *testing.T) {
	vars := map[string]string{"TIKRAY_DATA": t.TempDir()}
	for _, args := range [][]string{
		{"config"},
		{"config", "bogus"},
		{"config", "render", "extra"},
		{"config", "render", "--bogus"},
		{"config", "render", "--core"},
		{"config", "render", "--core", "latest"},
		{"config", "render", "--core="},
		{"apply", "extra"},
		{"apply", "--bogus"},
	} {
		code, stdout, stderr := runCLI(t, vars, args...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "usage") {
			t.Errorf("tikray %q: exit %d, stdout %q, stderr %q; want 2 and usage on stderr only", args, code, stdout, stderr)
		}
	}
	if ents, _ := os.ReadDir(vars["TIKRAY_DATA"]); len(ents) != 0 {
		t.Errorf("a usage error created %v in the data root", ents)
	}

	for _, args := range [][]string{{"config", "help"}, {"config", "render", "-h"}, {"apply", "-h"}, {"apply", "--help"}} {
		code, stdout, stderr := runCLI(t, vars, args...)
		if code != 0 || !strings.Contains(stdout+stderr, "usage") {
			t.Errorf("tikray %q: exit %d, stdout %q, stderr %q; want 0 and usage", args, code, stdout, stderr)
		}
	}
}

func TestUsageTextListsTheNewCommands(t *testing.T) {
	code, stdout, _ := runCLI(t, nil, "help")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"config render", "--core", "apply", "TIKRAY_XRAY_API"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the usage text lacks %q:\n%s", want, stdout)
		}
	}
}

// With no --config, an update runs the config the state renders to, and so
// updating to the active version trials a changed render. Both the flag's help
// and the usage text say so, in one sentence.
func TestUpdateHelpSaysItRenders(t *testing.T) {
	const sentence = "without --config the config is rendered from the state for the target core, " +
		"so updating to the version already active re-renders and trials the config when the state changed"
	flat := func(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

	code, stdout, stderr := runCLI(t, nil, "core", "update", "-h")
	if code != 0 {
		t.Fatalf("core update -h: exit %d", code)
	}
	if got := flat(stdout + stderr); !strings.Contains(got, sentence) {
		t.Errorf("the --config help lacks %q:\n%s", sentence, stdout+stderr)
	}

	code, stdout, _ = runCLI(t, nil, "help")
	if code != 0 {
		t.Fatalf("help: exit %d", code)
	}
	if got := flat(stdout); !strings.Contains(got, sentence) {
		t.Errorf("the usage text lacks %q:\n%s", sentence, stdout)
	}
}

// configFile writes an xray config with body and returns its path and its name
// under run/ once the CoreUpdater has stored it: config/<SHA-256>.json.
func configFile(t *testing.T, body string) (path, rel string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "xray.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	return path, "config/" + hex.EncodeToString(sum[:]) + ".json"
}

// With --config the state only supplies the runner's addresses, so an
// unreadable one (M1's recovery path: the user has a config to run) costs a
// warning and the default addresses, not the command. Without --config the
// config comes from the state, which then must be readable.
// writeBad writes body as the file name in data's state directory and returns
// name.
func writeBad(t *testing.T, data, name string, body []byte) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(data, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "state", name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

// unreadableStates each make the state in data unreadable and return the name
// of the file the error blames.
var unreadableStates = map[string]func(t *testing.T, data string) string{
	"corrupt": func(t *testing.T, data string) string {
		return writeBad(t, data, "state.v1.json", []byte("{not json"))
	},
	"invalid": func(t *testing.T, data string) string {
		// A state the store refuses to load: take a saved one and spoil a policy.
		writeState(t, data, func(*store.State) {})
		file := filepath.Join(data, "state", "state.v1.json")
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(b, []byte(`"direct"`)) {
			t.Fatalf("the saved state has no policy to spoil:\n%s", b)
		}
		return writeBad(t, data, "state.v1.json", bytes.Replace(b, []byte(`"direct"`), []byte(`"bogus"`), 1))
	},
	"only newer files": func(t *testing.T, data string) string {
		return writeBad(t, data, "state.v99.json", []byte(`{"version":99,"revision":1,"state":{}}`))
	},
}

// With no state file the state is the default one, which renders a config
// that sends all traffic direct. A plain update, rollback or apply must not put
// that in place of a config the runner runs, such as M1's --config one; a
// fresh install still bootstraps from it.
func TestNoStateFileKeepsAWorkingConfig(t *testing.T) {
	// setup leaves the runner on 26.3.27 with a config of the user's, as an
	// update from 26.10.21 with --config would have, and both cores
	// installed.
	setup := func(t *testing.T) (vars map[string]string, data string, runner *trialRunner, active runnerapi.Selection) {
		t.Helper()
		active = runnerapi.Selection{Core: "26.3.27", Config: testConfigRel}
		vars, data, runner = trialEnv(t, &active)
		installSlot(t, data, "26.3.27")
		installSlot(t, data, "26.10.21")
		b, err := json.Marshal(artifacts.Result{From: "26.10.21", To: "26.3.27", Outcome: runnerapi.OutcomeCommitted, At: time.Now().Add(-time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(data, "state"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(data, "state", "core-history.jsonl"), append(b, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		return vars, data, runner, active
	}
	for _, tc := range []struct {
		name   string
		args   []string
		advice string
	}{
		{"core update", []string{"core", "update", "26.10.21"}, "core update --config FILE"},
		{"core update to the active core", []string{"core", "update", "26.3.27"}, "core update --config FILE"},
		{"core rollback", []string{"core", "rollback"}, "create a state first"},
		{"apply", []string{"apply"}, "create a state first"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vars, data, runner, active := setup(t)
			trials := len(runner.candidates())
			code, stdout, stderr := runFast(t, vars, tc.args...)
			res := decodeResult(t, stdout)
			if code != 1 || res.Outcome != artifacts.OutcomeRefused || !strings.Contains(res.Detail, "no state has been saved") || !strings.Contains(res.Detail, tc.advice) {
				t.Errorf("exit %d, result %+v; want 1 and a refusal advising %q", code, res, tc.advice)
			}
			if !strings.Contains(stderr, "no state has been saved") {
				t.Errorf("stderr %q does not say why", stderr)
			}
			if n := len(runner.candidates()); n != trials {
				t.Errorf("%d trials after the refusal, want %d", n, trials)
			}
			if got := runner.active(); got != active {
				t.Errorf("the runner is on %+v, want %+v as before", got, active)
			}
			// Once there is a state, its render goes on trial.
			writeState(t, data, func(*store.State) {})
			if code, stdout, stderr := runFast(t, vars, tc.args...); code != 0 {
				t.Errorf("with a state: exit %d; stdout %q, stderr %q", code, stdout, stderr)
			}
		})
	}

	t.Run("a fresh install bootstraps from the default state", func(t *testing.T) {
		vars, _, runner := trialEnv(t, nil)
		installSlot(t, vars["TIKRAY_DATA"], "26.10.21")
		code, stdout, stderr := runFast(t, vars, "core", "update", "26.10.21")
		if code != 0 {
			t.Fatalf("exit %d; stdout %q, stderr %q", code, stdout, stderr)
		}
		want := runnerapi.Selection{Core: "26.10.21", Config: configName(t, store.Default(), "26.10.21")}
		if got := runner.active(); got != want {
			t.Errorf("the runner is on %+v, want %+v", got, want)
		}
	})
}

// core status needs the state for nothing but the runner's address, so an
// unreadable one costs a warning and the default address, as it does for
// update --config.
func TestCoreStatusSurvivesAnUnreadableState(t *testing.T) {
	want := runnerapi.Status{State: runnerapi.StateRunning, Active: &runnerapi.Selection{Core: "26.10.21", Config: testConfigRel}, GatewayUp: true}
	for name, breakState := range unreadableStates {
		t.Run(name, func(t *testing.T) {
			vars, data := testEnv(t, want)
			bad := breakState(t, data)
			code, stdout, stderr := runCLI(t, vars, "core", "status")
			if code != 0 {
				t.Fatalf("exit %d, stderr %q; want 0", code, stderr)
			}
			var got runnerapi.Status
			if err := json.Unmarshal([]byte(stdout), &got); err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("stdout %q (%v), want the runner's status %+v", stdout, err, want)
			}
			if n := strings.Count(stderr, "\n"); n != 1 || !strings.HasPrefix(stderr, "tikray: warning: ") || !strings.Contains(stderr, bad) {
				t.Errorf("stderr %q; want one warning line naming %s", stderr, bad)
			}
		})
	}
}

// config render renders the state, so an unreadable one ends it, before the
// runner is asked anything.
func TestConfigRenderNeedsAReadableState(t *testing.T) {
	for name, breakState := range unreadableStates {
		for core, args := range map[string][]string{
			"--core":      {"config", "render", "--core", "26.10.21"},
			"active core": {"config", "render"},
		} {
			t.Run(name+", "+core, func(t *testing.T) {
				vars, data := testEnv(t, runnerapi.Status{})
				runner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Errorf("the runner was asked %s %s", r.Method, r.URL.Path)
				}))
				t.Cleanup(runner.Close)
				vars["TIKRAY_RUNNER_URL"] = runner.URL
				bad := breakState(t, data)
				code, stdout, stderr := runCLI(t, vars, args...)
				if code != 1 || stdout != "" {
					t.Errorf("exit %d, stdout %q; want 1 and nothing", code, stdout)
				}
				if !strings.HasPrefix(stderr, "tikray: the state can't be read: ") || !strings.Contains(stderr, bad) || strings.Contains(stderr, "warning") {
					t.Errorf("stderr %q; want \"the state can't be read\", naming %s, and no warning", stderr, bad)
				}
			})
		}
	}
}

func TestUpdateConfigFileSurvivesAnUnreadableState(t *testing.T) {
	for name, breakState := range unreadableStates {
		t.Run(name, func(t *testing.T) {
			active, activeRel := configFile(t, `{"inbounds":[]}`+"\n")
			other, _ := configFile(t, `{"inbounds":[{"protocol":"tun"}]}`+"\n")
			vars, data, runner := trialEnv(t, &runnerapi.Selection{Core: "26.10.21", Config: activeRel})
			installSlot(t, data, "26.10.21")
			bad := breakState(t, data)
			warnings := func(stderr string) int { return strings.Count(stderr, "warning") }

			// The runner is already on this config: the update is a noop, which
			// takes the runner, and so its address, and nothing else.
			code, stdout, stderr := runFast(t, vars, "core", "update", "26.10.21", "--config", active)
			if res := decodeResult(t, stdout); code != 0 || res.Outcome != artifacts.OutcomeNoop {
				t.Errorf("noop: exit %d, result %+v, stderr %q; want exit 0 and a noop", code, res, stderr)
			}
			if line := lineWith(stderr, "warning"); warnings(stderr) != 1 || !strings.Contains(line, bad) {
				t.Errorf("noop: stderr %q; want one warning line naming %s", stderr, bad)
			}

			// A different config goes on trial. The runner's addresses come from
			// the default state: the health check probes SOCKS at its .3.
			code, stdout, stderr = runFast(t, vars, "core", "update", "26.10.21", "--config", other)
			res := decodeResult(t, stdout)
			if code != 1 || res.Outcome != artifacts.OutcomeUnhealthy || !strings.Contains(res.Detail, "172.31.255.3:1080") {
				t.Errorf("trial: exit %d, result %+v; want exit 1, unhealthy through the default SOCKS address", code, res)
			}
			if line := lineWith(stderr, "warning"); warnings(stderr) != 1 || !strings.Contains(line, bad) {
				t.Errorf("trial: stderr %q; want one warning line naming %s", stderr, bad)
			}
			if n := len(runner.candidates()); n != 1 {
				t.Errorf("%d trials, want 1", n)
			}

			// A variable still wins over the default state.
			vars["TIKRAY_SOCKS"] = closedAddr(t)
			code, stdout, _ = runFast(t, vars, "core", "update", "26.10.21", "--config", other)
			res = decodeResult(t, stdout)
			if code != 1 || !strings.Contains(res.Detail, vars["TIKRAY_SOCKS"]) {
				t.Errorf("TIKRAY_SOCKS set: exit %d, result %+v; want the probe at %s", code, res, vars["TIKRAY_SOCKS"])
			}
			delete(vars, "TIKRAY_SOCKS")

			// With the config from the state, the state has to be readable.
			trials := len(runner.candidates())
			code, stdout, stderr = runFast(t, vars, "core", "update", "26.10.21")
			res = decodeResult(t, stdout)
			if code != 1 || res.Outcome != artifacts.OutcomeRefused || !strings.Contains(res.Detail, bad) || !strings.Contains(stderr, bad) {
				t.Errorf("no --config: exit %d, result %+v, stderr %q; want a refusal naming %s", code, res, stderr, bad)
			}
			if warnings(stderr) != 0 {
				t.Errorf("no --config: stderr %q carries a warning; the refusal is the error", stderr)
			}
			if n := len(runner.candidates()); n != trials {
				t.Errorf("no --config: %d trials after the refusal, want %d", n, trials)
			}
		})
	}
}

// lineWith returns the first line of s that holds sub.
func lineWith(s, sub string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, sub) {
			return line
		}
	}
	return ""
}
