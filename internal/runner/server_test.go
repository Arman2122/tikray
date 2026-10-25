package runner

import (
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

const testToken = "0123456789abcdef-test-token"

// routes are every route the server offers.
var routes = []struct{ method, path string }{
	{http.MethodGet, "/v1/status"},
	{http.MethodPost, "/v1/trial"},
	{http.MethodPost, "/v1/commit"},
	{http.MethodPost, "/v1/abort"},
	{http.MethodPost, "/v1/restart"},
	{http.MethodPost, "/v1/reload"},
	{http.MethodPost, "/v1/xray-api"},
	{http.MethodPost, "/v1/test"},
}

// api is the server over a rig's runner, with a client for it and the number
// of times the xray api stub ran.
type api struct {
	g     *rig
	url   string
	c     *runnerapi.Client
	calls atomic.Int32
}

// newAPI serves g's runner over httptest. A nil stub answers every xray api
// call with exit code 0 and no output.
func newAPI(t *testing.T, g *rig, stub func(context.Context, []string) runnerapi.XrayAPIResponse) *api {
	t.Helper()
	a := &api{g: g}
	ts := httptest.NewServer(NewServer(g.r, testToken, func(ctx context.Context, args []string) runnerapi.XrayAPIResponse {
		a.calls.Add(1)
		if stub == nil {
			return runnerapi.XrayAPIResponse{}
		}
		return stub(ctx, args)
	}))
	t.Cleanup(ts.Close) // runs before the rig's Close
	a.url = ts.URL
	a.c = &runnerapi.Client{BaseURL: ts.URL, Token: testToken}
	return a
}

// send makes one request. auth is the Authorization header; "" sends none.
func send(t *testing.T, base, method, path, auth, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: reading the body: %v", method, path, err)
	}
	return resp, string(b)
}

// errorBody decodes a runner error body.
func errorBody(t *testing.T, body string) (code, detail string) {
	t.Helper()
	var eb struct{ Error, Detail string }
	if err := json.Unmarshal([]byte(body), &eb); err != nil {
		t.Fatalf("body %q is not a JSON error: %v", body, err)
	}
	return eb.Error, eb.Detail
}

// runningRig is a booted runner with core 26.1.18 active.
func runningRig(t *testing.T) *rig {
	t.Helper()
	g := newRig(t, nil)
	g.active(t, "ok")
	g.boot(t)
	return g
}

func TestServerAuth(t *testing.T) {
	g := runningRig(t)
	g.candidate(t, "ok", 5*time.Second)
	a := newAPI(t, g, nil)

	headers := map[string]string{
		"missing":        "",
		"wrong":          "Bearer " + strings.Repeat("x", len(testToken)),
		"shorter":        "Bearer " + testToken[:len(testToken)-1],
		"longer":         "Bearer " + testToken + "x",
		"empty":          "Bearer ",
		"no scheme":      testToken,
		"basic":          "Basic " + testToken,
		"scheme only":    "Bearer",
		"token in space": "Bearer  " + testToken,
	}
	for name, auth := range headers {
		for _, rt := range routes {
			resp, body := send(t, a.url, rt.method, rt.path, auth, `{"args":["x"]}`)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s: %s %s = %d, want 401", name, rt.method, rt.path, resp.StatusCode)
				continue
			}
			if got := strings.TrimSpace(body); got != `{"error":"unauthorized"}` {
				t.Errorf("%s: %s %s body = %s, want {\"error\":\"unauthorized\"}", name, rt.method, rt.path, got)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("%s: %s %s Content-Type = %q, want application/json", name, rt.method, rt.path, ct)
			}
			if resp.Header.Get("WWW-Authenticate") == "" {
				t.Errorf("%s: %s %s has no WWW-Authenticate header", name, rt.method, rt.path)
			}
		}
	}

	// Authentication comes before routing: nothing is learned about routes
	// without the token.
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/v1/trial"}, {http.MethodPost, "/v1/status"}, {http.MethodGet, "/nothing"}, {http.MethodGet, "/"},
	} {
		if resp, _ := send(t, a.url, rt.method, rt.path, "", ""); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("unauthenticated %s %s = %d, want 401", rt.method, rt.path, resp.StatusCode)
		}
	}

	// None of it reached the runner.
	g.wantState(t, runnerapi.StateRunning, oldCore)
	g.wantNoLastTrial(t)
	if n := a.calls.Load(); n != 0 {
		t.Errorf("xray api ran %d times for unauthenticated requests", n)
	}

	// The right token does.
	if resp, _ := send(t, a.url, http.MethodGet, "/v1/status", "Bearer "+testToken, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/status with the token = %d, want 200", resp.StatusCode)
	}
	// RFC 7235 makes the scheme case-insensitive.
	if resp, _ := send(t, a.url, http.MethodGet, "/v1/status", "bearer "+testToken, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/status with a lower-case scheme = %d, want 200", resp.StatusCode)
	}
}

// TestServerEmptyToken checks that a server given no token admits nobody,
// rather than everybody who sends an empty one.
func TestServerEmptyToken(t *testing.T) {
	g := runningRig(t)
	ts := httptest.NewServer(NewServer(g.r, "", nil))
	t.Cleanup(ts.Close)
	for _, auth := range []string{"", "Bearer ", "Bearer"} {
		if resp, _ := send(t, ts.URL, http.MethodGet, "/v1/status", auth, ""); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("empty token, Authorization %q = %d, want 401", auth, resp.StatusCode)
		}
	}
}

func TestServerTrialFlow(t *testing.T) {
	g := runningRig(t)
	a := newAPI(t, g, nil)
	ctx := t.Context()

	st, err := a.c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != runnerapi.StateRunning || st.Active == nil || st.Active.Core != oldCore || st.XrayPID == 0 {
		t.Fatalf("Status = %+v; want running core %s", st, oldCore)
	}
	if want := g.r.Status(); !reflect.DeepEqual(st, want) {
		t.Errorf("Status over HTTP = %+v, the runner's is %+v", st, want)
	}

	cand := g.candidate(t, "ok", 10*time.Second)
	if err := a.c.Trial(ctx); err != nil {
		t.Fatalf("Trial: %v", err)
	}
	st, err = a.c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != runnerapi.StateTrial || st.Candidate == nil || st.Candidate.Selection != cand.Selection {
		t.Fatalf("Status after Trial = %+v; want a trial of %+v", st, cand.Selection)
	}
	g.wantState(t, runnerapi.StateTrial, newCore)

	if err := a.c.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	st, err = a.c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != runnerapi.StateRunning || st.Active == nil || *st.Active != cand.Selection || st.Candidate != nil {
		t.Fatalf("Status after Commit = %+v; want running %+v", st, cand.Selection)
	}
	if st.LastTrial == nil || st.LastTrial.Outcome != runnerapi.OutcomeCommitted {
		t.Errorf("LastTrial = %+v, want outcome committed", st.LastTrial)
	}
	g.wantState(t, runnerapi.StateRunning, newCore)
}

func TestServerAbort(t *testing.T) {
	g := runningRig(t)
	a := newAPI(t, g, nil)
	ctx := t.Context()

	if err := a.c.Abort(ctx); !errors.Is(err, runnerapi.ErrNoTrial) {
		t.Errorf("Abort outside a trial = %v, want ErrNoTrial", err)
	}
	if err := a.c.Commit(ctx); !errors.Is(err, runnerapi.ErrNoTrial) {
		t.Errorf("Commit outside a trial = %v, want ErrNoTrial", err)
	}

	cand := g.candidate(t, "ok", 10*time.Second)
	if err := a.c.Trial(ctx); err != nil {
		t.Fatalf("Trial: %v", err)
	}
	if err := a.c.Abort(ctx); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	g.wantState(t, runnerapi.StateRunning, oldCore)
	g.wantNoCandidate(t)
	g.wantLastTrial(t, runnerapi.OutcomeAborted, cand)
	if err := a.c.Abort(ctx); !errors.Is(err, runnerapi.ErrNoTrial) {
		t.Errorf("second Abort = %v, want ErrNoTrial", err)
	}
}

func TestServerBusy(t *testing.T) {
	g := runningRig(t)
	a := newAPI(t, g, nil)
	ctx := t.Context()

	g.candidate(t, "ok", 10*time.Second)
	if err := a.c.Trial(ctx); err != nil {
		t.Fatalf("Trial: %v", err)
	}
	for name, call := range map[string]func(context.Context) error{
		"Trial": a.c.Trial, "Restart": a.c.Restart, "Reload": a.c.Reload,
	} {
		if err := call(ctx); !errors.Is(err, runnerapi.ErrBusy) {
			t.Errorf("%s during a trial = %v, want ErrBusy", name, err)
		}
	}
	g.wantState(t, runnerapi.StateTrial, newCore)
}

func TestServerRestartReload(t *testing.T) {
	g := runningRig(t)
	a := newAPI(t, g, nil)
	ctx := t.Context()
	first := g.r.Status().XrayPID

	if err := a.c.Restart(ctx); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	if pid := g.r.Status().XrayPID; pid == 0 || pid == first {
		t.Errorf("PID %d after Restart (first %d); want a new process", pid, first)
	}

	// Reload starts what active.json names now.
	sel := g.core(t, newCore, "ok")
	if err := WriteActive(g.d, sel); err != nil {
		t.Fatal(err)
	}
	if err := a.c.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	g.wantState(t, runnerapi.StateRunning, newCore)
	if st, err := a.c.Status(ctx); err != nil || st.Active == nil || *st.Active != sel {
		t.Errorf("Status after Reload = %+v, %v; want active %+v", st, err, sel)
	}
}

func TestServerTestFailed(t *testing.T) {
	g := runningRig(t)
	a := newAPI(t, g, nil)
	pid := g.r.Status().XrayPID
	cand := g.candidate(t, "badconfig", 10*time.Second)

	err := a.c.Trial(t.Context())
	var tf *runnerapi.TestFailedError
	if !errors.As(err, &tf) || !strings.Contains(tf.Output, "failed to load config") {
		t.Fatalf("Trial = %v; want a *TestFailedError containing \"failed to load config\"", err)
	}
	g.wantState(t, runnerapi.StateRunning, oldCore)
	if got := g.r.Status().XrayPID; got != pid {
		t.Errorf("PID %d, want the active xray %d untouched", got, pid)
	}
	g.wantLastTrial(t, runnerapi.OutcomeRejected, cand)
}

func TestServerXrayAPI(t *testing.T) {
	g := runningRig(t)
	var gotArgs []string
	var gotDeadline time.Time
	var hasDeadline bool
	resp := runnerapi.XrayAPIResponse{ExitCode: 0, Stdout: "ok"}
	a := newAPI(t, g, func(ctx context.Context, args []string) runnerapi.XrayAPIResponse {
		gotArgs = args
		gotDeadline, hasDeadline = ctx.Deadline()
		return resp
	})

	start := time.Now()
	got, err := a.c.XrayAPI(t.Context(), "statsquery", "-s", "127.0.0.1:10085")
	if err != nil {
		t.Fatalf("XrayAPI: %v", err)
	}
	if got != resp {
		t.Errorf("XrayAPI = %+v, want %+v", got, resp)
	}
	if want := []string{"statsquery", "-s", "127.0.0.1:10085"}; !reflect.DeepEqual(gotArgs, want) {
		t.Errorf("stub args = %q, want %q", gotArgs, want)
	}
	// The stub's context runs out 10 s after the request began.
	if !hasDeadline {
		t.Fatal("the stub's context has no deadline")
	}
	if d := gotDeadline.Sub(start); d < 9*time.Second || d > 11*time.Second {
		t.Errorf("deadline is %v after the request, want about 10s", d)
	}

	// An xray api that fails is still an answer: the exit code is in the body.
	resp = runnerapi.XrayAPIResponse{ExitCode: 3, Stdout: "partial", Stderr: "rpc error"}
	got, err = a.c.XrayAPI(t.Context(), "adi")
	if err != nil {
		t.Fatalf("XrayAPI with a failing xray api: %v", err)
	}
	if got != resp {
		t.Errorf("XrayAPI = %+v, want %+v", got, resp)
	}
}

// TestServerXrayAPIRefused covers the requests that never reach xray api.
func TestServerXrayAPIRefused(t *testing.T) {
	t.Run("no args", func(t *testing.T) {
		a := newAPI(t, runningRig(t), nil)
		_, err := a.c.XrayAPI(t.Context())
		if err == nil || !strings.Contains(err.Error(), "400") {
			t.Errorf("XrayAPI with no args = %v, want a 400 error", err)
		}
		if n := a.calls.Load(); n != 0 {
			t.Errorf("xray api ran %d times, want 0", n)
		}
	})
	t.Run("nothing runs", func(t *testing.T) {
		g := newRig(t, nil)
		g.boot(t) // no active.json: the runner stays empty
		a := newAPI(t, g, nil)
		_, err := a.c.XrayAPI(t.Context(), "adi")
		if err == nil || !strings.Contains(err.Error(), "503") || !strings.Contains(err.Error(), "no_xray") {
			t.Errorf("XrayAPI with no xray = %v, want a 503 no_xray error", err)
		}
		if n := a.calls.Load(); n != 0 {
			t.Errorf("xray api ran %d times, want 0", n)
		}
	})
}

// TestServerCancel checks that the request's context reaches Trial: a caller
// that hangs up during xray run -test ends the trial, instead of the
// candidate starting for nobody.
func TestServerCancel(t *testing.T) {
	g := runningRig(t)
	a := newAPI(t, g, nil)
	pid := g.r.Status().XrayPID
	g.candidate(t, "slowtest", 10*time.Second) // xray run -test takes a second

	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)
	go func() { errc <- a.c.Trial(ctx) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Trial = %v, want context.Canceled", err)
	}

	// Abort waits for the runner to finish with the canceled Trial. Had the
	// trial run on, the candidate would be open now and Abort would end it.
	if err := g.r.Abort(); !errors.Is(err, runnerapi.ErrNoTrial) {
		t.Fatalf("Abort after a canceled Trial = %v, want ErrNoTrial", err)
	}
	g.wantState(t, runnerapi.StateRunning, oldCore)
	if got := g.r.Status().XrayPID; got != pid {
		t.Errorf("PID %d, want the active %d untouched", got, pid)
	}
	g.wantNoLastTrial(t)
}

func TestServerTest(t *testing.T) {
	const config = `{"outbounds":[{"protocol":"freedom","tag":"direct"}]}`
	for _, tc := range []struct {
		mode   string // of the running core
		ok     bool
		output string
	}{
		{mode: "ok", ok: true, output: "Configuration OK."},
		{mode: "badconfig", ok: false, output: "failed to load config"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			g := newRig(t, nil)
			g.active(t, tc.mode)
			g.boot(t)
			a := newAPI(t, g, nil)
			before := g.r.Status()

			res, err := a.c.Test(t.Context(), []byte(config))
			if err != nil {
				t.Fatalf("Test: %v", err)
			}
			if res.OK != tc.ok || !strings.Contains(res.Output, tc.output) {
				t.Errorf("Test = %+v, want ok %v and output containing %q", res, tc.ok, tc.output)
			}

			resp, body := send(t, a.url, http.MethodPost, "/v1/test", "Bearer "+testToken, config)
			var raw map[string]any
			if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &raw) != nil || raw["ok"] != tc.ok || raw["output"] == nil {
				t.Errorf("POST /v1/test = %d %s; want 200 with ok %v and an output", resp.StatusCode, body, tc.ok)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}

			// Nothing about the runner changed: the same xray runs, and no
			// trial was recorded.
			if after := g.r.Status(); !reflect.DeepEqual(after, before) {
				t.Errorf("Status after Test = %+v, before it was %+v", after, before)
			}
			g.wantNoLastTrial(t)
			if left := testLeftovers(t, g.d); len(left) != 0 {
				t.Errorf("Test left %v", left)
			}
		})
	}
}

func TestServerTestNoCore(t *testing.T) {
	g := newRig(t, nil)
	g.boot(t) // no active.json: the runner stays empty
	a := newAPI(t, g, nil)
	if res, err := a.c.Test(t.Context(), []byte(`{}`)); !errors.Is(err, runnerapi.ErrNoCore) {
		t.Errorf("Test with no xray = %+v, %v; want ErrNoCore", res, err)
	}
	if left := testLeftovers(t, g.d); len(left) != 0 {
		t.Errorf("Test left %v", left)
	}
}

// TestServerTestDuringTrial checks that a test answers during a trial, with
// the core that runs now: the active core here rejects every config and the
// candidate's accepts them.
func TestServerTestDuringTrial(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "badconfig")
	g.boot(t)
	a := newAPI(t, g, nil)
	ctx := t.Context()
	if res, err := a.c.Test(ctx, []byte(`{}`)); err != nil || res.OK {
		t.Fatalf("Test before the trial = %+v, %v; want the active core's rejection", res, err)
	}

	g.candidate(t, "ok", 10*time.Second)
	g.trial(t)
	before := g.r.Status()
	if res, err := a.c.Test(ctx, []byte(`{}`)); err != nil || !res.OK {
		t.Errorf("Test during the trial = %+v, %v; want the candidate's acceptance", res, err)
	}
	if after := g.r.Status(); !reflect.DeepEqual(after, before) {
		t.Errorf("Status after Test = %+v, before it was %+v", after, before)
	}
	g.wantState(t, runnerapi.StateTrial, newCore)

	if err := a.c.Abort(ctx); err != nil {
		t.Fatal(err)
	}
	if res, err := a.c.Test(ctx, []byte(`{}`)); err != nil || res.OK {
		t.Errorf("Test after Abort = %+v, %v; want the active core's rejection", res, err)
	}
	if left := testLeftovers(t, g.d); len(left) != 0 {
		t.Errorf("Test left %v", left)
	}
}

// TestServerTestWhileTheRunnerIsBusy checks that a test does not queue behind
// the runner's goroutine: it answers while a trial's own xray run -test holds
// that goroutine.
func TestServerTestWhileTheRunnerIsBusy(t *testing.T) {
	g := runningRig(t)
	a := newAPI(t, g, nil)
	g.candidate(t, "slowtest", 10*time.Second) // its xray run -test takes a second
	errc := make(chan error, 1)
	go func() { errc <- a.c.Trial(t.Context()) }()
	// The trial stages the candidate's core right before it tests it.
	waitFor(t, 5*time.Second, "the candidate's core to be staged", func() bool {
		_, err := os.Stat(filepath.Join(g.stage, newCore, "xray"))
		return err == nil
	})

	res, err := a.c.Test(t.Context(), []byte(`{}`))
	if err != nil || !res.OK {
		t.Errorf("Test while the trial tests its candidate = %+v, %v; want the active core's acceptance", res, err)
	}
	select {
	case err := <-errc:
		t.Fatalf("the trial ended (%v) before Test answered; want Test to answer while the trial's xray run -test runs", err)
	default:
	}
	if err := <-errc; err != nil {
		t.Fatalf("Trial: %v", err)
	}
	g.wantState(t, runnerapi.StateTrial, newCore)
}

func TestServerTestBody(t *testing.T) {
	g := runningRig(t)
	a := newAPI(t, g, nil)
	// jsonOf is a JSON object of exactly n bytes.
	jsonOf := func(n int) string { return `{"x":"` + strings.Repeat("y", n-len(`{"x":""}`)) + `"}` }

	resp, body := send(t, a.url, http.MethodPost, "/v1/test", "Bearer "+testToken, jsonOf(1<<20))
	var res runnerapi.TestResult
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &res) != nil || !res.OK {
		t.Errorf("POST /v1/test of 1 MiB = %d %.200s; want 200 and ok", resp.StatusCode, body)
	}
	resp, body = send(t, a.url, http.MethodPost, "/v1/test", "Bearer "+testToken, jsonOf(1<<20+1))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("POST /v1/test of 1 MiB and a byte = %d %.200s; want 413", resp.StatusCode, body)
	} else if code, _ := errorBody(t, body); code != "too_large" {
		t.Errorf("error code = %q, want too_large", code)
	}
	resp, body = send(t, a.url, http.MethodPost, "/v1/test", "Bearer "+testToken, `{"outbounds":[`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /v1/test of a body that is not JSON = %d %s; want 400", resp.StatusCode, body)
	}
	// xray-api keeps its own, smaller cap.
	resp, body = send(t, a.url, http.MethodPost, "/v1/xray-api", "Bearer "+testToken, `{"args":["`+strings.Repeat("x", 64<<10)+`"]}`)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "too large") {
		t.Errorf("POST /v1/xray-api over 64 KiB = %d %s; want 400 too large", resp.StatusCode, body)
	}
	if left := testLeftovers(t, g.d); len(left) != 0 {
		t.Errorf("Test left %v", left)
	}
}

// TestServerStatusCodes pins the status code and error code of each answer.
func TestServerStatusCodes(t *testing.T) {
	trialOpen := func(t *testing.T, g *rig) {
		g.candidate(t, "ok", 10*time.Second)
		g.trial(t)
	}
	candidate := func(t *testing.T, g *rig) { g.candidate(t, "ok", 10*time.Second) }

	tests := []struct {
		name         string
		noActive     bool // boot without active.json
		setup        func(t *testing.T, g *rig)
		method, path string
		body         string
		status       int
		code, detail string // the error code and a substring of the detail; "" when the body is not an error
	}{
		{name: "status", method: "GET", path: "/v1/status", status: 200},
		{name: "trial", setup: candidate, method: "POST", path: "/v1/trial", status: 204},
		{name: "trial with a body", setup: candidate, method: "POST", path: "/v1/trial", body: `{"ignored":true}`, status: 204},
		{name: "commit", setup: trialOpen, method: "POST", path: "/v1/commit", status: 204},
		{name: "abort", setup: trialOpen, method: "POST", path: "/v1/abort", status: 204},
		{name: "restart", method: "POST", path: "/v1/restart", status: 204},
		{name: "reload", method: "POST", path: "/v1/reload", status: 204},

		{name: "trial without a candidate", method: "POST", path: "/v1/trial", status: 400, code: "bad_request", detail: "invalid candidate"},
		{name: "trial of an expired candidate", setup: func(t *testing.T, g *rig) { g.candidate(t, "ok", -time.Second) },
			method: "POST", path: "/v1/trial", status: 400, code: "bad_request", detail: "not in the future"},
		{name: "trial of a corrupt candidate", setup: func(t *testing.T, g *rig) { writeFile(t, g.d.CandidateFile(), "{not json") },
			method: "POST", path: "/v1/trial", status: 400, code: "bad_request", detail: "invalid candidate"},
		{name: "xray-api with malformed JSON", method: "POST", path: "/v1/xray-api", body: `{"args":`, status: 400, code: "bad_request"},
		{name: "xray-api with an empty body", method: "POST", path: "/v1/xray-api", status: 400, code: "bad_request"},
		{name: "xray-api with no args", method: "POST", path: "/v1/xray-api", body: `{}`, status: 400, code: "bad_request", detail: "args"},
		{name: "xray-api with empty args", method: "POST", path: "/v1/xray-api", body: `{"args":[]}`, status: 400, code: "bad_request", detail: "args"},
		{name: "xray-api with args of the wrong type", method: "POST", path: "/v1/xray-api", body: `{"args":"adi"}`, status: 400, code: "bad_request"},
		{name: "xray-api with a body over the cap", method: "POST", path: "/v1/xray-api",
			body: `{"args":["` + strings.Repeat("x", 64<<10) + `"]}`, status: 400, code: "bad_request", detail: "too large"},

		{name: "commit outside a trial", method: "POST", path: "/v1/commit", status: 409, code: "no_trial"},
		{name: "abort outside a trial", method: "POST", path: "/v1/abort", status: 409, code: "no_trial"},
		{name: "trial during a trial", setup: trialOpen, method: "POST", path: "/v1/trial", status: 409, code: "busy"},
		{name: "restart during a trial", setup: trialOpen, method: "POST", path: "/v1/restart", status: 409, code: "busy"},
		{name: "reload during a trial", setup: trialOpen, method: "POST", path: "/v1/reload", status: 409, code: "busy"},

		{name: "trial of a rejected config", setup: func(t *testing.T, g *rig) { g.candidate(t, "badconfig", 10*time.Second) },
			method: "POST", path: "/v1/trial", status: 422, code: "test_failed", detail: "failed to load config"},

		{name: "xray-api with no xray", noActive: true, method: "POST", path: "/v1/xray-api", body: `{"args":["adi"]}`, status: 503, code: "no_xray"},

		{name: "test with no xray", noActive: true, method: "POST", path: "/v1/test", body: `{}`, status: 409, code: "no_core"},
		{name: "test with an empty body", method: "POST", path: "/v1/test", status: 400, code: "bad_request"},
		{name: "test of a body that is not JSON", method: "POST", path: "/v1/test", body: `{"outbounds":`, status: 400, code: "bad_request"},
		{name: "test of two JSON values", method: "POST", path: "/v1/test", body: `{} {}`, status: 400, code: "bad_request"},
		{name: "test of a body over 1 MiB", method: "POST", path: "/v1/test", body: `"` + strings.Repeat("x", 1<<20) + `"`, status: 413, code: "too_large"},

		{name: "restart with no active selection", noActive: true, method: "POST", path: "/v1/restart", status: 500, code: "internal", detail: "no active selection"},
		{name: "reload of a corrupt active.json", setup: func(t *testing.T, g *rig) { writeFile(t, g.d.Active(), "{not json") },
			method: "POST", path: "/v1/reload", status: 500, code: "internal"},

		{name: "GET on a POST route", method: "GET", path: "/v1/trial", status: 405},
		{name: "POST on the status route", method: "POST", path: "/v1/status", status: 405},
		{name: "unknown route", method: "GET", path: "/v1/nothing", status: 404},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := newRig(t, nil)
			if !tc.noActive {
				g.active(t, "ok")
			}
			g.boot(t)
			if tc.setup != nil {
				tc.setup(t, g)
			}
			a := newAPI(t, g, nil)

			resp, body := send(t, a.url, tc.method, tc.path, "Bearer "+testToken, tc.body)
			if resp.StatusCode != tc.status {
				t.Fatalf("%s %s = %d (%s), want %d", tc.method, tc.path, resp.StatusCode, strings.TrimSpace(body), tc.status)
			}
			switch {
			case tc.code != "":
				if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", ct)
				}
				code, detail := errorBody(t, body)
				if code != tc.code {
					t.Errorf("error code = %q, want %q", code, tc.code)
				}
				if !strings.Contains(detail, tc.detail) {
					t.Errorf("detail = %q, want it to contain %q", detail, tc.detail)
				}
			case tc.status == 200:
				var st runnerapi.Status
				if err := json.Unmarshal([]byte(body), &st); err != nil || st.State != runnerapi.StateRunning {
					t.Errorf("body %q = %+v, %v; want a running Status", body, st, err)
				}
				if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", ct)
				}
			case tc.status == 204:
				if body != "" {
					t.Errorf("a 204 has the body %q", body)
				}
			case tc.status == 405:
				if resp.Header.Get("Allow") == "" {
					t.Error("a 405 has no Allow header")
				}
			}
			if n := a.calls.Load(); n != 0 {
				t.Errorf("xray api ran %d times, want 0", n)
			}
		})
	}
}
