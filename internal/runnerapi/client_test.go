package runnerapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func callRunnerControls(c *Client, t *testing.T) (error, error) {
	t.Helper()
	_, statusErr := c.Status(t.Context())
	_, testErr := c.Test(t.Context(), []byte(`{"outbounds":[{"test_value":"fixture-body"}]}`))
	return statusErr, testErr
}

// ProxyFromEnvironment reads its settings only once in a process. Use a
// fresh test process so this also tests the behavior of a newly started serve.
func TestRunnerControlIgnoresEnvironmentProxy(t *testing.T) {
	const key = "TIKRAY_TEST_PRIVATE_RUNNER_URL"
	if address := os.Getenv(key); address != "" {
		for _, hc := range []*http.Client{nil, {Timeout: 5 * time.Second}, {Transport: http.DefaultTransport.(*http.Transport).Clone()}} {
			control := &Client{BaseURL: address, Token: "fixture-bearer", HTTP: hc}
			statusErr, testErr := callRunnerControls(control, t)
			if statusErr != nil || testErr != nil {
				t.Fatal("direct runner requests failed")
			}
		}
		return
	}
	var proxyCalls, runnerCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer proxy.Close()
	runner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runnerCalls.Add(1)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer runner.Close()
	// Linux resolves 0.0.0.0 locally. Go's automatic loopback exception to
	// HTTP_PROXY would make a 127.0.0.1 fixture pass even on the old client.
	_, port, err := net.SplitHostPort(runner.Listener.Addr().String())
	if err != nil {
		t.Fatal("invalid fixture listener")
	}
	t.Setenv(key, "http://0.0.0.0:"+port)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRunnerControlIgnoresEnvironmentProxy$")
	err = cmd.Run()
	if got := proxyCalls.Load(); got != 0 {
		t.Errorf("the proxy received %d private requests", got)
	}
	if got := runnerCalls.Load(); got != 6 || err != nil {
		t.Errorf("the intended runner received %d of 6 requests", got)
	}
}

func TestRunnerControlRefusesRedirects(t *testing.T) {
	var redirected atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer receiver.Close()
	var location atomic.Value
	location.Store(receiver.URL + "/fixture-location")
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", location.Load().(string))
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = io.WriteString(w, "fixture-response")
	}))
	defer source.Close()
	for _, target := range []string{receiver.URL + "/fixture-location", "/%zz/fixture-location"} {
		location.Store(target)
		for _, hc := range []*http.Client{nil, {Timeout: time.Second}, source.Client()} {
			c := &Client{BaseURL: source.URL, Token: "fixture-bearer", HTTP: hc}
			statusErr, testErr := callRunnerControls(c, t)
			for _, err := range []error{statusErr, testErr} {
				if err == nil || strings.Contains(err.Error(), "fixture-") {
					t.Error("redirect was followed or disclosed private data")
				}
			}
		}
	}
	if n := redirected.Load(); n != 0 {
		t.Errorf("another port received %d private requests", n)
	}
}

func TestClientMapsErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/trial":
			w.WriteHeader(422)
			w.Write([]byte(`{"error":"test_failed","detail":"Failed to start: failed to load config"}`))
		case "/v1/commit":
			w.WriteHeader(409)
			w.Write([]byte(`{"error":"no_trial"}`))
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}
	var tf *TestFailedError
	if err := c.Trial(context.Background()); !errors.As(err, &tf) || tf.Output != "xray failed to load config" {
		t.Errorf("Trial: %v", err)
	}
	if err := c.Commit(context.Background()); !errors.Is(err, ErrNoTrial) {
		t.Errorf("Commit: %v", err)
	}
	c.Token = "wrong"
	if _, err := c.Status(context.Background()); err == nil {
		t.Error("bad token accepted")
	}
}

func TestLongRunnerErrorDoesNotQuoteAPartialCredential(t *testing.T) {
	const prefix = "fixture-part"
	for _, tc := range []struct{ status, limit int }{{500, maxErrText}, {422, maxBody}} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, strings.Repeat("x", tc.limit-len(prefix))+prefix+"-tail")
		}))
		c := &Client{BaseURL: server.URL, Token: "test", HTTP: server.Client()}
		err := c.Trial(t.Context())
		server.Close()
		if err == nil || strings.Contains(err.Error(), prefix) {
			t.Error("a truncated runner error body exposed part of a value")
		}
	}
}

func TestClientErrorBodies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/trial":
			w.WriteHeader(409)
			w.Write([]byte(`{"error":"busy","detail":"a trial is open"}`))
		case "/v1/abort":
			w.WriteHeader(409)
			w.Write([]byte(`{"error":"no_trial"}`))
		case "/v1/restart":
			w.WriteHeader(503)
			w.Write([]byte(`{"error":"no_xray","detail":"no core selected"}`))
		case "/v1/reload":
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"unauthorized"}`))
		case "/v1/commit":
			w.WriteHeader(409) // a 409 whose code is not recognised
			w.Write([]byte(`not json`))
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}
	ctx := context.Background()
	if err := c.Trial(ctx); !errors.Is(err, ErrBusy) || errors.Is(err, ErrNoTrial) {
		t.Errorf("Trial: %v", err)
	}
	if err := c.Abort(ctx); !errors.Is(err, ErrNoTrial) || errors.Is(err, ErrBusy) {
		t.Errorf("Abort: %v", err)
	}
	err := c.Restart(ctx)
	if err == nil || errors.Is(err, ErrBusy) || errors.Is(err, ErrNoTrial) ||
		!strings.Contains(err.Error(), "503") || !strings.Contains(err.Error(), "no_xray") {
		t.Errorf("Restart: %v", err)
	}
	err = c.Reload(ctx)
	if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("Reload: %v", err)
	}
	err = c.Commit(ctx)
	if err == nil || errors.Is(err, ErrBusy) || errors.Is(err, ErrNoTrial) || !strings.Contains(err.Error(), "409") {
		t.Errorf("Commit: %v", err)
	}
}

func TestTestFailedErrorMessage(t *testing.T) {
	err := error(&TestFailedError{Output: "unknown outbound tag"})
	if !strings.Contains(err.Error(), "unknown outbound tag") {
		t.Errorf("Error() = %q", err.Error())
	}
	// A refusal that says what xray rejected is not prefixed with it again.
	err = &TestFailedError{Output: ConfigRefusal("Failed to start: failed to build outbound config with tag srv-deadbeef > VLESS users: \"flow\" doesn't support \"xtls-rprx-direct\"")}
	if got, want := err.Error(), "runnerapi: xray rejected the config: outbound srv-deadbeef: unsupported flow"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestClientStatus(t *testing.T) {
	want := Status{
		State:       StateTrial,
		Active:      &Selection{Core: "26.10.21", Config: "config/" + strings.Repeat("a", 64) + ".json"},
		Candidate:   &Candidate{Selection: Selection{Core: "26.10.22", Geo: "g1", Config: "config/" + strings.Repeat("b", 64) + ".json"}, Deadline: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)},
		XrayPID:     42,
		XrayVersion: "26.10.21",
		RoutesOK:    true,
		GatewayUp:   true,
		LastTrial: &TrialResult{
			Candidate: Candidate{Selection: Selection{Core: "26.10.20", Config: "config/" + strings.Repeat("c", 64) + ".json"}, Deadline: time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)},
			Outcome:   OutcomeRejected,
			Detail:    "xray failed to load config",
			At:        time.Date(2026, 10, 24, 8, 59, 0, 0, time.UTC),
		},
	}
	var gotMethod, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotAuth = r.Method, r.Header.Get("Authorization")
		if r.URL.Path != "/v1/status" {
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}
	got, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Status = %+v, want %+v", got, want)
	}
	if gotMethod != http.MethodGet || gotAuth != "Bearer tok" {
		t.Errorf("request was %s with Authorization %q", gotMethod, gotAuth)
	}
}

func TestStatusWireNames(t *testing.T) {
	b, err := json.Marshal(Status{State: StateEmpty})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"state":"empty","xray_pid":0,"routes_ok":false,"gateway_up":false}`; string(b) != want {
		t.Errorf("Status JSON = %s, want %s", b, want)
	}
}

func TestClientPostRoutes(t *testing.T) {
	got := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got[r.URL.Path] = r.Method
		switch r.URL.Path {
		case "/v1/trial", "/v1/abort":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Write([]byte(`{"ok":true}`)) // a JSON body on a 200 is tolerated too
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL + "/", Token: "tok", HTTP: srv.Client()} // trailing slash must not double up
	ctx := context.Background()
	for name, call := range map[string]func(context.Context) error{
		"/v1/trial": c.Trial, "/v1/commit": c.Commit, "/v1/abort": c.Abort,
		"/v1/restart": c.Restart, "/v1/reload": c.Reload,
	} {
		if err := call(ctx); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if got[name] != http.MethodPost {
			t.Errorf("%s used %q", name, got[name])
		}
	}
}

func TestClientAdopt(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotType, gotBody string
	status, answer := http.StatusNoContent, ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth, gotType = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(status)
		w.Write([]byte(answer))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}
	config := "config/" + strings.Repeat("ab", 32) + ".json"

	if err := c.Adopt(context.Background(), config); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/adopt" || gotAuth != "Bearer tok" || gotType != "application/json" {
		t.Errorf("request was %s %s with expected bearer=%v, Content-Type %q", gotMethod, gotPath, gotAuth == "Bearer tok", gotType)
	}
	if want := `{"config":"` + config + `"}`; gotBody != want {
		t.Errorf("body = %s, want %s", gotBody, want)
	}

	// Every answer the runner gives: only the 409s are sentinels.
	for _, tc := range []struct {
		name     string
		status   int
		body     string
		busy     bool
		noCore   bool
		inError  string
		wantNone bool
	}{
		{name: "204 with no body", status: 204, wantNone: true},
		{name: "200 is tolerated", status: 200, body: `{}`, wantNone: true},
		{name: "busy", status: 409, body: `{"error":"busy"}`, busy: true},
		{name: "busy with detail", status: 409, body: `{"error":"busy","detail":"a trial is open"}`, busy: true, inError: "a trial is open"},
		{name: "no_core", status: 409, body: `{"error":"no_core"}`, noCore: true},
		{name: "no_core with detail", status: 409, body: `{"error":"no_core","detail":"no xray is running"}`, noCore: true, inError: "no xray is running"},
		{name: "a 409 with another code", status: 409, body: `{"error":"other"}`, inError: "409"},
		{name: "a 409 that is not JSON", status: 409, body: `conflict`, inError: "conflict"},
		{name: "bad_request", status: 400, body: `{"error":"bad_request","detail":"runner: invalid config: no such file"}`, inError: "400"},
		{name: "unauthorized", status: 401, body: `{"error":"unauthorized"}`, inError: "401"},
		{name: "internal", status: 500, body: `{"error":"internal","detail":"runner: adopt: disk full"}`, inError: "disk full"},
	} {
		status, answer = tc.status, tc.body
		err := c.Adopt(context.Background(), config)
		if tc.status == 400 && (err == nil || !strings.Contains(err.Error(), "no such file")) {
			t.Error("missing safe config error detail")
		}
		switch {
		case tc.wantNone:
			if err != nil {
				t.Errorf("%s: Adopt = %v, want nil", tc.name, err)
			}
			continue
		case err == nil:
			t.Errorf("%s: Adopt = nil, want an error", tc.name)
			continue
		}
		if errors.Is(err, ErrBusy) != tc.busy || errors.Is(err, ErrNoCore) != tc.noCore {
			t.Errorf("%s: Adopt error %v; errors.Is ErrBusy = %v, ErrNoCore = %v; want %v, %v",
				tc.name, err, errors.Is(err, ErrBusy), errors.Is(err, ErrNoCore), tc.busy, tc.noCore)
		}
		if !strings.Contains(err.Error(), tc.inError) {
			t.Errorf("%s: Adopt error %q, want it to contain %q", tc.name, err, tc.inError)
		}
		if !strings.HasPrefix(err.Error(), "runnerapi:") {
			t.Errorf("%s: Adopt error %q lacks the runnerapi prefix", tc.name, err)
		}
	}
}

func TestClientXrayAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req XrayAPIRequest
		if r.Method != http.MethodPost || r.URL.Path != "/v1/xray-api" || r.Header.Get("Authorization") != "Bearer tok" ||
			json.NewDecoder(r.Body).Decode(&req) != nil {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(XrayAPIResponse{ExitCode: 3, Stdout: strings.Join(req.Args, " "), Stderr: "warn"})
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}
	got, err := c.XrayAPI(context.Background(), "statsquery", "-s", "127.0.0.1:10085")
	if err != nil {
		t.Fatal(err)
	}
	if got != (XrayAPIResponse{ExitCode: 3}) {
		t.Error("a failed command should expose its exit code only")
	}
}

func TestOldRunnerCommandOutputRemainsPrivate(t *testing.T) {
	const marker = "fixture-private-fragment"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(XrayAPIResponse{Stdout: `{"outbounds":[{"tag":"srv-bbbbbbbb","opaque":"` + marker + `"}]}`, Stderr: marker})
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "test", HTTP: srv.Client()}
	for _, cmd := range []string{"lso", "ado", "lsi"} {
		got, err := c.XrayAPI(t.Context(), cmd)
		if err != nil || strings.Contains(got.Stdout+got.Stderr, marker) || (cmd == "lso" && !strings.Contains(got.Stdout, "srv-bbbbbbbb")) {
			t.Errorf("%s exposed an old runner's command output or lost the public tag", cmd)
		}
	}
}

func TestClientXrayAPIWithNoArgsSendsEmptyList(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw json.RawMessage
		json.NewDecoder(r.Body).Decode(&raw)
		body = string(raw)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}
	if _, err := c.XrayAPI(context.Background()); err != nil {
		t.Fatal(err)
	}
	if body != `{"args":[]}` {
		t.Errorf("body = %s, want {\"args\":[]}", body)
	}
}

func TestClientDefaultHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "tok"}
	if err := c.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestClientHonoursContext(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	c := &Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Status(ctx); err == nil {
		t.Error("Status returned no error on an expired context")
	}
}

func TestClientTest(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotType, gotBody string
	answer := `{"ok":true,"output":"Configuration OK.\n"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth, gotType = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Write([]byte(answer))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}

	// The config goes as it is, not re-encoded.
	config := "{ \"outbounds\": [ {\"protocol\": \"freedom\"} ] }\n"
	got, err := c.Test(context.Background(), []byte(config))
	if err != nil {
		t.Fatal(err)
	}
	if want := (TestResult{OK: true, Output: "Configuration OK."}); got != want {
		t.Errorf("Test = %+v, want %+v", got, want)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/test" || gotAuth != "Bearer tok" || gotType != "application/json" {
		t.Errorf("request was %s %s with expected bearer=%v, Content-Type %q", gotMethod, gotPath, gotAuth == "Bearer tok", gotType)
	}
	if gotBody != config {
		t.Errorf("body = %q, want the config %q as it is", gotBody, config)
	}

	// A rejection is an answer, not an error.
	answer = `{"ok":false,"output":"Failed to start: failed to load config"}`
	got, err = c.Test(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatalf("Test of a rejected config: %v", err)
	}
	if want := (TestResult{OK: false, Output: "xray failed to load config"}); got != want {
		t.Errorf("Test = %+v, want %+v", got, want)
	}
}

func TestOldRunnerFailedCommandDoesNotEchoResponse(t *testing.T) {
	const marker = "fixture-private-fragment"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errBody{Error: "internal", Detail: "config contains " + marker})
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "test", HTTP: srv.Client()}
	_, testErr := c.Test(t.Context(), []byte("{}"))
	_, apiErr := c.XrayAPI(t.Context(), "ado")
	for _, err := range []error{testErr, apiErr, c.Trial(t.Context())} {
		if err == nil || strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), "500") {
			t.Error("an unsuccessful runner operation should expose its status without its body")
		}
	}
}

func TestOldRunnerRejectionsCannotEchoOpaqueConfig(t *testing.T) {
	const marker = "fixture-private-fragment"
	for _, ok := range []bool{false, true} {
		res := TestResult{OK: ok, Output: "worker echoed " + marker}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/test":
				json.NewEncoder(w).Encode(res)
			case "/v1/trial":
				w.WriteHeader(422)
				json.NewEncoder(w).Encode(errBody{Error: "test_failed", Detail: res.Output})
			case "/v1/status":
				json.NewEncoder(w).Encode(Status{LastTrial: &TrialResult{Outcome: OutcomeRejected, Detail: res.Output}})
			}
		}))
		c := &Client{BaseURL: srv.URL, Token: "test", HTTP: srv.Client()}
		got, err := c.Test(t.Context(), []byte(`{"outbounds":[{"protocol":"future"}]}`))
		switch {
		case ok && (err != nil || !got.OK || strings.Contains(got.Output, marker)):
			t.Error("old runner test answer exposed a private fragment or lost its verdict")
		case !ok && (err == nil || strings.Contains(err.Error(), marker)):
			// No xray refusal in its words: an error, never a verdict.
			t.Error("old runner's unknown failure became a verdict or exposed a private fragment")
		}
		var tf *TestFailedError
		if err := c.Trial(t.Context()); !errors.As(err, &tf) || strings.Contains(err.Error(), marker) {
			t.Error("old runner trial rejection exposed a private fragment or lost its type")
		}
		st, err := c.Status(t.Context())
		if err != nil || st.LastTrial == nil || strings.Contains(st.LastTrial.Detail, marker) {
			t.Error("old runner last trial exposed a private fragment")
		}
		srv.Close()
	}
}

func TestClientTestOlderRunnerTimeout(t *testing.T) {
	const partial = "untrusted process output"
	for _, tc := range []struct {
		name    string
		result  TestResult
		timeout bool
	}{
		{"timeout", TestResult{Output: "xray run -test did not finish within 20s\n" + partial}, true},
		{"short timeout", TestResult{Output: "xray run -test did not finish within 100ms\n"}, true},
		{"accepted config", TestResult{OK: true, Output: "xray run -test did not finish within 20s\n"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(tc.result)
			}))
			defer srv.Close()
			c := &Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}
			res, err := c.Test(t.Context(), []byte(`{}`))
			if tc.timeout {
				if !errors.Is(err, context.DeadlineExceeded) || res != (TestResult{}) || strings.Contains(err.Error(), partial) {
					t.Error("a legacy timeout should give a deadline error without the incomplete output")
				}
			} else if err != nil || res.OK != tc.result.OK || strings.Contains(res.Output, partial) {
				t.Error("the completed verdict should be preserved without carrying child output")
			}
		})
	}
}

func TestClientTestErrors(t *testing.T) {
	answers := map[string]struct {
		status int
		body   string
	}{
		"/no_core":        {409, `{"error":"no_core"}`},
		"/no_core-detail": {409, `{"error":"no_core","detail":"no xray is running"}`},
		"/too_large":      {413, `{"error":"too_large","detail":"the config is over 1 MiB"}`},
		"/bad_request":    {400, `{"error":"bad_request","detail":"the config is not JSON"}`},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The case is the base URL's path, before /v1/test.
		a := answers[strings.TrimSuffix(r.URL.Path, "/v1/test")]
		w.WriteHeader(a.status)
		w.Write([]byte(a.body))
	}))
	defer srv.Close()
	for _, tc := range []struct {
		name    string
		noCore  bool
		inError string
	}{
		{name: "no_core", noCore: true},
		{name: "no_core-detail", noCore: true, inError: "no xray is running"},
		{name: "too_large", inError: "413"},
		{name: "bad_request", inError: "400"},
	} {
		c := &Client{BaseURL: srv.URL + "/" + tc.name, Token: "tok", HTTP: srv.Client()}
		res, err := c.Test(context.Background(), []byte(`{}`))
		if err == nil {
			t.Errorf("%s: Test = %+v, nil; want an error", tc.name, res)
			continue
		}
		if errors.Is(err, ErrNoCore) != tc.noCore || errors.Is(err, ErrBusy) || errors.Is(err, ErrNoTrial) {
			t.Errorf("%s: Test error %v; errors.Is ErrNoCore = %v, want %v", tc.name, err, errors.Is(err, ErrNoCore), tc.noCore)
		}
		if !strings.Contains(err.Error(), tc.inError) {
			t.Errorf("%s: Test error %q, want it to contain %q", tc.name, err, tc.inError)
		}
	}
}

func TestClientTestDefaultHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true,"output":""}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "tok"}
	if res, err := c.Test(context.Background(), []byte(`{}`)); err != nil || !res.OK {
		t.Fatalf("Test with the default HTTP client = %+v, %v", res, err)
	}
	// The runner bounds xray run -test at 20 s; the default client must
	// wait for it.
	if testHTTP.Timeout <= 20*time.Second {
		t.Errorf("the default client for Test times out after %v, before the runner's 20 s bound", testHTTP.Timeout)
	}
}

func TestTestResultWireNames(t *testing.T) {
	b, err := json.Marshal(TestResult{OK: true, Output: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"ok":true,"output":"x"}`; string(b) != want {
		t.Errorf("TestResult JSON = %s, want %s", b, want)
	}
}

// A TokenFunc makes the token of each request, so that a client can wait for a
// runner that has not made its token yet, and a copy of the client keeps it.
func TestClientTokenFunc(t *testing.T) {
	var auths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auths = append(auths, r.Header.Get("Authorization"))
		io.WriteString(w, `{"state":"empty"}`)
	}))
	defer srv.Close()

	token, failure := "first", error(nil)
	c := &Client{BaseURL: srv.URL, Token: "ignored", TokenFunc: func(ctx context.Context) (string, error) { return token, failure }}
	ctx := context.Background()
	if _, err := c.Status(ctx); err != nil {
		t.Fatal(err)
	}
	token = "second"
	cc := *c // a copy, as artifacts' withTimeout makes
	cc.HTTP = &http.Client{Timeout: time.Minute}
	if _, err := cc.Status(ctx); err != nil {
		t.Fatal(err)
	}
	if want := []string{"Bearer first", "Bearer second"}; !reflect.DeepEqual(auths, want) {
		t.Errorf("Authorization headers %q, want %q", auths, want)
	}

	// A token that can't be had ends the call before it is sent, with the cause.
	failure = errors.New("waiting for the runner token")
	if _, err := c.Status(ctx); !errors.Is(err, failure) || !strings.Contains(err.Error(), "GET /v1/status") {
		t.Errorf("error %v, want one that wraps the token's and names the call", err)
	}
	for _, call := range []func() error{
		func() error { return c.Trial(ctx) },
		func() error { _, err := c.Test(ctx, []byte("{}")); return err },
		func() error { _, err := c.XrayAPI(ctx, "statssys"); return err },
	} {
		if err := call(); !errors.Is(err, failure) {
			t.Errorf("error %v, want the token's", err)
		}
	}
	if len(auths) != 2 {
		t.Errorf("%d requests reached the runner, want the two with a token", len(auths))
	}
}

// Unauthorized hears of every 401, with the token the refused request sent,
// so that a TokenFunc that keeps its token can drop it. Other answers, and a
// call that sent nothing, are not its business.
func TestClientUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good" {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"unauthorized"}`)
			return
		}
		io.WriteString(w, `{"state":"empty"}`)
	}))
	defer srv.Close()

	var refused []string
	token, failure := "good", error(nil)
	c := &Client{BaseURL: srv.URL, TokenFunc: func(ctx context.Context) (string, error) { return token, failure },
		Unauthorized: func(tok string) { refused = append(refused, tok) }}
	ctx := context.Background()
	if _, err := c.Status(ctx); err != nil {
		t.Fatal(err)
	}
	token = "stale"
	if _, err := c.Status(ctx); err == nil {
		t.Fatal("Status with a token the runner refuses: no error")
	}
	if err := c.Trial(ctx); err == nil {
		t.Fatal("Trial with a token the runner refuses: no error")
	}
	failure = errors.New("no token")
	if _, err := c.Status(ctx); err == nil {
		t.Fatal("Status without a token: no error")
	}
	if want := []string{"stale", "stale"}; !reflect.DeepEqual(refused, want) {
		t.Errorf("Unauthorized heard of %q, want %q", refused, want)
	}
}

// A runner reports a test that ended without xray's verdict as an error in
// fixed words. The client passes those on, and nothing else a runner says.
func TestClientPassesOnRunnerTestErrors(t *testing.T) {
	for _, tc := range []struct {
		detail string
		passed bool
	}{
		{"xray was killed by a signal (SIGKILL)", true},
		{"xray was killed by a signal", true},
		{"xray exited with status 2", true},
		{"staging the core failed: no space left on device", true},
		{"staging the core failed", true},
		{"xray could not be started: exec format error", true},
		{"preparing the test config failed: read-only file system", true},
		{"xray config test did not finish within 20s", true},
		{"xray config test did not finish within the trial's 1m30s", true},
		{"runner: stage core 26.10.21: open /data/cores/26.10.21/xray: no such file or directory", false},
		{"staging the core failed: open /data/cores/26.10.21/xray", false},
		{"staging the core failed: fixture-private-fragment", false},
		{"xray exited with status 2: fixture-private-fragment", false},
		{"xray was killed by a signal (fixture-private-fragment)", false},
		{"xray exited with status 23", false}, // that is a verdict, not an error
		{"xray exited with status 0", false},
		{"xray config test did not finish within fixture-private-fragment", false},
	} {
		t.Run(tc.detail, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(errBody{Error: "internal", Detail: tc.detail})
			}))
			defer srv.Close()
			c := &Client{BaseURL: srv.URL, Token: "test", HTTP: srv.Client()}
			_, testErr := c.Test(t.Context(), []byte(`{}`))
			for name, err := range map[string]error{"Test": testErr, "Trial": c.Trial(t.Context())} {
				var tf *TestFailedError
				if err == nil || errors.As(err, &tf) || !strings.Contains(err.Error(), "HTTP 500") {
					t.Fatalf("%s = %v; want an HTTP 500 runner error", name, err)
				}
				if got := strings.Contains(err.Error(), tc.detail); got != tc.passed {
					t.Errorf("%s = %q; detail passed on = %v, want %v", name, err, got, tc.passed)
				}
				if strings.Contains(err.Error(), "fixture-private-fragment") || strings.Contains(err.Error(), "/data/") {
					t.Errorf("%s = %q repeats what the runner said", name, err)
				}
			}
			if !tc.passed && PublicTestError(tc.detail) {
				t.Errorf("PublicTestError(%q) = true", tc.detail)
			}
		})
	}
}

// An older runner reported any test that failed, for whatever reason, as a
// refusal with what xray printed. Only xray's own words of a refusal ("Failed
// to start:", an outbound it could not build, a known diagnostic) make that a
// refusal of the config: anything else gets neutral words, and a cut output
// never gives its last, partial line.
func TestPublicRefusalNeverGuessesAConfigVerdict(t *testing.T) {
	const private = "fixture-private-fragment"
	for _, tc := range []struct{ name, text, want string }{
		{"empty", "", ""},
		{"blank", " \n", ""},
		{"xray's refusal", "Xray 26.1.18 (Xray, Penetrates Everything.)\nFailed to start: main: failed to load config files: [/x] > " + private, "xray failed to load config"},
		{"an outbound xray could not build", "infra/conf: failed to build outbound config with tag srv-0123abcd > " + private, "outbound srv-0123abcd: xray failed to load config"},
		{"a known diagnostic", "Failed to start: unknown user " + private, "unknown user"},
		{"a known diagnostic without the marker", "infra/conf: bad user " + private, "the runner reported an error"},
		{"unknown words", "worker echoed " + private, "the runner reported an error"},
		{"a killed test", "runner: xray run -test: signal: killed", "the runner reported an error"},
		{"a partial diagnostic", "partial diagnostic\n" + private, "the runner reported an error"},
		{"a stage failure", "runner: stage core 26.10.21: open /data/cores/26.10.21/xray: no such file or directory", "the runner reported an error"},
		{"a lone truncation mark", TestOutputTruncated, "the runner reported an error"},
		{"a cut refusal", "Failed to start: main: failed to load config files\n" + strings.Repeat("x", 40) + "\n" + private + TestOutputTruncated, "xray failed to load config"},
		{"a cut diagnostic", "unknown user " + private + TestOutputTruncated, "the runner reported an error"},
		{"the previous verdict", "xray failed to load config (exit 23)", "xray failed to load config (exit 23)"},
		{"the previous verdict for a crash", "xray failed to load config (exit 2)", "xray exited with status 2"},
		{"the previous timeout", "xray run -test did not finish within the trial's 2m0s\n" + private, "xray config test did not finish"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := publicRefusal(tc.text); got != tc.want {
				t.Errorf("publicRefusal(%q) = %q, want %q", tc.text, got, tc.want)
			}
			if got := publicRefusal(tc.want); got != tc.want {
				t.Errorf("publicRefusal(%q) = %q; want its own texts kept", tc.want, got)
			}
		})
	}
}

// An older runner reported any test that failed as a refusal: a killed or
// crashed test, a core it could not stage, an empty output. Only xray's own
// words of a refusal ("Failed to start:", or the exit status 23 the previous
// runner named) condemn the servers in a config; anything else is an error,
// so that a good server is never disabled for the runner's fault.
func TestClientTestOlderRunnerNonVerdicts(t *testing.T) {
	const private = "fixture-private-fragment"
	for _, tc := range []struct {
		name, output string
		verdict      string // "" when the answer must be an error
	}{
		{"empty", "", ""},
		{"exit 2", "xray failed to load config (exit 2)", ""},
		{"killed", "runner: xray run -test: signal: killed " + private, ""},
		{"a panic with a rule's words", "panic: invalid user " + private + "\ngoroutine 1 [running]:", ""},
		{"a warning alone", `[Warning] "allowInsecure" is deprecated ` + private, ""},
		{"similar words", "xray run -test did not finish within this release\n", ""},
		{"exit 23", "xray failed to load config (exit 23)", "xray failed to load config"},
		{"xray's refusal", "Failed to start: main: failed to load config files: [/c.json] > infra/conf: failed to build outbound config with tag srv-0000000a > infra/conf: VLESS users: \"flow\" doesn't support \"xtls-rprx-direct\" in this version " + private, "srv-0000000a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(TestResult{Output: tc.output})
			}))
			defer srv.Close()
			c := &Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}
			res, err := c.Test(t.Context(), []byte(`{}`))
			switch {
			case tc.verdict == "" && (err == nil || res != (TestResult{})):
				t.Errorf("Test = %+v, %v; want an error, not a verdict", res, err)
			case tc.verdict != "" && (err != nil || res.OK || !strings.Contains(res.Output, tc.verdict)):
				t.Errorf("Test = %+v, %v; want a refusal naming %q", res, err, tc.verdict)
			case err != nil && strings.Contains(err.Error(), private), strings.Contains(res.Output, private):
				t.Error("the runner's output leaked into the result")
			}
		})
	}
}
