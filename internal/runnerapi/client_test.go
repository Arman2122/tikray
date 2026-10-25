package runnerapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestClientMapsErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/trial":
			w.WriteHeader(422)
			w.Write([]byte(`{"error":"test_failed","detail":"failed to load config"}`))
		case "/v1/commit":
			w.WriteHeader(409)
			w.Write([]byte(`{"error":"no_trial"}`))
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}
	var tf *TestFailedError
	if err := c.Trial(context.Background()); !errors.As(err, &tf) || tf.Output != "failed to load config" {
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
			Detail:    "bad config",
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
	if want := (XrayAPIResponse{ExitCode: 3, Stdout: "statsquery -s 127.0.0.1:10085", Stderr: "warn"}); got != want {
		t.Errorf("XrayAPI = %+v, want %+v", got, want)
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
	if want := (TestResult{OK: true, Output: "Configuration OK.\n"}); got != want {
		t.Errorf("Test = %+v, want %+v", got, want)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/test" || gotAuth != "Bearer tok" || gotType != "application/json" {
		t.Errorf("request was %s %s with Authorization %q, Content-Type %q", gotMethod, gotPath, gotAuth, gotType)
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
	if want := (TestResult{OK: false, Output: "Failed to start: failed to load config"}); got != want {
		t.Errorf("Test = %+v, want %+v", got, want)
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
