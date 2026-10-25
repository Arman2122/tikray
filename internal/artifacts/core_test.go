package artifacts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

// t0 is the updater's clock in these tests.
var t0 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

const (
	runnerToken      = "tok"
	testAsset        = "Xray-linux-64.zip" // the asset for Arch amd64
	activeConfigBody = `{"inbounds":[]}` + "\n"
)

// fakeRunner serves the runner's control API the way the real runner does,
// from a state the test scripts, and records the calls it gets.
type fakeRunner struct {
	t   *testing.T
	run string // the data root's run directory
	srv *httptest.Server

	mu    sync.Mutex
	st    runnerapi.Status
	calls []string
	cands []runnerapi.Candidate // candidate.json as each trial request found it
	delay map[string]time.Duration
	// Hooks run with mu held, before the route's own behaviour; a hook that
	// returns true has answered the request.
	onTrial   func(w http.ResponseWriter, c runnerapi.Candidate) bool
	onCommit  func(w http.ResponseWriter) bool
	onStatus  func()
	onXrayAPI func(w http.ResponseWriter, args []string)
}

func newFakeRunner(t *testing.T, run string, active *runnerapi.Selection) *fakeRunner {
	t.Helper()
	f := &fakeRunner{t: t, run: run, delay: map[string]time.Duration{}}
	f.st = runnerapi.Status{State: runnerapi.StateEmpty}
	if active != nil {
		a := *active
		f.st = runnerapi.Status{State: runnerapi.StateRunning, Active: &a, XrayPID: 42, RoutesOK: true, GatewayUp: true}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", f.handleStatus)
	mux.HandleFunc("POST /v1/trial", f.handleTrial)
	mux.HandleFunc("POST /v1/commit", f.handleCommit)
	mux.HandleFunc("POST /v1/abort", f.handleAbort)
	mux.HandleFunc("POST /v1/xray-api", f.handleXrayAPI)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+runnerToken {
			fakeError(w, http.StatusUnauthorized, "unauthorized", "")
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRunner) client() *runnerapi.Client {
	return &runnerapi.Client{BaseURL: f.srv.URL, Token: runnerToken, HTTP: f.srv.Client()}
}

// script changes the fake's state or hooks while it may be serving.
func (f *fakeRunner) script(fn func(f *fakeRunner)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// enter records the call and waits the route's scripted delay.
func (f *fakeRunner) enter(route string) {
	f.mu.Lock()
	d := f.delay[route]
	f.mu.Unlock()
	time.Sleep(d)
	f.mu.Lock()
	f.calls = append(f.calls, route)
}

func (f *fakeRunner) handleStatus(w http.ResponseWriter, r *http.Request) {
	f.enter("status")
	defer f.mu.Unlock()
	if f.onStatus != nil {
		f.onStatus()
	}
	writeJSONReply(w, http.StatusOK, f.st)
}

func (f *fakeRunner) handleTrial(w http.ResponseWriter, r *http.Request) {
	f.enter("trial")
	defer f.mu.Unlock()
	path := filepath.Join(f.run, "candidate.json")
	var c runnerapi.Candidate
	raw, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(raw, &c)
	}
	if err == nil {
		err = c.Validate()
	}
	if err != nil {
		f.t.Errorf("trial: candidate.json: %v", err)
		fakeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm() != 0o644 {
		f.t.Errorf("candidate.json mode %v, want 0644", fi.Mode().Perm())
	}
	f.cands = append(f.cands, c)
	if f.onTrial != nil && f.onTrial(w, c) {
		return
	}
	if f.st.State == runnerapi.StateTrial {
		fakeError(w, http.StatusConflict, "busy", "")
		return
	}
	f.st.State, f.st.Candidate = runnerapi.StateTrial, &c
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeRunner) handleCommit(w http.ResponseWriter, r *http.Request) {
	f.enter("commit")
	defer f.mu.Unlock()
	if f.onCommit != nil && f.onCommit(w) {
		return
	}
	if f.st.State != runnerapi.StateTrial {
		fakeError(w, http.StatusConflict, "no_trial", "")
		return
	}
	f.end(runnerapi.OutcomeCommitted, "")
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeRunner) handleAbort(w http.ResponseWriter, r *http.Request) {
	f.enter("abort")
	defer f.mu.Unlock()
	if f.st.State != runnerapi.StateTrial {
		fakeError(w, http.StatusConflict, "no_trial", "")
		return
	}
	f.end(runnerapi.OutcomeAborted, "")
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeRunner) handleXrayAPI(w http.ResponseWriter, r *http.Request) {
	var in runnerapi.XrayAPIRequest
	err := json.NewDecoder(r.Body).Decode(&in)
	f.enter("xray-api")
	defer f.mu.Unlock()
	if err != nil {
		fakeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if f.onXrayAPI != nil {
		f.onXrayAPI(w, in.Args)
		return
	}
	writeJSONReply(w, http.StatusOK, runnerapi.XrayAPIResponse{})
}

// end closes the open trial with outcome as the runner does: a commit makes
// the candidate active, anything else reverts. mu must be held.
func (f *fakeRunner) end(outcome, detail string) {
	c := *f.st.Candidate
	if outcome == runnerapi.OutcomeCommitted {
		sel := c.Selection
		f.st.Active = &sel
	}
	f.st.State, f.st.Candidate = runnerapi.StateRunning, nil
	f.st.LastTrial = &runnerapi.TrialResult{Candidate: c, Outcome: outcome, Detail: detail, At: t0}
	os.Remove(filepath.Join(f.run, "candidate.json"))
}

// actions returns the calls other than status, in order.
func (f *fakeRunner) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for _, c := range f.calls {
		if c != "status" {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeRunner) allCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.calls...)
}

func (f *fakeRunner) candidates() []runnerapi.Candidate {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]runnerapi.Candidate(nil), f.cands...)
}

func (f *fakeRunner) activeCore() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.st.Active == nil {
		return ""
	}
	return f.st.Active.Core
}

func fakeError(w http.ResponseWriter, code int, errCode, detail string) {
	writeJSONReply(w, code, map[string]string{"error": errCode, "detail": detail})
}

func writeJSONReply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// fakeReleases is an upstream release server that records the paths asked for.
type fakeReleases struct {
	srv    *httptest.Server
	mu     sync.Mutex
	files  map[string][]byte
	latest string
	hits   []string
}

func newFakeReleases(t *testing.T) *fakeReleases {
	t.Helper()
	f := &fakeReleases{files: map[string][]byte{}}
	f.srv = serve(t, func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits = append(f.hits, r.URL.Path)
		if r.URL.Path == "/releases/latest" && f.latest != "" {
			http.Redirect(w, r, "/releases/tag/v"+f.latest, http.StatusFound)
			return
		}
		b, ok := f.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	})
	return f
}

func assetPath(ver string) string { return "/releases/download/v" + ver + "/" + testAsset }

// add publishes a release of ver with its .dgst and returns the zip's SHA-256.
func (f *fakeReleases) add(t *testing.T, ver string) string {
	t.Helper()
	zip := releaseBytes(t, "bin-"+ver)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[assetPath(ver)] = zip
	f.files[assetPath(ver)+".dgst"] = []byte(dgstBody(shaOf(string(zip))))
	return shaOf(string(zip))
}

// addZipOnly publishes a release of ver without a .dgst and returns the zip's SHA-256.
func (f *fakeReleases) addZipOnly(t *testing.T, ver string) string {
	t.Helper()
	zip := releaseBytes(t, "bin-"+ver)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[assetPath(ver)] = zip
	return shaOf(string(zip))
}

// take removes a file from the server and returns it.
func (f *fakeReleases) take(path string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := f.files[path]
	delete(f.files, path)
	return b
}

func (f *fakeReleases) setLatest(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.latest = v
}

func (f *fakeReleases) hitList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.hits...)
}

// releaseBytes is a release zip whose xray holds bin.
func releaseBytes(t *testing.T, bin string) []byte {
	t.Helper()
	b, err := os.ReadFile(releaseZip(t, bin))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// stubHealth passes, or answers with fn, which gets the 1-based call number.
type stubHealth struct {
	n  atomic.Int32
	fn func(call int) error
}

func (s *stubHealth) Check(ctx context.Context) error {
	n := int(s.n.Add(1))
	if s.fn == nil {
		return nil
	}
	return s.fn(n)
}

// coreEnv is a data root whose runner runs an active core, and an updater for it.
type coreEnv struct {
	data, tmp string
	activeSel runnerapi.Selection
	runner    *fakeRunner
	rel       *fakeReleases
	health    *stubHealth
	u         *CoreUpdater
}

// newCoreEnv sets up a data root where the runner runs core active with geo
// g1 and a config (an empty runner when active is ""), and an updater that
// fetches and verifies from a fake upstream. TMPDIR is an empty directory of
// its own, so that a test can see what an update leaves there.
func newCoreEnv(t *testing.T, active string) *coreEnv {
	t.Helper()
	// The first TempDir call fixes where all of this test's TempDirs go, so
	// the TMPDIR set below holds only what the code under test leaves.
	e := &coreEnv{data: t.TempDir(), tmp: t.TempDir()}
	t.Setenv("TMPDIR", e.tmp)
	if err := os.MkdirAll(filepath.Join(e.data, "run", "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	var sel *runnerapi.Selection
	if active != "" {
		install(t, e.cores(), active)
		e.activeSel = runnerapi.Selection{Core: active, Geo: "g1", Config: "config/" + shaOf(activeConfigBody) + ".json"}
		if err := os.WriteFile(filepath.Join(e.data, "run", e.activeSel.Config), []byte(activeConfigBody), 0o644); err != nil {
			t.Fatal(err)
		}
		sel = &e.activeSel
	}
	e.runner = newFakeRunner(t, filepath.Join(e.data, "run"), sel)
	e.rel = newFakeReleases(t)
	e.health = &stubHealth{}
	up := Direct(e.rel.srv.URL, e.rel.srv.Client())
	e.u = &CoreUpdater{
		Data:  e.data,
		Arch:  "amd64",
		Fetch: Chain{Sources: []Source{up}},
		// Upstream holds only direct (and proxy) sources, never a mirror or the inbox.
		Verify:       Verifier{Upstream: Chain{Sources: []Source{up}}},
		Runner:       e.runner.client(),
		Health:       e.health,
		EarlyExit:    10 * time.Millisecond,
		HealthWindow: 200 * time.Millisecond,
		Now:          func() time.Time { return t0 },
	}
	return e
}

func (e *coreEnv) cores() string { return filepath.Join(e.data, "cores") }

func (e *coreEnv) slots(t *testing.T) []string {
	t.Helper()
	slots, err := ListCores(e.cores())
	if err != nil {
		t.Fatal(err)
	}
	return versions(slots)
}

func (e *coreEnv) meta(t *testing.T, ver string) Meta {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(e.cores(), ver, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Meta
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// wantClean fails unless TMPDIR is empty and cores/ holds no temporary install.
func (e *coreEnv) wantClean(t *testing.T) {
	t.Helper()
	if got := dirNames(t, e.tmp); len(got) != 0 {
		t.Errorf("TMPDIR holds %v, want nothing", got)
	}
	for _, n := range dirNames(t, e.cores()) {
		if strings.HasPrefix(n, ".tmp-") {
			t.Errorf("cores/ holds the temporary install %s", n)
		}
	}
}

func (e *coreEnv) history(t *testing.T) []Result {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(e.data, "state", "core-history.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []Result
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		var r Result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("history line %q: %v", line, err)
		}
		out = append(out, r)
	}
	return out
}

// writeHistory records rs as earlier updates.
func (e *coreEnv) writeHistory(t *testing.T, rs ...Result) {
	t.Helper()
	state := filepath.Join(e.data, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, r := range rs {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(append(line, '\n'))
	}
	if err := os.WriteFile(filepath.Join(state, "core-history.jsonl"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func committedResult(to, from string) Result {
	return Result{From: from, To: to, Outcome: runnerapi.OutcomeCommitted, At: t0.Add(-time.Hour)}
}

func writeConfigFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func wantResult(t *testing.T, got, want Result) {
	t.Helper()
	if !got.At.Equal(want.At) {
		t.Errorf("Result.At = %v, want %v", got.At, want.At)
	}
	got.At, want.At = time.Time{}, time.Time{}
	if got != want {
		t.Errorf("Result = %+v\nwant     %+v", got, want)
	}
}

func wantActions(t *testing.T, f *fakeRunner, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if got := f.actions(); !reflect.DeepEqual(got, want) {
		t.Errorf("runner actions = %v, want %v", got, want)
	}
}

func wantCandidate(t *testing.T, f *fakeRunner, want runnerapi.Candidate) {
	t.Helper()
	cands := f.candidates()
	if len(cands) != 1 {
		t.Fatalf("the runner saw %d trials, want 1", len(cands))
	}
	if c := cands[0]; c.Selection != want.Selection || !c.Deadline.Equal(want.Deadline) {
		t.Errorf("candidate.json = %+v, want %+v", c, want)
	}
}

func wantOutcome(t *testing.T, res Result, err error, outcome string) {
	t.Helper()
	if res.Outcome != outcome {
		t.Fatalf("Outcome = %q (%+v, err %v), want %q", res.Outcome, res, err, outcome)
	}
	failed := outcome != runnerapi.OutcomeCommitted && outcome != OutcomeNoop
	if failed != (err != nil) {
		t.Errorf("err = %v for outcome %s", err, outcome)
	}
}

func wantDetail(t *testing.T, res Result, sub string) {
	t.Helper()
	if !strings.Contains(res.Detail, sub) {
		t.Errorf("Detail = %q, want it to contain %q", res.Detail, sub)
	}
}

// tryLock takes the artifacts lock the way another process would; ok is
// false when someone holds it.
func tryLock(t *testing.T, data string) (release func(), ok bool) {
	t.Helper()
	state := filepath.Join(data, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(state, "artifacts.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			t.Fatal(err)
		}
		return nil, false
	}
	return func() { f.Close() }, true
}

var bg = context.Background()

func TestUpdateCommits(t *testing.T) {
	e := newCoreEnv(t, "26.3.27")
	sum := e.rel.add(t, "26.10.21")

	res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
	wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
	want := Result{From: "26.3.27", To: "26.10.21", Outcome: "committed", Source: "direct", Verified: "dgst", At: t0}
	wantResult(t, res, want)
	wantActions(t, e.runner, "trial", "commit")
	wantCandidate(t, e.runner, runnerapi.Candidate{
		Selection: runnerapi.Selection{Core: "26.10.21", Geo: "g1", Config: e.activeSel.Config},
		Deadline:  t0.Add(120 * time.Second),
	})
	if e.health.n.Load() == 0 {
		t.Error("the health check never ran")
	}
	if got := e.runner.activeCore(); got != "26.10.21" {
		t.Errorf("runner's active core = %q", got)
	}

	h := e.history(t)
	if len(h) != 1 {
		t.Fatalf("history has %d lines, want 1", len(h))
	}
	wantResult(t, h[0], want)
	if fi, err := os.Stat(filepath.Join(e.data, "state")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("state/ = %v, %v; want mode 0700", fi, err)
	}

	m := e.meta(t, "26.10.21")
	if m.Source != "direct" || m.ZipSHA256 != sum || m.Verified != "dgst" || !m.InstalledAt.Equal(t0) {
		t.Errorf("meta.json = %+v, want source direct, zip %s, verified dgst, installed at t0", m, sum)
	}
	if got := e.slots(t); !reflect.DeepEqual(got, []string{"26.10.21", "26.3.27"}) {
		t.Errorf("slots = %v", got)
	}
	e.wantClean(t)
}

func TestUpdateLatest(t *testing.T) {
	e := newCoreEnv(t, "26.3.27")
	e.rel.add(t, "26.10.21")
	e.rel.setLatest("26.10.21")

	res, err := e.u.Update(bg, "latest", UpdateOptions{})
	wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
	if res.To != "26.10.21" {
		t.Errorf("To = %q, want the latest release 26.10.21", res.To)
	}
}

func TestUpdateRejected(t *testing.T) {
	e := newCoreEnv(t, "26.3.27")
	e.rel.add(t, "26.10.21")
	e.runner.script(func(f *fakeRunner) {
		f.onTrial = func(w http.ResponseWriter, c runnerapi.Candidate) bool {
			fakeError(w, http.StatusUnprocessableEntity, "test_failed", "Failed to start: bad config")
			return true
		}
	})

	res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
	wantOutcome(t, res, err, runnerapi.OutcomeRejected)
	if res.Detail != "Failed to start: bad config" {
		t.Errorf("Detail = %q, want xray's output", res.Detail)
	}
	var tf *runnerapi.TestFailedError
	if !errors.As(err, &tf) {
		t.Errorf("err = %v, want a *TestFailedError", err)
	}
	wantActions(t, e.runner, "trial")
	if n := e.health.n.Load(); n != 0 {
		t.Errorf("health checked %d times", n)
	}
	if h := e.history(t); len(h) != 1 || h[0].Outcome != runnerapi.OutcomeRejected {
		t.Errorf("history = %+v", h)
	}
}

func TestUpdateUnhealthy(t *testing.T) {
	e := newCoreEnv(t, "26.3.27")
	e.rel.add(t, "26.10.21")
	e.health.fn = func(int) error { return errors.New("probe: connection refused") }

	res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
	wantOutcome(t, res, err, OutcomeUnhealthy)
	wantDetail(t, res, "probe: connection refused")
	wantActions(t, e.runner, "trial", "abort")
	if n := e.health.n.Load(); n < 2 {
		t.Errorf("health checked %d times, want retries", n)
	}
	if got := e.runner.activeCore(); got != "26.3.27" {
		t.Errorf("runner's active core = %q, want 26.3.27", got)
	}
}

func TestUpdateRefusesOld(t *testing.T) {
	e := newCoreEnv(t, "26.3.27")
	e.rel.add(t, "26.1.0")

	res, err := e.u.Update(bg, "26.1.0", UpdateOptions{})
	wantOutcome(t, res, err, OutcomeRefused)
	wantDetail(t, res, "26.1.18")
	if res.To != "26.1.0" {
		t.Errorf("To = %q", res.To)
	}
	if hits := e.rel.hitList(); len(hits) != 0 {
		t.Errorf("upstream was asked for %v", hits)
	}
	if calls := e.runner.allCalls(); len(calls) != 0 {
		t.Errorf("the runner got %v", calls)
	}
	if got := e.slots(t); !reflect.DeepEqual(got, []string{"26.3.27"}) {
		t.Errorf("slots = %v", got)
	}
	if h := e.history(t); len(h) != 1 || h[0].Outcome != OutcomeRefused {
		t.Errorf("history = %+v", h)
	}
}

func TestUpdateUnverified(t *testing.T) {
	e := newCoreEnv(t, "26.3.27")
	sum := e.rel.addZipOnly(t, "26.10.21")

	res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
	wantOutcome(t, res, err, OutcomeRefused)
	if !errors.Is(err, ErrNoHash) {
		t.Errorf("err = %v, want ErrNoHash", err)
	}
	wantDetail(t, res, "consent")
	wantActions(t, e.runner)
	for _, h := range e.rel.hitList() {
		if h == assetPath("26.10.21") {
			t.Error("the zip was downloaded without a hash or consent")
		}
	}
	if got := e.slots(t); !reflect.DeepEqual(got, []string{"26.3.27"}) {
		t.Errorf("slots = %v", got)
	}

	res, err = e.u.Update(bg, "26.10.21", UpdateOptions{AllowUnverified: true})
	wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
	if res.Verified != "unverified" || res.Source != "direct" {
		t.Errorf("Result = %+v, want verified unverified from direct", res)
	}
	if m := e.meta(t, "26.10.21"); m.Verified != "unverified" || m.ZipSHA256 != sum {
		t.Errorf("meta.json = %+v, want verified unverified, zip %s", m, sum)
	}
	if h := e.history(t); len(h) != 2 || h[0].Outcome != OutcomeRefused || h[1].Outcome != runnerapi.OutcomeCommitted {
		t.Errorf("history = %+v", h)
	}
	e.wantClean(t)
}

func TestUpdateNoop(t *testing.T) {
	t.Run("version", func(t *testing.T) {
		e := newCoreEnv(t, "26.3.27")
		res, err := e.u.Update(bg, "v26.3.27", UpdateOptions{})
		wantOutcome(t, res, err, OutcomeNoop)
		wantResult(t, res, Result{From: "26.3.27", To: "26.3.27", Outcome: OutcomeNoop, Detail: "already active", At: t0})
		wantActions(t, e.runner)
		if hits := e.rel.hitList(); len(hits) != 0 {
			t.Errorf("upstream was asked for %v", hits)
		}
		if h := e.history(t); len(h) != 1 || h[0].Outcome != OutcomeNoop {
			t.Errorf("history = %+v", h)
		}
	})
	t.Run("same config", func(t *testing.T) {
		e := newCoreEnv(t, "26.3.27")
		res, err := e.u.Update(bg, "26.3.27", UpdateOptions{ConfigFile: writeConfigFile(t, activeConfigBody)})
		wantOutcome(t, res, err, OutcomeNoop)
		wantActions(t, e.runner)
	})
	t.Run("new config is a trial", func(t *testing.T) {
		e := newCoreEnv(t, "26.3.27")
		body := `{"inbounds":[{"protocol":"tun"}]}`
		res, err := e.u.Update(bg, "26.3.27", UpdateOptions{ConfigFile: writeConfigFile(t, body)})
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		rel := "config/" + shaOf(body) + ".json"
		wantCandidate(t, e.runner, runnerapi.Candidate{
			Selection: runnerapi.Selection{Core: "26.3.27", Geo: "g1", Config: rel},
			Deadline:  t0.Add(120 * time.Second),
		})
		p := filepath.Join(e.data, "run", rel)
		if b, err := os.ReadFile(p); err != nil || string(b) != body {
			t.Errorf("%s = %q, %v; want the config file", rel, b, err)
		}
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o644 {
			t.Errorf("%s: %v, %v; want mode 0644", rel, fi, err)
		}
		if hits := e.rel.hitList(); len(hits) != 0 {
			t.Errorf("upstream was asked for %v; the slot is installed", hits)
		}
	})
}

func TestUpdateNeedsConfig(t *testing.T) {
	e := newCoreEnv(t, "")
	e.rel.add(t, "26.10.21")

	res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
	wantOutcome(t, res, err, OutcomeRefused)
	wantDetail(t, res, "config")
	wantActions(t, e.runner)

	body := `{"log":{}}`
	res, err = e.u.Update(bg, "26.10.21", UpdateOptions{ConfigFile: writeConfigFile(t, body)})
	wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
	if res.From != "" {
		t.Errorf("From = %q, want none", res.From)
	}
	wantCandidate(t, e.runner, runnerapi.Candidate{
		Selection: runnerapi.Selection{Core: "26.10.21", Config: "config/" + shaOf(body) + ".json"},
		Deadline:  t0.Add(120 * time.Second),
	})
}

func TestUpdateLocked(t *testing.T) {
	e := newCoreEnv(t, "26.3.27")
	e.rel.add(t, "26.10.21")
	release, ok := tryLock(t, e.data)
	if !ok {
		t.Fatal("could not take the lock")
	}

	res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
	wantOutcome(t, res, err, OutcomeRefused)
	if !errors.Is(err, ErrLocked) {
		t.Errorf("err = %v, want ErrLocked", err)
	}
	if calls := e.runner.allCalls(); len(calls) != 0 {
		t.Errorf("the runner got %v", calls)
	}
	if hits := e.rel.hitList(); len(hits) != 0 {
		t.Errorf("upstream was asked for %v", hits)
	}
	if h := e.history(t); len(h) != 1 || h[0].Outcome != OutcomeRefused {
		t.Errorf("history = %+v", h)
	}
	release()

	// The lock is held through the trial and released afterwards.
	e.health.fn = func(int) error {
		if release, ok := tryLock(t, e.data); ok {
			release()
			t.Error("the artifacts lock is free during the trial")
		}
		return nil
	}
	res, err = e.u.Update(bg, "26.10.21", UpdateOptions{})
	wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
	if release, ok := tryLock(t, e.data); !ok {
		t.Error("the artifacts lock is still held after the update")
	} else {
		release()
	}
}

func TestRollback(t *testing.T) {
	setup := func(t *testing.T, slots ...string) *coreEnv {
		e := newCoreEnv(t, "26.10.21")
		for _, v := range slots {
			install(t, e.cores(), v)
		}
		return e
	}
	t.Run("previous", func(t *testing.T) {
		e := setup(t, "26.1.18", "26.3.27")
		e.writeHistory(t, committedResult("26.1.18", ""), committedResult("26.3.27", "26.1.18"), committedResult("26.10.21", "26.3.27"))

		res, err := e.u.Rollback(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantResult(t, res, Result{From: "26.10.21", To: "26.3.27", Outcome: "committed", Source: "test", At: t0})
		wantActions(t, e.runner, "trial", "commit")
		wantCandidate(t, e.runner, runnerapi.Candidate{
			Selection: runnerapi.Selection{Core: "26.3.27", Geo: "g1", Config: e.activeSel.Config},
			Deadline:  t0.Add(120 * time.Second),
		})
		if got := e.slots(t); !reflect.DeepEqual(got, []string{"26.10.21", "26.3.27"}) {
			t.Errorf("slots = %v, want the current and the previous", got)
		}
		if h := e.history(t); len(h) != 4 {
			t.Errorf("history has %d lines, want 4", len(h))
		}
	})
	t.Run("skips a removed slot", func(t *testing.T) {
		e := setup(t, "26.1.18")
		e.writeHistory(t, committedResult("26.1.18", ""), committedResult("26.3.27", ""), committedResult("26.10.21", ""))
		res, err := e.u.Rollback(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		if res.To != "26.1.18" {
			t.Errorf("To = %q, want 26.1.18", res.To)
		}
	})
	t.Run("only one committed", func(t *testing.T) {
		e := setup(t, "26.3.27") // installed, but never committed
		e.writeHistory(t, committedResult("26.10.21", ""), Result{To: "26.3.27", Outcome: "exited"})
		res, err := e.u.Rollback(bg)
		wantOutcome(t, res, err, OutcomeRefused)
		wantActions(t, e.runner)
		if res.From != "26.10.21" {
			t.Errorf("From = %q", res.From)
		}
	})
	t.Run("no history", func(t *testing.T) {
		e := setup(t, "26.3.27")
		res, err := e.u.Rollback(bg)
		wantOutcome(t, res, err, OutcomeRefused)
		wantActions(t, e.runner)
	})
	t.Run("the core the first update replaced", func(t *testing.T) {
		// The installer put 26.3.27 in place, so only its replacement is in the history.
		e := setup(t, "26.3.27")
		e.writeHistory(t, committedResult("26.10.21", "26.3.27"))
		res, err := e.u.Rollback(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		if res.To != "26.3.27" {
			t.Errorf("To = %q, want 26.3.27", res.To)
		}
	})
	t.Run("unhealthy", func(t *testing.T) {
		e := setup(t, "26.3.27")
		e.writeHistory(t, committedResult("26.3.27", ""), committedResult("26.10.21", "26.3.27"))
		e.health.fn = func(int) error { return errors.New("no traffic") }
		res, err := e.u.Rollback(bg)
		wantOutcome(t, res, err, OutcomeUnhealthy)
		wantActions(t, e.runner, "trial", "abort")
	})
}

func TestPruneAfterCommit(t *testing.T) {
	t.Run("keeps the current and the previous", func(t *testing.T) {
		e := newCoreEnv(t, "26.3.27")
		install(t, e.cores(), "26.1.18")
		install(t, e.cores(), "99.0.1")
		e.writeHistory(t, committedResult("26.1.18", ""), committedResult("26.3.27", "26.1.18"),
			Result{From: "26.3.27", To: "99.0.1", Outcome: runnerapi.OutcomeExited, At: t0})
		e.rel.add(t, "26.10.21")

		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		if got := e.slots(t); !reflect.DeepEqual(got, []string{"26.10.21", "26.3.27"}) {
			t.Errorf("slots = %v, want exactly 26.10.21 and 26.3.27", got)
		}
	})
	t.Run("Keep 3", func(t *testing.T) {
		e := newCoreEnv(t, "26.3.27")
		install(t, e.cores(), "26.1.18")
		install(t, e.cores(), "99.0.1")
		e.writeHistory(t, committedResult("26.1.18", ""), committedResult("26.3.27", "26.1.18"))
		e.rel.add(t, "26.10.21")
		e.u.Keep = 3

		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		if got := e.slots(t); !reflect.DeepEqual(got, []string{"26.10.21", "26.3.27", "26.1.18"}) {
			t.Errorf("slots = %v", got)
		}
	})
	t.Run("first update keeps the core it replaced", func(t *testing.T) {
		e := newCoreEnv(t, "26.3.27") // no history: the installer put 26.3.27 in place
		install(t, e.cores(), "26.1.18")
		e.rel.add(t, "26.10.21")

		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		if got := e.slots(t); !reflect.DeepEqual(got, []string{"26.10.21", "26.3.27"}) {
			t.Errorf("slots = %v", got)
		}
	})
	t.Run("not after a failed trial", func(t *testing.T) {
		e := newCoreEnv(t, "26.3.27")
		install(t, e.cores(), "26.1.18")
		e.rel.add(t, "26.10.21")
		e.health.fn = func(int) error { return errors.New("down") }

		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
		wantOutcome(t, res, err, OutcomeUnhealthy)
		if got := e.slots(t); !reflect.DeepEqual(got, []string{"26.10.21", "26.3.27", "26.1.18"}) {
			t.Errorf("slots = %v, want all of them", got)
		}
	})
}

func TestUpdateWrongHash(t *testing.T) {
	setup := func(t *testing.T, inboxZip []byte) (*coreEnv, string) {
		e := newCoreEnv(t, "26.3.27")
		sum := e.rel.add(t, "26.10.21")
		good := e.rel.take(assetPath("26.10.21")) // upstream has only the .dgst
		if inboxZip == nil {
			inboxZip = good
		}
		evil := releaseBytes(t, "evil")
		mirror := serve(t, func(w http.ResponseWriter, r *http.Request) { w.Write(evil) })
		inbox := t.TempDir()
		if err := os.WriteFile(filepath.Join(inbox, testAsset), inboxZip, 0o644); err != nil {
			t.Fatal(err)
		}
		e.u.Fetch = Chain{Sources: []Source{
			Direct(e.rel.srv.URL, e.rel.srv.Client()),
			Mirror(mirror.URL+"/m/{version}/{file}", mirror.Client()),
			Inbox(inbox),
		}}
		return e, sum
	}
	t.Run("inbox has the right file", func(t *testing.T) {
		e, sum := setup(t, nil)
		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		if res.Source != "inbox" || res.Verified != "dgst" {
			t.Errorf("Result = %+v, want source inbox, verified dgst", res)
		}
		if m := e.meta(t, "26.10.21"); m.Source != "inbox" || m.ZipSHA256 != sum {
			t.Errorf("meta.json = %+v", m)
		}
		e.wantClean(t)
	})
	t.Run("no source has it", func(t *testing.T) {
		e, _ := setup(t, releaseBytes(t, "evil too"))
		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
		wantOutcome(t, res, err, OutcomeRefused)
		for _, s := range []string{"direct: ", "mirror 127.0.0.1:", "inbox: ", "SHA-256"} {
			if !strings.Contains(err.Error(), s) {
				t.Errorf("err = %v, want it to name %q", err, s)
			}
		}
		if got := dirNames(t, e.cores()); !reflect.DeepEqual(got, []string{"26.3.27"}) {
			t.Errorf("cores/ holds %v, want only 26.3.27", got)
		}
		wantActions(t, e.runner)
		e.wantClean(t)
	})
}

// The runner answers a trial only after xray run -test, which can outlast the
// Runner client's own timeout.
func TestUpdateTrialOutlastsClientTimeout(t *testing.T) {
	e := newCoreEnv(t, "26.3.27")
	e.rel.add(t, "26.10.21")
	e.runner.script(func(f *fakeRunner) { f.delay["trial"] = 300 * time.Millisecond })
	hc := &http.Client{Timeout: 100 * time.Millisecond, Transport: e.runner.srv.Client().Transport}
	e.u.Runner.HTTP = hc

	res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
	wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
	if e.u.Runner.HTTP != hc || hc.Timeout != 100*time.Millisecond {
		t.Errorf("the caller's client was changed: %+v", e.u.Runner.HTTP)
	}
}

func TestUpdateCandidateExits(t *testing.T) {
	e := newCoreEnv(t, "26.3.27")
	e.rel.add(t, "26.10.21")
	const why = "ran 5ms, within the 10s early-exit window: exit status 1"
	e.runner.script(func(f *fakeRunner) {
		f.onStatus = func() {
			if f.st.State == runnerapi.StateTrial {
				f.end(runnerapi.OutcomeExited, why)
			}
		}
	})

	res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
	wantOutcome(t, res, err, runnerapi.OutcomeExited)
	if res.Detail != why {
		t.Errorf("Detail = %q, want the runner's", res.Detail)
	}
	wantActions(t, e.runner, "trial")
	if n := e.health.n.Load(); n != 0 {
		t.Errorf("health checked %d times", n)
	}
}

func TestUpdateTrialErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		onTrial func(f *fakeRunner, w http.ResponseWriter, c runnerapi.Candidate)
		outcome string
		detail  string
		is      error
		actions []string
	}{
		{
			name: "busy",
			onTrial: func(f *fakeRunner, w http.ResponseWriter, c runnerapi.Candidate) {
				fakeError(w, http.StatusConflict, "busy", "")
			},
			outcome: OutcomeRefused,
			is:      runnerapi.ErrBusy,
			actions: []string{"trial"},
		},
		{
			name: "candidate did not start",
			onTrial: func(f *fakeRunner, w http.ResponseWriter, c runnerapi.Candidate) {
				f.st.State, f.st.Candidate = runnerapi.StateTrial, &c
				f.end(runnerapi.OutcomeExited, "could not start: exec format error")
				fakeError(w, http.StatusInternalServerError, "internal", "runner: start candidate: exec format error")
			},
			outcome: runnerapi.OutcomeExited,
			detail:  "could not start: exec format error",
			actions: []string{"trial"},
		},
		{
			name: "no record",
			onTrial: func(f *fakeRunner, w http.ResponseWriter, c runnerapi.Candidate) {
				fakeError(w, http.StatusInternalServerError, "internal", "disk on fire")
			},
			outcome: OutcomeRefused,
			detail:  "disk on fire",
			actions: []string{"trial"},
		},
		{
			name: "open despite the error",
			onTrial: func(f *fakeRunner, w http.ResponseWriter, c runnerapi.Candidate) {
				f.st.State, f.st.Candidate = runnerapi.StateTrial, &c
				fakeError(w, http.StatusInternalServerError, "internal", "lost")
			},
			outcome: runnerapi.OutcomeAborted,
			actions: []string{"trial", "abort"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newCoreEnv(t, "26.3.27")
			e.rel.add(t, "26.10.21")
			e.runner.script(func(f *fakeRunner) {
				f.onTrial = func(w http.ResponseWriter, c runnerapi.Candidate) bool {
					tc.onTrial(f, w, c)
					return true
				}
			})
			res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
			wantOutcome(t, res, err, tc.outcome)
			wantDetail(t, res, tc.detail)
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("err = %v, want %v", err, tc.is)
			}
			wantActions(t, e.runner, tc.actions...)
			if n := e.health.n.Load(); n != 0 {
				t.Errorf("health checked %d times", n)
			}
			if tc.name == "no record" {
				if _, err := os.Stat(filepath.Join(e.data, "run", "candidate.json")); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("candidate.json is left for the runner's next boot: %v", err)
				}
			}
		})
	}
}

func TestUpdateRefusesOpenTrial(t *testing.T) {
	e := newCoreEnv(t, "26.3.27")
	e.rel.add(t, "26.10.21")
	other := runnerapi.Candidate{Selection: runnerapi.Selection{Core: "26.9.1", Config: e.activeSel.Config}, Deadline: t0.Add(time.Minute)}
	e.runner.script(func(f *fakeRunner) { f.st.State, f.st.Candidate = runnerapi.StateTrial, &other })

	res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
	wantOutcome(t, res, err, OutcomeRefused)
	if !errors.Is(err, runnerapi.ErrBusy) {
		t.Errorf("err = %v, want ErrBusy", err)
	}
	wantActions(t, e.runner)
	if hits := e.rel.hitList(); len(hits) != 0 {
		t.Errorf("upstream was asked for %v", hits)
	}
	if _, err := os.Stat(filepath.Join(e.data, "run", "candidate.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("candidate.json was written over the open trial's: %v", err)
	}
}

func TestUpdateCommitFails(t *testing.T) {
	t.Run("the trial ended first", func(t *testing.T) {
		e := newCoreEnv(t, "26.3.27")
		e.rel.add(t, "26.10.21")
		// Health passes, but the runner reverts before the commit arrives.
		e.health.fn = func(int) error {
			e.runner.script(func(f *fakeRunner) {
				if f.st.State == runnerapi.StateTrial {
					f.end(runnerapi.OutcomeDeadline, "no commit before the deadline")
				}
			})
			return nil
		}
		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
		wantOutcome(t, res, err, runnerapi.OutcomeDeadline)
		wantDetail(t, res, "no commit before the deadline")
		wantActions(t, e.runner, "trial", "commit")
	})
	t.Run("the answer was lost", func(t *testing.T) {
		e := newCoreEnv(t, "26.3.27")
		e.rel.add(t, "26.10.21")
		// The runner commits; the core then dies during the commit's fsyncs
		// and is being restarted, and the connection drops before the answer.
		e.runner.script(func(f *fakeRunner) {
			f.onCommit = func(w http.ResponseWriter) bool {
				f.end(runnerapi.OutcomeCommitted, "")
				f.st.State, f.st.XrayPID = runnerapi.StateRestarting, 0
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return true
				}
				conn.Close()
				return true
			}
		})
		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantActions(t, e.runner, "trial", "commit")
		if got := e.slots(t); !reflect.DeepEqual(got, []string{"26.10.21", "26.3.27"}) {
			t.Errorf("slots = %v", got)
		}
	})
	t.Run("the runner could not commit", func(t *testing.T) {
		e := newCoreEnv(t, "26.3.27")
		e.rel.add(t, "26.10.21")
		e.runner.script(func(f *fakeRunner) {
			f.onCommit = func(w http.ResponseWriter) bool {
				fakeError(w, http.StatusInternalServerError, "internal", "runner: commit: read-only file system")
				return true
			}
		})
		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
		wantOutcome(t, res, err, runnerapi.OutcomeAborted)
		wantDetail(t, res, "read-only file system")
		wantActions(t, e.runner, "trial", "commit", "abort")
	})
}

func TestUpdateCanceled(t *testing.T) {
	e := newCoreEnv(t, "26.3.27")
	e.rel.add(t, "26.10.21")
	cctx, cancel := context.WithCancel(bg)
	e.health.fn = func(int) error {
		cancel()
		return errors.New("interrupted")
	}
	res, err := e.u.Update(cctx, "26.10.21", UpdateOptions{})
	wantOutcome(t, res, err, runnerapi.OutcomeAborted)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	// The abort still reaches the runner, so it reverts now, not at the deadline.
	wantActions(t, e.runner, "trial", "abort")
}
