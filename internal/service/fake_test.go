package service

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xrayver"
)

// testCore is the core the fake runner runs.
const testCore = "26.10.21"

// t0 is when the fake clock starts.
var t0 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// fakeClock is the service's clock and its timers. A timer fires only when
// the test advances the clock past it.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	d              time.Duration
	at             time.Time
	c              chan time.Time
	fired, stopped bool
}

func newFakeClock() *fakeClock { return &fakeClock{now: t0} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// timer is the service's timer constructor. Stop behaves like a Go 1.23
// timer's: a value that fired but was not received is dropped.
func (c *fakeClock) timer(d time.Duration) (<-chan time.Time, func() bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{d: d, at: c.now.Add(d), c: make(chan time.Time, 1)}
	c.timers = append(c.timers, t)
	return t.c, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		active := !t.fired && !t.stopped
		t.stopped = true
		select {
		case <-t.c:
		default:
		}
		return active
	}
}

// advance moves the clock on by d and fires the timers that are due. It
// reports whether any fired.
func (c *fakeClock) advance(d time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	fired := false
	for _, t := range c.timers {
		if !t.fired && !t.stopped && !t.at.After(c.now) {
			t.fired = true
			t.c <- c.now
			fired = true
		}
	}
	return fired
}

// firedUnread reports whether a timer fired and nobody has received it yet.
func (c *fakeClock) firedUnread() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, t := range c.timers {
		if t.fired && !t.stopped && len(t.c) > 0 {
			return true
		}
	}
	return false
}

// armed returns the duration of every timer made so far, in order.
func (c *fakeClock) armed() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []time.Duration
	for _, t := range c.timers {
		out = append(out, t.d)
	}
	return out
}

// pending returns the durations of the timers that have neither fired nor
// been stopped.
func (c *fakeClock) pending() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []time.Duration
	for _, t := range c.timers {
		if !t.fired && !t.stopped {
			out = append(out, t.d)
		}
	}
	return out
}

// fakeRunner serves the runner's control API in process, as the
// transport of a runnerapi.Client, from a state the test scripts. While it is
// down every call fails as a refused connection does.
type fakeRunner struct {
	t   *testing.T
	run string // the data root's run directory

	mu     sync.Mutex
	st     runnerapi.Status
	down   bool
	calls  []string // the routes called, "down:<route>" for those that failed
	trials []runnerapi.Candidate
	// reject, when set, is the xray output a trial is rejected with.
	reject string
	// reboot, when set, makes the next trial start and the runner restart
	// at once, as its boot finds the trial open: it reverts and records the
	// outcome reboot.
	reboot bool
	// gate, when set, holds each trial until it is closed; waiting gets a
	// value when a trial starts to wait at it.
	gate    chan struct{}
	waiting chan struct{}
	// tests are the configs that POST /v1/test got, in order. That route
	// accepts a config unless testReject is set, the xray output it then
	// answers with (ok false), or testNoCore makes it answer no_core, or
	// testBroken makes it fail with a 500. testRejectFor, when set, makes
	// it reject only the configs that hold that text, with testRejectOut.
	tests         [][]byte
	testReject    string
	testNoCore    bool
	testBroken    bool
	testRejectFor string
	testRejectOut string
}

func newFakeRunner(t *testing.T, run string) *fakeRunner {
	return &fakeRunner{t: t, run: run, st: runnerapi.Status{State: runnerapi.StateEmpty}, waiting: make(chan struct{}, 16)}
}

func (f *fakeRunner) client() *runnerapi.Client {
	return &runnerapi.Client{BaseURL: "http://runner.test:8080", Token: "tok", HTTP: &http.Client{Transport: f}}
}

// setActive makes the runner run testCore with the config named rel.
func (f *fakeRunner) setActive(rel string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st = runnerapi.Status{
		State:       runnerapi.StateRunning,
		Active:      &runnerapi.Selection{Core: testCore, Config: rel},
		XrayPID:     42,
		XrayVersion: fakeXrayVersion(testCore),
		RoutesOK:    true,
		GatewayUp:   true,
	}
}

func (f *fakeRunner) setDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

// setTestReject makes the runner's test of a config fail with output.
func (f *fakeRunner) setTestReject(output string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.testReject = output
}

// setTestRejectFor makes the runner's test fail with output for the configs
// that hold text, and pass for the others.
func (f *fakeRunner) setTestRejectFor(text, output string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.testRejectFor, f.testRejectOut = text, output
}

// failTest makes the runner's test of a config fail as if no xray ran
// (noCore) or as if the runner broke (a 500).
func (f *fakeRunner) failTest(noCore, broken bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.testNoCore, f.testBroken = noCore, broken
}

// gotTests returns the configs the runner was asked to test.
func (f *fakeRunner) gotTests() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.tests)
}

func (f *fakeRunner) setReject(output string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reject = output
}

// rebootNext makes the next trial end in a restart of the runner.
func (f *fakeRunner) rebootNext() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reboot = true
}

// restart brings a runner that went down back up as its boot does: a trial
// that was open is reverted, with the outcome reboot.
func (f *fakeRunner) restart() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = false
	if f.st.State == runnerapi.StateTrial {
		f.revert(runnerapi.OutcomeReboot)
	}
}

// hold makes the next trials wait until release.
func (f *fakeRunner) hold() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gate = make(chan struct{})
}

func (f *fakeRunner) release() {
	f.mu.Lock()
	defer f.mu.Unlock()
	close(f.gate)
	f.gate = nil
}

func (f *fakeRunner) active() runnerapi.Selection {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.st.Active == nil {
		return runnerapi.Selection{}
	}
	return *f.st.Active
}

func (f *fakeRunner) gotCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeRunner) gotTrials() []runnerapi.Candidate {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.trials)
}

// RoundTrip serves req as the runner would.
func (f *fakeRunner) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		defer req.Body.Close()
	}
	route := strings.TrimPrefix(req.URL.Path, "/v1/")
	f.mu.Lock()
	if f.down {
		f.calls = append(f.calls, "down:"+route)
		f.mu.Unlock()
		return nil, errors.New("dial tcp 172.31.255.3:8080: connect: connection refused")
	}
	f.calls = append(f.calls, route)
	f.mu.Unlock()
	if req.Header.Get("Authorization") != "Bearer tok" {
		return reply(http.StatusUnauthorized, map[string]string{"error": "unauthorized"}), nil
	}
	switch req.Method + " " + route {
	case "GET status":
		f.mu.Lock()
		defer f.mu.Unlock()
		return reply(http.StatusOK, f.st), nil
	case "POST trial":
		return f.trial(req.Context()), nil
	case "POST commit":
		return f.end(runnerapi.OutcomeCommitted), nil
	case "POST abort":
		return f.end(runnerapi.OutcomeAborted), nil
	case "POST test":
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		return f.test(req), nil
	}
	return reply(http.StatusNotFound, map[string]string{"error": "bad_request"}), nil
}

// test answers POST /v1/test.
func (f *fakeRunner) test(req *http.Request) *http.Response {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		f.t.Errorf("test: reading the body: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tests = append(f.tests, body)
	switch {
	case f.testNoCore:
		return reply(http.StatusConflict, map[string]string{"error": "no_core"})
	case f.testBroken:
		return reply(http.StatusInternalServerError, map[string]string{"error": "internal", "detail": "the trial ended while the config was tested"})
	case f.testReject != "":
		return reply(http.StatusOK, runnerapi.TestResult{Output: f.testReject})
	case f.testRejectFor != "" && bytes.Contains(body, []byte(f.testRejectFor)):
		return reply(http.StatusOK, runnerapi.TestResult{Output: f.testRejectOut})
	}
	return reply(http.StatusOK, runnerapi.TestResult{OK: true, Output: "Configuration OK."})
}

func (f *fakeRunner) trial(ctx context.Context) *http.Response {
	var c runnerapi.Candidate
	raw, err := os.ReadFile(filepath.Join(f.run, "candidate.json"))
	if err == nil {
		err = json.Unmarshal(raw, &c)
	}
	if err != nil {
		f.t.Errorf("trial: candidate.json: %v", err)
		return reply(http.StatusBadRequest, map[string]string{"error": "bad_request"})
	}
	f.mu.Lock()
	f.trials = append(f.trials, c)
	gate := f.gate
	f.mu.Unlock()
	if gate != nil {
		f.waiting <- struct{}{}
		select {
		case <-gate:
		case <-ctx.Done():
			return reply(http.StatusServiceUnavailable, map[string]string{"error": "gone"})
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.st.State == runnerapi.StateTrial:
		return reply(http.StatusConflict, map[string]string{"error": "busy"})
	case f.reject != "":
		return reply(http.StatusUnprocessableEntity, map[string]string{"error": "test_failed", "detail": f.reject})
	}
	f.st.State, f.st.Candidate = runnerapi.StateTrial, &c
	f.st.XrayVersion, f.st.RoutesOK, f.st.GatewayUp = fakeXrayVersion(c.Core), true, true
	if f.reboot {
		f.reboot = false
		f.revert(runnerapi.OutcomeReboot)
	}
	return reply(http.StatusNoContent, nil)
}

// end closes the open trial with outcome: a commit makes the candidate
// active, anything else reverts.
func (f *fakeRunner) end(outcome string) *http.Response {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.st.State != runnerapi.StateTrial {
		return reply(http.StatusConflict, map[string]string{"error": "no_trial"})
	}
	f.revert(outcome)
	return reply(http.StatusNoContent, nil)
}

// revert closes the open trial with outcome: a commit makes the candidate
// active, anything else leaves the active selection as it was. mu must be
// held.
func (f *fakeRunner) revert(outcome string) {
	c := *f.st.Candidate
	if outcome == runnerapi.OutcomeCommitted {
		sel := c.Selection
		f.st.Active = &sel
	}
	f.st.State, f.st.Candidate = runnerapi.StateRunning, nil
	if f.st.Active != nil {
		f.st.XrayVersion = fakeXrayVersion(f.st.Active.Core)
	}
	f.st.LastTrial = &runnerapi.TrialResult{Candidate: c, Outcome: outcome, At: t0}
	os.Remove(filepath.Join(f.run, "candidate.json"))
}

func reply(code int, v any) *http.Response {
	rec := httptest.NewRecorder()
	if v != nil {
		rec.Header().Set("Content-Type", "application/json")
		rec.WriteHeader(code)
		json.NewEncoder(rec).Encode(v)
	} else {
		rec.WriteHeader(code)
	}
	return rec.Result()
}

func fakeXrayVersion(core string) string {
	return "Xray " + core + " (Xray, Penetrates Everything.) fake (go1.24.7 linux/amd64)"
}

// stubHealth is the updater's health check: it fails with err when set, and
// calls then, when set, at each check.
type stubHealth struct {
	mu   sync.Mutex
	err  error
	then func()
}

func (h *stubHealth) Check(context.Context) error {
	h.mu.Lock()
	err, then := h.err, h.then
	h.mu.Unlock()
	if then != nil {
		then()
	}
	return err
}

func (h *stubHealth) fail(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.err = err
}

// failThen makes each check fail with err after calling then.
func (h *stubHealth) failThen(err error, then func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.err, h.then = err, then
}

// renderFor is the fake renderer: the state, the core and the geo as JSON,
// so that every change of the state changes the render.
func renderFor(st store.State, core xrayver.Version, geo string) ([]byte, error) {
	b, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, `{"core":%q,"geo":%q,"state":%s}`+"\n", core, geo, b), nil
}

// configOf is the name under run/ of the render of st for testCore.
func configOf(t *testing.T, st store.State) string {
	t.Helper()
	return configOn(t, st, testCore)
}

// configOn is the name under run/ of the render of st for core.
func configOn(t *testing.T, st store.State, core string) string {
	t.Helper()
	v, err := xrayver.Parse(core)
	if err != nil {
		t.Fatal(err)
	}
	b, err := renderFor(st, v, "")
	if err != nil {
		t.Fatal(err)
	}
	return artifacts.ConfigName(b)
}

// installCore installs a slot for core ver in the data root's cores/.
func installCore(t *testing.T, data, ver string) {
	t.Helper()
	v, err := xrayver.Parse(ver)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "xray", Method: zip.Deflate})
	if err == nil {
		_, err = w.Write([]byte("#!/bin/sh\necho xray " + ver + "\n"))
	}
	if err == nil {
		err = zw.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(t.TempDir(), "core.zip")
	if err := os.WriteFile(zipPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := artifacts.InstallCore(filepath.Join(data, "cores"), v, zipPath, artifacts.Meta{Source: "test", Verified: "dgst"}); err != nil {
		t.Fatal(err)
	}
}

// addServer adds a server with outbound to the store and returns the new
// state.
func (e *env) addServer(name, outbound string) store.State {
	e.t.Helper()
	st, _, err := e.store.Update(store.AnyRevision, func(st *store.State) error {
		st.Servers = append(st.Servers, store.Server{ID: store.NewID(), Name: name, Outbound: json.RawMessage(outbound)})
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return st
}

// eventually waits until cond holds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// within waits for a value from c.
func within[T any](t *testing.T, what string, c <-chan T) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
	panic("unreachable")
}

// env is a service over a store in a temporary data root, with a fake runner
// and a fake clock. Its loop reports on quiet each time it waits with nothing
// left to do.
type env struct {
	t      *testing.T
	data   string
	store  *store.Store
	runner *fakeRunner
	clock  *fakeClock
	health *stubHealth
	s      *Service

	quiet   chan struct{}
	lockers chan struct{} // gets a value when an operation waits for another
	stop    context.CancelFunc
	done    chan error
	edits   int

	// ticks makes the timers of the subscription scheduler: it has its own
	// clock, so that its timers stay out of the apply loop's armed and
	// pending ones. schedQuiet gets a value each time the scheduler is about
	// to wait.
	ticks      *fakeClock
	schedQuiet chan struct{}

	mu        sync.Mutex
	renderErr error // what the renders fail with, if set
}

func newEnv(t *testing.T) *env {
	t.Helper()
	data := t.TempDir()
	for _, dir := range []string{"run", "cores"} {
		if err := os.MkdirAll(filepath.Join(data, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.Open(filepath.Join(data, "state"))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{
		t:       t,
		data:    data,
		store:   st,
		runner:  newFakeRunner(t, filepath.Join(data, "run")),
		clock:   newFakeClock(),
		health:  &stubHealth{},
		quiet:   make(chan struct{}, 1000),
		lockers: make(chan struct{}, 16),

		ticks:      newFakeClock(),
		schedQuiet: make(chan struct{}, 1000),
	}
	e.s = e.newService(Config{})
	return e
}

// newService makes the env's service, from c with what c leaves unset filled
// in, and points its timers and hooks at the env.
func (e *env) newService(c Config) *Service {
	e.t.Helper()
	if c.Store == nil {
		c.Store = e.store
	}
	if c.Updaters == nil {
		c.Updaters = e.updaters
	}
	if c.Runner == nil {
		c.Runner = e.runner.client()
	}
	if c.Data == "" {
		c.Data = e.data
	}
	if c.Now == nil {
		c.Now = e.clock.Now
	}
	s, err := New(c)
	if err != nil {
		e.t.Fatal(err)
	}
	s.after = e.clock.timer
	s.idle = func() {
		if len(s.kicks) == 0 && !e.clock.firedUnread() {
			e.quiet <- struct{}{}
		}
	}
	s.onWait = func() { e.lockers <- struct{}{} }
	s.schedAfter = e.ticks.timer
	s.schedIdle = func() { e.schedQuiet <- struct{}{} }
	return s
}

// failRender makes the env's renders fail with err; nil makes them work.
func (e *env) failRender(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.renderErr = err
}

// updaters is the env's Updaters: a CoreUpdater over the fake runner that
// renders with renderFor, and whose own Redact leaves everything as it is.
func (e *env) updaters(st store.State, rev uint64) *artifacts.CoreUpdater {
	render := func(core xrayver.Version, geo string) ([]byte, error) {
		e.mu.Lock()
		err := e.renderErr
		e.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return renderFor(st, core, geo)
	}
	return &artifacts.CoreUpdater{
		Data:         e.data,
		Runner:       e.runner.client(),
		Render:       render,
		NoState:      rev == 0,
		Health:       e.health,
		Redact:       func(s string) string { return s },
		EarlyExit:    time.Nanosecond,
		HealthWindow: 5 * time.Millisecond,
		Now:          e.clock.Now,
	}
}

// start runs the service until the test ends, and waits for its loop to
// settle after the start.
func (e *env) start() {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	e.stop, e.done = cancel, make(chan error, 1)
	go func() { e.done <- e.s.Run(ctx) }()
	e.t.Cleanup(e.shutdown)
	e.settle()
}

// shutdown stops the service and waits for Run to return.
func (e *env) shutdown() {
	e.t.Helper()
	if e.stop == nil {
		return
	}
	e.stop()
	e.stop = nil
	select {
	case err := <-e.done:
		if err != nil {
			e.t.Errorf("Run = %v, want nil after the context ends", err)
		}
	case <-time.After(10 * time.Second):
		e.t.Error("Run did not return after the context ended")
	}
}

// settle waits until the loop waits with nothing left to do.
func (e *env) settle() {
	e.t.Helper()
	select {
	case <-e.quiet:
	case <-time.After(10 * time.Second):
		e.t.Fatal("the apply loop did not settle")
	}
}

// advance moves the clock on by d and, if that fired a timer, waits for the
// loop to settle after it.
func (e *env) advance(d time.Duration) {
	e.t.Helper()
	if e.clock.advance(d) {
		e.settle()
	}
}

// kick kicks the service and waits for the loop to settle.
func (e *env) kick() {
	e.t.Helper()
	e.s.Kick()
	e.settle()
}

// edit changes the state, as a mutation would without its kick, and returns
// the new state and revision.
func (e *env) edit() (store.State, uint64) {
	e.t.Helper()
	e.edits++
	st, rev, err := e.store.Update(store.AnyRevision, func(st *store.State) error {
		st.Routing.BlockList = append(st.Routing.BlockList, fmt.Sprintf("domain:edit%d.example", e.edits))
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return st, rev
}

// inSync makes the runner run the render of the current state.
func (e *env) inSync() {
	e.t.Helper()
	st, _ := e.store.State()
	e.runner.setActive(configOf(e.t, st))
}

// outOfSync makes the runner run a config that no state renders to.
func (e *env) outOfSync() {
	e.runner.setActive(artifacts.ConfigName([]byte("{}\n")))
}

// wantNoTimers fails if the loop has a timer armed.
func (e *env) wantNoTimers() {
	e.t.Helper()
	if p := e.clock.pending(); len(p) != 0 {
		e.t.Errorf("the loop has timers armed for %v, want none", p)
	}
}

// eventsOf returns the messages of the events of kind.
func (e *env) eventsOf(kind string) []string {
	var out []string
	for _, ev := range e.s.Events(0) {
		if ev.Kind == kind {
			out = append(out, ev.Message)
		}
	}
	return out
}

// historyText is the whole history file.
func (e *env) historyText() string {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(e.data, "state", "core-history.jsonl"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		e.t.Fatal(err)
	}
	return string(b)
}
