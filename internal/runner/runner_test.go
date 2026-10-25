package runner

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

const (
	oldCore = "26.1.18"  // what active.json runs
	newCore = "26.10.21" // the candidate
)

// rig is a Runner over fake cores in a fresh data directory, with the short
// timings of the tests and a wall clock the test can shift.
type rig struct {
	d      Dirs
	stage  string
	r      *Runner
	offset atomic.Int64 // added to the real clock by Config.Now
}

// newRig returns a runner that is not booted yet. tune may change its config.
func newRig(t *testing.T, tune func(*Config)) *rig {
	t.Helper()
	g := &rig{d: newDirs(t), stage: t.TempDir()}
	cfg := Config{
		Supervisor: SupervisorConfig{Dirs: g.d, StageDir: g.stage, StopGrace: 2 * time.Second},
		EarlyExit:  200 * time.Millisecond,
		BackoffMin: 50 * time.Millisecond,
		BackoffMax: 200 * time.Millisecond,
		Now:        g.now,
	}
	if tune != nil {
		tune(&cfg)
	}
	g.r = New(cfg)
	t.Cleanup(func() {
		if err := g.r.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return g
}

func (g *rig) now() time.Time { return time.Now().Add(time.Duration(g.offset.Load())) }

// core installs the fake xray of a mode as core ver, writes a config for it
// and returns the selection.
func (g *rig) core(t *testing.T, ver, mode string) runnerapi.Selection {
	t.Helper()
	installFake(t, g.d, ver, mode)
	sel := runnerapi.Selection{Core: ver, Config: fmt.Sprintf("config/%x.json", sha256.Sum256([]byte(ver)))}
	writeFile(t, g.d.ConfigPath(sel.Config), "{}")
	return sel
}

// active installs core 26.1.18 in a mode and makes it active.json's selection.
func (g *rig) active(t *testing.T, mode string) runnerapi.Selection {
	t.Helper()
	sel := g.core(t, oldCore, mode)
	if err := WriteActive(g.d, sel); err != nil {
		t.Fatal(err)
	}
	return sel
}

// candidate installs core 26.10.21 in a mode and writes a candidate.json for
// it whose deadline is in from the runner's clock.
func (g *rig) candidate(t *testing.T, mode string, in time.Duration) runnerapi.Candidate {
	t.Helper()
	c := runnerapi.Candidate{Selection: g.core(t, newCore, mode), Deadline: g.now().Add(in)}
	writeCandidate(t, g.d, c)
	return c
}

func (g *rig) boot(t *testing.T) {
	t.Helper()
	if err := g.r.Boot(); err != nil {
		t.Fatalf("Boot: %v", err)
	}
}

func (g *rig) trial(t *testing.T) {
	t.Helper()
	if err := g.r.Trial(t.Context()); err != nil {
		t.Fatalf("Trial: %v", err)
	}
}

// runningCore is the core of the xray running now, "" when none runs.
func (g *rig) runningCore() string {
	path, ok := g.r.RunningBinary()
	if !ok {
		return ""
	}
	return filepath.Base(filepath.Dir(path))
}

// waitState waits until the runner is in state and runs core ("" for none).
func (g *rig) waitState(t *testing.T, timeout time.Duration, state, core string) {
	t.Helper()
	waitFor(t, timeout, fmt.Sprintf("state %s running %q", state, core), func() bool {
		return g.r.Status().State == state && g.runningCore() == core
	})
}

// wantState fails unless the runner is in state and runs core right now.
func (g *rig) wantState(t *testing.T, state, core string) {
	t.Helper()
	if st, got := g.r.Status(), g.runningCore(); st.State != state || got != core {
		t.Fatalf("state %s running %q (status %+v); want %s running %q", st.State, got, st, state, core)
	}
}

// wantLastTrial checks how the last trial ended, on disk and in Status.
func (g *rig) wantLastTrial(t *testing.T, outcome string, cand runnerapi.Candidate) {
	t.Helper()
	got, err := ReadLastTrial(g.d)
	if err != nil || got == nil {
		t.Fatalf("last-trial.json = %+v, %v; want outcome %s", got, err, outcome)
	}
	if got.Outcome != outcome || got.Candidate.Selection != cand.Selection || !got.Candidate.Deadline.Equal(cand.Deadline) {
		t.Errorf("last trial = %s of %+v; want %s of %+v", got.Outcome, got.Candidate, outcome, cand)
	}
	if st := g.r.Status().LastTrial; st == nil || st.Outcome != outcome || st.Candidate.Selection != cand.Selection {
		t.Errorf("Status().LastTrial = %+v; want outcome %s", st, outcome)
	}
}

// wantNoLastTrial fails if any trial result was recorded.
func (g *rig) wantNoLastTrial(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(g.d.LastTrial()); !os.IsNotExist(err) {
		t.Errorf("last-trial.json exists (stat err %v); want none", err)
	}
	if lt := g.r.Status().LastTrial; lt != nil {
		t.Errorf("Status().LastTrial = %+v; want nil", lt)
	}
}

func (g *rig) wantNoCandidate(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(g.d.CandidateFile()); !os.IsNotExist(err) {
		t.Errorf("candidate.json still exists (stat err %v)", err)
	}
}

// waitFor polls cond until it holds, failing after timeout.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestBootEmpty(t *testing.T) {
	g := newRig(t, nil)
	g.boot(t)
	st := g.r.Status()
	if st.State != runnerapi.StateEmpty || st.XrayPID != 0 || g.r.sup.PID() != 0 || st.Active != nil {
		t.Errorf("status = %+v, PID() = %d; want empty with no xray", st, g.r.sup.PID())
	}
	if g.r.Healthy() {
		t.Error("Healthy with no xray")
	}
	g.r.SetNet(true, false)
	if st := g.r.Status(); !st.RoutesOK || st.GatewayUp {
		t.Errorf("after SetNet(true, false): routes_ok %v gateway_up %v", st.RoutesOK, st.GatewayUp)
	}
}

func TestTrialCommit(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "ok")
	g.boot(t)
	activePID := g.r.Status().XrayPID
	cand := g.candidate(t, "ok", 5*time.Second)
	g.trial(t)

	st := g.r.Status()
	if st.State != runnerapi.StateTrial || st.Candidate == nil || st.Candidate.Selection != cand.Selection {
		t.Fatalf("status after Trial = %+v; want a trial of %+v", st, cand.Selection)
	}
	if got := g.runningCore(); got != newCore {
		t.Fatalf("running core %q during the trial, want %s", got, newCore)
	}
	pid := st.XrayPID
	if pid <= 0 || pid == activePID || !gone(activePID) {
		t.Fatalf("candidate PID %d, active PID %d gone = %v; want the candidate alone", pid, activePID, gone(activePID))
	}
	if st.XrayVersion != "Xray 99.0.0 (fake ok)" {
		t.Errorf("xray_version = %q", st.XrayVersion)
	}
	if !g.r.Healthy() {
		t.Error("not Healthy during the trial")
	}

	if err := g.r.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	st = g.r.Status()
	if st.State != runnerapi.StateRunning || st.Candidate != nil || st.Active == nil || *st.Active != cand.Selection {
		t.Errorf("status after Commit = %+v; want running %+v", st, cand.Selection)
	}
	if st.XrayPID != pid || gone(pid) {
		t.Errorf("PID %d after Commit, want the candidate's %d still running", st.XrayPID, pid)
	}
	if a, err := ReadActive(g.d); err != nil || a == nil || *a != cand.Selection {
		t.Errorf("ReadActive = %+v, %v; want %+v", a, err, cand.Selection)
	}
	g.wantNoCandidate(t)
	g.wantLastTrial(t, runnerapi.OutcomeCommitted, cand)
	if !g.r.Healthy() {
		t.Error("not Healthy after Commit")
	}
	if err := g.r.Commit(); !errors.Is(err, runnerapi.ErrNoTrial) {
		t.Errorf("second Commit = %v, want ErrNoTrial", err)
	}
}

func TestCommitStopsDeadline(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "ok")
	g.boot(t)
	g.candidate(t, "ok", 400*time.Millisecond)
	g.trial(t)
	pid := g.r.Status().XrayPID
	if err := g.r.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	time.Sleep(800 * time.Millisecond) // past the deadline
	g.wantState(t, runnerapi.StateRunning, newCore)
	if got := g.r.Status().XrayPID; got != pid {
		t.Errorf("PID %d after the old deadline, want %d: the committed core was restarted", got, pid)
	}
	if lt, _ := ReadLastTrial(g.d); lt == nil || lt.Outcome != runnerapi.OutcomeCommitted {
		t.Errorf("last trial = %+v, want committed", lt)
	}
}

func TestTrialRejected(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "ok")
	g.boot(t)
	pid := g.r.Status().XrayPID
	cand := g.candidate(t, "badconfig", 5*time.Second)

	err := g.r.Trial(t.Context())
	var tf *runnerapi.TestFailedError
	if !errors.As(err, &tf) || !strings.Contains(tf.Output, "failed to load config") {
		t.Fatalf("Trial = %v; want a *TestFailedError with xray's output", err)
	}
	g.wantState(t, runnerapi.StateRunning, oldCore)
	if got := g.r.Status().XrayPID; got != pid || gone(pid) {
		t.Errorf("PID %d (old %d gone = %v); want the active xray untouched", got, pid, gone(pid))
	}
	g.wantLastTrial(t, runnerapi.OutcomeRejected, cand)
	g.wantNoCandidate(t)
}

func TestTrialExitReverts(t *testing.T) {
	t.Parallel()
	g := newRig(t, nil)
	g.active(t, "ok")
	g.boot(t)
	cand := g.candidate(t, "exit2s", 30*time.Second)
	g.trial(t)
	g.waitState(t, 4*time.Second, runnerapi.StateRunning, oldCore)
	g.wantLastTrial(t, runnerapi.OutcomeExited, cand)
	g.wantNoCandidate(t)
}

func TestTrialLateExitReverts(t *testing.T) {
	t.Parallel()
	g := newRig(t, nil)
	g.active(t, "ok")
	g.boot(t)
	cand := g.candidate(t, "exit15s", 30*time.Second)
	g.trial(t)
	time.Sleep(time.Second) // well past EarlyExit
	g.wantState(t, runnerapi.StateTrial, newCore)
	g.waitState(t, 20*time.Second, runnerapi.StateRunning, oldCore)
	g.wantLastTrial(t, runnerapi.OutcomeExited, cand)
	g.wantNoCandidate(t)
}

func TestTrialDeadlineReverts(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "ok")
	g.boot(t)
	cand := g.candidate(t, "ok", 500*time.Millisecond)
	g.trial(t)
	candPID := g.r.Status().XrayPID
	g.waitState(t, 2*time.Second, runnerapi.StateRunning, oldCore)
	g.wantLastTrial(t, runnerapi.OutcomeDeadline, cand)
	g.wantNoCandidate(t)
	if !gone(candPID) {
		t.Errorf("the candidate %d still runs after the revert", candPID)
	}
}

func TestDeadlineIsMonotonic(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "ok")
	g.boot(t)

	// The runner's clock is an hour behind the real one. A deadline compared
	// with the real clock would already have passed.
	g.offset.Store(int64(-time.Hour))
	cand := g.candidate(t, "ok", 500*time.Millisecond)
	g.trial(t)
	g.wantState(t, runnerapi.StateTrial, newCore)
	g.waitState(t, 2*time.Second, runnerapi.StateRunning, oldCore)
	g.wantLastTrial(t, runnerapi.OutcomeDeadline, cand)

	// The clock jumps an hour ahead once the trial runs: no early revert.
	g.offset.Store(0)
	cand = g.candidate(t, "ok", 1500*time.Millisecond)
	g.trial(t)
	g.offset.Store(int64(time.Hour))
	time.Sleep(300 * time.Millisecond)
	g.wantState(t, runnerapi.StateTrial, newCore)
	g.waitState(t, 3*time.Second, runnerapi.StateRunning, oldCore)
	g.wantLastTrial(t, runnerapi.OutcomeDeadline, cand)
}

func TestMaxTrialCapsDeadline(t *testing.T) {
	g := newRig(t, func(c *Config) { c.MaxTrial = 300 * time.Millisecond })
	g.active(t, "ok")
	g.boot(t)
	cand := g.candidate(t, "ok", time.Hour)
	g.trial(t)
	g.waitState(t, 2*time.Second, runnerapi.StateRunning, oldCore)
	g.wantLastTrial(t, runnerapi.OutcomeDeadline, cand)
}

func TestTrialBusy(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "ok")
	g.boot(t)
	g.candidate(t, "ok", 5*time.Second)
	g.trial(t)
	pid := g.r.Status().XrayPID
	if err := g.r.Trial(t.Context()); !errors.Is(err, runnerapi.ErrBusy) {
		t.Fatalf("second Trial = %v, want ErrBusy", err)
	}
	g.wantState(t, runnerapi.StateTrial, newCore)
	if got := g.r.Status().XrayPID; got != pid {
		t.Errorf("PID %d after the refused Trial, want %d", got, pid)
	}
	if _, err := os.Stat(g.d.CandidateFile()); err != nil {
		t.Errorf("candidate.json of the open trial is gone: %v", err)
	}
}

func TestAbort(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "ok")
	g.boot(t)
	if err := g.r.Abort(); !errors.Is(err, runnerapi.ErrNoTrial) {
		t.Fatalf("Abort outside a trial = %v, want ErrNoTrial", err)
	}
	cand := g.candidate(t, "ok", 5*time.Second)
	g.trial(t)
	if err := g.r.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	g.wantState(t, runnerapi.StateRunning, oldCore)
	g.wantLastTrial(t, runnerapi.OutcomeAborted, cand)
	g.wantNoCandidate(t)
	if err := g.r.Abort(); !errors.Is(err, runnerapi.ErrNoTrial) {
		t.Errorf("second Abort = %v, want ErrNoTrial", err)
	}
}

// A revert whose candidate cannot be stopped still ends the trial: no later
// request may find a trial without a candidate, which would bring down the
// runner (PID 1) on a nil candidate. The runner is left restarting, and the
// restart tries again.
func TestRevertWhenStopFails(t *testing.T) {
	g := newRig(t, nil)
	var fails atomic.Int32 // how many stop signals fail from now on
	g.r.sup.signal = func(p *os.Process, sig os.Signal) error {
		if fails.Add(-1) >= 0 {
			return errors.New("operation not permitted")
		}
		return p.Signal(sig)
	}
	g.active(t, "ok")
	g.boot(t)
	cand := g.candidate(t, "ok", 5*time.Second)
	g.trial(t)
	candPID := g.r.Status().XrayPID

	fails.Store(2) // the revert's stop, and the one before the active core starts
	if err := g.r.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if err := g.r.Commit(); !errors.Is(err, runnerapi.ErrNoTrial) {
		t.Errorf("Commit after the failed revert = %v, want ErrNoTrial", err)
	}
	if st := g.r.Status(); st.State == runnerapi.StateTrial || st.Candidate != nil {
		t.Errorf("status after the failed revert = %+v; want the trial over", st)
	}
	g.wantLastTrial(t, runnerapi.OutcomeAborted, cand)
	g.wantNoCandidate(t)

	// The restart stops the candidate this time and starts the active core.
	g.waitState(t, 5*time.Second, runnerapi.StateRunning, oldCore)
	waitFor(t, 5*time.Second, "the candidate to be gone", func() bool { return gone(candPID) })
}

// The staging directory keeps only the cores that run or are active: after a
// boot, a revert, a rejection and a commit the others go, and so does what an
// interrupted staging or test left there.
func TestStageDirSwept(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "ok")
	// What earlier runs left: another core, half a copy and a test config.
	writeFile(t, filepath.Join(g.stage, "26.3.27", "xray"), "an old staged core")
	writeFile(t, filepath.Join(g.stage, oldCore, ".xray.tmp-123"), "half a copy")
	writeFile(t, filepath.Join(g.stage, ".test-config-456.json"), "{}")
	g.boot(t)
	wantStaged(t, g.stage, oldCore)

	g.candidate(t, "ok", 5*time.Second)
	g.trial(t)
	wantStaged(t, g.stage, oldCore, newCore)
	if err := g.r.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	wantStaged(t, g.stage, oldCore)

	g.candidate(t, "badconfig", 5*time.Second)
	var tf *runnerapi.TestFailedError
	if err := g.r.Trial(t.Context()); !errors.As(err, &tf) {
		t.Fatalf("Trial of a bad config = %v, want a TestFailedError", err)
	}
	wantStaged(t, g.stage, oldCore)

	cand := g.candidate(t, "ok", 5*time.Second)
	g.trial(t)
	if err := g.r.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	wantStaged(t, g.stage, cand.Core)
	g.wantState(t, runnerapi.StateRunning, newCore)
}

// wantStaged fails unless dir holds exactly the staged copies of cores.
func wantStaged(t *testing.T, dir string, cores ...string) {
	t.Helper()
	var got, want []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			got = append(got, rel)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cores {
		want = append(want, filepath.Join(c, "xray"))
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("staging directory holds %q, want %q", got, want)
	}
}

func TestBootDuringTrial(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "ok")
	cand := g.candidate(t, "ok", time.Minute)
	g.boot(t)
	g.wantState(t, runnerapi.StateRunning, oldCore)
	g.wantNoCandidate(t)
	g.wantLastTrial(t, runnerapi.OutcomeReboot, cand)
}

func TestBootAfterCommitCrash(t *testing.T) {
	g := newRig(t, nil)
	sel := g.active(t, "ok")
	writeCandidate(t, g.d, runnerapi.Candidate{Selection: sel, Deadline: g.now().Add(time.Minute)})
	g.boot(t)
	g.wantState(t, runnerapi.StateRunning, oldCore)
	g.wantNoCandidate(t)
	g.wantNoLastTrial(t)
}

func TestBootRemovesInvalidCandidate(t *testing.T) {
	for name, body := range map[string]string{
		"garbage":       "{not json",
		"bad selection": `{"core":"../x","config":"config/x.json","deadline":"2026-10-25T12:00:00Z"}`,
	} {
		t.Run(name, func(t *testing.T) {
			g := newRig(t, nil)
			g.active(t, "ok")
			writeFile(t, g.d.CandidateFile(), body)
			g.boot(t)
			g.wantState(t, runnerapi.StateRunning, oldCore)
			g.wantNoCandidate(t)
			g.wantNoLastTrial(t)
		})
	}
}

func TestBootIgnoresBadLastTrial(t *testing.T) {
	for name, body := range map[string]string{
		"garbage":       "{not json",
		"bad selection": `{"candidate":{"core":"../x","config":"c","deadline":"2026-10-25T12:00:00Z"},"outcome":"exited","at":"2026-10-25T12:00:00Z"}`,
	} {
		t.Run(name, func(t *testing.T) {
			g := newRig(t, nil)
			g.active(t, "ok")
			writeFile(t, g.d.LastTrial(), body)
			g.boot(t)
			g.wantState(t, runnerapi.StateRunning, oldCore)
			if lt := g.r.Status().LastTrial; lt != nil {
				t.Errorf("Status().LastTrial = %+v, want nil", lt)
			}
		})
	}
}

func TestBootTwice(t *testing.T) {
	g := newRig(t, nil)
	g.boot(t)
	if err := g.r.Boot(); err == nil {
		t.Error("a second Boot succeeded")
	}
}

func TestCrashRestartsWithBackoff(t *testing.T) {
	t.Parallel()
	g := newRig(t, nil)
	g.active(t, "exit2s")
	g.boot(t)
	first := g.r.Status().XrayPID
	if first <= 0 {
		t.Fatalf("PID %d after Boot", first)
	}
	// Poll tightly: the first backoff lasts only 50 ms, so a missed one is
	// caught at the next crash, whose backoff is longer.
	sawRestarting := false
	deadline := time.Now().Add(10 * time.Second)
	for {
		st := g.r.Status()
		if st.State == runnerapi.StateRestarting {
			sawRestarting = true
			if st.XrayPID != 0 {
				t.Fatalf("PID %d while restarting", st.XrayPID)
			}
		}
		if sawRestarting && st.State == runnerapi.StateRunning && st.XrayPID > 0 && st.XrayPID != first {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no restart through restarting within 10s (saw restarting %v, status %+v)", sawRestarting, st)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBackoffDoublesAndResets(t *testing.T) {
	c := Config{BackoffMin: 50 * time.Millisecond, BackoffMax: 200 * time.Millisecond}
	var cur time.Duration
	var got []time.Duration
	for range 4 {
		var d time.Duration
		d, cur = nextBackoff(cur, 2*time.Second, c)
		got = append(got, d)
	}
	want := []time.Duration{50 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond, 200 * time.Millisecond}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("delays %v, want %v", got, want)
	}
	if d, next := nextBackoff(cur, time.Minute, c); d != c.BackoffMin || next != 2*c.BackoffMin {
		t.Errorf("after a minute up: delay %v next %v; want %v then %v", d, next, c.BackoffMin, 2*c.BackoffMin)
	}
}

func TestTrialFromEmpty(t *testing.T) {
	t.Parallel()
	g := newRig(t, nil)
	g.boot(t)
	cand := g.candidate(t, "exit2s", 30*time.Second)
	g.trial(t)
	g.wantState(t, runnerapi.StateTrial, newCore)
	g.waitState(t, 4*time.Second, runnerapi.StateEmpty, "")
	if pid := g.r.Status().XrayPID; pid != 0 {
		t.Errorf("PID %d after reverting to empty", pid)
	}
	g.wantLastTrial(t, runnerapi.OutcomeExited, cand)
	g.wantNoCandidate(t)
}

func TestRunningBinary(t *testing.T) {
	g := newRig(t, nil)
	if path, ok := g.r.RunningBinary(); ok {
		t.Errorf("RunningBinary before Boot = %q, true", path)
	}
	g.active(t, "ok")
	g.boot(t)
	path, ok := g.r.RunningBinary()
	if want := filepath.Join(g.stage, oldCore, "xray"); !ok || path != want {
		t.Fatalf("RunningBinary = %q, %v; want %q", path, ok, want)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("running binary %v, err %v; want a staged copy with mode 0755", fi, err)
	}
	g.candidate(t, "ok", 5*time.Second)
	g.trial(t)
	if path, ok := g.r.RunningBinary(); !ok || path != filepath.Join(g.stage, newCore, "xray") {
		t.Errorf("RunningBinary during the trial = %q, %v; want the candidate's", path, ok)
	}
	if err := g.r.Abort(); err != nil {
		t.Fatal(err)
	}
	if path, ok := g.r.RunningBinary(); !ok || path != filepath.Join(g.stage, oldCore, "xray") {
		t.Errorf("RunningBinary after Abort = %q, %v; want the active one", path, ok)
	}
}

func TestTrialRefusesBadCandidate(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "ok")
	g.boot(t)
	pid := g.r.Status().XrayPID
	sel := g.core(t, newCore, "ok")
	for name, write := range map[string]func(){
		"missing": func() { os.Remove(g.d.CandidateFile()) },
		"garbage": func() { writeFile(t, g.d.CandidateFile(), "{not json") },
		"past deadline": func() {
			writeCandidate(t, g.d, runnerapi.Candidate{Selection: sel, Deadline: g.now().Add(-time.Second)})
		},
	} {
		write()
		if err := g.r.Trial(t.Context()); !errors.Is(err, ErrInvalidCandidate) {
			t.Errorf("%s: Trial = %v, want ErrInvalidCandidate", name, err)
		}
		g.wantState(t, runnerapi.StateRunning, oldCore)
		if got := g.r.Status().XrayPID; got != pid {
			t.Errorf("%s: PID %d, want the active %d untouched", name, got, pid)
		}
	}
	g.wantNoLastTrial(t)
}

func TestCommitAfterCandidateExit(t *testing.T) {
	t.Parallel()
	g := newRig(t, nil)
	active := g.active(t, "ok")
	g.boot(t)
	cand := g.candidate(t, "exit2s", 30*time.Second)
	g.trial(t)
	// Hold the runner's goroutine until the candidate is dead and take its
	// exit, as if it had not arrived yet. The Commit that follows must still
	// see a dead candidate: it must never become active.
	hold := func() error {
		deadline := time.Now().Add(5 * time.Second)
		for g.r.sup.PID() != 0 {
			if time.Now().After(deadline) {
				return errors.New("the candidate never exited")
			}
			time.Sleep(time.Millisecond)
		}
		select {
		case <-g.r.sup.Exits():
		case <-time.After(time.Second):
			return errors.New("no exit was reported")
		}
		return nil
	}
	if err := g.r.do(t.Context(), hold); err != nil {
		t.Fatal(err)
	}
	if err := g.r.Commit(); !errors.Is(err, runnerapi.ErrNoTrial) {
		t.Fatalf("Commit after the candidate exited = %v, want ErrNoTrial", err)
	}
	if a, err := ReadActive(g.d); err != nil || a == nil || *a != active {
		t.Errorf("ReadActive = %+v, %v; want the old active %+v", a, err, active)
	}
	g.wantState(t, runnerapi.StateRunning, oldCore)
	g.wantLastTrial(t, runnerapi.OutcomeExited, cand)
}

// TestCommitAtDeadline holds the runner until the deadline has fired with a
// Commit queued, so both are ready at once. Either may win, but the result
// must be consistent.
func TestCommitAtDeadline(t *testing.T) {
	outcomes := map[string]int{}
	for i := range 5 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			g := newRig(t, nil)
			active := g.active(t, "ok")
			g.boot(t)
			cand := g.candidate(t, "ok", 200*time.Millisecond)
			g.trial(t)
			pid := g.r.Status().XrayPID
			held, holdDone := make(chan struct{}), make(chan error, 1)
			go func() {
				holdDone <- g.r.do(t.Context(), func() error {
					close(held)
					time.Sleep(400 * time.Millisecond)
					return nil
				})
			}()
			<-held
			err := g.r.Commit()
			if herr := <-holdDone; herr != nil {
				t.Fatal(herr)
			}
			switch {
			case err == nil:
				outcomes["committed"]++
				g.wantState(t, runnerapi.StateRunning, newCore)
				g.wantLastTrial(t, runnerapi.OutcomeCommitted, cand)
				if a, _ := ReadActive(g.d); a == nil || *a != cand.Selection {
					t.Errorf("active.json = %+v after a commit, want %+v", a, cand.Selection)
				}
				time.Sleep(200 * time.Millisecond)
				if st := g.r.Status(); st.State != runnerapi.StateRunning || st.XrayPID != pid {
					t.Errorf("after the commit: %+v; want the candidate %d still running", st, pid)
				}
			case errors.Is(err, runnerapi.ErrNoTrial):
				outcomes["deadline"]++
				g.wantState(t, runnerapi.StateRunning, oldCore)
				g.wantLastTrial(t, runnerapi.OutcomeDeadline, cand)
				if a, _ := ReadActive(g.d); a == nil || *a != active {
					t.Errorf("active.json = %+v after the deadline, want %+v", a, active)
				}
			default:
				t.Fatalf("Commit = %v, want nil or ErrNoTrial", err)
			}
			g.wantNoCandidate(t)
		})
	}
	t.Logf("outcomes: %v", outcomes)
}

// TestStaleExitIgnored delivers exits of earlier processes during a trial:
// one of another selection, and one of the candidate's selection while the
// candidate still runs. Neither may end the trial.
func TestStaleExitIgnored(t *testing.T) {
	g := newRig(t, nil)
	active := g.active(t, "ok")
	g.boot(t)
	cand := g.candidate(t, "ok", 5*time.Second)
	g.trial(t)
	pid := g.r.Status().XrayPID
	g.r.sup.exits <- Exit{Selection: active, Err: errors.New("exit status 1"), Ran: time.Second}
	g.r.sup.exits <- Exit{Selection: cand.Selection, Err: errors.New("exit status 1"), Ran: time.Second}
	time.Sleep(200 * time.Millisecond)
	g.wantState(t, runnerapi.StateTrial, newCore)
	if got := g.r.Status().XrayPID; got != pid {
		t.Errorf("PID %d, want the candidate %d untouched", got, pid)
	}
	if err := g.r.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

func TestStatusDuringSlowTest(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "ok")
	g.boot(t)
	g.candidate(t, "slowtest", 10*time.Second)
	errc := make(chan error, 1)
	go func() { errc <- g.r.Trial(t.Context()) }()
	time.Sleep(300 * time.Millisecond) // xray run -test takes a second
	start := time.Now()
	st := g.r.Status()
	healthy := g.r.Healthy()
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Errorf("Status and Healthy took %v during xray run -test", took)
	}
	if st.State != runnerapi.StateRunning || !healthy {
		t.Errorf("during xray run -test: state %s healthy %v; want running and healthy", st.State, healthy)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Trial: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Trial did not return")
	}
	g.wantState(t, runnerapi.StateTrial, newCore)
}

func TestTrialCanceled(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "ok")
	g.boot(t)
	pid := g.r.Status().XrayPID
	g.candidate(t, "slowtest", 10*time.Second)
	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)
	go func() { errc <- g.r.Trial(ctx) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled Trial = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled Trial did not return")
	}
	g.wantState(t, runnerapi.StateRunning, oldCore)
	if got := g.r.Status().XrayPID; got != pid {
		t.Errorf("PID %d, want the active %d untouched", got, pid)
	}
	g.wantNoLastTrial(t)
}

// TestTrialTestTimeout gives a candidate whose xray run -test takes a second
// a 300 ms deadline: the test is cut off at the deadline and rejected, and
// the active xray is left alone.
func TestTrialTestTimeout(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "ok")
	g.boot(t)
	pid := g.r.Status().XrayPID
	cand := g.candidate(t, "slowtest", 300*time.Millisecond)
	start := time.Now()
	err := g.r.Trial(t.Context())
	took := time.Since(start)
	var tf *runnerapi.TestFailedError
	if !errors.As(err, &tf) || !strings.Contains(tf.Output, "did not finish") {
		t.Fatalf("Trial = %v; want a *TestFailedError saying the test did not finish", err)
	}
	if took > 900*time.Millisecond {
		t.Errorf("Trial took %v; want xray run -test cut off at the 300ms deadline", took)
	}
	g.wantState(t, runnerapi.StateRunning, oldCore)
	if got := g.r.Status().XrayPID; got != pid || gone(pid) {
		t.Errorf("PID %d (old %d gone = %v); want the active xray untouched", got, pid, gone(pid))
	}
	g.wantLastTrial(t, runnerapi.OutcomeRejected, cand)
	g.wantNoCandidate(t)
}

func TestRestartAndReload(t *testing.T) {
	g := newRig(t, nil)
	if err := g.r.Restart(t.Context()); err == nil {
		t.Error("Restart with no active selection succeeded")
	}
	g.active(t, "ok")
	g.boot(t)
	first := g.r.Status().XrayPID

	if err := g.r.Restart(t.Context()); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	g.wantState(t, runnerapi.StateRunning, oldCore)
	if pid := g.r.Status().XrayPID; pid == first || !gone(first) {
		t.Errorf("PID %d after Restart (first %d gone = %v); want a new process", pid, first, gone(first))
	}

	sel := g.core(t, newCore, "ok")
	if err := WriteActive(g.d, sel); err != nil {
		t.Fatal(err)
	}
	if err := g.r.Reload(t.Context()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	g.wantState(t, runnerapi.StateRunning, newCore)
	if st := g.r.Status(); st.Active == nil || *st.Active != sel {
		t.Errorf("active after Reload = %+v, want %+v", st.Active, sel)
	}

	pid := g.r.Status().XrayPID
	writeFile(t, g.d.Active(), "{not json")
	if err := g.r.Reload(t.Context()); err == nil {
		t.Error("Reload of a corrupt active.json succeeded")
	}
	g.wantState(t, runnerapi.StateRunning, newCore)
	if got := g.r.Status().XrayPID; got != pid {
		t.Errorf("PID %d after a refused Reload, want %d untouched", got, pid)
	}
	if err := WriteActive(g.d, sel); err != nil {
		t.Fatal(err)
	}

	g.candidate(t, "ok", 5*time.Second)
	g.trial(t)
	if err := g.r.Restart(t.Context()); !errors.Is(err, runnerapi.ErrBusy) {
		t.Errorf("Restart during a trial = %v, want ErrBusy", err)
	}
	if err := g.r.Reload(t.Context()); !errors.Is(err, runnerapi.ErrBusy) {
		t.Errorf("Reload during a trial = %v, want ErrBusy", err)
	}
	if err := g.r.Abort(); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(g.d.Active()); err != nil {
		t.Fatal(err)
	}
	if err := g.r.Reload(t.Context()); err != nil {
		t.Fatalf("Reload without active.json: %v", err)
	}
	g.wantState(t, runnerapi.StateEmpty, "")
	if pid := g.r.Status().XrayPID; pid != 0 {
		t.Errorf("PID %d after reloading no active.json", pid)
	}
}
