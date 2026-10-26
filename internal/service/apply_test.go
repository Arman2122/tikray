package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/health"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xray"
)

var bg = context.Background()

// vlessID is a server credential that the tests' xray output repeats.
const vlessID = "b831381d-6324-4d53-ad4f-8cda48b30811"

const vlessOutbound = `{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443,"users":[{"encryption":"none","id":"` + vlessID + `"}]}]}}`

// hideID is v as %+v prints it, with vlessID in place of the id, so that a
// failure message never shows it.
func hideID(v any) string {
	return strings.ReplaceAll(fmt.Sprintf("%+v", v), vlessID, "<the id>")
}

// wantStatus fails unless the status says applied and pending as given.
func wantStatus(t *testing.T, s *Service, applied, pending bool) Status {
	t.Helper()
	st := s.Status(bg)
	if st.Applied != applied || st.Pending != pending {
		t.Errorf("Status: applied %t, pending %t; want %t, %t", st.Applied, st.Pending, applied, pending)
	}
	return st
}

// wantTrials fails unless the runner had trials of exactly the configs.
func wantTrials(t *testing.T, e *env, configs ...string) {
	t.Helper()
	var got []string
	for _, c := range e.runner.gotTrials() {
		got = append(got, c.Config)
	}
	if !slices.Equal(got, configs) {
		t.Errorf("trials of %v, want %v", got, configs)
	}
}

func TestKickDebounces(t *testing.T) {
	e := newEnv(t)
	e.edit()
	e.inSync()
	e.start()
	e.wantNoTimers()

	var st store.State
	for i := range 3 {
		if i > 0 {
			e.advance(500 * time.Millisecond)
		}
		st, _ = e.edit()
		e.kick()
	}
	wantStatus(t, e.s, false, true)
	// Each kick starts the wait again: 2 s after the first two kicks have
	// passed, but not 2 s after the last.
	e.advance(1500 * time.Millisecond)
	wantTrials(t, e)
	e.advance(500 * time.Millisecond)
	wantTrials(t, e, configOf(t, st))
	if got, want := e.clock.armed(), []time.Duration{2 * time.Second, 2 * time.Second, 2 * time.Second}; !slices.Equal(got, want) {
		t.Errorf("timers armed for %v, want %v", got, want)
	}
	e.wantNoTimers()
	got := wantStatus(t, e.s, true, false)
	if got.LastApply == nil || got.LastApply.Outcome != runnerapi.OutcomeCommitted {
		t.Errorf("LastApply = %+v, want committed", got.LastApply)
	}
	if got.Core != testCore || !got.CoreTested {
		t.Errorf("Status: core %q, tested %t; want %s, tested", got.Core, got.CoreTested, testCore)
	}
}

func TestApplyCatchesUpWithLaterEdits(t *testing.T) {
	e := newEnv(t)
	st1, _ := e.edit()
	e.outOfSync()
	e.runner.hold()
	e.start() // out of sync at revision 1: the start kicks
	e.clock.advance(2 * time.Second)
	within(t, "the first trial", e.runner.waiting)

	// An edit lands while the first apply runs.
	st2, rev2 := e.edit()
	e.s.Kick()
	wantStatus(t, e.s, false, true)
	e.runner.release()
	e.settle()
	if got := e.runner.active().Config; got != configOf(t, st1) {
		t.Errorf("after the first apply the runner runs %s, want revision 1's render", got)
	}
	wantStatus(t, e.s, false, true)

	e.advance(2 * time.Second)
	wantTrials(t, e, configOf(t, st1), configOf(t, st2))
	if got := e.runner.active().Config; got != configOf(t, st2) {
		t.Errorf("the runner runs %s, want revision 2's render", got)
	}
	got := wantStatus(t, e.s, true, false)
	if got.Revision != rev2 {
		t.Errorf("Status.Revision = %d, want %d", got.Revision, rev2)
	}
	e.wantNoTimers()
	applies := e.eventsOf(KindApply)
	if len(applies) != 2 || !strings.Contains(applies[0], "revision 1 ") || !strings.Contains(applies[1], "revision 2 ") {
		t.Errorf("apply events %q, want revision 1's and then revision 2's", applies)
	}
}

// An edit that lands while a core update runs is applied, on the new core,
// once the update is done.
func TestEditDuringCoreUpdateIsApplied(t *testing.T) {
	e := newEnv(t)
	installCore(t, e.data, "26.3.27")
	e.edit()
	e.inSync()
	e.runner.hold()
	e.start()

	type result struct {
		res artifacts.Result
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := e.s.CoreUpdate(bg, "26.3.27", artifacts.UpdateOptions{})
		done <- result{res, err}
	}()
	within(t, "the core update's trial", e.runner.waiting)
	st2, _ := e.edit()
	e.kick()
	e.clock.advance(2 * time.Second) // the pass waits for the update
	within(t, "the pass to wait for the core update", e.lockers)
	e.runner.release()
	r := within(t, "the core update", done)
	if r.err != nil || r.res.Outcome != runnerapi.OutcomeCommitted {
		t.Fatalf("CoreUpdate = %+v, %v; want committed", r.res, r.err)
	}
	e.settle()
	if got, want := e.runner.active(), (runnerapi.Selection{Core: "26.3.27", Config: configOn(t, st2, "26.3.27")}); got != want {
		t.Errorf("the runner runs %+v, want revision 2's render for 26.3.27", got)
	}
	wantStatus(t, e.s, true, false)
	if got := e.eventsOf(KindCore); len(got) != 1 || !strings.Contains(got[0], "26.3.27") {
		t.Errorf("core events %q, want one naming 26.3.27", got)
	}
}

func TestApplyRetriesWhenRunnerDown(t *testing.T) {
	e := newEnv(t)
	st, _ := e.edit()
	e.outOfSync()
	e.runner.setDown(true)
	e.start() // the runner can't say whether the state is applied: kick
	e.advance(2 * time.Second)
	wantStatus(t, e.s, false, true)
	e.advance(10 * time.Second)
	wantStatus(t, e.s, false, true)
	e.runner.setDown(false)
	e.advance(20 * time.Second)

	wantTrials(t, e, configOf(t, st))
	if got, want := e.clock.armed(), []time.Duration{2 * time.Second, 10 * time.Second, 20 * time.Second}; !slices.Equal(got, want) {
		t.Errorf("timers armed for %v, want the debounce, then retries after %v", got, want[1:])
	}
	e.wantNoTimers()
	wantStatus(t, e.s, true, false)
	applies := e.eventsOf(KindApply)
	if len(applies) != 3 ||
		!strings.Contains(applies[0], "can't be reached") || !strings.Contains(applies[0], "trying again in 10s") ||
		!strings.Contains(applies[1], "trying again in 20s") ||
		!strings.Contains(applies[2], "applied") {
		t.Errorf("apply events %q, want two failures that try again, then the apply", applies)
	}
}

// A runner that restarts during the trial reverts it on boot and records the
// outcome reboot: the loop tries again, and Status says pending until then.
func TestApplyRetriesAfterRunnerReboot(t *testing.T) {
	e := newEnv(t)
	st, _ := e.edit()
	e.outOfSync()
	e.runner.hold()
	e.start()
	e.clock.advance(2 * time.Second)
	within(t, "the trial", e.runner.waiting)
	e.runner.rebootNext()
	e.runner.release()
	e.settle()

	got := wantStatus(t, e.s, false, true)
	if got.LastApply == nil || got.LastApply.Outcome != runnerapi.OutcomeReboot {
		t.Fatalf("LastApply = %+v, want reboot", got.LastApply)
	}
	if p := e.clock.pending(); !slices.Equal(p, []time.Duration{10 * time.Second}) {
		t.Fatalf("timers armed for %v after the reboot, want a retry after 10s", p)
	}
	e.advance(10 * time.Second)
	wantTrials(t, e, configOf(t, st), configOf(t, st))
	wantStatus(t, e.s, true, false)
	e.wantNoTimers()
}

// A runner that goes away during the health check fails it, and its abort:
// the outcome is unhealthy, but the runner can't be reached, so the loop
// tries again. (An unhealthy outcome from a runner that answers is not
// retried: TestRejectedIsNotRetried.)
func TestApplyRetriesWhenRunnerGoesAwayInTrial(t *testing.T) {
	e := newEnv(t)
	st, _ := e.edit()
	e.outOfSync()
	e.health.failThen(errors.New("xray's API does not answer"), func() { e.runner.setDown(true) })
	e.start()
	e.advance(2 * time.Second)

	got := wantStatus(t, e.s, false, true)
	if got.LastApply == nil || got.LastApply.Outcome != artifacts.OutcomeUnhealthy {
		t.Fatalf("LastApply = %+v, want unhealthy", got.LastApply)
	}
	if p := e.clock.pending(); !slices.Equal(p, []time.Duration{10 * time.Second}) {
		t.Fatalf("timers armed for %v, want a retry after 10s", p)
	}
	if applies := e.eventsOf(KindApply); len(applies) != 1 || !strings.Contains(applies[0], "trying again in 10s") {
		t.Errorf("apply events %q, want one that tries again", applies)
	}
	e.health.failThen(nil, nil)
	e.runner.restart()
	e.advance(10 * time.Second)
	wantTrials(t, e, configOf(t, st), configOf(t, st))
	wantStatus(t, e.s, true, false)
	e.wantNoTimers()
}

// The wait between retries doubles up to 5 minutes, and a kick meanwhile
// starts the debounce without resetting it.
func TestRetryBackoff(t *testing.T) {
	e := newEnv(t)
	e.edit()
	e.outOfSync()
	e.runner.setDown(true)
	e.start()
	e.advance(2 * time.Second)
	for _, d := range []time.Duration{10, 20, 40, 80, 160, 300, 300} {
		e.advance(d * time.Second)
	}
	e.kick()
	e.advance(2 * time.Second)
	want := []time.Duration{2, 10, 20, 40, 80, 160, 300, 300, 300, 2, 300}
	for i := range want {
		want[i] *= time.Second
	}
	if got := e.clock.armed(); !slices.Equal(got, want) {
		t.Errorf("timers armed for %v, want %v", got, want)
	}
}

func TestRejectedIsNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fail    func(e *env)
		outcome string
	}{
		{"rejected", func(e *env) {
			e.runner.setReject("Failed to start: app/proxyman/outbound: failed to process outbound: user " + vlessID + " is invalid")
		}, runnerapi.OutcomeRejected},
		{"unhealthy", func(e *env) {
			e.health.fail(errors.New("xray's API does not answer for user " + vlessID))
		}, artifacts.OutcomeUnhealthy},
		// A probe through the proxy fails as net/http's calls do, with a
		// *url.Error, while the runner answers: still the config's fault.
		{"unhealthy probe", func(e *env) {
			e.health.fail(&url.Error{Op: "Get", URL: "https://www.gstatic.com/generate_204", Err: errors.New("socks connect: user " + vlessID + " refused")})
		}, artifacts.OutcomeUnhealthy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.addServer("v", vlessOutbound)
			e.outOfSync()
			tc.fail(e)
			e.start()
			e.advance(2 * time.Second)
			if n := len(e.runner.gotTrials()); n != 1 {
				t.Fatalf("%d trials, want 1", n)
			}
			e.wantNoTimers()
			e.advance(time.Hour)
			if n := len(e.runner.gotTrials()); n != 1 {
				t.Fatalf("%d trials an hour later, want still 1", n)
			}
			got := wantStatus(t, e.s, false, false)
			if got.LastApply == nil || got.LastApply.Outcome != tc.outcome {
				t.Fatalf("LastApply = %s, want %s", hideID(got.LastApply), tc.outcome)
			}
			applies := e.eventsOf(KindApply)
			if len(applies) != 1 || !strings.Contains(applies[0], tc.outcome) {
				t.Errorf("apply events %s, want one that says %s", hideID(applies), tc.outcome)
			}
			// The service's redactor is the updater's, whatever the factory set.
			for what, text := range map[string]string{"LastApply.Detail": got.LastApply.Detail, "the event": strings.Join(applies, "\n"), "the history": e.historyText()} {
				if strings.Contains(text, vlessID) {
					t.Errorf("%s holds the server's id", what)
				}
				if !strings.Contains(text, redacted) {
					t.Errorf("%s has no %s where the id was", what, redacted)
				}
			}

			// The next kick tries again, and so does ApplyNow.
			e.kick()
			e.advance(2 * time.Second)
			if n := len(e.runner.gotTrials()); n != 2 {
				t.Errorf("%d trials after a kick, want 2", n)
			}
			res, err := e.s.ApplyNow(bg)
			if err == nil || res.Outcome != tc.outcome {
				t.Errorf("ApplyNow = %s, %s; want %s", hideID(res), hideID(err), tc.outcome)
			}
			if n := len(e.runner.gotTrials()); n != 3 {
				t.Errorf("%d trials after ApplyNow, want 3", n)
			}
		})
	}
}

func TestStartInSyncAppliesNothing(t *testing.T) {
	e := newEnv(t)
	e.edit()
	e.inSync()
	e.start()
	e.wantNoTimers()
	e.advance(time.Hour)
	wantTrials(t, e)
	got := wantStatus(t, e.s, true, false)
	if got.LastApply != nil {
		t.Errorf("LastApply = %+v, want none", got.LastApply)
	}
	if got := e.eventsOf(KindApply); len(got) != 0 {
		t.Errorf("apply events %q, want none", got)
	}
}

// A pass whose render is the runner's config already calls no Apply: nothing
// is put on trial or added to the history.
func TestKickInSyncAppliesNothing(t *testing.T) {
	e := newEnv(t)
	e.edit()
	e.inSync()
	e.start()
	e.kick()
	e.advance(2 * time.Second)
	wantTrials(t, e)
	if h := e.historyText(); h != "" {
		t.Errorf("the history has %q, want nothing", h)
	}
	if got := e.eventsOf(KindApply); len(got) != 1 || !strings.Contains(got[0], "revision 1 is applied already") {
		t.Errorf("apply events %q, want one that says revision 1 is applied", got)
	}
	wantStatus(t, e.s, true, false)
}

// A state that does not render is not applied. Status records the failure
// once, not at every call, and a pass records it as why it applied nothing.
func TestRenderErrorRecordedOnce(t *testing.T) {
	e := newEnv(t)
	e.edit()
	e.inSync()
	e.start()
	e.failRender(errors.New("geosite:xx is not in the geo data"))
	for range 3 {
		wantStatus(t, e.s, false, false)
	}
	if got := e.eventsOf(KindError); len(got) != 1 || !strings.Contains(got[0], "geosite:xx") {
		t.Errorf("error events %q, want one with the render's error", got)
	}
	e.kick()
	e.advance(2 * time.Second)
	wantTrials(t, e)
	e.wantNoTimers()
	if got := e.eventsOf(KindApply); len(got) != 1 || !strings.Contains(got[0], "not applied") || !strings.Contains(got[0], "geosite:xx") {
		t.Errorf("apply events %q, want one that says why nothing was applied", got)
	}
	if got := e.eventsOf(KindError); len(got) != 1 {
		t.Errorf("error events %q after the pass, want still one", got)
	}
	// Once the state renders again, the next failure is news.
	e.failRender(nil)
	wantStatus(t, e.s, true, false)
	e.failRender(errors.New("geoip:yy is not in the geo data"))
	wantStatus(t, e.s, false, false)
	if got := e.eventsOf(KindError); len(got) != 2 {
		t.Errorf("error events %q, want a second one", got)
	}
}

func TestStartOutOfSyncApplies(t *testing.T) {
	e := newEnv(t)
	st, _ := e.edit()
	e.outOfSync()
	e.start()
	if got := e.clock.pending(); !slices.Equal(got, []time.Duration{2 * time.Second}) {
		t.Fatalf("timers armed for %v after the start, want the debounce", got)
	}
	wantStatus(t, e.s, false, true)
	e.advance(2 * time.Second)
	wantTrials(t, e, configOf(t, st))
	wantStatus(t, e.s, true, false)
}

// A state that was never saved is the default one: the start leaves the
// runner's config alone.
func TestStartWithoutStateAppliesNothing(t *testing.T) {
	e := newEnv(t)
	e.outOfSync()
	e.start()
	e.wantNoTimers()
	wantTrials(t, e)
	wantStatus(t, e.s, false, false)
}

func TestCoreUpdateSerialised(t *testing.T) {
	e := newEnv(t)
	st, _ := e.edit()
	e.outOfSync()
	e.runner.hold()
	e.start()
	e.clock.advance(2 * time.Second)
	within(t, "the pass's trial", e.runner.waiting)
	before := len(e.runner.gotCalls())

	type result struct {
		res artifacts.Result
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := e.s.CoreUpdate(bg, testCore, artifacts.UpdateOptions{})
		done <- result{res, err}
	}()
	within(t, "the core update to wait for the pass", e.lockers)
	if calls := e.runner.gotCalls()[before:]; len(calls) != 0 {
		t.Errorf("the core update called the runner (%v) during the pass", calls)
	}
	e.runner.release()
	e.settle()
	r := within(t, "the core update", done)
	// The pass committed the render of the state for testCore, which is
	// what an update to testCore would run: nothing to do.
	if r.err != nil || r.res.Outcome != artifacts.OutcomeNoop {
		t.Errorf("CoreUpdate = %+v, %v; want noop", r.res, r.err)
	}
	wantTrials(t, e, configOf(t, st))
	if got := e.eventsOf(KindCore); len(got) != 1 {
		t.Errorf("core events %q, want one", got)
	}
}

func TestApplyNowSerialised(t *testing.T) {
	e := newEnv(t)
	st, _ := e.edit()
	e.outOfSync()
	e.runner.hold()
	e.start()
	e.clock.advance(2 * time.Second)
	within(t, "the pass's trial", e.runner.waiting)

	type result struct {
		res artifacts.Result
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := e.s.ApplyNow(bg)
		done <- result{res, err}
	}()
	within(t, "ApplyNow to wait for the pass", e.lockers)
	e.runner.release()
	e.settle()
	r := within(t, "ApplyNow", done)
	if r.err != nil || r.res.Outcome != artifacts.OutcomeNoop {
		t.Errorf("ApplyNow = %+v, %v; want noop", r.res, r.err)
	}
	wantTrials(t, e, configOf(t, st))
}

// An operation that waits for another gives up when its context ends.
func TestWaitEndsWithTheContext(t *testing.T) {
	e := newEnv(t)
	e.edit()
	e.outOfSync()
	e.runner.hold()
	e.start()
	e.clock.advance(2 * time.Second)
	within(t, "the pass's trial", e.runner.waiting)

	ctx, cancel := context.WithCancel(bg)
	done := make(chan error, 1)
	go func() {
		_, err := e.s.ApplyNow(ctx)
		done <- err
	}()
	within(t, "ApplyNow to wait for the pass", e.lockers)
	cancel()
	if err := within(t, "ApplyNow", done); !errors.Is(err, context.Canceled) {
		t.Errorf("ApplyNow = %v, want context.Canceled", err)
	}
	e.runner.release()
	e.settle()
	if n := len(e.runner.gotTrials()); n != 1 {
		t.Errorf("%d trials, want the pass's alone", n)
	}
}

func TestRunnerUnavailable(t *testing.T) {
	e := newEnv(t)
	installCore(t, e.data, "26.3.27")
	e.edit()
	e.outOfSync()
	e.runner.setDown(true)

	_, err := e.s.ApplyNow(bg)
	if !errors.Is(err, ErrRunnerUnavailable) {
		t.Errorf("ApplyNow = %v, want ErrRunnerUnavailable", err)
	}
	_, err = e.s.CoreUpdate(bg, "26.3.27", artifacts.UpdateOptions{})
	if !errors.Is(err, ErrRunnerUnavailable) {
		t.Errorf("CoreUpdate = %v, want ErrRunnerUnavailable", err)
	}
	_, err = e.s.CoreRollback(bg)
	if !errors.Is(err, ErrRunnerUnavailable) {
		t.Errorf("CoreRollback = %v, want ErrRunnerUnavailable", err)
	}
	_, err = e.s.Core(bg)
	if !errors.Is(err, ErrRunnerUnavailable) {
		t.Errorf("Core = %v, want ErrRunnerUnavailable", err)
	}
	if err != nil && !strings.HasPrefix(err.Error(), "service: ") {
		t.Errorf("error %q lacks the package prefix", err)
	}
	wantTrials(t, e)
	if got := e.eventsOf(KindApply); len(got) != 1 {
		t.Errorf("apply events %q, want ApplyNow's", got)
	}
	if got := e.eventsOf(KindCore); len(got) != 2 {
		t.Errorf("core events %q, want the update's and the rollback's", got)
	}
	got := wantStatus(t, e.s, false, false)
	if got.Core != "" {
		t.Errorf("Status.Core = %q while the runner is down, want empty", got.Core)
	}
}

// A candidate that fails the proxy probe, which fails as net/http's calls do
// (a *url.Error), is unhealthy while the runner answers throughout: the
// operation's own failure, which the API answers 422 with its result, and not
// ErrRunnerUnavailable, which it answers 503.
func TestUnhealthyProbeIsNotRunnerUnavailable(t *testing.T) {
	e := newEnv(t)
	installCore(t, e.data, "26.3.27")
	installCore(t, e.data, testCore)
	e.edit()
	e.inSync()
	e.start()
	// The rollback goes back to the core this update replaces.
	if _, err := e.s.CoreUpdate(bg, "26.3.27", artifacts.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.edit() // a render that ApplyNow puts on trial
	e.health.fail(&url.Error{Op: "Get", URL: "http://203.0.113.30/whoami", Err: errors.New("socks connect: general failure")})
	for _, op := range []struct {
		name string
		do   func() (artifacts.Result, error)
	}{
		{"ApplyNow", func() (artifacts.Result, error) { return e.s.ApplyNow(bg) }},
		{"CoreUpdate", func() (artifacts.Result, error) { return e.s.CoreUpdate(bg, testCore, artifacts.UpdateOptions{}) }},
		{"CoreRollback", func() (artifacts.Result, error) { return e.s.CoreRollback(bg) }},
	} {
		res, err := op.do()
		if res.Outcome != artifacts.OutcomeUnhealthy || err == nil {
			t.Errorf("%s = %+v, %v; want unhealthy, with its error", op.name, res, err)
		}
		if errors.Is(err, ErrRunnerUnavailable) {
			t.Errorf("%s's error wraps ErrRunnerUnavailable though the runner answered: %v", op.name, err)
		}
	}
	if _, err := e.runner.client().Status(bg); err != nil {
		t.Fatalf("the runner's status: %v", err)
	}
}

// holdArtifactsLock takes the artifacts lock as another update would, until
// the returned function is called.
func holdArtifactsLock(t *testing.T, data string) func() {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(data, "state", "artifacts.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	return func() { f.Close() }
}

// While another update holds the artifacts lock, the loop tries again later,
// and ApplyNow passes ErrLocked on as it is.
func TestLockedRetries(t *testing.T) {
	e := newEnv(t)
	st, _ := e.edit()
	e.outOfSync()
	unlock := holdArtifactsLock(t, e.data)
	e.start()
	e.advance(2 * time.Second)
	wantStatus(t, e.s, false, true)
	if got := e.clock.pending(); !slices.Equal(got, []time.Duration{10 * time.Second}) {
		t.Errorf("timers armed for %v, want a retry after 10s", got)
	}
	_, err := e.s.ApplyNow(bg)
	if !errors.Is(err, artifacts.ErrLocked) || errors.Is(err, ErrRunnerUnavailable) {
		t.Errorf("ApplyNow = %v, want ErrLocked as it is", err)
	}
	unlock()
	e.advance(10 * time.Second)
	wantTrials(t, e, configOf(t, st))
	wantStatus(t, e.s, true, false)
}

func TestCoreInfo(t *testing.T) {
	e := newEnv(t)
	installCore(t, e.data, "26.3.27")
	installCore(t, e.data, testCore)
	st, _ := e.edit()
	e.inSync()
	e.start()
	if _, err := e.s.CoreUpdate(bg, "26.3.27", artifacts.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	info, err := e.s.Core(bg)
	if err != nil {
		t.Fatal(err)
	}
	if info.Active != "26.3.27" {
		t.Errorf("Core().Active = %q, want 26.3.27", info.Active)
	}
	var slots []string
	for _, s := range info.Slots {
		slots = append(slots, s.Version.String())
	}
	if !slices.Equal(slots, []string{testCore, "26.3.27"}) {
		t.Errorf("Core().Slots = %v, want both cores, newest first", slots)
	}
	if len(info.History) != 1 || info.History[0].To != "26.3.27" || info.History[0].Outcome != runnerapi.OutcomeCommitted {
		t.Errorf("Core().History = %+v, want the committed update", info.History)
	}
	if got := e.runner.active().Config; got != configOn(t, st, "26.3.27") {
		t.Errorf("the update runs %s, want the state's render for 26.3.27", got)
	}

	res, err := e.s.CoreRollback(bg)
	if err != nil || res.Outcome != runnerapi.OutcomeCommitted || res.To != testCore {
		t.Fatalf("CoreRollback = %+v, %v; want committed to %s", res, err, testCore)
	}
	if got, want := e.runner.active(), (runnerapi.Selection{Core: testCore, Config: configOf(t, st)}); got != want {
		t.Errorf("after the rollback the runner runs %+v, want the state's render for %s", got, testCore)
	}
	if got := e.eventsOf(KindCore); len(got) != 2 || !strings.HasPrefix(got[1], "rollback: xray-core "+testCore+" is active") {
		t.Errorf("core events %q, want the update's and the rollback's", got)
	}
}

func TestRunTwiceIsRefused(t *testing.T) {
	e := newEnv(t)
	e.start()
	if err := e.s.Run(bg); err == nil {
		t.Error("a second Run while the first runs = nil, want an error")
	}
}

func TestNewNeedsItsParts(t *testing.T) {
	e := newEnv(t)
	full := Config{Store: e.store, Updaters: e.updaters, Runner: e.runner.client(), Data: e.data}
	for name, c := range map[string]Config{
		"Store":    {Updaters: full.Updaters, Runner: full.Runner, Data: full.Data},
		"Updaters": {Store: full.Store, Runner: full.Runner, Data: full.Data},
		"Runner":   {Store: full.Store, Updaters: full.Updaters, Data: full.Data},
		"Data":     {Store: full.Store, Updaters: full.Updaters, Runner: full.Runner},
	} {
		if _, err := New(c); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("New without %s = %v, want an error naming it", name, err)
		}
	}
	if _, err := New(full); err != nil {
		t.Errorf("New = %v", err)
	}
}

// fakeXray is the monitor's view of xray: the servers with tags are dead
// with the error text err, and the balancer query fails with it.
type fakeXray struct {
	tags []string
	err  string
}

func (x fakeXray) OutboundStatus(context.Context) ([]xray.OutboundStatus, error) {
	var out []xray.OutboundStatus
	for _, tag := range x.tags {
		out = append(out, xray.OutboundStatus{Tag: tag, LastError: x.err})
	}
	return out, nil
}

func (x fakeXray) BalancerTargets(context.Context, string) (string, []string, error) {
	return "", nil, errors.New(x.err)
}

// Status carries the monitor's snapshot, with its errors redacted, and Run
// runs the monitor.
func TestStatusHealth(t *testing.T) {
	e := newEnv(t)
	st := e.addServer("v", vlessOutbound)
	e.inSync()
	leak := "dial tcp 203.0.113.10:443: user " + vlessID + " refused"
	m := &health.Monitor{
		Runner:   e.runner.client(),
		Xray:     fakeXray{tags: []string{st.Servers[0].Tag()}, err: leak},
		Probe:    func(store.State) artifacts.HealthChecker { return &stubHealth{err: errors.New(leak)} },
		Interval: time.Hour,
		Now:      e.clock.Now,
	}
	e.s = e.newService(Config{Monitor: m})
	if m.State == nil {
		t.Fatal("New left the monitor's State unset")
	}
	if got := e.s.Status(bg).Health.Level; got != LevelUnknown {
		t.Errorf("Health.Level before the first check = %q, want %q", got, LevelUnknown)
	}
	e.start()
	eventually(t, "the monitor's first check", func() bool { return m.Snapshot().Level != "" })
	h := e.s.Status(bg).Health
	if h.Level == LevelUnknown || len(h.Servers) != 1 {
		t.Fatalf("Health = %s, want the first check's", hideID(h))
	}
	for what, text := range map[string]string{"Runner.Err": h.Runner.Err, "Servers[0].LastError": h.Servers[0].LastError, "Probe.Err": h.Probe.Err} {
		if strings.Contains(text, vlessID) || !strings.Contains(text, redacted) {
			t.Errorf("Health.%s = %s, want the id redacted", what, hideID(text))
		}
	}
	e.shutdown()
}

// checkCounter is a monitor's runner that sends on checks at each call: the
// monitor asks the runner once per check.
type checkCounter struct {
	health.RunnerStatus
	checks chan struct{}
}

func (c checkCounter) Status(ctx context.Context) (runnerapi.Status, error) {
	c.checks <- struct{}{}
	return c.RunnerStatus.Status(ctx)
}

// A pass of the loop, ApplyNow and a core operation each end by asking the
// monitor for a check at once, which nothing else would make for an hour:
// until then its snapshot would say what the runner was before.
func TestPassesAndOperationsPokeTheMonitor(t *testing.T) {
	e := newEnv(t)
	checks := make(chan struct{}, 64)
	m := &health.Monitor{
		Runner:   checkCounter{e.runner.client(), checks},
		Xray:     fakeXray{},
		Interval: time.Hour,
		Now:      e.clock.Now,
	}
	e.s = e.newService(Config{Monitor: m})
	e.edit()
	e.inSync()
	e.start()
	within(t, "the monitor's first check", checks)

	e.edit()
	e.kick()
	e.advance(defaultDebounce) // the loop's pass applies the edit
	wantStatus(t, e.s, true, false)
	within(t, "a check after the loop's pass", checks)

	// What the operations return does not matter here: each ends with the
	// poke, a rollback with nothing to roll back to too. CoreUpdate and
	// CoreRollback share coreOp.
	e.s.ApplyNow(bg)
	within(t, "a check after ApplyNow", checks)
	e.s.CoreRollback(bg)
	within(t, "a check after a rollback", checks)
	e.shutdown()
}
