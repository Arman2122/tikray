package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/store"
)

type testRouter struct {
	mu                      sync.Mutex
	prepared, verified      []routeros.Target
	failPrepare, failVerify bool
	watching                chan func()
	beforePrepare           func(context.Context)
	beforeRelease           func()
	fixes                   int
}

func (r *testRouter) Prepare(ctx context.Context, target routeros.Target) error {
	if r.beforePrepare != nil {
		r.beforePrepare(ctx)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prepared = append(r.prepared, target)
	if r.failPrepare {
		return errors.New("private router diagnostic")
	}
	return nil
}
func (r *testRouter) Reconcile(ctx context.Context, target routeros.Target) (routeros.Report, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failVerify {
		return routeros.Report{}, errors.New("private router diagnostic")
	}
	if r.beforeRelease != nil {
		r.beforeRelease()
	}
	if target.Verify == nil {
		return routeros.Report{}, errors.New("missing committed runner check")
	}
	if err := target.Verify(ctx); err != nil {
		return routeros.Report{}, err
	}
	r.verified = append(r.verified, target)
	report := routeros.Report{Revision: target.Revision, Set: r.fixes}
	r.fixes = 0
	return report, nil
}
func (r *testRouter) Watch(ctx context.Context, hint func()) error {
	select {
	case r.watching <- hint:
	case <-ctx.Done():
	}
	<-ctx.Done()
	return ctx.Err()
}
func (r *testRouter) Leases(context.Context) ([]routeros.LeaseInfo, error) { return nil, nil }
func (r *testRouter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.verified)
}

func TestRouterStartupListenAndSweep(t *testing.T) {
	e := newEnv(t)
	r := &testRouter{watching: make(chan func(), 1)}
	e.s = e.newService(Config{Router: r})
	sweep := make(chan time.Time, 1)
	e.s.routerSweep = sweep
	e.s.after = realTimer
	e.s.debounce = time.Millisecond
	st, _ := e.s.State()
	e.runner.setActive(configOf(t, st))
	e.start()
	hint := within(t, "router watch", r.watching)
	eventually(t, "initial verification of revision zero", func() bool { return r.count() >= 1 })
	before := r.count()
	for range 10 {
		hint()
	}
	eventually(t, "notification reconciliation", func() bool { return r.count() > before })
	before = r.count()
	sweep <- time.Now()
	eventually(t, "periodic reconciliation", func() bool { return r.count() > before })
	if n := len(e.runner.gotTrials()); n != 0 {
		t.Fatalf("%d trials for identical runner selection", n)
	}
	for _, ev := range e.s.Events(0) {
		if ev.Kind == KindRouter || ev.Message == "drift corrected" {
			t.Fatal("no-op marked as correction")
		}
	}
	r.mu.Lock()
	r.fixes = 1
	r.mu.Unlock()
	hint()
	eventually(t, "verified drift event", func() bool {
		for _, ev := range e.s.Events(0) {
			if ev.Kind == KindRouter && ev.Message == "drift corrected" {
				return true
			}
		}
		return false
	})
}

func TestManagedBridgeQuarantineRefusesPolicyWrite(t *testing.T) {
	e := newEnv(t)
	e.s = e.newService(Config{Router: &testRouter{}})
	e.s.repairBridge = true
	_, rev := e.s.State()
	if _, err := e.s.SetDefaultPolicy(t.Context(), rev, store.Policy{Mode: store.ModeFull, KillSwitch: true}); !errors.Is(err, ErrRouterUnavailable) {
		t.Fatal("managed quarantine accepted an unguarded policy")
	}
	_, after := e.s.State()
	if after != rev {
		t.Fatal("quarantined write advanced revision")
	}
}

func TestRouterGuardsSurviveFailedStoreAndRestart(t *testing.T) {
	e := newEnv(t)
	r := &testRouter{}
	e.s = e.newService(Config{Router: r})
	st, _ := e.s.State()
	e.runner.setActive(configOf(t, st))
	ctx := context.Background()
	e.s.pass(ctx, time.Second)
	dir := filepath.Join(e.data, "state")
	blocked := filepath.Join(e.data, "state-held")
	if err := os.Rename(dir, blocked); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := e.s.SetDefaultPolicy(ctx, 0, store.Policy{Mode: store.ModeSmart, KillSwitch: true})
	if err == nil || r.prepared[len(r.prepared)-1].Revision != 1 {
		t.Fatal("expected interruption between guard and store")
	}
	if !e.s.pass(ctx, time.Second) || r.count() != 1 {
		t.Fatal("released a guard while the durable state was unreadable")
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(blocked, dir); err != nil {
		t.Fatal(err)
	}
	// Model a failure of the directory sync after rename: disk may show the
	// candidate even though the failed store never published it in memory.
	partial, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := partial.Update(0, func(st *store.State) error {
		st.DefaultPolicy = store.Policy{Mode: store.ModeSmart, KillSwitch: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e.s.pass(ctx, time.Second)
	reopened, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	e.s = e.newService(Config{Router: r, Store: reopened})
	e.s.pass(ctx, time.Second)
	if r.verified[len(r.verified)-1].Revision != 0 || r.prepared[len(r.prepared)-1].Policy.Default != st.DefaultPolicy || !e.s.Status(ctx).Applied {
		t.Fatal("restart failed to heal against durable state")
	}
}

func TestRouterChecksRunnerAtGuardRelease(t *testing.T) {
	e := newEnv(t)
	r := &testRouter{}
	e.s = e.newService(Config{Router: r})
	st, _ := e.s.State()
	e.runner.setActive(configOf(t, st))
	r.beforeRelease = func() { e.runner.setDown(true) }
	if again := e.s.pass(context.Background(), time.Second); !again || r.count() != 0 || !e.s.Status(context.Background()).Router.LastVerified.IsZero() {
		t.Fatal("released guard after runner disappeared")
	}
}

func TestRouterSerializesTrialAndNewPolicy(t *testing.T) {
	e := newEnv(t)
	r := &testRouter{}
	e.s = e.newService(Config{Router: r})
	ctx := context.Background()
	st, _ := e.s.State()
	e.runner.setActive(configOf(t, st))
	closed := store.Policy{Mode: store.ModeSmart, KillSwitch: true}
	if _, err := e.s.SetDefaultPolicy(ctx, 0, closed); err != nil {
		t.Fatal(err)
	}
	e.runner.hold()
	passDone := make(chan bool, 1)
	go func() { passDone <- e.s.pass(ctx, time.Second) }()
	within(t, "trial", e.runner.waiting)
	editDone := make(chan error, 1)
	go func() { _, err := e.s.SetDefaultPolicy(ctx, 1, store.Policy{Mode: store.ModeDirect}); editDone <- err }()
	within(t, "second policy waiting for the trial", e.lockers)
	if _, rev := e.s.State(); rev != 1 {
		t.Error("revision moved during trial")
	}
	e.runner.release()
	within(t, "first verified revision", passDone)
	if err := within(t, "second guarded edit", editDone); err != nil {
		t.Fatal(err)
	}
	if r.count() != 1 || r.verified[0].Revision != 1 || r.verified[0].Policy.Default != closed {
		t.Fatal("mixed revision committed")
	}
	e.s.pass(ctx, time.Second)
	if got := e.s.Status(ctx); !got.Applied || got.Router.Revision != 2 {
		t.Fatal("next revision did not converge")
	}
}

func TestRouterAndXrayCommitSameRevision(t *testing.T) {
	e := newEnv(t)
	r := &testRouter{}
	e.s = e.newService(Config{Router: r})
	ctx := context.Background()
	st, _ := e.s.State()
	e.runner.setActive(configOf(t, st))
	e.s.pass(ctx, time.Second)
	closed := store.Policy{Mode: store.ModeFull, KillSwitch: true}
	r.failPrepare = true
	if _, err := e.s.SetDefaultPolicy(ctx, 0, closed); !errors.Is(err, ErrRouterUnavailable) {
		t.Fatal("unverified protection acknowledged")
	}
	if st, rev := e.s.State(); rev != 0 || st.DefaultPolicy == closed {
		t.Fatal("failed protection published desired change")
	}
	r.failPrepare = false
	if _, err := e.s.SetDefaultPolicy(ctx, 0, closed); err != nil {
		t.Fatal(err)
	}
	if p := r.prepared[len(r.prepared)-1]; p.Revision != 1 || p.Policy.Default != closed {
		t.Fatal("new policy was not guarded before write")
	}
	e.runner.setReject("invalid test candidate")
	e.s.pass(ctx, time.Second)
	status := e.s.Status(ctx)
	if status.Applied || !status.Router.Pending || status.Router.Revision != 0 || r.count() != 1 {
		t.Fatal("rejected trial advanced effective router policy")
	}
	e.runner.setReject("")
	r.failVerify = true
	e.s.pass(ctx, time.Second)
	status = e.s.Status(ctx)
	if status.Applied || !status.Pending || status.Router.Revision != 0 || status.Router.Degraded != "unavailable" {
		t.Fatal("unverified router marked applied")
	}
	trials := len(e.runner.gotTrials())
	r.failVerify = false
	e.s.pass(ctx, time.Second)
	status = e.s.Status(ctx)
	if !status.Applied || status.Router.Pending || status.Router.Revision != 1 || status.Router.LastVerified.IsZero() || r.verified[1].Selection != e.runner.active() {
		t.Fatal("router and runner did not converge on revision one")
	}
	if len(e.runner.gotTrials()) != trials {
		t.Fatal("router recovery repeated the runner trial")
	}
}

func TestRouterFailureKeepsAPILive(t *testing.T) {
	e := newEnv(t)
	active := make(chan struct{})
	release := make(chan struct{})
	r := &testRouter{beforePrepare: func(ctx context.Context) {
		close(active)
		select {
		case <-ctx.Done():
		case <-release:
		}
	}, failPrepare: true}
	e.s = e.newService(Config{Router: r})
	st, _ := e.s.State()
	e.runner.setActive(configOf(t, st))
	result := make(chan error, 1)
	go func() {
		_, err := e.s.SetDefaultPolicy(context.Background(), 0, store.Policy{Mode: store.ModeFull, KillSwitch: true})
		result <- err
	}()
	within(t, "protection in flight", active)
	done := make(chan Status, 1)
	go func() { done <- e.s.Status(context.Background()) }()
	select {
	case got := <-done:
		if got.Revision != 0 || got.Applied {
			t.Error("unprotected policy visible during router failure")
		}
	case <-time.After(time.Second):
		t.Error("an unreachable router blocked status")
	}
	close(release)
	if err := within(t, "outage response", result); err != ErrRouterUnavailable {
		t.Fatal("router diagnostic escaped fixed category")
	}
}

func TestGuardedEditHonorsCallerBudget(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	want, _ := ctx.Deadline()
	r := &testRouter{beforePrepare: func(call context.Context) {
		if got, ok := call.Deadline(); !ok || !got.Equal(want) {
			t.Error("whole-policy timeout can restart a progressing guard release")
		}
	}}
	e.s = e.newService(Config{Router: r})
	if _, err := e.s.SetDefaultPolicy(ctx, 0, store.Policy{Mode: store.ModeFull, KillSwitch: true}); err != nil {
		t.Fatal(err)
	}
}
