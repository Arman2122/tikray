package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

// saveUntested represents servers saved while their core was unavailable.
func saveUntested(t *testing.T, e *env, names ...string) uint64 {
	t.Helper()
	_, rev, err := e.store.Update(store.AnyRevision, func(st *store.State) error {
		for _, name := range names {
			st.Servers = append(st.Servers, store.Server{
				ID: store.NewID(), Name: name, Outbound: json.RawMessage(vlessOutbound), Untested: true,
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(show(err))
	}
	return rev
}

func TestRetestAfterCoreArrives(t *testing.T) {
	e := newEnv(t)
	rev := saveUntested(t, e, "good", "bad")
	e.outOfSync()
	bad := e.serverNamed("bad")
	e.runner.setReject("trial rejected")
	e.runner.setTestRejectFor(bad.Tag(), "unknown user "+vlessID)

	e.s.pass(bg, defaultRetry)
	st, next := e.s.State()
	if next != rev+1 || kicks(e.s) != 1 {
		t.Errorf("got revision %d and %d kicks, want one update and one kick", next, kicks(e.s))
	}
	if srv := st.Servers[0]; srv.Untested || srv.Disabled || srv.Invalid != "" {
		t.Error("the accepted server should be tested and enabled")
	}
	if srv := st.Servers[1]; srv.Untested || !srv.Disabled || !strings.Contains(srv.Invalid, "unknown user") || strings.Contains(srv.Invalid, vlessID) {
		t.Error("the refused server should be tested, disabled and carry a redacted reason")
	}
	events := e.eventsOf(KindDegraded)
	if len(events) != 1 || !strings.Contains(events[0], bad.ID) || strings.Contains(events[0], vlessID) {
		t.Error("want one degraded event naming the rejected server without its credential")
	}
}

func TestRetestAfterStartupRetriesWithoutAnEdit(t *testing.T) {
	e := newEnv(t)
	rev := saveUntested(t, e, "saved")
	e.inSync()
	e.runner.failTest(false, true)
	e.start()
	e.advance(defaultDebounce)
	if len(e.runner.gotTests()) != 1 {
		t.Fatal("startup with a matching render did not attempt the pending test")
	}
	if srv := e.serverNamed("saved"); !srv.Untested || srv.Disabled {
		t.Error("a runner failure must leave the untested server alone")
	}
	if _, cur := e.s.State(); cur != rev || len(e.eventsOf(KindDegraded)) != 0 {
		t.Error("a runner failure must leave the revision and degraded events alone")
	}
	e.runner.failTest(false, false)
	e.advance(defaultRetry)
	if srv := e.serverNamed("saved"); srv.Untested || srv.Disabled {
		t.Error("the next pass should clear the marker without another edit")
	}
}

func TestCoreUpdateAndRollbackRetest(t *testing.T) {
	e := newEnv(t)
	installCore(t, e.data, "26.3.27")
	installCore(t, e.data, testCore)
	saveUntested(t, e, "on update")
	e.inSync()
	if _, err := e.s.CoreUpdate(bg, "26.3.27", artifacts.UpdateOptions{}); err != nil {
		t.Fatal(show(err))
	}
	if e.serverNamed("on update").Untested {
		t.Error("core update left the server untested")
	}
	saveUntested(t, e, "on rollback")
	if _, err := e.s.CoreRollback(bg); err != nil {
		t.Fatal(show(err))
	}
	if e.serverNamed("on rollback").Untested {
		t.Error("core rollback left the server untested")
	}
}

// duringTest runs an action while the runner checks an outbound.
type duringTest struct {
	Runner
	run func()
}

func (r duringTest) Test(ctx context.Context, config []byte) (runnerapi.TestResult, error) {
	r.run()
	return runnerapi.TestResult{Output: "rejected the old outbound"}, nil
}

func TestRetestDiscardsStaleVerdict(t *testing.T) {
	e := newEnv(t)
	rev := saveUntested(t, e, "saved")
	e.inSync()
	e.s.runner = duringTest{e.runner.client(), func() {
		_, _, err := e.store.Update(rev, func(st *store.State) error {
			st.Servers[0].Outbound = json.RawMessage(strings.Replace(vlessOutbound, "203.0.113.10", "203.0.113.11", 1))
			return nil
		})
		if err != nil {
			t.Fatal(show(err))
		}
	}}
	if !e.s.pass(bg, defaultRetry) {
		t.Error("a simultaneous edit should leave the retest pending")
	}
	st, cur := e.s.State()
	if cur != rev+1 || st.Servers[0].Disabled || !st.Servers[0].Untested || len(e.eventsOf(KindDegraded)) != 0 {
		t.Error("the replacement must stay untested, with no verdict from its previous outbound")
	}
}

// A caller that disconnects at the end of a core update leaves the loop to
// finish checking the new core. The request context cannot do it anymore.
func TestRetestContinuesAfterCoreCallerLeaves(t *testing.T) {
	e := newEnv(t)
	rev := saveUntested(t, e, "saved")
	e.inSync()
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	e.s.runner = duringTest{e.runner.client(), cancel}
	if _, err := e.s.CoreUpdate(ctx, testCore, artifacts.UpdateOptions{}); err != nil {
		t.Fatal(show(err))
	}
	if _, cur := e.s.State(); cur != rev || kicks(e.s) != 1 {
		t.Error("a canceled core caller must leave the server untested and kick the loop")
	}
}

func TestRetestDegradedEventOmitsShortCredential(t *testing.T) {
	e := newEnv(t)
	const short = "qZx"
	_, _, err := e.store.Update(store.AnyRevision, func(st *store.State) error {
		st.Servers = []store.Server{{
			ID: store.NewID(), Name: short, Untested: true,
			Outbound: json.RawMessage(strings.Replace(trojanOutbound, trojanPW, short, 1)),
		}}
		return nil
	})
	if err != nil {
		t.Fatal("could not save the untested server")
	}
	e.inSync()
	e.runner.setTestReject("bad password: " + short)
	e.s.pass(bg, defaultRetry)
	events := e.eventsOf(KindDegraded)
	if len(events) != 1 || strings.Contains(events[0], short) || strings.Contains(e.serverNamed(short).Invalid, short) {
		t.Error("a degraded event and its persisted reason must omit the short credential")
	}
}
