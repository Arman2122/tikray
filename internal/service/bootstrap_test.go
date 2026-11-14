package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

type attestationRouter struct {
	testRouter
	probe func(context.Context, routeros.Target) error
}

func (r *attestationRouter) VerifyInstallation(ctx context.Context, t routeros.Target) error {
	return r.probe(ctx, t)
}

// A durable install.ready survives a stopped-control restart. The owner can
// therefore challenge before this process has a working native controller.
func TestInstallChallengeWaitsForCurrentRouterStartup(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	installCore(t, e.data, testCore)
	r := &attestationRouter{}
	e.s = e.newService(Config{Router: r})
	logins := make(chan routeros.Target, 1)
	r.probe = func(_ context.Context, target routeros.Target) error {
		logins <- target
		return nil
	}

	start := func(ctx context.Context) <-chan error {
		done := make(chan error, 1)
		go func() { done <- e.s.VerifyInstallation(ctx) }()
		return done
	}
	// A failed initial reconciliation or expired check authorizes no login.
	r.failVerify = true
	st, rev := e.s.State()
	if err := e.s.finishRouter(t.Context(), st, rev); err == nil {
		t.Fatal("failed reconciliation became ready")
	}
	brief, stop := context.WithTimeout(t.Context(), 30*time.Millisecond)
	if err := <-start(brief); err == nil || len(logins) != 0 {
		stop()
		t.Fatal("challenge was attempted before this process verified its router")
	}
	stop()

	// Leave one real verification pending. Startup needs to be able to take
	// the writer while that check waits, including at revision zero.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := start(ctx)
	if err := e.s.acquire(ctx); err != nil {
		t.Fatal("waiting check blocked the policy writer")
	}
	r.failVerify = false
	err := e.s.finishRouter(ctx, st, rev)
	e.s.release()
	if err != nil {
		t.Fatal("valid startup did not reconcile")
	}
	if err = <-done; err != nil || len(logins) != 1 {
		t.Fatal("the pending challenge did not verify the live router once")
	}
	target := <-logins
	if target.Revision != rev || target.Selection.Core != testCore {
		t.Fatal("startup challenge used a stale revision or selection")
	}
}

func TestLiveInstallCheckRefusesStaleRouterAndRunner(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	installCore(t, e.data, testCore)
	r := &attestationRouter{}
	e.s = e.newService(Config{Router: r})
	st, rev := e.s.State()
	if err := e.s.finishRouter(t.Context(), st, rev); err != nil {
		t.Fatal("failed to establish the running installation")
	}
	probes := 0
	r.probe = func(context.Context, routeros.Target) error { probes++; return nil }
	if err := e.s.VerifyInstallation(t.Context()); err != nil || probes != 1 {
		t.Fatal("verified live installation failed")
	}
	r.probe = func(context.Context, routeros.Target) error { return errors.New("removed router login") }
	if err := e.s.VerifyInstallation(t.Context()); err == nil {
		t.Fatal("accepted lost router authentication")
	}
	r.probe = func(context.Context, routeros.Target) error { e.runner.setDown(true); return nil }
	if err := e.s.VerifyInstallation(t.Context()); err == nil {
		t.Fatal("runner vanished during verification")
	}
}

func TestBootstrapCoreRetryReportsTrial(t *testing.T) {
	e := newEnv(t)
	installCore(t, e.data, testCore)
	e.s = e.newService(Config{Bootstrap: &Bootstrap{Version: testCore, Ready: func() error { return nil }}})
	res, err := e.s.CoreUpdate(t.Context(), testCore, artifacts.UpdateOptions{})
	if err != nil || res.Outcome != runnerapi.OutcomeCommitted || res.To != testCore {
		t.Fatal("retry failed to report the committed trial")
	}
}

func TestBootstrapShowsBridgeRepair(t *testing.T) {
	e := newEnv(t)
	e.s = e.newService(Config{Router: &testRouter{}, VerifyBridge: true, Bootstrap: &Bootstrap{Version: testCore, Ready: func() error { return nil }}})
	s := e.s.Status(t.Context())
	if s.Router == nil || !s.Pending || s.Router.Degraded != "bridge_repair" {
		t.Fatal("bootstrap concealed a required bridge repair")
	}
}

func TestBootstrapRefusesDamagedCachedCoreBeforeTrial(t *testing.T) {
	e := newEnv(t)
	installCore(t, e.data, testCore)
	if err := os.WriteFile(filepath.Join(e.data, "cores", testCore, "xray"), []byte("different bytes"), 0755); err != nil {
		t.Fatal(err)
	}
	e.s = e.newService(Config{Bootstrap: &Bootstrap{Version: testCore, Ready: func() error { t.Fatal("bad core declared ready"); return nil }}})
	if err := e.s.BootstrapCore(t.Context(), testCore); !errors.Is(err, ErrBootstrapPending) || len(e.runner.gotTrials()) != 0 {
		t.Fatal("damaged cached core reached runner trial")
	}
}

func TestBootstrapBlocksAdmissionUntilCoreCommitted(t *testing.T) {
	e := newEnv(t)
	complete := false
	e.s = e.newService(Config{Bootstrap: &Bootstrap{Version: testCore, Ready: func() error { complete = true; return nil }}})
	ctx := t.Context()
	wantPending := func(err error) {
		t.Helper()
		if !errors.Is(err, ErrBootstrapPending) {
			t.Fatal("bootstrap gate missing")
		}
	}
	_, _, err := e.s.AddServer(ctx, 0, NewServer{})
	wantPending(err)
	_, _, err = e.s.UpdateServer(ctx, 0, "absent", ServerPatch{})
	wantPending(err)
	_, _, err = e.s.AddSubscription(ctx, 0, NewSubscription{})
	wantPending(err)
	_, _, err = e.s.UpdateSubscription(ctx, 0, "absent", SubscriptionPatch{})
	wantPending(err)
	_, err = e.s.RefreshSubscription(ctx, "absent")
	wantPending(err)
	_, err = e.s.SetDefaultPolicy(ctx, 0, store.Policy{Mode: store.ModeFull, KillSwitch: true})
	wantPending(err)
	_, err = e.s.ApplyNow(ctx)
	wantPending(err)
	_, err = e.s.CoreUpdate(ctx, testCore, artifacts.UpdateOptions{AllowUnverified: true})
	wantPending(err)
	_, err = e.s.CoreRollback(ctx)
	wantPending(err)
	if err := e.s.BootstrapCore(ctx, testCore); err == nil || complete {
		t.Fatal("missing core ended protected installation")
	}
	installCore(t, e.data, testCore)
	if err := e.s.BootstrapCore(ctx, testCore); err != nil || !complete {
		t.Fatal("verified bootstrap did not complete", err)
	}
	if _, err := e.s.SetDefaultPolicy(ctx, 0, store.Policy{Mode: store.ModeDirect}); err != nil {
		t.Fatal(err)
	}
}
func TestBootstrapKeepsExistingStateAndSecrets(t *testing.T) {
	e := newEnv(t)
	e.edit()
	e.inSync()
	installCore(t, e.data, testCore)
	_, rev := e.store.State()
	var saves int
	e.s = e.newService(Config{Bootstrap: &Bootstrap{Version: "latest", Ready: func() error {
		saves++
		if saves == 1 {
			return errors.New("interrupted")
		}
		return nil
	}}})
	if err := e.s.BootstrapCore(context.Background(), "latest"); err == nil {
		t.Fatal("ready marker lost acknowledgement accepted")
	}
	if err := e.s.BootstrapCore(context.Background(), "latest"); err != nil {
		t.Fatal(err)
	}
	if _, now := e.store.State(); now != rev || len(e.runner.gotTrials()) != 0 || saves != 2 {
		t.Fatal("bootstrap rewrote an active installation")
	}
}
