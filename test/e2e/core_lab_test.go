//go:build lab

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

// lifecycleState is the state that makes tikray render what the M1 fixture
// (config/xray-client.json) does: the fake internet's VLESS server a as the
// only server, smart routing with the fixture's domestic names and address,
// and its two resolvers (labState). The state is validated.
func lifecycleState() (store.State, error) {
	srv, err := serverFromLink(linkA)
	if err != nil {
		return store.State{}, err
	}
	st := labState()
	st.Servers = []store.Server{srv}
	st.DefaultPolicy = store.Policy{Mode: store.ModeSmart}
	return st, st.Validate()
}

// TestCoreLifecycle deploys the real images once and takes xray-core through
// its lifecycle in order: bootstrap, an update through the proxy, a core that
// xray run -test rejects, a core that crashes, an install from the mirror
// verified by the signed index, a rollback, pruning, a power cut during a
// trial, and the gateway signal following xray. Each scenario builds on the
// ones before it. The results file is written either way.
func TestCoreLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Minute)
	defer cancel()
	l := Deploy(ctx, t)
	c := l.CHR
	check := l.recordChecks(t, "m1")

	proxiedWithin := l.proxiedWithin()
	lanProxied := func(t *testing.T, note func(string, ...any)) {
		t.Helper()
		l.lanProxied(ctx, t, note)
	}
	tikray := func(t *testing.T, note func(string, ...any), args string) artifacts.Result {
		t.Helper()
		return l.tikray(ctx, t, note, args)
	}
	onCore := func(t *testing.T, note func(string, ...any), version string) runnerapi.Status {
		t.Helper()
		return checkCore(ctx, t, note, version)
	}
	// statssys runs the health check's xray api call by hand against the
	// running core, which must be version.
	statssys := func(t *testing.T, note func(string, ...any), version string) {
		if st, err := runnerStatus(ctx); err != nil || !strings.HasPrefix(st.XrayVersion, "Xray "+version+" ") {
			note("xray api statssys on %s: not run, the runner runs %q (%v)", version, st.XrayVersion, err)
			t.Errorf("xray api statssys on %s: the runner runs %q (%v)", version, st.XrayVersion, err)
			return
		}
		out, err := runnerAPI.XrayAPI(ctx, "statssys", "--server="+xrayAPI)
		note("xray api statssys on %s: exit %d, uptime line %q, err %v", version, out.ExitCode, uptimeLine(out.Stdout), err)
		if err != nil || out.ExitCode != 0 {
			t.Errorf("xray api statssys on %s: exit %d (%v): %s", version, out.ExitCode, err, out.Stderr)
		}
	}

	check("bootstrap", func(t *testing.T, note func(string, ...any)) {
		st, err := runnerStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st.State != runnerapi.StateEmpty {
			t.Fatalf("runner state %s before the first update, want empty", st.State)
		}
		// Not a check of this test (M0 covers fail-open): an empty runner
		// does not answer ping, so check-gateway sends the LAN direct once
		// it has noticed.
		took, direct := poll(ctx, time.Minute, 2*time.Second, func() bool { return l.whoami(ctx) == "198.51.100.2" })
		note("before: runner %s, gateway_up %v, LAN direct after %.0fs: %v", st.State, st.GatewayUp, took.Seconds(), direct)
		res := tikray(t, note, "core update "+oldestXray+" --config "+clientConfig)
		wantResult(t, res, artifacts.Result{Outcome: runnerapi.OutcomeCommitted, To: oldestXray, Source: "direct", Verified: "dgst"})
		// From here on the updates and the rollback run with no --config, so
		// tikray renders their config from the state. Give it one that
		// reproduces the fixture's routing.
		state, err := lifecycleState()
		if err != nil {
			t.Fatal(err)
		}
		if err := l.pushState(ctx, state); err != nil {
			t.Fatal(err)
		}
		note("pushed the state to %s: server %s (%s), smart routing, the fixture's domestic names and resolvers", statePath, state.Servers[0].Name, state.Servers[0].ID)
		onCore(t, note, oldestXray)
		statssys(t, note, oldestXray)
		lanProxied(t, note)
		// How RouterOS ran the one-shot container: cmd on top of the
		// image's ENTRYPOINT ["/tikray"] (no entrypoint of its own), as
		// root (no user), which reads the runner's 0600 token.
		cmd, _ := c.Get(ctx, "/container/get [find name=tikray] cmd")
		ep, _ := c.Get(ctx, "/container/get [find name=tikray] entrypoint")
		def, _ := c.Get(ctx, "/container/get [find name=tikray] default-entrypoint")
		user, _ := c.Get(ctx, "/container/get [find name=tikray] user")
		note("tikray container cmd=%q entrypoint=%q default-entrypoint=%q user=%q", cmd, ep, def, user)
	})

	check("update_latest_via_proxy", func(t *testing.T, note func(string, ...any)) {
		if err := l.setFlag(".block-direct", true); err != nil {
			t.Fatal(err)
		}
		res := tikray(t, note, "core update latest")
		wantResult(t, res, artifacts.Result{Outcome: runnerapi.OutcomeCommitted, From: oldestXray, To: l.Newest, Source: "proxy", Verified: "dgst"})
		onCore(t, note, l.Newest)
		statssys(t, note, l.Newest)
		lanProxied(t, note)
	})

	check("rejected", func(t *testing.T, note func(string, ...any)) {
		// 99.0.1 has no .dgst and the index lacks it, so its SHA-256 is
		// unknown: --allow-unverified takes it from the inbox only.
		if err := l.toInbox(ctx, rejectedXray); err != nil {
			t.Fatal(err)
		}
		// Every unverified update reads the inbox's one zip of this name.
		defer func() {
			if err := l.clearInbox(ctx); err != nil {
				t.Error(err)
			}
		}()
		res := tikray(t, note, "core update "+rejectedXray+" --allow-unverified")
		wantResult(t, res, artifacts.Result{Outcome: runnerapi.OutcomeRejected, From: l.Newest, To: rejectedXray, Source: "inbox", Verified: "unverified"})
		onCore(t, note, l.Newest)
		lanProxied(t, note)
	})

	check("crashing", func(t *testing.T, note func(string, ...any)) {
		res := tikray(t, note, "core update "+crashingXray)
		wantResult(t, res, artifacts.Result{Outcome: runnerapi.OutcomeExited, From: l.Newest, To: crashingXray, Source: "proxy", Verified: "dgst"})
		onCore(t, note, l.Newest)
		lanProxied(t, note)
	})

	check("mirror_and_index", func(t *testing.T, note func(string, ...any)) {
		// GitHub answers 503 directly and through the proxy: the zip comes
		// from the mirror, and with no .dgst the index vouches for it.
		if err := l.setFlag(".down", true); err != nil {
			t.Fatal(err)
		}
		res := tikray(t, note, "core update "+previousXray)
		wantResult(t, res, artifacts.Result{Outcome: runnerapi.OutcomeCommitted, From: l.Newest, To: previousXray, Source: "mirror 203.0.113.41", Verified: "index"})
		onCore(t, note, previousXray)
		statssys(t, note, previousXray)
		lanProxied(t, note)
	})

	check("rollback", func(t *testing.T, note func(string, ...any)) {
		res := tikray(t, note, "core rollback")
		wantResult(t, res, artifacts.Result{Outcome: runnerapi.OutcomeCommitted, From: previousXray, To: l.Newest})
		onCore(t, note, l.Newest)
		lanProxied(t, note)
	})

	check("prune", func(t *testing.T, note func(string, ...any)) {
		got, err := l.children(ctx, coresDir)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{previousXray, l.Newest}
		slices.Sort(want)
		note("cores: %v", got)
		if !slices.Equal(got, want) {
			t.Errorf("%s holds %v, want exactly %v (Keep is 2)", coresDir, got, want)
		}
	})

	check("reboot_during_trial", func(t *testing.T, note func(string, ...any)) {
		st := onCore(t, note, l.Newest)
		if st.Active == nil {
			t.Fatal("no active selection")
		}
		// The runner reads the deadline against the router's clock.
		now, err := l.routerClock(ctx)
		if err != nil {
			t.Fatal(err)
		}
		note("router clock %s, host clock %s", now.Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
		cand := runnerapi.Candidate{
			Selection: runnerapi.Selection{Core: previousXray, Geo: st.Active.Geo, Config: st.Active.Config},
			Deadline:  now.Add(10 * time.Minute),
		}
		b, err := json.Marshal(cand)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Run(ctx, fmt.Sprintf(`/file/add name="%s" contents="%s"`, candidateFile, rosEscape(string(b)))); err != nil {
			t.Fatal(err)
		}
		// The trial call waits for xray run -test of the candidate.
		trial := *runnerAPI
		trial.HTTP = &http.Client{Timeout: 5 * time.Minute}
		if err := trial.Trial(ctx); err != nil {
			t.Fatalf("trial of %s: %v", previousXray, err)
		}
		// tikray fsyncs candidate.json before it calls trial; nothing says
		// /file/add does, so let the router's page cache reach the disk
		// (ext4's delayed allocation can hold new data for 30 s) before the
		// power cut. The trial stays open meanwhile: its deadline is 10
		// minutes.
		if err := sleep(ctx, 45*time.Second); err != nil {
			t.Fatal(err)
		}
		st, err = runnerStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		onTrial := st.State == runnerapi.StateTrial && st.Candidate != nil && st.Candidate.Core == previousXray
		note("before the power cut: runner %s, xray_version %q", st.State, st.XrayVersion)
		if !onTrial {
			t.Fatalf("runner %s with candidate %+v before the power cut, want a trial of %s", st.State, st.Candidate, previousXray)
		}

		if err := c.PowerCycle(ctx); err != nil {
			t.Fatal(err)
		}
		booted := time.Now()
		took, ok := poll(ctx, 20*time.Minute, 3*time.Second, func() bool {
			s, err := runnerStatus(ctx)
			return err == nil && s.State == runnerapi.StateRunning && s.XrayPID > 0
		})
		note("runner running %.0fs after SSH: %v", took.Seconds(), ok)
		if !ok {
			t.Fatalf("the runner was not running within 20 min of boot (%s)", time.Since(booted).Round(time.Second))
		}
		st = onCore(t, note, l.Newest)
		if lt := st.LastTrial; lt == nil {
			t.Error("no last_trial after the reboot, want outcome reboot")
		} else {
			note("last_trial: core %s, outcome %s, detail %q", lt.Candidate.Core, lt.Outcome, lt.Detail)
			if lt.Outcome != runnerapi.OutcomeReboot || lt.Candidate.Core != previousXray {
				t.Errorf("last_trial outcome %s for core %s, want %s for %s", lt.Outcome, lt.Candidate.Core, runnerapi.OutcomeReboot, previousXray)
			}
		}
		gone, err := l.exists(ctx, candidateFile)
		note("candidate.json present after the reboot: %v", gone)
		if err != nil || gone {
			t.Errorf("candidate.json still present after the reboot (%v)", err)
		}
		lanProxied(t, note)
	})

	check("gateway_follows_xray", func(t *testing.T, note func(string, ...any)) {
		// GitHub is still down, so 99.0.2's .dgst is out of reach and the
		// index lacks it: the unverified core comes from the inbox.
		if err := l.toInbox(ctx, crashingXray); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := l.clearInbox(ctx); err != nil {
				t.Error(err)
			}
		}()
		if _, ok := poll(ctx, proxiedWithin, 2*time.Second, func() bool {
			st, err := runnerStatus(ctx)
			return err == nil && st.GatewayUp
		}); !ok {
			t.Fatal("gateway_up is not true before the update")
		}

		type outcome struct {
			res artifacts.Result
			err error
		}
		done := make(chan outcome, 1)
		args := "core update " + crashingXray + " --allow-unverified"
		start := time.Now()
		go func() {
			res, err := runTikray(ctx, c, args)
			done <- outcome{res, err}
		}()
		var samples, trialSamples, downInTrial int
		var o outcome
	sampling:
		for {
			select {
			case o = <-done:
				break sampling
			case <-time.After(250 * time.Millisecond):
			}
			st, err := runnerStatus(ctx)
			if err != nil {
				continue
			}
			samples++
			if st.State == runnerapi.StateTrial && st.Candidate != nil && st.Candidate.Core == crashingXray {
				trialSamples++
				if !st.GatewayUp {
					downInTrial++
				}
			}
		}
		note("tikray %s: %s (%.0fs)", args, describe(o.res), time.Since(start).Seconds())
		note("%d status samples, %d in the trial of %s, %d of those with gateway_up false", samples, trialSamples, crashingXray, downInTrial)
		if o.err != nil {
			t.Fatalf("tikray %s: %v", args, o.err)
		}
		wantResult(t, o.res, artifacts.Result{Outcome: runnerapi.OutcomeExited, From: l.Newest, To: crashingXray, Source: "inbox", Verified: "unverified"})
		if downInTrial == 0 {
			t.Errorf("gateway_up never read false during the trial of %s (%d trial samples)", crashingXray, trialSamples)
		}
		took, ok := poll(ctx, proxiedWithin, time.Second, func() bool {
			st, err := runnerStatus(ctx)
			return err == nil && st.GatewayUp
		})
		note("gateway_up true again %.0fs after the update: %v", took.Seconds(), ok)
		if !ok {
			t.Errorf("gateway_up not true again within %s of the update", proxiedWithin)
		}
		onCore(t, note, l.Newest)
		lanProxied(t, note)
	})
}

// wantResult checks the fields of got that want sets.
func wantResult(t *testing.T, got, want artifacts.Result) {
	t.Helper()
	for _, f := range []struct{ name, got, want string }{
		{"outcome", got.Outcome, want.Outcome},
		{"from", got.From, want.From},
		{"to", got.To, want.To},
		{"source", got.Source, want.Source},
		{"verified", got.Verified, want.Verified},
	} {
		if f.want != "" && f.got != f.want {
			t.Errorf("result %s %q, want %q (detail %q)", f.name, f.got, f.want, got.Detail)
		}
	}
}

// describe is a one-line summary of a result.
func describe(r artifacts.Result) string {
	d := r.Detail
	if len(d) > 300 {
		d = d[:300] + "..."
	}
	return fmt.Sprintf("outcome=%s from=%s to=%s source=%q verified=%s detail=%q", r.Outcome, r.From, r.To, r.Source, r.Verified, d)
}

// uptimeLine picks the Uptime line out of xray api statssys output.
func uptimeLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Uptime") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}
