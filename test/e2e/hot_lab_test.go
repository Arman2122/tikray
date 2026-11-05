//go:build lab

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
)

// TestHot follows the LAN client's traffic from a to b, watching the running
// xray process and the config from which the runner will start its next one.
func TestHot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Minute)
	defer cancel()
	l := Deploy(ctx, t)
	check := l.recordChecks(t, "m2c-hot")

	a, err := serverFromLink(linkA)
	if err != nil {
		t.Fatal("could not parse lab-a's fixture")
	}
	state := configState(false, a)
	if err := l.pushState(ctx, state); err != nil {
		t.Fatal("could not seed the smart device, lab probe URL and lab-a")
	}
	if err := l.startServe(ctx); err != nil {
		t.Fatal("tikray serve did not start")
	}
	start, stop := context.WithTimeout(ctx, serveWithin())
	api, err := l.api(start)
	if err == nil {
		_, up := poll(start, serveWithin(), time.Second, func() bool { return api.Healthz(start) == nil })
		if !up {
			err = errors.New("service did not become ready")
		}
	}
	stop()
	if err != nil {
		t.Fatal("could not reach the pinned service API")
	}

	call := func(t *testing.T, op string, timeout time.Duration, out any, f func(context.Context) (apiclient.Response, error)) uint64 {
		t.Helper()
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		resp, err := f(cctx)
		if err != nil {
			// Server responses can contain a full outbound, including its credentials.
			var ae *apiclient.Error
			if errors.As(err, &ae) {
				t.Fatalf("%s: HTTP %d", op, ae.Status)
			}
			t.Fatalf("%s: API call failed (%T)", op, err)
		}
		if out != nil && resp.Decode(out) != nil {
			t.Fatalf("%s: could not decode the response", op)
		}
		return resp.Revision
	}
	var core artifacts.Result
	call(t, "bootstrap core", opTimeout, &core, func(ctx context.Context) (apiclient.Response, error) {
		return api.CoreUpdate(ctx, "latest", false)
	})
	if core.Outcome != runnerapi.OutcomeCommitted || core.To != l.Newest {
		t.Fatal("the service did not commit the lab core")
	}

	waitApply := func(t *testing.T, note func(string, ...any), rev uint64, started time.Time, within time.Duration, detail string) artifacts.Result {
		t.Helper()
		hot := detail != ""
		st, _, ok := waitHotStatus(ctx, api, started.Add(within), func(st service.Status) bool {
			r := st.LastApply
			return st.Revision == rev && st.Applied && !st.Pending && r != nil &&
				r.Kind == artifacts.KindConfig && r.Outcome == runnerapi.OutcomeCommitted &&
				r.To == l.Newest && r.Hot == hot && strings.HasPrefix(r.Detail, detail)
		})
		if !ok {
			lastHot := st.LastApply != nil && st.LastApply.Hot
			lastCommitted := st.LastApply != nil && st.LastApply.Outcome == runnerapi.OutcomeCommitted
			t.Fatalf("revision %d did not commit with hot=%v: revision %d, applied %v, pending %v, last committed %v, last hot %v", rev, hot, st.Revision, st.Applied, st.Pending, lastCommitted, lastHot)
		}
		note("revision %d applied, hot=%v (observed after %.0fs)", rev, hot, time.Since(started).Seconds())
		if detail != "" {
			note("%s", detail)
		}
		return *st.LastApply
	}
	wantVia := func(t *testing.T, note func(string, ...any), server string) {
		t.Helper()
		took, ok := poll(ctx, l.proxiedWithin(), 2*time.Second, func() bool {
			return l.whoami(ctx) == serverEgress[server]
		})
		if !ok {
			t.Fatalf("LAN whoami did not reach the egress of lab-%s", server)
		}
		note("LAN whoami reached lab-%s (%s) after %.0fs", server, serverEgress[server], took.Seconds())
	}
	noMarker := func(t *testing.T, note func(string, ...any)) {
		t.Helper()
		present, err := l.exists(ctx, dataRoot+"/run/hot/pending")
		if err != nil || present {
			t.Fatal("could not confirm run/hot/pending was absent")
		}
		note("run/hot/pending absent")
	}
	var b store.Server

	check("hot_add", func(t *testing.T, note func(string, ...any)) {
		wantVia(t, note, "a")
		before := hotRunner(ctx, t)
		wantConfig(t, note, before, state, l.Newest)
		var summary store.Server
		rev := call(t, "add lab-b", callTimeout, &summary, func(ctx context.Context) (apiclient.Response, error) {
			return api.AddServer(ctx, apiclient.NewServer{Link: linkB})
		})
		start := time.Now()
		// The API only returns display metadata. Reconstruct the expected
		// private render independently from the link we submitted.
		b, err = serverFromLink(linkB)
		if err != nil || summary.ID == "" || summary.Name != b.Name || summary.Link != "" {
			t.Fatal("lab-b did not return its public metadata")
		}
		b.ID = summary.ID
		state.Servers = append(state.Servers, b)
		// Health.Alive comes from the observatory's OutboundStatus for this tag.
		_, took, alive := waitHotStatus(ctx, api, start.Add(30*time.Second), func(st service.Status) bool {
			return aliveIn(st.Health, b.ID)
		})
		if !alive {
			t.Error("the observatory did not report lab-b alive within 30s")
		} else {
			note("observatory reported lab-b alive after %.0fs", took.Seconds())
		}
		waitApply(t, note, rev, start, time.Minute, "applied without restarting xray: added 1, removed 0, changed 0")
		after := hotRunner(ctx, t)
		wantHotPID(t, note, before, after, true)
		wantConfig(t, note, after, state, l.Newest)
		noMarker(t, note)
	})

	check("hot_remove", func(t *testing.T, note func(string, ...any)) {
		if b.ID == "" {
			t.Fatal("hot_add did not create lab-b")
		}
		before := hotRunner(ctx, t)
		rev := call(t, "remove lab-a", callTimeout, nil, func(ctx context.Context) (apiclient.Response, error) {
			return api.RemoveServer(ctx, a.ID)
		})
		state.Servers = []store.Server{b}
		waitApply(t, note, rev, time.Now(), time.Minute, "applied without restarting xray: added 0, removed 1, changed 0")
		after := hotRunner(ctx, t)
		wantHotPID(t, note, before, after, true)
		wantConfig(t, note, after, state, l.Newest)
		// The observatory on older cores can keep a stale entry for lab-a.
		out, err := runnerAPI.XrayAPI(ctx, "lso", "--server="+xrayAPI)
		var list struct {
			Outbounds []struct{ Tag string }
		}
		if err != nil || out.ExitCode != 0 || json.Unmarshal([]byte(out.Stdout), &list) != nil {
			t.Fatal("could not read xray's live outbound tags")
		}
		var foundB bool
		for _, ob := range list.Outbounds {
			if ob.Tag == a.Tag() {
				t.Fatal("xray still lists the removed lab-a outbound")
			}
			foundB = foundB || ob.Tag == b.Tag()
		}
		if !foundB {
			t.Fatal("xray does not list the remaining lab-b outbound")
		}
		note("lso lists lab-b and no longer lists lab-a")
		wantVia(t, note, "b")
		noMarker(t, note)
	})

	check("not_hot", func(t *testing.T, note func(string, ...any)) {
		before := hotRunner(ctx, t)
		state.Devices[0].Policy.Mode = store.ModeFull
		rev := call(t, "set full policy", callTimeout, nil, func(ctx context.Context) (apiclient.Response, error) {
			return api.SetDevice(ctx, state.Devices[0])
		})
		waitApply(t, note, rev, time.Now(), l.proxiedWithin(), "")
		after := hotRunner(ctx, t)
		wantHotPID(t, note, before, after, false)
		wantConfig(t, note, after, state, l.Newest)
		if trial := after.LastTrial; trial == nil || trial.Outcome != runnerapi.OutcomeCommitted || trial.Candidate.Config != after.Active.Config {
			t.Fatal("the runner did not record a committed trial of the full policy")
		}
		note("runner committed a trial for the full policy")
		wantVia(t, note, "b")
		noMarker(t, note)
	})

	check("hot_survives_runner_restart", func(t *testing.T, note func(string, ...any)) {
		// The policy trial superseded the last adoption. Make a new hot change
		// whose render differs from that trial but still sends traffic through b.
		before := hotRunner(ctx, t)
		var outbound map[string]json.RawMessage
		if err := json.Unmarshal(b.Outbound, &outbound); err != nil || outbound == nil {
			t.Fatal("could not read lab-b's outbound")
		}
		outbound["sendThrough"] = json.RawMessage(`"0.0.0.0"`)
		raw, err := json.Marshal(outbound)
		if err != nil {
			t.Fatal("could not encode the changed lab-b outbound")
		}
		var summary store.Server
		rev := call(t, "change lab-b", callTimeout, &summary, func(ctx context.Context) (apiclient.Response, error) {
			return api.UpdateServer(ctx, b.ID, apiclient.ServerPatch{Outbound: raw})
		})
		if summary.ID != b.ID || summary.Link != "" {
			t.Fatal("changed lab-b did not return its public metadata")
		}
		b.Outbound, b.Link = raw, ""
		state.Servers = []store.Server{b}
		r := waitApply(t, note, rev, time.Now(), time.Minute, "applied without restarting xray: added 0, removed 0, changed 1")
		adopted := hotRunner(ctx, t)
		wantHotPID(t, note, before, adopted, true)
		wantConfig(t, note, adopted, state, r.To)
		if adopted.Active.Config == before.Active.Config {
			t.Fatal("the hot change did not replace the policy trial's config")
		}
		// Stop the owner so only the runner can restore the adopted selection.
		if err := l.stopServe(ctx); err != nil {
			t.Fatal("could not stop tikray before restarting the runner")
		}
		rctx, cancel := context.WithTimeout(ctx, serveWithin())
		defer cancel()
		c := l.CHR
		if _, err := c.Run(rctx, "/container/stop [find name=tikray-runner]"); err != nil {
			t.Fatal("RouterOS could not stop tikray-runner")
		}
		if err := waitContainer(rctx, c, "tikray-runner", "stopped"); err != nil {
			t.Fatal("tikray-runner did not stop")
		}
		var disk runnerapi.Selection
		active, err := c.Get(rctx, fileContents(dataRoot+"/run/active.json"))
		if err != nil || json.Unmarshal([]byte(active), &disk) != nil || disk != *adopted.Active || disk.Core != r.To {
			t.Fatal("active.json does not name the adopted core and config while both containers are stopped")
		}
		if _, err := c.Run(rctx, "/container/start [find name=tikray-runner]"); err != nil {
			t.Fatal("RouterOS could not restart tikray-runner")
		}
		_, ok := poll(rctx, serveWithin(), time.Second, func() bool {
			rs, err := runnerStatus(rctx)
			return err == nil && rs.State == runnerapi.StateRunning && rs.XrayPID > 0 && rs.XrayInstance != "" && rs.XrayInstance != adopted.XrayInstance && rs.Active != nil && *rs.Active == disk
		})
		if !ok {
			t.Fatal("the restarted runner did not boot the adopted selection")
		}
		note("runner restarted from active.json with core %s and config %s", disk.Core, disk.Config)
		wantVia(t, note, "b")
		noMarker(t, note)
	})
}

func hotRunner(ctx context.Context, t *testing.T) runnerapi.Status {
	t.Helper()
	st, err := runnerStatus(ctx)
	if err != nil || st.State != runnerapi.StateRunning || st.XrayPID <= 0 || st.XrayInstance == "" || st.Active == nil {
		t.Fatal("expected a running xray and its active selection")
	}
	return st
}

func wantHotPID(t *testing.T, note func(string, ...any), before, after runnerapi.Status, hot bool) {
	t.Helper()
	sameStart := before.XrayInstance != "" && before.XrayInstance == after.XrayInstance
	note("xray PID before %d, after %d; same process start: %v", before.XrayPID, after.XrayPID, sameStart)
	if sameStart != hot {
		t.Errorf("same xray process start = %v, want %v", sameStart, hot)
	}
	if (before.XrayPID == after.XrayPID) != hot {
		t.Errorf("xray PID before %d, after %d for hot=%v", before.XrayPID, after.XrayPID, hot)
	}
}

// Bound the HTTPS calls as well as the poll so a slow status cannot pass
// after the deadline for observing the change.
func waitHotStatus(ctx context.Context, api *apiclient.Client, deadline time.Time, want func(service.Status) bool) (service.Status, time.Duration, bool) {
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var st service.Status
	took, ok := poll(ctx, time.Until(deadline), time.Second, func() bool {
		resp, err := api.Status(ctx)
		// Omitted fields (including hot=false) must not inherit the prior poll.
		st = service.Status{}
		return err == nil && resp.Decode(&st) == nil && want(st) && time.Now().Before(deadline)
	})
	return st, took, ok
}

// A trial omits the false hot flag. Polling must discard the previous hot
// result before decoding a subsequent response from the service.
func TestPollStatusObservesTrialAfterAdoption(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Write([]byte(`{"last_apply":{"hot":true}}`))
		} else {
			w.Write([]byte(`{"last_apply":{}}`))
		}
	}))
	defer server.Close()
	api := &apiclient.Client{BaseURL: server.URL, HTTP: server.Client()}
	_, _, ok := waitHotStatus(t.Context(), api, time.Now().Add(3*time.Second), func(st service.Status) bool {
		return st.LastApply != nil && !st.LastApply.Hot
	})
	if !ok {
		t.Error("never observed the trial result following the hot result")
	}
}
