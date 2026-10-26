//go:build lab

package e2e

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/health"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
)

// callTimeout bounds a call to the service's API that is not an operation:
// the status waits 5 s at most for the runner, and a new server waits up to
// 20 s for the runner's xray to test it.
const callTimeout = time.Minute

// opTimeout bounds an operation, which the service answers when it is over: a
// core update fetches the core and puts it on trial (two minutes in the lab),
// and a refresh fetches the list and tests its servers.
const opTimeout = 20 * time.Minute

// subURL is the subscription the service fetches from the fake internet:
// the file Lab.Subs/lab, which setSub writes.
const subURL = "http://203.0.113.30/sub/lab"

// baselineSkipped is what an apply's Result.Detail says when the proxy probe
// failed on the active config too, and so was not asked of the new one
// (artifacts' baselineSkipped).
const baselineSkipped = "the proxy probe fails on the active config too"

// TestService deploys the real images once, starts the tikray container with
// its default command, tikray serve, and drives the service through its HTTPS
// API as a client would, in order: the service comes up with its pinned
// certificate and token, a core update bootstraps xray, a server from a share
// link and a smart device are applied, a subscription adds a second server and
// the other takes over when the one xray picked stops, a block page fails a
// refresh by both paths without losing the server, a kill switch is applied
// while every server is down, a server that xray refuses is refused before it
// is saved, and a restart keeps the revision, the applied config, the
// certificate and the token, and runs no trial. Each check builds on the ones
// before it. The results file is written either way.
func TestService(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Minute)
	defer cancel()
	l := Deploy(ctx, t)
	c := l.CHR
	check := l.recordChecks(t, "m2b")

	// cl is the service's API, pinned to its certificate and with its token,
	// once serve_starts has them.
	var cl *apiclient.Client
	need := func(t *testing.T) *apiclient.Client {
		t.Helper()
		if cl == nil {
			t.Fatal("no client of the service's API: serve_starts did not get one")
		}
		return cl
	}
	// The IDs the service gave lab-a, lab-b and the subscription.
	var serverA, serverB, subID string
	// stopped is the VLESS server ("a" or "b") that subscription_refresh
	// stopped: the one xray had picked.
	var stopped string

	// status is GET /v1/status.
	status := func(ctx context.Context, api *apiclient.Client) (service.Status, error) {
		ctx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()
		var st service.Status
		resp, err := api.Status(ctx)
		if err == nil {
			err = resp.Decode(&st)
		}
		return st, err
	}
	// call makes one call of the API that is not an operation, and decodes
	// its answer into out unless out is nil. It ends the check when the call
	// fails.
	call := func(t *testing.T, what string, out any, f func(ctx context.Context) (apiclient.Response, error)) apiclient.Response {
		t.Helper()
		cctx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()
		resp, err := f(cctx)
		if err == nil && out != nil {
			err = resp.Decode(out)
		}
		if err != nil {
			t.Fatalf("%s: %v; container log:\n%s", what, err, containerLog(c, 30))
		}
		return resp
	}
	// servers is GET /v1/servers.
	servers := func(t *testing.T, api *apiclient.Client) []store.Server {
		t.Helper()
		var list []store.Server
		call(t, "GET /v1/servers", &list, api.Servers)
		return list
	}
	setServer := func(t *testing.T, note func(string, ...any), name string, up bool) {
		t.Helper()
		if err := l.Inet.SetServer(name, up); err != nil {
			t.Fatal(err)
		}
		note("server %s (%s) up: %v", name, serverEgress[name], up)
	}
	// waitStatus polls the status every 2 s for up to d until ok holds, and
	// notes the last one it read and how long that took.
	waitStatus := func(t *testing.T, note func(string, ...any), api *apiclient.Client, d time.Duration, what string, ok func(service.Status) bool) (service.Status, bool) {
		t.Helper()
		var st service.Status
		var err error
		took, done := poll(ctx, d, 2*time.Second, func() bool {
			st, err = status(ctx, api)
			return err == nil && ok(st)
		})
		note("%s after %.0fs: %v; %s", what, took.Seconds(), done, describeStatus(st, err))
		return st, done
	}

	check("serve_starts", func(t *testing.T, note func(string, ...any)) {
		start := time.Now()
		if err := l.startServe(ctx); err != nil {
			t.Fatal(err)
		}
		props, err := c.Run(ctx, "/container/print detail where name=tikray")
		note("tikray container running %.0fs after the start (RouterOS imported the busybox-based archive): %s (%v)", time.Since(start).Seconds(), strings.Join(strings.Fields(props), " "), err)

		deadline := start.Add(60 * time.Second)
		wctx, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		api, err := l.api(wctx)
		if err != nil {
			t.Fatalf("%v; container log:\n%s", err, containerLog(c, 30))
		}
		var herr error
		_, up := poll(wctx, time.Until(deadline), time.Second, func() bool {
			herr = api.Healthz(wctx)
			return herr == nil
		})
		note("GET /healthz with the pinned certificate (sha256 %s) %.0fs after the start: %v (%v)", api.Fingerprint, time.Since(start).Seconds(), up, herr)
		if !up {
			t.Fatalf("/healthz did not answer within 60 s of the start: %v; container log:\n%s", herr, containerLog(c, 30))
		}
		var st service.Status
		var serr error
		_, ok := poll(wctx, time.Until(deadline), time.Second, func() bool {
			st, serr = status(wctx, api)
			return serr == nil && st.Revision == 0 && (st.Health.Level == health.LevelDown || st.Health.Level == health.LevelIdle)
		})
		note("GET /v1/status with the token %.0fs after the start: %s", time.Since(start).Seconds(), describeStatus(st, serr))
		if serr == nil {
			// The token works: the rest of the test can go on, whatever the
			// level said.
			cl = api
		}
		if !ok {
			t.Errorf("within 60 s of the start: %s; want revision 0 and level %s or %s", describeStatus(st, serr), health.LevelDown, health.LevelIdle)
		}

		// A token that is not the service's is turned away.
		wrong := *api
		wrong.Token = strings.Repeat("0", 64)
		_, err = wrong.Status(ctx)
		var ae *apiclient.Error
		note("GET /v1/status with another token: %v", err)
		if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
			t.Errorf("GET /v1/status with another token: %v, want 401", err)
		}

		// What Lab.api pinned is what serve printed: the PEM that /file/get
		// gave is the certificate the service serves.
		fps := serveFingerprints(c)
		note("fingerprints serve printed in the container log: %q", fps)
		if len(fps) == 0 {
			note("the container log holds no fingerprint line: the match with what serve printed is unverified")
		} else if last := fps[len(fps)-1]; last != api.Fingerprint {
			t.Errorf("serve printed the certificate sha256 %s, and Lab.api pinned %s from state/tls.crt", last, api.Fingerprint)
		}

		// The CLI is on the container's PATH, for /container/shell: what the
		// shell ran is the status, and not "sh: tikray: not found".
		out, ran := l.shellCLI(ctx)
		line := strings.Join(strings.Fields(out), " ")
		note("tikray status in /container/shell (ran: %v): %q", ran, line)
		if ran && !strings.Contains(out, "revision") {
			t.Errorf("tikray status in /container/shell printed %q, want the status, which starts with its revision", line)
		}
	})

	check("bootstrap_core", func(t *testing.T, note func(string, ...any)) {
		api := need(t)
		octx, cancel := context.WithTimeout(ctx, opTimeout)
		defer cancel()
		start := time.Now()
		var res artifacts.Result
		resp, err := api.CoreUpdate(octx, "latest", false)
		if err == nil {
			err = resp.Decode(&res)
		}
		note("POST /v1/core/update latest: %s (%.0fs)", describe(res), time.Since(start).Seconds())
		if err != nil {
			t.Fatalf("POST /v1/core/update latest: %v; container log:\n%s", err, containerLog(c, 30))
		}
		wantResult(t, res, artifacts.Result{Outcome: runnerapi.OutcomeCommitted, To: l.Newest, Source: "direct", Verified: "dgst"})
		rs := checkCore(ctx, t, note, l.Newest)
		// No state was saved: the service rendered the default one.
		wantConfig(t, note, rs, store.Default(), l.Newest)
		st, err := status(ctx, api)
		note("status: %s", describeStatus(st, err))
		if err != nil || st.Revision != 0 || !st.Applied {
			t.Errorf("status %s, want revision 0 applied", describeStatus(st, err))
		}
		// The default policy is direct: xray sends the LAN client's traffic,
		// which the router still routes to it, out direct.
		took, direct := poll(ctx, l.proxiedWithin(), 2*time.Second, func() bool { return l.whoami(ctx) == egressDirect })
		var got string
		n, err := viaDirect(ctx, func() { got = l.whoami(ctx) })
		if err != nil {
			t.Fatal(err)
		}
		note("LAN direct after %.0fs: %v; whoami %q, xray direct downlink +%d bytes", took.Seconds(), direct, got, n)
		if !direct || got != egressDirect || n <= 0 {
			t.Errorf("whoami %q with %d bytes through xray's direct outbound, want %s (direct, through xray)", got, n, egressDirect)
		}
	})

	check("add_server_applies", func(t *testing.T, note func(string, ...any)) {
		api := need(t)
		// The lab has no internet: xray's observatory probes the state's probe
		// URL through each server, and the default one would find none alive.
		resp := call(t, "PUT /v1/health", nil, func(ctx context.Context) (apiclient.Response, error) {
			return api.SetHealth(ctx, store.Health{ProbeURL: labProbeURL})
		})
		note("PUT /v1/health probe_url %s: revision %d", labProbeURL, resp.Revision)
		var srv store.Server
		resp = call(t, "POST /v1/servers", &srv, func(ctx context.Context) (apiclient.Response, error) {
			return api.AddServer(ctx, apiclient.NewServer{Link: linkA})
		})
		serverA = srv.ID
		note("POST /v1/servers lab-a's link: server %s (%s), revision %d", srv.ID, srv.Name, resp.Revision)
		if srv.Name != "lab-a" || srv.Link != linkA {
			t.Errorf("server %s named %q, link as given %v: want lab-a from its link", srv.ID, srv.Name, srv.Link == linkA)
		}
		dev := store.Device{Address: lanClient, Name: "lab-client", Policy: store.Policy{Mode: store.ModeSmart}}
		resp = call(t, "PUT /v1/devices", nil, func(ctx context.Context) (apiclient.Response, error) { return api.SetDevice(ctx, dev) })
		rev := resp.Revision
		note("PUT /v1/devices/%s smart: revision %d", lanClient, rev)

		var via string
		st, ok := waitStatus(t, note, api, 60*time.Second, "applied, through server a, lab-a alive and selected", func(st service.Status) bool {
			if !st.Applied || st.Revision < rev {
				return false
			}
			via, _ = l.proxiedVia(ctx)
			return via == "a" && aliveIn(st.Health, serverA) && st.Health.Selected == serverA
		})
		if !ok {
			t.Errorf("within 60 s of the device: %s, whoami through %q; want applied, through server a, and lab-a (%s) alive and selected", describeStatus(st, nil), via, serverA)
		}
		if r := st.LastApply; r != nil {
			note("last apply: %s", describe(*r))
		}
	})

	check("subscription_refresh", func(t *testing.T, note func(string, ...any)) {
		api := need(t)
		if err := l.setSub("lab", base64.StdEncoding.EncodeToString([]byte(linkB+"\n"))); err != nil {
			t.Fatal(err)
		}
		note("the subscription lists lab-b, base64")
		var sub store.Subscription
		resp := call(t, "POST /v1/subscriptions", &sub, func(ctx context.Context) (apiclient.Response, error) {
			return api.AddSubscription(ctx, apiclient.NewSubscription{Name: "lab", URL: subURL})
		})
		subID = sub.ID
		note("POST /v1/subscriptions: %s (%s), revision %d", sub.ID, sub.Name, resp.Revision)
		octx, cancel := context.WithTimeout(ctx, opTimeout)
		defer cancel()
		start := time.Now()
		var rr apiclient.RefreshResult
		resp, err := api.RefreshSubscription(octx, sub.ID)
		if err == nil {
			err = resp.Decode(&rr)
		}
		note("POST /v1/subscriptions/%s/refresh: added %d, updated %d, removed %d, kept %d, skipped %d, via %q (%.0fs, %v)", sub.ID, rr.Added, rr.Updated, rr.Removed, rr.Kept, len(rr.Skipped), rr.Via, time.Since(start).Seconds(), err)
		if err != nil {
			t.Fatalf("refresh: %v; container log:\n%s", err, containerLog(c, 30))
		}
		// A new subscription is due at the scheduler's next look, once a
		// minute, which can come between the two calls: the manual refresh
		// then finds lab-b there already, and the event of the scheduler's
		// refresh says it added it.
		switch {
		case rr.Added == 1:
			note("the manual refresh added lab-b")
		case rr.Added == 0 && rr.Kept == 1:
			var evs []service.Event
			call(t, "GET /v1/events", &evs, func(ctx context.Context) (apiclient.Response, error) { return api.Events(ctx, 0) })
			added := fmt.Sprintf("subscription %s (%s): added 1,", sub.ID, sub.Name)
			i := slices.IndexFunc(evs, func(e service.Event) bool {
				return e.Kind == service.KindRefresh && strings.HasPrefix(e.Message, added)
			})
			if i < 0 {
				t.Errorf("the refresh kept 1 server and added none, and no refresh event says another added it, want added 1")
			} else {
				note("the scheduler's refresh added lab-b first: event %q", evs[i].Message)
			}
		default:
			t.Errorf("refresh added %d servers and kept %d, want added 1", rr.Added, rr.Kept)
		}
		for _, srv := range servers(t, api) {
			if srv.Name == "lab-b" {
				serverB = srv.ID
			}
		}
		note("lab-b is server %q", serverB)
		if serverB == "" {
			t.Fatal("no server lab-b after the refresh")
		}

		// The refresh changed the state: wait for its apply, and for xray to
		// find both servers alive.
		st, ok := waitStatus(t, note, api, 90*time.Second, "applied with lab-a and lab-b alive", func(st service.Status) bool {
			return st.Applied && !st.Pending && aliveIn(st.Health, serverA) && aliveIn(st.Health, serverB)
		})
		if !ok {
			t.Fatalf("within 90 s of the refresh: %s; want applied with both servers alive", describeStatus(st, nil))
		}
		// Stop the server that xray's balancer picked, by the status, while
		// the LAN's traffic goes through it, so that the other has to take
		// over. The pick can move between two reads, so the status and whoami
		// are read until they agree.
		names := map[string]string{serverA: "a", serverB: "b"}
		var picked, before string
		took, ok := poll(ctx, 30*time.Second, 2*time.Second, func() bool {
			st, err := status(ctx, api)
			if err != nil {
				return false
			}
			picked = names[st.Health.Selected]
			before, _ = l.proxiedVia(ctx)
			return picked != "" && before == picked
		})
		note("the status names server %q as selected and the LAN goes through %q (%.0fs): %v", picked, before, took.Seconds(), ok)
		if !ok {
			t.Fatalf("within 30 s, the LAN's traffic did not go through the server the status names as selected (%q, whoami through %q)", picked, before)
		}
		other := map[string]string{"a": "b", "b": "a"}[picked]
		setServer(t, note, picked, false)
		stopped = picked
		took, ok = poll(ctx, 30*time.Second, time.Second, func() bool {
			server, _ := l.proxiedVia(ctx)
			return server == other
		})
		note("through server %s %.0fs after %s stopped: %v", other, took.Seconds(), picked, ok)
		if !ok {
			t.Errorf("whoami %q 30 s after server %s stopped, want %s (server %s)", l.whoami(ctx), picked, serverEgress[other], other)
		}
		// The subscription's server carried the LAN's traffic, before the stop
		// or after it.
		carried := before == "b" || (ok && other == "b")
		note("lab-b, the subscription's server, carried the LAN's traffic: %v (before the stop: %v)", carried, before == "b")
		if !carried {
			t.Error("lab-b, the subscription's server, carried the LAN's traffic neither before nor after the stop")
		}
	})

	check("subscription_block_page", func(t *testing.T, note func(string, ...any)) {
		api := need(t)
		if subID == "" || serverB == "" || stopped == "" {
			t.Fatal("no subscription with lab-b, or no server stopped, from subscription_refresh")
		}
		// A refresh falls back to the proxy only while the monitor says the
		// proxy works (ProxyHealthy): the runner running with its gateway up,
		// and a server alive. Wait for the status to say so, with the stopped
		// server found dead, so that both paths are tried and the proxy's goes
		// through the server that is up.
		ids := map[string]string{"a": serverA, "b": serverB}
		up := map[string]string{"a": "b", "b": "a"}[stopped]
		st, ok := waitStatus(t, note, api, 60*time.Second, "the proxy healthy through server "+up, func(st service.Status) bool {
			r := st.Health.Runner
			return r.Reachable && r.State == runnerapi.StateRunning && r.GatewayUp && aliveIn(st.Health, ids[up]) && !aliveIn(st.Health, ids[stopped])
		})
		if !ok {
			t.Fatalf("within 60 s: %s; want the runner running with its gateway up, server %s alive and %s dead", describeStatus(st, nil), up, stopped)
		}
		if err := l.setSub("lab", "<html>blocked</html>"); err != nil {
			t.Fatal(err)
		}
		note("the subscription answers a block page")
		octx, cancel := context.WithTimeout(ctx, opTimeout)
		defer cancel()
		start := time.Now()
		_, err := api.RefreshSubscription(octx, subID)
		var ae *apiclient.Error
		if !errors.As(err, &ae) {
			t.Fatalf("refresh of a block page: %v, want 502 fetch_failed", err)
		}
		note("POST /v1/subscriptions/%s/refresh: %d %s %q (%.0fs)", subID, ae.Status, ae.Code, ae.Detail, time.Since(start).Seconds())
		if ae.Status != http.StatusBadGateway || ae.Code != "fetch_failed" {
			t.Errorf("refresh of a block page: %d %s, want 502 fetch_failed", ae.Status, ae.Code)
		}
		// Both paths got the page, and refused it: direct, and through the
		// proxy, which is the one that matters where direct is blocked.
		for _, path := range []string{"direct", "proxy"} {
			if !strings.Contains(ae.Detail, path+": body refused") {
				t.Errorf("the detail does not say the %s fetch got the page and refused it (%q)", path, path+": body refused")
			}
		}
		// The subscription's URL is a secret.
		if strings.Contains(ae.Detail, "/sub/lab") {
			t.Error("the error's detail names the subscription's URL")
		}

		var subs []store.Subscription
		call(t, "GET /v1/subscriptions", &subs, api.Subscriptions)
		i := slices.IndexFunc(subs, func(s store.Subscription) bool { return s.ID == subID })
		if i < 0 {
			t.Fatalf("subscription %s is gone", subID)
		}
		note("last_error %q", subs[i].LastError)
		if subs[i].LastError == "" {
			t.Error("the subscription's last_error is empty after the failed refresh")
		}
		if strings.Contains(subs[i].LastError, "/sub/lab") {
			t.Error("the subscription's last_error names its URL")
		}
		list := servers(t, api)
		var names []string
		for _, srv := range list {
			names = append(names, srv.ID+" "+srv.Name)
		}
		note("servers: %q", names)
		if !slices.ContainsFunc(list, func(srv store.Server) bool { return srv.ID == serverB && srv.Name == "lab-b" }) {
			t.Errorf("servers %q after the failed refresh, want lab-b (%s) still there", names, serverB)
		}
	})

	check("outage_apply", func(t *testing.T, note func(string, ...any)) {
		api := need(t)
		// Both servers down: the one subscription_refresh stopped is already.
		setServer(t, note, "a", false)
		setServer(t, note, "b", false)
		dev := store.Device{Address: lanClient, Name: "lab-client", Policy: store.Policy{Mode: store.ModeSmart, KillSwitch: true}}
		resp := call(t, "PUT /v1/devices", nil, func(ctx context.Context) (apiclient.Response, error) { return api.SetDevice(ctx, dev) })
		rev := resp.Revision
		note("PUT /v1/devices/%s smart with the kill switch: revision %d", lanClient, rev)
		st, ok := waitStatus(t, note, api, 90*time.Second, "applied", func(st service.Status) bool {
			return st.Applied && st.Revision >= rev
		})
		if !ok {
			t.Fatalf("within 90 s of the device: %s; want applied; container log:\n%s", describeStatus(st, nil), containerLog(c, 30))
		}
		if r := st.LastApply; r == nil {
			t.Error("no last apply in the status")
		} else {
			note("last apply: %s", describe(*r))
			if r.Outcome != runnerapi.OutcomeCommitted || !strings.Contains(r.Detail, baselineSkipped) {
				t.Errorf("last apply %s, want committed with the proxy probe skipped (%q)", describe(*r), baselineSkipped)
			}
		}
		// While the requests fail, the runner must run xray and answer ping:
		// RouterOS then keeps routing to xray, and the block is proxy-closed's
		// fallback, not the router's.
		var requests int
		var answers, offAir []string
		for start := time.Now(); time.Since(start) < 30*time.Second && ctx.Err() == nil; requests++ {
			if got := l.whoami(ctx); got != "" {
				answers = append(answers, got)
			}
			if rs, err := runnerStatus(ctx); err != nil || rs.State != runnerapi.StateRunning || !rs.GatewayUp {
				offAir = append(offAir, fmt.Sprintf("%s gateway_up=%v (%v)", rs.State, rs.GatewayUp, err))
			}
			sleep(ctx, time.Second)
		}
		note("%d requests in 30 s with both servers down, answers %q; runner not running with gateway_up at %d of them %q", requests, answers, len(offAir), offAir)
		if len(answers) > 0 {
			t.Errorf("with both servers down and the kill switch on, whoami answered %q, want every request blocked", answers)
		}
		if requests == 0 || len(offAir) > 0 {
			t.Errorf("the runner was not running with gateway_up throughout the outage (%d of %d samples: %q), so the block need not be xray's", len(offAir), requests, offAir)
		}
		setServer(t, note, "a", true)
		took, ok := poll(ctx, 30*time.Second, time.Second, func() bool {
			server, _ := l.proxiedVia(ctx)
			return server == "a"
		})
		note("proxied %.0fs after server a started: %v", took.Seconds(), ok)
		if !ok {
			t.Errorf("whoami %q 30 s after server a started, want %s", l.whoami(ctx), serverEgress["a"])
		}
	})

	check("refused_server", func(t *testing.T, note func(string, ...any)) {
		api := need(t)
		before, err := status(ctx, api)
		if err != nil {
			t.Fatal(err)
		}
		bad := badServer()
		id := strings.Repeat("x", 40) // its VLESS id
		_, err = api.AddServer(ctx, apiclient.NewServer{Name: bad.Name, Outbound: bad.Outbound})
		var ae *apiclient.Error
		if !errors.As(err, &ae) {
			t.Fatalf("POST /v1/servers with a VLESS id of 40 characters: %v, want 422 refused", err)
		}
		leaks := strings.Contains(ae.Detail, id)
		if leaks {
			note("POST /v1/servers with a raw outbound whose VLESS id is 40 characters: %d %s, the detail naming the id", ae.Status, ae.Code)
			t.Error("the refusal's detail holds the server's id")
		} else {
			note("POST /v1/servers with a raw outbound whose VLESS id is 40 characters: %d %s %q", ae.Status, ae.Code, ae.Detail)
		}
		if ae.Status != http.StatusUnprocessableEntity || ae.Code != "refused" {
			t.Errorf("%d %s, want 422 refused", ae.Status, ae.Code)
		}
		after, err := status(ctx, api)
		note("revision %d before, %d after (%v)", before.Revision, after.Revision, err)
		if err != nil || after.Revision != before.Revision {
			t.Errorf("revision %d after the refusal (%v), want %d as before", after.Revision, err, before.Revision)
		}
		if slices.ContainsFunc(servers(t, api), func(srv store.Server) bool { return srv.Name == bad.Name }) {
			t.Errorf("server %s is in the state after the refusal", bad.Name)
		}
	})

	check("restart_persists", func(t *testing.T, note func(string, ...any)) {
		api := need(t)
		before, err := status(ctx, api)
		if err != nil {
			t.Fatal(err)
		}
		note("before: %s", describeStatus(before, nil))
		if !before.Applied {
			t.Fatalf("not applied before the restart: %s", describeStatus(before, nil))
		}
		rsBefore, err := runnerStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.stopServe(ctx); err != nil {
			t.Fatal(err)
		}
		note("tikray container stopped")
		start := time.Now()
		if err := l.startServe(ctx); err != nil {
			t.Fatal(err)
		}
		// The client of before the restart: its pin and its token.
		var herr error
		took, up := poll(ctx, 60*time.Second, time.Second, func() bool {
			herr = api.Healthz(ctx)
			return herr == nil
		})
		note("GET /healthz pinned to the certificate of before after %.0fs: %v (%v)", took.Seconds(), up, herr)
		if !up {
			t.Fatalf("/healthz did not answer within 60 s of the start with the certificate of before: %v; container log:\n%s", herr, containerLog(c, 30))
		}
		tok, crt, err := l.apiFiles(ctx)
		if err != nil {
			t.Fatal(err)
		}
		now, err := apiClient(tok, crt)
		if err != nil {
			t.Fatal(err)
		}
		note("certificate sha256 %s after the restart, the same: %v; the token the same: %v", now.Fingerprint, now.Fingerprint == api.Fingerprint, now.Token == api.Token)
		if now.Fingerprint != api.Fingerprint {
			t.Errorf("certificate sha256 %s after the restart, want %s", now.Fingerprint, api.Fingerprint)
		}
		if now.Token != api.Token {
			t.Error("state/api.token changed in the restart")
		}
		if fps := serveFingerprints(c); len(fps) > 0 && fps[len(fps)-1] != api.Fingerprint {
			t.Errorf("serve printed the certificate sha256 %s at the restart, want %s", fps[len(fps)-1], api.Fingerprint)
		}

		after, err := status(ctx, api)
		note("after %.0fs: %s", time.Since(start).Seconds(), describeStatus(after, err))
		if err != nil || after.Revision != before.Revision || !after.Applied || after.Pending {
			t.Errorf("status %s after the restart, want revision %d applied, nothing pending", describeStatus(after, err), before.Revision)
		}
		// A restart that applied would have done it at the start, after the
		// loop's 2 s debounce: give it time to show, then read what the new
		// service recorded.
		sleep(ctx, 20*time.Second)
		var evs []service.Event
		call(t, "GET /v1/events", &evs, func(ctx context.Context) (apiclient.Response, error) { return api.Events(ctx, 0) })
		var kinds, applies []string
		for _, e := range evs {
			kinds = append(kinds, e.Kind)
			if e.Kind == service.KindApply {
				applies = append(applies, e.Message)
			}
		}
		note("events since the restart: %q", kinds)
		if len(applies) > 0 {
			t.Errorf("apply events after the restart: %q, want none", applies)
		}
		rsAfter, err := runnerStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// No trial is open, and none ran: the runner runs what it ran before.
		note("the runner %s, candidate %+v", rsAfter.State, rsAfter.Candidate)
		if rsAfter.State != runnerapi.StateRunning || rsAfter.Candidate != nil {
			t.Errorf("the runner is %s with candidate %+v 20 s after the restart, want running with none", rsAfter.State, rsAfter.Candidate)
		}
		same := reflect.DeepEqual(rsAfter.LastTrial, rsBefore.LastTrial) && reflect.DeepEqual(rsAfter.Active, rsBefore.Active)
		note("the runner's active selection and last trial as before: %v", same)
		if !same {
			t.Errorf("runner active %+v and last trial %+v after the restart, want %+v and %+v as before (no trial)", rsAfter.Active, rsAfter.LastTrial, rsBefore.Active, rsBefore.LastTrial)
		}
	})
}

// aliveIn reports whether the snapshot lists server id as alive.
func aliveIn(h health.Snapshot, id string) bool {
	return slices.ContainsFunc(h.Servers, func(s health.ServerHealth) bool { return s.ID == id && s.Alive })
}

// describeStatus is a one-line summary of the service's status, or of the
// error that came instead.
func describeStatus(st service.Status, err error) string {
	if err != nil {
		return "no status: " + err.Error()
	}
	var servers []string
	for _, s := range st.Health.Servers {
		servers = append(servers, fmt.Sprintf("%s alive=%v", s.ID, s.Alive))
	}
	s := fmt.Sprintf("revision %d, applied %v, pending %v, core %q, level %s, runner reachable=%v state=%q gateway_up=%v, servers %q, selected %q",
		st.Revision, st.Applied, st.Pending, st.Core, st.Health.Level, st.Health.Runner.Reachable, st.Health.Runner.State, st.Health.Runner.GatewayUp, servers, st.Health.Selected)
	if e := st.Health.Runner.Err; e != "" {
		s += fmt.Sprintf(", runner error %q", e)
	}
	return s
}
