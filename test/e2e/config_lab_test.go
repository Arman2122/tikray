//go:build lab

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xrayver"
)

// What labinet's resolvers (203.0.113.53 and .54) answer for domestic.test
// and foreign.test: the real address to a query that came through a VLESS
// server, and a poisoned one, as an ISP's resolver would give, to a query
// sent direct.
const (
	answerProxied = "203.0.113.30"
	answerDirect  = "10.10.34.34"
)

// configState is a state of TestConfigApply: labState with servers, and the
// lab's LAN client as a smart device with the kill switch as given. The
// default policy stays direct, so the LAN client reaches the proxy through
// its device's own rules.
func configState(killSwitch bool, servers ...store.Server) store.State {
	st := labState()
	st.Servers = servers
	st.Devices = []store.Device{{
		Address: lanClient,
		Name:    "lab-client",
		Policy:  store.Policy{Mode: store.ModeSmart, KillSwitch: killSwitch},
	}}
	return st
}

// badServer is a raw-JSON server that store.Validate accepts and xray-core
// refuses: its VLESS id is 40 characters long and not a UUID, where xray maps
// only ids of 1 to 30 characters to one (common/uuid ParseString), so xray
// run -test fails on the config that holds it.
func badServer() store.Server {
	return store.Server{
		ID:   store.NewID(),
		Name: "bad-raw",
		Outbound: json.RawMessage(`{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443,` +
			`"users":[{"id":"` + strings.Repeat("x", 40) + `","encryption":"none"}]}]},` +
			`"streamSettings":{"network":"tcp","security":"none"}}`),
	}
}

// renderedName is the name tikray gives the config st renders to for xray-core
// version: config/<sha256>.json. The state goes through a state file first,
// as it does on its way to the router, so that the render is of the state
// tikray reads there.
func renderedName(st store.State, version string) (string, error) {
	v, err := xrayver.Parse(version)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "tikray-state-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	if _, err := writeStateFile(dir, st); err != nil {
		return "", err
	}
	s, err := store.Open(dir)
	if err != nil {
		return "", err
	}
	read, _ := s.State()
	b, err := render.Render(render.Input{State: read, Core: v})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "config/" + hex.EncodeToString(sum[:]) + ".json", nil
}

// wantConfig checks that the runner's active config is the one st renders to
// for xray-core version.
func wantConfig(t *testing.T, note func(string, ...any), status runnerapi.Status, st store.State, version string) {
	t.Helper()
	want, err := renderedName(st, version)
	if err != nil {
		t.Fatal(err)
	}
	got := "<none>"
	if status.Active != nil {
		got = status.Active.Config
	}
	note("active config %s, the render for %s: %v", got, version, got == want)
	if got != want {
		t.Errorf("active config %s, want %s, the render of the state for %s", got, want, version)
	}
}

// directValueRE finds the value in the output of xray api stats.
var directValueRE = regexp.MustCompile(`"value"\s*:\s*"?(\d+)`)

// directBytes is how many bytes xray's direct outbound has received, from the
// stats the rendered config turns on. A counter xray has not made yet, before
// anything went direct, counts 0, as does one whose zero value the output
// leaves out.
func directBytes(ctx context.Context) (int64, error) {
	out, err := runnerAPI.XrayAPI(ctx, "stats", "--server="+xrayAPI, "-name", "outbound>>>"+render.TagDirect+">>>traffic>>>downlink")
	if err != nil {
		return 0, err
	}
	if out.ExitCode != 0 {
		if strings.Contains(out.Stdout+out.Stderr, "not found") {
			return 0, nil
		}
		return 0, fmt.Errorf("xray api stats: exit %d: %s%s", out.ExitCode, out.Stdout, out.Stderr)
	}
	m := directValueRE.FindStringSubmatch(out.Stdout)
	if m == nil {
		return 0, nil
	}
	return strconv.ParseInt(m[1], 10, 64)
}

// viaDirect runs f and returns how many bytes xray's direct outbound received
// meanwhile. Some bytes mean that xray sent f's request direct: a direct
// answer could otherwise also come from RouterOS's fallback route, which
// takes the WAN while the runner doesn't answer ping.
func viaDirect(ctx context.Context, f func()) (int64, error) {
	before, err := directBytes(ctx)
	if err != nil {
		return 0, err
	}
	f()
	after, err := directBytes(ctx)
	if err != nil {
		return 0, err
	}
	return after - before, nil
}

// TestConfigApply deploys the real images once and takes tikray's rendered
// configs through the lab in order: a bootstrap rendered from the default
// state, a server from a share link, the smart policy's domestic split and
// DNS, failover between the fake internet's two VLESS servers, both servers
// down with and without the kill switch, a server that xray run -test
// refuses, and a core update and rollback rendering for their own core. Each
// check builds on the ones before it. The results file is written either way.
func TestConfigApply(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Minute)
	defer cancel()
	l := Deploy(ctx, t)
	c := l.CHR
	check := l.recordChecks(t, "m2a")

	srvA, err := serverFromLink(linkA)
	if err != nil {
		t.Fatal(err)
	}
	srvB, err := serverFromLink(linkB)
	if err != nil {
		t.Fatal(err)
	}
	// applied is the state of the config committed last: what the runner
	// runs, as far as the checks so far could tell.
	applied := store.Default()

	// push puts st on the router as the state tikray reads.
	push := func(t *testing.T, note func(string, ...any), st store.State, what string) {
		t.Helper()
		if err := l.pushState(ctx, st); err != nil {
			t.Fatal(err)
		}
		note("pushed the state: %s", what)
	}
	// apply runs tikray apply, which must end in outcome, and returns the
	// runner's status after it. next is the state pushed for it, which
	// becomes applied if it commits.
	apply := func(t *testing.T, note func(string, ...any), next store.State, outcome string) runnerapi.Status {
		t.Helper()
		res := l.tikray(ctx, t, note, "apply")
		wantResult(t, res, artifacts.Result{Outcome: outcome, From: l.Newest, To: l.Newest})
		if res.Kind != artifacts.KindConfig {
			t.Errorf("result kind %q, want %q", res.Kind, artifacts.KindConfig)
		}
		if res.Outcome == runnerapi.OutcomeCommitted {
			applied = next
		}
		return checkCore(ctx, t, note, l.Newest)
	}
	// setServer takes a VLESS server of the fake internet down or up.
	setServer := func(t *testing.T, note func(string, ...any), name string, up bool) {
		t.Helper()
		if err := l.Inet.SetServer(name, up); err != nil {
			t.Fatal(err)
		}
		note("server %s (%s) up: %v", name, serverEgress[name], up)
	}

	check("bootstrap_rendered", func(t *testing.T, note func(string, ...any)) {
		st, err := runnerStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st.State != runnerapi.StateEmpty {
			t.Fatalf("runner state %s before the first update, want empty", st.State)
		}
		if ok, err := l.exists(ctx, statePath); err != nil || ok {
			t.Fatalf("state file %s present before the first update: %v (%v)", statePath, ok, err)
		}
		res := l.tikray(ctx, t, note, "core update latest")
		wantResult(t, res, artifacts.Result{Outcome: runnerapi.OutcomeCommitted, To: l.Newest, Source: "direct", Verified: "dgst"})
		st = checkCore(ctx, t, note, l.Newest)
		wantConfig(t, note, st, store.Default(), l.Newest)
		// The CLI only reads the state: the render came from the defaults.
		if ok, err := l.exists(ctx, statePath); err != nil || ok {
			t.Errorf("state file %s present after the update: %v (%v)", statePath, ok, err)
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

	check("apply_share_link", func(t *testing.T, note func(string, ...any)) {
		next := configState(false, srvA)
		push(t, note, next, "server lab-a from its share link, the LAN client smart")
		st := apply(t, note, next, runnerapi.OutcomeCommitted)
		wantConfig(t, note, st, next, l.Newest)
		if server := l.lanProxied(ctx, t, note); server != "a" {
			t.Errorf("proxied through server %q, want a (%s)", server, serverEgress["a"])
		}
	})

	check("smart_split", func(t *testing.T, note func(string, ...any)) {
		// Neither name's address, the web server's, is domestic to RouterOS,
		// so both requests reach xray: sniffing reads the HTTP Host, and the
		// domestic name goes direct.
		var dom string
		n, err := viaDirect(ctx, func() {
			dom = l.curl(ctx, "--resolve", "domestic.test:80:203.0.113.30", "http://domestic.test/whoami")
		})
		if err != nil {
			t.Fatal(err)
		}
		foreign := l.curl(ctx, "--resolve", "foreign.test:80:203.0.113.30", "http://foreign.test/whoami")
		note("domestic.test by Host: %q, xray direct downlink +%d bytes; foreign.test: %q", dom, n, foreign)
		if dom != egressDirect || n <= 0 {
			t.Errorf("domestic.test: whoami %q and %d bytes through xray's direct outbound, want %s and some", dom, n, egressDirect)
		}
		if foreign != serverEgress["a"] {
			t.Errorf("foreign.test: whoami %q, want %s (proxied)", foreign, serverEgress["a"])
		}

		// 203.0.113.20 is in RouterOS's tikray-domestic list too, which keeps
		// it away from xray. With that entry off, the request reaches xray,
		// whose domestic IP rule sends it direct.
		viaRouter := l.curl(ctx, "http://203.0.113.20/whoami")
		const entry = `/ip/firewall/address-list/%s [find comment="tikray:domestic"]`
		if _, err := c.Run(ctx, fmt.Sprintf(entry, "disable")); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := c.Run(ctx, fmt.Sprintf(entry, "enable")); err != nil {
				t.Error(err)
			}
		}()
		var viaXray string
		if n, err = viaDirect(ctx, func() { viaXray = l.curl(ctx, "http://203.0.113.20/whoami") }); err != nil {
			t.Fatal(err)
		}
		note("203.0.113.20: %q with the RouterOS list entry, %q without it (xray direct downlink +%d bytes)", viaRouter, viaXray, n)
		if viaRouter != egressDirect {
			t.Errorf("203.0.113.20 with RouterOS's tikray-domestic entry: whoami %q, want %s", viaRouter, egressDirect)
		}
		if viaXray != egressDirect || n <= 0 {
			t.Errorf("203.0.113.20 through xray: whoami %q and %d bytes through its direct outbound, want %s and some", viaXray, n, egressDirect)
		}

		// The router sends the LAN client's DNS to the runner, where the
		// domestic name goes to the domestic resolver direct and every other
		// name to the remote one through the proxy.
		domDNS, foreignDNS := l.dig(ctx, "domestic.test"), l.dig(ctx, "foreign.test")
		note("DNS: domestic.test %q, foreign.test %q", domDNS, foreignDNS)
		if domDNS != answerDirect {
			t.Errorf("domestic.test resolves to %q, want %s (the domestic resolver, asked direct)", domDNS, answerDirect)
		}
		if foreignDNS != answerProxied {
			t.Errorf("foreign.test resolves to %q, want %s (the remote resolver, asked through the proxy)", foreignDNS, answerProxied)
		}
	})

	check("failover", func(t *testing.T, note func(string, ...any)) {
		next := configState(false, srvA, srvB)
		push(t, note, next, "servers lab-a and lab-b")
		st := apply(t, note, next, runnerapi.OutcomeCommitted)
		wantConfig(t, note, st, next, l.Newest)
		first := l.lanProxied(ctx, t, note)
		if first == "" {
			t.FailNow()
		}
		other := map[string]string{"a": "b", "b": "a"}[first]
		setServer(t, note, first, false)
		took, ok := poll(ctx, 30*time.Second, time.Second, func() bool {
			server, _ := l.proxiedVia(ctx)
			return server == other
		})
		note("through server %s %.0fs after %s stopped: %v", other, took.Seconds(), first, ok)
		if !ok {
			t.Errorf("whoami %q 30 s after server %s stopped, want %s (server %s)", l.whoami(ctx), first, serverEgress[other], other)
		}
	})

	check("all_down_open", func(t *testing.T, note func(string, ...any)) {
		setServer(t, note, "a", false)
		setServer(t, note, "b", false)
		took, ok := poll(ctx, 30*time.Second, time.Second, func() bool { return l.whoami(ctx) == egressDirect })
		var got string
		n, err := viaDirect(ctx, func() { got = l.whoami(ctx) })
		if err != nil {
			t.Fatal(err)
		}
		note("direct %.0fs after both servers stopped: %v; whoami %q, xray direct downlink +%d bytes", took.Seconds(), ok, got, n)
		if !ok || got != egressDirect || n <= 0 {
			t.Errorf("whoami %q 30 s after both servers stopped, with %d bytes through xray's direct outbound: want %s through xray (proxy-open falls back direct)", got, n, egressDirect)
		}
	})

	check("all_down_kill_switch", func(t *testing.T, note func(string, ...any)) {
		// The apply's SOCKS probe goes through proxy-closed, and so needs a
		// server up.
		setServer(t, note, "a", true)
		if _, server, ok := l.waitProxied(ctx, l.proxiedWithin()); !ok || server != "a" {
			t.Fatalf("not proxied through server a after it started: whoami %q", l.whoami(ctx))
		}
		next := configState(true, srvA, srvB)
		push(t, note, next, "servers lab-a and lab-b, the LAN client's kill switch on")
		st := apply(t, note, next, runnerapi.OutcomeCommitted)
		wantConfig(t, note, st, next, l.Newest)
		if server := l.lanProxied(ctx, t, note); server != "a" {
			t.Fatalf("proxied through server %q before the outage, want a", server)
		}
		setServer(t, note, "a", false) // b is still down
		var requests int
		var answers []string
		for start := time.Now(); time.Since(start) < 30*time.Second && ctx.Err() == nil; requests++ {
			if got := l.whoami(ctx); got != "" {
				answers = append(answers, got)
			}
			sleep(ctx, time.Second)
		}
		// The runner still answers ping, so RouterOS keeps routing to xray,
		// and the blocking is proxy-closed's fallback.
		rs, err := runnerStatus(ctx)
		note("%d requests in 30 s with both servers down, answers %q; runner %s, gateway_up %v (%v)", requests, answers, rs.State, rs.GatewayUp, err)
		if len(answers) > 0 {
			t.Errorf("with both servers down and the kill switch on, whoami answered %q, want every request blocked", answers)
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

	check("bad_raw_server", func(t *testing.T, note func(string, ...any)) {
		before, err := runnerStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if before.Active == nil {
			t.Fatal("no active selection before the apply")
		}
		bad := badServer()
		next := applied.Clone()
		next.Servers = append(next.Servers, bad)
		push(t, note, next, "the applied state and a raw-JSON server whose VLESS id is 40 characters, not a UUID")
		st := apply(t, note, next, runnerapi.OutcomeRejected)
		// xray run -test refused the config for that server's outbound.
		if lt := st.LastTrial; lt == nil {
			t.Error("no last_trial after the apply")
		} else {
			note("last_trial: outcome %s, detail %q", lt.Outcome, lt.Detail)
			if lt.Outcome != runnerapi.OutcomeRejected || !strings.Contains(lt.Detail, bad.Tag()) {
				t.Errorf("last_trial outcome %s, detail %q: want %s, naming %s", lt.Outcome, lt.Detail, runnerapi.OutcomeRejected, bad.Tag())
			}
		}
		if st.Active == nil || *st.Active != *before.Active {
			t.Errorf("active selection %+v after the rejected apply, want %+v as before", st.Active, *before.Active)
		}
		wantConfig(t, note, st, applied, l.Newest)
		l.lanProxied(ctx, t, note)
	})

	check("older_core_renders", func(t *testing.T, note func(string, ...any)) {
		// The server xray refuses goes again: core updates render from the
		// state as well.
		push(t, note, applied, "the applied state again")
		res := l.tikray(ctx, t, note, "core update "+previousXray)
		wantResult(t, res, artifacts.Result{Outcome: runnerapi.OutcomeCommitted, From: l.Newest, To: previousXray, Source: "direct", Verified: "dgst"})
		st := checkCore(ctx, t, note, previousXray)
		wantConfig(t, note, st, applied, previousXray)
		older, errOld := renderedName(applied, previousXray)
		newest, errNew := renderedName(applied, l.Newest)
		note("the render for %s is the render for %s: %v (%v, %v)", previousXray, l.Newest, older == newest, errOld, errNew)
		l.lanProxied(ctx, t, note)

		res = l.tikray(ctx, t, note, "core rollback")
		wantResult(t, res, artifacts.Result{Outcome: runnerapi.OutcomeCommitted, From: previousXray, To: l.Newest})
		st = checkCore(ctx, t, note, l.Newest)
		wantConfig(t, note, st, applied, l.Newest)
		l.lanProxied(ctx, t, note)
	})
}
