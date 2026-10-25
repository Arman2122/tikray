package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/api"
	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/health"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
)

// The secrets of the fake daemon's state and the token it is called with:
// none of them may be in what a command prints without --json.
const (
	apiToken   = "f00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeed"
	secretID   = "5fdc6e8a-4a2b-4a3c-9d8e-1f2a3b4c5d6e"
	secretPass = "hunter2-trojan-password"
	secretURL  = "https://sub.example.com/feed/4f9a1c7e2b"
	secretLink = "vless://" + secretID + "@203.0.113.10:443?encryption=none#lab-a"
)

var t0 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// fakeState is what the fake daemon holds: three servers (one disabled, one
// on an IPv6 address), two subscriptions and two devices.
func fakeState() store.State {
	st := store.Default()
	st.Servers = []store.Server{
		{
			ID: "5ab3c4d5", Name: "lab-a", Link: secretLink,
			Outbound: json.RawMessage(`{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443,"users":[{"id":"` + secretID + `","encryption":"none"}]}]}}`),
		},
		{
			ID: "6bc4d5e6", Name: "lab-b", Disabled: true,
			Outbound: json.RawMessage(`{"protocol":"trojan","settings":{"servers":[{"address":"b.example.com","port":"8443","password":"` + secretPass + `"}]}}`),
		},
		{
			ID: "7cd5e6f7", Name: "lab-c", Subscription: "9be8f7a6",
			Outbound: json.RawMessage(`{"protocol":"shadowsocks","settings":{"servers":[{"address":"2001:db8::1","port":8388,"method":"aes-128-gcm","password":"` + secretPass + `"}]}}`),
		},
	}
	st.Subscriptions = []store.Subscription{
		{ID: "9be8f7a6", Name: "lab", URL: secretURL, Interval: store.Duration(24 * time.Hour), LastFetch: t0},
		// A last error that repeats the URL, as an error of net/http does.
		{ID: "8ad6f7a8", Name: "broken", URL: secretURL + "-2", Interval: store.Duration(6 * time.Hour), Disabled: true,
			LastError: `Get "` + secretURL + `-2": dial tcp: connection refused`},
	}
	st.Devices = []store.Device{
		{Address: netip.MustParsePrefix("192.168.88.10/32"), Name: "tv", Policy: store.Policy{Mode: store.ModeSmart}},
		{Address: netip.MustParsePrefix("192.168.88.0/24"), Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}},
	}
	return st
}

type fakeCall struct {
	Method string
	Args   []any
}

// fakeBackend is an api.Backend that records its calls and answers from
// canned values.
type fakeBackend struct {
	mu    sync.Mutex
	calls []fakeCall

	state   store.State
	rev     uint64
	err     error // returned by every method that can fail
	result  artifacts.Result
	status  service.Status
	events  []service.Event
	refresh service.RefreshResult
	// gate, if set, runs in ApplyNow, CoreUpdate and CoreRollback.
	gate func(ctx context.Context)
}

var _ api.Backend = (*fakeBackend)(nil)

func newFake() *fakeBackend {
	return &fakeBackend{
		state:  fakeState(),
		rev:    7,
		result: artifacts.Result{From: "26.3.27", To: "26.10.21", Outcome: "committed", Kind: artifacts.KindConfig, At: t0},
		status: service.Status{
			Revision: 7, Applied: true, Core: "26.10.21", CoreTested: true,
			LastApply: &artifacts.Result{From: "26.10.21", To: "26.10.21", Outcome: "committed", Kind: artifacts.KindConfig, At: t0},
			Health: health.Snapshot{
				At: t0, Level: health.LevelDegraded, Selected: "5ab3c4d5",
				Runner: health.RunnerHealth{Reachable: true, State: "running", RoutesOK: true, GatewayUp: true},
				Servers: []health.ServerHealth{
					{ID: "5ab3c4d5", Alive: true, Delay: 120 * time.Millisecond},
					{ID: "7cd5e6f7", Alive: false, LastError: "i/o timeout"},
				},
				Probe: health.ProbeHealth{Ran: true, OK: true, At: t0},
			},
			Degraded: []string{},
		},
		events: []service.Event{
			{Seq: 5, At: t0, Kind: service.KindApply, Message: "revision 6 applied"},
			{Seq: 6, At: t0.Add(time.Minute), Kind: service.KindRefresh, Message: "subscription 9be8f7a6 (lab): 2 added"},
		},
	}
}

func (f *fakeBackend) rec(method string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeCall{method, args})
}

// called returns the arguments of each call to method.
func (f *fakeBackend) called(method string) [][]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]any
	for _, c := range f.calls {
		if c.Method == method {
			out = append(out, c.Args)
		}
	}
	return out
}

// mutations is how many calls changed or did anything: every call but the
// reads.
func (f *fakeBackend) mutations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		switch c.Method {
		case "State", "Status", "Events", "Core", "Redactor":
		default:
			out = append(out, c.Method)
		}
	}
	return out
}

func (f *fakeBackend) enter(ctx context.Context) {
	if f.gate != nil {
		f.gate(ctx)
	}
}

func (f *fakeBackend) State() (store.State, uint64)  { return f.state.Clone(), f.rev }
func (f *fakeBackend) Redactor() func(string) string { return service.RedactorFor(f.state) }

func (f *fakeBackend) Status(context.Context) service.Status {
	f.rec("Status")
	return f.status
}

func (f *fakeBackend) Events(after uint64) []service.Event {
	f.rec("Events", after)
	var out []service.Event
	for _, e := range f.events {
		if e.Seq > after {
			out = append(out, e)
		}
	}
	return out
}

func (f *fakeBackend) Core(context.Context) (service.CoreInfo, error) {
	f.rec("Core")
	return service.CoreInfo{Active: "26.10.21"}, f.err
}

func (f *fakeBackend) ApplyNow(ctx context.Context) (artifacts.Result, error) {
	f.rec("ApplyNow")
	f.enter(ctx)
	return f.result, f.err
}

func (f *fakeBackend) CoreUpdate(ctx context.Context, version string, o artifacts.UpdateOptions) (artifacts.Result, error) {
	f.rec("CoreUpdate", version, o)
	f.enter(ctx)
	return f.result, f.err
}

func (f *fakeBackend) CoreRollback(ctx context.Context) (artifacts.Result, error) {
	f.rec("CoreRollback")
	f.enter(ctx)
	return f.result, f.err
}

func (f *fakeBackend) AddServer(_ context.Context, rev uint64, n service.NewServer) (store.Server, uint64, error) {
	f.rec("AddServer", rev, n)
	if f.err != nil {
		return store.Server{}, 0, f.err
	}
	srv := store.Server{ID: "5ab3c4d5", Name: n.Name, Link: n.Link, Outbound: n.Outbound}
	if n.Link != "" {
		srv.Name = "from-link"
		srv.Outbound = f.state.Servers[0].Outbound
	}
	if n.Name != "" {
		srv.Name = n.Name
	}
	return srv, f.rev + 1, nil
}

func (f *fakeBackend) UpdateServer(_ context.Context, rev uint64, id string, p service.ServerPatch) (store.Server, uint64, error) {
	f.rec("UpdateServer", rev, id, p)
	if f.err != nil {
		return store.Server{}, 0, f.err
	}
	for _, s := range f.state.Servers {
		if s.ID == id {
			if p.Disabled != nil {
				s.Disabled = *p.Disabled
			}
			return s, f.rev + 1, nil
		}
	}
	return store.Server{}, 0, fmt.Errorf("%w: no server %s", service.ErrNotFound, id)
}

func (f *fakeBackend) RemoveServer(_ context.Context, rev uint64, id string) (uint64, error) {
	f.rec("RemoveServer", rev, id)
	return f.rev + 1, f.err
}

func (f *fakeBackend) AddSubscription(_ context.Context, rev uint64, n service.NewSubscription) (store.Subscription, uint64, error) {
	f.rec("AddSubscription", rev, n)
	if f.err != nil {
		return store.Subscription{}, 0, f.err
	}
	sub := store.Subscription{ID: "9be8f7a6", Name: n.Name, URL: n.URL, Interval: n.Interval}
	if sub.Interval == 0 {
		sub.Interval = store.Duration(24 * time.Hour)
	}
	return sub, f.rev + 1, nil
}

func (f *fakeBackend) UpdateSubscription(_ context.Context, rev uint64, id string, p service.SubscriptionPatch) (store.Subscription, uint64, error) {
	f.rec("UpdateSubscription", rev, id, p)
	return store.Subscription{}, 0, f.err
}

func (f *fakeBackend) RemoveSubscription(_ context.Context, rev uint64, id string) (uint64, error) {
	f.rec("RemoveSubscription", rev, id)
	return f.rev + 1, f.err
}

func (f *fakeBackend) RefreshSubscription(_ context.Context, id string) (service.RefreshResult, error) {
	f.rec("RefreshSubscription", id)
	return f.refresh, f.err
}

func (f *fakeBackend) SetDevice(_ context.Context, rev uint64, d store.Device) (uint64, error) {
	f.rec("SetDevice", rev, d)
	return f.rev + 1, f.err
}

func (f *fakeBackend) RemoveDevice(_ context.Context, rev uint64, addr netip.Prefix) (uint64, error) {
	f.rec("RemoveDevice", rev, addr)
	return f.rev + 1, f.err
}

func (f *fakeBackend) SetDefaultPolicy(_ context.Context, rev uint64, p store.Policy) (uint64, error) {
	f.rec("SetDefaultPolicy", rev, p)
	return f.rev + 1, f.err
}

func (f *fakeBackend) SetRouting(_ context.Context, rev uint64, r store.Routing) (uint64, error) {
	f.rec("SetRouting", rev, r)
	return f.rev + 1, f.err
}

func (f *fakeBackend) SetDNS(_ context.Context, rev uint64, d store.DNS) (uint64, error) {
	f.rec("SetDNS", rev, d)
	return f.rev + 1, f.err
}

func (f *fakeBackend) SetHealth(_ context.Context, rev uint64, h store.Health) (uint64, error) {
	f.rec("SetHealth", rev, h)
	return f.rev + 1, f.err
}

// discardLog is the error log of a test server that is refused on purpose.
func discardLog() *log.Logger { return log.New(io.Discard, "", 0) }

// daemon is the fake backend behind the real API handler, on a TLS test
// server.
type daemon struct {
	fake *fakeBackend
	srv  *httptest.Server
}

// startDaemon serves fake over HTTPS with the test server's own certificate.
func startDaemon(t *testing.T, fake *fakeBackend) *daemon {
	t.Helper()
	srv := httptest.NewUnstartedServer(api.NewHandler(fake, apiToken))
	// Refusing a certificate on purpose makes the server log the handshake.
	srv.Config.ErrorLog = discardLog()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &daemon{fake: fake, srv: srv}
}

func (d *daemon) fingerprint() string {
	sum := sha256.Sum256(d.srv.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

// env is the environment of a CLI that reaches the daemon with the variables
// alone, in a data root of its own. TMPDIR is restored afterwards: the
// commands that touch the data root set it.
func (d *daemon) env(t *testing.T) map[string]string {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	return map[string]string{
		"TIKRAY_DATA":            t.TempDir(),
		"TIKRAY_API":             d.srv.URL,
		"TIKRAY_API_TOKEN":       apiToken,
		"TIKRAY_API_FINGERPRINT": d.fingerprint(),
		"TIKRAY_RUNNER_URL":      "http://127.0.0.1:1", // the daemon's job; a direct path would fail loudly
	}
}

// noDaemonEnv is the environment of a CLI with no daemon: TIKRAY_API names a
// port that nothing listens on.
func noDaemonEnv(t *testing.T) map[string]string {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	return map[string]string{
		"TIKRAY_DATA": t.TempDir(),
		"TIKRAY_API":  "https://" + closedAddr(t),
	}
}
