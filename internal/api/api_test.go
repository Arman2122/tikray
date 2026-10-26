package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/health"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/subscription"
	"github.com/Arman2122/tikray/internal/xrayver"
)

// *service.Service must keep every method the handlers call: a signature that
// drifts breaks the build here.
var _ Backend = (*service.Service)(nil)

const (
	testToken = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	// secretID is a VLESS id in the test state, and secretURL a subscription's
	// URL: neither may ever show in a response.
	secretID  = "5fdc6e8a-4a2b-4a3c-9d8e-1f2a3b4c5d6e"
	secretURL = "https://sub.example.com/feed/4f9a1c7e2b"
)

var t0 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

func testState() store.State {
	st := store.Default()
	st.Servers = []store.Server{{
		ID:       "5ab3c4d5",
		Name:     "lab-a",
		Link:     "vless://" + secretID + "@203.0.113.10:443?encryption=none#lab-a",
		Outbound: json.RawMessage(`{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443,"users":[{"id":"` + secretID + `","encryption":"none"}]}]}}`),
	}}
	st.Subscriptions = []store.Subscription{{ID: "9be8f7a6", Name: "lab", URL: secretURL, Interval: store.Duration(24 * time.Hour)}}
	st.Devices = []store.Device{{Address: netip.MustParsePrefix("192.168.88.10/32"), Name: "tv", Policy: store.Policy{Mode: store.ModeSmart}}}
	st.Health = store.Health{ProbeURL: "https://probe.example/204"}
	return st
}

// call is one call of the fake backend. State and Redactor are not recorded:
// the handlers use them for the ETag and for redaction on any route.
type call struct {
	Method string
	Rev    uint64
	Args   []any
}

type fakeBackend struct {
	mu    sync.Mutex
	calls []call

	state  store.State
	rev    uint64 // the current revision
	newRev uint64 // what a change returns
	err    error  // returned by every method that can fail
	result artifacts.Result
	events []service.Event
	core   service.CoreInfo

	// onStatus, if set, runs inside Status.
	onStatus func()
	// gate, if set, runs inside ApplyNow, CoreUpdate, CoreRollback,
	// RefreshSubscription and SetDefaultPolicy, with the context they got.
	gate func(method string, ctx context.Context)
}

func newFake() *fakeBackend {
	return &fakeBackend{
		state:  testState(),
		rev:    7,
		newRev: 8,
		result: artifacts.Result{From: "26.3.27", To: "26.10.21", Outcome: "committed", At: t0},
		events: []service.Event{{Seq: 6, At: t0, Kind: "apply", Message: "revision 7 applied"}},
		core: service.CoreInfo{
			Active: "26.10.21",
			Slots: []artifacts.Slot{{
				Version: xrayver.Version{Major: 26, Minor: 10, Patch: 21},
				Dir:     "/data/cores/26.10.21",
				Meta:    artifacts.Meta{Version: "26.10.21", Source: "github", Verified: "sha256", InstalledAt: t0},
			}},
			History: []artifacts.Result{{To: "26.10.21", Outcome: "committed", At: t0}},
		},
	}
}

func (f *fakeBackend) rec(method string, rev uint64, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{method, rev, args})
}

func (f *fakeBackend) recorded() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]call(nil), f.calls...)
}

// enter runs the gate, if there is one.
func (f *fakeBackend) enter(method string, ctx context.Context) {
	if f.gate != nil {
		f.gate(method, ctx)
	}
}

// change records a mutation, and fails it as the store would on a stale
// revision.
func (f *fakeBackend) change(method string, rev uint64, args ...any) (uint64, error) {
	f.rec(method, rev, args...)
	if f.err != nil {
		return 0, f.err
	}
	if rev != store.AnyRevision && rev != f.rev {
		return 0, store.ErrConflict
	}
	return f.newRev, nil
}

func (f *fakeBackend) State() (store.State, uint64) { return f.state.Clone(), f.rev }

func (f *fakeBackend) Redactor() func(string) string { return service.RedactorFor(f.state) }

func (f *fakeBackend) Status(context.Context) service.Status {
	f.rec("Status", 0)
	if f.onStatus != nil {
		f.onStatus()
	}
	return service.Status{Revision: f.rev, Applied: true, Core: "26.10.21", Health: health.Snapshot{Level: "ok"}, Degraded: []string{}}
}

func (f *fakeBackend) Events(after uint64) []service.Event {
	f.rec("Events", 0, after)
	var out []service.Event
	for _, e := range f.events {
		if e.Seq > after {
			out = append(out, e)
		}
	}
	return out
}

func (f *fakeBackend) Core(context.Context) (service.CoreInfo, error) {
	f.rec("Core", 0)
	return f.core, f.err
}

func (f *fakeBackend) ApplyNow(ctx context.Context) (artifacts.Result, error) {
	f.rec("ApplyNow", 0)
	f.enter("ApplyNow", ctx)
	return f.result, f.err
}

func (f *fakeBackend) CoreUpdate(ctx context.Context, version string, o artifacts.UpdateOptions) (artifacts.Result, error) {
	f.rec("CoreUpdate", 0, version, o)
	f.enter("CoreUpdate", ctx)
	return f.result, f.err
}

func (f *fakeBackend) CoreRollback(ctx context.Context) (artifacts.Result, error) {
	f.rec("CoreRollback", 0)
	f.enter("CoreRollback", ctx)
	return f.result, f.err
}

func (f *fakeBackend) AddServer(_ context.Context, rev uint64, n service.NewServer) (store.Server, uint64, error) {
	r, err := f.change("AddServer", rev, n)
	return store.Server{ID: "aaaaaaaa", Name: n.Name, Link: n.Link, Outbound: json.RawMessage(`{"protocol":"vless"}`)}, r, err
}

func (f *fakeBackend) UpdateServer(_ context.Context, rev uint64, id string, p service.ServerPatch) (store.Server, uint64, error) {
	r, err := f.change("UpdateServer", rev, id, p)
	return store.Server{ID: id, Name: "lab-a", Disabled: p.Disabled != nil && *p.Disabled, Outbound: json.RawMessage(`{"protocol":"vless"}`)}, r, err
}

func (f *fakeBackend) RemoveServer(_ context.Context, rev uint64, id string) (uint64, error) {
	return f.change("RemoveServer", rev, id)
}

func (f *fakeBackend) AddSubscription(_ context.Context, rev uint64, n service.NewSubscription) (store.Subscription, uint64, error) {
	r, err := f.change("AddSubscription", rev, n)
	return store.Subscription{ID: "bbbbbbbb", Name: n.Name, URL: n.URL, Interval: n.Interval}, r, err
}

func (f *fakeBackend) UpdateSubscription(_ context.Context, rev uint64, id string, p service.SubscriptionPatch) (store.Subscription, uint64, error) {
	r, err := f.change("UpdateSubscription", rev, id, p)
	return store.Subscription{ID: id, Name: "lab", URL: "https://sub.example/x", Interval: store.Duration(12 * time.Hour)}, r, err
}

func (f *fakeBackend) RemoveSubscription(_ context.Context, rev uint64, id string) (uint64, error) {
	return f.change("RemoveSubscription", rev, id)
}

func (f *fakeBackend) RefreshSubscription(ctx context.Context, id string) (service.RefreshResult, error) {
	f.rec("RefreshSubscription", 0, id)
	f.enter("RefreshSubscription", ctx)
	return service.RefreshResult{
		Added: 1, Updated: 2, Removed: 3, Kept: 4,
		Skipped: []subscription.Skipped{{Line: "trojan://" + secretID + "@host#lab-b", Err: "bad port"}, {Line: "hello", Err: "scheme is not supported"}},
		Via:     "direct",
	}, f.err
}

func (f *fakeBackend) SetDevice(_ context.Context, rev uint64, d store.Device) (uint64, error) {
	return f.change("SetDevice", rev, d)
}

func (f *fakeBackend) RemoveDevice(_ context.Context, rev uint64, a netip.Prefix) (uint64, error) {
	return f.change("RemoveDevice", rev, a)
}

func (f *fakeBackend) SetDefaultPolicy(ctx context.Context, rev uint64, p store.Policy) (uint64, error) {
	f.enter("SetDefaultPolicy", ctx)
	return f.change("SetDefaultPolicy", rev, p)
}

func (f *fakeBackend) SetRouting(_ context.Context, rev uint64, r store.Routing) (uint64, error) {
	return f.change("SetRouting", rev, r)
}

func (f *fakeBackend) SetDNS(_ context.Context, rev uint64, d store.DNS) (uint64, error) {
	return f.change("SetDNS", rev, d)
}

func (f *fakeBackend) SetHealth(_ context.Context, rev uint64, h store.Health) (uint64, error) {
	return f.change("SetHealth", rev, h)
}

// response is what a request got.
type response struct {
	status int
	header http.Header
	body   []byte
}

// request sends one request, with the headers h and nothing else.
func request(t *testing.T, srv *httptest.Server, method, path, body string, h http.Header) response {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range h {
		req.Header[k] = v
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{resp.StatusCode, resp.Header, b}
}

// authed is the headers of a request that carries the token, plus the pairs
// of extra (name, value, name, value, ...).
func authed(extra ...string) http.Header {
	h := http.Header{"Authorization": {"Bearer " + testToken}}
	for i := 0; i+1 < len(extra); i += 2 {
		h.Set(extra[i], extra[i+1])
	}
	return h
}

func serve(t *testing.T, f *fakeBackend) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(NewHandler(f, testToken))
	t.Cleanup(srv.Close)
	return srv
}

func mustJSON(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// sameJSON fails unless got and want are the same JSON value.
func sameJSON(t *testing.T, got []byte, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Errorf("the body is not JSON: %v", err)
		return
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("bad want: %v", err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("body = %s\nwant   %s", got, want)
	}
}

// errorOf decodes an error body.
func errorOf(t *testing.T, r response) (code, detail string) {
	t.Helper()
	var e struct{ Error, Detail string }
	if err := json.Unmarshal(r.body, &e); err != nil || e.Error == "" {
		t.Fatalf("status %d: the body is not an error object (%v)", r.status, err)
	}
	return e.Error, e.Detail
}

// routeCase is one row of the route table.
type routeCase struct {
	name, method, path, body string
	status                   int
	etag                     string // the ETag the response must carry
	calls                    []call // the backend calls, State and Redactor aside
	response                 string // the JSON body, when it is worth checking; "" for none
}

const (
	curRev  = `"7"` // the ETag of what is read
	nextRev = `"8"` // the ETag of what a change returned
)

var anyRev = store.AnyRevision

func routes(t testing.TB) []routeCase {
	st := testState()
	dev := func(addr string, name string, mode store.Mode) store.Device {
		return store.Device{Address: netip.MustParsePrefix(addr), Name: name, Policy: store.Policy{Mode: mode}}
	}
	return []routeCase{
		{name: "status", method: "GET", path: "/v1/status", status: 200, etag: curRev,
			calls:    []call{{Method: "Status"}},
			response: `{"revision":7,"applied":true,"pending":false,"core":"26.10.21","core_tested":false,"health":` + mustJSON(t, health.Snapshot{Level: "ok"}) + `,"degraded":[]}`},
		{name: "state", method: "GET", path: "/v1/state", status: 200, etag: curRev, response: mustJSON(t, st)},
		{name: "events", method: "GET", path: "/v1/events?after=5", status: 200, etag: curRev,
			calls:    []call{{Method: "Events", Args: []any{uint64(5)}}},
			response: `[{"seq":6,"at":"2026-10-25T12:00:00Z","kind":"apply","message":"revision 7 applied"}]`},
		{name: "events from the start", method: "GET", path: "/v1/events", status: 200, etag: curRev,
			calls: []call{{Method: "Events", Args: []any{uint64(0)}}}},
		{name: "events, none new", method: "GET", path: "/v1/events?after=6", status: 200, etag: curRev,
			calls: []call{{Method: "Events", Args: []any{uint64(6)}}}, response: `[]`},

		{name: "list servers", method: "GET", path: "/v1/servers", status: 200, etag: curRev, response: mustJSON(t, st.Servers)},
		{name: "add a server from a link", method: "POST", path: "/v1/servers", body: `{"link":"vless://x","name":"lab"}`, status: 201, etag: nextRev,
			calls:    []call{{Method: "AddServer", Rev: anyRev, Args: []any{service.NewServer{Link: "vless://x", Name: "lab"}}}},
			response: `{"id":"aaaaaaaa","name":"lab","link":"vless://x","outbound":{"protocol":"vless"}}`},
		{name: "add a server from an outbound", method: "POST", path: "/v1/servers", body: `{"name":"raw","outbound":{"protocol":"vless"}}`, status: 201, etag: nextRev,
			calls: []call{{Method: "AddServer", Rev: anyRev, Args: []any{service.NewServer{Name: "raw", Outbound: json.RawMessage(`{"protocol":"vless"}`)}}}}},
		{name: "add a server, null outbound", method: "POST", path: "/v1/servers", body: `{"link":"vless://x","outbound":null}`, status: 201, etag: nextRev,
			calls: []call{{Method: "AddServer", Rev: anyRev, Args: []any{service.NewServer{Link: "vless://x"}}}}},
		{name: "patch a server", method: "PATCH", path: "/v1/servers/5ab3c4d5", body: `{"name":"new","disabled":true}`, status: 200, etag: nextRev,
			calls:    []call{{Method: "UpdateServer", Rev: anyRev, Args: []any{"5ab3c4d5", service.ServerPatch{Name: ptr("new"), Disabled: ptr(true)}}}},
			response: `{"id":"5ab3c4d5","name":"lab-a","disabled":true,"outbound":{"protocol":"vless"}}`},
		{name: "patch a server's outbound", method: "PATCH", path: "/v1/servers/5ab3c4d5", body: `{"link":"vless://y","outbound":null}`, status: 200, etag: nextRev,
			calls: []call{{Method: "UpdateServer", Rev: anyRev, Args: []any{"5ab3c4d5", service.ServerPatch{Link: ptr("vless://y")}}}}},
		{name: "delete a server", method: "DELETE", path: "/v1/servers/5ab3c4d5", status: 204, etag: nextRev,
			calls: []call{{Method: "RemoveServer", Rev: anyRev, Args: []any{"5ab3c4d5"}}}},

		{name: "list subscriptions", method: "GET", path: "/v1/subscriptions", status: 200, etag: curRev, response: mustJSON(t, st.Subscriptions)},
		{name: "add a subscription", method: "POST", path: "/v1/subscriptions", body: `{"name":"lab","url":"https://sub.example/x","interval":"6h"}`, status: 201, etag: nextRev,
			calls:    []call{{Method: "AddSubscription", Rev: anyRev, Args: []any{service.NewSubscription{Name: "lab", URL: "https://sub.example/x", Interval: store.Duration(6 * time.Hour)}}}},
			response: `{"id":"bbbbbbbb","name":"lab","url":"https://sub.example/x","interval":"6h0m0s"}`},
		{name: "patch a subscription", method: "PATCH", path: "/v1/subscriptions/9be8f7a6", body: `{"interval":"12h","disabled":false,"url":"https://sub.example/y","name":"n"}`, status: 200, etag: nextRev,
			calls: []call{{Method: "UpdateSubscription", Rev: anyRev, Args: []any{"9be8f7a6", service.SubscriptionPatch{
				Name: ptr("n"), URL: ptr("https://sub.example/y"), Disabled: ptr(false), Interval: ptr(store.Duration(12 * time.Hour))}}}}},
		{name: "delete a subscription", method: "DELETE", path: "/v1/subscriptions/9be8f7a6", status: 204, etag: nextRev,
			calls: []call{{Method: "RemoveSubscription", Rev: anyRev, Args: []any{"9be8f7a6"}}}},
		{name: "refresh a subscription", method: "POST", path: "/v1/subscriptions/9be8f7a6/refresh", status: 200, etag: curRev,
			calls: []call{{Method: "RefreshSubscription", Args: []any{"9be8f7a6"}}},
			response: `{"added":1,"updated":2,"removed":3,"kept":4,"via":"direct","skipped":[` +
				`{"line":"trojan://…#lab-b","reason":"bad port"},{"line":"…","reason":"scheme is not supported"}]}`},

		{name: "list devices", method: "GET", path: "/v1/devices", status: 200, etag: curRev, response: mustJSON(t, st.Devices)},
		{name: "set a device, escaped CIDR", method: "PUT", path: "/v1/devices/192.168.88.10%2F32", body: `{"name":"tv","policy":{"mode":"smart"}}`, status: 200, etag: nextRev,
			calls:    []call{{Method: "SetDevice", Rev: anyRev, Args: []any{dev("192.168.88.10/32", "tv", store.ModeSmart)}}},
			response: `{"address":"192.168.88.10/32","name":"tv","policy":{"mode":"smart"}}`},
		{name: "set a device, bare IP", method: "PUT", path: "/v1/devices/192.168.88.10", body: `{"name":"tv","policy":{"mode":"smart"}}`, status: 200, etag: nextRev,
			calls: []call{{Method: "SetDevice", Rev: anyRev, Args: []any{dev("192.168.88.10/32", "tv", store.ModeSmart)}}}},
		{name: "set a range", method: "PUT", path: "/v1/devices/192.168.88.0%2f24", body: `{"policy":{"mode":"full","kill_switch":true}}`, status: 200, etag: nextRev,
			calls: []call{{Method: "SetDevice", Rev: anyRev, Args: []any{store.Device{Address: netip.MustParsePrefix("192.168.88.0/24"), Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}}}}}},
		{name: "set a device, address in the body too", method: "PUT", path: "/v1/devices/192.168.88.10", body: `{"address":"192.168.88.10/32","policy":{"mode":"direct"}}`, status: 200, etag: nextRev,
			calls: []call{{Method: "SetDevice", Rev: anyRev, Args: []any{dev("192.168.88.10/32", "", store.ModeDirect)}}}},
		{name: "delete a device, escaped CIDR", method: "DELETE", path: "/v1/devices/192.168.88.10%2F32", status: 204, etag: nextRev,
			calls: []call{{Method: "RemoveDevice", Rev: anyRev, Args: []any{netip.MustParsePrefix("192.168.88.10/32")}}}},
		{name: "delete a device, bare IP", method: "DELETE", path: "/v1/devices/192.168.88.10", status: 204, etag: nextRev,
			calls: []call{{Method: "RemoveDevice", Rev: anyRev, Args: []any{netip.MustParsePrefix("192.168.88.10/32")}}}},

		{name: "set the default policy", method: "PUT", path: "/v1/policy", body: `{"mode":"smart","kill_switch":true}`, status: 200, etag: nextRev,
			calls:    []call{{Method: "SetDefaultPolicy", Rev: anyRev, Args: []any{store.Policy{Mode: store.ModeSmart, KillSwitch: true}}}},
			response: `{"mode":"smart","kill_switch":true}`},
		{name: "set the routing", method: "PUT", path: "/v1/routing", body: `{"pinned":"5ab3c4d5","block_list":["domain:ads.example"]}`, status: 200, etag: nextRev,
			calls: []call{{Method: "SetRouting", Rev: anyRev, Args: []any{store.Routing{Pinned: "5ab3c4d5", BlockList: []string{"domain:ads.example"}}}}}},
		{name: "set the DNS", method: "PUT", path: "/v1/dns", body: `{"domestic":"192.168.88.1","remote":"https://dns.example/dns-query"}`, status: 200, etag: nextRev,
			calls: []call{{Method: "SetDNS", Rev: anyRev, Args: []any{store.DNS{Domestic: netip.MustParseAddr("192.168.88.1"), Remote: "https://dns.example/dns-query"}}}}},
		{name: "get the health settings", method: "GET", path: "/v1/health", status: 200, etag: curRev, response: `{"probe_url":"https://probe.example/204"}`},
		{name: "set the health settings", method: "PUT", path: "/v1/health", body: `{"probe_url":"https://probe.example/generate_204"}`, status: 200, etag: nextRev,
			calls:    []call{{Method: "SetHealth", Rev: anyRev, Args: []any{store.Health{ProbeURL: "https://probe.example/generate_204"}}}},
			response: `{"probe_url":"https://probe.example/generate_204"}`},

		{name: "apply", method: "POST", path: "/v1/apply", status: 200, etag: curRev,
			calls:    []call{{Method: "ApplyNow"}},
			response: `{"from":"26.3.27","to":"26.10.21","outcome":"committed","at":"2026-10-25T12:00:00Z"}`},
		{name: "core update", method: "POST", path: "/v1/core/update", body: `{"version":"latest","allow_unverified":true}`, status: 200, etag: curRev,
			calls: []call{{Method: "CoreUpdate", Args: []any{"latest", artifacts.UpdateOptions{AllowUnverified: true}}}}},
		{name: "core update, a release", method: "POST", path: "/v1/core/update", body: `{"version":"26.10.21"}`, status: 200, etag: curRev,
			calls: []call{{Method: "CoreUpdate", Args: []any{"26.10.21", artifacts.UpdateOptions{}}}}},
		{name: "core rollback", method: "POST", path: "/v1/core/rollback", status: 200, etag: curRev,
			calls: []call{{Method: "CoreRollback"}}},
		{name: "core info", method: "GET", path: "/v1/core", status: 200, etag: curRev,
			calls: []call{{Method: "Core"}},
			response: `{"active":"26.10.21","slots":[{"version":"26.10.21","verified":"sha256","source":"github","installed_at":"2026-10-25T12:00:00Z"}],` +
				`"history":[{"to":"26.10.21","outcome":"committed","at":"2026-10-25T12:00:00Z"}]}`},
	}
}

func TestTokenRequired(t *testing.T) {
	wrong := map[string]http.Header{
		"no header":      {},
		"wrong token":    {"Authorization": {"Bearer wrong-token-9f3a"}},
		"a prefix":       {"Authorization": {"Bearer " + testToken[:63]}},
		"a suffix":       {"Authorization": {"Bearer " + testToken + "0"}},
		"empty token":    {"Authorization": {"Bearer "}},
		"no scheme":      {"Authorization": {testToken}},
		"basic":          {"Authorization": {"Basic " + testToken}},
		"token in query": {},
	}
	for _, rt := range routes(t) {
		t.Run(rt.name, func(t *testing.T) {
			f := newFake()
			srv := serve(t, f)
			for what, h := range wrong {
				path := rt.path
				if what == "token in query" {
					path += map[bool]string{true: "&", false: "?"}[strings.Contains(path, "?")] + "token=" + testToken
				}
				r := request(t, srv, rt.method, path, rt.body, h)
				if r.status != 401 {
					t.Errorf("%s: status = %d, want 401", what, r.status)
				}
				if code, _ := errorOf(t, r); code != "unauthorized" {
					t.Errorf("%s: code = %q, want unauthorized", what, code)
				}
				if r.header.Get("WWW-Authenticate") != "Bearer" {
					t.Errorf("%s: WWW-Authenticate = %q", what, r.header.Get("WWW-Authenticate"))
				}
				if r.header.Get("ETag") != "" {
					t.Errorf("%s: an unauthenticated response carries an ETag", what)
				}
				if strings.Contains(string(r.body), "wrong-token-9f3a") || strings.Contains(string(r.body), testToken) {
					t.Errorf("%s: the body echoes a token", what)
				}
			}
			if got := f.recorded(); len(got) != 0 {
				t.Errorf("a request without the token reached the backend: %v", got)
			}
		})
	}

	t.Run("healthz needs no token", func(t *testing.T) {
		srv := serve(t, newFake())
		for _, h := range []http.Header{{}, {"Authorization": {"Bearer wrong"}}, authed()} {
			r := request(t, srv, "GET", "/healthz", "", h)
			if r.status != 200 {
				t.Errorf("status = %d, want 200", r.status)
			}
			sameJSON(t, r.body, `{"ok":true}`)
			if r.header.Get("ETag") != "" {
				t.Error("healthz carries an ETag")
			}
		}
	})

	t.Run("the scheme is case-insensitive", func(t *testing.T) {
		srv := serve(t, newFake())
		r := request(t, srv, "GET", "/v1/status", "", http.Header{"Authorization": {"bearer " + testToken}})
		if r.status != 200 {
			t.Errorf("status = %d, want 200", r.status)
		}
	})

	t.Run("an empty token admits nobody", func(t *testing.T) {
		srv := httptest.NewServer(NewHandler(newFake(), ""))
		defer srv.Close()
		for _, h := range []http.Header{{}, {"Authorization": {"Bearer "}}, {"Authorization": {"Bearer"}}} {
			if r := request(t, srv, "GET", "/v1/status", "", h); r.status != 401 {
				t.Errorf("status = %d, want 401", r.status)
			}
		}
	})
}

func TestRoutes(t *testing.T) {
	for _, rt := range routes(t) {
		t.Run(rt.name, func(t *testing.T) {
			f := newFake()
			srv := serve(t, f)
			r := request(t, srv, rt.method, rt.path, rt.body, authed())
			if r.status != rt.status {
				t.Fatalf("status = %d, want %d (body %s)", r.status, rt.status, r.body)
			}
			if got := r.header.Get("ETag"); got != rt.etag {
				t.Errorf("ETag = %q, want %q", got, rt.etag)
			}
			if got := f.recorded(); !reflect.DeepEqual(got, rt.calls) && !(len(got) == 0 && len(rt.calls) == 0) {
				t.Errorf("backend calls = %+v\nwant           %+v", got, rt.calls)
			}
			if r.header.Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store: bodies hold credentials", r.header.Get("Cache-Control"))
			}
			if rt.status == 204 {
				if len(r.body) != 0 {
					t.Errorf("a 204 has a body: %s", r.body)
				}
				return
			}
			if ct := r.header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			if rt.response != "" {
				sameJSON(t, r.body, rt.response)
			} else if !json.Valid(r.body) {
				t.Errorf("the body is not JSON: %s", r.body)
			}
			if rt.status == 201 {
				// The collection, where a GET finds what was made: no route
				// reads one server or subscription alone.
				loc := r.header.Get("Location")
				if loc != rt.path {
					t.Errorf("Location = %q, want %s", loc, rt.path)
				}
				if got := request(t, srv, "GET", loc, "", authed()); got.status != 200 {
					t.Errorf("GET %s, the Location, = %d, want 200", loc, got.status)
				}
			}
		})
	}
}

func TestListsAreNeverNull(t *testing.T) {
	f := newFake()
	f.state.Servers, f.state.Subscriptions, f.state.Devices = nil, nil, nil
	f.events = nil
	f.core = service.CoreInfo{}
	srv := serve(t, f)
	for _, path := range []string{"/v1/servers", "/v1/subscriptions", "/v1/devices", "/v1/events"} {
		if r := request(t, srv, "GET", path, "", authed()); strings.TrimSpace(string(r.body)) != "[]" {
			t.Errorf("GET %s = %s, want []", path, r.body)
		}
	}
	r := request(t, srv, "GET", "/v1/core", "", authed())
	sameJSON(t, r.body, `{"active":"","slots":[],"history":[]}`)

	// A refresh that skipped nothing says so with a list, too.
	srv2 := httptest.NewServer(NewHandler(&withSkips{newFake(), nil}, testToken))
	defer srv2.Close()
	r = request(t, srv2, "POST", "/v1/subscriptions/9be8f7a6/refresh", "", authed())
	sameJSON(t, r.body, `{"added":0,"updated":0,"removed":0,"kept":0,"skipped":[],"via":"direct"}`)
}

// withSkips is a fake whose refresh skips these lines.
type withSkips struct {
	*fakeBackend
	skipped []subscription.Skipped
}

func (w *withSkips) RefreshSubscription(context.Context, string) (service.RefreshResult, error) {
	return service.RefreshResult{Via: "direct", Skipped: w.skipped}, nil
}

// A skipped line may be a share link that holds a credential the state does
// not know, so that no redactor can hide it: the body shows its scheme and its
// name (the fragment) and nothing else.
func TestSkippedLinesCarryNoCredential(t *testing.T) {
	const password = "s3cretPassw0rd"
	for _, c := range []struct{ name, line, want string }{
		{"a trojan link", "trojan://" + password + "@host.example:443?sni=x#Frankfurt%202", "trojan://…#Frankfurt 2"},
		{"a link without a name", "ss://YWVzLTI1Ni1nY206" + password + "@1.2.3.4:8388", "ss://…"},
		{"a base64 link", "vmess://eyJhZGQiOiJob3N0In0=", "vmess://…"},
		{"a credential in the query", "trojan://p@h?password=" + password, "trojan://…"},
		{"the name starts at the first #", "trojan://" + password + "@h#a#b", "trojan://…#a#b"},
		{"a name that does not unescape", "trojan://" + password + "@h#100%zz", "trojan://…#100%zz"},
		{"a name with an escape character", "vless://" + password + "@h#ev\x1b[31mil", "vless://…#ev[31mil"},
		{"a name with a bidi override", "vless://" + password + "@h#ab\u202ecd", "vless://…#abcd"},
		{"text", "hello", "…"},
		{"a page", "<html>blocked</html>", "…"},
		{"text that holds ://", "not a url ://" + password, "…"},
		{"no scheme", "://" + password, "…"},
		{"a # before the ://", "x#y://" + password, "…"},
		{"a credential and no scheme", password, "…"},
		{"empty", "", "…"},
	} {
		t.Run(c.name, func(t *testing.T) {
			skipped := []subscription.Skipped{{Line: c.line, Err: "bad port"}}
			srv := httptest.NewServer(NewHandler(&withSkips{newFake(), skipped}, testToken))
			defer srv.Close()
			r := request(t, srv, "POST", "/v1/subscriptions/9be8f7a6/refresh", "", authed())
			if r.status != 200 {
				t.Fatalf("status = %d", r.status)
			}
			if strings.Contains(string(r.body), password) {
				t.Error("the body shows the credential")
			}
			var got struct {
				Skipped []struct{ Line, Reason string }
			}
			if err := json.Unmarshal(r.body, &got); err != nil || len(got.Skipped) != 1 {
				t.Fatalf("body = %s (%v)", r.body, err)
			}
			if got.Skipped[0].Line != c.want {
				t.Errorf("line = %q, want %q", got.Skipped[0].Line, c.want)
			}
		})
	}

	t.Run("the reason is redacted", func(t *testing.T) {
		skipped := []subscription.Skipped{{Line: "trojan://x@h", Err: "xray rejects id " + secretID}}
		srv := httptest.NewServer(NewHandler(&withSkips{newFake(), skipped}, testToken))
		defer srv.Close()
		r := request(t, srv, "POST", "/v1/subscriptions/9be8f7a6/refresh", "", authed())
		if strings.Contains(string(r.body), secretID) || !strings.Contains(string(r.body), "‹redacted›") {
			t.Error("the reason was not redacted")
		}
	})
}

// A client that goes away must not stop an apply, an update, a rollback or a
// refresh half way, with a trial open on the router: they run on a context
// of their own. A change keeps the request's.
func TestOperationsOutliveTheirRequest(t *testing.T) {
	for _, c := range []struct {
		name, method, path, body, call string
		detached                       bool
	}{
		{"apply", "POST", "/v1/apply", "", "ApplyNow", true},
		{"core update", "POST", "/v1/core/update", `{"version":"latest"}`, "CoreUpdate", true},
		{"core rollback", "POST", "/v1/core/rollback", "", "CoreRollback", true},
		{"refresh", "POST", "/v1/subscriptions/9be8f7a6/refresh", "", "RefreshSubscription", true},
		// The control: here the disconnect does reach the backend's context,
		// so that the others show nothing for want of a way to see it.
		{"a change", "PUT", "/v1/policy", `{"mode":"full"}`, "SetDefaultPolicy", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			got, release := make(chan context.Context, 1), make(chan struct{})
			f.gate = func(method string, ctx context.Context) {
				if method == c.call {
					got <- ctx
					<-release
				}
			}
			srv := serve(t, f)
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock) // before the server's Close, which waits for the handler

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, c.method, srv.URL+c.path, strings.NewReader(c.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+testToken)
			done := make(chan struct{})
			go func() {
				defer close(done)
				if resp, err := srv.Client().Do(req); err == nil {
					resp.Body.Close()
				}
			}()

			var backendCtx context.Context
			select {
			case backendCtx = <-got:
			case <-time.After(5 * time.Second):
				t.Fatal("the backend was not called")
			}
			cancel() // the client goes away
			<-done

			if c.detached {
				time.Sleep(300 * time.Millisecond)
				if err := backendCtx.Err(); err != nil {
					t.Errorf("the backend's context ended with the request: %v", err)
				}
			} else {
				select {
				case <-backendCtx.Done():
				case <-time.After(5 * time.Second):
					t.Error("control: the server never saw the client go")
				}
			}
			unblock()
		})
	}
}

func TestUnknownRoute(t *testing.T) {
	srv := serve(t, newFake())
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/nope"},
		{"GET", "/"},
		{"GET", "/v1/servers/"},
		{"GET", "/v1/devices/192.168.88.10/32"}, // an unescaped slash is another segment
		{"PUT", "/v1/servers/5ab3c4d5"},         // no such method on the route
	} {
		r := request(t, srv, c.method, c.path, "", authed())
		if r.status != 404 {
			t.Errorf("%s %s: status = %d, want 404", c.method, c.path, r.status)
			continue
		}
		if code, _ := errorOf(t, r); code != "not_found" {
			t.Errorf("%s %s: code = %q, want not_found", c.method, c.path, code)
		}
	}
	// Without the token a caller learns nothing of the routes.
	if r := request(t, srv, "GET", "/v1/nope", "", nil); r.status != 401 {
		t.Errorf("status = %d, want 401", r.status)
	}
}

func TestDeviceAddresses(t *testing.T) {
	for _, c := range []struct {
		name, method, path, body string
		status                   int
	}{
		{"not an address", "PUT", "/v1/devices/tv", `{"policy":{"mode":"smart"}}`, 400},
		{"a bad prefix length", "PUT", "/v1/devices/192.168.88.10%2F33", `{"policy":{"mode":"smart"}}`, 400},
		{"a bad octet", "DELETE", "/v1/devices/192.168.88.300", "", 400},
		{"the body names another address", "PUT", "/v1/devices/192.168.88.10", `{"address":"192.168.88.11/32","policy":{"mode":"smart"}}`, 400},
		{"the body's address is not one", "PUT", "/v1/devices/192.168.88.10", `{"address":"x","policy":{"mode":"smart"}}`, 400},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			s := serve(t, f)
			r := request(t, s, c.method, c.path, c.body, authed())
			if r.status != c.status {
				t.Fatalf("status = %d, want %d (%s)", r.status, c.status, r.body)
			}
			if code, _ := errorOf(t, r); code != "bad_request" {
				t.Errorf("code = %q, want bad_request", code)
			}
			if got := f.recorded(); len(got) != 0 {
				t.Errorf("the backend was called: %v", got)
			}
		})
	}
}

func TestIfMatchConflict(t *testing.T) {
	t.Run("a stale revision is a conflict", func(t *testing.T) {
		f := newFake()
		srv := serve(t, f)
		r := request(t, srv, "PATCH", "/v1/servers/5ab3c4d5", `{"disabled":true}`, authed("If-Match", `"3"`))
		if r.status != 409 {
			t.Fatalf("status = %d, want 409", r.status)
		}
		if code, _ := errorOf(t, r); code != "conflict" {
			t.Errorf("code = %q, want conflict", code)
		}
		// The error says what the revision is now, so that the caller can read again.
		if got := r.header.Get("ETag"); got != curRev {
			t.Errorf("ETag = %q, want %s", got, curRev)
		}
		if got := f.recorded(); len(got) != 1 || got[0].Rev != 3 {
			t.Errorf("the backend saw %+v, want one call with revision 3", got)
		}
	})

	t.Run("the current revision goes through", func(t *testing.T) {
		f := newFake()
		srv := serve(t, f)
		r := request(t, srv, "PUT", "/v1/policy", `{"mode":"full"}`, authed("If-Match", `"7"`))
		if r.status != 200 {
			t.Fatalf("status = %d (%s)", r.status, r.body)
		}
		if got := r.header.Get("ETag"); got != nextRev {
			t.Errorf("ETag = %q, want the new revision %s", got, nextRev)
		}
		if got := f.recorded(); len(got) != 1 || got[0].Rev != 7 {
			t.Errorf("the backend saw %+v, want revision 7", got)
		}
	})

	t.Run("revision 0 is a revision", func(t *testing.T) {
		f := newFake()
		f.rev = 0
		srv := serve(t, f)
		r := request(t, srv, "DELETE", "/v1/servers/5ab3c4d5", "", authed("If-Match", `"0"`))
		if r.status != 204 {
			t.Fatalf("status = %d (%s)", r.status, r.body)
		}
		if got := f.recorded(); len(got) != 1 || got[0].Rev != 0 {
			t.Errorf("the backend saw %+v, want revision 0", got)
		}
	})

	t.Run("every change takes a revision", func(t *testing.T) {
		for _, rt := range routes(t) {
			if rt.etag != nextRev {
				continue
			}
			f := newFake()
			srv := serve(t, f)
			r := request(t, srv, rt.method, rt.path, rt.body, authed("If-Match", `"3"`))
			if r.status != 409 {
				t.Errorf("%s: status = %d, want 409", rt.name, r.status)
			}
		}
	})
}

func TestIfMatchForms(t *testing.T) {
	// Present means it must name one revision, in quotes; an empty one is no
	// better than a wrong one.
	var first string
	for _, h := range []string{``, ` `, `7`, `W/"7"`, `"x"`, `"7", "8"`, `*`, `""`, `"-1"`, `"99999999999999999999999"`, `"7`} {
		t.Run(h, func(t *testing.T) {
			f := newFake()
			srv := serve(t, f)
			r := request(t, srv, "PUT", "/v1/policy", `{"mode":"full"}`, http.Header{"Authorization": {"Bearer " + testToken}, "If-Match": {h}})
			if r.status != 400 {
				t.Fatalf("status = %d, want 400", r.status)
			}
			code, detail := errorOf(t, r)
			if code != "bad_request" {
				t.Errorf("code = %q, want bad_request", code)
			}
			// The header is not echoed: the text is the same for every form.
			if first == "" {
				first = detail
			} else if detail != first {
				t.Errorf("detail = %q, but another header got %q", detail, first)
			}
			if got := f.recorded(); len(got) != 0 {
				t.Errorf("the backend was called: %v", got)
			}
		})
	}

	t.Run("two If-Match headers", func(t *testing.T) {
		srv := serve(t, newFake())
		r := request(t, srv, "PUT", "/v1/policy", `{"mode":"full"}`, http.Header{"Authorization": {"Bearer " + testToken}, "If-Match": {`"7"`, `"7"`}})
		if r.status != 400 {
			t.Errorf("status = %d, want 400", r.status)
		}
	})

	t.Run("a read ignores If-Match", func(t *testing.T) {
		srv := serve(t, newFake())
		r := request(t, srv, "GET", "/v1/state", "", authed("If-Match", `"3"`))
		if r.status != 200 {
			t.Errorf("status = %d, want 200", r.status)
		}
	})

	t.Run("so do the routes that take no revision", func(t *testing.T) {
		f := newFake()
		srv := serve(t, f)
		for _, path := range []string{"/v1/apply", "/v1/core/rollback", "/v1/subscriptions/9be8f7a6/refresh"} {
			if r := request(t, srv, "POST", path, "", authed("If-Match", `"3"`)); r.status != 200 {
				t.Errorf("%s: status = %d, want 200", path, r.status)
			}
		}
	})
}

func TestErrorMapping(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("while doing it: %w", err) }
	every := []string{"POST /v1/apply", "POST /v1/core/update", "POST /v1/core/rollback", "POST /v1/subscriptions/9be8f7a6/refresh",
		"GET /v1/core", "PUT /v1/policy", "DELETE /v1/servers/5ab3c4d5"}
	// The three operations that return an outcome with their error.
	ops := []string{"POST /v1/apply", "POST /v1/core/update", "POST /v1/core/rollback"}
	cases := []struct {
		name   string
		err    error
		result artifacts.Result // what the backend returns with the error
		routes []string
		status int
		code   string
		detail string // wanted in the detail, when set
	}{
		{"refused", &service.Refused{Reason: "servers[0]: bad port"}, artifacts.Result{}, every, 422, "refused", "servers[0]: bad port"},
		{"refused, wrapped", wrap(&service.Refused{Reason: "servers[0]: bad port"}), artifacts.Result{}, every, 422, "refused", "servers[0]: bad port"},
		{"not found", wrap(service.ErrNotFound), artifacts.Result{}, every, 404, "not_found", "not found"},
		{"conflict", wrap(store.ErrConflict), artifacts.Result{}, every, 409, "conflict", "changed"},
		{"locked", wrap(artifacts.ErrLocked), artifacts.Result{}, every, 409, "busy", "another core update"},
		{"the runner has a trial open", wrap(runnerapi.ErrBusy), artifacts.Result{}, every, 409, "busy", ""},
		{"runner unavailable", fmt.Errorf("%w: %w", service.ErrRunnerUnavailable, context.DeadlineExceeded), artifacts.Result{}, every, 503, "runner_unavailable", "can't be reached"},
		{"fetch failed", fmt.Errorf("%w: %w", service.ErrFetchFailed, context.DeadlineExceeded), artifacts.Result{}, every, 502, "fetch_failed", "could not be fetched"},
		{"cancelled", context.Canceled, artifacts.Result{}, every, 503, "unavailable", "the request was cancelled or timed out"},
		{"timed out", wrap(context.DeadlineExceeded), artifacts.Result{}, every, 503, "unavailable", "the request was cancelled or timed out"},
		{"anything else", errors.New("disk on fire"), artifacts.Result{}, every, 500, "internal", "disk on fire"},
		// A change that ran to an outcome and failed is the person's to fix
		// (xray rejected the config, the proxy did not come up), not a fault.
		{"rejected", errors.New("rejected: xray run -test failed"), artifacts.Result{Outcome: "rejected"}, ops, 422, "refused", "rejected: xray run -test failed"},
		{"unhealthy", errors.New("unhealthy: no proxy"), artifacts.Result{Outcome: "unhealthy"}, ops, 422, "refused", "unhealthy: no proxy"},
		// The service's error when the proxy probe fails through the
		// candidate, as net/http's calls do, while the runner answers.
		{"unhealthy, the probe failing", fmt.Errorf("unhealthy: health check failing for 15s: %w", &url.Error{Op: "Get", URL: "http://203.0.113.30/whoami", Err: errors.New("socks connect: general failure")}),
			artifacts.Result{Outcome: "unhealthy"}, ops, 422, "refused", "socks connect: general failure"},
		{"aborted by a cancelled request", wrap(context.Canceled), artifacts.Result{Outcome: "aborted"}, ops, 503, "unavailable", ""},
		{"an outcome with the lock held", wrap(artifacts.ErrLocked), artifacts.Result{Outcome: "refused"}, ops, 409, "busy", ""},
		{"an outcome with a trial open", wrap(runnerapi.ErrBusy), artifacts.Result{Outcome: "refused"}, ops, 409, "busy", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			f.err, f.result = c.err, c.result
			srv := serve(t, f)
			for _, route := range c.routes {
				method, path, _ := strings.Cut(route, " ")
				body := ""
				switch path {
				case "/v1/core/update":
					body = `{"version":"latest"}`
				case "/v1/policy":
					body = `{"mode":"full"}`
				}
				r := request(t, srv, method, path, body, authed())
				if r.status != c.status {
					t.Errorf("%s: status = %d, want %d (%s)", route, r.status, c.status, r.body)
					continue
				}
				code, detail := errorOf(t, r)
				if code != c.code {
					t.Errorf("%s: code = %q, want %q", route, code, c.code)
				}
				if c.detail != "" && !strings.Contains(detail, c.detail) {
					t.Errorf("%s: detail = %q, want it to hold %q", route, detail, c.detail)
				}
				if r.header.Get("ETag") != curRev {
					t.Errorf("%s: ETag = %q, want the current revision", route, r.header.Get("ETag"))
				}
			}
		})
	}
}

// An apply, an update or a rollback that ran to an outcome and failed says how
// it ended in the error body's "result", as the direct path prints it, with
// its Detail redacted: the client reports that, not a refusal of its own. An
// error without an outcome, and every other route, have no result.
func TestOperationErrorsCarryTheResult(t *testing.T) {
	unhealthy := artifacts.Result{From: "26.3.27", To: "26.10.21", Outcome: "unhealthy", Kind: artifacts.KindConfig,
		Source: "github", Verified: "sha256", Detail: "health check failing for 15s: user " + secretID, At: t0}
	locked := artifacts.Result{Outcome: "refused", Kind: artifacts.KindConfig, Detail: "artifacts: another core update or rollback is running", At: t0}
	for _, c := range []struct {
		name   string
		err    error
		result artifacts.Result
		routes []string
		status int
		want   *artifacts.Result // the body's result
	}{
		{"unhealthy", errors.New("unhealthy: health check failing for 15s: user " + secretID), unhealthy,
			[]string{"POST /v1/apply", "POST /v1/core/update", "POST /v1/core/rollback"}, 422,
			&artifacts.Result{From: "26.3.27", To: "26.10.21", Outcome: "unhealthy", Kind: artifacts.KindConfig,
				Source: "github", Verified: "sha256", Detail: "health check failing for 15s: user ‹redacted›", At: t0}},
		{"the lock held", fmt.Errorf("refused: %w", artifacts.ErrLocked), locked, []string{"POST /v1/apply"}, 409, &locked},
		{"no outcome", fmt.Errorf("%w: connection refused", service.ErrRunnerUnavailable), artifacts.Result{}, []string{"POST /v1/apply"}, 503, nil},
		{"another route", &service.Refused{Reason: "no"}, unhealthy, []string{"PUT /v1/policy", "GET /v1/core"}, 422, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			f.err, f.result = c.err, c.result
			srv := serve(t, f)
			for _, route := range c.routes {
				method, path, _ := strings.Cut(route, " ")
				body := map[string]string{"/v1/core/update": `{"version":"latest"}`, "/v1/policy": `{"mode":"full"}`}[path]
				r := request(t, srv, method, path, body, authed())
				if r.status != c.status {
					t.Errorf("%s: status = %d, want %d", route, r.status, c.status)
				}
				errorOf(t, r)
				var got struct {
					Result *artifacts.Result `json:"result"`
				}
				if err := json.Unmarshal(r.body, &got); err != nil {
					t.Fatalf("%s: %v", route, err)
				}
				if !reflect.DeepEqual(got.Result, c.want) {
					// The message never shows the secret.
					shown := strings.ReplaceAll(fmt.Sprintf("%+v", got.Result), secretID, "<the id>")
					t.Errorf("%s: result = %s, want %+v", route, shown, c.want)
				}
				if strings.Contains(string(r.body), secretID) {
					t.Errorf("%s: the body shows a secret", route)
				}
			}
		})
	}
}

func TestErrorsHaveNoSecrets(t *testing.T) {
	leaky := fmt.Sprintf("fetching %s failed for id %s", secretURL, secretID)
	cases := []struct {
		name     string
		err      error
		result   artifacts.Result
		route    string
		status   int
		fixedMsg bool // the detail is a fixed text, so nothing is there to redact
	}{
		{"internal", errors.New(leaky), artifacts.Result{}, "POST /v1/apply", 500, false},
		{"refused", &service.Refused{Reason: leaky}, artifacts.Result{}, "PUT /v1/policy", 422, false},
		{"not found", fmt.Errorf("%w: server %s", service.ErrNotFound, secretID), artifacts.Result{}, "DELETE /v1/servers/5ab3c4d5", 404, false},
		{"conflict", fmt.Errorf("%w (%s)", store.ErrConflict, leaky), artifacts.Result{}, "PUT /v1/policy", 409, false},
		{"busy", fmt.Errorf("%w (%s)", artifacts.ErrLocked, leaky), artifacts.Result{}, "POST /v1/apply", 409, false},
		{"runner unavailable", fmt.Errorf("%w: %s", service.ErrRunnerUnavailable, leaky), artifacts.Result{}, "POST /v1/apply", 503, false},
		{"fetch failed", fmt.Errorf("%w: %s", service.ErrFetchFailed, leaky), artifacts.Result{}, "POST /v1/subscriptions/9be8f7a6/refresh", 502, false},
		{"cancelled", fmt.Errorf("%s: %w", leaky, context.Canceled), artifacts.Result{}, "POST /v1/apply", 503, true},
		// xray's own output reaches an error through TestFailedError, whose
		// text holds it raw: the body takes the error's text, redacted, and
		// never the .Output field.
		{"rejected by xray", fmt.Errorf("rejected: %w", &runnerapi.TestFailedError{Output: "bad id " + secretID}), artifacts.Result{Outcome: "rejected", Detail: "bad id " + secretID}, "POST /v1/core/update", 422, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			f.err, f.result = c.err, c.result
			srv := serve(t, f)
			method, path, _ := strings.Cut(c.route, " ")
			body := ""
			switch path {
			case "/v1/policy":
				body = `{"mode":"full"}`
			case "/v1/core/update":
				body = `{"version":"latest"}`
			}
			r := request(t, srv, method, path, body, authed())
			if r.status != c.status {
				t.Fatalf("status = %d, want %d", r.status, c.status)
			}
			_, detail := errorOf(t, r)
			for _, secret := range []string{secretID, secretURL, testToken} {
				if strings.Contains(string(r.body), secret) {
					t.Errorf("the body shows a secret (%d bytes of it)", len(secret))
				}
			}
			if !c.fixedMsg && !strings.Contains(detail, "‹redacted›") {
				t.Errorf("the detail was not redacted: %q", detail)
			}
		})
	}

	t.Run("a bad request", func(t *testing.T) {
		srv := serve(t, newFake())
		// The unknown field's name is the secret: json's message quotes it.
		r := request(t, srv, "POST", "/v1/servers", `{"`+secretID+`":1}`, authed())
		if r.status != 400 {
			t.Fatalf("status = %d, want 400", r.status)
		}
		if strings.Contains(string(r.body), secretID) {
			t.Error("the body shows a secret")
		}
	})

	t.Run("a bad device address", func(t *testing.T) {
		srv := serve(t, newFake())
		r := request(t, srv, "DELETE", "/v1/devices/"+secretID, "", authed())
		if r.status != 400 || strings.Contains(string(r.body), secretID) {
			t.Errorf("status = %d, and the body may show a secret", r.status)
		}
	})

	t.Run("a refresh result", func(t *testing.T) {
		// A line the refresh skipped may hold a credential of a server the
		// state knows.
		srv := serve(t, newFake())
		r := request(t, srv, "POST", "/v1/subscriptions/9be8f7a6/refresh", "", authed())
		if r.status != 200 || strings.Contains(string(r.body), secretID) {
			t.Errorf("status = %d, and the body may show a secret", r.status)
		}
	})

	t.Run("the token", func(t *testing.T) {
		// No error path puts the Authorization header in a body.
		srv := serve(t, newFake())
		for _, h := range []string{"Bearer " + testToken + "x", "Bearer sekret-9f3a", "Basic c2VrcmV0OjlmM2E="} {
			r := request(t, srv, "GET", "/v1/status", "", http.Header{"Authorization": {h}})
			if strings.Contains(string(r.body), strings.TrimPrefix(strings.TrimPrefix(h, "Bearer "), "Basic ")) {
				t.Errorf("the 401 body echoes the header")
			}
		}
	})
}

func TestBodyLimitAndUnknownFields(t *testing.T) {
	for _, c := range []struct {
		name, method, path, body string
	}{
		{"unknown field", "POST", "/v1/servers", `{"link":"vless://x","bogus":1}`},
		{"unknown field in a nested object", "PUT", "/v1/policy", `{"mode":"smart","extra":{"a":1}}`},
		{"unknown field on a patch", "PATCH", "/v1/subscriptions/9be8f7a6", `{"nope":true}`},
		{"unknown field in the device's policy", "PUT", "/v1/devices/192.168.88.10", `{"policy":{"mode":"smart","x":1}}`},
		{"unknown field on core update", "POST", "/v1/core/update", `{"version":"latest","config_file":"/etc/passwd"}`},
		{"a second value", "POST", "/v1/servers", `{"link":"vless://x"} {"link":"vless://y"}`},
		{"trailing garbage", "POST", "/v1/servers", `{"link":"vless://x"}x`},
		{"trailing token", "PUT", "/v1/policy", `{"mode":"smart"},`},
		{"not JSON", "POST", "/v1/servers", `link=vless://x`},
		{"truncated", "POST", "/v1/servers", `{"link":"vless://x"`},
		{"a list for an object", "POST", "/v1/servers", `[]`},
		{"a number for a string", "POST", "/v1/servers", `{"link":5}`},
		{"a number for an interval", "POST", "/v1/subscriptions", `{"url":"https://x.example","interval":3600}`},
		{"a bad interval", "POST", "/v1/subscriptions", `{"url":"https://x.example","interval":"soon"}`},
		{"an empty body", "PUT", "/v1/policy", ``},
		{"an empty body to core update", "POST", "/v1/core/update", ``},
		{"core update without a version", "POST", "/v1/core/update", `{"allow_unverified":true}`},
		{"over the cap", "POST", "/v1/servers", `{"name":"` + strings.Repeat("a", 1<<20) + `"}`},
		{"over the cap, no JSON", "PUT", "/v1/routing", strings.Repeat(" ", 1<<20+1)},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			srv := serve(t, f)
			r := request(t, srv, c.method, c.path, c.body, authed())
			if r.status != 400 {
				t.Fatalf("status = %d, want 400 (%.200s)", r.status, r.body)
			}
			if code, _ := errorOf(t, r); code != "bad_request" {
				t.Errorf("code = %q, want bad_request", code)
			}
			if got := f.recorded(); len(got) != 0 {
				t.Errorf("the backend was called: %v", got)
			}
		})
	}

	t.Run("a body just under the cap is read", func(t *testing.T) {
		f := newFake()
		srv := serve(t, f)
		name := strings.Repeat("a", 1<<20-len(`{"name":""}`))
		r := request(t, srv, "POST", "/v1/servers", `{"name":"`+name+`"}`, authed())
		if r.status != 201 {
			t.Fatalf("status = %d, want 201 (%.200s)", r.status, r.body)
		}
	})

	t.Run("trailing space is no trailing data", func(t *testing.T) {
		f := newFake()
		srv := serve(t, f)
		r := request(t, srv, "PUT", "/v1/policy", "{\"mode\":\"smart\"} \n\t\n", authed())
		if r.status != 200 {
			t.Fatalf("status = %d, want 200 (%s)", r.status, r.body)
		}
	})

	t.Run("a body is no use to a route that takes none", func(t *testing.T) {
		// It is not read, so that it can't be wrong; the cap still holds.
		f := newFake()
		srv := serve(t, f)
		r := request(t, srv, "POST", "/v1/apply", `{"anything":true}`, authed())
		if r.status != 200 {
			t.Errorf("status = %d, want 200", r.status)
		}
	})
}

func TestEventsAfter(t *testing.T) {
	srv := serve(t, newFake())
	for _, after := range []string{"x", "-1", "1.5", "99999999999999999999999"} {
		r := request(t, srv, "GET", "/v1/events?after="+after, "", authed())
		if r.status != 400 {
			t.Errorf("after=%s: status = %d, want 400", after, r.status)
		}
	}
}
