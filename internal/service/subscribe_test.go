package service

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/sharelink"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/subscription"
)

const (
	subToken = "tk-8c41f7e2a9b0"
	subPass  = "pw-Zq93kd0"
	subHost  = "sub.example.net"
	// subURL is a subscription URL as providers hand them out: a token in the
	// path and a password in the userinfo.
	subURL = "https://alice:" + subPass + "@" + subHost + "/api/v1/sub/" + subToken + "?flag=v2ray"
	// otherID is the id of a second VLESS credential.
	otherID = "0f1e2d3c-4b5a-4968-8778-695a4b3c2d1e"

	blockPage = `<html><body>Access to this site is blocked. <a href="http://block.example/">Why?</a></body></html>`
)

var subSecrets = []secret{
	{"the subscription URL", subURL},
	{"the subscription token", subToken},
	{"the subscription password", subPass},
	{"the subscription host", subHost},
}

// feedLink is a VLESS link for 203.0.113.<n> named name, with the credential
// vlessID.
func feedLink(n int, name string) string {
	return strings.NewReplacer("203.0.113.10", fmt.Sprintf("203.0.113.%d", n), "#lab", "#"+name).Replace(vlessLink)
}

// feedBody is a subscription's body that lists links.
func feedBody(links ...string) string { return strings.Join(links, "\n") + "\n" }

// feedReply is what the fake provider answers one request with.
type feedReply struct {
	status int // 0 means 200
	body   string
	// err fails the request. The error names the URL, as a transport's can.
	err error
}

func okFeed(body string) feedReply { return feedReply{body: body} }

// feedCall is one request the fake provider got.
type feedCall struct{ route, path string }

// fakeFeed is the provider's server, reached directly and through the proxy.
type fakeFeed struct {
	mu      sync.Mutex
	direct  feedReply
	proxy   feedReply
	per     map[string]feedReply // direct replies by URL path, before direct
	proxyUp bool
	// onDirect, if set, runs at each direct request before it is answered.
	onDirect func(path string)
	calls    []feedCall
}

func (f *fakeFeed) setDirect(r feedReply) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.direct = r
}

func (f *fakeFeed) setProxy(r feedReply) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proxy = r
}

func (f *fakeFeed) setPer(path string, r feedReply) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.per == nil {
		f.per = map[string]feedReply{}
	}
	f.per[path] = r
}

// routes returns the routes of the requests so far, in order.
func (f *fakeFeed) routes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		out = append(out, c.route)
	}
	return out
}

// requests returns the requests so far, as "<route> <path>".
func (f *fakeFeed) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		out = append(out, c.route+" "+c.path)
	}
	return out
}

// fetcher is the Config.Fetcher of a service that fetches from f. Its Accept
// takes everything, which the refresh must override.
func (f *fakeFeed) fetcher(store.State) subscription.Fetcher {
	return subscription.Fetcher{
		Direct: &http.Client{Transport: feedRoute{f, "direct"}},
		Proxy:  &http.Client{Transport: feedRoute{f, "proxy"}},
		ProxyHealthy: func(context.Context) bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.proxyUp
		},
		Accept: func([]byte) error { return nil },
	}
}

type feedRoute struct {
	f     *fakeFeed
	route string
}

func (r feedRoute) RoundTrip(req *http.Request) (*http.Response, error) {
	f := r.f
	f.mu.Lock()
	f.calls = append(f.calls, feedCall{r.route, req.URL.Path})
	reply, hook := f.proxy, f.onDirect
	if r.route == "direct" {
		reply = f.direct
		if p, ok := f.per[req.URL.Path]; ok {
			reply = p
		}
	}
	f.mu.Unlock()
	if r.route == "direct" && hook != nil {
		hook(req.URL.Path)
	}
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	if reply.err != nil {
		return nil, fmt.Errorf("%w (%s)", reply.err, req.URL)
	}
	return &http.Response{
		StatusCode:    cmp.Or(reply.status, http.StatusOK),
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader(reply.body)),
		ContentLength: -1,
		Request:       req,
	}, nil
}

// newSubEnv is an env whose service fetches from the returned feed, which
// starts out answering nothing and with a healthy proxy.
func newSubEnv(t *testing.T) (*env, *fakeFeed) {
	t.Helper()
	e := newEnv(t)
	f := &fakeFeed{proxyUp: true, direct: feedReply{status: http.StatusNotFound}, proxy: feedReply{status: http.StatusNotFound}}
	e.s = e.newService(Config{Fetcher: f.fetcher})
	return e, f
}

// putSub adds sub to the state.
func (e *env) putSub(sub store.Subscription) {
	e.t.Helper()
	_, _, err := e.store.Update(store.AnyRevision, func(st *store.State) error {
		st.Subscriptions = append(st.Subscriptions, sub)
		return nil
	})
	if err != nil {
		e.t.Fatal(show(err))
	}
}

// addSub adds a subscription named name at subURL, with the servers that an
// earlier refresh would have made of links, and returns it and them.
func (e *env) addSub(name string, links ...string) (store.Subscription, []store.Server) {
	e.t.Helper()
	res := subscription.Parse([]byte(feedBody(links...)))
	if len(res.Entries) != len(links) {
		e.t.Fatalf("%d of the %d links give a server", len(res.Entries), len(links))
	}
	sub := store.Subscription{ID: store.NewID(), Name: name, URL: subURL, Interval: store.Duration(24 * time.Hour)}
	var servers []store.Server
	for _, en := range res.Entries {
		servers = append(servers, store.Server{ID: store.NewID(), Name: en.Server.Name, Link: en.Link, Subscription: sub.ID, Outbound: en.Server.Outbound})
	}
	_, _, err := e.store.Update(store.AnyRevision, func(st *store.State) error {
		st.Subscriptions = append(st.Subscriptions, sub)
		st.Servers = append(st.Servers, servers...)
		return nil
	})
	if err != nil {
		e.t.Fatal(show(err))
	}
	return sub, servers
}

// patchSub changes the subscription id in the state.
func (e *env) patchSub(id string, fn func(*store.Subscription)) {
	e.t.Helper()
	_, _, err := e.store.Update(store.AnyRevision, func(st *store.State) error {
		i := slices.IndexFunc(st.Subscriptions, func(s store.Subscription) bool { return s.ID == id })
		if i < 0 {
			return fmt.Errorf("no subscription %s", id)
		}
		fn(&st.Subscriptions[i])
		return nil
	})
	if err != nil {
		e.t.Fatal(show(err))
	}
}

// subOf returns the subscription id of the state.
func (e *env) subOf(id string) store.Subscription {
	e.t.Helper()
	st, _ := e.store.State()
	for _, sub := range st.Subscriptions {
		if sub.ID == id {
			return sub
		}
	}
	e.t.Fatalf("no subscription %s", id)
	return store.Subscription{}
}

// namesOf lists the names of servers.
func namesOf(servers []store.Server) []string {
	out := []string{}
	for _, srv := range servers {
		out = append(out, srv.Name)
	}
	return out
}

// wantNoURL fails if text holds any part of the subscription's URL.
func wantNoURL(t *testing.T, what, text string) {
	t.Helper()
	for _, s := range subSecrets {
		if strings.Contains(text, s.value) {
			t.Errorf("%s holds %s", what, s.name)
		}
	}
}

// wantEventsClean fails if an event holds a credential or part of the
// subscription's URL.
func (e *env) wantEventsClean() {
	e.t.Helper()
	for _, ev := range e.s.Events(0) {
		wantNoURL(e.t, "the "+ev.Kind+" event", ev.Message)
		wantRedacted(e.t, ev.Message, vlessSecret, trojanSecret, secret{"the other VLESS id", otherID})
	}
}

// testedWith counts the configs that the runner was asked to test that hold
// text.
func (e *env) testedWith(text string) int {
	n := 0
	for _, cfg := range e.runner.gotTests() {
		if strings.Contains(string(cfg), text) {
			n++
		}
	}
	return n
}

// refreshEvent is the text of the refresh event for sub.
func refreshEvent(sub store.Subscription, counts, via string) string {
	return fmt.Sprintf("subscription %s (%s): %s via %s", sub.ID, sub.Name, counts, via)
}

func TestRefreshMerges(t *testing.T) {
	e, feed := newSubEnv(t)
	a, b, c := feedLink(11, "a"), feedLink(12, "b"), feedLink(13, "c")
	sub, olds := e.addSub("provider", a, b, c)
	e.addServer("manual", trojanOutbound)
	e.patchSub(sub.ID, func(s *store.Subscription) {
		s.LastError = "an earlier failure"
		s.LastFetch = t0.Add(-48 * time.Hour)
	})
	// a changes its name and so its link, which keeps its outbound; b is as it
	// was; c is gone; d is new.
	feed.setDirect(okFeed(feedBody(feedLink(11, "a-renamed"), b, feedLink(14, "d"))))
	_, rev := e.store.State()

	res, err := e.s.RefreshSubscription(bg, sub.ID)
	if err != nil {
		t.Fatal(show(err))
	}
	if res.Added != 1 || res.Updated != 1 || res.Removed != 1 || res.Kept != 1 || res.Via != "direct" || len(res.Skipped) != 0 {
		t.Errorf("result = %+v, want 1 added, 1 updated, 1 removed, 1 kept, none skipped, via direct", res)
	}
	st, got := e.store.State()
	if got != rev+1 {
		t.Errorf("revision = %d, want %d: one write", got, rev+1)
	}
	if want := []string{"a-renamed", "b", "d", "manual"}; !slices.Equal(namesOf(st.Servers), want) {
		t.Fatalf("servers %q, want %q", namesOf(st.Servers), want)
	}
	if st.Servers[0].ID != olds[0].ID || st.Servers[1].ID != olds[1].ID {
		t.Error("a refresh gave the servers it kept new IDs")
	}
	if st.Servers[0].Link != feedLink(11, "a-renamed") {
		t.Error("the renamed server did not take its new link")
	}
	if d := st.Servers[2]; !hexID.MatchString(d.ID) || d.ID == olds[2].ID || d.Subscription != sub.ID || d.Link != feedLink(14, "d") {
		t.Errorf("the new server is %s, want a new ID and the subscription's", show(d))
	}
	if st.Servers[3].Subscription != "" {
		t.Error("a refresh touched a server of no subscription")
	}
	if got := e.subOf(sub.ID); !got.LastFetch.Equal(t0) || got.LastError != "" {
		t.Errorf("LastFetch %v, LastError %q; want %v and none", got.LastFetch, got.LastError, t0)
	}
	if n := len(e.runner.gotTests()); n != 1 || e.testedWith("203.0.113.14") != 1 {
		t.Errorf("the runner tested %d configs, want only the new server's", n)
	}
	if got, want := e.eventsOf(KindRefresh), []string{refreshEvent(sub, "added 1, updated 1, removed 1, kept 1, skipped 0", "direct")}; !slices.Equal(got, want) {
		t.Errorf("refresh events %q, want %q", got, want)
	}
	if got := kicks(e.s); got != 1 {
		t.Errorf("kicked %d times, want 1", got)
	}
	if err := st.Validate(); err != nil {
		t.Errorf("the state is not valid: %v", show(err))
	}
	e.wantEventsClean()
}

func TestRefreshOfAnUnchangedListTestsNothing(t *testing.T) {
	e, feed := newSubEnv(t)
	a, b := feedLink(11, "a"), feedLink(12, "b")
	sub, olds := e.addSub("provider", a, b)
	feed.setDirect(okFeed(feedBody(a, b)))

	res, err := e.s.RefreshSubscription(bg, sub.ID)
	if err != nil {
		t.Fatal(show(err))
	}
	if res.Added != 0 || res.Updated != 0 || res.Removed != 0 || res.Kept != 2 {
		t.Errorf("result = %+v, want 2 kept", res)
	}
	st, _ := e.store.State()
	if !reflect.DeepEqual(st.Servers, olds) {
		t.Errorf("servers changed: %s", show(st.Servers))
	}
	if n := len(e.runner.gotTests()); n != 0 {
		t.Errorf("the runner tested %d configs, want none", n)
	}
	if got := e.subOf(sub.ID).LastFetch; !got.Equal(t0) {
		t.Errorf("LastFetch = %v, want %v", got, t0)
	}
}

func TestRefreshBlockPageKeepsServers(t *testing.T) {
	e, feed := newSubEnv(t)
	sub, olds := e.addSub("provider", feedLink(11, "a"), feedLink(12, "b"))
	e.patchSub(sub.ID, func(s *store.Subscription) { s.LastFetch = t0.Add(-time.Hour) })
	if _, _, err := e.store.Update(store.AnyRevision, func(st *store.State) error {
		st.Routing.Pinned = olds[0].ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The provider's 200 is a block page, and the proxy can't help.
	feed.setDirect(okFeed(blockPage))
	feed.setProxy(feedReply{status: http.StatusServiceUnavailable})
	before, _ := e.store.State()

	_, err := e.s.RefreshSubscription(bg, sub.ID)
	if !errors.Is(err, ErrFetchFailed) {
		t.Fatalf("error = %v, want ErrFetchFailed", err)
	}
	if got, want := feed.routes(), []string{"direct", "proxy"}; !slices.Equal(got, want) {
		t.Errorf("fetched by %v, want %v", got, want)
	}
	st, _ := e.store.State()
	if !reflect.DeepEqual(st.Servers, before.Servers) || !reflect.DeepEqual(st.Routing, before.Routing) {
		t.Error("the servers or the routing changed")
	}
	got := e.subOf(sub.ID)
	if !got.LastFetch.Equal(t0.Add(-time.Hour)) {
		t.Errorf("LastFetch = %v, want it as it was", got.LastFetch)
	}
	if !strings.Contains(got.LastError, "no server") || !strings.Contains(got.LastError, "503") {
		t.Errorf("LastError = %q, want the two attempts' reasons", got.LastError)
	}
	if want := ErrFetchFailed.Error() + ": " + got.LastError; err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	if want := []string{fmt.Sprintf("subscription %s (provider): %s", sub.ID, got.LastError)}; !slices.Equal(e.eventsOf(KindError), want) {
		t.Errorf("error events %q, want %q", e.eventsOf(KindError), want)
	}
	if got := e.eventsOf(KindRefresh); len(got) != 0 {
		t.Errorf("refresh events %q, want none", got)
	}
	if k := kicks(e.s); k != 0 {
		t.Errorf("kicked %d times, want 0: nothing to apply", k)
	}
	wantNoURL(t, "the error", err.Error())
	e.wantEventsClean()
}

func TestRefreshBlockPageFallsThroughToTheProxy(t *testing.T) {
	e, feed := newSubEnv(t)
	a, b := feedLink(11, "a"), feedLink(12, "b")
	sub, olds := e.addSub("provider", a)
	feed.setDirect(okFeed(blockPage))
	feed.setProxy(okFeed(feedBody(a, b)))

	res, err := e.s.RefreshSubscription(bg, sub.ID)
	if err != nil {
		t.Fatal(show(err))
	}
	if res.Via != "proxy" || res.Added != 1 || res.Kept != 1 {
		t.Errorf("result = %+v, want 1 added and 1 kept via the proxy", res)
	}
	if st, _ := e.store.State(); len(st.Servers) != 2 || st.Servers[0].ID != olds[0].ID {
		t.Errorf("servers %s, want the old one kept and a new one", show(st.Servers))
	}
	if got, want := e.eventsOf(KindRefresh), []string{refreshEvent(sub, "added 1, updated 0, removed 0, kept 1, skipped 0", "proxy")}; !slices.Equal(got, want) {
		t.Errorf("refresh events %q, want %q", got, want)
	}
}

func TestRefreshClearsReferences(t *testing.T) {
	e, feed := newSubEnv(t)
	a, b, c := feedLink(11, "a"), feedLink(12, "b"), feedLink(13, "c")
	sub, olds := e.addSub("provider", a, b, c)
	e.addServer("manual", trojanOutbound)
	manual := e.serverNamed("manual")
	if _, _, err := e.store.Update(store.AnyRevision, func(st *store.State) error {
		st.Routing.Pinned = olds[0].ID
		st.Routing.Rules = []store.Rule{
			{Domains: []string{"domain:a.example"}, Action: store.ActionServer, Server: olds[1].ID},
			{Domains: []string{"domain:m.example"}, Action: store.ActionServer, Server: manual.ID},
			{Domains: []string{"domain:c.example"}, Action: store.ActionServer, Server: olds[2].ID},
			{Domains: []string{"domain:d.example"}, Action: store.ActionDirect},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The pinned server, and another that a rule names, leave the list.
	feed.setDirect(okFeed(feedBody(c)))

	res, err := e.s.RefreshSubscription(bg, sub.ID)
	if err != nil {
		t.Fatal(show(err))
	}
	if res.Removed != 2 || res.Kept != 1 {
		t.Errorf("result = %+v, want 2 removed and 1 kept", res)
	}
	st, _ := e.store.State()
	if err := st.Validate(); err != nil {
		t.Fatalf("the state is not valid: %v", show(err))
	}
	if st.Routing.Pinned != "" {
		t.Errorf("pinned = %q, want it cleared", st.Routing.Pinned)
	}
	if len(st.Routing.Rules) != 3 || st.Routing.Rules[0].Server != manual.ID || st.Routing.Rules[1].Server != olds[2].ID || st.Routing.Rules[2].Action != store.ActionDirect {
		t.Errorf("rules = %+v, want those of the manual and the kept server, and the direct one", st.Routing.Rules)
	}
	cleanup := e.eventsOf(KindCleanup)
	if len(cleanup) != 2 {
		t.Fatalf("cleanup events %q, want one for the pin and one for the rule", cleanup)
	}
	if !strings.Contains(cleanup[0], olds[0].ID) || !strings.Contains(cleanup[0], "pin") {
		t.Errorf("cleanup event %q, want the pin on the first server", cleanup[0])
	}
	if !strings.Contains(cleanup[1], olds[1].ID) || !strings.Contains(cleanup[1], "1 custom") {
		t.Errorf("cleanup event %q, want the rule of the second server", cleanup[1])
	}
	if got := e.eventsOf(KindRefresh); len(got) != 1 {
		t.Errorf("refresh events %q, want one", got)
	}
	e.wantEventsClean()
}

func TestRefreshSkipsRefused(t *testing.T) {
	e, feed := newSubEnv(t)
	sub, _ := e.addSub("provider", feedLink(11, "a"))
	bad := strings.ReplaceAll(feedLink(13, "bad"), vlessID, otherID)
	feed.setDirect(okFeed(feedBody(feedLink(11, "a"), bad, feedLink(12, "b"))))
	// xray's words repeat the entry's credential and address.
	e.runner.setTestRejectFor("203.0.113.13", "VLESS: user "+otherID+" at 203.0.113.13 is not valid, from "+subURL)

	res, err := e.s.RefreshSubscription(bg, sub.ID)
	if err != nil {
		t.Fatal(show(err))
	}
	if res.Added != 1 || res.Kept != 1 || len(res.Skipped) != 1 {
		t.Fatalf("result = %+v, want 1 added, 1 kept, 1 skipped", res)
	}
	sk := res.Skipped[0]
	if !strings.Contains(sk.Err, "xray rejected") || !strings.Contains(sk.Err, "is not valid") {
		t.Errorf("skipped reason %q, want xray's words", sk.Err)
	}
	wantRedacted(t, sk.Err, secret{"the entry's id", otherID})
	wantNoURL(t, "the skipped reason", sk.Err)
	if !strings.HasPrefix(bad, sk.Line) || sk.Line == "" {
		t.Errorf("skipped line %q, want the start of the entry's link", sk.Line)
	}
	st, _ := e.store.State()
	if want := []string{"a", "b"}; !slices.Equal(namesOf(st.Servers), want) {
		t.Errorf("servers %q, want %q: the refused one is left out", namesOf(st.Servers), want)
	}
	if got, want := e.eventsOf(KindRefresh), []string{refreshEvent(sub, "added 1, updated 0, removed 0, kept 1, skipped 1", "direct")}; !slices.Equal(got, want) {
		t.Errorf("refresh events %q, want %q", got, want)
	}
	e.wantEventsClean()
}

func TestRefreshReportsTheListsOwnSkips(t *testing.T) {
	e, feed := newSubEnv(t)
	sub, _ := e.addSub("provider")
	feed.setDirect(okFeed(feedBody(feedLink(11, "a"), "wireguard://nope@example.com:51820#wg")))

	res, err := e.s.RefreshSubscription(bg, sub.ID)
	if err != nil {
		t.Fatal(show(err))
	}
	if res.Added != 1 || len(res.Skipped) != 1 || res.Skipped[0].Err == "" {
		t.Errorf("result = %+v, want 1 added and the unsupported link skipped with a reason", res)
	}
	if got, want := e.eventsOf(KindRefresh), []string{refreshEvent(sub, "added 1, updated 0, removed 0, kept 0, skipped 1", "direct")}; !slices.Equal(got, want) {
		t.Errorf("refresh events %q, want %q", got, want)
	}
}

// A list that xray refuses whole is no list: merging it would remove every
// server the user has.
func TestRefreshOfOnlyRefusedServersKeepsTheServers(t *testing.T) {
	e, feed := newSubEnv(t)
	sub, _ := e.addSub("provider", feedLink(11, "a"), feedLink(12, "b"))
	feed.setDirect(okFeed(feedBody(feedLink(21, "x"), feedLink(22, "y"))))
	e.runner.setTestReject("Failed to start: " + vlessID)
	before, _ := e.store.State()

	_, err := e.s.RefreshSubscription(bg, sub.ID)
	r := wantRefused(t, err, vlessSecret)
	if !strings.Contains(r.Reason, "xray rejected every server") {
		t.Errorf("reason %q, want it to say xray rejected every server", r.Reason)
	}
	st, _ := e.store.State()
	if !reflect.DeepEqual(st.Servers, before.Servers) {
		t.Error("the servers changed")
	}
	got := e.subOf(sub.ID)
	if got.LastError != r.Reason || !got.LastFetch.IsZero() {
		t.Errorf("LastError %q, LastFetch %v; want the reason and no fetch recorded", got.LastError, got.LastFetch)
	}
	if k := kicks(e.s); k != 0 {
		t.Errorf("kicked %d times, want 0", k)
	}
	if got := e.eventsOf(KindError); len(got) != 1 {
		t.Errorf("error events %q, want one", got)
	}
	e.wantEventsClean()
}

func TestRefreshWithoutRunner(t *testing.T) {
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close() // a refused connection, as net/http reports it
	for _, c := range []struct {
		name  string
		setup func(e *env, feed *fakeFeed)
		tests int // how many configs the runner got
	}{
		{"the runner can't be reached", func(e *env, feed *fakeFeed) {
			e.s = e.newService(Config{Fetcher: feed.fetcher, Runner: &runnerapi.Client{BaseURL: downURL, Token: "tok"}})
		}, 0},
		{"the runner is down", func(e *env, _ *fakeFeed) { e.runner.setDown(true) }, 0},
		{"no xray runs", func(e *env, _ *fakeFeed) { e.runner.failTest(true, false) }, 1},
		{"the runner fails", func(e *env, _ *fakeFeed) { e.runner.failTest(false, true) }, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, feed := newSubEnv(t)
			b := feedLink(12, "b")
			sub, olds := e.addSub("provider", b)
			c.setup(e, feed)
			feed.setDirect(okFeed(feedBody(b, feedLink(14, "d"), feedLink(15, "e"))))

			res, err := e.s.RefreshSubscription(bg, sub.ID)
			if err != nil {
				t.Fatal(show(err))
			}
			if res.Added != 2 || res.Kept != 1 {
				t.Errorf("result = %+v, want 2 added and 1 kept: the entries merge untested", res)
			}
			st, _ := e.store.State()
			if want := []string{"b", "d", "e"}; !slices.Equal(namesOf(st.Servers), want) || st.Servers[0].ID != olds[0].ID {
				t.Errorf("servers %q, want %q with b kept", namesOf(st.Servers), want)
			}
			want := []string{fmt.Sprintf("subscription %s (provider): 2 servers saved without a runner test", sub.ID)}
			if got := e.eventsOf(KindUntested); !slices.Equal(got, want) {
				t.Errorf("untested events %q, want %q", got, want)
			}
			if n := len(e.runner.gotTests()); n != c.tests {
				t.Errorf("the runner got %d configs, want %d: the first failure ends the testing", n, c.tests)
			}
			if got := e.eventsOf(KindRefresh); len(got) != 1 {
				t.Errorf("refresh events %q, want one", got)
			}
			e.wantEventsClean()
		})
	}
}

func TestRefreshWarningsBecomeEvents(t *testing.T) {
	warnings := mustWarnings(t, warnLink)
	e, feed := newSubEnv(t)
	sub, _ := e.addSub("provider", feedLink(11, "a"))
	feed.setDirect(okFeed(feedBody(feedLink(11, "a"), warnLink)))

	if _, err := e.s.RefreshSubscription(bg, sub.ID); err != nil {
		t.Fatal(show(err))
	}
	srv := e.serverNamed("example.com:443")
	var want []string
	for _, w := range warnings {
		want = append(want, fmt.Sprintf("server %s (%s): %s", srv.ID, srv.Name, w))
	}
	if got := e.eventsOf(KindWarning); !slices.Equal(got, want) {
		t.Errorf("warning events %q, want %q", got, want)
	}

	// The same list again: nothing is new, so nothing is said again.
	if _, err := e.s.RefreshSubscription(bg, sub.ID); err != nil {
		t.Fatal(show(err))
	}
	if got := e.eventsOf(KindWarning); !slices.Equal(got, want) {
		t.Errorf("warning events after a second refresh %q, want the same %q", got, want)
	}
}

func mustWarnings(t *testing.T, link string) []string {
	t.Helper()
	sv, err := sharelink.Parse(link)
	if err != nil || len(sv.Warnings) == 0 {
		t.Fatalf("the link gives warnings %q, error %v; want some", sv.Warnings, err)
	}
	return sv.Warnings
}

func TestRefreshConflictRetries(t *testing.T) {
	e, feed := newSubEnv(t)
	a, b := feedLink(11, "a"), feedLink(12, "b")
	sub, olds := e.addSub("provider", a, b)
	feed.setDirect(okFeed(feedBody(b, feedLink(14, "d"))))
	// While the list is on its way, the user pins the server that the list
	// is about to drop, and blocks a domain.
	done := false
	feed.onDirect = func(string) {
		if done {
			return
		}
		done = true
		_, _, err := e.store.Update(store.AnyRevision, func(st *store.State) error {
			st.Routing.Pinned = olds[0].ID
			st.Routing.BlockList = append(st.Routing.BlockList, "domain:ads.example")
			return nil
		})
		if err != nil {
			t.Error(show(err))
		}
	}
	_, rev := e.store.State()

	res, err := e.s.RefreshSubscription(bg, sub.ID)
	if err != nil {
		t.Fatal(show(err))
	}
	if res.Added != 1 || res.Removed != 1 || res.Kept != 1 {
		t.Errorf("result = %+v, want 1 added, 1 removed, 1 kept", res)
	}
	st, got := e.store.State()
	if got != rev+2 {
		t.Errorf("revision = %d, want %d: the user's change and the refresh", got, rev+2)
	}
	if !slices.Equal(st.Routing.BlockList, []string{"domain:ads.example"}) {
		t.Errorf("block list %q: the user's change was lost", st.Routing.BlockList)
	}
	if st.Routing.Pinned != "" {
		t.Errorf("pinned = %q: the merge was not redone on the new state", st.Routing.Pinned)
	}
	if want := []string{"b", "d"}; !slices.Equal(namesOf(st.Servers), want) {
		t.Errorf("servers %q, want %q", namesOf(st.Servers), want)
	}
	if err := st.Validate(); err != nil {
		t.Errorf("the state is not valid: %v", show(err))
	}
	if n := len(feed.routes()); n != 1 {
		t.Errorf("fetched %d times, want once: the retry keeps the fetched entries", n)
	}
	if n := len(e.runner.gotTests()); n != 1 {
		t.Errorf("the runner tested %d configs, want 1: the retry does not test again", n)
	}
	// What was recorded is what the one write did.
	if got := len(e.eventsOf(KindRefresh)); got != 1 {
		t.Errorf("%d refresh events, want 1", got)
	}
	if got := e.eventsOf(KindCleanup); len(got) != 1 || !strings.Contains(got[0], "pin") {
		t.Errorf("cleanup events %q, want one, for the pin", got)
	}
	if k := kicks(e.s); k != 1 {
		t.Errorf("kicked %d times, want 1", k)
	}
}

// A second conflict ends the refresh with store.ErrConflict, and writes and
// records nothing.
func TestRefreshConflictTwiceFails(t *testing.T) {
	e, feed := newSubEnv(t)
	sub, olds := e.addSub("provider", feedLink(11, "a"))
	feed.setDirect(okFeed(feedBody(feedLink(12, "b"))))
	// The subscription is pointed elsewhere while its old address is fetched,
	// so the list can't be merged into it, now or on a retry.
	done := false
	feed.onDirect = func(string) {
		if done {
			return
		}
		done = true
		other := "https://other.example.org/list"
		if _, _, err := e.s.UpdateSubscription(bg, store.AnyRevision, sub.ID, SubscriptionPatch{URL: &other}); err != nil {
			t.Error(show(err))
		}
	}

	_, err := e.s.RefreshSubscription(bg, sub.ID)
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("error = %v, want store.ErrConflict", show(err))
	}
	st, _ := e.store.State()
	if !reflect.DeepEqual(st.Servers, olds) {
		t.Errorf("servers %s, want them as they were", show(st.Servers))
	}
	if got := e.eventsOf(KindRefresh); len(got) != 0 {
		t.Errorf("refresh events %q, want none", got)
	}
	if got := e.eventsOf(KindError); len(got) != 1 || !strings.Contains(got[0], sub.ID) || !strings.Contains(got[0], "not stored") {
		t.Errorf("error events %q, want one that says the refresh was not stored", got)
	}
	if got := e.subOf(sub.ID); got.LastError != "" {
		t.Errorf("LastError = %q, want none: the fetch did not fail", got.LastError)
	}
}

func TestRefreshOfAMissingSubscription(t *testing.T) {
	e, feed := newSubEnv(t)
	// A caller who pastes the URL where the ID goes gets no URL back.
	e.addSub("provider", feedLink(11, "a"))
	for name, id := range map[string]string{"an unknown ID": "0000abcd", "a URL": subURL} {
		_, err := e.s.RefreshSubscription(bg, id)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("refreshing %s: %v, want ErrNotFound", name, show(err))
			continue
		}
		wantNoURL(t, "the error", err.Error())
	}
	if n := len(feed.routes()); n != 0 {
		t.Errorf("fetched %d times, want none", n)
	}
}

func TestRefreshOfADisabledSubscription(t *testing.T) {
	e, feed := newSubEnv(t)
	sub, _ := e.addSub("provider", feedLink(11, "a"))
	e.patchSub(sub.ID, func(s *store.Subscription) { s.Disabled = true })
	_, err := e.s.RefreshSubscription(bg, sub.ID)
	wantRefused(t, err)
	if n := len(feed.routes()); n != 0 {
		t.Errorf("fetched %d times, want none: a disabled subscription is not fetched", n)
	}
}

func TestRefreshStopsWhenTheContextEnds(t *testing.T) {
	e, feed := newSubEnv(t)
	sub, olds := e.addSub("provider", feedLink(11, "a"))
	feed.setDirect(okFeed(feedBody(feedLink(12, "b"))))
	ctx, cancel := context.WithCancel(bg)
	feed.onDirect = func(string) { cancel() }

	_, err := e.s.RefreshSubscription(ctx, sub.ID)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrFetchFailed) {
		t.Fatalf("error = %v, want context.Canceled and no fetch failure", show(err))
	}
	st, _ := e.store.State()
	if !reflect.DeepEqual(st.Servers, olds) {
		t.Error("the servers changed")
	}
	if got := e.subOf(sub.ID); got.LastError != "" {
		t.Errorf("LastError = %q, want none: the caller gave up, the fetch did not fail", got.LastError)
	}
	if got := e.s.Events(0); len(got) != 0 {
		t.Errorf("events %v, want none", got)
	}
}

func TestRefreshErrorsHaveNoURL(t *testing.T) {
	refused := errors.New("connection refused")
	for _, c := range []struct {
		name          string
		direct, proxy feedReply
		runnerRejects bool
	}{
		{"both routes fail to connect", feedReply{err: refused}, feedReply{err: refused}, false},
		{"both answer with an error", feedReply{status: http.StatusForbidden}, feedReply{status: http.StatusBadGateway}, false},
		{"a block page, then a failure", okFeed(blockPage), feedReply{err: refused}, false},
		{"an expired account's notice", okFeed("Your account has expired. Renew at " + subURL), feedReply{err: refused}, false},
		{"every entry refused", okFeed(feedBody(feedLink(21, "x"))), feedReply{}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, feed := newSubEnv(t)
			sub, _ := e.addSub("provider", feedLink(11, "a"))
			feed.setDirect(c.direct)
			feed.setProxy(c.proxy)
			if c.runnerRejects {
				e.runner.setTestReject("failed to load " + subURL)
			}
			res, err := e.s.RefreshSubscription(bg, sub.ID)
			if err == nil {
				t.Fatal("the refresh worked, want an error")
			}
			wantNoURL(t, "the error", err.Error())
			wantNoURL(t, "LastError", e.subOf(sub.ID).LastError)
			for _, sk := range res.Skipped {
				wantNoURL(t, "a skipped reason", sk.Err)
			}
			if e.subOf(sub.ID).LastError == "" {
				t.Error("LastError is empty")
			}
			e.wantEventsClean()
		})
	}
}

// Refreshes run one at a time, whoever asks.
func TestRefreshesDoNotOverlap(t *testing.T) {
	e, feed := newSubEnv(t)
	var ids []string
	for i := range 4 {
		sub, _ := e.addSub(fmt.Sprintf("p%d", i), feedLink(11+i, "a"))
		ids = append(ids, sub.ID)
	}
	feed.setDirect(okFeed(feedBody(feedLink(30, "z"))))
	var mu sync.Mutex
	active, most := 0, 0
	feed.onDirect = func(string) {
		mu.Lock()
		active++
		most = max(most, active)
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		active--
		mu.Unlock()
	}
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.s.RefreshSubscription(bg, id); err != nil {
				t.Error(show(err))
			}
		}()
	}
	wg.Wait()
	if most != 1 {
		t.Errorf("%d refreshes ran at once, want 1", most)
	}
}

// A refresh that waits for another can be given up on.
func TestRefreshWaitStopsWhenTheContextEnds(t *testing.T) {
	e, feed := newSubEnv(t)
	sub, _ := e.addSub("provider", feedLink(11, "a"))
	feed.setDirect(okFeed(feedBody(feedLink(12, "b"))))
	inside, release := make(chan struct{}), make(chan struct{})
	feed.onDirect = func(string) {
		close(inside)
		<-release
	}
	first := make(chan error, 1)
	go func() {
		_, err := e.s.RefreshSubscription(bg, sub.ID)
		first <- err
	}()
	within(t, "the first refresh to fetch", inside)

	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, err := e.s.RefreshSubscription(ctx, sub.ID); !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", show(err))
	}
	close(release)
	if err := within(t, "the first refresh to end", first); err != nil {
		t.Error(show(err))
	}
}

func TestAddSubscription(t *testing.T) {
	e, feed := newSubEnv(t)
	sub, rev, err := e.s.AddSubscription(bg, 0, NewSubscription{Name: "provider", URL: "  " + subURL + "\n"})
	if err != nil {
		t.Fatal(show(err))
	}
	if rev != 1 {
		t.Errorf("revision = %d, want 1", rev)
	}
	if !hexID.MatchString(sub.ID) || sub.Name != "provider" || sub.URL != subURL || sub.Disabled || sub.Interval != store.Duration(24*time.Hour) {
		t.Errorf("subscription = %+v, want an enabled one with a new ID, the URL trimmed and 24 h", sub)
	}
	if !sub.LastFetch.IsZero() || sub.LastError != "" {
		t.Errorf("LastFetch %v, LastError %q; want neither: adding does not fetch", sub.LastFetch, sub.LastError)
	}
	if st, _ := e.store.State(); len(st.Subscriptions) != 1 || st.Subscriptions[0].ID != sub.ID {
		t.Error("the subscription is not in the state")
	}
	if n := len(feed.routes()); n != 0 {
		t.Errorf("fetched %d times, want none", n)
	}
	if k := kicks(e.s); k != 1 {
		t.Errorf("kicked %d times, want 1", k)
	}

	sub2, _, err := e.s.AddSubscription(bg, rev, NewSubscription{Name: "slow", URL: "https://two.example.org/s", Interval: store.Duration(6 * time.Hour)})
	if err != nil {
		t.Fatal(show(err))
	}
	if sub2.Interval != store.Duration(6*time.Hour) || sub2.ID == sub.ID {
		t.Errorf("second subscription = %+v, want its own interval and ID", sub2)
	}
}

func TestAddSubscriptionRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		n    NewSubscription
	}{
		{"no name", NewSubscription{URL: subURL}},
		{"a name with a control character", NewSubscription{Name: "a\x1bb", URL: subURL}},
		{"no URL", NewSubscription{Name: "p"}},
		{"a URL that isn't http", NewSubscription{Name: "p", URL: "ftp://alice:" + subPass + "@" + subHost + "/" + subToken}},
		{"a URL that isn't a URL", NewSubscription{Name: "p", URL: subToken}},
		{"an interval under an hour", NewSubscription{Name: "p", URL: subURL, Interval: store.Duration(30 * time.Minute)}},
		{"a negative interval", NewSubscription{Name: "p", URL: subURL, Interval: store.Duration(-time.Hour)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, _ := newSubEnv(t)
			_, _, err := e.s.AddSubscription(bg, 0, c.n)
			r := wantRefused(t, err)
			wantNoURL(t, "the refusal", r.Reason)
			if _, rev := e.store.State(); rev != 0 {
				t.Errorf("revision = %d, want 0", rev)
			}
			if k := kicks(e.s); k != 0 {
				t.Errorf("kicked %d times, want 0", k)
			}
		})
	}
}

func TestAddSubscriptionChecksTheRevision(t *testing.T) {
	e, _ := newSubEnv(t)
	if _, _, err := e.s.AddSubscription(bg, 7, NewSubscription{Name: "p", URL: subURL}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("error = %v, want store.ErrConflict", err)
	}
	if _, _, err := e.s.AddSubscription(bg, store.AnyRevision, NewSubscription{Name: "p", URL: subURL}); err != nil {
		t.Errorf("AnyRevision: %v", show(err))
	}
}

func TestUpdateSubscription(t *testing.T) {
	e, _ := newSubEnv(t)
	sub, _ := e.addSub("provider", feedLink(11, "a"))
	fetched := t0.Add(-time.Hour)
	e.patchSub(sub.ID, func(s *store.Subscription) { s.LastFetch, s.LastError = fetched, "an earlier failure" })
	_, rev := e.store.State()

	name, off, every := "renamed", true, store.Duration(12*time.Hour)
	got, rev2, err := e.s.UpdateSubscription(bg, rev, sub.ID, SubscriptionPatch{Name: &name, Disabled: &off, Interval: &every})
	if err != nil {
		t.Fatal(show(err))
	}
	if rev2 != rev+1 || got.Name != "renamed" || !got.Disabled || got.Interval != every || got.URL != subURL {
		t.Errorf("subscription = %+v at revision %d, want the new name, disabled and 12 h at %d", got, rev2, rev+1)
	}
	if !got.LastFetch.Equal(fetched) || got.LastError != "an earlier failure" {
		t.Errorf("LastFetch %v, LastError %q; want them as they were: the URL did not change", got.LastFetch, got.LastError)
	}
	if k := kicks(e.s); k != 1 {
		t.Errorf("kicked %d times, want 1", k)
	}

	// The same URL again changes nothing about the fetch.
	same := subURL
	got, _, err = e.s.UpdateSubscription(bg, store.AnyRevision, sub.ID, SubscriptionPatch{URL: &same})
	if err != nil || !got.LastFetch.Equal(fetched) {
		t.Errorf("same URL: LastFetch %v, error %v; want it kept", got.LastFetch, show(err))
	}

	// A new URL has not been fetched: it is due at once.
	next := "https://other.example.org/list"
	got, _, err = e.s.UpdateSubscription(bg, store.AnyRevision, sub.ID, SubscriptionPatch{URL: &next})
	if err != nil {
		t.Fatal(show(err))
	}
	if got.URL != next || !got.LastFetch.IsZero() || got.LastError != "" {
		t.Errorf("subscription = %+v, want the new URL, never fetched, no error", got)
	}
	if st, _ := e.store.State(); len(st.Servers) != 1 {
		t.Error("a new URL removed the servers: only a refresh may")
	}
}

func TestUpdateSubscriptionRefusals(t *testing.T) {
	e, _ := newSubEnv(t)
	sub, _ := e.addSub("provider", feedLink(11, "a"))
	bad, short, empty := "ftp://alice:"+subPass+"@"+subHost+"/"+subToken, store.Duration(time.Minute), ""
	for _, c := range []struct {
		name  string
		patch SubscriptionPatch
	}{
		{"a URL that isn't http", SubscriptionPatch{URL: &bad}},
		{"an interval under an hour", SubscriptionPatch{Interval: &short}},
		{"an empty name", SubscriptionPatch{Name: &empty}},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, rev := e.store.State()
			_, _, err := e.s.UpdateSubscription(bg, rev, sub.ID, c.patch)
			r := wantRefused(t, err)
			wantNoURL(t, "the refusal", r.Reason)
			if _, got := e.store.State(); got != rev {
				t.Errorf("revision = %d, want %d", got, rev)
			}
		})
	}
}

func TestUpdateSubscriptionErrors(t *testing.T) {
	e, _ := newSubEnv(t)
	sub, _ := e.addSub("provider", feedLink(11, "a"))
	name := "x"
	_, _, err := e.s.UpdateSubscription(bg, store.AnyRevision, subURL, SubscriptionPatch{Name: &name})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", show(err))
	}
	wantNoURL(t, "the error", err.Error())
	if _, _, err := e.s.UpdateSubscription(bg, 99, sub.ID, SubscriptionPatch{Name: &name}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("error = %v, want store.ErrConflict", err)
	}
}

func TestRemoveSubscriptionRemovesServers(t *testing.T) {
	e, _ := newSubEnv(t)
	sub, olds := e.addSub("provider", feedLink(11, "a"), feedLink(12, "b"))
	other, keep := e.addSub("other", feedLink(13, "c"))
	e.addServer("manual", trojanOutbound)
	manual := e.serverNamed("manual")
	if _, _, err := e.store.Update(store.AnyRevision, func(st *store.State) error {
		st.Routing.Pinned = olds[1].ID
		st.Routing.Rules = []store.Rule{
			{Domains: []string{"domain:a.example"}, Action: store.ActionServer, Server: olds[0].ID},
			{Domains: []string{"domain:c.example"}, Action: store.ActionServer, Server: keep[0].ID},
			{Domains: []string{"domain:m.example"}, Action: store.ActionServer, Server: manual.ID},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, rev := e.store.State()

	next, err := e.s.RemoveSubscription(bg, rev, sub.ID)
	if err != nil {
		t.Fatal(show(err))
	}
	st, got := e.store.State()
	if got != next || next != rev+1 {
		t.Errorf("revision = %d (state at %d), want %d", next, got, rev+1)
	}
	if want := []string{"c", "manual"}; !slices.Equal(namesOf(st.Servers), want) {
		t.Errorf("servers %q, want %q", namesOf(st.Servers), want)
	}
	if len(st.Subscriptions) != 1 || st.Subscriptions[0].ID != other.ID {
		t.Errorf("subscriptions %+v, want only the other one", st.Subscriptions)
	}
	if st.Routing.Pinned != "" {
		t.Errorf("pinned = %q, want it cleared", st.Routing.Pinned)
	}
	if len(st.Routing.Rules) != 2 || st.Routing.Rules[0].Server != keep[0].ID || st.Routing.Rules[1].Server != manual.ID {
		t.Errorf("rules = %+v, want those of the servers that stay", st.Routing.Rules)
	}
	if err := st.Validate(); err != nil {
		t.Errorf("the state is not valid: %v", show(err))
	}
	cleanup := e.eventsOf(KindCleanup)
	if len(cleanup) != 2 {
		t.Fatalf("cleanup events %q, want one for the rule of the first server and one for the pin on the second", cleanup)
	}
	if !strings.Contains(cleanup[0], olds[0].ID) || !strings.Contains(cleanup[1], olds[1].ID) {
		t.Errorf("cleanup events %q, want them to name the servers in order", cleanup)
	}
	if k := kicks(e.s); k != 1 {
		t.Errorf("kicked %d times, want 1", k)
	}
	e.wantEventsClean()

	if _, err := e.s.RemoveSubscription(bg, next, sub.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing it again: %v, want ErrNotFound", show(err))
	}
	_, err = e.s.RemoveSubscription(bg, store.AnyRevision, subURL)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("removing by URL: %v, want ErrNotFound", show(err))
	}
	wantNoURL(t, "the error", err.Error())
}

func TestRemoveSubscriptionChecksTheRevision(t *testing.T) {
	e, _ := newSubEnv(t)
	sub, olds := e.addSub("provider", feedLink(11, "a"))
	if _, err := e.s.RemoveSubscription(bg, 99, sub.ID); !errors.Is(err, store.ErrConflict) {
		t.Errorf("error = %v, want store.ErrConflict", err)
	}
	if st, _ := e.store.State(); len(st.Servers) != 1 || st.Servers[0].ID != olds[0].ID || len(st.Subscriptions) != 1 {
		t.Error("a refused removal changed the state")
	}
}
