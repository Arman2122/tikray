package service

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
