package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

const (
	// vlessLink is a share link for a VLESS server with REALITY, which
	// xray-core takes to a public address.
	vlessLink = "vless://" + vlessID + "@203.0.113.10:443?type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision#lab"
	// plainLink is VLESS with neither TLS nor encryption to a public
	// address, which xray-core 26.7.11 and newer refuse.
	plainLink = "vless://" + vlessID + "@vpn.example.org:443?type=tcp#plain"

	trojanPW       = "trojan-pass-1234"
	trojanOutbound = `{"protocol":"trojan","settings":{"servers":[{"address":"example.com","port":443,"password":"` + trojanPW + `"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}}`
)

var (
	vlessSecret  = secret{"the VLESS id", vlessID}
	trojanSecret = secret{"the Trojan password", trojanPW}
	hexID        = regexp.MustCompile(`^[0-9a-f]{8}$`)
)

// show prints v for a failure message without the credentials the tests use:
// a server's outbound and link are left out, and the strings that hold the
// VLESS id or the Trojan password are masked.
func show(v any) string {
	var text string
	switch v := v.(type) {
	case store.Server:
		text = showServer(v)
	case []store.Server:
		parts := make([]string, len(v))
		for i, srv := range v {
			parts[i] = showServer(srv)
		}
		text = "[" + strings.Join(parts, " ") + "]"
	case json.RawMessage:
		text = string(v)
	default:
		text = fmt.Sprintf("%+v", v)
	}
	text = strings.ReplaceAll(text, vlessLink, "<the link>")
	text = strings.ReplaceAll(text, vlessID, "<the id>")
	return strings.ReplaceAll(text, trojanPW, "<the password>")
}

func showServer(s store.Server) string {
	return fmt.Sprintf("{ID:%s Name:%q Disabled:%t Invalid:%q Link:%t Outbound:%d bytes}", s.ID, s.Name, s.Disabled, s.Invalid, s.Link != "", len(s.Outbound))
}

// kicks is how many times the service was kicked.
func kicks(s *Service) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kicked
}

// wantRefused fails unless err is a *Refused whose reason holds none of
// secrets, and returns it.
func wantRefused(t *testing.T, err error, secrets ...secret) *Refused {
	t.Helper()
	var r *Refused
	if !errors.As(err, &r) {
		t.Fatalf("error = %v, want a *Refused", show(err))
	}
	if r.Reason == "" {
		t.Error("Refused.Reason is empty")
	}
	if want := "refused: " + r.Reason; r.Error() != want {
		t.Errorf("Refused.Error() = %q, want %q", show(r.Error()), show(want))
	}
	wantRedacted(t, r.Reason, secrets...)
	return r
}

// wantUnchanged fails unless the state is at revision rev, the service was
// not kicked since before kicks, and the runner tested no config beyond
// tested.
func (e *env) wantUnchanged(rev, before uint64, tested int) {
	e.t.Helper()
	if _, got := e.store.State(); got != rev {
		e.t.Errorf("the state is at revision %d, want %d", got, rev)
	}
	if got := kicks(e.s); got != before {
		e.t.Errorf("the service was kicked %d times, want %d", got-before, 0)
	}
	if got := len(e.runner.gotTests()); got != tested {
		e.t.Errorf("the runner tested %d configs, want %d", got, tested)
	}
}

// wantTestConfig fails unless the runner's last test was of the config that
// tikray makes for srv: its outbound, tagged srv-<id>, and the direct one.
func (e *env) wantTestConfig(srv store.Server) {
	e.t.Helper()
	tests := e.runner.gotTests()
	if len(tests) == 0 {
		e.t.Fatal("the runner tested no config")
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(tests[len(tests)-1], &cfg); err != nil {
		e.t.Fatalf("the tested config is no JSON object: %v", err)
	}
	if len(cfg) != 1 || cfg["outbounds"] == nil {
		e.t.Errorf("the tested config has keys %v, want only outbounds", keysOf(cfg))
	}
	var outs []map[string]any
	if err := json.Unmarshal(cfg["outbounds"], &outs); err != nil || len(outs) != 2 {
		e.t.Fatalf("outbounds = %s, want two", show(string(cfg["outbounds"])))
	}
	if outs[0]["tag"] != "srv-"+srv.ID {
		e.t.Errorf("the server's outbound has tag %v, want srv-%s", outs[0]["tag"], srv.ID)
	}
	delete(outs[0], "tag")
	var want map[string]any
	if err := json.Unmarshal(srv.Outbound, &want); err != nil {
		e.t.Fatal(err)
	}
	if !reflect.DeepEqual(outs[0], want) {
		e.t.Errorf("the tested outbound is not the server's: %s", show(outs[0]))
	}
	if !reflect.DeepEqual(outs[1], map[string]any{"protocol": "freedom", "tag": "direct"}) {
		e.t.Errorf("the second outbound is %v, want freedom tagged direct", outs[1])
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// hasKeyFold reports whether the JSON object raw has a key equal to key
// without regard to case.
func hasKeyFold(t *testing.T, raw json.RawMessage, key string) bool {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("not a JSON object: %v", err)
	}
	for k := range obj {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

// serverNamed returns the server of the current state with the name.
func (e *env) serverNamed(name string) store.Server {
	e.t.Helper()
	st, _ := e.store.State()
	for _, srv := range st.Servers {
		if srv.Name == name {
			return srv
		}
	}
	e.t.Fatalf("no server named %q", name)
	return store.Server{}
}

func TestAddServerByLink(t *testing.T) {
	e := newEnv(t)
	srv, rev, err := e.s.AddServer(bg, 0, NewServer{Link: vlessLink})
	if err != nil {
		t.Fatal(show(err))
	}
	if rev != 1 {
		t.Errorf("revision = %d, want 1", rev)
	}
	if !hexID.MatchString(srv.ID) || srv.Name != "lab" || srv.Link != vlessLink || srv.Disabled || srv.Invalid != "" || srv.Subscription != "" {
		t.Errorf("server = %s, want a new enabled server named lab, from the link", show(srv))
	}
	if hasKeyFold(t, srv.Outbound, "tag") {
		t.Error("the outbound has a tag")
	}
	st, got := e.store.State()
	if got != rev || len(st.Servers) != 1 || !reflect.DeepEqual(st.Servers[0], srv) {
		t.Errorf("state at revision %d holds %s, want revision %d with the server returned", got, show(st.Servers), rev)
	}
	e.wantTestConfig(srv)
	if got := kicks(e.s); got != 1 {
		t.Errorf("kicked %d times, want 1", got)
	}
	if got := e.eventsOf(KindUntested); len(got) != 0 {
		t.Errorf("untested events %q for a server that was tested", got)
	}
}

func TestAddServerNameOverridesTheLinksName(t *testing.T) {
	e := newEnv(t)
	srv, _, err := e.s.AddServer(bg, 0, NewServer{Link: vlessLink, Name: "mine"})
	if err != nil {
		t.Fatal(show(err))
	}
	if srv.Name != "mine" {
		t.Errorf("Name = %q, want the one given", srv.Name)
	}
}

func TestAddServerByJSONDropsTheTag(t *testing.T) {
	e := newEnv(t)
	raw := strings.Replace(vlessOutbound, `{"protocol"`, `{"tag":"mine","TAG":"x","protocol"`, 1)
	srv, rev, err := e.s.AddServer(bg, 0, NewServer{Name: "raw", Outbound: json.RawMessage(raw)})
	if err != nil {
		t.Fatal(show(err))
	}
	if srv.Name != "raw" || srv.Link != "" || !hexID.MatchString(srv.ID) {
		t.Errorf("server = %s, want a new one named raw with no link", show(srv))
	}
	if hasKeyFold(t, srv.Outbound, "tag") {
		t.Errorf("the saved outbound keeps a tag: %s", show(string(srv.Outbound)))
	}
	var got, want any
	if json.Unmarshal(srv.Outbound, &got) != nil || json.Unmarshal([]byte(vlessOutbound), &want) != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("outbound = %s, want the given one without its tag", show(string(srv.Outbound)))
	}
	if st, got := e.store.State(); got != rev || !reflect.DeepEqual(st.Servers, []store.Server{srv}) {
		t.Errorf("the state does not hold just the server returned, at revision %d", rev)
	}
	e.wantTestConfig(srv)
}

// A server that tikray refuses is never tested, saved or kicked for.
func TestAddServerRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		n    NewServer
		want string
	}{
		{"a scheme sharelink does not read", NewServer{Link: "wireguard://x@example.com:51820"}, "unsupported"},
		{"a link xray-core refuses", NewServer{Link: plainLink}, "VLESS"},
		{"a text that is no link", NewServer{Link: "hello"}, "not a share link"},
		{"a direct outbound", NewServer{Name: "d", Outbound: json.RawMessage(`{"protocol":"direct"}`)}, "not a proxy protocol"},
		{"an outbound that is no object", NewServer{Name: "d", Outbound: json.RawMessage(`[1]`)}, "must be a JSON object"},
		{"an outbound with no name", NewServer{Outbound: json.RawMessage(vlessOutbound)}, "name"},
		{"a name with a control character", NewServer{Name: "a\nb", Outbound: json.RawMessage(vlessOutbound)}, "control characters"},
		{"a link and an outbound", NewServer{Link: vlessLink, Outbound: json.RawMessage(vlessOutbound)}, "not both"},
		{"neither", NewServer{Name: "x"}, "share link or an outbound"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			srv, rev, err := e.s.AddServer(bg, 0, c.n)
			r := wantRefused(t, err, vlessSecret)
			if !strings.Contains(r.Reason, c.want) {
				t.Errorf("reason = %q, want it to hold %q", show(r.Reason), c.want)
			}
			if rev != 0 || srv.ID != "" {
				t.Errorf("AddServer returned revision %d and %s, want zero values", rev, show(srv))
			}
			e.wantUnchanged(0, 0, 0)
			if got := e.s.Events(0); len(got) != 0 {
				t.Errorf("events %s for a refusal", show(got))
			}
		})
	}
}

// What xray prints about a server repeats its credentials; the refusal must
// not.
func TestAddServerRejectedByXray(t *testing.T) {
	for _, c := range []struct {
		name   string
		n      NewServer
		secret secret
	}{
		{"a VLESS id from JSON", NewServer{Name: "v", Outbound: json.RawMessage(vlessOutbound)}, vlessSecret},
		{"a Trojan password", NewServer{Name: "t", Outbound: json.RawMessage(trojanOutbound)}, trojanSecret},
		{"a VLESS id from a link", NewServer{Link: vlessLink}, vlessSecret},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.runner.setTestReject("main: failed to load config: infra/conf: bad user " + c.secret.value + " in outbound srv")
			_, rev, err := e.s.AddServer(bg, 0, c.n)
			r := wantRefused(t, err, vlessSecret, trojanSecret)
			if !strings.Contains(r.Reason, "main: failed to load config: infra/conf: bad user "+redacted+" in outbound srv") {
				t.Errorf("reason = %q, want xray's output with the secret redacted", show(r.Reason))
			}
			if rev != 0 {
				t.Errorf("revision = %d, want 0", rev)
			}
			e.wantUnchanged(0, 0, 1)
			if got := e.eventsOf(KindUntested); len(got) != 0 {
				t.Errorf("untested events %q for a server that xray rejected", got)
			}
		})
	}
}

func TestAddServerRejectedWithNoOutput(t *testing.T) {
	e := newEnv(t)
	e.runner.setTestReject(" \n")
	_, _, err := e.s.AddServer(bg, 0, NewServer{Link: vlessLink})
	r := wantRefused(t, err, vlessSecret)
	if !strings.Contains(r.Reason, "rejected") {
		t.Errorf("reason = %q, want it to say xray rejected the server", r.Reason)
	}
}

// A runner that can't test leaves the trial before the apply as the net: the
// server is saved, with an untested event.
func TestAddServerSavedWithoutARunnerTest(t *testing.T) {
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close() // a real refused connection, as a *url.Error from net/http
	for _, c := range []struct {
		name  string
		setup func(e *env)
	}{
		{"the runner can't be reached", func(e *env) {
			e.s = e.newService(Config{Runner: &runnerapi.Client{BaseURL: downURL, Token: "tok"}})
		}},
		{"the runner is down", func(e *env) { e.runner.setDown(true) }},
		{"no xray runs", func(e *env) { e.runner.failTest(true, false) }},
		{"the runner fails", func(e *env) { e.runner.failTest(false, true) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			c.setup(e)
			srv, rev, err := e.s.AddServer(bg, 0, NewServer{Name: "later", Outbound: json.RawMessage(vlessOutbound)})
			if err != nil {
				t.Fatal(show(err))
			}
			if rev != 1 || srv.Name != "later" {
				t.Errorf("revision %d, server %s; want 1 and the server saved", rev, show(srv))
			}
			if st, _ := e.store.State(); len(st.Servers) != 1 || st.Servers[0].ID != srv.ID {
				t.Error("the server is not in the state")
			}
			got := e.eventsOf(KindUntested)
			if len(got) != 1 || !strings.Contains(got[0], srv.ID) || !strings.Contains(got[0], "later") {
				t.Errorf("untested events %q, want one that names the server", show(got))
			}
			for _, ev := range e.s.Events(0) {
				wantRedacted(t, ev.Message, vlessSecret)
			}
			if got := kicks(e.s); got != 1 {
				t.Errorf("kicked %d times, want 1", got)
			}
		})
	}
}

// A caller that gave up is not told the server was saved untested.
func TestAddServerStopsWhenTheContextEnds(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	_, rev, err := e.s.AddServer(ctx, 0, NewServer{Link: vlessLink})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", show(err))
	}
	if rev != 0 {
		t.Errorf("revision = %d, want 0", rev)
	}
	e.wantUnchanged(0, 0, 0)
	if got := e.s.Events(0); len(got) != 0 {
		t.Errorf("events %s, want none", show(got))
	}
}

func TestUpdateServerWithoutANewOutboundIsNotTested(t *testing.T) {
	e := newEnv(t)
	e.addServer("old", vlessOutbound)
	srv := e.serverNamed("old")
	_, rev := e.store.State()

	name, off := "renamed", true
	got, rev2, err := e.s.UpdateServer(bg, rev, srv.ID, ServerPatch{Name: &name})
	if err != nil {
		t.Fatal(show(err))
	}
	if got.Name != "renamed" || got.Disabled || !reflect.DeepEqual(got.Outbound, srv.Outbound) || rev2 != rev+1 {
		t.Errorf("after the rename: %s at revision %d", show(got), rev2)
	}
	got, rev3, err := e.s.UpdateServer(bg, rev2, srv.ID, ServerPatch{Disabled: &off})
	if err != nil {
		t.Fatal(show(err))
	}
	if got.Name != "renamed" || !got.Disabled || rev3 != rev2+1 {
		t.Errorf("after disabling: %s at revision %d", show(got), rev3)
	}
	if st, _ := e.store.State(); !reflect.DeepEqual(st.Servers, []store.Server{got}) {
		t.Error("the state does not hold the server returned")
	}
	if tests := e.runner.gotTests(); len(tests) != 0 {
		t.Errorf("the runner tested %d configs for edits that change no outbound", len(tests))
	}
	if slices.Contains(e.runner.gotCalls(), "test") {
		t.Error("the runner was called to test")
	}
	if got := kicks(e.s); got != 2 {
		t.Errorf("kicked %d times, want 2", got)
	}
}

// A server that Open disabled stays so until its outbound is replaced; the
// replacement is tested like a new server.
func TestUpdateServerNewOutboundClearsInvalid(t *testing.T) {
	e := newEnv(t)
	_, _, err := e.store.Update(store.AnyRevision, func(st *store.State) error {
		st.Servers = append(st.Servers, store.Server{ID: "0000000a", Name: "old", Disabled: true, Invalid: "an older reason",
			Link: "vless://old.example", Outbound: json.RawMessage(`{"protocol":"direct"}`)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, rev := e.store.State()
	on := false

	// Still invalid: it can't be enabled.
	_, _, err = e.s.UpdateServer(bg, rev, "0000000a", ServerPatch{Disabled: &on})
	r := wantRefused(t, err)
	if !strings.Contains(r.Reason, "stays disabled") {
		t.Errorf("reason = %q, want it to say the server stays disabled", r.Reason)
	}
	e.wantUnchanged(rev, 0, 0)

	// The outbound is replaced: tested, and the reason is gone.
	srv, rev2, err := e.s.UpdateServer(bg, rev, "0000000a", ServerPatch{Outbound: json.RawMessage(vlessOutbound)})
	if err != nil {
		t.Fatal(show(err))
	}
	if srv.Invalid != "" || srv.Link != "" || !srv.Disabled || srv.Name != "old" || rev2 != rev+1 {
		t.Errorf("server = %s at revision %d, want no reason and no link, still disabled", show(srv), rev2)
	}
	e.wantTestConfig(srv)
	if srv.Tag() != "srv-0000000a" {
		t.Errorf("tag = %q", srv.Tag())
	}

	// Now it can be enabled.
	srv, _, err = e.s.UpdateServer(bg, rev2, "0000000a", ServerPatch{Disabled: &on})
	if err != nil || srv.Disabled {
		t.Errorf("enabling: %s, %v; want an enabled server", show(srv), show(err))
	}
}

func TestUpdateServerByLinkAndByOutbound(t *testing.T) {
	e := newEnv(t)
	e.addServer("keep", `{"protocol":"vless","settings":{"vnext":[{"address":"198.51.100.7","port":443,"users":[{"encryption":"none","id":"11111111-2222-3333-4444-555555555555"}]}]},"streamSettings":{"security":"reality","realitySettings":{"publicKey":"SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc","serverName":"www.example.com"}}}`)
	srv := e.serverNamed("keep")

	link := vlessLink
	got, rev, err := e.s.UpdateServer(bg, store.AnyRevision, srv.ID, ServerPatch{Link: &link})
	if err != nil {
		t.Fatal(show(err))
	}
	if got.Name != "keep" || got.Link != vlessLink || got.ID != srv.ID || reflect.DeepEqual(got.Outbound, srv.Outbound) {
		t.Errorf("after a new link: %s, want the same name and ID, the link and its outbound", show(got))
	}
	e.wantTestConfig(got)

	raw := strings.Replace(vlessOutbound, `{"protocol"`, `{"Tag":"x","protocol"`, 1)
	got, _, err = e.s.UpdateServer(bg, rev, srv.ID, ServerPatch{Outbound: json.RawMessage(raw)})
	if err != nil {
		t.Fatal(show(err))
	}
	if got.Link != "" || hasKeyFold(t, got.Outbound, "tag") {
		t.Errorf("after a new outbound: %s, want no link and no tag", show(got))
	}
	e.wantTestConfig(got)
	if n := len(e.runner.gotTests()); n != 2 {
		t.Errorf("%d tests, want 2", n)
	}

	// Not both.
	before := kicks(e.s)
	_, _, err = e.s.UpdateServer(bg, store.AnyRevision, srv.ID, ServerPatch{Link: &link, Outbound: json.RawMessage(vlessOutbound)})
	wantRefused(t, err, vlessSecret)
	e.wantUnchanged(rev+1, before, 2)
}

func TestUpdateServerRefusals(t *testing.T) {
	e := newEnv(t)
	e.addServer("one", vlessOutbound)
	srv := e.serverNamed("one")
	_, rev := e.store.State()
	bad, empty := "hello", ""
	for _, c := range []struct {
		name  string
		patch ServerPatch
		want  string
	}{
		{"a link that is none", ServerPatch{Link: &bad}, "not a share link"},
		{"an empty link", ServerPatch{Link: &empty}, "not a share link"},
		{"a direct outbound", ServerPatch{Outbound: json.RawMessage(`{"protocol":"direct"}`)}, "not a proxy protocol"},
		{"an empty name", ServerPatch{Name: &empty}, "must not be empty"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := e.s.UpdateServer(bg, rev, srv.ID, c.patch)
			r := wantRefused(t, err, vlessSecret)
			if !strings.Contains(r.Reason, c.want) {
				t.Errorf("reason = %q, want it to hold %q", r.Reason, c.want)
			}
			e.wantUnchanged(rev, 0, 0)
		})
	}
}

func TestUpdateServerRejectedByXray(t *testing.T) {
	e := newEnv(t)
	e.addServer("one", vlessOutbound)
	srv := e.serverNamed("one")
	_, rev := e.store.State()
	e.runner.setTestReject("infra/conf: bad user " + vlessID)

	link := vlessLink
	_, _, err := e.s.UpdateServer(bg, rev, srv.ID, ServerPatch{Link: &link})
	r := wantRefused(t, err, vlessSecret)
	if !strings.Contains(r.Reason, "infra/conf: bad user "+redacted) {
		t.Errorf("reason = %q, want xray's output with the id redacted", show(r.Reason))
	}
	e.wantUnchanged(rev, 0, 1)
	if st, _ := e.store.State(); !reflect.DeepEqual(st.Servers, []store.Server{srv}) {
		t.Error("the server changed though xray rejected the new link")
	}
}

func TestUpdateServerSavedWithoutARunnerTest(t *testing.T) {
	e := newEnv(t)
	e.addServer("one", vlessOutbound)
	srv := e.serverNamed("one")
	e.runner.setDown(true)
	link := vlessLink
	got, _, err := e.s.UpdateServer(bg, store.AnyRevision, srv.ID, ServerPatch{Link: &link})
	if err != nil || got.Link != vlessLink {
		t.Fatalf("UpdateServer = %s, %v; want the new link saved", show(got), show(err))
	}
	if evs := e.eventsOf(KindUntested); len(evs) != 1 || !strings.Contains(evs[0], srv.ID) {
		t.Errorf("untested events %q, want one that names the server", show(evs))
	}
}

func TestUpdateServerNotFound(t *testing.T) {
	e := newEnv(t)
	e.addServer("one", vlessOutbound)
	_, rev := e.store.State()
	name, link := "x", vlessLink
	for _, p := range []ServerPatch{{Name: &name}, {Link: &link}, {Outbound: json.RawMessage(vlessOutbound)}} {
		_, _, err := e.s.UpdateServer(bg, rev, "0000ffff", p)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("error = %v, want ErrNotFound", show(err))
		}
		e.wantUnchanged(rev, 0, 0)
	}
}

// The error names what was not found, as the caller gave it, unless that is a
// credential.
func TestNotFoundNamesWhatWasAsked(t *testing.T) {
	e := newEnv(t)
	e.addServer("one", vlessOutbound)
	_, err := e.s.RemoveServer(bg, store.AnyRevision, "0000ffff")
	if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "0000ffff") {
		t.Errorf("error = %v, want ErrNotFound that names the server", show(err))
	}
	_, err = e.s.RemoveServer(bg, store.AnyRevision, vlessID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", show(err))
	}
	wantRedacted(t, err.Error(), vlessSecret)
	_, err = e.s.RemoveDevice(bg, store.AnyRevision, netip.MustParsePrefix("192.168.9.9/32"))
	if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "192.168.9.9/32") {
		t.Errorf("error = %v, want ErrNotFound that names the device", show(err))
	}
}

// A patch can replace the outbound of a server that Open disabled and enable
// it in one go.
func TestUpdateServerReplacesAndEnablesTogether(t *testing.T) {
	e := newEnv(t)
	_, _, err := e.store.Update(store.AnyRevision, func(st *store.State) error {
		st.Servers = append(st.Servers, store.Server{ID: "0000000a", Name: "old", Disabled: true, Invalid: "an older reason",
			Outbound: json.RawMessage(`{"protocol":"direct"}`)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	on := false
	srv, _, err := e.s.UpdateServer(bg, store.AnyRevision, "0000000a", ServerPatch{Disabled: &on, Outbound: json.RawMessage(vlessOutbound)})
	if err != nil || srv.Disabled || srv.Invalid != "" {
		t.Errorf("UpdateServer = %s, %v; want an enabled server with no reason", show(srv), show(err))
	}
}

func TestRemoveServerClearsThePinAndDropsRules(t *testing.T) {
	e := newEnv(t)
	e.addServer("a", vlessOutbound)
	e.addServer("b", trojanOutbound)
	a, b := e.serverNamed("a"), e.serverNamed("b")
	_, _, err := e.store.Update(store.AnyRevision, func(st *store.State) error {
		st.Routing.Pinned = a.ID
		st.Routing.Rules = []store.Rule{
			{Domains: []string{"domain:a.example"}, Action: store.ActionServer, Server: a.ID},
			{Domains: []string{"domain:b.example"}, Action: store.ActionServer, Server: b.ID},
			{Domains: []string{"domain:c.example"}, Action: store.ActionDirect},
			{IPs: []string{"10.0.0.0/8"}, Action: store.ActionServer, Server: a.ID},
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, rev := e.store.State()

	rev2, err := e.s.RemoveServer(bg, rev, a.ID)
	if err != nil {
		t.Fatal(show(err))
	}
	st, got := e.store.State()
	if got != rev2 || rev2 != rev+1 {
		t.Errorf("revision = %d (state at %d), want %d", rev2, got, rev+1)
	}
	if len(st.Servers) != 1 || st.Servers[0].ID != b.ID {
		t.Errorf("servers left: %s, want only b", show(st.Servers))
	}
	if st.Routing.Pinned != "" {
		t.Errorf("pinned = %q, want it cleared", st.Routing.Pinned)
	}
	if len(st.Routing.Rules) != 2 || st.Routing.Rules[0].Server != b.ID || st.Routing.Rules[1].Action != store.ActionDirect {
		t.Errorf("rules = %+v, want b's and the direct one, in order", st.Routing.Rules)
	}
	cleanup := e.eventsOf(KindCleanup)
	if len(cleanup) != 2 {
		t.Fatalf("cleanup events %q, want one for the pin and one for the rules", cleanup)
	}
	for _, msg := range cleanup {
		if !strings.Contains(msg, a.ID) {
			t.Errorf("cleanup event %q does not name the server", msg)
		}
		wantRedacted(t, msg, vlessSecret, trojanSecret)
	}
	if !strings.Contains(cleanup[0], "pin") || !strings.Contains(cleanup[1], "2 ") {
		t.Errorf("cleanup events %q, want the pin first and then the 2 rules", cleanup)
	}
	if got := kicks(e.s); got != 1 {
		t.Errorf("kicked %d times, want 1", got)
	}
}

func TestRemoveServerWithNothingToCleanUp(t *testing.T) {
	e := newEnv(t)
	e.addServer("a", vlessOutbound)
	a := e.serverNamed("a")
	if _, err := e.s.RemoveServer(bg, store.AnyRevision, a.ID); err != nil {
		t.Fatal(show(err))
	}
	if st, _ := e.store.State(); len(st.Servers) != 0 {
		t.Errorf("servers left: %s", show(st.Servers))
	}
	if got := e.eventsOf(KindCleanup); len(got) != 0 {
		t.Errorf("cleanup events %q, want none", got)
	}
	_, rev := e.store.State()
	if _, err := e.s.RemoveServer(bg, rev, a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing it again: %v, want ErrNotFound", err)
	}
}

func TestSetDeviceReplacesByAddress(t *testing.T) {
	e := newEnv(t)
	five := netip.MustParsePrefix("192.168.1.5/32")
	six := netip.MustParsePrefix("192.168.1.6/32")
	rev, err := e.s.SetDevice(bg, 0, store.Device{Address: five, Name: "tv", Policy: store.Policy{Mode: store.ModeSmart}})
	if err != nil || rev != 1 {
		t.Fatalf("SetDevice = %d, %v; want 1", rev, err)
	}
	if rev, err = e.s.SetDevice(bg, rev, store.Device{Address: six, Policy: store.Policy{Mode: store.ModeFull}}); err != nil || rev != 2 {
		t.Fatalf("SetDevice = %d, %v; want 2", rev, err)
	}
	want := store.Device{Address: five, Name: "phone", MAC: "aa:bb:cc:dd:ee:ff", Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}}
	if rev, err = e.s.SetDevice(bg, rev, want); err != nil || rev != 3 {
		t.Fatalf("SetDevice = %d, %v; want 3", rev, err)
	}
	st, _ := e.store.State()
	if len(st.Devices) != 2 || !reflect.DeepEqual(st.Devices[0], want) || st.Devices[1].Address != six {
		t.Errorf("devices = %+v, want the first replaced in place and the second as it was", st.Devices)
	}
	if got := kicks(e.s); got != 3 {
		t.Errorf("kicked %d times, want 3", got)
	}
}

func TestSetDeviceRefusals(t *testing.T) {
	e := newEnv(t)
	if _, err := e.s.SetDevice(bg, 0, store.Device{Address: netip.MustParsePrefix("192.168.1.5/32"), Policy: store.Policy{Mode: store.ModeSmart}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		d    store.Device
		want string
	}{
		{"an overlapping range", store.Device{Address: netip.MustParsePrefix("192.168.1.0/24"), Policy: store.Policy{Mode: store.ModeFull}}, "overlaps"},
		{"host bits", store.Device{Address: netip.MustParsePrefix("192.168.2.5/24"), Policy: store.Policy{Mode: store.ModeFull}}, "host bits"},
		{"no address", store.Device{Policy: store.Policy{Mode: store.ModeFull}}, "IPv4"},
		{"a kill switch in direct", store.Device{Address: netip.MustParsePrefix("192.168.3.5/32"), Policy: store.Policy{Mode: store.ModeDirect, KillSwitch: true}}, "kill_switch"},
		{"no mode", store.Device{Address: netip.MustParsePrefix("192.168.3.5/32")}, "mode"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rev, err := e.s.SetDevice(bg, 1, c.d)
			r := wantRefused(t, err)
			if !strings.Contains(r.Reason, c.want) {
				t.Errorf("reason = %q, want it to hold %q", r.Reason, c.want)
			}
			if rev != 0 {
				t.Errorf("revision = %d, want 0", rev)
			}
			e.wantUnchanged(1, 1, 0)
		})
	}
}

func TestRemoveDevice(t *testing.T) {
	e := newEnv(t)
	five := netip.MustParsePrefix("192.168.1.5/32")
	rev, err := e.s.SetDevice(bg, 0, store.Device{Address: five, Policy: store.Policy{Mode: store.ModeFull}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.RemoveDevice(bg, rev, netip.MustParsePrefix("192.168.1.6/32")); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing an unknown device: %v, want ErrNotFound", err)
	}
	e.wantUnchanged(rev, 1, 0)

	rev2, err := e.s.RemoveDevice(bg, rev, five)
	if err != nil || rev2 != rev+1 {
		t.Fatalf("RemoveDevice = %d, %v; want %d", rev2, err, rev+1)
	}
	if st, _ := e.store.State(); len(st.Devices) != 0 {
		t.Errorf("devices = %+v, want none", st.Devices)
	}
	if got := kicks(e.s); got != 2 {
		t.Errorf("kicked %d times, want 2", got)
	}
}

func TestSetDefaultPolicy(t *testing.T) {
	e := newEnv(t)
	want := store.Policy{Mode: store.ModeFull, KillSwitch: true}
	rev, err := e.s.SetDefaultPolicy(bg, 0, want)
	if err != nil || rev != 1 {
		t.Fatalf("SetDefaultPolicy = %d, %v; want 1", rev, err)
	}
	if st, _ := e.store.State(); st.DefaultPolicy != want {
		t.Errorf("default policy = %+v, want %+v", st.DefaultPolicy, want)
	}
	for _, p := range []store.Policy{{Mode: "everything"}, {Mode: store.ModeDirect, KillSwitch: true}, {}} {
		_, err := e.s.SetDefaultPolicy(bg, 1, p)
		wantRefused(t, err)
	}
	e.wantUnchanged(1, 1, 0)
}

func TestSetRouting(t *testing.T) {
	e := newEnv(t)
	e.addServer("a", vlessOutbound)
	a := e.serverNamed("a")
	_, rev := e.store.State()
	want := store.Routing{
		Pinned:    a.ID,
		BlockList: []string{"domain:ads.example"},
		Domestic:  store.Domestic{Domains: []string{"domain:bank.example"}, IPs: []string{"10.0.0.0/8"}},
		Rules:     []store.Rule{{Domains: []string{"full:x.example"}, Action: store.ActionServer, Server: a.ID}},
	}
	rev2, err := e.s.SetRouting(bg, rev, want)
	if err != nil || rev2 != rev+1 {
		t.Fatalf("SetRouting = %d, %v; want %d", rev2, err, rev+1)
	}
	if st, _ := e.store.State(); !reflect.DeepEqual(st.Routing, want) {
		t.Errorf("routing = %+v, want %+v", st.Routing, want)
	}

	for _, c := range []struct {
		name string
		r    store.Routing
		want string
	}{
		{"a pin on no server", store.Routing{Pinned: "0000ffff"}, "names no server"},
		{"a rule for no server", store.Routing{Rules: []store.Rule{{Domains: []string{"a.example"}, Action: store.ActionServer, Server: "0000ffff"}}}, "names no server"},
		{"an ext: matcher", store.Routing{BlockList: []string{"ext:geo.dat:ads"}}, "ext:"},
		{"a rule that matches nothing", store.Routing{Rules: []store.Rule{{Action: store.ActionDirect}}}, "needs domains or ips"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.s.SetRouting(bg, rev2, c.r)
			r := wantRefused(t, err, vlessSecret)
			if !strings.Contains(r.Reason, c.want) {
				t.Errorf("reason = %q, want it to hold %q", r.Reason, c.want)
			}
			e.wantUnchanged(rev2, 1, 0)
		})
	}
}

func TestSetDNS(t *testing.T) {
	e := newEnv(t)
	want := store.DNS{Domestic: netip.MustParseAddr("192.168.1.1"), Remote: "https://dns.example/dns-query"}
	rev, err := e.s.SetDNS(bg, 0, want)
	if err != nil || rev != 1 {
		t.Fatalf("SetDNS = %d, %v; want 1", rev, err)
	}
	if st, _ := e.store.State(); st.DNS != want {
		t.Errorf("dns = %+v, want %+v", st.DNS, want)
	}
	for _, d := range []store.DNS{
		{Domestic: want.Domestic, Remote: "192.168.1.1"}, // the remote resolver may not be the domestic one
		{Remote: "dns.example"},
		{Domestic: netip.MustParseAddr("2001:db8::1"), Remote: "1.1.1.1"},
	} {
		_, err := e.s.SetDNS(bg, 1, d)
		wantRefused(t, err)
	}
	e.wantUnchanged(1, 1, 0)
}

func TestSetHealth(t *testing.T) {
	e := newEnv(t)
	want := store.Health{ProbeURL: "https://probe.example/generate_204"}
	rev, err := e.s.SetHealth(bg, 0, want)
	if err != nil || rev != 1 {
		t.Fatalf("SetHealth = %d, %v; want 1", rev, err)
	}
	if st, _ := e.store.State(); st.Health != want {
		t.Errorf("health = %+v, want %+v", st.Health, want)
	}
	for _, h := range []store.Health{{ProbeURL: "ftp://probe.example"}, {}} {
		_, err := e.s.SetHealth(bg, 1, h)
		wantRefused(t, err)
	}
	e.wantUnchanged(1, 1, 0)
}

// A refusal is redacted with the secrets of the state it is about: a pin on a
// "server" that is a credential someone pasted in the wrong field must not
// echo the credential.
func TestRefusalsAreRedacted(t *testing.T) {
	e := newEnv(t)
	e.addServer("a", vlessOutbound)
	_, err := e.s.SetRouting(bg, store.AnyRevision, store.Routing{Pinned: vlessID})
	r := wantRefused(t, err, vlessSecret)
	if !strings.Contains(r.Reason, redacted) {
		t.Errorf("reason = %q, want the id redacted", r.Reason)
	}
}

// Every stale revision is a conflict, with nothing written, tested or kicked.
func TestMutationsCheckTheRevision(t *testing.T) {
	e := newEnv(t)
	e.addServer("a", vlessOutbound)
	a := e.serverNamed("a")
	_, stale := e.store.State()
	e.edit() // the state moves on
	_, rev := e.store.State()
	name := "x"
	five := netip.MustParsePrefix("192.168.1.5/32")
	for _, c := range []struct {
		name string
		call func(rev uint64) error
	}{
		{"AddServer", func(rev uint64) error {
			_, _, err := e.s.AddServer(bg, rev, NewServer{Link: vlessLink})
			return err
		}},
		{"UpdateServer", func(rev uint64) error {
			_, _, err := e.s.UpdateServer(bg, rev, a.ID, ServerPatch{Name: &name})
			return err
		}},
		{"UpdateServer with a new outbound", func(rev uint64) error {
			_, _, err := e.s.UpdateServer(bg, rev, a.ID, ServerPatch{Outbound: json.RawMessage(vlessOutbound)})
			return err
		}},
		{"RemoveServer", func(rev uint64) error { _, err := e.s.RemoveServer(bg, rev, a.ID); return err }},
		{"SetDevice", func(rev uint64) error {
			_, err := e.s.SetDevice(bg, rev, store.Device{Address: five, Policy: store.Policy{Mode: store.ModeFull}})
			return err
		}},
		{"RemoveDevice", func(rev uint64) error { _, err := e.s.RemoveDevice(bg, rev, five); return err }},
		{"SetDefaultPolicy", func(rev uint64) error {
			_, err := e.s.SetDefaultPolicy(bg, rev, store.Policy{Mode: store.ModeFull})
			return err
		}},
		{"SetRouting", func(rev uint64) error { _, err := e.s.SetRouting(bg, rev, store.Routing{}); return err }},
		{"SetDNS", func(rev uint64) error {
			_, err := e.s.SetDNS(bg, rev, store.DNS{Remote: "https://dns.example/dns-query"})
			return err
		}},
		{"SetHealth", func(rev uint64) error {
			_, err := e.s.SetHealth(bg, rev, store.Health{ProbeURL: "https://probe.example"})
			return err
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := c.call(stale); !errors.Is(err, store.ErrConflict) {
				t.Errorf("error = %v, want store.ErrConflict", show(err))
			}
			e.wantUnchanged(rev, 0, 0)
		})
	}
	if got := e.s.Events(0); len(got) != 0 {
		t.Errorf("events %s for conflicts", show(got))
	}
}

func TestAnyRevisionSkipsTheCheck(t *testing.T) {
	e := newEnv(t)
	e.edit()
	e.edit()
	want := store.Health{ProbeURL: "https://probe.example/204"}
	rev, err := e.s.SetHealth(bg, store.AnyRevision, want)
	if err != nil || rev != 3 {
		t.Fatalf("SetHealth = %d, %v; want revision 3", rev, err)
	}
}

// Each change that is written kicks the apply loop once.
func TestMutationsKickOnce(t *testing.T) {
	e := newEnv(t)
	five := netip.MustParsePrefix("192.168.1.5/32")
	var id string
	name := "renamed"
	for _, c := range []struct {
		name string
		call func(rev uint64) (uint64, error)
	}{
		{"AddServer", func(rev uint64) (uint64, error) {
			srv, rev, err := e.s.AddServer(bg, rev, NewServer{Link: vlessLink})
			id = srv.ID
			return rev, err
		}},
		{"UpdateServer", func(rev uint64) (uint64, error) {
			_, rev, err := e.s.UpdateServer(bg, rev, id, ServerPatch{Name: &name})
			return rev, err
		}},
		{"SetDevice", func(rev uint64) (uint64, error) {
			return e.s.SetDevice(bg, rev, store.Device{Address: five, Policy: store.Policy{Mode: store.ModeSmart}})
		}},
		{"RemoveDevice", func(rev uint64) (uint64, error) { return e.s.RemoveDevice(bg, rev, five) }},
		{"SetDefaultPolicy", func(rev uint64) (uint64, error) {
			return e.s.SetDefaultPolicy(bg, rev, store.Policy{Mode: store.ModeSmart})
		}},
		{"SetRouting", func(rev uint64) (uint64, error) {
			return e.s.SetRouting(bg, rev, store.Routing{BlockList: []string{"domain:ads.example"}})
		}},
		{"SetDNS", func(rev uint64) (uint64, error) {
			return e.s.SetDNS(bg, rev, store.DNS{Remote: "https://dns.example/dns-query"})
		}},
		{"SetHealth", func(rev uint64) (uint64, error) {
			return e.s.SetHealth(bg, rev, store.Health{ProbeURL: "https://probe.example/204"})
		}},
		{"RemoveServer", func(rev uint64) (uint64, error) { return e.s.RemoveServer(bg, rev, id) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := kicks(e.s)
			_, rev := e.store.State()
			got, err := c.call(rev)
			if err != nil {
				t.Fatal(show(err))
			}
			if got != rev+1 {
				t.Errorf("revision = %d, want %d", got, rev+1)
			}
			if after := kicks(e.s); after != before+1 {
				t.Errorf("kicked %d times, want once", after-before)
			}
		})
	}
}

// A change leads to an apply of the new state, once the debounce has passed.
func TestMutationLeadsToAnApply(t *testing.T) {
	e := newEnv(t)
	e.outOfSync()
	e.start()
	rev, err := e.s.SetDefaultPolicy(bg, 0, store.Policy{Mode: store.ModeFull})
	if err != nil {
		t.Fatal(err)
	}
	e.settle()
	wantStatus(t, e.s, false, true)
	wantTrials(t, e)
	e.advance(2 * time.Second)
	st, got := e.store.State()
	if got != rev {
		t.Fatalf("revision = %d, want %d", got, rev)
	}
	wantTrials(t, e, configOf(t, st))
	wantStatus(t, e.s, true, false)
}
