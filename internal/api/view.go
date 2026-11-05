package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Arman2122/tikray/internal/auth"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
)

// publicName is the auth store's PublicName, for the admin's username and a
// token's name, with the root bearer checked too: the auth store does not own
// it. Only bounded display fields go through this check.
func (h *handler) publicName(name string, session auth.Session) string {
	if len(name) > 128*utf8.UTFMax || h.holdsRoot(name) {
		return store.Masked
	}
	return h.a.PublicName(name, session)
}

// holdsRoot reports whether text holds the root bearer. The root itself is
// not retained: each window of its length is compared by its hash.
func (h *handler) holdsRoot(text string) bool {
	for i := 0; h.rootLen > 0 && i+h.rootLen <= len(text); i++ {
		if sha256.Sum256([]byte(text[i:i+h.rootLen])) == h.root {
			return true
		}
	}
	return false
}

// shown is a value of the state as a view shows it: with the state's secrets
// replaced where they occur, and masked whole when it holds the root bearer or
// a credential the auth store knows. A view hides only a real secret: a name
// or a routing value that merely looks like a credential, such as
// "VMESS-HTTP-WS01", is shown as it is, so that what a view shows is the
// value itself wherever it can be.
func (h *handler) shown(v string, redact func(string) string, session auth.Session) string {
	v = redact(v)
	if h.holdsRoot(v) || h.a.HoldsSecret(v, session) {
		return store.Masked
	}
	return v
}

// maskedRequest answers 400 when a request holds the placeholder a view shows
// for a hidden value. A view is for display: a section copied from a GET
// response and sent back would replace a rule or a name with the placeholder.
// The store refuses it too; this says so before any work is done, as a fault
// of the request. Callers give it only what a view shows: a link or an
// outbound may hold anything.
func (h *handler) maskedRequest(w http.ResponseWriter, v any) bool {
	b, err := json.Marshal(v)
	if err != nil || !bytes.Contains(b, []byte(store.Masked)) {
		return false
	}
	h.writeError(w, http.StatusBadRequest, codeBadRequest, "the request holds "+store.Masked+", a masked placeholder from a view: a GET response is for display; send the values themselves")
	return true
}

// The CLI consumes the protocol and first host/port from the outbound field.
// Project only those values: transports, users, and unknown protocol settings
// can all carry credentials, even when tikray does not understand their keys.
type endpointFields struct {
	Address string          `json:"address"`
	Port    json.RawMessage `json:"port"`
}

func publicHost(host string) string {
	host = strings.TrimSpace(host)
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return a.String()
	}
	for _, c := range host {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && !strings.ContainsRune("._-", c) {
			return ""
		}
	}
	return host
}

func publicOutbound(raw json.RawMessage, safe func(string) string) json.RawMessage {
	var ob struct {
		Protocol string
		Settings struct {
			endpointFields
			Vnext, Servers []endpointFields
			Peers          []struct{ Endpoint string }
		}
	}
	_ = json.Unmarshal(raw, &ob)
	view := map[string]any{"protocol": publicHost(safe(ob.Protocol))}
	t := ob.Settings.endpointFields
	if t.Address == "" {
		switch {
		case len(ob.Settings.Vnext) > 0:
			t = ob.Settings.Vnext[0]
		case len(ob.Settings.Servers) > 0:
			t = ob.Settings.Servers[0]
		case len(ob.Settings.Peers) > 0:
			host, port, err := net.SplitHostPort(ob.Settings.Peers[0].Endpoint)
			if err == nil {
				t.Address, t.Port = host, json.RawMessage(port)
			}
		}
	}
	if host := publicHost(safe(t.Address)); host != "" {
		settings := map[string]any{"address": host}
		if port, err := strconv.ParseUint(strings.Trim(string(t.Port), `"`), 10, 16); err == nil && port > 0 {
			settings["port"] = port
		}
		view["settings"] = settings
	}
	b, _ := json.Marshal(view) // strings, an integer and string-keyed maps
	return b
}

// Keep the revision and the shape that existing clients use for display.
// A state response is a view; private state on disk remains the restore source.
func (h *handler) visibleServer(s store.Server, redact func(string) string) store.Server {
	safe := func(v string) string { return h.shown(v, redact, auth.Session{}) }
	return store.Server{ID: s.ID, Name: safe(s.Name), Disabled: s.Disabled, Untested: s.Untested,
		Invalid: redact(s.Invalid), Subscription: s.Subscription, Outbound: publicOutbound(s.Outbound, safe)}
}

func (h *handler) visibleSub(s store.Subscription, redact func(string) string) store.Subscription {
	return store.Subscription{ID: s.ID, Name: h.shown(s.Name, redact, auth.Session{}), Interval: s.Interval,
		Disabled: s.Disabled, LastFetch: s.LastFetch, LastError: redact(s.LastError)}
}

// publicURL is a probe or resolver URL as a view shows it: its scheme, host,
// port and path, without the userinfo, query and fragment, which can carry
// passwords or tokens. It is empty when what is left still holds a secret:
// the path of a probe can be the private account path of a subscription,
// whose full URL the redactor knows, or hold the root bearer.
func (h *handler) publicURL(raw string, redact func(string) string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" {
		return ""
	}
	u.User, u.RawQuery, u.Fragment, u.RawFragment = nil, "", "", ""
	u.ForceQuery = false
	public := u.String()
	if h.shown(public, redact, auth.Session{}) != public {
		return ""
	}
	return public
}

func (h *handler) visibleServers(st store.State, redact func(string) string) []store.Server {
	servers := make([]store.Server, len(st.Servers))
	for i, srv := range st.Servers {
		servers[i] = h.visibleServer(srv, redact)
	}
	return servers
}

func (h *handler) visibleSubscriptions(st store.State, redact func(string) string) []store.Subscription {
	subs := make([]store.Subscription, len(st.Subscriptions))
	for i, sub := range st.Subscriptions {
		subs[i] = h.visibleSub(sub, redact)
	}
	return subs
}

func (h *handler) visibleDevices(st store.State, redact func(string) string) []store.Device {
	devices := slices.Clone(st.Devices)
	for i := range devices {
		devices[i].Name = h.shown(devices[i].Name, redact, auth.Session{})
	}
	return orEmpty(devices)
}

func (h *handler) visibleRouting(r store.Routing, redact func(string) string) store.Routing {
	clean := func(values []string) []string {
		values = slices.Clone(values)
		for i, v := range values {
			values[i] = h.shown(v, redact, auth.Session{})
		}
		return values
	}
	r.BlockList = clean(r.BlockList)
	r.Domestic.Domains, r.Domestic.IPs = clean(r.Domestic.Domains), clean(r.Domestic.IPs)
	r.Rules = slices.Clone(r.Rules)
	for i := range r.Rules {
		r.Rules[i].Domains, r.Rules[i].IPs = clean(r.Rules[i].Domains), clean(r.Rules[i].IPs)
	}
	return r
}

func (h *handler) visibleState(st store.State) store.State {
	redact := service.RedactorFor(st)
	st.Servers = h.visibleServers(st, redact)
	st.Subscriptions = h.visibleSubscriptions(st, redact)
	st.Devices = h.visibleDevices(st, redact)
	st.Routing = h.visibleRouting(st.Routing, redact)
	st.Health.ProbeURL = h.publicURL(st.Health.ProbeURL, redact)
	st.DNS.Remote = h.publicURL(st.DNS.Remote, redact)
	return st
}
