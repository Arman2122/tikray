package api

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/auth"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
)

// The wire types. A request body that the store's own types describe, such as
// a device or the routing, is decoded into them; the rest are here, with
// snake_case names like the store's.

// newServerRequest is the body of POST /v1/servers: exactly one of Link and
// Outbound (see service.NewServer).
type newServerRequest struct {
	Link     string          `json:"link"`
	Name     string          `json:"name"`
	Outbound json.RawMessage `json:"outbound"`
}

// serverPatchRequest is the body of PATCH /v1/servers/{id}: each field that
// is set replaces the server's (see service.ServerPatch).
type serverPatchRequest struct {
	Name     *string         `json:"name"`
	Disabled *bool           `json:"disabled"`
	Link     *string         `json:"link"`
	Outbound json.RawMessage `json:"outbound"`
}

// newSubscriptionRequest is the body of POST /v1/subscriptions. Interval is
// text such as "6h"; left out, it is the service's 24 h.
type newSubscriptionRequest struct {
	Name     string         `json:"name"`
	URL      string         `json:"url"`
	Interval store.Duration `json:"interval"`
}

// subscriptionPatchRequest is the body of PATCH /v1/subscriptions/{id}.
type subscriptionPatchRequest struct {
	Name     *string         `json:"name"`
	URL      *string         `json:"url"`
	Disabled *bool           `json:"disabled"`
	Interval *store.Duration `json:"interval"`
}

// coreUpdateRequest is the body of POST /v1/core/update: Version is "latest"
// or a release such as "26.10.21".
type coreUpdateRequest struct {
	Version         string `json:"version"`
	AllowUnverified bool   `json:"allow_unverified"`
}

// setupRequest is the body of POST /v1/auth/setup: the setup code, and the
// username and password of the admin it makes.
type setupRequest struct {
	Code     string `json:"code"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// loginRequest is the body of POST /v1/auth/login.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// passwordRequest is the body of PUT /v1/auth/password.
type passwordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

// authStateResponse is the answer of GET /v1/auth/state, which anyone may
// ask: whether the admin is yet to be made with the setup code, and whether
// this request is from a caller that is signed in.
type authStateResponse struct {
	SetupRequired bool `json:"setup_required"`
	SignedIn      bool `json:"signed_in"`
}

// sessionResponse is what setup and login answer with (the session itself
// is the cookie): the CSRF token its mutations carry, and when it ends if it
// is not used.
type sessionResponse struct {
	CSRFToken string    `json:"csrf_token"`
	Expires   time.Time `json:"expires"`
}

// whoamiResponse is the answer of GET /v1/auth/session: sessionResponse and
// the admin's username.
type whoamiResponse struct {
	Username  string    `json:"username"`
	CSRFToken string    `json:"csrf_token"`
	Expires   time.Time `json:"expires"`
}

// newTokenRequest is the body of POST /v1/tokens: a name, and ExpiresIn as
// text such as "720h" (left out, the token does not expire).
type newTokenRequest struct {
	Name      string `json:"name"`
	ExpiresIn string `json:"expires_in"`
}

// newTokenResponse is the answer to a new token: the token, which is shown
// this once, and what is known of it.
type newTokenResponse struct {
	Token string    `json:"token"`
	Info  tokenInfo `json:"info"`
}

// tokenInfo is an API token as the list shows it: never its secret. Expires
// and LastUsed are left out when the token never expires or was never used.
type tokenInfo struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires,omitzero"`
	LastUsed time.Time `json:"last_used,omitzero"`
}

func newTokenInfo(t auth.TokenInfo) tokenInfo {
	return tokenInfo{ID: t.ID, Name: t.Name, Created: t.Created, Expires: t.Expires, LastUsed: t.LastUsed}
}

// refreshResponse is service.RefreshResult on the wire.
type refreshResponse struct {
	Added   int           `json:"added"`
	Updated int           `json:"updated"`
	Removed int           `json:"removed"`
	Kept    int           `json:"kept"`
	Skipped []skippedLine `json:"skipped"`
	Via     string        `json:"via"`
}

// skippedLine is a line of a subscription that gave no server, and why. Line
// is not the line (see lineLabel), and Reason is redacted.
type skippedLine struct {
	Line   string `json:"line"`
	Reason string `json:"reason"`
}

func newRefreshResponse(r service.RefreshResult, redact func(string) string) refreshResponse {
	out := refreshResponse{Added: r.Added, Updated: r.Updated, Removed: r.Removed, Kept: r.Kept, Via: r.Via, Skipped: []skippedLine{}}
	for _, s := range r.Skipped {
		out.Skipped = append(out.Skipped, skippedLine{Line: redact(lineLabel(s.Line)), Reason: redact(s.Err)})
	}
	return out
}

// A malformed link can contain a credential on either side of a '#'. Only
// its recognized protocol is safe to identify in the refresh response.
func lineLabel(line string) string {
	scheme, _, ok := strings.Cut(line, "://")
	if ok {
		switch strings.ToLower(scheme) {
		case "vless", "vmess", "trojan", "ss":
			return strings.ToLower(scheme) + "://…"
		}
	}
	return "…"
}

// coreResponse is service.CoreInfo on the wire.
type coreResponse struct {
	Active  string             `json:"active"`
	Slots   []coreSlot         `json:"slots"`
	History []artifacts.Result `json:"history"`
}

// coreSlot is an installed core, as `tikray core list --json` shows it.
type coreSlot struct {
	Version     string    `json:"version"`
	Verified    string    `json:"verified"`
	Source      string    `json:"source"`
	InstalledAt time.Time `json:"installed_at"`
}

func newCoreResponse(c service.CoreInfo, redact func(string) string) coreResponse {
	out := coreResponse{Active: c.Active, Slots: []coreSlot{}, History: []artifacts.Result{}}
	for _, s := range c.Slots {
		out.Slots = append(out.Slots, coreSlot{s.Version.String(), s.Meta.Verified, s.Meta.Source, s.Meta.InstalledAt})
	}
	for _, r := range c.History {
		out.History = append(out.History, redactResult(r, redact))
	}
	return out
}

// redactResult returns r with its Detail redacted once more. The updater has
// done it already; a body is where a missed secret would reach a caller.
func redactResult(r artifacts.Result, redact func(string) string) artifacts.Result {
	r.Detail = redact(r.Detail)
	return r
}

// present returns raw, or nil when the body left it out or gave null.
func present(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return raw
}

// orEmpty makes a nil list an empty one, so that it marshals as [].
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
