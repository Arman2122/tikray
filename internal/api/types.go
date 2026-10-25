package api

import (
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
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

// lineLabel says which line of a subscription was skipped without showing it.
// A share link that did not parse holds a credential that is in no state, so
// that no redactor knows it: the label is the link's scheme, "://…", and
// "#<name>" when the link has a fragment, which is the name it shows (as the
// parser reads it: unescaped, without the characters a name may not hold).
// A line that is no URL is "…".
//
// The fragment starts at the first "#", as in any URL. A link that is broken
// by a raw "#" in its credential shows what follows it; this is the one
// place the label can show part of one.
func lineLabel(line string) string {
	const none = "…"
	i := strings.Index(line, "://")
	if i <= 0 || !isScheme(line[:i]) {
		return none
	}
	label := line[:i] + "://…"
	if _, frag, ok := strings.Cut(line[i:], "#"); ok {
		if name, err := url.PathUnescape(frag); err == nil {
			frag = name
		}
		frag = strings.Map(func(r rune) rune {
			if store.ForbiddenInName(r) {
				return -1
			}
			return r
		}, frag)
		if frag != "" {
			label += "#" + frag
		}
	}
	return label
}

// isScheme reports whether s is a URL scheme: a letter, then letters,
// digits, "+", "-" or ".".
func isScheme(s string) bool {
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return s != ""
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
