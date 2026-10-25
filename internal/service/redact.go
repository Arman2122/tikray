package service

import (
	"cmp"
	"encoding/json"
	"net/url"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/store"
)

// redacted is what a secret is replaced with.
const redacted = "‹redacted›"

// minSecret is the length, in bytes, below which a string is not taken for a
// secret: replacing every "abc" would make a text unreadable without
// protecting anything.
const minSecret = 4

// secretKeys are the keys of an outbound whose string values are
// credentials, in lower case: xray matches its keys without regard to case.
// secretKey is WireGuard's private key, as xray names it.
var secretKeys = map[string]bool{"id": true, "password": true, "privatekey": true, "presharedkey": true, "seed": true, "secretkey": true}

// RedactorFor returns a function that replaces every secret of st in a text
// with ‹redacted›. The secrets are:
//   - in each server's outbound, the strings under the keys id, password,
//     privateKey, preSharedKey, seed and secretKey (WireGuard's private key),
//     in any case and at any depth, and the strings of a list under them;
//   - each server's share link, which encodes its credentials (an SS link
//     holds its password in base64);
//   - each subscription URL, as it is, as its parsed form, with its password
//     masked the way net/http and url.URL.Redacted show it, and without its
//     userinfo, and that userinfo's user name and password;
//   - the user name and password in the probe URL's userinfo, which xray's
//     observatory may repeat; the rest of that URL is no secret.
//
// A string shorter than 4 bytes is left alone. Where secrets overlap in the
// text, as when one holds another, the whole stretch they cover is replaced
// once, so that no part of either is left.
func RedactorFor(st store.State) func(string) string {
	set := map[string]bool{}
	add := func(s string) {
		if len(s) >= minSecret {
			set[s] = true
		}
	}
	for _, srv := range st.Servers {
		outboundSecrets(srv.Outbound, add)
		add(srv.Link)
	}
	for _, sub := range st.Subscriptions {
		add(sub.URL)
		urlSecrets(sub.URL, true, add)
	}
	urlSecrets(st.Health.ProbeURL, false, add)
	if len(set) == 0 {
		return func(s string) string { return s }
	}
	secrets := make([]string, 0, len(set))
	for s := range set {
		secrets = append(secrets, s)
	}
	// Longest first, for the same result whatever the map's order.
	slices.SortFunc(secrets, func(a, b string) int { return cmp.Or(cmp.Compare(len(b), len(a)), strings.Compare(a, b)) })
	return func(text string) string { return redact(text, secrets) }
}

// redact replaces every stretch of text that secrets cover with one
// ‹redacted›.
func redact(text string, secrets []string) string {
	type span struct{ start, end int }
	var spans []span
	for _, s := range secrets {
		for i := 0; ; {
			j := strings.Index(text[i:], s)
			if j < 0 {
				break
			}
			spans = append(spans, span{i + j, i + j + len(s)})
			i += j + 1 // overlapping matches count too
		}
	}
	if len(spans) == 0 {
		return text
	}
	slices.SortFunc(spans, func(a, b span) int { return cmp.Compare(a.start, b.start) })
	var b strings.Builder
	at := 0 // text before at is written
	for k := 0; k < len(spans); {
		start, end := spans[k].start, spans[k].end
		for k++; k < len(spans) && spans[k].start < end; k++ {
			end = max(end, spans[k].end)
		}
		b.WriteString(text[at:start])
		b.WriteString(redacted)
		at = end
	}
	b.WriteString(text[at:])
	return b.String()
}

// outboundSecrets calls add with the credentials in an outbound (see
// RedactorFor). An outbound that is not JSON has none to find.
func outboundSecrets(raw json.RawMessage, add func(string)) {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return
	}
	var walk func(v any, secret bool)
	walk = func(v any, secret bool) {
		switch v := v.(type) {
		case string:
			if secret {
				add(v)
			}
		case []any:
			for _, e := range v {
				walk(e, secret)
			}
		case map[string]any:
			for k, e := range v {
				walk(e, secretKeys[strings.ToLower(k)])
			}
		}
	}
	walk(v, false)
}

// urlSecrets calls add with the user name and password of raw's userinfo
// and, when whole is set, with the forms of raw that a client's error can
// show (see RedactorFor). raw that does not parse adds nothing.
func urlSecrets(raw string, whole bool, add func(string)) {
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	if u.User != nil {
		add(u.User.Username())
		if p, ok := u.User.Password(); ok {
			add(p)
		}
	}
	if !whole {
		return
	}
	add(u.String())
	add(u.Redacted())
	if u.User != nil {
		if _, ok := u.User.Password(); ok {
			// net/http's errors mask the password with three stars, as
			// its stripPassword does.
			add(strings.Replace(u.String(), u.User.String()+"@", u.User.Username()+":***@", 1))
		}
		m := *u
		m.User = nil
		add(m.String())
	}
}

// Redactor returns a function that replaces every secret of the state with
// ‹redacted› (see RedactorFor). It reads the state each time it is called,
// so it keeps up with every change.
func (s *Service) Redactor() func(string) string { return s.redact }

// redact applies RedactorFor of the current state to text.
func (s *Service) redact(text string) string { return s.redactorNow()(text) }

// redactorNow is RedactorFor of the current state. The redactor of the last
// revision it saw is kept, so that the outbounds are parsed once a revision.
func (s *Service) redactorNow() func(string) string {
	st, rev := s.store.State()
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if s.red == nil || s.redRev != rev {
		s.red, s.redRev = RedactorFor(st), rev
	}
	return s.red
}
