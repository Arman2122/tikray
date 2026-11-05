package service

import (
	"cmp"
	"encoding/json"
	"net/url"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/secrettext"
	"github.com/Arman2122/tikray/internal/store"
)

// redacted is what a secret is replaced with: the placeholder the API's views
// show too, which the store refuses to hold.
const redacted = store.Masked

// minSecret is the length, in bytes, below which a string is not taken for a
// secret: replacing every "abc" would make a text unreadable without
// protecting anything, and withholding every text that holds a "3" (an
// SSPanel URL's "?sub=3") would hide addresses, IDs and revisions. The
// runner's batch diagnostics withhold their detail instead (batchRedactor),
// since a verdict there can quote a short credential and is kept.
const minSecret = 4

// RedactorFor returns a function that replaces every secret of st in a text
// with ‹redacted›. The secrets are:
//   - in each server's outbound, the strings under the keys id, password,
//     privateKey, preSharedKey, seed, secretKey (WireGuard's private key),
//     user and pass (SOCKS's, HTTP's and MASQUE's), auth (Hysteria 2's), key
//     (a TLS client certificate's) and secrets (XDrive's), in any case and at
//     any depth, and the strings of a list under them;
//   - each server's share link, which encodes its credentials (an SS link
//     holds its password in base64);
//   - each subscription URL, as it is, as its parsed form, with its password
//     masked the way net/http and url.URL.Redacted show it, and without its
//     userinfo, and that userinfo's user name and password;
//   - the query string of each of these URLs and those of its values that
//     can be credentials (under a credential's key, or long), encoded and
//     decoded, and the userinfo of probe and resolver URLs. Earlier
//     diagnostics can contain these values even after their URL is shortened.
//
// A string shorter than 4 bytes is left alone. Where secrets overlap in the
// text, as when one holds another, the whole stretch they cover is replaced
// once, so that no part of either is left. A text that holds the runner's
// truncation marker is withheld whole: the cut can leave only the prefix of a
// secret.
func RedactorFor(st store.State) func(string) string { return RedactorWith(st) }

// RedactorWith is RedactorFor(st) that also hides the credentials in the JSON
// documents, each read as an outbound is: the strings under the same keys, at
// any depth, whatever the document's shape. It is for what a command runs
// that is no part of the state, such as an xray config file, whose outbounds
// (and inbounds' clients) xray may quote when it rejects it. A document that is
// not JSON has none to find.
func RedactorWith(st store.State, documents ...json.RawMessage) func(string) string {
	set := map[string]bool{}
	add := func(s string) {
		if len(s) >= minSecret {
			set[s] = true
		}
	}
	for _, doc := range documents {
		outboundSecrets(doc, add)
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
	urlSecrets(st.DNS.Remote, false, add)
	secrets := make([]string, 0, len(set))
	for s := range set {
		secrets = append(secrets, s)
	}
	// Longest first, for the same result whatever the map's order.
	slices.SortFunc(secrets, func(a, b string) int { return cmp.Or(cmp.Compare(len(b), len(a)), strings.Compare(a, b)) })
	return func(text string) string {
		if strings.Contains(text, runnerapi.TestOutputTruncated) {
			return redacted // the cut can leave only the prefix of a secret
		}
		return redact(text, secrets)
	}
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

// outboundSecrets visits the same config fields the runner hides from test
// and trial diagnostics.
func outboundSecrets(raw json.RawMessage, add func(string)) {
	secrettext.Credentials(raw, add)
}

// longQueryValue is the length from which a URL's query value counts as a
// secret whatever its key: tokens, UUIDs and signatures are this long, the
// words a provider's URL selects a format with are not.
const longQueryValue = 16

// credentialKeys are the parts of a query key that mark its value as a
// credential, matched without regard to case: "token", "access_key",
// "password", "uuid", "sign"...
var credentialKeys = []string{"token", "key", "secret", "pass", "pwd", "auth", "uuid", "sig", "hash"}

// credentialKey reports whether a URL query key names a credential.
func credentialKey(key string) bool {
	if k, err := url.QueryUnescape(key); err == nil {
		key = k
	}
	key = strings.ToLower(key)
	return slices.ContainsFunc(credentialKeys, func(part string) bool { return strings.Contains(key, part) })
}

// urlSecrets calls add with the user name and password of raw's userinfo, its
// query string and each query value, and, when whole is set, with the forms
// of raw that a client's error can show (see RedactorFor). add drops what is
// too short to be a secret, such as the "3" of "?sub=3". raw that does not
// parse adds nothing.
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
	// HTTP errors and stored diagnostics can echo an individual value in
	// its original URL encoding or after decoding it. Only a value that can
	// be a credential counts: one under a credential's key, or a long one.
	// The rest are ordinary words, such as V2Board's "flag=clash" and
	// "format=base64", that ordinary text holds too.
	add(u.RawQuery)
	for pair := range strings.SplitSeq(u.RawQuery, "&") {
		key, encoded, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		decoded, err := url.QueryUnescape(encoded)
		if err != nil {
			decoded = encoded
		}
		if !credentialKey(key) && len(decoded) < longQueryValue {
			continue
		}
		add(encoded)
		add(decoded)
	}
	if !whole {
		return
	}
	add(u.String())
	add(u.Redacted())
	if u.Path != "" && u.Path != "/" {
		// Account paths can also occur in probe URLs or errors that have
		// lost or changed their query string.
		base := *u
		base.User, base.Fragment, base.RawFragment = nil, "", ""
		base.RawQuery, base.ForceQuery = "", false
		add(base.String())
	}
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
