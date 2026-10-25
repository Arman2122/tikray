// Package sharelink turns the share links people paste (vless://, trojan://)
// into xray outbound objects.
//
// A link is a credential, so no error message repeats the secret parts of
// one: the VLESS id or the Trojan password.
package sharelink

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxNameRunes is the longest name a link can give a server.
const maxNameRunes = 128

// Server is one outbound that a share link describes.
type Server struct {
	// Name is the link's own name for the server, or host:port when it has none.
	Name string
	// Outbound is an xray outbound object without a tag. It is marshalled from
	// maps, so its keys are sorted.
	Outbound json.RawMessage
	// Warnings are notes about what the parser changed or ignored, safe to show
	// the user: they hold no secrets. It is nil when there are none.
	Warnings []string
}

// warnInsecureRemoved is the warning for a link that asks to skip the
// verification of the server's certificate. It is shown to the user, so it
// says what the parser did and what a link needs instead.
const warnInsecureRemoved = "allowInsecure was ignored because xray-core removed it: " +
	"the server's certificate must be valid, or pinned with the pcs parameter"

// ErrUnsupported is wrapped by the error for a link that is valid but that
// tikray cannot use: a scheme it does not read or a transport it does not run.
var ErrUnsupported = errors.New("sharelink: unsupported")

// Parse turns a share link into the server it describes. The scheme is case
// insensitive. A link that is not valid gives an error; a valid link that
// tikray cannot use gives an error that wraps ErrUnsupported.
func Parse(link string) (Server, error) {
	link = strings.TrimSpace(link)
	scheme, _, ok := strings.Cut(link, "://")
	if !ok || !validScheme(scheme) {
		return Server{}, errors.New("sharelink: not a share link")
	}
	switch strings.ToLower(scheme) {
	case "vless":
		return parseVLESS(link)
	case "trojan":
		return parseTrojan(link)
	}
	return Server{}, fmt.Errorf("%w scheme %q", ErrUnsupported, scheme)
}

// validScheme reports whether s looks like a URL scheme, so that an error
// message can name it. It is not a limit on which schemes are known.
func validScheme(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && (r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.'):
		default:
			return false
		}
	}
	return true
}

// target is the parts of a link that every scheme shares.
type target struct {
	// secret is the userinfo, decoded: the VLESS id or the Trojan password.
	secret string
	host   string
	port   int
	query  url.Values
	// fragment is the link's name for the server, decoded and not yet trimmed.
	fragment string
}

// parseTarget splits a link of the given scheme into its parts. It checks the
// host and the port, and the query parameters that the parser reads, which are
// streamKeys and the extra keys the scheme adds. It does not check the secret,
// which only the caller knows the rules for.
//
// The name after the # is only a label, so a bad escape in it never fails the
// link: the raw text is the name. A query parameter that the parser does not
// read is ignored even when it is malformed, but a malformed one that it reads
// fails the link, because dropping it would change the outbound.
//
// The errors it returns do not repeat any of the link: the text of a net/url
// error would.
func parseTarget(link, scheme string, extraKeys ...string) (target, error) {
	// url.Parse refuses the whole link when the fragment has a bad escape.
	link, rawFragment, _ := strings.Cut(link, "#")
	u, err := url.Parse(link)
	if err != nil {
		return target{}, fmt.Errorf("sharelink: malformed %s link", scheme)
	}
	fragment, err := url.PathUnescape(rawFragment)
	if err != nil {
		fragment = rawFragment
	}
	host := u.Hostname()
	if host == "" {
		return target{}, fmt.Errorf("sharelink: %s link has no host", scheme)
	}
	if u.Port() == "" {
		return target{}, fmt.Errorf("sharelink: %s link has no port", scheme)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return target{}, fmt.Errorf("sharelink: %s link has an invalid port, want 1 to 65535", scheme)
	}
	q, bad := parseQuery(u.RawQuery, append(slices.Clone(streamKeys), extraKeys...))
	if bad != "" {
		return target{}, fmt.Errorf("sharelink: %s link has a malformed %q parameter", scheme, bad)
	}
	t := target{host: host, port: port, query: q, fragment: fragment}
	if u.User != nil {
		t.secret = u.User.Username()
		// A colon splits the userinfo into a user and a password, but in a
		// share link it is part of the one secret.
		if p, ok := u.User.Password(); ok {
			t.secret += ":" + p
		}
	}
	return t, nil
}

// parseQuery splits a raw query into its parameters, like url.ParseQuery, but
// it skips a malformed pair instead of failing. A pair is malformed when its
// key or value has a bad escape, or it has a semicolon, which url.ParseQuery
// also refuses. If a malformed pair is for a key in read, parseQuery stops
// and returns that key as bad. A key with a bad escape is none of read, which
// are all plain text.
func parseQuery(raw string, read []string) (q url.Values, bad string) {
	q = url.Values{}
	for raw != "" {
		var pair string
		pair, raw, _ = strings.Cut(raw, "&")
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		key, kerr := url.QueryUnescape(k)
		value, verr := url.QueryUnescape(v)
		if kerr != nil {
			continue
		}
		if verr != nil || strings.Contains(pair, ";") {
			if slices.Contains(read, key) {
				return nil, key
			}
			continue
		}
		q.Add(key, value)
	}
	return q, ""
}

// name gives the name of a server: the link's fragment, trimmed and cut to 128
// runes, or host:port when the fragment is empty. An IPv6 host is bracketed.
func name(fragment, host string, port int) string {
	n := strings.TrimSpace(strings.ToValidUTF8(fragment, string(utf8.RuneError)))
	if n == "" {
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	if r := []rune(n); len(r) > maxNameRunes {
		n = string(r[:maxNameRunes])
	}
	return n
}

// buildOutbound marshals an outbound of the given protocol from its settings
// and streamSettings. The outbound has no tag; render adds one.
func buildOutbound(protocol string, settings, streamSettings map[string]any) (json.RawMessage, error) {
	b, err := json.Marshal(map[string]any{
		"protocol":       protocol,
		"settings":       settings,
		"streamSettings": streamSettings,
	})
	if err != nil {
		return nil, fmt.Errorf("sharelink: marshal %s outbound: %w", protocol, err)
	}
	return b, nil
}
