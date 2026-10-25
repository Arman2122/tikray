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
	"strconv"
	"strings"
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
}

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
// host and the port, and that the query is well formed, but not the secret,
// which only the caller knows the rules for. The errors it returns do not
// repeat any of the link: the text of a net/url error would.
func parseTarget(link, scheme string) (target, error) {
	u, err := url.Parse(link)
	if err != nil {
		return target{}, fmt.Errorf("sharelink: malformed %s link", scheme)
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
	// Query would silently drop a parameter with a bad escape, and the outbound
	// would then not match the server.
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return target{}, fmt.Errorf("sharelink: malformed query in %s link", scheme)
	}
	t := target{host: host, port: port, query: q, fragment: u.Fragment}
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

// name gives the name of a server: the link's fragment, trimmed and cut to 128
// runes, or host:port when the fragment is empty. An IPv6 host is bracketed.
func name(fragment, host string, port int) string {
	n := strings.TrimSpace(strings.ToValidUTF8(fragment, "�"))
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
