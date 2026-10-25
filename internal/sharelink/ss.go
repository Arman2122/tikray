package sharelink

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode/utf8"
)

// ssMethods maps each cipher name that a link may use to the name xray reads.
// Anything else, like the old stream ciphers, is not supported.
var ssMethods = map[string]string{
	"aes-128-gcm":                   "aes-128-gcm",
	"aes-256-gcm":                   "aes-256-gcm",
	"chacha20-poly1305":             "chacha20-poly1305",
	"chacha20-ietf-poly1305":        "chacha20-poly1305",
	"xchacha20-poly1305":            "xchacha20-poly1305",
	"xchacha20-ietf-poly1305":       "xchacha20-poly1305",
	"2022-blake3-aes-128-gcm":       "2022-blake3-aes-128-gcm",
	"2022-blake3-aes-256-gcm":       "2022-blake3-aes-256-gcm",
	"2022-blake3-chacha20-poly1305": "2022-blake3-chacha20-poly1305",
	"none":                          "none",
}

// parseSS reads a Shadowsocks link in either of its two forms.
//
// SIP002 is ss://<userinfo>@<host>:<port>[/][?<query>]#<name>. The userinfo is
// the base64url of method:password, or method:password itself with the
// password percent-encoded, which is how the 2022 ciphers write their keys.
//
// The legacy form is ss://<base64 of method:password@host:port>#<name>, where
// the last @ splits the password from the host, since a password may have one.
// The base64 is in either alphabet, with or without padding.
//
// A plugin parameter, whatever its value, is not supported, as tikray runs no
// plugins. The transport and security are read from the same parameters as in
// a VLESS link (type, security, sni, host, path and the rest), with security
// none unless the link says otherwise. The outbound has streamSettings only
// when they ask for more than plain tcp: a network other than tcp, a security
// other than none, or a tcp header. Any other parameter is ignored.
//
// The errors it returns do not repeat any of the link, not even the method.
func parseSS(link string) (Server, error) {
	_, rest, _ := strings.Cut(link, "://")
	rest, rawFragment, _ := strings.Cut(rest, "#")
	body, query, _ := strings.Cut(rest, "?")
	if queryHasKey(query, "plugin") {
		return Server{}, fmt.Errorf("%w shadowsocks plugin", ErrUnsupported)
	}

	var (
		userinfo, host, fragment string
		port                     int
		q                        url.Values
	)
	if strings.Contains(body, "@") {
		// Base64 has no @, so this is SIP002.
		t, err := parseTarget(link, "ss")
		if err != nil {
			return Server{}, err
		}
		userinfo, host, port, fragment, q = t.secret, t.host, t.port, t.fragment, t.query
		if !strings.Contains(userinfo, ":") {
			raw, ok := decodeBase64(userinfo)
			if !ok {
				return Server{}, errors.New("sharelink: shadowsocks userinfo is neither method:password nor the base64 of it")
			}
			userinfo = string(raw)
		}
	} else {
		raw, ok := decodeBase64(body)
		if !ok {
			return Server{}, errors.New("sharelink: shadowsocks link is not base64")
		}
		text := string(raw)
		at := strings.LastIndex(text, "@")
		if at < 0 {
			return Server{}, errors.New("sharelink: shadowsocks link has no host")
		}
		h, p, err := net.SplitHostPort(text[at+1:])
		if err != nil {
			return Server{}, errors.New("sharelink: shadowsocks link has no valid host and port")
		}
		if host, ok = cleanHost(h); !ok {
			return Server{}, errors.New("sharelink: shadowsocks link has no valid host")
		}
		if port, ok = parsePort(p); !ok {
			return Server{}, errors.New("sharelink: shadowsocks link has an invalid port, want 1 to 65535")
		}
		userinfo, fragment = text[:at], unescapeFragment(rawFragment)
		var bad string
		if q, bad = parseQuery(query, streamKeys); bad != "" {
			return Server{}, fmt.Errorf("sharelink: ss link has a malformed %q parameter", bad)
		}
	}

	method, password, ok := strings.Cut(userinfo, ":")
	if !ok {
		return Server{}, errors.New("sharelink: shadowsocks link has no method:password")
	}
	method, ok = ssMethods[strings.ToLower(strings.TrimSpace(method))]
	if !ok {
		return Server{}, fmt.Errorf("%w shadowsocks method, want aes-128-gcm, aes-256-gcm, chacha20-poly1305, "+
			"xchacha20-poly1305, 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305 or none", ErrUnsupported)
	}
	if password == "" {
		return Server{}, errors.New("sharelink: shadowsocks link has no password")
	}
	// A password that is not text would be changed when it is written as JSON.
	if !utf8.ValidString(password) {
		return Server{}, errors.New("sharelink: shadowsocks password is not valid UTF-8")
	}
	strm := streamFromQuery(q, "none")
	st, err := strm.settings()
	if err != nil {
		return Server{}, err
	}
	// Plain tcp is what Shadowsocks does with no streamSettings at all.
	if st["network"] == "tcp" && len(st) == 1 {
		st = nil
	}
	out, err := buildOutbound("shadowsocks", map[string]any{
		"servers": []any{map[string]any{
			"address":  host,
			"port":     port,
			"method":   method,
			"password": password,
		}},
	}, st)
	if err != nil {
		return Server{}, err
	}
	return Server{Name: name(fragment, host, port), Outbound: out, Warnings: strm.warnings()}, nil
}
