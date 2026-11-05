// Package secrettext finds credentials in xray configuration documents.
package secrettext

import (
	"encoding/json"
	"net/url"
	"strings"
)

// secretKeys are the keys of an outbound whose string values are
// credentials, in lower case: xray matches its keys without regard to case.
// secretKey is WireGuard's private key, as xray names it; user and pass are
// SOCKS's and HTTP's (pass MASQUE's too), auth is Hysteria 2's, key a TLS
// client certificate's, and secrets XDrive's.
var secretKeys = map[string]bool{
	"id": true, "password": true, "privatekey": true, "presharedkey": true, "seed": true, "secretkey": true,
	"user": true, "pass": true, "auth": true, "key": true, "secrets": true,
	"authorization": true, "proxy-authorization": true,
}

// Credentials visits nonempty string values under known credential keys.
// A document it cannot parse gives false: its output is unsafe to publish.
func Credentials(raw json.RawMessage, add func(string)) bool {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	var walk func(v any, secret, cookie bool)
	walk = func(v any, secret, cookie bool) {
		switch v := v.(type) {
		case string:
			if secret && v != "" {
				add(v)
				// Older runners can quote the JSON-escaped spelling alone.
				if quoted, err := json.Marshal(v); err == nil {
					add(string(quoted[1 : len(quoted)-1]))
				}
				if cookie {
					for pair := range strings.SplitSeq(v, ";") {
						if _, value, ok := strings.Cut(pair, "="); ok {
							value = strings.Trim(strings.TrimSpace(value), `"`)
							if value != "" {
								add(value)
							}
						}
					}
				}
				// A diagnostic can quote just the credentials of an HTTP
				// authorization header, without its scheme.
				if fields := strings.Fields(v); len(fields) == 2 &&
					(strings.EqualFold(fields[0], "Bearer") || strings.EqualFold(fields[0], "Basic")) {
					add(fields[1])
				}
			}
			if strings.Contains(v, "://") {
				if u, err := url.Parse(v); err == nil && u.User != nil {
					// The URL can appear encoded, or its userinfo decoded.
					if encoded := u.User.String(); encoded != "" {
						add(encoded)
					}
					if name := u.User.Username(); name != "" {
						add(name)
					}
					if password, ok := u.User.Password(); ok && password != "" {
						add(password)
					}
				}
			}
		case []any:
			for _, e := range v {
				walk(e, secret, cookie)
			}
		case map[string]any:
			for k, e := range v {
				key := strings.ToLower(k)
				isCookie := cookie || key == "cookie" || key == "set-cookie"
				walk(e, secret || key == "headers" || isCookie || secretKeys[key], isCookie)
			}
		}
	}
	walk(v, false, false)
	return true
}
