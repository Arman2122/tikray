// Package xraypolicy knows which outbounds the newest xray-core refuses.
//
// A config with one such outbound does not load at all, so one server that
// holds it makes every later apply fail `xray run -test`. Check finds those
// outbounds when a server is added, from a share link or from raw JSON, so
// that they never reach a config. The rules are xray's own, read from
// v26.10.21: infra/conf/xray.go (validateOutboundTransportSecurity, since
// 26.7.11), infra/conf/shadowsocks.go, proxy/shadowsocks_2022 and, for
// allowInsecure (since 26.3.27, once past 2026-06-01),
// infra/conf/transport_internet.go.
//
// Errors here never repeat a user id, a password or a key: they end up in
// logs, in the answers of the API and in the list of lines a subscription
// skipped.
package xraypolicy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strings"
)

// ErrRefused is wrapped by every refusal Check returns.
var ErrRefused = errors.New("xraypolicy: outbound refused")

// Refusal is the error Check returns for an outbound that xray refuses. Its
// text is Reason with the package's prefix. It wraps ErrRefused.
type Refusal struct {
	// Reason says what xray refuses, and why, in words that can be shown to a
	// user. It holds no id, password or key and does not start with the
	// package's prefix.
	Reason string
}

// Error returns the reason, prefixed with "xraypolicy: ".
func (r *Refusal) Error() string { return "xraypolicy: " + r.Reason }

// Unwrap returns ErrRefused.
func (r *Refusal) Unwrap() error { return ErrRefused }

func refuse(reason string) error { return &Refusal{Reason: reason} }

// privateIPRules is the list of private IP ranges, copied from
// common/geodata/consts.go of xray-core v26.10.21 (GetPrivateIPMatcher). Keep
// the entries as they are there.
var privateIPRules = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/3",
	"::/127",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

// privateDomainRules is the list of private domains, copied from
// common/geodata/consts.go of xray-core v26.10.21 (GetPrivateDomainMatcher). A
// rule without a prefix is a domain suffix, as in a routing rule's "domain:".
// Keep the entries as they are there.
var privateDomainRules = []string{
	"lan",
	"localdomain",
	"example",
	"invalid",
	"localhost",
	"test",
	"local",
	"home.arpa",
	"internal",
	"regexp:^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", // Dotless domains
}

var (
	privatePrefixes []netip.Prefix
	// privateSuffixes are the domain rules without a prefix.
	privateSuffixes []string
	// privatePatterns are the rules with the regexp: prefix.
	privatePatterns []*regexp.Regexp
)

func init() {
	for _, rule := range privateIPRules {
		privatePrefixes = append(privatePrefixes, netip.MustParsePrefix(rule))
	}
	for _, rule := range privateDomainRules {
		if pattern, ok := strings.CutPrefix(rule, "regexp:"); ok {
			privatePatterns = append(privatePatterns, regexp.MustCompile(pattern))
		} else {
			privateSuffixes = append(privateSuffixes, rule)
		}
	}
}

// PrivateAddress reports whether xray lets a server at host take plain
// traffic: whether host is an IP address in its list of private ranges, or a
// domain its list of private domains matches. A dotless name, which is a single
// label that starts with a letter and has only letters, digits and hyphens,
// matches too. It is xray's requiresTransportSecurity, inverted.
//
// host is read the way xray reads a server's address: brackets around an IPv6
// address are dropped, an IPv6 address that maps an IPv4 one is that IPv4
// address, and a name is lower-cased and loses one trailing dot. An address
// with an IPv6 zone is a name, as it is in xray.
func PrivateAddress(host string) bool {
	// net.ParseAddress of xray.
	if n := len(host); n > 0 && host[0] == '[' && host[n-1] == ']' {
		host = host[1 : n-1]
	}
	if n := len(host); n > 0 && (!alphaNum(host[0]) || !alphaNum(host[n-1])) {
		host = strings.TrimSpace(host)
	}
	if a, err := netip.ParseAddr(host); err == nil && a.Zone() == "" {
		a = a.Unmap()
		for _, p := range privatePrefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}

	domain := strings.TrimSuffix(strings.ToLower(host), ".")
	for _, suffix := range privateSuffixes {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	for _, re := range privatePatterns {
		if re.MatchString(domain) {
			return true
		}
	}
	return false
}

func alphaNum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// Check returns nil if xray accepts the outbound, or a *Refusal that wraps
// ErrRefused if it refuses it, which are:
//
//   - an outbound of any protocol with allowInsecure true in a tlsSettings
//     anywhere under streamSettings, whatever its security says: in the
//     stream's own tlsSettings or in those of a stream nested in it, such as
//     xhttp's download leg (xhttpSettings.extra.downloadSettings). xray
//     26.3.27 and later refuse it once past 2026-06-01 (with security tls,
//     the only one xray reads tlsSettings for), 26.1.18 skips the check of
//     the server's certificate with it, and tikray never lets a server ask
//     for that;
//   - VLESS with no encryption (empty or "none") over a stream with no
//     security, to a server that is not PrivateAddress;
//   - Trojan over a stream with no security, to a server that is not
//     PrivateAddress;
//   - Shadowsocks with the method none or plain;
//   - Shadowsocks 2022 with a password that is not made of base64 keys of the
//     cipher's length, or that has two keys for chacha20-poly1305.
//
// A stream has no security when streamSettings.security is absent, empty or
// "none". Check reads the settings in the nested form (vnext or servers) and
// in the flat one, which has the address in settings; the flat one wins when
// both are there, as in xray. It also reads keys without regard to case, like
// xray.
//
// An outbound whose shape Check cannot read is not refused, for store
// validation and xray's own `-test` already catch broken outbounds: only the
// rules above refuse.
func Check(outbound json.RawMessage) error {
	var ob struct {
		Protocol       string          `json:"protocol"`
		Settings       json.RawMessage `json:"settings"`
		StreamSettings json.RawMessage `json:"streamSettings"`
	}
	if json.Unmarshal(outbound, &ob) != nil {
		return nil
	}
	if insecureTLS(ob.StreamSettings) {
		return refuse("xray-core refuses allowInsecure, which turns off the check of the server's TLS certificate: " +
			"pin the certificate with pinnedPeerCertSha256 instead")
	}
	switch strings.ToLower(ob.Protocol) {
	case "vless":
		return checkVLESS(ob.Settings, ob.StreamSettings)
	case "trojan":
		return checkTrojan(ob.Settings, ob.StreamSettings)
	case "shadowsocks":
		return checkShadowsocks(ob.Settings)
	}
	return nil
}

// insecureTLS reports whether streamSettings holds, at any depth, a
// tlsSettings object whose allowInsecure is true: the stream's own, or that of
// a stream nested in it, such as xhttp's download leg
// (xhttpSettings.extra.downloadSettings), which xray builds like any other.
// Keys are read without regard to case, like xray, and a key that is there
// twice in different cases counts if either says true. A value that is not
// true, or tlsSettings that are not an object, are not Check's to refuse:
// xray cannot read them either.
func insecureTLS(streamSettings json.RawMessage) bool {
	var ss any
	if len(streamSettings) == 0 || json.Unmarshal(streamSettings, &ss) != nil {
		return false
	}
	return holdsInsecureTLS(ss)
}

// holdsInsecureTLS reports whether v, decoded JSON, has a tlsSettings object
// with allowInsecure true in it, at any depth.
func holdsInsecureTLS(v any) bool {
	switch v := v.(type) {
	case map[string]any:
		for key, child := range v {
			if tls, ok := child.(map[string]any); ok && strings.EqualFold(key, "tlsSettings") {
				for k, insecure := range tls {
					if strings.EqualFold(k, "allowInsecure") && insecure == true {
						return true
					}
				}
			}
			if holdsInsecureTLS(child) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if holdsInsecureTLS(child) {
				return true
			}
		}
	}
	return false
}

// plainStream reports whether the stream has no security: streamSettings is
// absent or has a security that is absent, empty or "none". Any other value is
// tls, reality or an error of xray's own. streamSettings that cannot be read
// are not plain, for they are not Check's to refuse.
func plainStream(streamSettings json.RawMessage) bool {
	var ss struct {
		Security string `json:"security"`
	}
	if len(streamSettings) > 0 && json.Unmarshal(streamSettings, &ss) != nil {
		return false
	}
	security := strings.ToLower(ss.Security)
	return security == "" || security == "none"
}

func checkVLESS(settings, streamSettings json.RawMessage) error {
	var s struct {
		Address    *string `json:"address"`
		Encryption string  `json:"encryption"`
		Vnext      []struct {
			Address *string `json:"address"`
			Users   []struct {
				Encryption string `json:"encryption"`
			} `json:"users"`
		} `json:"vnext"`
	}
	if json.Unmarshal(settings, &s) != nil {
		return nil
	}
	var address, encryption string
	switch {
	case s.Address != nil:
		address, encryption = *s.Address, s.Encryption
	case len(s.Vnext) > 0 && s.Vnext[0].Address != nil && len(s.Vnext[0].Users) > 0:
		address, encryption = *s.Vnext[0].Address, s.Vnext[0].Users[0].Encryption
	default:
		return nil
	}
	// xray compares the encryption as it is: "NONE" is another word, which it
	// refuses for another reason.
	if encryption != "" && encryption != "none" {
		return nil
	}
	if plainStream(streamSettings) && !PrivateAddress(address) {
		return refuse("xray-core refuses VLESS without TLS or encryption to a public address")
	}
	return nil
}

func checkTrojan(settings, streamSettings json.RawMessage) error {
	var s struct {
		Address *string `json:"address"`
		Servers []struct {
			Address *string `json:"address"`
		} `json:"servers"`
	}
	if json.Unmarshal(settings, &s) != nil {
		return nil
	}
	var address string
	switch {
	case s.Address != nil:
		address = *s.Address
	case len(s.Servers) > 0 && s.Servers[0].Address != nil:
		address = *s.Servers[0].Address
	default:
		return nil
	}
	if plainStream(streamSettings) && !PrivateAddress(address) {
		return refuse("xray-core refuses Trojan without TLS to a public address")
	}
	return nil
}

// ss2022Keys is the length of the key of each Shadowsocks 2022 cipher.
var ss2022Keys = map[string]int{
	"2022-blake3-aes-128-gcm":       16,
	"2022-blake3-aes-256-gcm":       32,
	"2022-blake3-chacha20-poly1305": 32,
}

func checkShadowsocks(settings json.RawMessage) error {
	var s struct {
		Address  *string `json:"address"`
		Method   string  `json:"method"`
		Password string  `json:"password"`
		Servers  []struct {
			Method   string `json:"method"`
			Password string `json:"password"`
		} `json:"servers"`
	}
	if json.Unmarshal(settings, &s) != nil {
		return nil
	}
	var method, password string
	switch {
	case s.Address != nil:
		method, password = s.Method, s.Password
	case len(s.Servers) > 0:
		method, password = s.Servers[0].Method, s.Servers[0].Password
	default:
		return nil
	}
	method = strings.ToLower(method)
	if method == "none" || method == "plain" {
		return refuse("xray-core refuses the Shadowsocks methods none and plain")
	}
	size, is2022 := ss2022Keys[method]
	if !is2022 {
		return nil
	}
	// xray 26.10.21 also takes a part that is not base64 as the key itself when
	// it is exactly as long as the key, but older releases refuse that, so only
	// base64 is let through: a server that must work on every release needs it.
	keys := strings.Split(password, ":")
	for _, k := range keys {
		if b, err := base64.StdEncoding.DecodeString(k); err != nil || len(b) != size {
			return refuse("xray-core refuses a Shadowsocks 2022 password that is not made of base64 keys " +
				"of the cipher's length: 16 bytes for aes-128-gcm, 32 for aes-256-gcm and chacha20-poly1305, joined by ':'")
		}
	}
	if len(keys) > 1 && method == "2022-blake3-chacha20-poly1305" {
		return refuse("xray-core refuses a Shadowsocks 2022 chacha20-poly1305 password with more than one key")
	}
	return nil
}
