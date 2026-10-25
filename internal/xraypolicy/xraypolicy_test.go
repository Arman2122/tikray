package xraypolicy

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The addresses and the cases below were also run through xray 26.10.21:
// `xray run -test` refused the VLESS outbound to each address that
// PrivateAddress reports false, and accepted the others.
func TestPrivateAddress(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		// The private IP list.
		{"10.1.2.3", true},
		{"203.0.113.10", true},
		{"198.18.5.5", true},
		{"198.19.255.255", true},
		{"100.64.0.1", true},
		{"224.0.0.1", true},
		{"255.255.255.255", true},
		{"0.0.0.0", true},
		{"fd00::1", true},
		{"fc00::1", true},
		{"::", true},
		{"::1", true},
		{"ff02::1", true},
		{"[fd00::1]", true},
		{"::ffff:10.1.2.3", true},
		// Outside it.
		{"1.2.3.4", false},
		{"8.8.8.8", false},
		{"172.32.0.1", false},
		{"2001:db8::1", false},
		{"::2", false},
		{"::ffff:8.8.8.8", false},
		// A zone makes it a name, which is not in the list.
		{"fe80::1%eth0", false},

		// The private domain list: a suffix, the name itself or a subdomain.
		{"router.lan", true},
		{"printer.local", true},
		{"foo.home.arpa", true},
		{"home.arpa", true},
		{"localhost", true},
		{"foo.test", true},
		{"a.example", true},
		{"foo.internal", true},
		{"x.invalid", true},
		{"foo.localdomain", true},
		{"a.b.c.lan", true},
		// Case and the trailing dot do not matter.
		{"X.LAN.", true},
		{"localhost.", true},
		// A dotless name is a single label.
		{"nas", true},
		{"NAS", true},
		{"a1-b", true},
		{"xn--nas", true},
		{strings.Repeat("n", 63), true},
		// Not private.
		{"example.com", false},
		{"cdn.example.net", false},
		// The suffix is a label, not a substring.
		{"lan.example.com", false},
		{"notlan", true}, // dotless
		{"not.lan.net", false},
		{"arpa", true}, // dotless
		{"foo.arpa", false},
		{"1a", false},
		{"nas_1", false},
		{"-nas", false},
		{strings.Repeat("n", 64), false},
		{"", false},
	}
	for _, tc := range tests {
		if got := PrivateAddress(tc.host); got != tc.want {
			t.Errorf("PrivateAddress(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

const (
	testID       = "b831381d-6324-4d53-ad4f-8cda48b30811"
	testPassword = "hunter2-trojan-pass"
)

// key is the standard base64 of n bytes, starting at seed so that the keys of
// one test differ.
func key(n int, seed byte) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// vlessNested is a VLESS outbound in the vnext form, with the stream JSON
// (either "" or a `"streamSettings":{...}` member) after the settings.
func vlessNested(addr, encryption, stream string) string {
	if stream != "" {
		stream = "," + stream
	}
	return fmt.Sprintf(`{"protocol":"vless","settings":{"vnext":[{"address":%q,"port":443,"users":[{"id":%q,"encryption":%q}]}]}%s}`,
		addr, testID, encryption, stream)
}

// vlessFlat is a VLESS outbound in the flat form xray 26 also reads.
func vlessFlat(addr, encryption, stream string) string {
	if stream != "" {
		stream = "," + stream
	}
	return fmt.Sprintf(`{"protocol":"vless","settings":{"address":%q,"port":443,"id":%q,"encryption":%q}%s}`,
		addr, testID, encryption, stream)
}

func trojanNested(addr, stream string) string {
	if stream != "" {
		stream = "," + stream
	}
	return fmt.Sprintf(`{"protocol":"trojan","settings":{"servers":[{"address":%q,"port":443,"password":%q}]}%s}`,
		addr, testPassword, stream)
}

func trojanFlat(addr, stream string) string {
	if stream != "" {
		stream = "," + stream
	}
	return fmt.Sprintf(`{"protocol":"trojan","settings":{"address":%q,"port":443,"password":%q}%s}`,
		addr, testPassword, stream)
}

func ssNested(method, password string) string {
	return fmt.Sprintf(`{"protocol":"shadowsocks","settings":{"servers":[{"address":"1.2.3.4","port":8388,"method":%q,"password":%q}]}}`,
		method, password)
}

func ssFlat(method, password string) string {
	return fmt.Sprintf(`{"protocol":"shadowsocks","settings":{"address":"1.2.3.4","port":8388,"method":%q,"password":%q}}`,
		method, password)
}

// vmessWith is a VMess outbound to a public address, with the stream JSON (a
// `"streamSettings":{...}` member) after the settings.
func vmessWith(stream string) string {
	return fmt.Sprintf(`{"protocol":"vmess","settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":%q,"security":"auto"}]}]},%s}`,
		testID, stream)
}

// xhttpDownload is the stream JSON (a `"streamSettings":{...}` member) of
// xhttp over TLS whose download leg goes to another server over TLS with
// allowInsecure set to insecure. The leg is in xhttpSettings.<in>, or in
// xhttpSettings itself when in is "". The upload leg checks its certificate.
func xhttpDownload(in string, insecure bool) string {
	leg := fmt.Sprintf(`"downloadSettings":{"address":"5.6.7.8","port":443,"network":"xhttp","security":"tls",`+
		`"tlsSettings":{"serverName":"dl.example.com","allowInsecure":%t},"xhttpSettings":{"path":"/down"}}`, insecure)
	if in != "" {
		leg = fmt.Sprintf(`%q:{%s}`, in, leg)
	}
	return `"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"example.com"},` +
		`"xhttpSettings":{"path":"/up",` + leg + `}}`
}

const (
	tlsInsecure = `"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","allowInsecure":true}}`
	tlsSecure   = `"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","allowInsecure":false}}`

	tls     = `"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}`
	reality = `"streamSettings":{"network":"tcp","security":"reality"}`
	secNone = `"streamSettings":{"network":"tcp","security":"none"}`
	noSec   = `"streamSettings":{"network":"ws"}`

	aes128 = "2022-blake3-aes-128-gcm"
	aes256 = "2022-blake3-aes-256-gcm"
	chacha = "2022-blake3-chacha20-poly1305"

	// mlkem is a VLESS post-quantum encryption string, not a working one: only
	// that it is neither empty nor none matters.
	mlkem = "mlkem768x25519plus.native.0rtt.dGhpcyBpcyBub3QgYSByZWFsIGtleSBhdCBhbGw"
)

func TestCheck(t *testing.T) {
	// urlSafe is the base64 of 16 bytes that uses '-' and '_': the URL alphabet
	// that xray does not read.
	urlSafe := strings.NewReplacer("+", "-", "/", "_").Replace(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\xfb\xff", 8))))
	k16, k16b, k32, k32b := key(16, 1), key(16, 50), key(32, 1), key(32, 90)

	tests := []struct {
		name     string
		outbound string
		// reason is text in the refusal's reason; "" means Check must return nil.
		reason string
		// secrets are parts of the outbound that no error may repeat. The
		// test adds the VLESS id and the Trojan password.
		secrets []string
	}{
		// VLESS.
		{name: "vless none/none to a public IP", outbound: vlessNested("1.2.3.4", "none", ""), reason: "VLESS"},
		{name: "vless none/none with security none to a public IP", outbound: vlessNested("1.2.3.4", "none", secNone), reason: "VLESS"},
		{name: "vless security none in capitals", outbound: vlessNested("1.2.3.4", "none", `"streamSettings":{"security":"NONE"}`), reason: "VLESS"},
		{name: "vless with a transport but no security", outbound: vlessNested("1.2.3.4", "none", noSec), reason: "VLESS"},
		{name: "vless none/none to a private IP", outbound: vlessNested("203.0.113.10", "none", "")},
		{name: "vless none/none to a domain", outbound: vlessNested("example.com", "none", ""), reason: "VLESS"},
		{name: "vless none/none to a private domain", outbound: vlessNested("foo.test", "none", "")},
		{name: "vless none/none to a dotless name", outbound: vlessNested("nas", "none", "")},
		{name: "vless none/none to a private IPv6", outbound: vlessNested("fd00::1", "none", "")},
		{name: "vless empty encryption to a public IP", outbound: vlessNested("1.2.3.4", "", ""), reason: "VLESS"},
		{name: "vless tls to a public IP", outbound: vlessNested("1.2.3.4", "none", tls)},
		{name: "vless reality to a public IP", outbound: vlessNested("1.2.3.4", "none", reality)},
		{name: "vless tls to a domain", outbound: vlessNested("example.com", "none", tls)},
		{name: "vless post-quantum encryption to a public IP", outbound: vlessNested("1.2.3.4", mlkem, "")},
		{name: "vless flat none/none to a public IP", outbound: vlessFlat("1.2.3.4", "none", ""), reason: "VLESS"},
		{name: "vless flat none/none to a domain", outbound: vlessFlat("example.com", "none", noSec), reason: "VLESS"},
		{name: "vless flat none/none to a private IP", outbound: vlessFlat("203.0.113.10", "none", "")},
		{name: "vless flat tls to a public IP", outbound: vlessFlat("1.2.3.4", "none", tls)},
		{name: "vless flat post-quantum encryption", outbound: vlessFlat("1.2.3.4", mlkem, "")},
		{
			// xray builds the outbound from the flat settings and ignores vnext.
			name:     "vless flat address wins over vnext",
			outbound: `{"protocol":"vless","settings":{"address":"203.0.113.10","port":443,"id":"` + testID + `","encryption":"none","vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"` + testID + `","encryption":"none"}]}]}}`,
		},
		{
			// xray reads keys without regard to case, as store does.
			name:     "vless with keys in other cases",
			outbound: `{"Protocol":"VLESS","Settings":{"Vnext":[{"Address":"1.2.3.4","Port":443,"Users":[{"ID":"` + testID + `","Encryption":"none"}]}]}}`,
			reason:   "VLESS",
		},
		{
			name:     "vless tls with keys in other cases",
			outbound: `{"Protocol":"VLESS","Settings":{"Vnext":[{"Address":"1.2.3.4","Port":443,"Users":[{"ID":"` + testID + `","Encryption":"none"}]}]},"StreamSettings":{"Security":"TLS"}}`,
		},
		{
			// Only "none" and "" mean no encryption, and xray compares them
			// case by case: another word is an error of its own in xray.
			name:     "vless encryption in capitals is another word",
			outbound: vlessNested("1.2.3.4", "NONE", ""),
		},

		// Trojan.
		{name: "trojan without security to a public IP", outbound: trojanNested("1.2.3.4", ""), reason: "Trojan"},
		{name: "trojan with security none to a public IP", outbound: trojanNested("1.2.3.4", secNone), reason: "Trojan"},
		{name: "trojan without security to a domain", outbound: trojanNested("example.com", noSec), reason: "Trojan"},
		{name: "trojan without security to a private IP", outbound: trojanNested("10.1.2.3", "")},
		{name: "trojan without security to a private domain", outbound: trojanNested("router.lan", secNone)},
		{name: "trojan tls to a public IP", outbound: trojanNested("1.2.3.4", tls)},
		{name: "trojan reality to a public IP", outbound: trojanNested("1.2.3.4", reality)},
		{name: "trojan flat without security to a public IP", outbound: trojanFlat("1.2.3.4", ""), reason: "Trojan"},
		{name: "trojan flat tls to a public IP", outbound: trojanFlat("1.2.3.4", tls)},
		{name: "trojan flat without security to a private IP", outbound: trojanFlat("10.1.2.3", "")},

		// allowInsecure, for every protocol: xray ≥26.3.27 refuses it once past
		// 2026-06-01, and 26.1.18 skips the certificate check with it.
		{name: "vless tls with allowInsecure to a public IP", outbound: vlessNested("1.2.3.4", "none", tlsInsecure), reason: "pinnedPeerCertSha256"},
		{name: "vless tls with allowInsecure to a private IP", outbound: vlessNested("203.0.113.10", "none", tlsInsecure), reason: "allowInsecure"},
		{name: "vless flat tls with allowInsecure", outbound: vlessFlat("1.2.3.4", "none", tlsInsecure), reason: "allowInsecure"},
		{name: "trojan tls with allowInsecure", outbound: trojanNested("1.2.3.4", tlsInsecure), reason: "allowInsecure"},
		{name: "vmess tls with allowInsecure", outbound: vmessWith(tlsInsecure), reason: "allowInsecure"},
		{name: "shadowsocks over tls with allowInsecure", outbound: `{"protocol":"shadowsocks","settings":{"servers":[{"address":"1.2.3.4","port":443,"method":"aes-256-gcm","password":"` + testPassword + `"}]},` + tlsInsecure + `}`, reason: "allowInsecure"},
		{name: "unknown protocol with allowInsecure", outbound: `{"protocol":"wireguard","settings":{},` + tlsInsecure + `}`, reason: "allowInsecure"},
		{name: "allowInsecure beside a pinned certificate", outbound: vlessNested("1.2.3.4", "none", `"streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":true,"pinnedPeerCertSha256":"`+strings.Repeat("ab", 32)+`"}}`), reason: "allowInsecure"},
		{
			// xray reads tlsSettings only with security tls, but the key asks
			// that the server's certificate not be checked, which tikray never
			// lets a server ask.
			name:     "allowInsecure under another security",
			outbound: vlessNested("1.2.3.4", "none", `"streamSettings":{"security":"reality","tlsSettings":{"allowInsecure":true}}`),
			reason:   "allowInsecure",
		},
		{name: "allowInsecure with keys in other cases", outbound: vlessNested("1.2.3.4", "none", `"StreamSettings":{"Security":"TLS","TLSSettings":{"AllowInsecure":true}}`), reason: "allowInsecure"},
		{name: "vless tls with allowInsecure false", outbound: vlessNested("1.2.3.4", "none", tlsSecure)},
		{name: "trojan tls with allowInsecure false", outbound: trojanNested("1.2.3.4", tlsSecure)},
		{name: "vmess tls with allowInsecure false", outbound: vmessWith(tlsSecure)},
		{name: "vmess tls without allowInsecure", outbound: vmessWith(tls)},
		{name: "allowInsecure null", outbound: vlessNested("1.2.3.4", "none", `"streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":null}}`)},
		// Not a bool: xray's -test refuses the config, as it does any
		// tlsSettings it cannot read.
		{name: "allowInsecure is a string", outbound: vlessNested("1.2.3.4", "none", `"streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":"true"}}`)},
		{name: "tlsSettings is a string", outbound: vlessNested("1.2.3.4", "none", `"streamSettings":{"security":"tls","tlsSettings":"x"}`)},
		// tlsSettings deeper in the stream, such as those of xhttp's download
		// leg, which xray builds as a stream of its own: 26.10.21 refuses
		// allowInsecure there too, and 26.1.18 skips the certificate check of
		// that leg with it.
		{name: "xhttp download leg with allowInsecure", outbound: vlessNested("1.2.3.4", "none", xhttpDownload("extra", true)), reason: "allowInsecure"},
		{name: "xhttp download leg with allowInsecure false", outbound: vlessNested("1.2.3.4", "none", xhttpDownload("extra", false))},
		{name: "xhttp download leg outside extra with allowInsecure", outbound: vlessNested("1.2.3.4", "none", xhttpDownload("", true)), reason: "allowInsecure"},
		{name: "xhttp download leg outside extra with allowInsecure false", outbound: vlessNested("1.2.3.4", "none", xhttpDownload("", false))},
		{
			name:     "xhttp download leg with allowInsecure, keys in other cases",
			outbound: vlessNested("1.2.3.4", "none", `"streamSettings":{"security":"tls","XHTTPSettings":{"Extra":{"DownloadSettings":{"Security":"tls","TlsSettings":{"ALLOWINSECURE":true}}}}}`),
			reason:   "allowInsecure",
		},
		{name: "allowInsecure in a tlsSettings in a list", outbound: vlessNested("1.2.3.4", "none", `"streamSettings":{"security":"tls","x":[1,{"tlsSettings":{"allowInsecure":true}}]}`), reason: "allowInsecure"},
		{
			// Two keys that xray reads as one: refuse if either asks.
			name:     "allowInsecure twice, the second true",
			outbound: vlessNested("1.2.3.4", "none", `"streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":false,"AllowInsecure":true}}`),
			reason:   "allowInsecure",
		},
		{
			name:     "tlsSettings twice, the second insecure",
			outbound: vlessNested("1.2.3.4", "none", `"streamSettings":{"security":"tls","tlsSettings":{},"TLSSettings":{"allowInsecure":true}}`),
			reason:   "allowInsecure",
		},
		// xray reads allowInsecure in tlsSettings alone, and tlsSettings in
		// streamSettings alone.
		{name: "allowInsecure outside tlsSettings", outbound: vlessNested("1.2.3.4", "none", `"streamSettings":{"security":"tls","allowInsecure":true,"realitySettings":{"allowInsecure":true}}`)},
		{name: "tlsSettings outside streamSettings", outbound: `{"protocol":"vless","settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"` + testID + `","encryption":"none","tlsSettings":{"allowInsecure":true}}]}]},` + tls + `}`},
		{name: "xhttp download leg with allowInsecure a string", outbound: vlessNested("1.2.3.4", "none", `"streamSettings":{"security":"tls","xhttpSettings":{"downloadSettings":{"tlsSettings":{"allowInsecure":"true"}}}}`)},

		// Shadowsocks methods.
		{name: "ss method none", outbound: ssNested("none", "pw-for-none-method"), reason: "Shadowsocks", secrets: []string{"pw-for-none-method"}},
		{name: "ss method plain", outbound: ssNested("plain", "pw-for-plain-method"), reason: "Shadowsocks", secrets: []string{"pw-for-plain-method"}},
		{name: "ss method none in capitals", outbound: ssNested("NONE", "pw-for-none-method"), reason: "Shadowsocks", secrets: []string{"pw-for-none-method"}},
		{name: "ss flat method none", outbound: ssFlat("none", "pw-for-none-method"), reason: "Shadowsocks", secrets: []string{"pw-for-none-method"}},
		{name: "ss aes-256-gcm", outbound: ssNested("aes-256-gcm", "any password at all")},
		{name: "ss flat chacha20-poly1305", outbound: ssFlat("chacha20-poly1305", "any password at all")},

		// Shadowsocks 2022 keys.
		{name: "ss2022 aes-128 with a 16-byte key", outbound: ssNested(aes128, k16)},
		{name: "ss2022 aes-128 with a 15-byte key", outbound: ssNested(aes128, key(15, 1)), reason: "2022", secrets: []string{key(15, 1)}},
		{name: "ss2022 aes-128 with a 17-byte key", outbound: ssNested(aes128, key(17, 1)), reason: "2022", secrets: []string{key(17, 1)}},
		{name: "ss2022 aes-128 with a 32-byte key", outbound: ssNested(aes128, k32), reason: "2022", secrets: []string{k32}},
		{name: "ss2022 aes-256 with a 32-byte key", outbound: ssNested(aes256, k32)},
		{name: "ss2022 aes-256 with a 16-byte key", outbound: ssNested(aes256, k16), reason: "2022", secrets: []string{k16}},
		{name: "ss2022 chacha with a 32-byte key", outbound: ssNested(chacha, k32)},
		{name: "ss2022 chacha with a 16-byte key", outbound: ssNested(chacha, k16), reason: "2022", secrets: []string{k16}},
		{name: "ss2022 aes-128 server and user keys", outbound: ssNested(aes128, k16+":"+k16b)},
		{name: "ss2022 aes-256 three keys", outbound: ssNested(aes256, k32+":"+k32b+":"+k32)},
		{name: "ss2022 aes-128 pair with a short second key", outbound: ssNested(aes128, k16+":"+key(15, 9)), reason: "2022", secrets: []string{k16, key(15, 9)}},
		{name: "ss2022 aes-128 pair with a non-base64 second key", outbound: ssNested(aes128, k16+":not base64!"), reason: "2022", secrets: []string{k16}},
		{name: "ss2022 aes-128 with an empty part", outbound: ssNested(aes128, k16+":"), reason: "2022", secrets: []string{k16}},
		{name: "ss2022 aes-128 with an empty password", outbound: ssNested(aes128, ""), reason: "2022"},
		{name: "ss2022 non-base64 key", outbound: ssNested(aes128, "this is not base64!"), reason: "2022", secrets: []string{"this is not base64!"}},
		{name: "ss2022 url-safe base64 key", outbound: ssNested(aes128, urlSafe), reason: "2022", secrets: []string{urlSafe}},
		{name: "ss2022 key without its padding", outbound: ssNested(aes128, strings.TrimRight(k16, "=")), reason: "2022", secrets: []string{strings.TrimRight(k16, "=")}},
		{
			// xray 26.10.21 also reads a key that is not base64 but is 16 bytes
			// long as it is. Older releases refuse it, so a server that must
			// work on every release needs the base64 key.
			name:     "ss2022 raw 16-byte key",
			outbound: ssNested(aes128, "pass-word-123456"),
			reason:   "2022",
			secrets:  []string{"pass-word-123456"},
		},
		{
			// Every xray release refuses more than one key for this cipher.
			name:     "ss2022 chacha with two keys",
			outbound: ssNested(chacha, k32+":"+k32b),
			reason:   "chacha20-poly1305",
			secrets:  []string{k32, k32b},
		},
		{name: "ss2022 method in capitals", outbound: ssNested("2022-BLAKE3-AES-128-GCM", k16)},
		{name: "ss2022 method in capitals with a bad key", outbound: ssNested("2022-BLAKE3-AES-128-GCM", key(15, 1)), reason: "2022", secrets: []string{key(15, 1)}},
		{name: "ss2022 flat with a bad key", outbound: ssFlat(aes128, key(15, 1)), reason: "2022", secrets: []string{key(15, 1)}},
		{name: "ss2022 flat with a good key", outbound: ssFlat(aes128, k16)},

		// Protocols with no rule.
		{name: "vmess", outbound: `{"protocol":"vmess","settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"` + testID + `"}]}]}}`},
		{name: "freedom", outbound: `{"protocol":"freedom"}`},
		{name: "unknown protocol", outbound: `{"protocol":"wireguard","settings":{}}`},

		// A shape the rules cannot read is not this package's to refuse.
		{name: "empty input", outbound: ``},
		{name: "not JSON", outbound: `{"protocol":`},
		{name: "null", outbound: `null`},
		{name: "number", outbound: `42`},
		{name: "string", outbound: `"vless"`},
		{name: "array", outbound: `[{"protocol":"vless"}]`},
		{name: "empty object", outbound: `{}`},
		{name: "protocol is not a string", outbound: `{"protocol":7,"settings":{}}`},
		{name: "vless without settings", outbound: `{"protocol":"vless"}`},
		{name: "vless with null settings", outbound: `{"protocol":"vless","settings":null}`},
		{name: "vless with string settings", outbound: `{"protocol":"vless","settings":"x"}`},
		{name: "vless with empty settings", outbound: `{"protocol":"vless","settings":{}}`},
		{name: "vless vnext is not an array", outbound: `{"protocol":"vless","settings":{"vnext":"1.2.3.4"}}`},
		{name: "vless vnext is empty", outbound: `{"protocol":"vless","settings":{"vnext":[]}}`},
		{name: "vless vnext entry has no address", outbound: `{"protocol":"vless","settings":{"vnext":[{"port":443,"users":[{"encryption":"none"}]}]}}`},
		{name: "vless vnext entry has no users", outbound: `{"protocol":"vless","settings":{"vnext":[{"address":"1.2.3.4","port":443}]}}`},
		{name: "vless vnext address is a number", outbound: `{"protocol":"vless","settings":{"vnext":[{"address":4,"users":[{"encryption":"none"}]}]}}`},
		{name: "vless streamSettings is a string", outbound: `{"protocol":"vless","settings":{"address":"1.2.3.4","encryption":"none"},"streamSettings":"tls"}`},
		{name: "vless security is a number", outbound: `{"protocol":"vless","settings":{"address":"1.2.3.4","encryption":"none"},"streamSettings":{"security":1}}`},
		{name: "trojan without settings", outbound: `{"protocol":"trojan"}`},
		{name: "trojan servers is an object", outbound: `{"protocol":"trojan","settings":{"servers":{"address":"1.2.3.4"}}}`},
		{name: "trojan servers is empty", outbound: `{"protocol":"trojan","settings":{"servers":[]}}`},
		{name: "trojan server has no address", outbound: `{"protocol":"trojan","settings":{"servers":[{"port":443}]}}`},
		{name: "shadowsocks without settings", outbound: `{"protocol":"shadowsocks"}`},
		{name: "shadowsocks servers is a string", outbound: `{"protocol":"shadowsocks","settings":{"servers":"x"}}`},
		{name: "shadowsocks servers is empty", outbound: `{"protocol":"shadowsocks","settings":{"servers":[]}}`},
		{name: "shadowsocks method is a number", outbound: `{"protocol":"shadowsocks","settings":{"servers":[{"method":1}]}}`},
		{name: "shadowsocks password is a number", outbound: `{"protocol":"shadowsocks","settings":{"servers":[{"method":"` + aes128 + `","password":1}]}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Check([]byte(tc.outbound))
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("Check = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Check = nil, want a refusal naming %q", tc.reason)
			}
			msg := err.Error()
			if !errors.Is(err, ErrRefused) {
				t.Errorf("error %q does not wrap ErrRefused", msg)
			}
			if !strings.HasPrefix(msg, "xraypolicy: ") {
				t.Errorf("error %q lacks the \"xraypolicy: \" prefix", msg)
			}
			if !strings.Contains(msg, tc.reason) {
				t.Errorf("error %q does not name %q", msg, tc.reason)
			}
			var r *Refusal
			if !errors.As(err, &r) {
				t.Fatalf("error %q is not a *Refusal", msg)
			}
			if r.Reason == "" || strings.Contains(r.Reason, "xraypolicy") || msg != "xraypolicy: "+r.Reason {
				t.Errorf("Reason = %q, want the message without its prefix (%q)", r.Reason, msg)
			}
			for _, secret := range append([]string{testID, testPassword}, tc.secrets...) {
				if strings.Contains(msg, secret) {
					t.Errorf("error %q repeats the secret %q", msg, secret)
				}
			}
		})
	}
}
