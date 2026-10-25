package sharelink

import (
	"encoding/base64"
	"strings"
	"testing"
)

// ssOut is the expected Shadowsocks outbound for a link that asks for plain
// tcp, which has no streamSettings. The password is JSON text, already escaped.
func ssOut(addr, port, method, password string) string {
	return ssServers(addr, port, method, password) + `}`
}

// ssOutStream is the expected Shadowsocks outbound for a link that asks for
// more than plain tcp, with the given streamSettings JSON.
func ssOutStream(addr, port, method, password, stream string) string {
	return ssServers(addr, port, method, password) + `,"streamSettings":` + stream + `}`
}

// ssServers is the start of a Shadowsocks outbound, up to and including its
// settings.
func ssServers(addr, port, method, password string) string {
	return `{"protocol":"shadowsocks","settings":{"servers":[{"address":"` + addr + `","port":` + port + `,"method":"` + method + `","password":"` + password + `"}]}`
}

// ssBase is a SIP002 link for the password "pass", with no query.
const ssBase = "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388"

// ssUser is the base64url, unpadded form of method:password that SIP002 uses.
func ssUser(userinfo string) string { return base64.RawURLEncoding.EncodeToString([]byte(userinfo)) }

// ssLegacy is a legacy link: the base64 of method:password@host:port, padded.
func ssLegacy(text string) string {
	return "ss://" + base64.StdEncoding.EncodeToString([]byte(text))
}

const (
	// ssLegacyAlphabet is the legacy body whose standard base64 has a + and a /
	// and two padding characters, so that the url alphabet and the missing
	// padding show.
	ssLegacyAlphabetText = "aes-256-gcm:pa???>?@h.example:8388"
	// ssUserAlphabetText is the userinfo whose url base64 has a - and a _.
	ssUserAlphabetText = "aes-256-gcm:?????>?"
)

const (
	// ss2022Key16 and ss2022Key32 are the base64 of 16 and of 32 bytes, the key
	// lengths of the 2022 ciphers, and the Link forms are their percent-encoded
	// userinfo.
	ss2022Key16     = "AAECAwQFBgcICQoLDA0ODw=="
	ss2022Key16Link = "AAECAwQFBgcICQoLDA0ODw%3D%3D"
	ss2022Key32     = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	ss2022Key32Link = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8%3D"
)

// ssCases are the Shadowsocks links Parse must read or refuse. The fuzz test
// seeds from them too.
var ssCases = []parseCase{
	// SIP002
	{
		name:     "sip002, unpadded",
		link:     "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#a",
		wantName: "a",
		wantJSON: ssOut("1.2.3.4", "8388", "aes-256-gcm", "pass"),
	},
	{
		name:     "sip002, padded",
		link:     "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#a",
		wantName: "a",
		wantJSON: ssOut("1.2.3.4", "8388", "aes-256-gcm", "pass"),
	},
	{
		name:     "sip002 with a percent-encoded userinfo, as the 2022 ciphers use",
		link:     "ss://2022-blake3-aes-128-gcm:YWJjZGVmZ2hpamtsbW5vcA%3D%3D@h.example:443#b",
		wantName: "b",
		wantJSON: ssOut("h.example", "443", "2022-blake3-aes-128-gcm", "YWJjZGVmZ2hpamtsbW5vcA=="),
	},
	{
		name:     "sip002 with a base64 userinfo whose padding is percent-encoded",
		link:     "ss://YWVzLTI1Ni1nY206cGFzcw%3D%3D@1.2.3.4:8388",
		wantName: "1.2.3.4:8388",
		wantJSON: ssOut("1.2.3.4", "8388", "aes-256-gcm", "pass"),
	},
	{
		name:     "sip002 userinfo in the url alphabet",
		link:     "ss://" + ssUser(ssUserAlphabetText) + "@h.example:8388",
		wantName: "h.example:8388",
		wantJSON: ssOut("h.example", "8388", "aes-256-gcm", "?????>?"),
	},
	{
		name:     "sip002 with a slash before the name",
		link:     "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388/#a",
		wantName: "a",
		wantJSON: ssOut("1.2.3.4", "8388", "aes-256-gcm", "pass"),
	},
	{
		name:     "sip002 with a slash and other parameters",
		link:     "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388/?udp-over-tcp=1&foo=%zz#a",
		wantName: "a",
		wantJSON: ssOut("1.2.3.4", "8388", "aes-256-gcm", "pass"),
	},
	{
		name:     "sip002 with a name that is percent-encoded",
		link:     "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#lab%20%F0%9F%9A%80",
		wantName: "lab 🚀",
		wantJSON: ssOut("1.2.3.4", "8388", "aes-256-gcm", "pass"),
	},
	{
		name:     "sip002 with an empty name",
		link:     "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#",
		wantName: "1.2.3.4:8388",
		wantJSON: ssOut("1.2.3.4", "8388", "aes-256-gcm", "pass"),
	},
	{
		name:     "sip002 with an ipv6 address",
		link:     "ss://YWVzLTI1Ni1nY206cGFzcw@[2001:db8::1]:8388",
		wantName: "[2001:db8::1]:8388",
		wantJSON: ssOut("2001:db8::1", "8388", "aes-256-gcm", "pass"),
	},
	{
		name:     "a password that has a colon, in base64",
		link:     "ss://" + ssUser("aes-256-gcm:pa:ss") + "@h.example:443",
		wantName: "h.example:443",
		wantJSON: ssOut("h.example", "443", "aes-256-gcm", "pa:ss"),
	},
	{
		name:     "a password that has an at sign, in percent-encoded text",
		link:     "ss://aes-256-gcm:p%40ss%3Aw@h.example:443",
		wantName: "h.example:443",
		wantJSON: ssOut("h.example", "443", "aes-256-gcm", "p@ss:w"),
	},
	{
		name:     "a password that has a colon, in plain text",
		link:     "ss://aes-256-gcm:pa:ss@h.example:443",
		wantName: "h.example:443",
		wantJSON: ssOut("h.example", "443", "aes-256-gcm", "pa:ss"),
	},
	{
		name:     "a password that is not ascii, and has a quote",
		link:     "ss://" + ssUser(`aes-256-gcm:pässwörd"1`) + "@h.example:443",
		wantName: "h.example:443",
		wantJSON: ssOut("h.example", "443", "aes-256-gcm", `pässwörd\"1`),
	},
	{
		name:     "unread parameters with bad escapes are ignored",
		link:     "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?foo=%zz&bar&remark=a;b&%zz=1",
		wantName: "1.2.3.4:8388",
		wantJSON: ssOut("1.2.3.4", "8388", "aes-256-gcm", "pass"),
	},
	{
		name:     "scheme in upper case",
		link:     "SS://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388",
		wantName: "1.2.3.4:8388",
		wantJSON: ssOut("1.2.3.4", "8388", "aes-256-gcm", "pass"),
	},

	// transport and security, the same parameters as a VLESS link
	{
		name:     "websocket over tls: the host is the server name",
		link:     ssBase + "?type=ws&security=tls&path=%2Fws&host=cdn.example.com#a",
		wantName: "a",
		wantJSON: ssOutStream("1.2.3.4", "8388", "aes-256-gcm", "pass",
			`{"network":"ws","security":"tls","tlsSettings":{"serverName":"cdn.example.com"},"wsSettings":{"host":"cdn.example.com","path":"/ws"}}`),
	},
	{
		name:     "websocket over tls with an sni, a fingerprint and alpn, after a slash",
		link:     "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388/?type=ws&security=tls&sni=front.example.com&host=cdn.example.com&fp=chrome&alpn=h2,http/1.1",
		wantName: "1.2.3.4:8388",
		wantJSON: ssOutStream("1.2.3.4", "8388", "aes-256-gcm", "pass",
			`{"network":"ws","security":"tls","tlsSettings":{"alpn":["h2","http/1.1"],"fingerprint":"chrome","serverName":"front.example.com"},"wsSettings":{"host":"cdn.example.com","path":"/"}}`),
	},
	{
		name:     "grpc",
		link:     ssBase + "?type=grpc&serviceName=x",
		wantName: "1.2.3.4:8388",
		wantJSON: ssOutStream("1.2.3.4", "8388", "aes-256-gcm", "pass", `{"network":"grpc","grpcSettings":{"multiMode":false,"serviceName":"x"}}`),
	},
	{
		name:     "tls over tcp",
		link:     ssBase + "?security=tls&sni=h.example",
		wantName: "1.2.3.4:8388",
		wantJSON: ssOutStream("1.2.3.4", "8388", "aes-256-gcm", "pass", `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"h.example"}}`),
	},
	{
		name:     "reality",
		link:     ssBase + "?security=reality&pbk=" + vlessPBK + "&sni=www.example.com",
		wantName: "1.2.3.4:8388",
		wantJSON: ssOutStream("1.2.3.4", "8388", "aes-256-gcm", "pass",
			`{"network":"tcp","realitySettings":{"fingerprint":"chrome","publicKey":"`+vlessPBK+`","serverName":"www.example.com"},"security":"reality"}`),
	},
	{
		name:     "tcp with an http header",
		link:     ssBase + "?type=tcp&headerType=http&host=a.example.com&path=/p",
		wantName: "1.2.3.4:8388",
		wantJSON: ssOutStream("1.2.3.4", "8388", "aes-256-gcm", "pass",
			`{"network":"tcp","tcpSettings":{"header":{"request":{"headers":{"Host":["a.example.com"]},"path":["/p"]},"type":"http"}}}`),
	},
	{
		name:         "allowInsecure over tls keeps verification on and warns",
		link:         ssBase + "?security=tls&sni=h.example&allowInsecure=1",
		wantName:     "1.2.3.4:8388",
		wantWarnings: []string{warnInsecureRemoved},
		wantJSON:     ssOutStream("1.2.3.4", "8388", "aes-256-gcm", "pass", `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"h.example"}}`),
	},
	{
		name:     "allowInsecure over tls with a pinned certificate has no warning",
		link:     ssBase + "?security=tls&sni=h.example&insecure=1&pcs=" + pinA,
		wantName: "1.2.3.4:8388",
		wantJSON: ssOutStream("1.2.3.4", "8388", "aes-256-gcm", "pass",
			`{"network":"tcp","security":"tls","tlsSettings":{"pinnedPeerCertSha256":"`+pinA+`","serverName":"h.example"}}`),
	},
	{name: "tcp and no security is plain", link: ssBase + "?type=tcp&security=none", wantName: "1.2.3.4:8388", wantJSON: ssOut("1.2.3.4", "8388", "aes-256-gcm", "pass")},
	{name: "raw is plain", link: ssBase + "?type=raw", wantName: "1.2.3.4:8388", wantJSON: ssOut("1.2.3.4", "8388", "aes-256-gcm", "pass")},
	{name: "an empty security is plain", link: ssBase + "?security=&type=", wantName: "1.2.3.4:8388", wantJSON: ssOut("1.2.3.4", "8388", "aes-256-gcm", "pass")},
	{name: "a tcp header of none is plain", link: ssBase + "?type=tcp&headerType=none&host=ignored.example.com", wantName: "1.2.3.4:8388", wantJSON: ssOut("1.2.3.4", "8388", "aes-256-gcm", "pass")},
	{name: "allowInsecure without tls is plain and has no warning", link: ssBase + "?allowInsecure=1", wantName: "1.2.3.4:8388", wantJSON: ssOut("1.2.3.4", "8388", "aes-256-gcm", "pass")},
	{
		name:     "a legacy link with a transport",
		link:     ssLegacy("aes-128-gcm:p@ss@host.example:8388") + "?type=ws&security=tls&sni=cdn.example.com&path=/ws#n",
		wantName: "n",
		wantJSON: ssOutStream("host.example", "8388", "aes-128-gcm", "p@ss",
			`{"network":"ws","security":"tls","tlsSettings":{"serverName":"cdn.example.com"},"wsSettings":{"path":"/ws"}}`),
	},
	{
		name:     "a legacy link with only unread parameters is plain",
		link:     ssLegacy("aes-128-gcm:p@ss@host.example:8388") + "?udp-over-tcp=1&foo=%zz",
		wantName: "host.example:8388",
		wantJSON: ssOut("host.example", "8388", "aes-128-gcm", "p@ss"),
	},

	// legacy
	{
		name:     "legacy, the last at sign splits",
		link:     "ss://YWVzLTEyOC1nY206cEBzc0Bob3N0LmV4YW1wbGU6ODM4OA==#c",
		wantName: "c",
		wantJSON: ssOut("host.example", "8388", "aes-128-gcm", "p@ss"),
	},
	{
		name:     "legacy, unpadded",
		link:     "ss://YWVzLTEyOC1nY206cEBzc0Bob3N0LmV4YW1wbGU6ODM4OA#c",
		wantName: "c",
		wantJSON: ssOut("host.example", "8388", "aes-128-gcm", "p@ss"),
	},
	{
		name:     "legacy, standard alphabet",
		link:     ssLegacy(ssLegacyAlphabetText) + "#d",
		wantName: "d",
		wantJSON: ssOut("h.example", "8388", "aes-256-gcm", "pa???>?"),
	},
	{
		name:     "legacy, standard alphabet, unpadded",
		link:     strings.TrimRight(ssLegacy(ssLegacyAlphabetText), "="),
		wantName: "h.example:8388",
		wantJSON: ssOut("h.example", "8388", "aes-256-gcm", "pa???>?"),
	},
	{
		name:     "legacy, url alphabet",
		link:     "ss://" + base64.URLEncoding.EncodeToString([]byte(ssLegacyAlphabetText)),
		wantName: "h.example:8388",
		wantJSON: ssOut("h.example", "8388", "aes-256-gcm", "pa???>?"),
	},
	{
		name:     "legacy with an ipv6 address",
		link:     ssLegacy("aes-256-gcm:pw@[2001:db8::1]:8388"),
		wantName: "[2001:db8::1]:8388",
		wantJSON: ssOut("2001:db8::1", "8388", "aes-256-gcm", "pw"),
	},
	{
		name:     "legacy with a colon in the password",
		link:     ssLegacy("aes-256-gcm:pa:ss@h.example:443"),
		wantName: "h.example:443",
		wantJSON: ssOut("h.example", "443", "aes-256-gcm", "pa:ss"),
	},
	{
		name:     "legacy with a plain-text name that has a percent",
		link:     ssLegacy("aes-256-gcm:pw@h.example:443") + "#50%",
		wantName: "50%",
		wantJSON: ssOut("h.example", "443", "aes-256-gcm", "pw"),
	},

	// methods
	{name: "aes-128-gcm", link: "ss://aes-128-gcm:pw@h.example:443", wantName: "h.example:443", wantJSON: ssOut("h.example", "443", "aes-128-gcm", "pw")},
	{name: "chacha20-poly1305", link: "ss://chacha20-poly1305:pw@h.example:443", wantName: "h.example:443", wantJSON: ssOut("h.example", "443", "chacha20-poly1305", "pw")},
	{name: "chacha20-ietf-poly1305 is chacha20-poly1305", link: "ss://chacha20-ietf-poly1305:pw@h.example:443", wantName: "h.example:443", wantJSON: ssOut("h.example", "443", "chacha20-poly1305", "pw")},
	{name: "xchacha20-poly1305", link: "ss://xchacha20-poly1305:pw@h.example:443", wantName: "h.example:443", wantJSON: ssOut("h.example", "443", "xchacha20-poly1305", "pw")},
	{name: "xchacha20-ietf-poly1305 is xchacha20-poly1305", link: "ss://xchacha20-ietf-poly1305:pw@h.example:443", wantName: "h.example:443", wantJSON: ssOut("h.example", "443", "xchacha20-poly1305", "pw")},
	{name: "2022-blake3-aes-256-gcm", link: "ss://2022-blake3-aes-256-gcm:" + ss2022Key32Link + "@h.example:443", wantName: "h.example:443", wantJSON: ssOut("h.example", "443", "2022-blake3-aes-256-gcm", ss2022Key32)},
	{name: "2022-blake3-chacha20-poly1305", link: "ss://2022-blake3-chacha20-poly1305:" + ss2022Key32Link + "@h.example:443", wantName: "h.example:443", wantJSON: ssOut("h.example", "443", "2022-blake3-chacha20-poly1305", ss2022Key32)},
	{
		name:     "2022-blake3-aes-256-gcm with a server key and a user key",
		link:     "ss://2022-blake3-aes-256-gcm:" + ss2022Key32Link + ":" + ss2022Key32Link + "@h.example:443",
		wantName: "h.example:443",
		wantJSON: ssOut("h.example", "443", "2022-blake3-aes-256-gcm", ss2022Key32+":"+ss2022Key32),
	},
	{name: "method in upper case", link: "ss://" + ssUser("AES-256-GCM:pw") + "@h.example:443", wantName: "h.example:443", wantJSON: ssOut("h.example", "443", "aes-256-gcm", "pw")},

	// xray-core 26.7.11 and newer refuse the whole config for these.
	{name: "none", link: "ss://none:pw@h.example:443", wantErr: kindUnsupported, refused: true, errContains: "Shadowsocks", secret: "pw"},
	{name: "none, as a SIP002 userinfo", link: "ss://" + ssUser("none:hunter2") + "@h.example:443", wantErr: kindUnsupported, refused: true, errContains: "Shadowsocks", secret: "hunter2"},
	{name: "none on a legacy link", link: ssLegacy("none:hunter2@h.example:443"), wantErr: kindUnsupported, refused: true, errContains: "Shadowsocks", secret: "hunter2"},
	{name: "2022-blake3-aes-256-gcm with a short key", link: "ss://2022-blake3-aes-256-gcm:" + ss2022Key16Link + "@h.example:443", wantErr: kindUnsupported, refused: true, errContains: "2022", secret: ss2022Key16},
	{name: "2022-blake3-aes-128-gcm with a long key", link: "ss://2022-blake3-aes-128-gcm:" + ss2022Key32Link + "@h.example:443", wantErr: kindUnsupported, refused: true, errContains: "2022", secret: ss2022Key32},
	{name: "2022-blake3-aes-128-gcm with a password that is not base64", link: "ss://2022-blake3-aes-128-gcm:hunter2hunter2@h.example:443", wantErr: kindUnsupported, refused: true, errContains: "2022", secret: "hunter2hunter2"},
	{name: "2022-blake3-chacha20-poly1305 with two keys", link: "ss://2022-blake3-chacha20-poly1305:" + ss2022Key32Link + ":" + ss2022Key32Link + "@h.example:443", wantErr: kindUnsupported, refused: true, errContains: "chacha20-poly1305", secret: ss2022Key32},

	// refused
	{name: "plugin", link: "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp#a", wantErr: kindUnsupported, errContains: "plugin", secret: "pass"},
	{name: "plugin without a slash", link: "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?plugin=obfs-local", wantErr: kindUnsupported, secret: "pass"},
	{name: "plugin after another parameter", link: "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?x=1&plugin=v2ray-plugin", wantErr: kindUnsupported, secret: "pass"},
	{name: "plugin with no value", link: "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?plugin=", wantErr: kindUnsupported, secret: "pass"},
	{name: "plugin with a bad escape", link: "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?plugin=%zz", wantErr: kindUnsupported, secret: "pass"},
	{name: "plugin with an escaped name", link: "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?%70lugin=x", wantErr: kindUnsupported, secret: "pass"},
	{name: "plugin on a legacy link", link: "ss://YWVzLTEyOC1nY206cEBzc0Bob3N0LmV4YW1wbGU6ODM4OA==?plugin=obfs-local#c", wantErr: kindUnsupported, secret: "p@ss"},
	{name: "plugin beside a transport", link: ssBase + "?type=ws&security=tls&plugin=v2ray-plugin", wantErr: kindUnsupported, secret: "pass"},
	{name: "kcp", link: ssBase + "?type=kcp", wantErr: kindUnsupported, secret: "pass"},
	{name: "reality without a public key", link: ssBase + "?security=reality&sni=www.example.com", wantErr: kindInvalid, errContains: "reality", secret: "pass"},
	{name: "reality over websocket", link: ssBase + "?security=reality&type=ws&pbk=" + vlessPBK, wantErr: kindInvalid, secret: "pass"},
	{name: "unknown security", link: ssBase + "?security=foo", wantErr: kindInvalid, secret: "pass"},
	{name: "unknown network", link: ssBase + "?type=carrier-pigeon", wantErr: kindInvalid, secret: "pass"},
	{name: "read parameter with a bad escape", link: ssBase + "?type=ws&path=%zz", wantErr: kindInvalid, errContains: `"path"`, secret: "pass"},
	{name: "read parameter with a bad escape in the type", link: ssBase + "/?type=%zz", wantErr: kindInvalid, errContains: `"type"`, secret: "pass"},
	{name: "read parameter with a semicolon", link: ssBase + "?security=tls&alpn=h2;http/1.1", wantErr: kindInvalid, errContains: `"alpn"`, secret: "pass"},
	{name: "read parameter on a legacy link with a bad escape", link: ssLegacy("aes-128-gcm:pass@host.example:8388") + "?type=%zz", wantErr: kindInvalid, errContains: `"type"`, secret: "pass"},
	{name: "read parameter on a legacy link with a semicolon", link: ssLegacy("aes-128-gcm:pass@host.example:8388") + "?alpn=a;b#n", wantErr: kindInvalid, errContains: `"alpn"`, secret: "pass"},
	{name: "rc4-md5", link: "ss://" + ssUser("rc4-md5:pass") + "@1.2.3.4:8388", wantErr: kindUnsupported, errContains: "method", secret: "pass"},
	{name: "rc4-md5 in plain text", link: "ss://rc4-md5:pass@1.2.3.4:8388", wantErr: kindUnsupported, secret: "pass"},
	{name: "rc4-md5 on a legacy link", link: ssLegacy("rc4-md5:pass@1.2.3.4:8388"), wantErr: kindUnsupported, secret: "pass"},
	{name: "chacha20, the old stream cipher", link: "ss://chacha20:pass@1.2.3.4:8388", wantErr: kindUnsupported, secret: "pass"},
	{name: "aes-256-cfb", link: "ss://aes-256-cfb:pass@1.2.3.4:8388", wantErr: kindUnsupported, secret: "pass"},
	{name: "an unsupported method is not repeated", link: "ss://" + ssUser("secretmethod:pass") + "@1.2.3.4:8388", wantErr: kindUnsupported, secret: "secretmethod"},

	{name: "empty password in base64", link: "ss://" + ssUser("aes-256-gcm:") + "@1.2.3.4:8388", wantErr: kindInvalid, errContains: "password"},
	{name: "empty password in plain text", link: "ss://aes-256-gcm:@1.2.3.4:8388", wantErr: kindInvalid, errContains: "password"},
	{name: "empty password on a legacy link", link: ssLegacy("aes-256-gcm:@1.2.3.4:8388"), wantErr: kindInvalid, errContains: "password"},
	{name: "empty password with the none method", link: "ss://none:@1.2.3.4:8388", wantErr: kindInvalid, errContains: "password"},
	{name: "userinfo that is not method:password", link: "ss://" + ssUser("justapassword") + "@1.2.3.4:8388", wantErr: kindInvalid, secret: "justapassword"},
	{name: "userinfo that is not base64", link: "ss://!!!@1.2.3.4:8388", wantErr: kindInvalid},
	{name: "empty userinfo", link: "ss://@1.2.3.4:8388", wantErr: kindInvalid},
	{name: "password that is not text", link: "ss://" + ssUser("aes-256-gcm:pw\xff\xfe") + "@1.2.3.4:8388", wantErr: kindInvalid, errContains: "UTF-8"},
	{name: "password that is not text on a legacy link", link: ssLegacy("aes-256-gcm:pw\xff\xfe@1.2.3.4:8388"), wantErr: kindInvalid, errContains: "UTF-8"},
	{name: "no scheme body", link: "ss://", wantErr: kindInvalid},
	{name: "only a name", link: "ss://#name", wantErr: kindInvalid},
	{name: "host and port without userinfo", link: "ss://example.com:8388", wantErr: kindInvalid},
	{name: "port missing", link: "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4", wantErr: kindInvalid, secret: "pass"},
	{name: "port zero", link: "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:0", wantErr: kindInvalid, secret: "pass"},
	{name: "port too high", link: "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:70000", wantErr: kindInvalid, secret: "pass"},
	{name: "host missing", link: "ss://YWVzLTI1Ni1nY206cGFzcw@:8388", wantErr: kindInvalid, secret: "pass"},

	{name: "legacy that is not base64", link: "ss://not base64 at all#x", wantErr: kindInvalid},
	{name: "legacy with no at sign", link: ssLegacy("aes-256-gcm:pass"), wantErr: kindInvalid, secret: "pass"},
	{name: "legacy with no port", link: ssLegacy("aes-256-gcm:pass@h.example"), wantErr: kindInvalid, secret: "pass"},
	{name: "legacy with port zero", link: ssLegacy("aes-256-gcm:pass@h.example:0"), wantErr: kindInvalid, secret: "pass"},
	{name: "legacy with a port that is not a number", link: ssLegacy("aes-256-gcm:pass@h.example:https"), wantErr: kindInvalid, secret: "pass"},
	{name: "legacy with no host", link: ssLegacy("aes-256-gcm:pass@:443"), wantErr: kindInvalid, secret: "pass"},
	{name: "legacy with a space in the host", link: ssLegacy("aes-256-gcm:pass@bad host:443"), wantErr: kindInvalid, secret: "pass"},
	{name: "legacy with no colon in the userinfo", link: ssLegacy("justapassword@h.example:443"), wantErr: kindInvalid, secret: "justapassword"},
}

func TestParseShadowsocks(t *testing.T) { runParseCases(t, ssCases) }

// TestSSAlphabetBody checks that the alphabet cases test what they claim.
func TestSSAlphabetBody(t *testing.T) {
	std := base64.StdEncoding.EncodeToString([]byte(ssLegacyAlphabetText))
	if !strings.Contains(std, "+") || !strings.Contains(std, "/") || !strings.HasSuffix(std, "==") {
		t.Errorf("the legacy body %q must have a +, a / and padding", std)
	}
	if u := ssUser(ssUserAlphabetText); !strings.Contains(u, "-") || !strings.Contains(u, "_") {
		t.Errorf("the userinfo %q must have a - and a _", u)
	}
}

// TestShadowsocksHasNoStreamSettings is the check that the outbound has no
// streamSettings key at all, not even a null one.
func TestShadowsocksHasNoStreamSettings(t *testing.T) {
	s, err := Parse("ss://aes-256-gcm:pw@h.example:443")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(s.Outbound), "streamSettings") {
		t.Errorf("Outbound has streamSettings: %s", s.Outbound)
	}
}
