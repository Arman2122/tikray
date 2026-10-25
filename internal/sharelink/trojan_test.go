package sharelink

import "testing"

// trojanOut is the expected Trojan outbound for one server with the given
// streamSettings JSON.
func trojanOut(addr, port, password, stream string) string {
	return `{"protocol":"trojan","settings":{"servers":[{"address":"` + addr + `","port":` + port + `,"password":"` + password + `"}]},"streamSettings":` + stream + `}`
}

// trojanCases are the Trojan links Parse must read or refuse. The fuzz test
// seeds from them too.
var trojanCases = []parseCase{
	{
		name:     "tls by default, encoded password",
		link:     "trojan://p%40ss@example.com:443?sni=example.com#t",
		wantName: "t",
		wantJSON: trojanOut("example.com", "443", "p@ss",
			`{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}`),
	},
	{
		name:     "security none has no tls settings",
		link:     "trojan://pw@1.2.3.4:443?security=none&type=ws&path=/t",
		wantName: "1.2.3.4:443",
		wantJSON: trojanOut("1.2.3.4", "443", "pw", `{"network":"ws","wsSettings":{"path":"/t"}}`),
	},
	{
		name:     "no query at all is tls",
		link:     "trojan://pw@example.com:443",
		wantName: "example.com:443",
		wantJSON: trojanOut("example.com", "443", "pw", `{"network":"tcp","security":"tls","tlsSettings":{}}`),
	},
	{
		// An empty value says nothing, so the scheme's default applies.
		name:     "an empty security is tls",
		link:     "trojan://pw@example.com:443?security=",
		wantName: "example.com:443",
		wantJSON: trojanOut("example.com", "443", "pw", `{"network":"tcp","security":"tls","tlsSettings":{}}`),
	},
	{
		name:     "websocket over tls",
		link:     "trojan://pw@[2001:db8::2]:443?type=ws&host=cdn.example.com&path=%2Fws&sni=cdn.example.com&fp=chrome&alpn=http/1.1#ws%20node",
		wantName: "ws node",
		wantJSON: trojanOut("2001:db8::2", "443", "pw",
			`{"network":"ws","security":"tls","tlsSettings":{"alpn":["http/1.1"],"fingerprint":"chrome","serverName":"cdn.example.com"},"wsSettings":{"host":"cdn.example.com","path":"/ws"}}`),
	},
	{
		// Trojan's default security is tls, so the flag is as live here as in a vless link.
		name:         "an insecure trojan link keeps verification on and warns",
		link:         "trojan://pw@example.com:443?allowInsecure=1&sni=example.com",
		wantName:     "example.com:443",
		wantWarnings: []string{warnInsecureRemoved},
		wantJSON:     trojanOut("example.com", "443", "pw", `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}`),
	},
	{
		name:     "a pinned trojan link",
		link:     "trojan://pw@example.com:443?insecure=1&sni=example.com&pcs=" + pinA + "&vcn=example.com",
		wantName: "example.com:443",
		wantJSON: trojanOut("example.com", "443", "pw",
			`{"network":"tcp","security":"tls","tlsSettings":{"pinnedPeerCertSha256":"`+pinA+`","serverName":"example.com","verifyPeerCertByName":"example.com"}}`),
	},
	{
		name:     "a percent in the name",
		link:     "trojan://pw@example.com:443?security=none#50%",
		wantName: "50%",
		wantJSON: trojanOut("example.com", "443", "pw", `{"network":"tcp"}`),
	},
	{
		name:     "grpc over tls",
		link:     "trojan://pw@example.com:443?type=grpc&serviceName=gun&mode=multi&sni=example.com",
		wantName: "example.com:443",
		wantJSON: trojanOut("example.com", "443", "pw",
			`{"network":"grpc","grpcSettings":{"multiMode":true,"serviceName":"gun"},"security":"tls","tlsSettings":{"serverName":"example.com"}}`),
	},
	{
		name:     "reality",
		link:     "trojan://pw@example.com:443?security=reality&pbk=" + vlessPBK + "&sni=www.example.com",
		wantName: "example.com:443",
		wantJSON: trojanOut("example.com", "443", "pw",
			`{"network":"tcp","realitySettings":{"fingerprint":"chrome","publicKey":"`+vlessPBK+`","serverName":"www.example.com"},"security":"reality"}`),
	},
	{
		name:     "password with reserved characters",
		link:     "trojan://a%2Fb%3Fc%23d%25e@example.com:443?security=none",
		wantName: "example.com:443",
		wantJSON: trojanOut("example.com", "443", "a/b?c#d%e", `{"network":"tcp"}`),
	},
	{
		name:     "password with a quote",
		link:     "trojan://say%22hi@example.com:443?security=none",
		wantName: "example.com:443",
		wantJSON: trojanOut("example.com", "443", `say\"hi`, `{"network":"tcp"}`),
	},

	{name: "kcp", link: "trojan://secret@example.com:443?type=kcp", wantErr: kindUnsupported, secret: "secret"},
	{name: "unknown security", link: "trojan://secret@example.com:443?security=foo", wantErr: kindInvalid, secret: "secret"},
	{name: "reality without a public key", link: "trojan://secret@example.com:443?security=reality", wantErr: kindInvalid, secret: "secret"},
	{name: "reality over websocket", link: "trojan://secret@example.com:443?security=reality&type=ws&pbk=" + vlessPBK, wantErr: kindInvalid, secret: "secret"},
	{name: "port zero", link: "trojan://secret@example.com:0", wantErr: kindInvalid, secret: "secret"},
	{name: "port too high", link: "trojan://secret@example.com:70000", wantErr: kindInvalid, secret: "secret"},
	{name: "port missing", link: "trojan://secret@example.com", wantErr: kindInvalid, secret: "secret"},
	{name: "port not a number", link: "trojan://secret@example.com:https", wantErr: kindInvalid, secret: "secret"},
	{name: "host missing", link: "trojan://secret@:443", wantErr: kindInvalid, secret: "secret"},
	{name: "empty password", link: "trojan://@example.com:443", wantErr: kindInvalid},
	{name: "no password", link: "trojan://example.com:443", wantErr: kindInvalid},
	{name: "malformed escape in the password", link: "trojan://secret%zz@example.com:443", wantErr: kindInvalid, secret: "secret"},
	{name: "malformed escape in the query", link: "trojan://secret@example.com:443?sni=%zz", wantErr: kindInvalid, secret: "secret"},
}

func TestParseTrojan(t *testing.T) { runParseCases(t, trojanCases) }
