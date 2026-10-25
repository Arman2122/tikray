package sharelink

import "testing"

const (
	vlessID  = "b831381d-6324-4d53-ad4f-8cda48b30811"
	vlessPBK = "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"
	// pinA and pinB are certificate pins in the two formats xray reads: hex,
	// and hex with colons.
	pinA = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	pinB = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
)

// vlessOut is the expected VLESS outbound for the user users[0] at addr:port
// with the given streamSettings JSON.
func vlessOut(addr string, port string, user, stream string) string {
	return `{"protocol":"vless","settings":{"vnext":[{"address":"` + addr + `","port":` + port + `,"users":[` + user + `]}]},"streamSettings":` + stream + `}`
}

// plainUser is the user a link gets when it sets neither flow nor encryption.
const plainUser = `{"encryption":"none","id":"` + vlessID + `"}`

func TestParseVLESS(t *testing.T) {
	const base = "vless://" + vlessID + "@example.com:443"
	runParseCases(t, []parseCase{
		{
			name:     "reality and vision",
			link:     "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision#lab%20%F0%9F%9A%80",
			wantName: "lab 🚀",
			wantJSON: `{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443,"users":[{"encryption":"none","flow":"xtls-rprx-vision","id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},"streamSettings":{"network":"tcp","realitySettings":{"fingerprint":"chrome","publicKey":"SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc","serverName":"www.example.com","shortId":"6ba85179e30d4fc2"},"security":"reality"}}`,
		},
		{
			name:     "websocket and tls, encoded path, ipv6, empty fragment",
			link:     "vless://" + vlessID + "@[2001:db8::1]:8443?type=ws&security=tls&sni=cdn.example.com&host=cdn.example.com&path=%2Fws%3Fed%3D2048&alpn=h2,http/1.1#",
			wantName: "[2001:db8::1]:8443",
			wantJSON: vlessOut("2001:db8::1", "8443", plainUser,
				`{"network":"ws","security":"tls","tlsSettings":{"alpn":["h2","http/1.1"],"serverName":"cdn.example.com"},"wsSettings":{"host":"cdn.example.com","path":"/ws?ed=2048"}}`),
		},
		{
			name:     "websocket path defaults to slash",
			link:     base + "?type=ws#ws",
			wantName: "ws",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"ws","wsSettings":{"path":"/"}}`),
		},
		{
			name:     "grpc multi",
			link:     base + "?type=grpc&serviceName=gun&mode=multi&security=tls#g",
			wantName: "g",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"grpc","grpcSettings":{"multiMode":true,"serviceName":"gun"},"security":"tls","tlsSettings":{}}`),
		},
		{
			name:     "grpc single with authority",
			link:     base + "?type=grpc&serviceName=gun&authority=front.example.com&mode=gun",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"grpc","grpcSettings":{"authority":"front.example.com","multiMode":false,"serviceName":"gun"}}`),
		},
		{
			name:     "grpc with nothing set",
			link:     base + "?type=grpc",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"grpc","grpcSettings":{"multiMode":false}}`),
		},
		{
			name:     "xhttp",
			link:     base + "?type=xhttp&path=/x&mode=packet-up#x",
			wantName: "x",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"xhttp","xhttpSettings":{"mode":"packet-up","path":"/x"}}`),
		},
		{
			name:     "xhttp mode defaults to auto",
			link:     base + "?type=xhttp&host=front.example.com",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"xhttp","xhttpSettings":{"host":"front.example.com","mode":"auto"}}`),
		},
		{
			name:     "splithttp is xhttp",
			link:     base + "?type=splithttp&path=/x",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"xhttp","xhttpSettings":{"mode":"auto","path":"/x"}}`),
		},
		{
			name:     "httpupgrade",
			link:     base + "?type=httpupgrade&path=/up&host=up.example.com",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"httpupgrade","httpupgradeSettings":{"host":"up.example.com","path":"/up"}}`),
		},
		{
			name:     "httpupgrade with nothing set",
			link:     base + "?type=httpupgrade",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"httpupgrade","httpupgradeSettings":{}}`),
		},
		{
			name:     "raw with an empty security",
			link:     base + "?type=raw&security=",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"tcp"}`),
		},
		{
			name:     "no query at all",
			link:     base,
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"tcp"}`),
		},
		{
			name:     "security none has no tls settings",
			link:     base + "?type=tcp&security=none&sni=ignored.example.com",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"tcp"}`),
		},
		{
			name:     "tcp with an http header",
			link:     base + "?type=tcp&headerType=http&host=front.example.com&path=/h",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"tcp","tcpSettings":{"header":{"request":{"headers":{"Host":["front.example.com"]},"path":["/h"]},"type":"http"}}}`),
		},
		{
			name:     "tcp http header without host or path",
			link:     base + "?headerType=http",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"tcp","tcpSettings":{"header":{"request":{"headers":{},"path":["/"]},"type":"http"}}}`),
		},
		{
			name:     "tcp header type none",
			link:     base + "?type=tcp&headerType=none&host=ignored.example.com&path=/ignored",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"tcp"}`),
		},
		{
			name:     "header type does not apply to websocket",
			link:     base + "?type=ws&headerType=http&path=/w",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"ws","wsSettings":{"path":"/w"}}`),
		},
		{
			name:     "network and security are case-insensitive",
			link:     base + "?type=WS&security=TLS&sni=a.example.com",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"ws","security":"tls","tlsSettings":{"serverName":"a.example.com"},"wsSettings":{"path":"/"}}`),
		},
		// xray-core refuses allowInsecure, so no outbound carries it: the link
		// still parses, with verification on and a warning.
		{
			name:         "allowInsecure is never emitted",
			link:         base + "?security=tls&sni=a.example.com&fp=firefox&allowInsecure=1",
			wantName:     "example.com:443",
			wantWarnings: []string{warnInsecureRemoved},
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"tcp","security":"tls","tlsSettings":{"fingerprint":"firefox","serverName":"a.example.com"}}`),
		},
		{
			name:         "insecure true is not emitted either",
			link:         base + "?security=tls&insecure=true",
			wantName:     "example.com:443",
			wantWarnings: []string{warnInsecureRemoved},
			wantJSON:     vlessOut("example.com", "443", plainUser, `{"network":"tcp","security":"tls","tlsSettings":{}}`),
		},
		{
			name:         "allowInsecure True counts as insecure",
			link:         base + "?security=tls&allowInsecure=True",
			wantName:     "example.com:443",
			wantWarnings: []string{warnInsecureRemoved},
			wantJSON:     vlessOut("example.com", "443", plainUser, `{"network":"tcp","security":"tls","tlsSettings":{}}`),
		},
		{
			name:         "insecure TRUE counts as insecure",
			link:         base + "?security=tls&insecure=TRUE",
			wantName:     "example.com:443",
			wantWarnings: []string{warnInsecureRemoved},
			wantJSON:     vlessOut("example.com", "443", plainUser, `{"network":"tcp","security":"tls","tlsSettings":{}}`),
		},
		{
			name:     "tls with allowInsecure off",
			link:     base + "?security=tls&allowInsecure=0&insecure=false",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"tcp","security":"tls","tlsSettings":{}}`),
		},
		{
			name:         "tls with only one of the insecure flags on",
			link:         base + "?security=tls&allowInsecure=0&insecure=1",
			wantName:     "example.com:443",
			wantWarnings: []string{warnInsecureRemoved},
			wantJSON:     vlessOut("example.com", "443", plainUser, `{"network":"tcp","security":"tls","tlsSettings":{}}`),
		},
		{
			name:         "both insecure flags give one warning",
			link:         base + "?security=tls&allowInsecure=1&insecure=1",
			wantName:     "example.com:443",
			wantWarnings: []string{warnInsecureRemoved},
			wantJSON:     vlessOut("example.com", "443", plainUser, `{"network":"tcp","security":"tls","tlsSettings":{}}`),
		},
		{
			name:     "insecure without tls has nothing to warn about",
			link:     base + "?security=none&allowInsecure=1",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"tcp"}`),
		},
		{
			name:     "pcs pins the certificate",
			link:     base + "?security=tls&sni=a.example.com&pcs=" + pinA,
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"tcp","security":"tls","tlsSettings":{"pinnedPeerCertSha256":"`+pinA+`","serverName":"a.example.com"}}`),
		},
		{
			name:     "pcs replaces the insecure flag, with no warning",
			link:     base + "?security=tls&allowInsecure=1&insecure=true&pcs=" + pinA,
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"tcp","security":"tls","tlsSettings":{"pinnedPeerCertSha256":"`+pinA+`"}}`),
		},
		{
			name:     "pcs is given as it is, trimmed",
			link:     base + "?security=tls&pcs=%20" + pinA + "," + pinB + "%20",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"tcp","security":"tls","tlsSettings":{"pinnedPeerCertSha256":"`+pinA+","+pinB+`"}}`),
		},
		{
			name:         "a blank pcs does not count as a pin",
			link:         base + "?security=tls&allowInsecure=1&pcs=%20",
			wantName:     "example.com:443",
			wantWarnings: []string{warnInsecureRemoved},
			wantJSON:     vlessOut("example.com", "443", plainUser, `{"network":"tcp","security":"tls","tlsSettings":{}}`),
		},
		{
			name:     "vcn names the certificate",
			link:     base + "?security=tls&sni=a.example.com&vcn=real.example.com&pcs=" + pinA,
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"tcp","security":"tls","tlsSettings":{"pinnedPeerCertSha256":"`+pinA+`","serverName":"a.example.com","verifyPeerCertByName":"real.example.com"}}`),
		},
		{
			name:     "vcn alone",
			link:     base + "?security=tls&vcn=real.example.com",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"tcp","security":"tls","tlsSettings":{"verifyPeerCertByName":"real.example.com"}}`),
		},
		{
			name:         "vcn does not stop the insecure warning",
			link:         base + "?security=tls&insecure=1&vcn=real.example.com",
			wantName:     "example.com:443",
			wantWarnings: []string{warnInsecureRemoved},
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"tcp","security":"tls","tlsSettings":{"verifyPeerCertByName":"real.example.com"}}`),
		},
		{
			name:     "pcs and vcn are for tls only",
			link:     base + "?security=none&pcs=" + pinA + "&vcn=real.example.com",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"tcp"}`),
		},
		{
			name:     "pcs and vcn are not reality settings",
			link:     base + "?security=reality&pbk=" + vlessPBK + "&pcs=" + pinA + "&vcn=real.example.com",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"tcp","realitySettings":{"fingerprint":"chrome","publicKey":"`+vlessPBK+`"},"security":"reality"}`),
		},
		{
			name:     "alpn is trimmed and split on commas",
			link:     base + "?security=tls&alpn=h2%2C%20http/1.1,,",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"tcp","security":"tls","tlsSettings":{"alpn":["h2","http/1.1"]}}`),
		},
		{
			name:     "flow and a post-quantum encryption pass through",
			link:     base + "?encryption=mlkem768x25519plus.native.0rtt.dGVzdC1rZXk&flow=xtls-rprx-vision",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443",
				`{"encryption":"mlkem768x25519plus.native.0rtt.dGVzdC1rZXk","flow":"xtls-rprx-vision","id":"`+vlessID+`"}`,
				`{"network":"tcp"}`),
		},
		{
			name:     "encryption none is explicit",
			link:     base + "?encryption=none",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"tcp"}`),
		},
		{
			name:     "reality fingerprint defaults to chrome",
			link:     base + "?security=reality&pbk=" + vlessPBK + "&sni=www.example.com&spx=%2F",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"tcp","realitySettings":{"fingerprint":"chrome","publicKey":"`+vlessPBK+`","serverName":"www.example.com","spiderX":"/"},"security":"reality"}`),
		},
		{
			name:     "reality over grpc",
			link:     base + "?type=grpc&serviceName=gun&security=reality&pbk=" + vlessPBK + "&fp=safari&sid=ab",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"grpc","grpcSettings":{"multiMode":false,"serviceName":"gun"},"realitySettings":{"fingerprint":"safari","publicKey":"`+vlessPBK+`","shortId":"ab"},"security":"reality"}`),
		},
		{
			name:     "reality over xhttp",
			link:     base + "?type=xhttp&path=/r&security=reality&pbk=" + vlessPBK,
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"xhttp","realitySettings":{"fingerprint":"chrome","publicKey":"`+vlessPBK+`"},"security":"reality","xhttpSettings":{"mode":"auto","path":"/r"}}`),
		},
		{
			name:     "reality ignores allowInsecure",
			link:     base + "?security=reality&pbk=" + vlessPBK + "&allowInsecure=1",
			wantName: "example.com:443",
			wantJSON: vlessOut("example.com", "443", plainUser,
				`{"network":"tcp","realitySettings":{"fingerprint":"chrome","publicKey":"`+vlessPBK+`"},"security":"reality"}`),
		},
		{
			name:     "ipv6 host without a fragment",
			link:     "vless://" + vlessID + "@[::1]:1",
			wantName: "[::1]:1",
			wantJSON: vlessOut("::1", "1", plainUser, `{"network":"tcp"}`),
		},
		{
			name:     "highest port",
			link:     "vless://" + vlessID + "@example.com:65535",
			wantName: "example.com:65535",
			wantJSON: vlessOut("example.com", "65535", plainUser, `{"network":"tcp"}`),
		},
		{
			name:     "fragment is trimmed",
			link:     base + "#%20%20node%20one%20%20",
			wantName: "node one",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"tcp"}`),
		},

		{
			name:     "a bare percent in the name",
			link:     base + "#50%",
			wantName: "50%",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"tcp"}`),
		},
		{
			name:     "a short escape in the name",
			link:     base + "#a%2",
			wantName: "a%2",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"tcp"}`),
		},
		{
			name:     "a percent in a name beside a bad query parameter nobody reads",
			link:     base + "?remark=50%&type=ws#🔥 20% off",
			wantName: "🔥 20% off",
			wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"ws","wsSettings":{"path":"/"}}`),
		},

		{name: "kcp", link: base + "?type=kcp&seed=x", wantErr: kindUnsupported, secret: vlessID},
		{name: "mkcp", link: base + "?type=mkcp", wantErr: kindUnsupported, secret: vlessID},
		{name: "quic", link: base + "?type=quic", wantErr: kindUnsupported, secret: vlessID},
		{name: "h2", link: base + "?type=h2&security=tls", wantErr: kindUnsupported, secret: vlessID},
		{name: "http", link: base + "?type=http", wantErr: kindUnsupported, secret: vlessID},
		{name: "unknown network", link: base + "?type=carrier-pigeon", wantErr: kindInvalid, secret: vlessID},
		{name: "reality without a public key", link: base + "?security=reality&sni=www.example.com&sid=ab", wantErr: kindInvalid, secret: vlessID},
		{name: "reality over websocket", link: base + "?type=ws&security=reality&pbk=" + vlessPBK, wantErr: kindInvalid, secret: vlessID},
		{name: "reality over httpupgrade", link: base + "?type=httpupgrade&security=reality&pbk=" + vlessPBK, wantErr: kindInvalid, secret: vlessID},
		{name: "unknown security", link: base + "?security=foo", wantErr: kindInvalid, secret: vlessID},
		{name: "legacy xtls security", link: base + "?security=xtls", wantErr: kindInvalid, secret: vlessID},
		{name: "unknown tcp header type", link: base + "?type=tcp&headerType=srtp", wantErr: kindInvalid, secret: vlessID},
		{name: "port zero", link: "vless://" + vlessID + "@example.com:0", wantErr: kindInvalid, secret: vlessID},
		{name: "port too high", link: "vless://" + vlessID + "@example.com:70000", wantErr: kindInvalid, secret: vlessID},
		{name: "port way too high", link: "vless://" + vlessID + "@example.com:99999999999999999999", wantErr: kindInvalid, secret: vlessID},
		{name: "port not a number", link: "vless://" + vlessID + "@example.com:https", wantErr: kindInvalid, secret: vlessID},
		{name: "port missing", link: "vless://" + vlessID + "@example.com", wantErr: kindInvalid, secret: vlessID},
		{name: "port empty", link: "vless://" + vlessID + "@example.com:", wantErr: kindInvalid, secret: vlessID},
		{name: "host missing", link: "vless://" + vlessID + "@:443", wantErr: kindInvalid, secret: vlessID},
		{name: "ipv6 host missing a bracket", link: "vless://" + vlessID + "@[2001:db8::1:443", wantErr: kindInvalid, secret: vlessID},
		{name: "empty id", link: "vless://@example.com:443?type=tcp", wantErr: kindInvalid},
		{name: "no id", link: "vless://example.com:443?type=tcp", wantErr: kindInvalid},
		// A dropped parameter would give an outbound that does not match the server.
		{name: "malformed escape in the query", link: base + "?type=ws&path=%zz", wantErr: kindInvalid, secret: vlessID},
		{name: "semicolon in the query", link: base + "?security=tls&alpn=h2;http/1.1", wantErr: kindInvalid, secret: vlessID},
		{name: "malformed escape in the encryption", link: base + "?encryption=%zz", wantErr: kindInvalid, errContains: `"encryption"`, secret: vlessID},
		{name: "malformed escape in the flow", link: base + "?flow=xtls-rprx-vision%", wantErr: kindInvalid, errContains: `"flow"`, secret: vlessID},
		{name: "malformed escape in the id", link: "vless://secret%zz@example.com:443", wantErr: kindInvalid, secret: "secret"},
	})
}
