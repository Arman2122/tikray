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

// vlessBase is a VLESS link with no query, for the cases that add one.
const vlessBase = "vless://" + vlessID + "@example.com:443"

// vlessPlain is vlessBase to a private address. xray-core 26.7.11 and newer
// refuse VLESS with no TLS and no encryption to a public one, so the cases that
// have neither use this link.
const vlessPlain = "vless://" + vlessID + "@nas.lan:443"

// vlessCases are the VLESS links Parse must read or refuse. The fuzz test
// seeds from them too.
var vlessCases = []parseCase{
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
		// A CDN-fronted link: a clean address, a host and no sni. The handshake
		// must name the first host, not the address.
		name:     "tls without sni takes the first host",
		link:     "vless://" + vlessID + "@203.0.113.10:443?type=ws&security=tls&host=a.example.com,b.example.com&path=/ws",
		wantName: "203.0.113.10:443",
		wantJSON: vlessOut("203.0.113.10", "443", plainUser,
			`{"network":"ws","security":"tls","tlsSettings":{"serverName":"a.example.com"},"wsSettings":{"host":"a.example.com,b.example.com","path":"/ws"}}`),
	},
	{
		name:     "an sni wins over the host",
		link:     "vless://" + vlessID + "@203.0.113.10:443?type=ws&security=tls&sni=front.example.com&host=a.example.com&path=/ws",
		wantName: "203.0.113.10:443",
		wantJSON: vlessOut("203.0.113.10", "443", plainUser,
			`{"network":"ws","security":"tls","tlsSettings":{"serverName":"front.example.com"},"wsSettings":{"host":"a.example.com","path":"/ws"}}`),
	},
	{
		name:     "reality does not take the host for a server name",
		link:     "vless://" + vlessID + "@203.0.113.10:443?security=reality&pbk=" + vlessPBK + "&host=a.example.com",
		wantName: "203.0.113.10:443",
		wantJSON: vlessOut("203.0.113.10", "443", plainUser,
			`{"network":"tcp","realitySettings":{"fingerprint":"chrome","publicKey":"`+vlessPBK+`"},"security":"reality"}`),
	},
	{
		name:     "no tls does not take the host for a server name",
		link:     "vless://" + vlessID + "@203.0.113.10:443?type=ws&host=a.example.com",
		wantName: "203.0.113.10:443",
		wantJSON: vlessOut("203.0.113.10", "443", plainUser,
			`{"network":"ws","wsSettings":{"host":"a.example.com","path":"/"}}`),
	},
	{
		name:     "websocket path defaults to slash",
		link:     vlessPlain + "?type=ws#ws",
		wantName: "ws",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"ws","wsSettings":{"path":"/"}}`),
	},
	{
		name:     "grpc multi",
		link:     vlessBase + "?type=grpc&serviceName=gun&mode=multi&security=tls#g",
		wantName: "g",
		wantJSON: vlessOut("example.com", "443", plainUser,
			`{"network":"grpc","grpcSettings":{"multiMode":true,"serviceName":"gun"},"security":"tls","tlsSettings":{}}`),
	},
	{
		name:     "grpc single with authority",
		link:     vlessPlain + "?type=grpc&serviceName=gun&authority=front.example.com&mode=gun",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser,
			`{"network":"grpc","grpcSettings":{"authority":"front.example.com","multiMode":false,"serviceName":"gun"}}`),
	},
	{
		name:     "grpc with nothing set",
		link:     vlessPlain + "?type=grpc",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"grpc","grpcSettings":{"multiMode":false}}`),
	},
	{
		name:     "xhttp",
		link:     vlessPlain + "?type=xhttp&path=/x&mode=packet-up#x",
		wantName: "x",
		wantJSON: vlessOut("nas.lan", "443", plainUser,
			`{"network":"xhttp","xhttpSettings":{"mode":"packet-up","path":"/x"}}`),
	},
	{
		name:     "xhttp mode defaults to auto",
		link:     vlessPlain + "?type=xhttp&host=front.example.com",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser,
			`{"network":"xhttp","xhttpSettings":{"host":"front.example.com","mode":"auto"}}`),
	},
	{
		name:     "splithttp is xhttp",
		link:     vlessPlain + "?type=splithttp&path=/x",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser,
			`{"network":"xhttp","xhttpSettings":{"mode":"auto","path":"/x"}}`),
	},
	{
		name:     "httpupgrade",
		link:     vlessPlain + "?type=httpupgrade&path=/up&host=up.example.com",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser,
			`{"network":"httpupgrade","httpupgradeSettings":{"host":"up.example.com","path":"/up"}}`),
	},
	{
		name:     "httpupgrade with nothing set",
		link:     vlessPlain + "?type=httpupgrade",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"httpupgrade","httpupgradeSettings":{}}`),
	},
	{
		name:     "raw with an empty security",
		link:     vlessPlain + "?type=raw&security=",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"tcp"}`),
	},
	{
		name:     "no query at all",
		link:     vlessPlain,
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"tcp"}`),
	},
	{
		name:     "security none has no tls settings",
		link:     vlessPlain + "?type=tcp&security=none&sni=ignored.example.com",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"tcp"}`),
	},
	{
		name:     "tcp with an http header",
		link:     vlessPlain + "?type=tcp&headerType=http&host=front.example.com&path=/h",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser,
			`{"network":"tcp","tcpSettings":{"header":{"request":{"headers":{"Host":["front.example.com"]},"path":["/h"]},"type":"http"}}}`),
	},
	{
		name:     "tcp http header without host or path",
		link:     vlessPlain + "?headerType=http",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser,
			`{"network":"tcp","tcpSettings":{"header":{"request":{"headers":{},"path":["/"]},"type":"http"}}}`),
	},
	{
		name:     "tcp header type none",
		link:     vlessPlain + "?type=tcp&headerType=none&host=ignored.example.com&path=/ignored",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"tcp"}`),
	},
	{
		name:     "header type does not apply to websocket",
		link:     vlessPlain + "?type=ws&headerType=http&path=/w",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"ws","wsSettings":{"path":"/w"}}`),
	},
	{
		name:     "network and security are case-insensitive",
		link:     vlessBase + "?type=WS&security=TLS&sni=a.example.com",
		wantName: "example.com:443",
		wantJSON: vlessOut("example.com", "443", plainUser,
			`{"network":"ws","security":"tls","tlsSettings":{"serverName":"a.example.com"},"wsSettings":{"path":"/"}}`),
	},
	// xray-core refuses allowInsecure, so no outbound carries it: the link
	// still parses, with verification on and a warning.
	{
		name:         "allowInsecure is never emitted",
		link:         vlessBase + "?security=tls&sni=a.example.com&fp=firefox&allowInsecure=1",
		wantName:     "example.com:443",
		wantWarnings: []string{warnInsecureRemoved},
		wantJSON: vlessOut("example.com", "443", plainUser,
			`{"network":"tcp","security":"tls","tlsSettings":{"fingerprint":"firefox","serverName":"a.example.com"}}`),
	},
	{
		name:         "insecure true is not emitted either",
		link:         vlessBase + "?security=tls&insecure=true",
		wantName:     "example.com:443",
		wantWarnings: []string{warnInsecureRemoved},
		wantJSON:     vlessOut("example.com", "443", plainUser, `{"network":"tcp","security":"tls","tlsSettings":{}}`),
	},
	{
		name:         "allowInsecure True counts as insecure",
		link:         vlessBase + "?security=tls&allowInsecure=True",
		wantName:     "example.com:443",
		wantWarnings: []string{warnInsecureRemoved},
		wantJSON:     vlessOut("example.com", "443", plainUser, `{"network":"tcp","security":"tls","tlsSettings":{}}`),
	},
	{
		name:         "insecure TRUE counts as insecure",
		link:         vlessBase + "?security=tls&insecure=TRUE",
		wantName:     "example.com:443",
		wantWarnings: []string{warnInsecureRemoved},
		wantJSON:     vlessOut("example.com", "443", plainUser, `{"network":"tcp","security":"tls","tlsSettings":{}}`),
	},
	{
		name:     "tls with allowInsecure off",
		link:     vlessBase + "?security=tls&allowInsecure=0&insecure=false",
		wantName: "example.com:443",
		wantJSON: vlessOut("example.com", "443", plainUser, `{"network":"tcp","security":"tls","tlsSettings":{}}`),
	},
	{
		name:         "tls with only one of the insecure flags on",
		link:         vlessBase + "?security=tls&allowInsecure=0&insecure=1",
		wantName:     "example.com:443",
		wantWarnings: []string{warnInsecureRemoved},
		wantJSON:     vlessOut("example.com", "443", plainUser, `{"network":"tcp","security":"tls","tlsSettings":{}}`),
	},
	{
		name:         "both insecure flags give one warning",
		link:         vlessBase + "?security=tls&allowInsecure=1&insecure=1",
		wantName:     "example.com:443",
		wantWarnings: []string{warnInsecureRemoved},
		wantJSON:     vlessOut("example.com", "443", plainUser, `{"network":"tcp","security":"tls","tlsSettings":{}}`),
	},
	{
		name:     "insecure without tls has nothing to warn about",
		link:     vlessPlain + "?security=none&allowInsecure=1",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"tcp"}`),
	},
	{
		name:     "pcs pins the certificate",
		link:     vlessBase + "?security=tls&sni=a.example.com&pcs=" + pinA,
		wantName: "example.com:443",
		wantJSON: vlessOut("example.com", "443", plainUser,
			`{"network":"tcp","security":"tls","tlsSettings":{"pinnedPeerCertSha256":"`+pinA+`","serverName":"a.example.com"}}`),
	},
	{
		name:     "pcs replaces the insecure flag, with no warning",
		link:     vlessBase + "?security=tls&allowInsecure=1&insecure=true&pcs=" + pinA,
		wantName: "example.com:443",
		wantJSON: vlessOut("example.com", "443", plainUser,
			`{"network":"tcp","security":"tls","tlsSettings":{"pinnedPeerCertSha256":"`+pinA+`"}}`),
	},
	{
		name:     "pcs is given as it is, trimmed",
		link:     vlessBase + "?security=tls&pcs=%20" + pinA + "," + pinB + "%20",
		wantName: "example.com:443",
		wantJSON: vlessOut("example.com", "443", plainUser,
			`{"network":"tcp","security":"tls","tlsSettings":{"pinnedPeerCertSha256":"`+pinA+","+pinB+`"}}`),
	},
	{
		name:         "a blank pcs does not count as a pin",
		link:         vlessBase + "?security=tls&allowInsecure=1&pcs=%20",
		wantName:     "example.com:443",
		wantWarnings: []string{warnInsecureRemoved},
		wantJSON:     vlessOut("example.com", "443", plainUser, `{"network":"tcp","security":"tls","tlsSettings":{}}`),
	},
	{
		name:     "vcn names the certificate",
		link:     vlessBase + "?security=tls&sni=a.example.com&vcn=real.example.com&pcs=" + pinA,
		wantName: "example.com:443",
		wantJSON: vlessOut("example.com", "443", plainUser,
			`{"network":"tcp","security":"tls","tlsSettings":{"pinnedPeerCertSha256":"`+pinA+`","serverName":"a.example.com","verifyPeerCertByName":"real.example.com"}}`),
	},
	{
		name:     "vcn alone",
		link:     vlessBase + "?security=tls&vcn=real.example.com",
		wantName: "example.com:443",
		wantJSON: vlessOut("example.com", "443", plainUser,
			`{"network":"tcp","security":"tls","tlsSettings":{"verifyPeerCertByName":"real.example.com"}}`),
	},
	{
		name:         "vcn does not stop the insecure warning",
		link:         vlessBase + "?security=tls&insecure=1&vcn=real.example.com",
		wantName:     "example.com:443",
		wantWarnings: []string{warnInsecureRemoved},
		wantJSON: vlessOut("example.com", "443", plainUser,
			`{"network":"tcp","security":"tls","tlsSettings":{"verifyPeerCertByName":"real.example.com"}}`),
	},
	{
		name:     "pcs and vcn are for tls only",
		link:     vlessPlain + "?security=none&pcs=" + pinA + "&vcn=real.example.com",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"tcp"}`),
	},
	{
		name:     "pcs and vcn are not reality settings",
		link:     vlessBase + "?security=reality&pbk=" + vlessPBK + "&pcs=" + pinA + "&vcn=real.example.com",
		wantName: "example.com:443",
		wantJSON: vlessOut("example.com", "443", plainUser,
			`{"network":"tcp","realitySettings":{"fingerprint":"chrome","publicKey":"`+vlessPBK+`"},"security":"reality"}`),
	},
	{
		name:     "alpn is trimmed and split on commas",
		link:     vlessBase + "?security=tls&alpn=h2%2C%20http/1.1,,",
		wantName: "example.com:443",
		wantJSON: vlessOut("example.com", "443", plainUser,
			`{"network":"tcp","security":"tls","tlsSettings":{"alpn":["h2","http/1.1"]}}`),
	},
	{
		name:     "flow and a post-quantum encryption pass through",
		link:     vlessBase + "?encryption=mlkem768x25519plus.native.0rtt.dGVzdC1rZXk&flow=xtls-rprx-vision",
		wantName: "example.com:443",
		wantJSON: vlessOut("example.com", "443",
			`{"encryption":"mlkem768x25519plus.native.0rtt.dGVzdC1rZXk","flow":"xtls-rprx-vision","id":"`+vlessID+`"}`,
			`{"network":"tcp"}`),
	},
	{
		name:     "encryption none is explicit",
		link:     vlessPlain + "?encryption=none",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"tcp"}`),
	},
	{
		name:     "reality fingerprint defaults to chrome",
		link:     vlessBase + "?security=reality&pbk=" + vlessPBK + "&sni=www.example.com&spx=%2F",
		wantName: "example.com:443",
		wantJSON: vlessOut("example.com", "443", plainUser,
			`{"network":"tcp","realitySettings":{"fingerprint":"chrome","publicKey":"`+vlessPBK+`","serverName":"www.example.com","spiderX":"/"},"security":"reality"}`),
	},
	{
		name:     "reality over grpc",
		link:     vlessBase + "?type=grpc&serviceName=gun&security=reality&pbk=" + vlessPBK + "&fp=safari&sid=ab",
		wantName: "example.com:443",
		wantJSON: vlessOut("example.com", "443", plainUser,
			`{"network":"grpc","grpcSettings":{"multiMode":false,"serviceName":"gun"},"realitySettings":{"fingerprint":"safari","publicKey":"`+vlessPBK+`","shortId":"ab"},"security":"reality"}`),
	},
	{
		name:     "reality over xhttp",
		link:     vlessBase + "?type=xhttp&path=/r&security=reality&pbk=" + vlessPBK,
		wantName: "example.com:443",
		wantJSON: vlessOut("example.com", "443", plainUser,
			`{"network":"xhttp","realitySettings":{"fingerprint":"chrome","publicKey":"`+vlessPBK+`"},"security":"reality","xhttpSettings":{"mode":"auto","path":"/r"}}`),
	},
	{
		name:     "reality ignores allowInsecure",
		link:     vlessBase + "?security=reality&pbk=" + vlessPBK + "&allowInsecure=1",
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
		link:     "vless://" + vlessID + "@nas.lan:65535",
		wantName: "nas.lan:65535",
		wantJSON: vlessOut("nas.lan", "65535", plainUser, `{"network":"tcp"}`),
	},
	{
		name:     "fragment is trimmed",
		link:     vlessPlain + "#%20%20node%20one%20%20",
		wantName: "node one",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"tcp"}`),
	},

	{
		name:     "a bare percent in the name",
		link:     vlessPlain + "#50%",
		wantName: "50%",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"tcp"}`),
	},
	{
		name:     "a short escape in the name",
		link:     vlessPlain + "#a%2",
		wantName: "a%2",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"tcp"}`),
	},
	{
		name:     "a percent in a name beside a bad query parameter nobody reads",
		link:     vlessPlain + "?remark=50%&type=ws#🔥 20% off",
		wantName: "🔥 20% off",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"ws","wsSettings":{"path":"/"}}`),
	},

	// xray-core 26.7.11 and newer refuse the whole config for VLESS with no TLS
	// and no encryption to a public address.
	{
		name:        "no security to a public IP is refused",
		link:        "vless://" + vlessID + "@1.2.3.4:443",
		wantErr:     kindUnsupported,
		refused:     true,
		errContains: "VLESS",
		secret:      vlessID,
	},
	{
		name:        "security none to a public IP is refused",
		link:        "vless://" + vlessID + "@1.2.3.4:443?security=none&type=ws",
		wantErr:     kindUnsupported,
		refused:     true,
		errContains: "VLESS",
		secret:      vlessID,
	},
	{
		name:        "security none to a public domain is refused",
		link:        vlessBase + "?security=none",
		wantErr:     kindUnsupported,
		refused:     true,
		errContains: "public address",
		secret:      vlessID,
	},
	{
		name:     "security none to a private IP",
		link:     "vless://" + vlessID + "@203.0.113.10:443?security=none",
		wantName: "203.0.113.10:443",
		wantJSON: vlessOut("203.0.113.10", "443", plainUser, `{"network":"tcp"}`),
	},
	{
		name:     "security none to a private domain",
		link:     "vless://" + vlessID + "@nas.lan:443",
		wantName: "nas.lan:443",
		wantJSON: vlessOut("nas.lan", "443", plainUser, `{"network":"tcp"}`),
	},
	{
		name:     "security none to a dotless name",
		link:     "vless://" + vlessID + "@nas:443",
		wantName: "nas:443",
		wantJSON: vlessOut("nas", "443", plainUser, `{"network":"tcp"}`),
	},
	{
		name:     "tls to a public IP",
		link:     "vless://" + vlessID + "@1.2.3.4:443?security=tls",
		wantName: "1.2.3.4:443",
		wantJSON: vlessOut("1.2.3.4", "443", plainUser, `{"network":"tcp","security":"tls","tlsSettings":{}}`),
	},
	{
		name:     "reality to a public IP",
		link:     "vless://" + vlessID + "@1.2.3.4:443?security=reality&pbk=" + vlessPBK,
		wantName: "1.2.3.4:443",
		wantJSON: vlessOut("1.2.3.4", "443", plainUser,
			`{"network":"tcp","realitySettings":{"fingerprint":"chrome","publicKey":"`+vlessPBK+`"},"security":"reality"}`),
	},
	{
		name:     "a post-quantum encryption to a public IP",
		link:     "vless://" + vlessID + "@1.2.3.4:443?encryption=mlkem768x25519plus.native.0rtt.dGVzdC1rZXk",
		wantName: "1.2.3.4:443",
		wantJSON: vlessOut("1.2.3.4", "443",
			`{"encryption":"mlkem768x25519plus.native.0rtt.dGVzdC1rZXk","id":"`+vlessID+`"}`,
			`{"network":"tcp"}`),
	},

	{name: "kcp", link: vlessBase + "?type=kcp&seed=x", wantErr: kindUnsupported, secret: vlessID},
	{name: "mkcp", link: vlessBase + "?type=mkcp", wantErr: kindUnsupported, secret: vlessID},
	{name: "quic", link: vlessBase + "?type=quic", wantErr: kindUnsupported, secret: vlessID},
	{name: "h2", link: vlessBase + "?type=h2&security=tls", wantErr: kindUnsupported, secret: vlessID},
	{name: "http", link: vlessBase + "?type=http", wantErr: kindUnsupported, secret: vlessID},
	{name: "unknown network", link: vlessBase + "?type=carrier-pigeon", wantErr: kindInvalid, secret: vlessID},
	{name: "reality without a public key", link: vlessBase + "?security=reality&sni=www.example.com&sid=ab", wantErr: kindInvalid, secret: vlessID},
	{name: "reality over websocket", link: vlessBase + "?type=ws&security=reality&pbk=" + vlessPBK, wantErr: kindInvalid, secret: vlessID},
	{name: "reality over httpupgrade", link: vlessBase + "?type=httpupgrade&security=reality&pbk=" + vlessPBK, wantErr: kindInvalid, secret: vlessID},
	{name: "unknown security", link: vlessBase + "?security=foo", wantErr: kindInvalid, secret: vlessID},
	{name: "legacy xtls security", link: vlessBase + "?security=xtls", wantErr: kindInvalid, secret: vlessID},
	{name: "unknown tcp header type", link: vlessBase + "?type=tcp&headerType=srtp", wantErr: kindInvalid, secret: vlessID},
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
	{name: "malformed escape in the query", link: vlessBase + "?type=ws&path=%zz", wantErr: kindInvalid, secret: vlessID},
	{name: "semicolon in the query", link: vlessBase + "?security=tls&alpn=h2;http/1.1", wantErr: kindInvalid, secret: vlessID},
	{name: "malformed escape in the encryption", link: vlessBase + "?encryption=%zz", wantErr: kindInvalid, errContains: `"encryption"`, secret: vlessID},
	{name: "malformed escape in the flow", link: vlessBase + "?flow=xtls-rprx-vision%", wantErr: kindInvalid, errContains: `"flow"`, secret: vlessID},
	{name: "malformed escape in the id", link: "vless://secret%zz@example.com:443", wantErr: kindInvalid, secret: "secret"},
	// A parameter can hold anything, even the id, and no error repeats it.
	{name: "unknown tcp header that is the id", link: vlessBase + "?headerType=" + vlessID, wantErr: kindInvalid, secret: vlessID},
	{name: "unknown network that is the id", link: vlessBase + "?type=" + vlessID, wantErr: kindInvalid, secret: vlessID},
	{name: "unknown security that is the id", link: vlessBase + "?security=" + vlessID, wantErr: kindInvalid, secret: vlessID},
}

func TestParseVLESS(t *testing.T) { runParseCases(t, vlessCases) }
