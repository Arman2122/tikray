package sharelink

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"
)

const vmessID = "5783a3e7-e373-51cd-8642-c83782b807c5"

// vmessLink is a vmess link for the JSON body, encoded the given way.
func vmessLink(enc *base64.Encoding, js string) string {
	return "vmess://" + enc.EncodeToString([]byte(js))
}

// stdLink is a vmess link with a padded standard base64 body, which is what
// most apps write.
func stdLink(js string) string { return vmessLink(base64.StdEncoding, js) }

// vmessJSON is a body with just the three fields that a link must have, and
// then the extra JSON members, if any.
func vmessJSON(extra string) string {
	js := `{"add":"example.com","port":443,"id":"` + vmessID + `"`
	if extra != "" {
		js += "," + extra
	}
	return js + "}"
}

// vmessOut is the expected VMess outbound for one user with the given
// security, with the given streamSettings JSON.
func vmessOut(addr, port, security, stream string) string {
	return `{"protocol":"vmess","settings":{"vnext":[{"address":"` + addr + `","port":` + port + `,"users":[{"id":"` + vmessID + `","security":"` + security + `"}]}]},"streamSettings":` + stream + `}`
}

const (
	// vmessWSJSON is the body of a websocket link over TLS, the way v2rayN
	// writes it: the port and aid are strings, and the name is Persian.
	vmessWSJSON = `{"v":"2","ps":"سرور","add":"example.com","port":"443","id":"` + vmessID + `","aid":"0","net":"ws","type":"none","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"cdn.example.com","alpn":"h2,http/1.1","fp":"chrome"}`
	vmessWSOut  = `{"network":"ws","security":"tls","tlsSettings":{"alpn":["h2","http/1.1"],"fingerprint":"chrome","serverName":"cdn.example.com"},"wsSettings":{"host":"cdn.example.com","path":"/ws"}}`

	// vmessAlphabetJSON is a body whose standard base64 has a + and a / and one
	// padding character, so that the two alphabets and the padding all show.
	vmessAlphabetJSON = `{"ps":"سرور","add":"example.com","port":"443","id":"` + vmessID + `","aid":"0","net":"ws","host":"cdn.example.com","path":"/ws????>","tls":"tls","sni":"cdn.example.com"}`
	vmessAlphabetOut  = `{"network":"ws","security":"tls","tlsSettings":{"serverName":"cdn.example.com"},"wsSettings":{"host":"cdn.example.com","path":"/ws????>"}}`
)

// vmessFlagCases are bodies with an allowInsecure value, over TLS, and what
// Parse must make of each.
func vmessFlagCases() []parseCase {
	const out = `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}`
	var cases []parseCase
	for _, v := range []string{`true`, `1`, `"1"`, `"true"`, `"TRUE"`, `"True"`, `" true "`} {
		cases = append(cases, parseCase{
			name:         "allowInsecure " + v + " warns",
			link:         stdLink(vmessJSON(`"tls":"tls","sni":"example.com","allowInsecure":` + v)),
			wantName:     "example.com:443",
			wantWarnings: []string{warnInsecureRemoved},
			wantJSON:     vmessOut("example.com", "443", "auto", out),
		})
	}
	for _, v := range []string{`false`, `0`, `""`, `"false"`, `"0"`, `null`, `2`, `"yes"`} {
		cases = append(cases, parseCase{
			name:     "allowInsecure " + v + " is off",
			link:     stdLink(vmessJSON(`"tls":"tls","sni":"example.com","allowInsecure":` + v)),
			wantName: "example.com:443",
			wantJSON: vmessOut("example.com", "443", "auto", out),
		})
	}
	return cases
}

// vmessCases are the VMess links Parse must read or refuse. The fuzz test
// seeds from them too.
var vmessCases = slices.Concat([]parseCase{
	{
		name:     "websocket over tls, string port and aid, persian name",
		link:     stdLink(vmessWSJSON),
		wantName: "سرور",
		wantJSON: vmessOut("example.com", "443", "auto", vmessWSOut),
	},
	{
		name:     "standard alphabet, padded",
		link:     vmessLink(base64.StdEncoding, vmessAlphabetJSON),
		wantName: "سرور",
		wantJSON: vmessOut("example.com", "443", "auto", vmessAlphabetOut),
	},
	{
		name:     "standard alphabet, unpadded",
		link:     vmessLink(base64.RawStdEncoding, vmessAlphabetJSON),
		wantName: "سرور",
		wantJSON: vmessOut("example.com", "443", "auto", vmessAlphabetOut),
	},
	{
		name:     "url alphabet, padded",
		link:     vmessLink(base64.URLEncoding, vmessAlphabetJSON),
		wantName: "سرور",
		wantJSON: vmessOut("example.com", "443", "auto", vmessAlphabetOut),
	},
	{
		name:     "url alphabet, unpadded",
		link:     vmessLink(base64.RawURLEncoding, vmessAlphabetJSON),
		wantName: "سرور",
		wantJSON: vmessOut("example.com", "443", "auto", vmessAlphabetOut),
	},
	{
		name:     "only the three required fields",
		link:     stdLink(vmessJSON("")),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "number port, ip address, no name",
		link:     stdLink(`{"add":"1.2.3.4","port":8443,"id":"` + vmessID + `"}`),
		wantName: "1.2.3.4:8443",
		wantJSON: vmessOut("1.2.3.4", "8443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "values with spaces around them",
		link:     stdLink(`{"ps":"  lab  ","add":" example.com ","port":" 443 ","id":" ` + vmessID + ` ","aid":" 0 ","scy":" none ","tls":" tls "}`),
		wantName: "lab",
		wantJSON: vmessOut("example.com", "443", "none", `{"network":"tcp","security":"tls","tlsSettings":{}}`),
	},
	{
		name:     "unknown fields and a version are ignored",
		link:     stdLink(vmessJSON(`"v":"2","extra":{"a":[1,2]},"remark":null`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "ipv6 address in brackets",
		link:     stdLink(`{"add":"[2001:db8::1]","port":8443,"id":"` + vmessID + `"}`),
		wantName: "[2001:db8::1]:8443",
		wantJSON: vmessOut("2001:db8::1", "8443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "ipv6 address without brackets",
		link:     stdLink(`{"add":"2001:db8::1","port":8443,"id":"` + vmessID + `","ps":"six"}`),
		wantName: "six",
		wantJSON: vmessOut("2001:db8::1", "8443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "internationalized host name",
		link:     stdLink(`{"add":"bücher.example","port":443,"id":"` + vmessID + `"}`),
		wantName: "bücher.example:443",
		wantJSON: vmessOut("bücher.example", "443", "auto", `{"network":"tcp"}`),
	},
	// The name after the #: used when ps says nothing, never over a ps.
	{
		name:     "a name after the body, when there is no ps",
		link:     stdLink(vmessJSON("")) + "#name",
		wantName: "name",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "a name after the body, when ps is empty",
		link:     stdLink(vmessJSON(`"ps":""`)) + "#name",
		wantName: "name",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "a name after the body, when ps is blank",
		link:     stdLink(vmessJSON(`"ps":"  "`)) + "#name",
		wantName: "name",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "ps wins over the name after the body",
		link:     stdLink(vmessJSON(`"ps":"from ps"`)) + "#from fragment",
		wantName: "from ps",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "a percent-encoded name after the body",
		link:     stdLink(vmessJSON("")) + "#lab%20%F0%9F%9A%80",
		wantName: "lab 🚀",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "a name after the body with a bad escape stays raw",
		link:     stdLink(vmessJSON("")) + "#50%",
		wantName: "50%",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "an empty name after the body",
		link:     stdLink(vmessJSON("")) + "#",
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "a name after the body that has a question mark and a second hash",
		link:     stdLink(vmessJSON("")) + "#why?#not",
		wantName: "why?#not",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "a name after an unpadded url-alphabet body is cut off before decoding, and ps still wins",
		link:     vmessLink(base64.RawURLEncoding, vmessAlphabetJSON) + "#late",
		wantName: "سرور",
		wantJSON: vmessOut("example.com", "443", "auto", vmessAlphabetOut),
	},
	{
		name:     "a name with an at sign after the body is not the url form",
		link:     stdLink(vmessJSON("")) + "#user@host",
		wantName: "user@host",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "control characters in ps are dropped",
		link:     stdLink(vmessJSON(`"ps":"\u001b[2J\nlab\u202e-a"`)),
		wantName: "[2Jlab-a",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "a long name is cut to 128 runes",
		link:     stdLink(vmessJSON(`"ps":"` + strings.Repeat("é", 200) + `"`)),
		wantName: strings.Repeat("é", 128),
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},

	// security
	{name: "aes-128-gcm", link: stdLink(vmessJSON(`"scy":"aes-128-gcm"`)), wantName: "example.com:443", wantJSON: vmessOut("example.com", "443", "aes-128-gcm", `{"network":"tcp"}`)},
	{name: "chacha20-poly1305", link: stdLink(vmessJSON(`"scy":"chacha20-poly1305"`)), wantName: "example.com:443", wantJSON: vmessOut("example.com", "443", "chacha20-poly1305", `{"network":"tcp"}`)},
	{name: "none", link: stdLink(vmessJSON(`"scy":"none"`)), wantName: "example.com:443", wantJSON: vmessOut("example.com", "443", "none", `{"network":"tcp"}`)},
	{name: "zero", link: stdLink(vmessJSON(`"scy":"zero"`)), wantName: "example.com:443", wantJSON: vmessOut("example.com", "443", "zero", `{"network":"tcp"}`)},
	{name: "auto", link: stdLink(vmessJSON(`"scy":"auto"`)), wantName: "example.com:443", wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`)},
	{name: "an empty security is auto", link: stdLink(vmessJSON(`"scy":""`)), wantName: "example.com:443", wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`)},
	{name: "a null security is auto", link: stdLink(vmessJSON(`"scy":null`)), wantName: "example.com:443", wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`)},
	{name: "security in upper case", link: stdLink(vmessJSON(`"scy":"AES-128-GCM"`)), wantName: "example.com:443", wantJSON: vmessOut("example.com", "443", "aes-128-gcm", `{"network":"tcp"}`)},

	// aid: zero in any spelling is the only value xray reads
	{name: "aid zero as a number", link: stdLink(vmessJSON(`"aid":0`)), wantName: "example.com:443", wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`)},
	{name: "aid zero as a string", link: stdLink(vmessJSON(`"aid":"0"`)), wantName: "example.com:443", wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`)},
	{name: "aid empty", link: stdLink(vmessJSON(`"aid":""`)), wantName: "example.com:443", wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`)},
	{name: "aid null", link: stdLink(vmessJSON(`"aid":null`)), wantName: "example.com:443", wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`)},

	// transports
	{
		name:     "tcp with an http header",
		link:     stdLink(vmessJSON(`"net":"tcp","type":"http","host":"a.example.com","path":"/p"`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto",
			`{"network":"tcp","tcpSettings":{"header":{"request":{"headers":{"Host":["a.example.com"]},"path":["/p"]},"type":"http"}}}`),
	},
	{
		name:     "tcp with no header",
		link:     stdLink(vmessJSON(`"net":"tcp","type":"none","host":"a.example.com","path":"/p"`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "raw is tcp",
		link:     stdLink(vmessJSON(`"net":"raw"`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},
	{
		// The type of a websocket link is "none" and is no header.
		name:     "websocket ignores the type and defaults the path",
		link:     stdLink(vmessJSON(`"net":"ws","type":"http"`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"ws","wsSettings":{"path":"/"}}`),
	},
	{
		name:     "grpc: the path is the service, the host the authority, the type the mode",
		link:     stdLink(vmessJSON(`"net":"grpc","path":"gun","host":"front.example.com","type":"multi","tls":"tls"`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto",
			`{"network":"grpc","grpcSettings":{"authority":"front.example.com","multiMode":true,"serviceName":"gun"},"security":"tls","tlsSettings":{"serverName":"front.example.com"}}`),
	},
	{
		name:     "grpc gun is a single stream",
		link:     stdLink(vmessJSON(`"net":"grpc","path":"gun","type":"gun"`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"grpc","grpcSettings":{"multiMode":false,"serviceName":"gun"}}`),
	},
	{
		name:     "grpc with a type of none is a single stream",
		link:     stdLink(vmessJSON(`"net":"grpc","path":"gun","type":"none"`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"grpc","grpcSettings":{"multiMode":false,"serviceName":"gun"}}`),
	},
	{
		name:     "httpupgrade",
		link:     stdLink(vmessJSON(`"net":"httpupgrade","path":"/hu","host":"cdn.example.com","type":"none"`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"httpupgrade","httpupgradeSettings":{"host":"cdn.example.com","path":"/hu"}}`),
	},
	{
		name:     "xhttp: the type is the mode",
		link:     stdLink(vmessJSON(`"net":"xhttp","path":"/x","host":"cdn.example.com","type":"packet-up"`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"xhttp","xhttpSettings":{"host":"cdn.example.com","mode":"packet-up","path":"/x"}}`),
	},
	{
		// A type of none says nothing: it must not become an xhttp mode, which
		// xray would refuse.
		name:     "xhttp with a type of none has the auto mode",
		link:     stdLink(vmessJSON(`"net":"xhttp","path":"/x","type":"none"`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"xhttp","xhttpSettings":{"mode":"auto","path":"/x"}}`),
	},
	{
		name:     "splithttp is xhttp",
		link:     stdLink(vmessJSON(`"net":"splithttp","path":"/x"`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"xhttp","xhttpSettings":{"mode":"auto","path":"/x"}}`),
	},

	// tls
	{
		name:     "tls without sni takes the first host",
		link:     stdLink(`{"add":"203.0.113.10","port":443,"id":"` + vmessID + `","net":"ws","host":"a.example.com, b.example.com","path":"/ws","tls":"tls"}`),
		wantName: "203.0.113.10:443",
		wantJSON: vmessOut("203.0.113.10", "443", "auto",
			`{"network":"ws","security":"tls","tlsSettings":{"serverName":"a.example.com"},"wsSettings":{"host":"a.example.com, b.example.com","path":"/ws"}}`),
	},
	{
		name:     "an sni wins over the host",
		link:     stdLink(`{"add":"203.0.113.10","port":443,"id":"` + vmessID + `","net":"ws","host":"a.example.com","path":"/ws","tls":"tls","sni":"front.example.com"}`),
		wantName: "203.0.113.10:443",
		wantJSON: vmessOut("203.0.113.10", "443", "auto",
			`{"network":"ws","security":"tls","tlsSettings":{"serverName":"front.example.com"},"wsSettings":{"host":"a.example.com","path":"/ws"}}`),
	},
	{name: "tls none", link: stdLink(vmessJSON(`"tls":"none","sni":"example.com"`)), wantName: "example.com:443", wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`)},
	{name: "tls empty", link: stdLink(vmessJSON(`"tls":"","sni":"example.com"`)), wantName: "example.com:443", wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`)},
	{name: "tls in upper case", link: stdLink(vmessJSON(`"tls":"TLS"`)), wantName: "example.com:443", wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp","security":"tls","tlsSettings":{}}`)},
	{
		name:     "a pinned certificate",
		link:     stdLink(vmessJSON(`"tls":"tls","sni":"example.com","pcs":"` + pinA + `","vcn":"example.com"`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto",
			`{"network":"tcp","security":"tls","tlsSettings":{"pinnedPeerCertSha256":"`+pinA+`","serverName":"example.com","verifyPeerCertByName":"example.com"}}`),
	},
	{
		name:     "allowInsecure with a pinned certificate has no warning",
		link:     stdLink(vmessJSON(`"tls":"tls","allowInsecure":true,"pcs":"` + pinA + `"`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto",
			`{"network":"tcp","security":"tls","tlsSettings":{"pinnedPeerCertSha256":"`+pinA+`"}}`),
	},
	{
		name:     "allowInsecure without tls has no warning",
		link:     stdLink(vmessJSON(`"tls":"none","allowInsecure":true`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},
	{
		name:     "pcs and vcn without tls are ignored",
		link:     stdLink(vmessJSON(`"pcs":"` + pinA + `","vcn":"example.com"`)),
		wantName: "example.com:443",
		wantJSON: vmessOut("example.com", "443", "auto", `{"network":"tcp"}`),
	},

	// refused
	{name: "aid 64", link: stdLink(vmessJSON(`"aid":64,"scy":"auto"`)), wantErr: kindUnsupported, errContains: "alterId", secret: vmessID},
	{name: "aid 64 as a string", link: stdLink(vmessJSON(`"aid":"64"`)), wantErr: kindUnsupported, secret: vmessID},
	{name: "aid 1", link: stdLink(vmessJSON(`"aid":1`)), wantErr: kindUnsupported, secret: vmessID},
	{name: "aid negative", link: stdLink(vmessJSON(`"aid":-1`)), wantErr: kindUnsupported, secret: vmessID},
	{name: "aid not a number", link: stdLink(vmessJSON(`"aid":"many"`)), wantErr: kindInvalid, errContains: `"aid"`, secret: vmessID},
	{name: "aid a boolean", link: stdLink(vmessJSON(`"aid":true`)), wantErr: kindInvalid, errContains: `"aid"`, secret: vmessID},
	{name: "kcp", link: stdLink(vmessJSON(`"net":"kcp","type":"srtp"`)), wantErr: kindUnsupported, secret: vmessID},
	{name: "h2", link: stdLink(vmessJSON(`"net":"h2","tls":"tls"`)), wantErr: kindUnsupported, secret: vmessID},
	{name: "quic", link: stdLink(vmessJSON(`"net":"quic"`)), wantErr: kindUnsupported, secret: vmessID},
	{name: "unknown network", link: stdLink(vmessJSON(`"net":"carrier-pigeon"`)), wantErr: kindInvalid, secret: vmessID},
	{name: "unknown tcp header", link: stdLink(vmessJSON(`"type":"srtp"`)), wantErr: kindInvalid, secret: vmessID},
	{name: "unknown security", link: stdLink(vmessJSON(`"scy":"aes-128-cfb"`)), wantErr: kindInvalid, errContains: "chacha20-poly1305", secret: vmessID},
	{name: "legacy security", link: stdLink(vmessJSON(`"scy":"legacy"`)), wantErr: kindInvalid, secret: vmessID},
	{name: "tls reality", link: stdLink(vmessJSON(`"tls":"reality"`)), wantErr: kindInvalid, secret: vmessID},
	{name: "tls a boolean", link: stdLink(vmessJSON(`"tls":true`)), wantErr: kindInvalid, errContains: `"tls"`, secret: vmessID},
	{name: "name an object", link: stdLink(vmessJSON(`"ps":{"a":1}`)), wantErr: kindInvalid, errContains: `"ps"`, secret: vmessID},
	{name: "path an array", link: stdLink(vmessJSON(`"net":"ws","path":["/a"]`)), wantErr: kindInvalid, errContains: `"path"`, secret: vmessID},
	{name: "allowInsecure an object", link: stdLink(vmessJSON(`"allowInsecure":{}`)), wantErr: kindInvalid, errContains: `"allowInsecure"`, secret: vmessID},
	{name: "a pinned certificate of the wrong type", link: stdLink(vmessJSON(`"tls":"tls","pcs":[1]`)), wantErr: kindInvalid, errContains: `"pcs"`, secret: vmessID},

	// the address, the port and the id
	{name: "no address", link: stdLink(`{"port":443,"id":"` + vmessID + `"}`), wantErr: kindInvalid, errContains: "address", secret: vmessID},
	{name: "empty address", link: stdLink(`{"add":"  ","port":443,"id":"` + vmessID + `"}`), wantErr: kindInvalid, secret: vmessID},
	{name: "address with a space", link: stdLink(`{"add":"bad host","port":443,"id":"` + vmessID + `"}`), wantErr: kindInvalid, secret: vmessID},
	{name: "address that is a url", link: stdLink(`{"add":"https://example.com/","port":443,"id":"` + vmessID + `"}`), wantErr: kindInvalid, secret: vmessID},
	{name: "address with a port", link: stdLink(`{"add":"example.com:443","port":443,"id":"` + vmessID + `"}`), wantErr: kindInvalid, secret: vmessID},
	{name: "address with a zone", link: stdLink(`{"add":"fe80::1%eth0","port":443,"id":"` + vmessID + `"}`), wantErr: kindInvalid, secret: vmessID},
	{name: "brackets around a name", link: stdLink(`{"add":"[example.com]","port":443,"id":"` + vmessID + `"}`), wantErr: kindInvalid, secret: vmessID},
	{name: "no port", link: stdLink(`{"add":"example.com","id":"` + vmessID + `"}`), wantErr: kindInvalid, errContains: "port", secret: vmessID},
	{name: "port zero", link: stdLink(`{"add":"example.com","port":0,"id":"` + vmessID + `"}`), wantErr: kindInvalid, secret: vmessID},
	{name: "port too high", link: stdLink(`{"add":"example.com","port":"70000","id":"` + vmessID + `"}`), wantErr: kindInvalid, secret: vmessID},
	{name: "port not a number", link: stdLink(`{"add":"example.com","port":"https","id":"` + vmessID + `"}`), wantErr: kindInvalid, secret: vmessID},
	{name: "port with a sign", link: stdLink(`{"add":"example.com","port":"+443","id":"` + vmessID + `"}`), wantErr: kindInvalid, secret: vmessID},
	{name: "port a fraction", link: stdLink(`{"add":"example.com","port":443.5,"id":"` + vmessID + `"}`), wantErr: kindInvalid, secret: vmessID},
	{name: "port a boolean", link: stdLink(`{"add":"example.com","port":true,"id":"` + vmessID + `"}`), wantErr: kindInvalid, errContains: `"port"`, secret: vmessID},
	{name: "no id", link: stdLink(`{"add":"example.com","port":443}`), wantErr: kindInvalid, errContains: "id"},
	{name: "empty id", link: stdLink(`{"add":"example.com","port":443,"id":" "}`), wantErr: kindInvalid, errContains: "id"},
	{name: "id an object", link: stdLink(`{"add":"example.com","port":443,"id":{"v":"` + vmessID + `"}}`), wantErr: kindInvalid, errContains: `"id"`, secret: vmessID},
	{name: "field names are case sensitive", link: stdLink(`{"Add":"example.com","port":443,"id":"` + vmessID + `"}`), wantErr: kindInvalid, secret: vmessID},

	// the body
	{name: "not json", link: stdLink("not json " + vmessID), wantErr: kindInvalid, secret: vmessID},
	{name: "a json array", link: stdLink(`["` + vmessID + `"]`), wantErr: kindInvalid, secret: vmessID},
	{name: "a json string", link: stdLink(`"` + vmessID + `"`), wantErr: kindInvalid, secret: vmessID},
	{name: "json null", link: stdLink(`null`), wantErr: kindInvalid},
	{name: "json with a trailing comma", link: stdLink(`{"id":"` + vmessID + `",}`), wantErr: kindInvalid, secret: vmessID},
	{name: "json with trailing text", link: stdLink(vmessJSON("") + ` ` + vmessID), wantErr: kindInvalid, secret: vmessID},
	{name: "an empty body", link: "vmess://", wantErr: kindInvalid},
	{name: "not base64", link: "vmess://!!not base64!!", wantErr: kindInvalid, secret: "!!not"},
	{name: "base64 with both alphabets", link: "vmess://ab+c_dAA", wantErr: kindInvalid, secret: "ab+c_dAA"},
	{name: "base64 with a bad length", link: "vmess://eyJhIjoxfQ=x", wantErr: kindInvalid},
	{name: "a query after the body", link: stdLink(vmessJSON("")) + "?remarks=x", wantErr: kindInvalid, errContains: "after the base64 body"},
	{name: "a query and a name after the body", link: stdLink(vmessJSON("")) + "?remarks=x&obfs=none#name", wantErr: kindInvalid, errContains: "after the base64 body"},
	{name: "a bare question mark after the body", link: stdLink(vmessJSON("")) + "?", wantErr: kindInvalid, errContains: "after the base64 body"},
	{name: "a name with text that is not base64 before it", link: "vmess://!!!#name", wantErr: kindInvalid, errContains: "not base64"},
	{name: "a name with no body", link: "vmess://#name", wantErr: kindInvalid},

	// the URL form of the VMess link is not read
	{name: "url form", link: "vmess://" + vmessID + "@example.com:443?type=ws&security=tls#name", wantErr: kindUnsupported, errContains: "URL form", secret: vmessID},
	{name: "url form in upper case", link: "VMESS://" + vmessID + "@example.com:443", wantErr: kindUnsupported, secret: vmessID},
}, vmessFlagCases())

func TestParseVMess(t *testing.T) { runParseCases(t, vmessCases) }

// TestVMessAlphabetBody checks that the alphabet cases test what they claim:
// the body has a + and a / in the standard alphabet and is padded, so the url
// alphabet and the missing padding are each used.
func TestVMessAlphabetBody(t *testing.T) {
	std := base64.StdEncoding.EncodeToString([]byte(vmessAlphabetJSON))
	if !strings.Contains(std, "+") || !strings.Contains(std, "/") || !strings.HasSuffix(std, "=") {
		t.Errorf("the standard body %q must have a +, a / and padding", std)
	}
	urlBody := base64.URLEncoding.EncodeToString([]byte(vmessAlphabetJSON))
	if !strings.Contains(urlBody, "-") || !strings.Contains(urlBody, "_") {
		t.Errorf("the url body %q must have a - and a _", urlBody)
	}
}

// TestVMessErrorsKeepSecrets runs a body that has a secret in every place a
// parser might repeat it: a value of the wrong type, a bad id, a bad syntax.
// It leaves out net and type, which name a transport and are repeated in the
// error for an unknown one, as the same parameters are for a VLESS link.
func TestVMessErrorsKeepSecrets(t *testing.T) {
	const secret = "SeCrEt-0123456789"
	for _, js := range []string{
		`{"add":"example.com","port":443,"id":"` + secret + `","aid":"` + secret + `"}`,
		`{"add":"example.com","port":443,"id":"` + secret + `","scy":"` + secret + `"}`,
		`{"add":"example.com","port":443,"id":"` + secret + `","tls":"` + secret + `"}`,
		`{"add":"example.com","port":"` + secret + `","id":"` + secret + `"}`,
		`{"add":"` + secret + ` x","port":443,"id":"` + secret + `"}`,
		`{"add":"example.com","port":443,"id":["` + secret + `"]}`,
		`{"add":"example.com","port":443,"id":"` + secret + `",` + secret + `}`,
		`{"add":"example.com","port":443,"id":"` + secret + `"} ` + secret,
		secret,
	} {
		_, err := Parse(stdLink(js))
		if err == nil {
			t.Errorf("Parse(%s) succeeded, want an error", js)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("Parse(%s) error %q repeats the secret", js, err)
		}
	}
}
