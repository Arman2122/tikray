package sharelink

import (
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestStreamFromQuery(t *testing.T) {
	q := url.Values{
		"type":          {"ws"},
		"security":      {"reality"},
		"sni":           {"www.example.com"},
		"fp":            {"chrome"},
		"alpn":          {"h2,http/1.1"},
		"pbk":           {"PBK"},
		"sid":           {"SID"},
		"spx":           {"/spider"},
		"host":          {"h.example.com"},
		"path":          {"/p"},
		"serviceName":   {"gun"},
		"authority":     {"a.example.com"},
		"mode":          {"multi"},
		"headerType":    {"http"},
		"allowInsecure": {"true"},
		"pcs":           {" PIN "},
		"vcn":           {"real.example.com"},
	}
	want := stream{
		Network: "ws", Security: "reality", SNI: "www.example.com", Fingerprint: "chrome",
		ALPN: "h2,http/1.1", PublicKey: "PBK", ShortID: "SID", SpiderX: "/spider",
		Host: "h.example.com", Path: "/p", ServiceName: "gun", Authority: "a.example.com",
		Mode: "multi", HeaderType: "http", AllowInsecure: true,
		PinnedCertSHA256: " PIN ", VerifyCertByName: "real.example.com",
	}
	if got := streamFromQuery(q, "tls"); !reflect.DeepEqual(got, want) {
		t.Errorf("streamFromQuery:\n got %+v\nwant %+v", got, want)
	}
}

// TestStreamKeys keeps streamKeys, which decides which malformed parameters
// fail a link, in step with what streamFromQuery reads.
func TestStreamKeys(t *testing.T) {
	empty := streamFromQuery(url.Values{}, "")
	for _, k := range streamKeys {
		if reflect.DeepEqual(streamFromQuery(url.Values{k: {"true"}}, ""), empty) {
			t.Errorf("streamFromQuery does not read %q", k)
		}
	}
	// Each field comes from one key, but allowInsecure and insecure share one.
	if got, want := len(streamKeys), reflect.TypeOf(stream{}).NumField()+1; got != want {
		t.Errorf("streamKeys has %d keys, but stream has %d fields (and one is set by two keys)", got, want-1)
	}
}

func TestStreamFromQuerySecurity(t *testing.T) {
	tests := []struct {
		name string
		q    url.Values
		def  string
		want string
	}{
		{"absent, no default", url.Values{}, "", ""},
		{"absent, default tls", url.Values{}, "tls", "tls"},
		{"empty, default tls", url.Values{"security": {""}}, "tls", "tls"},
		{"set beats the default", url.Values{"security": {"none"}}, "tls", "none"},
		{"set, no default", url.Values{"security": {"reality"}}, "", "reality"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := streamFromQuery(tc.q, tc.def).Security; got != tc.want {
				t.Errorf("Security = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStreamFromQueryAllowInsecure(t *testing.T) {
	tests := []struct {
		query string
		want  bool
	}{
		{"", false},
		{"allowInsecure=1", true},
		{"allowInsecure=true", true},
		{"insecure=1", true},
		{"insecure=true", true},
		{"allowInsecure=0", false},
		{"allowInsecure=false", false},
		{"allowInsecure=yes", false},
		{"allowInsecure=", false},
		{"allowInsecure=0&insecure=1", true},
		{"allowInsecure=1&insecure=0", true},
		{"allowInsecure=0&insecure=0", false},
		{"allowInsecure=True", true},
		{"allowInsecure=TRUE", true},
		{"insecure=True", true},
		{"insecure=tRuE", true},
		{"allowInsecure=%20true", true},
		{"allowInsecure=2", false},
	}
	for _, tc := range tests {
		q, err := url.ParseQuery(tc.query)
		if err != nil {
			t.Fatal(err)
		}
		if got := streamFromQuery(q, "").AllowInsecure; got != tc.want {
			t.Errorf("streamFromQuery(%q).AllowInsecure = %v, want %v", tc.query, got, tc.want)
		}
	}
}

// TestStreamSettings builds streams directly, the way the VMess parser does.
func TestStreamSettings(t *testing.T) {
	tests := []struct {
		name string
		s    stream
		want map[string]any
	}{
		{"zero stream is plain tcp", stream{}, map[string]any{"network": "tcp"}},
		{
			"tcp aliases", stream{Network: "raw", Security: "none"},
			map[string]any{"network": "tcp"},
		},
		{
			"surrounding space and case", stream{Network: " WS ", Security: " TLS "},
			map[string]any{
				"network":     "ws",
				"security":    "tls",
				"tlsSettings": map[string]any{},
				"wsSettings":  map[string]any{"path": "/"},
			},
		},
		{
			"alpn with one value", stream{Security: "tls", ALPN: "h2"},
			map[string]any{
				"network":     "tcp",
				"security":    "tls",
				"tlsSettings": map[string]any{"alpn": []string{"h2"}},
			},
		},
		{
			"alpn of only separators", stream{Security: "tls", ALPN: " , ,"},
			map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{}},
		},
		{
			// xray-core refuses allowInsecure, so it is never written.
			"allowInsecure is dropped", stream{Security: "tls", SNI: "a.example.com", AllowInsecure: true},
			map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "a.example.com"}},
		},
		{
			"pin and verify name", stream{Security: "tls", PinnedCertSHA256: " aa:bb ", VerifyCertByName: "real.example.com", AllowInsecure: true},
			map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{
				"pinnedPeerCertSha256": "aa:bb",
				"verifyPeerCertByName": "real.example.com",
			}},
		},
		{
			"pin and verify name are for tls only", stream{Security: "none", PinnedCertSHA256: "aa", VerifyCertByName: "real.example.com"},
			map[string]any{"network": "tcp"},
		},
		{
			"pin and verify name are not reality settings", stream{Security: "reality", PublicKey: "k", PinnedCertSHA256: "aa", VerifyCertByName: "real.example.com"},
			map[string]any{
				"network":         "tcp",
				"security":        "reality",
				"realitySettings": map[string]any{"fingerprint": "chrome", "publicKey": "k"},
			},
		},
		{
			// A clean IP address with a host and no sni is how CDN-fronted links
			// are written: the handshake needs the host, not the address.
			"tls without sni takes the first host", stream{Network: "ws", Security: "tls", Host: "a.example, b.example"},
			map[string]any{
				"network":     "ws",
				"security":    "tls",
				"tlsSettings": map[string]any{"serverName": "a.example"},
				"wsSettings":  map[string]any{"path": "/", "host": "a.example, b.example"},
			},
		},
		{
			"tls with a blank sni takes the first host", stream{Security: "tls", SNI: "  ", Host: " a.example ,b.example"},
			map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "a.example"}},
		},
		{
			"tls with one host", stream{Security: "tls", Host: "a.example"},
			map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "a.example"}},
		},
		{
			"an sni wins over the host", stream{Security: "tls", SNI: "s.example", Host: "a.example,b.example"},
			map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "s.example"}},
		},
		{
			"a host of only separators gives no server name", stream{Security: "tls", Host: " , "},
			map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{}},
		},
		{
			"an empty first host gives no server name", stream{Security: "tls", Host: ",b.example"},
			map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{}},
		},
		{
			"no tls, no server name from the host", stream{Security: "none", Host: "a.example"},
			map[string]any{"network": "tcp"},
		},
		{
			"reality keeps sni only", stream{Security: "reality", PublicKey: "k", Host: "a.example"},
			map[string]any{
				"network":         "tcp",
				"security":        "reality",
				"realitySettings": map[string]any{"fingerprint": "chrome", "publicKey": "k"},
			},
		},
		{
			"reality with an sni", stream{Security: "reality", PublicKey: "k", SNI: "s.example", Host: "a.example"},
			map[string]any{
				"network":         "tcp",
				"security":        "reality",
				"realitySettings": map[string]any{"fingerprint": "chrome", "publicKey": "k", "serverName": "s.example"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.s.settings()
			if err != nil {
				t.Fatalf("settings: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("settings:\n got %#v\nwant %#v", got, tc.want)
			}
		})
	}
}

func TestStreamSettingsErrors(t *testing.T) {
	tests := []struct {
		name        string
		s           stream
		unsupported bool
	}{
		{"kcp", stream{Network: "kcp"}, true},
		{"quic", stream{Network: "quic"}, true},
		{"h2", stream{Network: "h2"}, true},
		{"http", stream{Network: "http"}, true},
		{"unknown network", stream{Network: "udp"}, false},
		{"unknown security", stream{Security: "foo"}, false},
		{"reality needs a key", stream{Security: "reality"}, false},
		{"reality over ws", stream{Security: "reality", PublicKey: "k", Network: "ws"}, false},
		{"unknown tcp header", stream{HeaderType: "wechat-video"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.s.settings()
			if err == nil {
				t.Fatal("settings succeeded, want an error")
			}
			if is := errors.Is(err, ErrUnsupported); is != tc.unsupported {
				t.Errorf("errors.Is(%q, ErrUnsupported) = %v, want %v", err, is, tc.unsupported)
			}
		})
	}
}

// TestStreamErrorsKeepValues checks that an error for an unknown value does not
// repeat it: a parameter can hold anything, even the id of the link.
func TestStreamErrorsKeepValues(t *testing.T) {
	const value = "SeCrEt-0123456789"
	for _, s := range []stream{
		{Network: value},
		{Security: value},
		{HeaderType: value},
		{Network: value, Security: value, HeaderType: value},
	} {
		_, err := s.settings()
		if err == nil {
			t.Errorf("settings(%+v) succeeded, want an error", s)
		} else if strings.Contains(err.Error(), value) {
			t.Errorf("settings(%+v) error %q repeats the value", s, err)
		}
	}
}

func TestStreamWarnings(t *testing.T) {
	insecure := []string{warnInsecureRemoved}
	tests := []struct {
		name string
		s    stream
		want []string
	}{
		{"nothing set", stream{}, nil},
		{"tls", stream{Security: "tls"}, nil},
		{"tls, insecure", stream{Security: "tls", AllowInsecure: true}, insecure},
		{"security case and space", stream{Security: " TLS ", AllowInsecure: true}, insecure},
		{"tls, insecure, pinned", stream{Security: "tls", AllowInsecure: true, PinnedCertSHA256: "aa"}, nil},
		{"tls, insecure, blank pin", stream{Security: "tls", AllowInsecure: true, PinnedCertSHA256: "  "}, insecure},
		{"tls, insecure, verify name only", stream{Security: "tls", AllowInsecure: true, VerifyCertByName: "a.example.com"}, insecure},
		{"no security, insecure", stream{AllowInsecure: true}, nil},
		{"none, insecure", stream{Security: "none", AllowInsecure: true}, nil},
		{"reality, insecure", stream{Security: "reality", PublicKey: "k", AllowInsecure: true}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.warnings(); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("warnings() = %q, want %q", got, tc.want)
			}
		})
	}
}
