package sharelink

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/xraypolicy"
)

// errKind is how a parse case is expected to end.
type errKind int

const (
	// kindOK means the link parses.
	kindOK errKind = iota
	// kindInvalid means a plain "sharelink: " error that is not ErrUnsupported.
	kindInvalid
	// kindUnsupported means an error that wraps ErrUnsupported.
	kindUnsupported
)

// parseCase is one link and the Server or error Parse must give for it.
type parseCase struct {
	name     string
	link     string
	wantName string
	// wantJSON is the exact outbound, compared after a canonical re-marshal.
	wantJSON string
	// wantWarnings is the exact Server.Warnings; nil means there must be none.
	wantWarnings []string
	wantErr      errKind
	// errContains, when set, is text the error message must contain.
	errContains string
	// secret is a part of the link that no error message may repeat.
	secret string
	// refused means the error also wraps xraypolicy.ErrRefused: the link is
	// valid, but the outbound it gives is one that xray-core refuses.
	refused bool
}

// canonical decodes b and encodes it again, which sorts every object's keys.
func canonical(t *testing.T, b []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("invalid JSON %s: %v", b, err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// runParseCases runs every case through Parse.
func runParseCases(t *testing.T, cases []parseCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.link)
			if tc.wantErr != kindOK {
				if err == nil {
					t.Fatalf("Parse succeeded with %s, want an error", got.Outbound)
				}
				if !strings.HasPrefix(err.Error(), "sharelink: ") {
					t.Errorf("error %q lacks the \"sharelink: \" prefix", err)
				}
				if is := errors.Is(err, ErrUnsupported); is != (tc.wantErr == kindUnsupported) {
					t.Errorf("errors.Is(%q, ErrUnsupported) = %v, want %v", err, is, !is)
				}
				if is := errors.Is(err, xraypolicy.ErrRefused); is != tc.refused {
					t.Errorf("errors.Is(%q, xraypolicy.ErrRefused) = %v, want %v", err, is, !is)
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error %q does not contain %q", err, tc.errContains)
				}
				if tc.secret != "" && strings.Contains(err.Error(), tc.secret) {
					t.Errorf("error %q repeats the link's secret", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tc.wantName)
			}
			if !reflect.DeepEqual(got.Warnings, tc.wantWarnings) {
				t.Errorf("Warnings = %q, want %q", got.Warnings, tc.wantWarnings)
			}
			// Current xray refuses a config that has it.
			if strings.Contains(string(got.Outbound), "allowInsecure") {
				t.Errorf("Outbound has allowInsecure: %s", got.Outbound)
			}
			var gotV, wantV any
			if err := json.Unmarshal(got.Outbound, &gotV); err != nil {
				t.Fatalf("Outbound is not JSON: %v\n%s", err, got.Outbound)
			}
			if err := json.Unmarshal([]byte(tc.wantJSON), &wantV); err != nil {
				t.Fatalf("bad expectation: %v", err)
			}
			if !reflect.DeepEqual(gotV, wantV) {
				t.Errorf("Outbound:\n got %s\nwant %s", canonical(t, got.Outbound), canonical(t, []byte(tc.wantJSON)))
			}
			// The outbound is marshalled from maps, so it is already canonical.
			if string(got.Outbound) != canonical(t, got.Outbound) {
				t.Errorf("Outbound keys are not sorted or not compact: %s", got.Outbound)
			}
		})
	}
}

const (
	dispatchVLESS  = `{"protocol":"vless","settings":{"vnext":[{"address":"nas.lan","port":443,"users":[{"encryption":"none","id":"` + vlessID + `"}]}]},"streamSettings":{"network":"tcp"}}`
	dispatchTrojan = `{"protocol":"trojan","settings":{"servers":[{"address":"example.com","port":443,"password":"pw"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{}}}`
)

// dispatchCases are links that Parse's choice of scheme alone decides. The
// fuzz test seeds from them too.
var dispatchCases = []parseCase{
	{name: "vless", link: "vless://" + vlessID + "@nas.lan:443", wantName: "nas.lan:443", wantJSON: dispatchVLESS},
	{name: "vless upper case scheme", link: "VLESS://" + vlessID + "@nas.lan:443", wantName: "nas.lan:443", wantJSON: dispatchVLESS},
	{name: "vless mixed case scheme", link: "VLess://" + vlessID + "@nas.lan:443", wantName: "nas.lan:443", wantJSON: dispatchVLESS},
	{name: "surrounding whitespace", link: " \t vless://" + vlessID + "@nas.lan:443\r\n", wantName: "nas.lan:443", wantJSON: dispatchVLESS},
	{name: "trojan", link: "trojan://pw@example.com:443", wantName: "example.com:443", wantJSON: dispatchTrojan},
	{name: "trojan upper case scheme", link: "TROJAN://pw@example.com:443", wantName: "example.com:443", wantJSON: dispatchTrojan},

	{name: "other scheme", link: "hysteria2://secret@example.com:443", wantErr: kindUnsupported, secret: "secret"},
	{name: "other scheme upper case", link: "WireGuard://secret@example.com:443", wantErr: kindUnsupported, secret: "secret"},
	{name: "no scheme", link: "secret@example.com:443", wantErr: kindInvalid, secret: "secret"},
	{name: "empty", link: "", wantErr: kindInvalid},
	{name: "blank", link: "  \n", wantErr: kindInvalid},
	{name: "not a scheme", link: "not a link://secret@example.com:443", wantErr: kindInvalid, secret: "secret"},
	{name: "empty scheme", link: "://secret@example.com:443", wantErr: kindInvalid, secret: "secret"},
	{name: "scheme too long", link: strings.Repeat("a", 33) + "://secret@example.com:443", wantErr: kindInvalid, secret: "secret"},
	{name: "scheme starts with a digit", link: "1vless://secret@example.com:443", wantErr: kindInvalid, secret: "secret"},
}

func TestParseDispatch(t *testing.T) { runParseCases(t, dispatchCases) }

func TestName(t *testing.T) {
	long := strings.Repeat("é", 200)
	tests := []struct {
		fragment string
		host     string
		port     int
		want     string
	}{
		{"lab", "example.com", 443, "lab"},
		{"lab 🚀", "example.com", 443, "lab 🚀"},
		{"  padded \t", "example.com", 443, "padded"},
		{"", "example.com", 443, "example.com:443"},
		{" \t ", "example.com", 443, "example.com:443"},
		{"", "203.0.113.10", 8443, "203.0.113.10:8443"},
		{"", "2001:db8::1", 8443, "[2001:db8::1]:8443"},
		{strings.Repeat("a", 128), "h", 1, strings.Repeat("a", 128)},
		{strings.Repeat("a", 129), "h", 1, strings.Repeat("a", 128)},
		// 128 runes, not 128 bytes.
		{long, "h", 1, strings.Repeat("é", 128)},
		{"bad\xffbyte", "h", 1, "bad�byte"},
		// The host and port are cut like a name, and made valid UTF-8 like one.
		{"", strings.Repeat("h", 200), 443, strings.Repeat("h", 128)},
		{"", strings.Repeat("é", 200), 443, strings.Repeat("é", 128)},
		{"", "bad\xffhost", 1, "bad�host:1"},
	}
	for _, tc := range tests {
		if got := name(tc.fragment, tc.host, tc.port); got != tc.want {
			t.Errorf("name(%q, %q, %d) = %q, want %q", tc.fragment, tc.host, tc.port, got, tc.want)
		}
	}
}

// userinfoWant is the trojan outbound for the password pa:ss.
const userinfoWant = `{"protocol":"trojan","settings":{"servers":[{"address":"example.com","port":443,"password":"pa:ss"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{}}}`

// userinfoCases all decode to the same trojan password.
var userinfoCases = []parseCase{
	{name: "encoded colon", link: "trojan://pa%3Ass@example.com:443", wantName: "example.com:443", wantJSON: userinfoWant},
	{name: "plain colon", link: "trojan://pa:ss@example.com:443", wantName: "example.com:443", wantJSON: userinfoWant},
}

func TestParseUserinfoAndHost(t *testing.T) { runParseCases(t, userinfoCases) }

const (
	fragmentLink = "trojan://pw@example.com:443"
	fragmentOut  = `{"protocol":"trojan","settings":{"servers":[{"address":"example.com","port":443,"password":"pw"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{}}}`
)

// fragmentCases are one trojan link with different names after the #.
var fragmentCases = []parseCase{
	{name: "encoded", link: fragmentLink + "#lab%20%F0%9F%9A%80", wantName: "lab 🚀", wantJSON: fragmentOut},
	{name: "encoded percent", link: fragmentLink + "#20%25%20off", wantName: "20% off", wantJSON: fragmentOut},
	{name: "plus stays a plus", link: fragmentLink + "#a+b%2Bc", wantName: "a+b+c", wantJSON: fragmentOut},
	{name: "empty", link: fragmentLink + "#", wantName: "example.com:443", wantJSON: fragmentOut},
	// A name is only a label: a bad escape must not cost the server.
	{name: "bare percent", link: fragmentLink + "#50%", wantName: "50%", wantJSON: fragmentOut},
	{name: "short escape", link: fragmentLink + "#a%2", wantName: "a%2", wantJSON: fragmentOut},
	{name: "not hex", link: fragmentLink + "#a%zzb", wantName: "a%zzb", wantJSON: fragmentOut},
	{name: "literal name with a percent", link: fragmentLink + "#🔥 20% off", wantName: "🔥 20% off", wantJSON: fragmentOut},
	{name: "good escapes beside a bad one stay raw", link: fragmentLink + "#a%20b%", wantName: "a%20b%", wantJSON: fragmentOut},
	{name: "second hash", link: fragmentLink + "#a#b", wantName: "a#b", wantJSON: fragmentOut},
	{name: "only a bad escape", link: fragmentLink + "#%", wantName: "%", wantJSON: fragmentOut},
	// Control characters and bidi overrides are dropped before the trim: they
	// could rewrite a terminal or reverse the text around a name.
	{name: "an escape sequence", link: fragmentLink + "#red%1B%5B31m%1B%5B2Jalert", wantName: "red[31m[2Jalert", wantJSON: fragmentOut},
	{name: "a raw escape sequence", link: fragmentLink + "#red\x1b[31m", wantName: "red[31m", wantJSON: fragmentOut},
	{name: "a newline", link: fragmentLink + "#one%0Atwo%0D%0A", wantName: "onetwo", wantJSON: fragmentOut},
	{name: "a tab, DEL and a C1 control", link: fragmentLink + "#a%09b%7Fc%C2%9Bd", wantName: "abcd", wantJSON: fragmentOut},
	{name: "a right-to-left override", link: fragmentLink + "#evil%E2%80%AEtxt.exe", wantName: "eviltxt.exe", wantJSON: fragmentOut},
	{name: "the bidi embeddings and isolates", link: fragmentLink + "#a\u202ab\u202bc\u202cd\u202de\u2066f\u2067g\u2068h\u2069i", wantName: "abcdefghi", wantJSON: fragmentOut},
	{name: "spaces behind a control character are trimmed", link: fragmentLink + "#%0A%20name%20%1B", wantName: "name", wantJSON: fragmentOut},
	{name: "nothing but control characters", link: fragmentLink + "#%1B%0A%E2%80%AE%20", wantName: "example.com:443", wantJSON: fragmentOut},
	// Marks that Persian text needs stay: the zero-width non-joiner and the
	// right-to-left mark are neither.
	{name: "a zero-width non-joiner and a right-to-left mark", link: fragmentLink + "#%D9%85%DB%8C%E2%80%8C%D8%B1%D9%88%D8%AF\u200f", wantName: "می\u200cرود\u200f", wantJSON: fragmentOut},
}

func TestParseFragment(t *testing.T) { runParseCases(t, fragmentCases) }

// TestParseUnreadQuery checks that a parameter the parser does not read cannot
// cost a server, and that one it reads cannot be dropped silently.
const (
	unreadWS   = `{"protocol":"trojan","settings":{"servers":[{"address":"example.com","port":443,"password":"pw"}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{},"wsSettings":{"path":"/"}}}`
	unreadLink = "trojan://pw@example.com:443?"
)

var unreadQueryCases = []parseCase{
	{name: "unread parameter with a bare percent", link: unreadLink + "remark=50%&type=ws", wantName: "example.com:443", wantJSON: unreadWS},
	{name: "unread parameter with a bad escape last", link: unreadLink + "type=ws&remark=%zz", wantName: "example.com:443", wantJSON: unreadWS},
	{name: "unread parameter with a semicolon", link: unreadLink + "remark=a;b&type=ws", wantName: "example.com:443", wantJSON: unreadWS},
	{name: "unread parameter with a bad escape in its name", link: unreadLink + "re%zzmark=1&type=ws", wantName: "example.com:443", wantJSON: unreadWS},
	{name: "unread parameter without a value", link: unreadLink + "remark&type=ws", wantName: "example.com:443", wantJSON: unreadWS},
	{name: "empty pairs", link: unreadLink + "&&type=ws&", wantName: "example.com:443", wantJSON: unreadWS},
	{name: "vless-only parameters on a trojan link", link: unreadLink + "type=ws&encryption=%zz&flow=%zz", wantName: "example.com:443", wantJSON: unreadWS},
	{name: "escaped parameter name", link: unreadLink + "%74ype=ws", wantName: "example.com:443", wantJSON: unreadWS},

	{name: "read parameter with a bad escape", link: unreadLink + "type=ws&path=%zz", wantErr: kindInvalid, errContains: `"path"`, secret: "%zz"},
	{name: "read parameter with a bare percent", link: unreadLink + "type=ws&host=50%", wantErr: kindInvalid, errContains: `"host"`},
	{name: "read parameter with a semicolon", link: unreadLink + "alpn=h2;http/1.1", wantErr: kindInvalid, errContains: `"alpn"`},
	{name: "read parameter that comes first", link: unreadLink + "sni=%zz&type=ws", wantErr: kindInvalid, errContains: `"sni"`},
	{name: "read parameter repeated, second one bad", link: unreadLink + "type=ws&type=%zz", wantErr: kindInvalid, errContains: `"type"`},
	{name: "pinned certificate with a bad escape", link: unreadLink + "pcs=%zz", wantErr: kindInvalid, errContains: `"pcs"`},
	{name: "insecure flag with a bad escape", link: unreadLink + "allowInsecure=%zz", wantErr: kindInvalid, errContains: `"allowInsecure"`},
}

func TestParseUnreadQuery(t *testing.T) { runParseCases(t, unreadQueryCases) }

func TestInsecureWarning(t *testing.T) {
	// The user is shown this text, so it must say what happened and the way out.
	for _, want := range []string{"allowInsecure", "xray-core", "pcs"} {
		if !strings.Contains(warnInsecureRemoved, want) {
			t.Errorf("warning %q does not mention %q", warnInsecureRemoved, want)
		}
	}
}

func TestParsePort(t *testing.T) {
	tests := []struct {
		in   string
		want int
		ok   bool
	}{
		{"1", 1, true},
		{"443", 443, true},
		{"0443", 443, true},
		{"65535", 65535, true},
		{"", 0, false},
		{"0", 0, false},
		{"65536", 0, false},
		{"70000", 0, false},
		{"99999999999999999999", 0, false},
		{"-1", 0, false},
		{"+443", 0, false},
		{" 443", 0, false},
		{"4.43", 0, false},
		{"0x1bb", 0, false},
		{"https", 0, false},
		{"٤٤٣", 0, false},
	}
	for _, tc := range tests {
		if got, ok := parsePort(tc.in); got != tc.want || ok != tc.ok {
			t.Errorf("parsePort(%q) = %d, %v; want %d, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestCleanHost(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"example.com", "example.com", true},
		{" example.com ", "example.com", true},
		{"Sub-Domain.example.com.", "Sub-Domain.example.com.", true},
		{"my_host.example", "my_host.example", true},
		{"1.2.3.4", "1.2.3.4", true},
		{"bücher.example", "bücher.example", true},
		{"例え.jp", "例え.jp", true},
		{"2001:db8::1", "2001:db8::1", true},
		{"[2001:db8::1]", "2001:db8::1", true},
		{"::ffff:1.2.3.4", "::ffff:1.2.3.4", true},
		{"", "", false},
		{"  ", "", false},
		{"bad host", "", false},
		{"exa mple.com", "", false},
		{"example.com:443", "", false},
		{"example.com/path", "", false},
		{"user@example.com", "", false},
		{"https://example.com", "", false},
		{"example.com?x=1", "", false},
		{"exa\tmple.com", "", false},
		{"exa\x00mple.com", "", false},
		{"bad\xffhost", "", false},
		{"fe80::1%eth0", "", false},
		{"2001:db8::zz", "", false},
		{"[example.com]", "", false},
		{"[2001:db8::1", "", false},
		{"2001:db8::1]", "", false},
		{"[]", "", false},
	}
	for _, tc := range tests {
		if got, ok := cleanHost(tc.in); got != tc.want || ok != tc.ok {
			t.Errorf("cleanHost(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDecodeBase64(t *testing.T) {
	// "??>>??" has a + and a / in the standard alphabet.
	const want = "??>>??"
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"standard", "Pz8+Pj8/", want, true},
		{"standard padded", "YQ==", "a", true},
		{"standard unpadded", "YQ", "a", true},
		{"url", "Pz8-Pj8_", want, true},
		{"url padded", "YWI=", "ab", true},
		{"empty", "", "", true},
		{"mixed alphabets", "Pz8+Pj8_", "", false},
		{"not base64", "a b", "", false},
		{"bad length", "Y", "", false},
		{"padding in the middle", "YQ==YQ==", "", false},
		{"punctuation", "YQ!", "", false},
	}
	for _, tc := range tests {
		got, ok := decodeBase64(tc.in)
		if string(got) != tc.want || ok != tc.ok {
			t.Errorf("%s: decodeBase64(%q) = %q, %v; want %q, %v", tc.name, tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestQueryHasKey(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{"plugin=obfs", true},
		{"plugin", true},
		{"plugin=", true},
		{"a=1&plugin=x", true},
		{"a=1&&plugin=x&b=2", true},
		{"%70lugin=x", true},
		{"plugin=%zz", true},
		{"plugin=a;b", true},
		{"", false},
		{"plugins=x", false},
		{"Plugin=x", false},
		{"a=plugin", false},
		{"a=1&b=plugin=2", false},
		{"plug%zzin=x", false},
	}
	for _, tc := range tests {
		if got := queryHasKey(tc.raw, "plugin"); got != tc.want {
			t.Errorf("queryHasKey(%q, plugin) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}
