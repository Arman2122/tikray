package sharelink

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
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
	wantErr  errKind
	// secret is a part of the link that no error message may repeat.
	secret string
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

func TestParseDispatch(t *testing.T) {
	const id = "b831381d-6324-4d53-ad4f-8cda48b30811"
	vless := `{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"encryption":"none","id":"` + id + `"}]}]},"streamSettings":{"network":"tcp"}}`
	trojan := `{"protocol":"trojan","settings":{"servers":[{"address":"example.com","port":443,"password":"pw"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{}}}`
	runParseCases(t, []parseCase{
		{name: "vless", link: "vless://" + id + "@example.com:443", wantName: "example.com:443", wantJSON: vless},
		{name: "vless upper case scheme", link: "VLESS://" + id + "@example.com:443", wantName: "example.com:443", wantJSON: vless},
		{name: "vless mixed case scheme", link: "VLess://" + id + "@example.com:443", wantName: "example.com:443", wantJSON: vless},
		{name: "surrounding whitespace", link: " \t vless://" + id + "@example.com:443\r\n", wantName: "example.com:443", wantJSON: vless},
		{name: "trojan", link: "trojan://pw@example.com:443", wantName: "example.com:443", wantJSON: trojan},
		{name: "trojan upper case scheme", link: "TROJAN://pw@example.com:443", wantName: "example.com:443", wantJSON: trojan},

		{name: "other scheme", link: "hysteria2://secret@example.com:443", wantErr: kindUnsupported, secret: "secret"},
		{name: "other scheme upper case", link: "WireGuard://secret@example.com:443", wantErr: kindUnsupported, secret: "secret"},
		{name: "no scheme", link: "secret@example.com:443", wantErr: kindInvalid, secret: "secret"},
		{name: "empty", link: "", wantErr: kindInvalid},
		{name: "blank", link: "  \n", wantErr: kindInvalid},
		{name: "not a scheme", link: "not a link://secret@example.com:443", wantErr: kindInvalid, secret: "secret"},
		{name: "empty scheme", link: "://secret@example.com:443", wantErr: kindInvalid, secret: "secret"},
		{name: "scheme too long", link: strings.Repeat("a", 33) + "://secret@example.com:443", wantErr: kindInvalid, secret: "secret"},
		{name: "scheme starts with a digit", link: "1vless://secret@example.com:443", wantErr: kindInvalid, secret: "secret"},
	})
}

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
	}
	for _, tc := range tests {
		if got := name(tc.fragment, tc.host, tc.port); got != tc.want {
			t.Errorf("name(%q, %q, %d) = %q, want %q", tc.fragment, tc.host, tc.port, got, tc.want)
		}
	}
}

func TestParseUserinfoAndHost(t *testing.T) {
	// Each of these decodes to the same trojan password.
	const want = `{"protocol":"trojan","settings":{"servers":[{"address":"example.com","port":443,"password":"pa:ss"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{}}}`
	runParseCases(t, []parseCase{
		{name: "encoded colon", link: "trojan://pa%3Ass@example.com:443", wantName: "example.com:443", wantJSON: want},
		{name: "plain colon", link: "trojan://pa:ss@example.com:443", wantName: "example.com:443", wantJSON: want},
	})
}
