package sharelink

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// seedCases is every table of links in this package's tests, so that the fuzzer
// starts from a link of each kind and each kind of mistake.
func seedCases() []parseCase {
	return slices.Concat(dispatchCases, userinfoCases, fragmentCases, unreadQueryCases, vlessCases, trojanCases, vmessCases, ssCases)
}

// FuzzParse checks what must hold for any text: Parse never panics, a link it
// accepts gives a usable server, and a link it refuses gives an error that
// repeats none of the link.
func FuzzParse(f *testing.F) {
	for _, tc := range seedCases() {
		f.Add(tc.link)
	}
	f.Fuzz(func(t *testing.T, link string) {
		s, err := Parse(link)
		if err != nil {
			checkError(t, link, err)
			return
		}
		checkServer(t, s)
	})
}

// protocols are the outbound protocols that Parse gives.
var protocols = []string{"vless", "trojan", "vmess", "shadowsocks"}

// checkServer fails t if s breaks a rule that every server Parse gives must keep.
func checkServer(t *testing.T, s Server) {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(s.Outbound, &out); err != nil {
		t.Fatalf("Outbound is not a JSON object: %v\n%s", err, s.Outbound)
	}
	protocol, ok := out["protocol"].(string)
	if !ok || protocol == "" {
		t.Errorf("Outbound has no protocol: %s", s.Outbound)
	}
	if !slices.Contains(protocols, protocol) {
		t.Errorf("Outbound has an unknown protocol %q", protocol)
	}
	if _, ok := out["tag"]; ok {
		t.Errorf("Outbound has a tag, which render adds: %s", s.Outbound)
	}
	if _, ok := out["settings"].(map[string]any); !ok {
		t.Errorf("Outbound has no settings object: %s", s.Outbound)
	}
	// Shadowsocks has no transport; every other protocol has one.
	if _, has := out["streamSettings"]; has == (protocol == "shadowsocks") {
		t.Errorf("Outbound with protocol %q has streamSettings = %v: %s", protocol, has, s.Outbound)
	}
	// Current xray refuses a config that has the key, wherever it is.
	if hasKey(out, "allowInsecure") {
		t.Errorf("Outbound has an allowInsecure key: %s", s.Outbound)
	}

	if s.Name == "" {
		t.Errorf("Name is empty")
	}
	if n := utf8.RuneCountInString(s.Name); n > maxNameRunes {
		t.Errorf("Name has %d runes, want at most %d: %q", n, maxNameRunes, s.Name)
	}
	if !utf8.ValidString(s.Name) {
		t.Errorf("Name is not valid UTF-8: %q", s.Name)
	}

	// nil means nothing to say; an empty slice would say that wrongly.
	if s.Warnings != nil && len(s.Warnings) == 0 {
		t.Errorf("Warnings is empty but not nil")
	}
	for _, w := range s.Warnings {
		if w == "" {
			t.Errorf("Warnings has an empty warning: %q", s.Warnings)
		}
	}
}

// echoLen is how many bytes of the link, in a row, an error may not repeat. It
// is long enough that a link cannot repeat the fixed words of a message by
// chance (the fuzzer found a method name that was a part of the list of methods
// in the error for an unsupported one), and short enough to catch a UUID or a
// base64 body. The shorter secrets are checked by the secret of each case.
const echoLen = 32

// checkError fails t if err breaks a rule that every error from Parse must keep.
func checkError(t *testing.T, link string, err error) {
	t.Helper()
	msg := err.Error()
	if !strings.HasPrefix(msg, "sharelink: ") {
		t.Errorf("error %q lacks the \"sharelink: \" prefix", msg)
	}
	// The scheme is named in an error on purpose, and so is a query parameter
	// that is wrong, like an unknown network. What is left is the userinfo, the
	// host and port, or the base64 body: the part with the secrets.
	_, body, _ := strings.Cut(strings.TrimSpace(link), "://")
	body, _, _ = strings.Cut(body, "#")
	body, _, _ = strings.Cut(body, "?")
	for i := 0; i+echoLen <= len(body); i++ {
		if strings.Contains(msg, body[i:i+echoLen]) {
			t.Errorf("error %q repeats %q from the link", msg, body[i:i+echoLen])
			return
		}
	}
}

// hasKey reports whether v, a decoded JSON value, has an object member called
// key at any depth.
func hasKey(v any, key string) bool {
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			if k == key || hasKey(e, key) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(v, func(e any) bool { return hasKey(e, key) })
	}
	return false
}

func TestHasKey(t *testing.T) {
	tests := []struct {
		json string
		want bool
	}{
		{`{}`, false},
		{`{"allowInsecure":false}`, true},
		{`{"a":{"b":[1,{"allowInsecure":1}]}}`, true},
		{`{"a":[{"b":"allowInsecure"}]}`, false},
		{`{"password":"allowInsecure"}`, false},
		{`[]`, false},
	}
	for _, tc := range tests {
		var v any
		if err := json.Unmarshal([]byte(tc.json), &v); err != nil {
			t.Fatal(err)
		}
		if got := hasKey(v, "allowInsecure"); got != tc.want {
			t.Errorf("hasKey(%s) = %v, want %v", tc.json, got, tc.want)
		}
	}
}
