//go:build lab

package e2e

import (
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/api"
	"github.com/Arman2122/tikray/test/lab/fixtures/labinet"
)

// The helpers that reach the service and the subscriptions have to work from
// what the router and labinet give them. These tests need no lab: run them with
//
//	go test -tags lab -run 'TestAPIClient|TestSetSub' ./test/e2e/
func TestAPIClient(t *testing.T) {
	dir := t.TempDir()
	_, want, err := api.LoadOrCreateCert(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	crt, err := os.ReadFile(filepath.Join(dir, "tls.crt"))
	if err != nil {
		t.Fatal(err)
	}
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	for name, c := range map[string]struct{ token, crt string }{
		"as the file has it":     {token, string(crt)},
		"trimmed, as Get has it": {token, strings.TrimSpace(string(crt))},
		"with CRLF":              {token + "\r\n", strings.ReplaceAll(string(crt), "\n", "\r\n")},
	} {
		got, err := apiClient(c.token, c.crt)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.BaseURL != "https://172.31.255.2:443" || got.Token != token || got.Fingerprint != want || got.HTTP != nil {
			t.Errorf("%s: client {BaseURL %q, Fingerprint %q, HTTP set %v}, want the service's address and fingerprint %s, pinned", name, got.BaseURL, got.Fingerprint, got.HTTP != nil, want)
		}
	}

	for name, c := range map[string]struct{ token, crt string }{
		"no token":       {"  \n", string(crt)},
		"no certificate": {token, ""},
		"not a PEM":      {token, "failure: no such item"},
		"a key":          {token, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"},
	} {
		if got, err := apiClient(c.token, c.crt); err == nil {
			t.Errorf("%s: got a client %+v, want an error", name, got)
		} else if strings.Contains(err.Error(), token) {
			t.Errorf("%s: the error names the token", name)
		}
	}
}

func TestSetSub(t *testing.T) {
	l := &Lab{Subs: t.TempDir()}
	srv := httptest.NewServer(labinet.HTTPHandler(l.Subs))
	defer srv.Close()
	fetch := func(name string) (int, string) {
		t.Helper()
		resp, err := srv.Client().Get(srv.URL + "/sub/" + name)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	if code, _ := fetch("a"); code != 404 {
		t.Errorf("a subscription nobody set = %d, want 404", code)
	}
	for _, body := range []string{"vless://one\n", "vless://two\nvless://three\n", ""} {
		if err := l.setSub("a", body); err != nil {
			t.Fatal(err)
		}
		if code, got := fetch("a"); code != 200 || got != body {
			t.Errorf("after setSub(a, %q): %d %q, want 200 and the body", body, code, got)
		}
	}
	if err := l.setSub("b.txt", "other"); err != nil {
		t.Fatal(err)
	}
	if code, got := fetch("b.txt"); code != 200 || got != "other" {
		t.Errorf("b.txt: %d %q, want 200 \"other\"", code, got)
	}
	if code, got := fetch("a"); code != 200 || got != "" {
		t.Errorf("a after b.txt was set: %d %q, want it unchanged", code, got)
	}

	// Only the subscriptions are left in the directory.
	entries, err := os.ReadDir(l.Subs)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, " ") != "a b.txt" {
		t.Errorf("the subscriptions directory holds %v, want [a b.txt]", names)
	}

	// A name labinet would answer 404 is refused here, with the rule it
	// breaks, and not found out when the service's fetch fails.
	for _, bad := range []string{"", ".", "..", ".hidden", "a/b", "../x", "/etc/passwd", "x/", "a b", "-x", "a?b", "é", strings.Repeat("a", 129)} {
		err := l.setSub(bad, "x")
		if err == nil {
			t.Errorf("setSub(%q) succeeded, want an error", bad)
		} else if !strings.Contains(err.Error(), "A-Za-z0-9") {
			t.Errorf("setSub(%q) = %q, want the rule for a name in it", bad, err)
		}
	}
	if err := (&Lab{}).setSub("a", "x"); err == nil {
		t.Error("setSub on a lab without a subscriptions directory succeeded, want an error")
	}
}

func TestSetSubCleansUp(t *testing.T) {
	l := &Lab{Subs: t.TempDir()}
	// A directory with something in it cannot be replaced by a file, so the
	// rename fails; the file under construction must not stay behind.
	if err := os.MkdirAll(filepath.Join(l.Subs, "a", "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := l.setSub("a", "x"); err == nil {
		t.Fatal("setSub over a non-empty directory succeeded, want an error")
	}
	entries, err := os.ReadDir(l.Subs)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "a" {
			t.Errorf("setSub left %q behind after a failed rename", e.Name())
		}
	}
}
