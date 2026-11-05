//go:build lab

package e2e

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/api"
	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/service"
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
		if _, err := apiClient(c.token, c.crt); err == nil {
			t.Errorf("%s: expected an error", name)
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

// Regressions in upstream redaction must fail checks without copying the
// offending diagnostic into their test output or committed results.
func TestServiceEvidenceOmitsDiagnostics(t *testing.T) {
	const private = "unexpected-provider-value"
	var st service.Status
	st.Health.Runner.Err = private
	for _, evidence := range []string{
		describeStatus(st, nil),
		describeStatus(st, errors.New(private)),
		describe(artifacts.Result{Outcome: "rejected", Detail: private}),
	} {
		if strings.Contains(evidence, private) {
			t.Error("service evidence included raw diagnostic text")
		}
	}
}

func TestServiceStatusCLI(t *testing.T) {
	for _, tc := range []struct {
		name, syntax, output     string
		discoveryErr, commandErr bool
		supported, wantErr       bool
	}{
		{"discovery failed", "", "", true, false, false, true},
		{"discovery empty", "", "", false, false, false, true},
		{"interactive only", "number", "", false, false, false, false},
		{"command failed", "number cmd", "", false, true, true, true},
		{"incorrect revision", "number cmd", "revision 1\ncli-succeeded", false, false, true, true},
		{"command exited unsuccessfully", "number cmd", "revision 0", false, false, true, true},
		{"status succeeded", "number cmd", "revision   0\napplied no\ncli-succeeded\n", false, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			run := func(_ context.Context, _ string) (string, error) {
				calls++
				if calls == 1 {
					if tc.discoveryErr {
						return "", errors.New("private discovery diagnostic")
					}
					return tc.syntax, nil
				}
				if tc.commandErr {
					return "", errors.New("private command diagnostic")
				}
				return tc.output, nil
			}
			supported, err := statusCLI(t.Context(), run)
			if supported != tc.supported || (err != nil) != tc.wantErr || (err != nil && strings.Contains(err.Error(), "private")) {
				t.Error("incorrect support or error result, or unsafe diagnostic")
			}
			if (calls == 2) != tc.supported {
				t.Error("command should run only after discovery confirms support")
			}
		})
	}
}

func TestServicePrintedFingerprint(t *testing.T) {
	const id = "*3"
	pin := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	line := func(id, fp string) string {
		return id + " container: tikray: serving on :443, certificate sha256 " + fp + "\n"
	}
	for _, tc := range []struct {
		name, output, previous string
		wantErr                bool
	}{
		{"no listener", "", "", true},
		{"wrong pin", line(id, other), "", true},
		{"only the old start", line(id, pin), id, true},
		{"initial start", line(id, pin), "", false},
		{"new start", line("*2", other) + line(id, pin), "*2", false},
		{"latest pin differs", line("*2", pin) + line(id, other), "*2", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := matchServeFingerprint(tc.output, pin, tc.previous)
			if (err != nil) != tc.wantErr || !tc.wantErr && got != id {
				t.Error("the newest service start must print the pinned fingerprint")
			}
		})
	}
}
