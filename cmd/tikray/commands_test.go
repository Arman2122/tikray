package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/api"
	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/health"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/subscription"
)

// humanSecrets are in the fake daemon's state and must stay out of all CLI formats.
var humanSecrets = []string{secretID, secretPass, "4f9a1c7e2b", "hunter2"}

// runAPI is runCLI for a command that talks to the daemon. Whatever the
// command, the token is in neither of its outputs.
func runAPI(t *testing.T, vars map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	code, stdout, stderr = runCLI(t, vars, args...)
	for name, out := range map[string]string{"stdout": stdout, "stderr": stderr} {
		if strings.Contains(out, apiToken) {
			t.Errorf("the API token is in %s", name)
		}
	}
	return code, stdout, stderr
}

// noSecrets reports each of humanSecrets in out.
func noSecrets(t *testing.T, out string) {
	t.Helper()
	for _, s := range humanSecrets {
		if strings.Contains(out, s) {
			t.Fatal("the CLI output contains a fixture credential")
		}
	}
}

// rows splits a table into the fields of each line.
func rows(out string) [][]string {
	var all [][]string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		all = append(all, strings.Fields(line))
	}
	return all
}

// ok runs a command that must succeed on stdout alone.
func ok(t *testing.T, vars map[string]string, args ...string) string {
	t.Helper()
	code, stdout, stderr := runAPI(t, vars, args...)
	if code != 0 || stderr != "" {
		t.Fatalf("command failed (exit %d, stderr length %d)", code, len(stderr))
	}
	noSecrets(t, stdout)
	return stdout
}

func TestServerAddLink(t *testing.T) {
	fake := newFake()
	vars := startDaemon(t, fake).env(t)

	out := ok(t, vars, "server", "add", secretLink, "--name", "lab-a")
	for _, want := range []string{"5ab3c4d5", "lab-a", "vless", "203.0.113.10:443"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout %q lacks %q", out, want)
		}
	}
	calls := fake.called("AddServer")
	if len(calls) != 1 {
		t.Fatalf("%d AddServer calls, want 1", len(calls))
	}
	if want := (service.NewServer{Link: secretLink, Name: "lab-a"}); calls[0][0] != store.AnyRevision || !reflect.DeepEqual(calls[0][1], want) {
		t.Errorf("AddServer(%v), want revision any and %+v", calls[0], want)
	}

	// The flag may come first; without --name the link's own name stands.
	fake2 := newFake()
	vars2 := startDaemon(t, fake2).env(t)
	out = ok(t, vars2, "server", "add", secretLink)
	if !strings.Contains(out, "from-link") {
		t.Errorf("stdout %q lacks the server's name", out)
	}
	if got := fake2.called("AddServer")[0][1].(service.NewServer); got.Name != "" || got.Link != secretLink {
		t.Errorf("AddServer got %+v, want the link alone", got)
	}
}

func TestServerAddOutboundFile(t *testing.T) {
	fake := newFake()
	vars := startDaemon(t, fake).env(t)
	const outbound = `{
  "protocol": "vless",
  "settings": {"vnext": [{"address": "198.51.100.7", "port": 443, "users": [{"id": "` + secretID + `"}]}]}
}`
	file := filepath.Join(t.TempDir(), "outbound.json")
	if err := os.WriteFile(file, []byte(outbound), 0o600); err != nil {
		t.Fatal(err)
	}

	out := ok(t, vars, "server", "add", "--json", file, "--name", "from-file")
	if !strings.Contains(out, "from-file") || !strings.Contains(out, "5ab3c4d5") {
		t.Errorf("stdout %q lacks the new server", out)
	}
	got := fake.called("AddServer")[0][1].(service.NewServer)
	var want, have any
	if err := json.Unmarshal([]byte(outbound), &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got.Outbound, &have); err != nil {
		t.Fatalf("outbound %q: %v", got.Outbound, err)
	}
	if got.Link != "" || got.Name != "from-file" || !reflect.DeepEqual(have, want) {
		t.Errorf("AddServer got %+v, want the file's outbound named from-file and no link", got)
	}
}

func TestServerAddRefusals(t *testing.T) {
	fake := newFake()
	vars := startDaemon(t, fake).env(t)
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	notJSON := write("bad.json", `{"id": "`+secretID+`"`)
	array := write("array.json", `["`+secretID+`"]`)

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"missing file", []string{"--json", filepath.Join(dir, "none.json"), "--name", "x"}, "none.json"},
		{"not JSON", []string{"--json", notJSON, "--name", "x"}, "bad.json"},
		{"not an object", []string{"--json", array, "--name", "x"}, "array.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runAPI(t, vars, append([]string{"server", "add"}, tc.args...)...)
			if code != 1 || stdout != "" || !strings.Contains(stderr, tc.want) {
				t.Errorf("exit %d, stdout %q, stderr %q; want 1 and an error naming %q", code, stdout, stderr, tc.want)
			}
			noSecrets(t, stderr)
		})
	}
	if n := len(fake.called("AddServer")); n != 0 {
		t.Errorf("%d AddServer calls for files that are no outbound", n)
	}

	// The daemon's refusal is the error, as it worded it.
	fake.err = &service.Refused{Reason: "give a share link or an outbound"}
	code, stdout, stderr := runAPI(t, vars, "server", "add", "vless://x")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "refused") || !strings.Contains(stderr, "give a share link or an outbound") {
		t.Errorf("exit %d, stdout %q, stderr %q; want 1 and the refusal", code, stdout, stderr)
	}
}

func TestServerList(t *testing.T) {
	fake := newFake()
	vars := startDaemon(t, fake).env(t)

	out := ok(t, vars, "server", "list")
	got := rows(out)
	want := [][]string{
		{"ID", "NAME", "PROTOCOL", "ADDRESS", "STATE"},
		{"5ab3c4d5", "lab-a", "vless", "203.0.113.10:443", "enabled"},
		{"6bc4d5e6", "lab-b", "trojan", "b.example.com:8443", "disabled"},
		{"7cd5e6f7", "lab-c", "shadowsocks", "[2001:db8::1]:8388", "enabled"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("table\n%s\nwant rows %q", out, want)
	}

	// JSON retains public server metadata without its credentials.
	code, stdout, stderr := runAPI(t, vars, "server", "list", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var servers []store.Server
	if err := json.Unmarshal([]byte(stdout), &servers); err != nil || len(servers) != len(fake.state.Servers) {
		t.Fatal("--json did not return the expected number of servers")
	}
	for i, srv := range servers {
		if srv.ID != fake.state.Servers[i].ID || srv.Name != fake.state.Servers[i].Name || srv.Link != "" {
			t.Error("--json did not return public server metadata")
		}
	}
	noSecrets(t, stdout)
	if !strings.HasSuffix(stdout, "\n") {
		t.Error("--json output does not end in a newline")
	}
}

// A subscription URL of the common SSPanel form ".../link/<token>?sub=3"
// has a one-character query value. A value that short is no secret the
// redactor looks for: the table keeps every name and endpoint with a "3".
func TestServerListWithShortSubscriptionQuery(t *testing.T) {
	const token = "4f9a1c7e2b5d6a8c"
	fake := newFake()
	fake.state.Subscriptions[0].URL = "https://provider.example/link/" + token + "?sub=3"
	fake.state.Servers[1].Name = "HK 03"
	vars := startDaemon(t, fake).env(t)

	out := ok(t, vars, "server", "list")
	got := rows(out)
	want := [][]string{
		{"ID", "NAME", "PROTOCOL", "ADDRESS", "STATE"},
		{"5ab3c4d5", "lab-a", "vless", "203.0.113.10:443", "enabled"},
		{"6bc4d5e6", "HK", "03", "trojan", "b.example.com:8443", "disabled"},
		{"7cd5e6f7", "lab-c", "shadowsocks", "[2001:db8::1]:8388", "enabled"},
	}
	if strings.Contains(out, token) {
		t.Fatal("the table shows the subscription token")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("table\n%s\nwant rows %q", out, want)
	}
}

func TestServerRemoveEnableDisable(t *testing.T) {
	fake := newFake()
	vars := startDaemon(t, fake).env(t)

	if out := ok(t, vars, "server", "rm", "5ab3c4d5"); !strings.Contains(out, "5ab3c4d5") {
		t.Errorf("rm: stdout %q", out)
	}
	if calls := fake.called("RemoveServer"); len(calls) != 1 || calls[0][0] != store.AnyRevision || calls[0][1] != "5ab3c4d5" {
		t.Errorf("RemoveServer calls %v", calls)
	}

	if out := ok(t, vars, "server", "disable", "5ab3c4d5"); !strings.Contains(out, "lab-a") || !strings.Contains(out, "disabled") {
		t.Errorf("disable: stdout %q", out)
	}
	if out := ok(t, vars, "server", "enable", "6bc4d5e6"); !strings.Contains(out, "lab-b") || !strings.Contains(out, "enabled") {
		t.Errorf("enable: stdout %q", out)
	}
	patches := fake.called("UpdateServer")
	if len(patches) != 2 {
		t.Fatalf("%d UpdateServer calls, want 2", len(patches))
	}
	for i, want := range []struct {
		id       string
		disabled bool
	}{{"5ab3c4d5", true}, {"6bc4d5e6", false}} {
		p := patches[i][2].(service.ServerPatch)
		if patches[i][1] != want.id || p.Disabled == nil || *p.Disabled != want.disabled || p.Name != nil || p.Link != nil || p.Outbound != nil {
			t.Errorf("UpdateServer(%v), want only Disabled=%t on %s", patches[i], want.disabled, want.id)
		}
	}

	code, stdout, stderr := runAPI(t, vars, "server", "enable", "00000000")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "not_found") || !strings.Contains(stderr, "00000000") {
		t.Errorf("an unknown server: exit %d, stdout %q, stderr %q; want 1 and not_found", code, stdout, stderr)
	}
}

func TestSubAdd(t *testing.T) {
	fake := newFake()
	vars := startDaemon(t, fake).env(t)

	// With no --name, the name is the URL's host: the rest of the URL is a
	// credential.
	out := ok(t, vars, "sub", "add", secretURL)
	if !strings.Contains(out, "9be8f7a6") || !strings.Contains(out, "sub.example.com") || !strings.Contains(out, "24h") {
		t.Errorf("stdout %q lacks the id, the name or the interval", out)
	}
	n := fake.called("AddSubscription")[0][1].(service.NewSubscription)
	if want := (service.NewSubscription{Name: "sub.example.com", URL: secretURL}); n != want {
		t.Errorf("AddSubscription got %+v, want %+v", n, want)
	}

	out = ok(t, vars, "sub", "add", secretURL, "--name", "lab", "--interval", "6h")
	if !strings.Contains(out, "lab") || !strings.Contains(out, "6h") {
		t.Errorf("stdout %q", out)
	}
	n = fake.called("AddSubscription")[1][1].(service.NewSubscription)
	if want := (service.NewSubscription{Name: "lab", URL: secretURL, Interval: store.Duration(6 * time.Hour)}); n != want {
		t.Errorf("AddSubscription got %+v, want %+v", n, want)
	}
}

func TestSubList(t *testing.T) {
	fake := newFake()
	vars := startDaemon(t, fake).env(t)

	out := ok(t, vars, "sub", "list")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("table has %d lines, want a header and 2 subscriptions:\n%s", len(lines), out)
	}
	for _, want := range []string{"ID", "NAME", "INTERVAL", "LAST FETCH", "STATE", "LAST ERROR"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("header %q lacks %q", lines[0], want)
		}
	}
	if f := strings.Fields(lines[1]); !reflect.DeepEqual(f, []string{"9be8f7a6", "lab", "24h", "2026-10-25T12:00:00Z", "enabled", "-"}) {
		t.Errorf("first row %q", f)
	}
	// The second one's error repeated its URL; the list does not.
	f := strings.Fields(lines[2])
	if !reflect.DeepEqual(f[:5], []string{"8ad6f7a8", "broken", "6h", "-", "disabled"}) {
		t.Errorf("second row %q", f)
	}
	if !strings.Contains(lines[2], "connection refused") || !strings.Contains(lines[2], "‹redacted›") {
		t.Errorf("second row %q should show the error with the URL redacted", lines[2])
	}

	code, stdout, stderr := runAPI(t, vars, "sub", "list", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var subs []store.Subscription
	if err := json.Unmarshal([]byte(stdout), &subs); err != nil || len(subs) != len(fake.state.Subscriptions) {
		t.Fatal("--json did not return the expected number of subscriptions")
	}
	for i, sub := range subs {
		if sub.ID != fake.state.Subscriptions[i].ID || sub.Name != fake.state.Subscriptions[i].Name || sub.URL != "" {
			t.Error("--json did not return public subscription metadata")
		}
	}
	noSecrets(t, stdout)
}

func TestSubRemoveAndRefresh(t *testing.T) {
	fake := newFake()
	fake.refresh = service.RefreshResult{
		Added: 2, Updated: 1, Removed: 0, Kept: 5, Via: "proxy",
		Skipped: []subscription.Skipped{{Line: "vless://" + secretID + "@bad#odd", Err: "unsupported"}},
	}
	vars := startDaemon(t, fake).env(t)

	if out := ok(t, vars, "sub", "rm", "9be8f7a6"); !strings.Contains(out, "9be8f7a6") {
		t.Errorf("rm: stdout %q", out)
	}
	if calls := fake.called("RemoveSubscription"); len(calls) != 1 || calls[0][1] != "9be8f7a6" {
		t.Errorf("RemoveSubscription calls %v", calls)
	}

	out := ok(t, vars, "sub", "refresh", "9be8f7a6")
	for _, want := range []string{"9be8f7a6", "proxy", "2 added", "1 updated", "0 removed", "5 kept", "vless://…", "unsupported"} {
		if !strings.Contains(out, want) {
			t.Errorf("refresh: stdout %q lacks %q", out, want)
		}
	}
	if strings.Contains(out, "#odd") {
		t.Error("the refresh repeated the private link fragment")
	}
	if calls := fake.called("RefreshSubscription"); len(calls) != 1 || calls[0][0] != "9be8f7a6" {
		t.Errorf("RefreshSubscription calls %v", calls)
	}

	fake.err = service.ErrFetchFailed
	code, stdout, stderr := runAPI(t, vars, "sub", "refresh", "9be8f7a6")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "fetch_failed") {
		t.Errorf("exit %d, stdout %q, stderr %q; want 1 and fetch_failed", code, stdout, stderr)
	}
}

func TestDevices(t *testing.T) {
	fake := newFake()
	vars := startDaemon(t, fake).env(t)

	out := ok(t, vars, "device", "set", "192.168.88.10", "smart", "--name", "tv")
	if !strings.Contains(out, "192.168.88.10/32") || !strings.Contains(out, "smart") {
		t.Errorf("stdout %q", out)
	}
	out = ok(t, vars, "device", "set", "192.168.88.0/24", "full", "--kill-switch")
	if !strings.Contains(out, "192.168.88.0/24") || !strings.Contains(out, "full") || !strings.Contains(out, "kill switch") {
		t.Errorf("stdout %q", out)
	}
	sets := fake.called("SetDevice")
	if len(sets) != 2 {
		t.Fatalf("%d SetDevice calls, want 2", len(sets))
	}
	if want := (store.Device{Address: netip.MustParsePrefix("192.168.88.10/32"), Name: "tv", Policy: store.Policy{Mode: store.ModeSmart}}); sets[0][1] != want {
		t.Errorf("first SetDevice %+v, want %+v", sets[0][1], want)
	}
	if want := (store.Device{Address: netip.MustParsePrefix("192.168.88.0/24"), Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}}); sets[1][1] != want {
		t.Errorf("second SetDevice %+v, want %+v", sets[1][1], want)
	}

	if out := ok(t, vars, "device", "rm", "192.168.88.0/24"); !strings.Contains(out, "192.168.88.0/24") {
		t.Errorf("rm: stdout %q", out)
	}
	ok(t, vars, "device", "rm", "192.168.88.10")
	rms := fake.called("RemoveDevice")
	if len(rms) != 2 || rms[0][1] != netip.MustParsePrefix("192.168.88.0/24") || rms[1][1] != netip.MustParsePrefix("192.168.88.10/32") {
		t.Errorf("RemoveDevice calls %v", rms)
	}

	got := rows(ok(t, vars, "device", "list"))
	want := [][]string{
		{"ADDRESS", "NAME", "MODE", "KILL-SWITCH"},
		{"192.168.88.10/32", "tv", "smart", "no"},
		{"192.168.88.0/24", "-", "full", "yes"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("device list rows %q, want %q", got, want)
	}

	code, stdout, stderr := runAPI(t, vars, "device", "list", "--json")
	var devs []store.Device
	if code != 0 || stderr != "" || json.Unmarshal([]byte(stdout), &devs) != nil || !reflect.DeepEqual(devs, fake.state.Devices) {
		t.Errorf("--json: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	// The daemon's refusal.
	fake.err = &service.Refused{Reason: "devices[0].policy: a kill switch needs a proxied mode"}
	code, _, stderr = runAPI(t, vars, "device", "set", "192.168.88.11", "direct", "--kill-switch")
	if code != 1 || !strings.Contains(stderr, "a kill switch needs a proxied mode") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}

func TestPolicyDefault(t *testing.T) {
	fake := newFake()
	vars := startDaemon(t, fake).env(t)

	if out := ok(t, vars, "policy", "default", "smart"); !strings.Contains(out, "smart") {
		t.Errorf("stdout %q", out)
	}
	if out := ok(t, vars, "policy", "default", "full", "--kill-switch"); !strings.Contains(out, "full") || !strings.Contains(out, "kill switch") {
		t.Errorf("stdout %q", out)
	}
	calls := fake.called("SetDefaultPolicy")
	if len(calls) != 2 || calls[0][1] != (store.Policy{Mode: store.ModeSmart}) || calls[1][1] != (store.Policy{Mode: store.ModeFull, KillSwitch: true}) {
		t.Errorf("SetDefaultPolicy calls %v", calls)
	}
}

func TestStatus(t *testing.T) {
	fake := newFake()
	vars := startDaemon(t, fake).env(t)

	out := ok(t, vars, "status")
	for _, want := range []string{
		"revision", "7", "applied", "yes", "26.10.21", "tested", "degraded", "committed",
		"lab-a", "vless", "203.0.113.10:443", "alive", "120ms", "selected",
		"lab-b", "disabled", "lab-c", "dead",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}

	code, stdout, stderr := runAPI(t, vars, "status", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var st service.Status
	if err := json.Unmarshal([]byte(stdout), &st); err != nil || st.Revision != 7 || st.Core != "26.10.21" || st.Health.Selected != "5ab3c4d5" {
		t.Errorf("--json printed %q (%v), want the API's status", stdout, err)
	}
}

func TestStatusShowsWhatIsNotWell(t *testing.T) {
	fake := newFake()
	fake.status.Applied, fake.status.Pending = false, true
	fake.status.Core, fake.status.CoreTested = "", false
	fake.status.Degraded = []string{"6bc4d5e6"}
	fake.status.Health.Level = "down"
	fake.status.Health.Runner = health.RunnerHealth{Err: "the runner can't be reached\nsecond line"}
	fake.status.Router = &service.RouterStatus{Revision: 6, Pending: true, Degraded: "unavailable", LastVerified: time.Unix(100, 0).UTC()}
	vars := startDaemon(t, fake).env(t)

	out := ok(t, vars, "status")
	for _, want := range []string{"no", "pending", "down", "the runner can't be reached second line", "6bc4d5e6", "routeros", "revision 6", "unavailable", atTime(fake.status.Router.LastVerified)} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "reached\nsecond") {
		t.Errorf("status shows a line break from an error text:\n%s", out)
	}
}

func TestEvents(t *testing.T) {
	fake := newFake()
	vars := startDaemon(t, fake).env(t)

	out := ok(t, vars, "events")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines, want 2:\n%s", len(lines), out)
	}
	if f := strings.Fields(lines[0]); len(f) < 4 || f[0] != "5" || f[1] != "2026-10-25T12:00:00Z" || f[2] != service.KindApply || strings.Join(f[3:], " ") != "revision 6 applied" {
		t.Errorf("first line %q", lines[0])
	}

	out = ok(t, vars, "events", "--after", "5")
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 1 || !strings.Contains(lines[0], "subscription 9be8f7a6") {
		t.Errorf("--after 5 printed %q, want event 6 alone", out)
	}
	if got := fake.called("Events"); len(got) != 2 || got[1][0] != uint64(5) {
		t.Errorf("Events calls %v, want after=5 the second time", got)
	}

	// An event text is one line, whatever it holds.
	fake.events = []service.Event{{Seq: 9, At: t0, Kind: service.KindError, Message: "first\nsecond\x1b[31m"}}
	out = ok(t, vars, "events")
	if strings.Count(strings.TrimSpace(out), "\n") != 0 || strings.Contains(out, "\x1b") {
		t.Errorf("events printed %q, want one line with no control characters", out)
	}

	fake.events = nil
	if out := ok(t, vars, "events"); out != "" {
		t.Errorf("no events printed %q", out)
	}
}

func TestEveryAPICommandNeedsTheDaemon(t *testing.T) {
	for _, args := range [][]string{
		{"server", "add", "vless://x"},
		{"server", "list"},
		{"server", "list", "--json"},
		{"server", "rm", "5ab3c4d5"},
		{"server", "enable", "5ab3c4d5"},
		{"server", "disable", "5ab3c4d5"},
		{"sub", "add", "https://sub.example.com/feed"},
		{"sub", "list"},
		{"sub", "rm", "9be8f7a6"},
		{"sub", "refresh", "9be8f7a6"},
		{"device", "set", "192.168.88.10", "smart"},
		{"device", "rm", "192.168.88.10"},
		{"device", "list"},
		{"policy", "default", "smart"},
		{"status"},
		{"events"},
		{"token", "create", "ci"},
		{"token", "create", "ci", "--expires", "720h"},
		{"token", "list"},
		{"token", "list", "--json"},
		{"token", "rm", "3fa9c1d2"},
	} {
		vars := noDaemonEnv(t)
		code, stdout, stderr := runCLI(t, vars, args...)
		if code != 1 || stdout != "" || !strings.Contains(stderr, "tikray serve is not running") {
			t.Errorf("tikray %q: exit %d, stdout %q, stderr %q; want 1 and \"tikray serve is not running\"", args, code, stdout, stderr)
		}
		// Nothing is written: the state is the daemon's.
		if ents, _ := os.ReadDir(vars["TIKRAY_DATA"]); len(ents) != 0 {
			t.Errorf("tikray %q created %v in the data root", args, dirNamesOf(ents))
		}
	}
}

func dirNamesOf(ents []os.DirEntry) []string {
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// With no daemon the command fails before it reads the outbound file.
func TestServerAddWithoutDaemonReadsNoFile(t *testing.T) {
	vars := noDaemonEnv(t)
	code, _, stderr := runCLI(t, vars, "server", "add", "--json", filepath.Join(t.TempDir(), "none.json"), "--name", "x")
	if code != 1 || !strings.Contains(stderr, "tikray serve is not running") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}

// --- apply, core update and core rollback

func TestApplyGoesThroughTheDaemon(t *testing.T) {
	fake := newFake()
	d := startDaemon(t, fake)
	vars := d.env(t)
	data := vars["TIKRAY_DATA"]

	code, stdout, stderr := runAPI(t, vars, "apply")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	res := decodeResult(t, stdout)
	if res.Outcome != runnerapi.OutcomeCommitted || res.Kind != artifacts.KindConfig || res.To != "26.10.21" {
		t.Errorf("result %+v, want the daemon's", res)
	}
	if n := len(fake.called("ApplyNow")); n != 1 {
		t.Errorf("%d ApplyNow calls, want 1", n)
	}
	// Same as the direct path: the result is saved.
	if saved, err := os.ReadFile(filepath.Join(data, "state", "last-result.json")); err != nil || string(saved) != stdout {
		t.Errorf("last-result.json is %q (%v), want the stdout %q", saved, err, stdout)
	}
	// The CLI wrote no state, and made no updater of its own.
	if _, err := os.Stat(filepath.Join(data, "state", "state.v1.json")); err == nil {
		t.Error("the CLI wrote a state file while the daemon ran")
	}
	if _, err := os.Stat(filepath.Join(data, "state", "core-history.jsonl")); err == nil {
		t.Error("the CLI wrote a history while the daemon ran")
	}
}

func TestCoreUpdateAndRollbackGoThroughTheDaemon(t *testing.T) {
	fake := newFake()
	fake.result = artifacts.Result{From: "26.3.27", To: "26.10.21", Outcome: runnerapi.OutcomeCommitted, Source: "github", Verified: "sha256", At: t0}
	vars := startDaemon(t, fake).env(t)

	code, stdout, stderr := runAPI(t, vars, "core", "update", "26.10.21")
	if code != 0 || stderr != "" {
		t.Fatalf("update: exit %d, stderr %q", code, stderr)
	}
	if res := decodeResult(t, stdout); res.Outcome != runnerapi.OutcomeCommitted || res.To != "26.10.21" || res.Source != "github" {
		t.Errorf("update: result %+v", res)
	}
	code, _, stderr = runAPI(t, vars, "core", "update", "--allow-unverified", "latest")
	if code != 0 || stderr != "" {
		t.Fatalf("update latest: exit %d, stderr %q", code, stderr)
	}
	updates := fake.called("CoreUpdate")
	if len(updates) != 2 ||
		updates[0][0] != "26.10.21" || updates[0][1] != (artifacts.UpdateOptions{}) ||
		updates[1][0] != "latest" || updates[1][1] != (artifacts.UpdateOptions{AllowUnverified: true}) {
		t.Errorf("CoreUpdate calls %v", updates)
	}

	code, stdout, stderr = runAPI(t, vars, "core", "rollback")
	if code != 0 || stderr != "" || decodeResult(t, stdout).Outcome != runnerapi.OutcomeCommitted {
		t.Errorf("rollback: exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	if n := len(fake.called("CoreRollback")); n != 1 {
		t.Errorf("%d CoreRollback calls, want 1", n)
	}
}

func TestNoopThroughTheDaemonIsSuccess(t *testing.T) {
	fake := newFake()
	fake.result = artifacts.Result{To: "26.10.21", Outcome: artifacts.OutcomeNoop, Detail: "already active", Kind: artifacts.KindConfig, At: t0}
	vars := startDaemon(t, fake).env(t)
	if code, _, stderr := runAPI(t, vars, "apply"); code != 0 {
		t.Errorf("exit %d, stderr %q; want 0 for a noop", code, stderr)
	}
}

func TestDaemonFailureOfAnOperation(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string // in stderr and in the saved result's detail
	}{
		{"another update holds the lock", artifacts.ErrLocked, "busy"},
		{"the runner can't be reached", service.ErrRunnerUnavailable, "runner_unavailable"},
		{"the trial failed", &service.Refused{Reason: "rejected: xray says no"}, "rejected: xray says no"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFake()
			// The daemon's updater did not run, so there is no result.
			fake.err, fake.result = tc.err, artifacts.Result{}
			vars := startDaemon(t, fake).env(t)
			for _, args := range [][]string{{"apply"}, {"core", "update", "26.10.21"}, {"core", "rollback"}} {
				code, stdout, stderr := runAPI(t, vars, args...)
				if code != 1 || !strings.Contains(stderr, tc.want) {
					t.Errorf("tikray %q: exit %d, stderr %q; want 1 and %q", args, code, stderr, tc.want)
				}
				// As for the direct path, stdout holds this run's result: the
				// daemon sent none of its updater's, so it is a refusal that
				// carries the daemon's words.
				res := decodeResult(t, stdout)
				if res.Outcome != artifacts.OutcomeRefused || !strings.Contains(res.Detail, tc.want) {
					t.Errorf("tikray %q: result %+v, want a refused one naming %q", args, res, tc.want)
				}
				if saved, err := os.ReadFile(filepath.Join(vars["TIKRAY_DATA"], "state", "last-result.json")); err != nil || string(saved) != stdout {
					t.Errorf("tikray %q: last-result.json is %q (%v), want the stdout", args, saved, err)
				}
			}
		})
	}
}

// An operation that the daemon's updater ran to an outcome and that failed is
// reported with that result, as the direct path reports it: printed, saved and
// with its exit code, its outcome and the rest kept.
func TestDaemonFailureReportsTheDaemonsResult(t *testing.T) {
	for _, res := range []artifacts.Result{
		{From: "26.3.27", To: "26.10.21", Outcome: runnerapi.OutcomeRejected, Source: "github", Verified: "sha256", Detail: "xray says no", At: t0},
		{From: "26.10.21", To: "26.10.21", Outcome: artifacts.OutcomeUnhealthy, Kind: artifacts.KindConfig, Detail: "health check failing for 15s: socks connect: general failure", At: t0},
	} {
		t.Run(res.Outcome, func(t *testing.T) {
			fake := newFake()
			fake.err, fake.result = errors.New(res.Outcome+": "+res.Detail), res
			vars := startDaemon(t, fake).env(t)
			for _, args := range [][]string{{"apply"}, {"core", "update", "26.10.21"}, {"core", "rollback"}} {
				code, stdout, stderr := runAPI(t, vars, args...)
				if code != 1 || !strings.Contains(stderr, res.Detail) {
					t.Errorf("tikray %q: exit %d, stderr %q; want 1 and the daemon's error", args, code, stderr)
				}
				if got := decodeResult(t, stdout); got != res {
					t.Errorf("tikray %q: result %+v, want the daemon's %+v", args, got, res)
				}
				if saved, err := os.ReadFile(filepath.Join(vars["TIKRAY_DATA"], "state", "last-result.json")); err != nil || string(saved) != stdout {
					t.Errorf("tikray %q: last-result.json is %q (%v), want the stdout", args, saved, err)
				}
			}
		})
	}
}

// An interrupted command leaves the operation running in the daemon, and says
// so rather than that the operation failed.
func TestInterruptedOperationSaysTheDaemonGoesOn(t *testing.T) {
	fake := newFake()
	entered, release := make(chan struct{}), make(chan struct{})
	fake.gate = func(ctx context.Context) {
		close(entered)
		<-release
	}
	vars := startDaemon(t, fake).env(t)
	t.Cleanup(func() { // before the server waits for its handlers
		select {
		case <-release:
		default:
			close(release)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	type out struct {
		code           int
		stdout, stderr string
	}
	done := make(chan out, 1)
	go func() {
		var o, e bytes.Buffer
		code := run(ctx, []string{"apply"}, envOf(vars), &o, &e)
		done <- out{code, o.String(), e.String()}
	}()
	<-entered
	cancel()
	select {
	case r := <-done:
		if r.code != 1 || !strings.Contains(r.stderr, "tikray serve goes on") {
			t.Errorf("exit %d, stderr %q; want 1 and that the daemon goes on", r.code, r.stderr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the command did not stop when interrupted")
	}
	close(release)
}

func TestCoreUpdateWithAConfigFileNeedsTheDaemonStopped(t *testing.T) {
	fake := newFake()
	d := startDaemon(t, fake)
	vars := d.env(t)
	cfgFile, _ := configFile(t, `{"log":{}}`)

	code, stdout, stderr := runAPI(t, vars, "core", "update", "26.10.21", "--config", cfgFile)
	if code != 1 || !strings.Contains(stderr, "--config") || !strings.Contains(stderr, "tikray serve") {
		t.Errorf("exit %d, stderr %q; want 1 and an error about --config and tikray serve", code, stderr)
	}
	if res := decodeResult(t, stdout); res.Outcome != artifacts.OutcomeRefused || res.To != "26.10.21" {
		t.Errorf("result %+v, want a refusal of the version asked for", res)
	}
	if got := fake.mutations(); len(got) != 0 {
		t.Errorf("the daemon was asked to %v", got)
	}
}

// With nothing listening on the API's address, apply, update and rollback are
// M2a's direct commands, and run as before.
func TestNothingListeningMeansTheDirectPath(t *testing.T) {
	vars, data, runner := trialEnv(t, &runnerapi.Selection{Core: "26.10.21", Config: testConfigRel})
	vars["TIKRAY_API"] = "https://" + closedAddr(t)
	st := writeState(t, data, func(*store.State) {})

	code, stdout, stderr := runFast(t, vars, "apply")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	if res := decodeResult(t, stdout); res.Outcome != runnerapi.OutcomeCommitted {
		t.Errorf("result %+v, want committed", res)
	}
	if strings.Contains(stderr, "not running") {
		t.Errorf("stderr %q: a direct apply says nothing of the daemon", stderr)
	}
	if got, want := runner.active().Config, configName(t, st, "26.10.21"); got != want {
		t.Errorf("the runner is on %s, want %s", got, want)
	}
}

// A daemon that answers badly is no daemon that is not there: the command
// must not fall back to writing the state itself, beside a process that owns it.
func TestAnUntrustedDaemonIsNotBypassed(t *testing.T) {
	hang := func(t *testing.T) map[string]string {
		// A TLS server that takes its time over /healthz.
		release := make(chan struct{})
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
		srv.StartTLS()
		t.Cleanup(srv.Close)
		t.Cleanup(func() { close(release) })
		return map[string]string{"TIKRAY_API": srv.URL, "TIKRAY_API_FINGERPRINT": (&daemon{srv: srv}).fingerprint()}
	}
	for name, tc := range map[string]struct {
		change func(t *testing.T, d *daemon, vars map[string]string)
		want   string
	}{
		"another certificate": {func(t *testing.T, d *daemon, vars map[string]string) {
			vars["TIKRAY_API_FINGERPRINT"] = strings.Repeat("ab", 32)
		}, "certificate"},
		"no answer in time": {func(t *testing.T, d *daemon, vars map[string]string) {
			for k, v := range hang(t) {
				vars[k] = v
			}
		}, "did not answer"},
		"not a tikray": {func(t *testing.T, d *daemon, vars map[string]string) {
			// Pinned correctly, but the thing answers /healthz with an error.
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "nope", http.StatusTeapot)
			}))
			srv.StartTLS()
			t.Cleanup(srv.Close)
			vars["TIKRAY_API"] = srv.URL
			vars["TIKRAY_API_FINGERPRINT"] = (&daemon{srv: srv}).fingerprint()
		}, "418"},
	} {
		t.Run(name, func(t *testing.T) {
			defer func(old time.Duration) { probeWait = old }(probeWait)
			probeWait = 150 * time.Millisecond

			fake := newFake()
			d := startDaemon(t, fake)
			vars, data, runner := trialEnv(t, &runnerapi.Selection{Core: "26.10.21", Config: testConfigRel})
			vars["TIKRAY_API"], vars["TIKRAY_API_TOKEN"], vars["TIKRAY_API_FINGERPRINT"] = d.srv.URL, apiToken, d.fingerprint()
			tc.change(t, d, vars)
			writeState(t, data, func(*store.State) {})
			stateFile := filepath.Join(data, "state", "state.v1.json")
			before, err := os.ReadFile(stateFile)
			if err != nil {
				t.Fatal(err)
			}

			for _, args := range [][]string{{"apply"}, {"core", "update", "26.10.21"}, {"core", "rollback"}, {"server", "list"}, {"status"}, {"admin", "reset"}, {"token", "list"}} {
				code, _, stderr := runFast(t, vars, args...)
				if code != 1 || !strings.Contains(stderr, tc.want) {
					t.Errorf("tikray %q: exit %d, stderr %q; want 1 and %q", args, code, stderr, tc.want)
				}
				if strings.Contains(stderr, "not running") || strings.Contains(stderr, apiToken) {
					t.Errorf("tikray %q: stderr %q", args, stderr)
				}
			}
			if n := len(runner.candidates()); n != 0 {
				t.Errorf("%d trials: the direct path ran beside a daemon", n)
			}
			if after, err := os.ReadFile(stateFile); err != nil || !bytes.Equal(after, before) {
				t.Errorf("the state file changed (%v)", err)
			}
			// admin reset's direct path would open the auth store, which makes
			// these.
			for _, name := range []string{"auth.json", "setup.code"} {
				if _, err := os.Stat(filepath.Join(data, "state", name)); err == nil {
					t.Errorf("%s was made: the direct path of admin reset ran beside a daemon", name)
				}
			}
			if got := fake.mutations(); len(got) != 0 {
				t.Errorf("the daemon was asked to %v", got)
			}
		})
	}
}

func TestMissingAndWrongTokens(t *testing.T) {
	fake := newFake()
	d := startDaemon(t, fake)

	t.Run("no token anywhere", func(t *testing.T) {
		vars := d.env(t)
		delete(vars, "TIKRAY_API_TOKEN")
		for _, args := range [][]string{{"server", "list"}, {"apply"}} {
			code, _, stderr := runAPI(t, vars, args...)
			if code != 1 || !strings.Contains(stderr, "TIKRAY_API_TOKEN") || !strings.Contains(stderr, "api.token") {
				t.Errorf("tikray %q: exit %d, stderr %q; want 1 and the two places a token comes from", args, code, stderr)
			}
		}
		if got := fake.mutations(); len(got) != 0 {
			t.Errorf("the daemon was asked to %v", got)
		}
	})

	t.Run("wrong token", func(t *testing.T) {
		vars := d.env(t)
		const wrong = "0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0d"
		vars["TIKRAY_API_TOKEN"] = wrong
		code, stdout, stderr := runAPI(t, vars, "server", "list")
		if code != 1 || stdout != "" || !strings.Contains(stderr, "unauthorized") {
			t.Errorf("exit %d, stdout %q, stderr %q; want 1 and unauthorized", code, stdout, stderr)
		}
		if strings.Contains(stderr, wrong) {
			t.Errorf("stderr %q repeats the token it was given", stderr)
		}
	})
}

// With no variable but the data root, the token comes from state/api.token and
// the fingerprint from state/tls.crt, the files tikray serve makes.
func TestTokenAndFingerprintFromTheStateDirectory(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, "state")
	token, err := api.LoadOrCreateToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := api.LoadOrCreateCert(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	fake := newFake()
	srv := httptest.NewUnstartedServer(apiHandler(t, fake, token))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.Config.ErrorLog = discardLog()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	t.Setenv("TMPDIR", t.TempDir())

	// run is runCLI that checks the token of the file stays out of the output.
	run := func(vars map[string]string, args ...string) (int, string, string) {
		t.Helper()
		code, stdout, stderr := runCLI(t, vars, args...)
		if strings.Contains(stdout+stderr, token) {
			t.Errorf("tikray %q: the token is in the output: %q %q", args, stdout, stderr)
		}
		return code, stdout, stderr
	}
	vars := map[string]string{"TIKRAY_DATA": data, "TIKRAY_API": srv.URL}
	if code, stdout, stderr := run(vars, "server", "list"); code != 0 || !strings.Contains(stdout, "lab-a") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	// A variable wins over its file.
	vars["TIKRAY_API_TOKEN"] = "0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0de0badc0d"
	if code, _, stderr := run(vars, "server", "list"); code != 1 || !strings.Contains(stderr, "unauthorized") {
		t.Errorf("a wrong TIKRAY_API_TOKEN: exit %d, stderr %q; want unauthorized", code, stderr)
	}
	delete(vars, "TIKRAY_API_TOKEN")
	vars["TIKRAY_API_FINGERPRINT"] = strings.Repeat("cd", 32)
	if code, _, stderr := run(vars, "server", "list"); code != 1 || !strings.Contains(stderr, "certificate") {
		t.Errorf("a wrong TIKRAY_API_FINGERPRINT: exit %d, stderr %q; want a certificate error", code, stderr)
	}
	delete(vars, "TIKRAY_API_FINGERPRINT")

	// An editor leaves a newline at the end of the token file.
	if err := os.WriteFile(filepath.Join(dir, "api.token"), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run(vars, "server", "list"); code != 0 {
		t.Errorf("a token file with a newline: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

// --- sign-in: the setup code, the admin and the tokens

// stateSnapshot is the content and the time of the files of the state
// directory that sign-in keeps, for a test that a command left them as they
// were. A file that is not there is not in it.
func stateSnapshot(t *testing.T, data string) map[string]string {
	t.Helper()
	got := map[string]string{}
	for _, name := range []string{"auth.json", "setup.code"} {
		path := filepath.Join(data, "state", name)
		fi, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		b, rerr := os.ReadFile(path)
		if err != nil || rerr != nil {
			t.Fatal(err, rerr)
		}
		got[name] = fi.ModTime().String() + " " + string(b)
	}
	return got
}

// setup-code shows the code from the file. It is a read: it works while serve
// runs, with no token and no lock, and it makes nothing.
func TestSetupCodeCommand(t *testing.T) {
	const claimed = "the admin has been claimed\n"

	t.Run("before serve has run", func(t *testing.T) {
		vars := noDaemonEnv(t)
		code, stdout, stderr := runCLI(t, vars, "setup-code")
		if code != 1 || stdout != "" || stderr != "tikray: no setup code yet: start tikray serve\n" {
			t.Errorf("exit %d, want 1 and the no-setup-code message on stderr", code)
		}
		if strings.Contains(stdout+stderr, "claimed") {
			t.Error("setup-code says the admin is claimed when there is none")
		}
		// Not even the state directory, or the lock: a read makes nothing.
		if ents, _ := os.ReadDir(vars["TIKRAY_DATA"]); len(ents) != 0 {
			t.Errorf("setup-code created %v in the data root", dirNamesOf(ents))
		}
	})

	t.Run("while serve runs, and after the claim", func(t *testing.T) {
		vars, data := serveEnv(t)
		r := startServe(t, vars)
		// Nothing but the data root: no daemon to reach, and no token.
		cli := map[string]string{"TIKRAY_DATA": data}
		want := setupCodeOf(t, data)
		before := stateSnapshot(t, data)

		code, stdout, stderr := runCLI(t, cli, "setup-code")
		if code != 0 || stdout != want+"\n" || stderr != "" {
			t.Errorf("exit %d, want only the code in setup.code on stdout", code)
		}
		if after := stateSnapshot(t, data); !reflect.DeepEqual(before, after) {
			t.Error("setup-code changed auth.json or setup.code")
		}

		r.claimAdmin(t, want)
		code, stdout, stderr = runCLI(t, cli, "setup-code")
		if code != 0 || stdout != claimed || stderr != "" {
			t.Errorf("after the claim: exit %d, want only the claimed message", code)
		}
		if _, err := os.Stat(filepath.Join(data, "state", "setup.code")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("setup-code made setup.code beside the admin: %v", err)
		}

		// Without serve, the same.
		if c := r.stop(t); c != 0 {
			t.Fatalf("exit %d", c)
		}
		if code, stdout, _ := runCLI(t, cli, "setup-code"); code != 0 || stdout != claimed {
			t.Errorf("serve stopped: exit %d, want only the claimed message", code)
		}

		// A code that a claim that died left beside the admin is not shown.
		if err := os.WriteFile(filepath.Join(data, "state", "setup.code"), []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
		code, stdout, _ = runCLI(t, cli, "setup-code")
		if code != 0 || stdout != claimed || strings.Contains(stdout, want) {
			t.Errorf("with a stale code beside the admin: exit %d, want only the claimed message", code)
		}
	})
}

// admin reset goes through serve when it answers, and takes the lock and does
// it itself when nothing does, and then it is the same reset.
func TestAdminResetViaDaemonAndDirect(t *testing.T) {
	const done = "the admin was reset: run \"tikray setup-code\" for the new setup code\n"
	vars, data := serveEnv(t)
	r := startServe(t, vars)
	cli := map[string]string{"TIKRAY_DATA": data, "TIKRAY_API": "https://" + r.addr}
	state := filepath.Join(data, "state")

	first := setupCodeOf(t, data)
	cookie := r.claimAdmin(t, first)
	if _, in := r.authState(t, cookie); !in {
		t.Fatal("the admin is not signed in after its claim")
	}

	// Through the daemon: it is the one that resets, and it says so in its
	// events (the direct path has no service to tell).
	if out := ok2(t, cli, "admin", "reset"); out != done {
		t.Error("admin reset did not print the recovery instructions")
	}
	if events := ok2(t, cli, "events"); !strings.Contains(events, "auth  admin reset from 127.0.0.1") {
		t.Error("serve recorded no reset event")
	}
	if need, in := r.authState(t, cookie); !need || in {
		t.Errorf("after the reset setup_required is %v and signed_in %v, want true and false", need, in)
	}
	second := strings.TrimSpace(ok2(t, cli, "setup-code"))
	if !setupCodeForm.MatchString(second) || second == first || second != setupCodeOf(t, data) {
		t.Error("after reset setup-code must show only the new code in setup.code")
	}
	if resp, _ := r.call(t, http.MethodPost, "/v1/auth/login", map[string]string{"username": "alice", "password": adminPassword}, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the old admin signed in after the reset: status %d", resp.StatusCode)
	}
	if resp, _ := r.call(t, http.MethodPost, "/v1/auth/setup", map[string]string{"code": first, "username": "alice", "password": adminPassword}, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the old setup code claimed after the reset: status %d", resp.StatusCode)
	}
	r.claimAdmin(t, second) // the new one does

	// Without a daemon: it takes serve.lock, and does it itself.
	if c := r.stop(t); c != 0 {
		t.Fatalf("exit %d", c)
	}
	// A serve that the probe can't see still owns the state, and the reset
	// leaves it alone.
	unlock, err := lockServe(data)
	if err != nil {
		t.Fatal(err)
	}
	before := stateSnapshot(t, data)
	code, stdout, stderr := runCLI(t, cli, "admin", "reset")
	if want := "tikray: tikray serve is running (it holds " + filepath.Join(state, "serve.lock") + ")\n"; code != 1 || stdout != "" || stderr != want {
		t.Errorf("with the lock held: exit %d, stdout %q, stderr %q; want 1 and %q", code, stdout, stderr, want)
	}
	if after := stateSnapshot(t, data); !reflect.DeepEqual(before, after) {
		t.Error("a reset beside a serve that holds the lock changed auth.json or setup.code")
	}
	unlock()

	if out := ok2(t, cli, "admin", "reset"); out != done {
		t.Error("direct admin reset did not print the recovery instructions")
	}
	b, err := os.ReadFile(filepath.Join(state, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Admin *json.RawMessage `json:"admin"`
	}
	if err := json.Unmarshal(b, &file); err != nil || file.Admin != nil {
		t.Errorf("auth.json after the direct reset still has an admin (%v)", err)
	}
	third := setupCodeOf(t, data)
	if !setupCodeForm.MatchString(third) || third == second {
		t.Error("the direct reset made no new setup code")
	}
	if fi, err := os.Stat(filepath.Join(state, "setup.code")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("setup.code after the direct reset: %v, %v; want mode 600", fi, err)
	}
	// The lock was let go of, and serve starts on what the reset left.
	unlock, err = lockServe(data)
	if err != nil {
		t.Fatalf("the direct reset kept the lock: %v", err)
	}
	unlock()
	again := startServe(t, vars)
	if need, _ := again.authState(t, nil); !need {
		t.Error("serve after the direct reset has an admin")
	}
	if got := setupCodeOf(t, data); got != third {
		t.Error("serve changed the setup code the direct reset made")
	}
}

// An admin reset is the root token's. A named token is refused by the daemon
// and its refusal is reported as the daemon's own.
func TestAdminResetNeedsTheRootToken(t *testing.T) {
	vars, data := serveEnv(t)
	r := startServe(t, vars)
	cli := map[string]string{"TIKRAY_DATA": data, "TIKRAY_API": "https://" + r.addr}
	named := strings.Split(ok2(t, cli, "token", "create", "script"), "\n")[0]

	asToken := maps.Clone(cli)
	asToken["TIKRAY_API_TOKEN"] = named
	code, stdout, stderr := runCLI(t, asToken, "admin", "reset")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "forbidden") || strings.Contains(stderr, named) {
		t.Errorf("a named token's reset: exit %d, want 1 and a safe forbidden error", code)
	}
}

// token create shows the token once, token list never shows a secret, and
// token rm ends one.
func TestTokenCommands(t *testing.T) {
	d := startDaemon(t, newFake())
	vars := d.env(t)
	form := regexp.MustCompile(`^tkr_([0-9a-f]{8})_([A-Za-z0-9_-]{43})$`)

	create := func(args ...string) string {
		t.Helper()
		code, out, hint := runCLI(t, vars, append([]string{"token", "create"}, args...)...)
		if code != 0 || hint != "this token is shown only once\n" || strings.Count(out, "\n") != 1 {
			t.Fatalf("token create must print only the token on stdout and its notice on stderr (exit %d)", code)
		}
		token := strings.TrimSuffix(out, "\n")
		if !form.MatchString(token) {
			t.Fatal("token create did not return a token")
		}
		return token
	}
	token := create("ci-runner", "--expires", "720h")
	m := form.FindStringSubmatch(token)
	id, secret := m[1], m[2]
	other := create("backup")
	otherID := form.FindStringSubmatch(other)[1]

	// The list has the ids, the names and the times, and no secret: not the
	// token, not the part of it that is one, and (in the JSON) no token at all.
	table := ok(t, vars, "token", "list")
	if got := rows(table)[0]; !reflect.DeepEqual(got, []string{"ID", "NAME", "CREATED", "EXPIRES", "LAST", "USED"}) {
		t.Errorf("the header is %q", got)
	}
	rowOf := func(table, id string) []string {
		for _, row := range rows(table) {
			if row[0] == id {
				return row
			}
		}
		return nil
	}
	// id, name, created, expires, last used
	if row := rowOf(table, id); len(row) != 5 || row[1] != "ci-runner" || row[3] == "never" || row[4] != "never" {
		t.Errorf("the row of the token with an expiry is %q, want its name, a time to expire at and never used", row)
	} else if _, err := time.Parse(time.RFC3339, row[3]); err != nil {
		t.Errorf("the expiry %q is no time: %v", row[3], err)
	}
	if row := rowOf(table, otherID); len(row) != 5 || row[1] != "backup" || row[3] != "never" || row[4] != "never" {
		t.Errorf("the row of the token that does not expire is %q, want its name and never, never", row)
	}
	jsonOut := ok(t, vars, "token", "list", "--json")
	var listed []apiclient.TokenInfo
	if err := json.Unmarshal([]byte(jsonOut), &listed); err != nil || len(listed) != 2 {
		t.Fatalf("token list --json: %v, %d tokens, want 2", err, len(listed))
	}
	if got := time.Until(listed[0].Expires); got < 719*time.Hour || got > 721*time.Hour {
		t.Errorf("--expires 720h gave a token that expires in %v", got)
	}
	if !listed[1].Expires.IsZero() {
		t.Errorf("a token made with no --expires expires at %v", listed[1].Expires)
	}
	for name, shown := range map[string]string{"the table": table, "the JSON": jsonOut} {
		for what, s := range map[string]string{"the token": token, "its secret": secret, "the prefix of a token": "tkr_"} {
			if strings.Contains(shown, s) {
				t.Errorf("%s shows %s", name, what)
			}
		}
	}

	// The token works, and its use is noted.
	use := maps.Clone(vars)
	use["TIKRAY_API_TOKEN"] = token
	if code, stdout, stderr := runCLI(t, use, "token", "list"); code != 0 || strings.Contains(stdout+stderr, secret) {
		t.Errorf("token list with the new token: exit %d or unsafe output", code)
	}
	if err := json.Unmarshal([]byte(ok(t, vars, "token", "list", "--json")), &listed); err != nil || listed[0].LastUsed.IsZero() {
		t.Errorf("the list does not show that the token was used (%v)", err)
	}

	// Revoking one ends it, and only it.
	if got := ok(t, vars, "token", "rm", id); got != "revoked token "+id+"\n" {
		t.Errorf("token rm printed %q", got)
	}
	if table := ok(t, vars, "token", "list"); strings.Contains(table, id) || !strings.Contains(table, otherID) {
		t.Error("the list must include only the surviving token")
	}
	if code, _, stderr := runCLI(t, use, "token", "list"); code != 1 || !strings.Contains(stderr, "unauthorized") {
		t.Errorf("a revoked token: exit %d, want 1 and unauthorized", code)
	}
	// What the API refuses is printed as it says it.
	if code, stdout, stderr := runAPI(t, vars, "token", "rm", id); code != 1 || stdout != "" || !strings.HasPrefix(stderr, "tikray: not_found: ") {
		t.Errorf("revoking it again: exit %d, want 1 and not_found", code)
	}
	if code, stdout, stderr := runAPI(t, vars, "token", "create", ""); code != 1 || stdout != "" || !strings.HasPrefix(stderr, "tikray: bad_request: ") {
		t.Errorf("a token with no name: exit %d, want 1 and bad_request", code)
	}
	// An empty list is its header.
	if code, out, errOut := runCLI(t, vars, "token", "rm", other); code != 0 || out != "revoked token "+otherID+"\n" || errOut != "" {
		t.Error("pasting the full token for revocation should report only the public id")
	}
	if got := rows(ok(t, vars, "token", "list")); len(got) != 1 {
		t.Errorf("the list of no tokens is %q, want the header alone", got)
	}
	if got := strings.TrimSpace(ok(t, vars, "token", "list", "--json")); got != "[]" {
		t.Errorf("token list --json of no tokens is %q, want []", got)
	}
}

// A pasted credential must not reach the request path or an error, even
// when it is malformed and the daemon cannot be reached.
func TestTokenRemoveRejectsMalformedInput(t *testing.T) {
	value := "tkr_00000001_private-fixture-value"
	code, out, errOut := runCLI(t, map[string]string{"TIKRAY_DATA": t.TempDir()}, "token", "rm", value)
	if code != 2 || out != "" || strings.Contains(errOut, value) {
		t.Error("malformed token argument was accepted or echoed")
	}
}

func TestTokenExpiryDoesNotEchoInput(t *testing.T) {
	value := "private-fixture-value"
	code, out, errOut := runCLI(t, nil, "token", "create", "script", "--expires", value)
	if code != 2 || out != "" || strings.Contains(errOut, value) {
		t.Error("an invalid token expiry must not be echoed in the usage error")
	}
}

func TestTokenCreateReportsLostOutput(t *testing.T) {
	d := startDaemon(t, newFake())
	var errBuf bytes.Buffer
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer full.Close()
	code := run(context.Background(), []string{"token", "create", "script"}, envOf(d.env(t)), full, &errBuf)
	if code != 1 || !strings.Contains(errBuf.String(), "could not write") || strings.Contains(errBuf.String(), "tkr_") {
		t.Error("failed token output should report a safe delivery failure")
	}
}

// --- usage

func TestAPICommandsUsage(t *testing.T) {
	vars := noDaemonEnv(t)
	for _, args := range [][]string{
		{"server"},
		{"server", "bogus"},
		{"server", "add"},
		{"server", "add", "a", "b"},
		{"server", "add", "vless://x", "--json", "f.json", "--name", "n"},
		{"server", "add", "--json", "f.json"},
		{"server", "add", "--bogus"},
		{"server", "list", "extra"},
		{"server", "list", "--bogus"},
		{"server", "rm"},
		{"server", "rm", "a", "b"},
		{"server", "enable"},
		{"server", "disable", "a", "b"},
		{"sub"},
		{"sub", "bogus"},
		{"sub", "add"},
		{"sub", "add", "https://sub.example.com/f", "--interval", "soon"},
		{"sub", "add", "feed"},
		{"sub", "add", "a", "b"},
		{"sub", "list", "extra"},
		{"sub", "rm"},
		{"sub", "refresh"},
		{"device"},
		{"device", "bogus"},
		{"device", "set"},
		{"device", "set", "192.168.88.10"},
		{"device", "set", "192.168.88.10", "turbo"},
		{"device", "set", "banana", "smart"},
		{"device", "set", "192.168.88.10", "smart", "extra"},
		{"device", "rm"},
		{"device", "rm", "banana"},
		{"device", "list", "extra"},
		{"policy"},
		{"policy", "bogus"},
		{"policy", "default"},
		{"policy", "default", "turbo"},
		{"policy", "default", "smart", "extra"},
		{"status", "extra"},
		{"status", "--bogus"},
		{"events", "extra"},
		{"events", "--after", "soon"},
		{"events", "--after", "-1"},
		{"serve", "extra"},
		{"serve", "--bogus"},
		{"setup-code", "extra"},
		{"setup-code", "--bogus"},
		{"admin"},
		{"admin", "bogus"},
		{"admin", "reset", "extra"},
		{"admin", "reset", "--bogus"},
		{"token"},
		{"token", "bogus"},
		{"token", "create"},
		{"token", "create", "a", "b"},
		{"token", "create", "ci", "--expires", "soon"},
		{"token", "create", "ci", "--expires", "0"},
		{"token", "create", "ci", "--expires", "-1h"},
		{"token", "list", "extra"},
		{"token", "list", "--bogus"},
		{"token", "rm"},
		{"token", "rm", "a", "b"},
	} {
		code, stdout, stderr := runCLI(t, vars, args...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "usage") {
			t.Errorf("tikray %q: exit %d, stdout %q, stderr %q; want 2 and usage on stderr only", args, code, stdout, stderr)
		}
	}
	if ents, _ := os.ReadDir(vars["TIKRAY_DATA"]); len(ents) != 0 {
		t.Errorf("a usage error created %v in the data root", dirNamesOf(ents))
	}

	for _, args := range [][]string{
		{"server", "help"}, {"server", "add", "-h"}, {"sub", "add", "--help"}, {"device", "set", "-h"},
		{"policy", "default", "-h"}, {"status", "-h"}, {"events", "-h"}, {"serve", "-h"},
		{"setup-code", "-h"}, {"admin", "help"}, {"admin", "reset", "-h"}, {"token", "help"}, {"token", "create", "-h"}, {"token", "list", "--help"}, {"token", "rm", "-h"},
	} {
		code, stdout, stderr := runCLI(t, vars, args...)
		if code != 0 || !strings.Contains(stdout+stderr, "usage") {
			t.Errorf("tikray %q: exit %d, stdout %q, stderr %q; want 0 and usage", args, code, stdout, stderr)
		}
	}
}

func TestUsageTextListsTheAPICommands(t *testing.T) {
	code, stdout, _ := runCLI(t, nil, "help")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{
		"serve", "server add", "server list", "server rm", "server enable", "server disable",
		"sub add", "sub list", "sub rm", "sub refresh",
		"device set", "device rm", "device list", "policy default", "status", "events",
		"setup-code", "admin reset", "token create", "token list", "token rm", "--expires",
		"TIKRAY_LISTEN", "TIKRAY_API", "TIKRAY_API_TOKEN", "TIKRAY_API_FINGERPRINT",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the usage text lacks %q:\n%s", want, stdout)
		}
	}
}

// --- what a row shows of an outbound

func TestOutboundEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name     string
		outbound string
		protocol string
		endpoint string
	}{
		{"vnext", `{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443}]}}`, "vless", "203.0.113.10:443"},
		{"servers with a text port", `{"protocol":"trojan","settings":{"servers":[{"address":"b.example.com","port":"8443"}]}}`, "trojan", "b.example.com:8443"},
		{"flat settings", `{"protocol":"vless","settings":{"address":"198.51.100.7","port":8443}}`, "vless", "198.51.100.7:8443"},
		{"IPv6", `{"protocol":"shadowsocks","settings":{"servers":[{"address":"2001:db8::1","port":8388}]}}`, "shadowsocks", "[2001:db8::1]:8388"},
		{"wireguard", `{"protocol":"wireguard","settings":{"peers":[{"endpoint":"198.51.100.9:51820"}]}}`, "wireguard", "198.51.100.9:51820"},
		{"protocol in any case", `{"protocol":"VLESS","settings":{"address":"h","port":1}}`, "vless", "h:1"},
		{"no port", `{"protocol":"socks","settings":{"servers":[{"address":"h"}]}}`, "socks", "h"},
		{"unknown shape", `{"protocol":"hysteria","settings":{"anything":1}}`, "hysteria", "-"},
		{"no settings", `{"protocol":"vless"}`, "vless", "-"},
		{"not an object", `[1]`, "-", "-"},
		{"not JSON", `nope`, "-", "-"},
		{"empty", ``, "-", "-"},
		{"control characters", "{\"protocol\":\"vl\\u001bess\",\"settings\":{\"address\":\"h\\nost\",\"port\":1}}", "vless", "host:1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			protocol, endpoint := outboundEndpoint(json.RawMessage(tc.outbound))
			if protocol != tc.protocol || endpoint != tc.endpoint {
				t.Errorf("got %q, %q; want %q, %q", protocol, endpoint, tc.protocol, tc.endpoint)
			}
		})
	}
}

func TestOneLine(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                 "plain",
		"two\nlines":            "two lines",
		"tab\there":             "tab here",
		"\x1b[31mred\x1b[0m":    "[31mred [0m",
		"a\r\n\r\nb":            "a b",
		"  padded  ":            "padded",
		"bidi \u202eoverride":   "bidi override",
		"line\u2028separator":   "line separator",
		"ünïcode is fine — yes": "ünïcode is fine — yes",
		"":                      "",
		"\n":                    "",
	} {
		if got := oneLine(in); got != want {
			t.Errorf("oneLine(%q) = %q, want %q", in, got, want)
		}
	}
}
