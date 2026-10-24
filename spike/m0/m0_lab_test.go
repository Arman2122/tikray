//go:build lab

package m0

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/test/lab/fixtures/labinet"
	"golang.org/x/crypto/ssh"
)

// result is one assumption's outcome, as written to results/<version>-<arch>.json.
type result struct {
	ID      string  `json:"id"`
	Pass    bool    `json:"pass"`
	Detail  string  `json:"detail"`
	Seconds float64 `json:"seconds"`
}

func httpDo(ctx context.Context, method, url, body string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b)), nil
}

func isIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// poll calls f every interval until it returns true or d passes, and
// returns how long it took.
func poll(ctx context.Context, d, interval time.Duration, f func() bool) (time.Duration, bool) {
	start := time.Now()
	for time.Since(start) < d && ctx.Err() == nil {
		if f() {
			return time.Since(start), true
		}
		time.Sleep(interval)
	}
	return time.Since(start), false
}

// TestAssumptions deploys the M0 data path once and checks each spec
// assumption in order. A failing subtest is a finding, recorded with what was
// observed; the results file is written either way.
func TestAssumptions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 360*time.Minute)
	defer cancel()
	l := Deploy(ctx, t)
	c := l.CHR

	var results []result
	t.Cleanup(func() {
		dir := filepath.Join(spikeDir(), "results")
		os.MkdirAll(dir, 0o755)
		b, _ := json.MarshalIndent(results, "", "  ")
		name := fmt.Sprintf("%s-%s-xray%s", l.Version, l.Arch, l.XrayVersion)
		if f := flag.Lookup("test.run"); f != nil && strings.Contains(f.Value.String(), "/") {
			name += "-partial" // a filtered run must not replace the full results
		}
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Error(err)
		}
		t.Logf("results: %s", path)
	})
	check := func(id string, f func(t *testing.T, note func(string, ...any))) {
		t.Run(id, func(t *testing.T) {
			var notes []string
			note := func(format string, args ...any) { notes = append(notes, fmt.Sprintf(format, args...)) }
			start := time.Now()
			defer func() {
				results = append(results, result{ID: id, Pass: !t.Failed(), Detail: strings.Join(notes, "; "), Seconds: time.Since(start).Round(100 * time.Millisecond).Seconds()})
			}()
			f(t, note)
		})
	}
	curl := func(args ...string) string {
		out, _ := l.ClientCurl(ctx, args...)
		return out
	}
	accessLog := func() string {
		_, body, _ := httpDo(ctx, http.MethodGet, runnerURL+"/v0/file?path=/data/run/access.log", "")
		return body
	}
	container := func(action, name string) {
		c.Run(ctx, fmt.Sprintf("/container/%s [find name=%s]", action, name))
	}
	waitRoutes := func(d time.Duration) bool {
		_, ok := poll(ctx, d, 3*time.Second, func() bool {
			s, err := l.RunnerStatus(ctx)
			return err == nil && s.RoutesOK
		})
		return ok
	}

	check("xray_version", func(t *testing.T, note func(string, ...any)) {
		s, err := l.RunnerStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		note("runner reports %q, deployed %s", s.XrayVersion, l.XrayVersion)
		if !strings.Contains(s.XrayVersion, "Xray "+l.XrayVersion+" ") {
			t.Errorf("runner runs %q, want xray %s", s.XrayVersion, l.XrayVersion)
		}
	})
	check("sysctl_in_container", func(t *testing.T, note func(string, ...any)) {
		s, err := l.RunnerStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		note("sysctl=%v", s.Sysctl)
		for k, v := range s.Sysctl {
			if v != "ok" {
				t.Errorf("%s: %s", k, v)
			}
		}
	})
	check("exec_from_mount", func(t *testing.T, note func(string, ...any)) {
		// M0 found that RouterOS-placed files have no execute bit; the design
		// now stages the core (spec §3.3). Record the finding, require xray up.
		s, _ := l.RunnerStatus(ctx)
		note("exec_from_mount=%q xray_pid=%d (staged copy used when not ok)", s.ExecFromMount, s.XrayPID)
		if s.XrayPID <= 0 {
			t.Errorf("xray not running (exec from mount: %s)", s.ExecFromMount)
		}
	})
	check("proxied_ip", func(t *testing.T, note func(string, ...any)) {
		got := curl("http://203.0.113.30/whoami")
		note("whoami=%q", got)
		if got != "203.0.113.10" {
			t.Errorf("whoami %q, want 203.0.113.10", got)
		}
	})
	check("domestic_ip_direct", func(t *testing.T, note func(string, ...any)) {
		got := curl("http://203.0.113.20/whoami")
		inXray := strings.Contains(accessLog(), "203.0.113.20")
		note("whoami=%q in_access_log=%v", got, inXray)
		if got != "198.51.100.2" || inXray {
			t.Errorf("whoami %q (want 198.51.100.2), in xray access log %v (want false)", got, inXray)
		}
	})
	check("sniffed_domain_direct", func(t *testing.T, note func(string, ...any)) {
		got := curl("-k", "--resolve", "domestic.test:443:203.0.113.30", "https://domestic.test/whoami")
		note("whoami=%q", got)
		if got != "198.51.100.2" {
			t.Errorf("whoami %q, want 198.51.100.2", got)
		}
	})
	check("sniffed_domain_proxied", func(t *testing.T, note func(string, ...any)) {
		got := curl("-k", "--resolve", "foreign.test:443:203.0.113.30", "https://foreign.test/whoami")
		note("whoami=%q", got)
		if got != "203.0.113.10" {
			t.Errorf("whoami %q, want 203.0.113.10", got)
		}
	})
	check("no_src_nat", func(t *testing.T, note func(string, ...any)) {
		log := accessLog()
		ok := strings.Contains(log, "from tcp:192.168.88.10:")
		note("access log has client source: %v", ok)
		if !ok {
			t.Errorf("xray access log lacks source 192.168.88.10:\n%s", log)
		}
	})
	dig := func(name string) string {
		b, _ := l.Net.Client(ctx, "dig", "+short", "+time=3", "+tries=2", "@192.168.88.1", name).Output()
		return strings.TrimSpace(string(b))
	}
	check("dns_proxied", func(t *testing.T, note func(string, ...any)) {
		got := dig("foreign.test")
		note("answer=%q", got)
		if got != "203.0.113.30" {
			t.Errorf("foreign.test = %q, want 203.0.113.30", got)
		}
	})
	check("dns_domestic_direct", func(t *testing.T, note func(string, ...any)) {
		got := dig("domestic.test")
		note("answer=%q", got)
		if got != "10.10.34.34" {
			t.Errorf("domestic.test = %q, want 10.10.34.34", got)
		}
	})
	check("udp_proxied", func(t *testing.T, note func(string, ...any)) {
		b, _ := l.Net.Client(ctx, "sh", "-c", "echo ping | nc -u -w2 203.0.113.30 9000").Output()
		got := strings.TrimSpace(string(b))
		note("reply=%q", got)
		if got != "203.0.113.10" {
			t.Errorf("udp echo reply %q, want 203.0.113.10", got)
		}
	})
	check("large_transfer", func(t *testing.T, note func(string, ...any)) {
		want := labinet.BlobSHA256()
		for _, tc := range []struct{ path, url string }{
			{"direct", "http://203.0.113.20/blob2m"},
			{"proxied", "http://203.0.113.30/blob2m"},
		} {
			start := time.Now()
			b, _ := l.Net.Client(ctx, "sh", "-c", "curl -s --noproxy '*' --max-time 300 "+tc.url+" | sha256sum").Output()
			got, _, _ := strings.Cut(string(b), " ")
			note("%s 2 MiB %.1fs sha_ok=%v", tc.path, time.Since(start).Seconds(), got == want)
			if got != want {
				t.Errorf("%s 2 MiB transfer: sha256 %s, want %s", tc.path, got, want)
			}
		}
	})
	check("no_fasttrack_marked", func(t *testing.T, note func(string, ...any)) {
		done := make(chan struct{})
		go func() {
			l.ClientCurl(ctx, "--max-time", "30", "-o", "/dev/null", "http://203.0.113.30/blob2m")
			close(done)
		}()
		time.Sleep(5 * time.Second)
		marked, err := c.Get(ctx, "[:len [/ip/firewall/connection/find where connection-mark=tikray-open]]")
		if err != nil {
			t.Fatal(err)
		}
		fast, err := c.Get(ctx, "[:len [/ip/firewall/connection/find where connection-mark=tikray-open and fasttrack]]")
		<-done
		note("marked=%s fasttracked=%s err=%v", marked, fast, err)
		if err != nil || marked == "0" || fast != "0" {
			t.Errorf("marked connections %s, fasttracked %s (%v): want >0 and 0", marked, fast, err)
		}
	})
	check("fallback_open", func(t *testing.T, note func(string, ...any)) {
		container("stop", "tikray-runner")
		took, ok := poll(ctx, 60*time.Second, 2*time.Second, func() bool { return curl("--max-time", "3", "http://203.0.113.30/whoami") == "198.51.100.2" })
		note("direct after %.1fs ok=%v", took.Seconds(), ok)
		if !ok {
			t.Error("traffic did not fall back to direct within 60 s")
		}
		// Fail-open must keep name resolution too, not just routes.
		_, dnsOK := poll(ctx, 30*time.Second, 2*time.Second, func() bool { return isIPv4(dig("foreign.test")) })
		ans := dig("foreign.test")
		note("dns with runner stopped: %q", ans)
		if !dnsOK {
			t.Errorf("DNS for a fail-open device with the runner stopped: %q, want an answer", ans)
		}
	})
	check("fallback_recovery", func(t *testing.T, note func(string, ...any)) {
		container("start", "tikray-runner")
		if !waitRoutes(5 * time.Minute) {
			t.Fatal("runner did not report routes_ok within 5 min")
		}
		took, ok := poll(ctx, 120*time.Second, 2*time.Second, func() bool { return curl("--max-time", "3", "http://203.0.113.30/whoami") == "203.0.113.10" })
		note("proxied again %.1fs after routes_ok, ok=%v", took.Seconds(), ok)
		if !ok {
			t.Error("traffic did not return to the proxy within 120 s")
		}
	})
	check("fallback_closed", func(t *testing.T, note func(string, ...any)) {
		if err := l.SetSourcePolicy(ctx, "tikray-src-smart-closed"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			container("start", "tikray-runner")
			waitRoutes(5 * time.Minute)
			l.SetSourcePolicy(ctx, "tikray-src-smart-open")
		}()
		_, viaProxy := poll(ctx, 60*time.Second, 2*time.Second, func() bool { return curl("--max-time", "3", "http://203.0.113.30/whoami") == "203.0.113.10" })
		note("closed policy proxied while runner up: %v", viaProxy)
		container("stop", "tikray-runner")
		leaked := ""
		poll(ctx, 60*time.Second, 2*time.Second, func() bool {
			if got := curl("--max-time", "3", "http://203.0.113.30/whoami"); got != "" {
				leaked = got
				return true
			}
			return false
		})
		note("answer with runner stopped: %q", leaked)
		if !viaProxy || leaked != "" {
			t.Errorf("closed policy: proxied while up %v (want true), answer while down %q (want none)", viaProxy, leaked)
		}
	})
	check("xray_dead_fallback", func(t *testing.T, note func(string, ...any)) {
		// xray dies while the runner container keeps running: fail-open must
		// still go direct, and come back to the proxy when xray returns.
		code, body, err := httpDo(ctx, http.MethodPost, runnerURL+"/v0/xray/pause?seconds=150", "")
		if err != nil || code != http.StatusNoContent {
			t.Fatalf("pause xray: %d %q %v", code, body, err)
		}
		took, ok := poll(ctx, 60*time.Second, 2*time.Second, func() bool { return curl("--max-time", "3", "http://203.0.113.30/whoami") == "198.51.100.2" })
		ans := dig("foreign.test")
		note("direct %.1fs after xray stopped ok=%v; dns %q", took.Seconds(), ok, ans)
		if !ok || !isIPv4(ans) {
			t.Errorf("with xray stopped and the runner up: direct=%v dns=%q, want direct and an answer", ok, ans)
		}
		back, ok := poll(ctx, 240*time.Second, 3*time.Second, func() bool { return curl("--max-time", "3", "http://203.0.113.30/whoami") == "203.0.113.10" })
		note("proxied again %.1fs later ok=%v", back.Seconds(), ok)
		if !ok {
			t.Error("traffic did not return to the proxy after xray came back")
		}
	})
	check("policy_switch_existing_conn", func(t *testing.T, note func(string, ...any)) {
		// Turning the kill switch on for a device must not strand its open
		// connections: a download in flight must complete intact.
		type res struct {
			sum string
			err error
		}
		ch := make(chan res, 1)
		go func() {
			b, err := l.Net.Client(ctx, "sh", "-c", "curl -s --noproxy '*' --max-time 120 http://203.0.113.30/blob2m | sha256sum").Output()
			sum, _, _ := strings.Cut(string(b), " ")
			ch <- res{sum, err}
		}()
		time.Sleep(5 * time.Second)
		if err := l.SetSourcePolicy(ctx, "tikray-src-smart-closed"); err != nil {
			t.Fatal(err)
		}
		r := <-ch
		l.SetSourcePolicy(ctx, "tikray-src-smart-open")
		ok := r.sum == labinet.BlobSHA256()
		note("download across the policy switch sha_ok=%v err=%v", ok, r.err)
		if !ok {
			t.Errorf("download that started before the kill switch was turned on: sha %q (%v), want intact", r.sum, r.err)
		}
	})
	check("shared_mount", func(t *testing.T, note func(string, ...any)) {
		code, body, err := httpDo(ctx, http.MethodPost, ctlURL+"/v0/write?path=/data/run/hello.txt", "hello-m0")
		_, read, _ := httpDo(ctx, http.MethodGet, runnerURL+"/v0/file?path=/data/run/hello.txt", "")
		note("ctl write run: %d %q %v; runner read %q", code, body, err, read)
		if read != "hello-m0" {
			t.Errorf("runner read %q from /data/run, want hello-m0", read)
		}
		code, body, _ = httpDo(ctx, http.MethodPost, ctlURL+"/v0/write?path=/data/cores/m0-probe", "cores-m0")
		_, read, _ = httpDo(ctx, http.MethodGet, runnerURL+"/v0/file?path=/data/cores/m0-probe", "")
		note("ctl write cores (rw): %d %q; runner read %q", code, body, read)
		if read != "cores-m0" {
			t.Errorf("runner read %q from /data/cores, want cores-m0", read)
		}
		code, body, _ = httpDo(ctx, http.MethodPost, runnerURL+"/v0/write?path=/data/cores/runner-probe", "x")
		note("runner write to its ro cores mount: %d %q", code, body)
		if code != http.StatusInternalServerError {
			t.Errorf("runner write to read-only mount returned %d, want 500", code)
		}
	})
	check("api_listen_restricted", func(t *testing.T, note func(string, ...any)) {
		type probe struct {
			code int
			body string
			err  error
		}
		ch := make(chan probe, 1)
		go func() {
			code, body, err := httpDo(ctx, http.MethodGet, ctlURL+"/v0/api-probe?user=tikray&pass=tikray-lab-api", "")
			ch <- probe{code, body, err}
		}()
		time.Sleep(5 * time.Second)
		c.Run(ctx, "/ip/firewall/address-list/add list=tikray-probe address=192.0.2.1 comment=lab:probe")
		p := <-ch
		note("api-probe: %d %q %v", p.code, p.body, p.err)
		if p.code != http.StatusOK || !strings.Contains(p.body, "192.0.2.1") {
			t.Errorf("api-probe %d %q (%v), want an event with 192.0.2.1", p.code, p.body, p.err)
		}
		_, err := ssh.Dial("tcp", "198.51.100.2:22", &ssh.ClientConfig{
			User: "tikray", Auth: []ssh.AuthMethod{ssh.Password("tikray-lab-api")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 30 * time.Second,
		})
		note("ssh as tikray: %v", err)
		if err == nil {
			t.Error("SSH login as the restricted tikray user succeeded")
		}
	})
	check("memory", func(t *testing.T, note func(string, ...any)) {
		s, _ := l.RunnerStatus(ctx)
		mem, _ := c.Get(ctx, "/container/get [find name=tikray-runner] memory-current")
		ctlMem, _ := c.Get(ctx, "/container/get [find name=tikray-ctl] memory-current")
		note("xray_rss_kb=%d runner_memory_current=%s ctl_memory_current=%s", s.XrayRSSKB, mem, ctlMem)
	})
	check("reboot_persistence", func(t *testing.T, note func(string, ...any)) {
		if err := c.PowerCycle(ctx); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if !waitRoutes(20 * time.Minute) {
			t.Fatal("runner did not report routes_ok within 20 min of boot")
		}
		got := curl("http://203.0.113.30/whoami")
		note("routes_ok %.0fs after SSH; whoami=%q", time.Since(start).Seconds(), got)
		if got != "203.0.113.10" {
			t.Errorf("whoami after power cycle %q, want 203.0.113.10", got)
		}
	})
}
