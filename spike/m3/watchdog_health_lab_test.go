//go:build lab

package m3

import (
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/api"
	routerosfiles "github.com/Arman2122/tikray/routeros"
)

// Run the release probe itself against controlled HTTPS responses. The ARP
// and port-isolation attack have their own production-network CHR witness.
func TestWatchdogHealthResponse(t *testing.T) {
	r := newRig(t)
	dir := t.TempDir()
	host := "198.51.100.254"
	if _, _, e := api.LoadOrCreateCert(dir, []net.IP{net.ParseIP(host)}); e != nil {
		t.Fatal("TLS fixture")
	}
	const id = "1234567890abcdef1234567890abcdef"
	valid := `{"ok":true,"installation_id":"` + id + `"}`
	body := filepath.Join(dir, "response")
	set := func(s string) {
		t.Helper()
		if os.WriteFile(body, []byte(s), 0600) != nil {
			t.Fatal("fixture response")
		}
	}
	set(valid)
	proc := r.net.Inet(r.ctx, "python3", "-c", `import http.server,ssl,sys,pathlib,time
d=pathlib.Path(sys.argv[2])
class Health(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def do_GET(self):
  p=(d/"response").read_bytes()
  if self.path=="/healthz" and p==b"redirect":
   self.send_response(302);self.send_header("Location","/other");self.send_header("Content-Length","0");self.end_headers();return
  if self.path=="/other":p=sys.argv[3].encode()
  if p==b"trickle":
   tail=sys.argv[3].encode()
   self.send_response(200);self.send_header("Content-Length",str(16+len(tail)));self.end_headers()
   try:
    for i in range(16):
     self.wfile.write(b" ");self.wfile.flush();(d/"trickle-count").write_text(str(i+1));time.sleep(1)
    self.wfile.write(tail)
   except OSError:pass
   return
  self.send_response(200);self.send_header("Content-Length",str(len(p)));self.end_headers();self.wfile.write(p)
s=http.server.HTTPServer((sys.argv[1],443),Health)
c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.load_cert_chain(str(d/"tls.crt"),str(d/"tls.key"))
s.socket=c.wrap_socket(s.socket,server_side=True);s.serve_forever()`, host, dir, valid)
	diagPath := filepath.Join(dir, "server-diagnostic")
	f, e := os.OpenFile(diagPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal("diagnostic fixture")
	}
	defer f.Close()
	proc.Stderr = f
	if e := proc.Start(); e != nil {
		t.Fatal("HTTPS fixture start")
	}
	t.Cleanup(func() { proc.Process.Kill(); proc.Wait() })
	fragment, e := routerosfiles.Sources.ReadFile("watchdog-health.rsc")
	if e != nil {
		t.Fatal(e)
	}
	src := `{ :local ctlIP 198.51.100.254; :local gateway 198.51.100.2; :local healthy false; :local savedState {"installation_id"="` + id + `"}
` + string(fragment) + `
 :if ($healthy) do={ /system/script/set [find name="m3-health-result"] comment=verified } else={ /system/script/set [find name="m3-health-result"] comment=miss } }`
	if _, e = r.admin.RunContext(r.ctx, "/system/script/add", "=name=m3-health-result", "=source=", "=policy=read"); e != nil {
		t.Fatal("result fixture")
	}
	add, e := r.admin.RunContext(r.ctx, "/system/script/add", "=name=m3-health-probe", "=source="+src, "=policy=read,write,test")
	if e != nil || add.Done == nil {
		t.Fatal("probe fixture")
	}
	observe := func() string {
		t.Helper()
		if _, err := r.chr.RunPrivate(r.ctx, "/system/script/run m3-health-probe"); err != nil {
			out, _ := r.chr.RunPrivate(r.ctx, `:onerror reason in={ /system/script/run m3-health-probe } do={ :put ("m3-reason=" . [:convert $reason to=base64]) }`)
			_, raw, _ := strings.Cut(out, "m3-reason=")
			msg, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
			t.Fatal("health probe refused", regexp.MustCompile(`line [0-9]+ column [0-9]+`).FindString(err.Error()+string(msg)))
		}
		row, err := r.admin.RunContext(r.ctx, "/system/script/print", "?name=m3-health-result", "=.proplist=comment")
		if err != nil || len(row.Re) != 1 {
			t.Fatal("health result unavailable")
		}
		return row.Re[0].Map["comment"]
	}
	for deadline := time.Now().Add(8 * time.Second); observe() != "verified"; {
		if time.Now().After(deadline) {
			pos, e := r.net.Inet(r.ctx, "curl", "--noproxy", "*", "--silent", "--show-error", "--insecure", "--max-time", "3", "https://"+host+"/healthz").Output()
			if e != nil || string(pos) != valid {
				b, _ := os.ReadFile(diagPath)
				for _, s := range []string{"Address already in use", "Cannot assign requested address", "No such file or directory", "Permission denied", "SyntaxError", "KeyError", "AttributeError", "SSLError", "IndexError", "TypeError"} {
					if strings.Contains(string(b), s) {
						t.Fatal("independent fixture", s)
					}
				}
				t.Fatalf("independent TLS responder control failed (error=%t, body length=%d)", e != nil, len(pos))
			}
			t.Fatal("genuine response did not reach the native health check")
		}
		time.Sleep(150 * time.Millisecond)
	}
	for _, tc := range []struct{ name, reply string }{
		{"wrong_id", strings.Replace(valid, id, strings.Repeat("0", 32), 1)},
		{"missing_id", `{"ok":true}`}, {"unhealthy", strings.Replace(valid, "true", "false", 1)},
		{"text_boolean", strings.Replace(valid, "true", `"true"`, 1)}, {"malformed", "{"}, {"oversize", valid + strings.Repeat(" ", 500)}, {"redirect", "redirect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set(tc.reply)
			if observe() != "miss" {
				t.Fatal("response counted as healthy")
			}
		})
	}
	t.Run("trickle_response", func(st *testing.T) {
		// One byte per second keeps the native idle timer from expiring.
		// Even the eventual valid body is too late for this watchdog tick.
		set("trickle")
		start := time.Now()
		got := observe()
		elapsed := time.Since(start)
		bytes, err := os.ReadFile(filepath.Join(dir, "trickle-count"))
		count, parseErr := strconv.Atoi(string(bytes))
		if err != nil || parseErr != nil || count < 2 {
			st.Fatal("fixture did not sustain a slow HTTPS response")
		}
		if got != "miss" || elapsed > 12*time.Second {
			st.Fatal("slow HTTPS service held the watchdog beyond its probe deadline")
		}
		if _, err := r.admin.RunContext(r.ctx, "/system/resource/print", "=.proplist=version"); err != nil {
			st.Fatal("original owner API session failed after health probe timeout")
		}
	})
	set(valid)
	if observe() != "verified" {
		t.Fatal("genuine service did not recover")
	}
	// Native fetch can return different output in an API command context.
	// Verify the actual scheduler context with its production policies.
	timer, e := r.admin.RunContext(r.ctx, "/system/scheduler/add", "=name=m3-health-probe", "=on-event=m3-health-probe", "=policy=read,write,test", "=interval=2s", "=start-time=startup", "=disabled=yes")
	if e != nil || timer.Done == nil {
		t.Fatal("scheduler fixture")
	}
	for _, sample := range []struct{ body, want string }{{valid, "verified"}, {strings.Replace(valid, id, strings.Repeat("f", 32), 1), "miss"}} {
		set(sample.body)
		if _, e := r.chr.RunPrivate(r.ctx, `/system/script/set [find where name="m3-health-result"] comment=pending; /system/scheduler/enable [find where name="m3-health-probe"]`); e != nil {
			t.Fatal("enable scheduled probe")
		}
		got := ""
		for end := time.Now().Add(9 * time.Second); time.Now().Before(end); {
			row, err := r.admin.RunContext(r.ctx, "/system/script/print", "?name=m3-health-result", "=.proplist=comment")
			if err == nil && len(row.Re) == 1 {
				got = row.Re[0].Map["comment"]
				if got != "pending" {
					break
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		if _, e := r.admin.RunContext(r.ctx, "/system/scheduler/disable", "=.id="+timer.Done.Map["ret"]); e != nil {
			t.Fatal("stop scheduled fixture")
		}
		if got != sample.want {
			t.Fatalf("scheduled probe disagreed with HTTPS witness, wanted %s (tick completed=%t)", sample.want, got != "pending")
		}
	}
}
