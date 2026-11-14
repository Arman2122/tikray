//go:build lab

package m3

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/api"
)

// Use the same non-CA leaf as the control plane. An alternate valid leaf
// for the same address distinguishes actual pinning from trusting any peer.
func TestWatchdogFetchLeafCapability(t *testing.T) {
	r := newRig(t)
	setFixtureClock(t, r)
	dir := t.TempDir()
	host := "198.51.100.254"
	serve := func(port int) (string, string) {
		d := filepath.Join(dir, fmt.Sprint(port))
		if os.Mkdir(d, 0700) != nil {
			t.Fatal("TLS fixture directory")
		}
		_, fingerprint, err := api.LoadOrCreateCert(d, []net.IP{net.ParseIP(host)})
		if err != nil {
			t.Fatal("control certificate")
		}
		p := r.net.Inet(r.ctx, "python3", "-c", `import http.server,ssl,sys
s=http.server.HTTPServer((sys.argv[1],int(sys.argv[2])),http.server.SimpleHTTPRequestHandler)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[3]+"/tls.crt",sys.argv[3]+"/tls.key")
s.socket=ctx.wrap_socket(s.socket,server_side=True)
s.serve_forever()`, host, fmt.Sprint(port), d)
		if err := p.Start(); err != nil {
			t.Fatal("TLS service")
		}
		t.Cleanup(func() { p.Process.Kill(); p.Wait() })
		return filepath.Join(d, "tls.crt"), fingerprint
	}
	cert, pin := serve(18441)
	otherCert, _ := serve(18442)
	for i, name := range []string{cert, otherCert} {
		if err := r.chr.Push(r.ctx, name, fmt.Sprintf("wd-public%d.crt", i)); err != nil {
			t.Fatal("leaf transfer")
		}
	}
	check := func(stmt string) bool {
		out, e := r.chr.RunPrivate(r.ctx, `{ :do { `+stmt+`; :put "PASS" } on-error={ :put "FAIL" } }`)
		return e == nil && strings.HasSuffix(strings.TrimSpace(out), "PASS")
	}
	get := func(port int, opts string) bool {
		args := []string{"/tool/fetch", fmt.Sprintf("=url=https://%s:%d/", host, port), "=output=none", "=http-max-redirect-count=0"}
		for _, word := range strings.Fields(opts) {
			args = append(args, "="+word)
		}
		_, e := r.admin.RunArgsContext(r.ctx, args)
		if e == nil {
			return true
		}
		for _, reason := range []string{"private key", "not valid", "trusted CA", "handshake", "name verification", "certificate", "status 404", "input does not match", "expected end", "policy", "refused", "timeout", "failed"} {
			if strings.Contains(strings.ToLower(e.Error()), strings.ToLower(reason)) {
				t.Log("fetch failure category", reason)
				break
			}
		}
		return false
	}
	time.Sleep(200 * time.Millisecond)
	if !get(18441, "check-certificate=no") || !get(18442, "check-certificate=no") {
		t.Fatal("positive TLS reachability controls failed")
	}
	if get(18441, "check-certificate=yes") {
		t.Fatal("untrusted peer accepted")
	}
	for i := 0; i < 2; i++ {
		if !check(fmt.Sprintf(`/certificate/import file-name="wd-public%d.crt" name="wd-%d" passphrase="" trusted=yes trust-store=fetch`, i, i)) {
			t.Fatal("public leaf import")
		}
	}
	if !check(`:if ([/certificate/get [find name="wd-0"] fingerprint] != "` + strings.ToLower(strings.ReplaceAll(pin, ":", "")) + `") do={ :error "different public cert" }`) {
		t.Fatal("wrong imported fingerprint")
	}
	ordinary := get(18441, "check-certificate=yes")
	named := get(18441, "check-certificate=yes certificate=wd-0")
	alternate := get(18442, "check-certificate=yes certificate=wd-1")
	if named != alternate {
		t.Fatal("equivalent leaf controls disagree")
	}
	if named && get(18442, "check-certificate=yes certificate=wd-0") {
		t.Fatal("a named leaf did not authenticate the peer")
	}
	t.Logf("control leaf accepted with scoped trust=%t, named public certificate=%t", ordinary, named)
}

func TestWatchdogFetchCertificateRole(t *testing.T) {
	r := newRig(t)
	setFixtureClock(t, r)
	host := "198.51.100.254"
	var keys []string
	for i := 0; i < 2; i++ {
		dir := t.TempDir()
		run := func(args ...string) {
			t.Helper()
			cmd := exec.CommandContext(r.ctx, "openssl", args...)
			cmd.Dir = dir
			if cmd.Run() != nil {
				t.Fatal("fixture certificate generation")
			}
		}
		run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365", "-subj", fmt.Sprintf("/CN=m3-watch-%d", i), "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", "ca.key", "-out", "ca.crt")
		run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=tikray", "-keyout", "tls.key", "-out", "leaf.csr")
		if os.WriteFile(filepath.Join(dir, "leaf.cfg"), []byte("subjectAltName=IP:"+host+"\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"), 0600) != nil {
			t.Fatal("fixture config")
		}
		run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-days", "360", "-extfile", "leaf.cfg", "-out", "tls.crt")
		keys = append(keys, filepath.Join(dir, "ca.key"))
		c := r.net.Inet(r.ctx, "python3", "-c", `import http.server,ssl,sys
s=http.server.HTTPServer((sys.argv[1],int(sys.argv[2])),http.server.SimpleHTTPRequestHandler)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(sys.argv[3]+"/tls.crt",sys.argv[3]+"/tls.key")
s.socket=ctx.wrap_socket(s.socket,server_side=True);s.serve_forever()`, host, fmt.Sprint(18441+i), dir)
		if c.Start() != nil {
			t.Fatal("start TLS fixture")
		}
		t.Cleanup(func() { c.Process.Kill(); c.Wait() })
		name := fmt.Sprintf("wd-ca-%d", i)
		if r.chr.Push(r.ctx, filepath.Join(dir, "ca.crt"), name+".crt") != nil {
			t.Fatal("transfer public CA")
		}
		if _, e := r.admin.RunContext(r.ctx, "/certificate/import", "=file-name="+name+".crt", "=name="+name, "=passphrase=", "=trust-store=fetch", "=trusted=yes"); e != nil {
			t.Fatal("import disposable CA")
		}
	}
	time.Sleep(400 * time.Millisecond)
	get := func(i int, cert string) bool {
		args := []string{"/tool/fetch", "=url=https://" + host + ":" + fmt.Sprint(18441+i) + "/", "=output=none", "=check-certificate=yes", "=http-max-redirect-count=0"}
		if cert != "" {
			args = append(args, "=certificate="+cert)
		}
		_, e := r.admin.RunArgsContext(r.ctx, args)
		if e != nil {
			for _, reason := range []string{"private", "trusted CA", "not valid", "certificate", "key", "parameter", "match", "timeout", "refused", "execution", "failure"} {
				if strings.Contains(strings.ToLower(e.Error()), strings.ToLower(reason)) {
					t.Log("verified-fetch failure category", reason)
					break
				}
			}
		}
		return e == nil
	}
	if !get(0, "") || !get(1, "") {
		t.Fatal("ordinary CA verified control failed")
	}
	namedPublic := get(0, "wd-ca-0")
	// These keys exist only in the disposable fixture. Never import an
	// owner's signing key to check the health of a public server.
	for i, key := range keys {
		name := fmt.Sprintf("test-only-%d.key", i)
		if r.chr.Push(r.ctx, key, name) != nil {
			t.Fatal("stage disposable test identity")
		}
		if _, e := r.admin.RunContext(r.ctx, "/certificate/import", "=file-name="+name, "=passphrase="); e != nil {
			t.Fatal("import disposable test identity")
		}
	}
	if !get(0, "wd-ca-0") || !get(1, "wd-ca-1") {
		t.Fatal("client identity positive control failed")
	}
	substitute := get(1, "wd-ca-0")
	t.Logf("named public-only CA accepted=%t, different trusted server accepted with named client key=%t", namedPublic, substitute)
}

func setFixtureClock(t *testing.T, r *rig) {
	t.Helper()
	// The cached ready overlay can start earlier than certificates issued by
	// this test. A failed validity check is not a pinning experiment.
	now := time.Now().UTC().Add(3 * time.Minute)
	if _, e := r.admin.RunContext(r.ctx, "/system/clock/set", "=time-zone-autodetect=no", "=time-zone-name=UTC", "=date="+now.Format("2006-01-02"), "=time="+now.Format("15:04:05")); e != nil {
		t.Fatal("could not synchronize disposable router clock")
	}
}
