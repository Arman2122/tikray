//go:build lab

package adapters

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/tikray/test/lab"
)

// This test runs the release assembler's actual verification and fetch
// blocks without installing containers. A PC-side TLS server can pause in
// the middle of a download so another router session observes publication.
func TestOnlineArchiveStagingOnCHR(t *testing.T) {
	version := os.Getenv("TIKRAY_LAB_CHANNEL")
	if os.Getuid() != 0 || (version != "7.23.8" && version != "7.25") || os.Getenv("TIKRAY_LAB_ARCH") != "x86_64" {
		t.Fatal("requires a pinned disposable x86_64 CHR")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	pw, e := os.ReadFile(filepath.Join(lab.CacheDir(), "ready", version, "x86_64", "password"))
	if e != nil || len(pw) == 0 {
		t.Fatal("ready overlay unavailable")
	}
	art, e := lab.FetchCHR(ctx, "", lab.CacheDir(), version, lab.ArchX86)
	if e != nil {
		t.Fatal("CHR image unavailable")
	}
	if _, err := net.InterfaceByName("tklab-wan"); err == nil {
		t.Fatal("another lab is active")
	}
	n, e := lab.SetupNetwork(ctx)
	if e != nil {
		t.Fatal("lab network unavailable")
	}
	t.Cleanup(func() {
		if n.Teardown() != nil {
			t.Error("lab network cleanup failed")
		}
	})
	chr, e := lab.BootReadyCHR(ctx, n, lab.BootOptions{Version: version, Arch: lab.ArchX86, Artifacts: art, WorkDir: t.TempDir(), Password: string(pw)})
	if e != nil {
		t.Fatal("CHR boot failed")
	}
	t.Cleanup(func() {
		if chr.Shutdown() != nil {
			t.Error("CHR shutdown failed")
		}
	})
	run := func(source string) string {
		t.Helper()
		out, e := chr.RunPrivate(ctx, source)
		if e != nil {
			t.Fatal("fixture command failed")
		}
		return strings.TrimSpace(out)
	}
	dir := t.TempDir()
	push := func(path string, b []byte) {
		t.Helper()
		f := filepath.Join(dir, filepath.Base(path))
		if os.WriteFile(f, b, 0600) != nil || chr.Push(ctx, f, path) != nil {
			t.Fatal("public fixture upload failed")
		}
	}
	now := time.Now().UTC().Add(2 * time.Minute)
	run(fmt.Sprintf("/system/clock/set time-zone-name=UTC time-zone-autodetect=no date=%s time=%s", now.Format("2006-01-02"), now.Format("15:04:05")))
	const base = "disk1/tikray-online-fixture"
	const ctl = "tikray-amd64.tar"
	const runner = "tikray-runner-amd64.tar"
	const nonce = "0123456789abcdef0123456789abcdef"
	const foreignNonce = "22222222222222222222222222222222"
	const prefix = base + "/images/"
	const owner = "owner-public-canary"
	fileID := func(path string) string { return run(`:put [:tostr [/file/find where name="` + path + `"]]`) }
	for _, folder := range []string{base, base + "/images"} {
		run(`/file/add name="` + folder + `" type=directory`)
		limit := time.Now().Add(7 * time.Second)
		for fileID(folder) == "" {
			if time.Now().After(limit) {
				t.Fatal("fixture directory did not appear")
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	ownerPart := prefix + "incoming-" + foreignNonce + "-" + ctl
	const ownerPath = prefix + "owner.txt"
	push(ownerPath, []byte(owner))
	ownerID := fileID(ownerPath)
	checkOwner := func() {
		t.Helper()
		if ownerID == "" || fileID(ownerPath) != ownerID || run(`:put [/file/get [find where name="`+ownerPath+`"] contents]`) != owner {
			t.Fatal("an unrelated owner file changed")
		}
	}

	blobs := map[string][]byte{ctl: fixtureImage(t, "tikray", "amd64"), runner: fixtureImage(t, "tikray-runner", "amd64")}
	var requests, plainHits, foreignHits, followed atomic.Int32
	var mode atomic.Value
	mode.Store("good")
	reached, release := make(chan struct{}, 1), make(chan struct{})
	plain := onlineHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { plainHits.Add(1); w.Write(blobs[ctl]) }), nil)
	leaf, ca := archiveServerCertificate(t)
	foreign := onlineHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignHits.Add(1); w.Write(blobs[ctl]) }), &leaf)
	secure := onlineHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		name := strings.TrimPrefix(r.URL.Path, "/release/")
		if name == "redirect-control" {
			followed.Add(1)
			w.Write(blobs[ctl])
			return
		}
		b, ok := blobs[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if name == ctl {
			switch mode.Load() {
			case "bad":
				b = bytes.Clone(b)
				b[len(b)/2] ^= 0xff
			case "downgrade":
				http.Redirect(w, r, plain.URL+"/public", http.StatusFound)
				return
			case "foreign":
				http.Redirect(w, r, foreign.URL+"/public", http.StatusFound)
				return
			case "loop":
				http.Redirect(w, r, "/release/"+ctl, http.StatusTemporaryRedirect)
				return
			case "metadata", "redirect":
				http.Redirect(w, r, "/release/redirect-control", http.StatusFound)
				return
			case "query":
				http.Redirect(w, r, "/release/redirect-control?proof=onlinecanary32901", http.StatusFound)
				return
			case "query-default":
				http.Redirect(w, r, "/release/redirect-control?proof=onlinecanary71802", http.StatusFound)
				return
			case "held":
				w.Header().Set("Content-Length", fmt.Sprint(len(b)))
				w.Write(b[:1024])
				w.(http.Flusher).Flush()
				select {
				case reached <- struct{}{}:
				case <-ctx.Done():
					return
				}
				select {
				case <-release:
				case <-r.Context().Done():
					return
				case <-ctx.Done():
					return
				}
				w.Write(b[1024:])
				return
			}
		}
		w.Write(b)
	}), &leaf)
	p, _ := Installed(version, "x86_64", "CHR")
	var verified []VerifiedArchive
	for _, name := range []string{"tikray", "tikray-runner"} {
		a, err := describeArchive(p, name, blobs[name+"-amd64.tar"], secure.URL+"/release")
		if err != nil {
			t.Fatal(err)
		}
		verified = append(verified, a)
	}
	program := fmt.Sprintf(`{
    :global onlineNonce
    :local lease {"nonce"=$onlineNonce}
    :local requireInstall do={
        :if (([:len ($1->"nonce")] != 32) or ([:len [/file/find where name="online-expired.txt"]] > 0)) do={ :error "online fixture lease" }
        :return true
    }
    :local base "%s"
    :local offline false
    :local archivesVerified false
    %s
    %s
    :if (!$archivesVerified) do={:error "online fixture"}
}`, base, archiveVerifier(verified), archiveChecks(verified))
	push("online-test.rsc", []byte(program))
	attempt := func(lease string) bool {
		out, err := chr.RunPrivate(ctx, `{ :global onlineNonce "`+lease+`"; :do { /import online-test.rsc; :put "online-ok" } on-error={ :put "online-refused" } }`)
		return err == nil && strings.HasSuffix(strings.TrimSpace(out), "online-ok")
	}
	noPublication := func() {
		t.Helper()
		if fileID(prefix+ctl) != "" || fileID(prefix+"incoming-"+nonce+"-"+ctl) != "" {
			t.Fatal("unsuccessful fetch left a final archive or its staging file")
		}
		checkOwner()
	}
	if attempt(nonce) || requests.Load() != 0 {
		t.Fatal("untrusted TLS origin accepted")
	}
	noPublication()
	push("online-test-ca.crt", ca)
	run(`/certificate/import file-name=online-test-ca.crt passphrase="" name=online-test-ca trusted=yes trust-store=fetch`)
	mode.Store("metadata")
	push("online-redirect.rsc", []byte(fmt.Sprintf(`{
    :local result "no-redirect-data"
    :onerror ignored,attr in={
        :local reply [/tool/fetch url="%s/release/%s" check-certificate=yes http-max-redirect-count=0 output=none as-value]
    } do={
        :if ([:tonum ($attr->"code")] = 302) do={
            :set result "status-only"
            :foreach k,v in=($attr->"http-headers") do={
                :if (([:convert [:tostr $k] transform=lc] = "location") and ($v = "/release/redirect-control")) do={ :set result "mapped-location" }
                :if (([:convert [:pick [:tostr $v] 0 10] transform=lc] = "location: ") and ([:pick [:tostr $v] 10 [:len [:tostr $v]]] = "/release/redirect-control")) do={ :set result "text-location" }
            }
        }
    }
    :put $result
    /file/add name="online-meta.txt" type=file contents=$result
}`, secure.URL, ctl)))
	shape, probeErr := chr.Run(ctx, "/import online-redirect.rsc")
	shape = strings.TrimSpace(shape)
	if fileID("online-meta.txt") != "" {
		shape = run(`:put [/file/get [find where name="online-meta.txt"] contents]`)
	}
	if probeErr != nil {
		shape = "unsupported"
		if strings.Contains(probeErr.Error(), "syntax error") {
			shape = "unsupported-syntax"
		}
	}
	switch shape {
	case "mapped-location", "text-location", "status-only", "no-redirect-data", "unsupported", "unsupported-syntax":
		t.Log("native redirect attribute", shape)
	default:
		t.Log("native redirect attribute unavailable")
	}
	fileWrite, e := chr.RunPrivate(ctx, `{ :local found false; :foreach entry in=[/console/inspect request=completion input="/file/writ" as-value] do={ :if (($entry->"completion") = "write") do={ :set found true } }; :put $found }`)
	t.Log("native file write command witnessed", e == nil && strings.TrimSpace(fileWrite) == "true")
	collisionBaseline := requests.Load()
	push(ownerPart, []byte(owner))
	partID := fileID(ownerPart)
	if attempt(foreignNonce) || requests.Load() != collisionBaseline {
		t.Fatal("staging collision reached the origin")
	}
	checkOwner()
	if partID == "" || fileID(ownerPart) != partID || run(`:put [/file/get [find where name="`+ownerPart+`"] contents]`) != owner {
		t.Fatal("pre-existing same-nonce file changed")
	}
	mode.Store("downgrade")
	before := requests.Load()
	if attempt(nonce) || requests.Load() <= before || plainHits.Load() != 0 {
		t.Fatal("secure redirect was allowed to send traffic in plaintext")
	}
	noPublication()
	mode.Store("foreign")
	if attempt(nonce) || foreignHits.Load() != 0 {
		t.Fatal("release redirect contacted an unrelated TLS origin")
	}
	noPublication()
	mode.Store("loop")
	before = requests.Load()
	if attempt(nonce) || requests.Load()-before != 1 {
		t.Fatal("the importer followed a redirect loop")
	}
	noPublication()
	before = requests.Load()
	mode.Store("bad")
	if attempt(nonce) || requests.Load() <= before {
		t.Fatal("corrupt bytes did not reach and fail verification")
	}
	noPublication()
	push(prefix+ctl, []byte(owner))
	id := fileID(prefix + ctl)
	before = requests.Load()
	if attempt(nonce) || fileID(prefix+ctl) != id || run(`:put [/file/get [find name="`+prefix+ctl+`"] contents]`) != owner || requests.Load() != before {
		t.Fatal("existing invalid final archive was replaced")
	}
	run(`/file/set [find name="` + prefix + ctl + `"] name="` + prefix + `owner-original"`)
	mode.Store("held")
	done := make(chan bool, 1)
	go func() { done <- attempt(nonce) }()
	select {
	case <-reached:
	case <-done:
		t.Fatal("verified-origin positive control refused before download")
	case <-time.After(15 * time.Second):
		t.Fatal("TLS server saw no transfer")
	}
	stagedID := fileID(prefix + "incoming-" + nonce + "-" + ctl)
	visible := fileID(prefix + ctl)
	push("online-expired.txt", []byte("expired"))
	close(release)
	if stagedID == "" || visible != "" {
		t.Fatal("final archive was visible during transfer")
	}
	if <-done {
		t.Fatal("a transfer published after its lease expired")
	}
	noPublication()
	run(`/file/remove [find where name="online-expired.txt"]`)
	mode.Store("query-default")
	before = requests.Load()
	if attempt(nonce) || requests.Load() != before+1 || followed.Load() != 0 {
		t.Fatal("query-bearing redirect was contacted")
	}
	defaultLogged := run(`:put [:len [/log/find where message~"onlinecanary71802"]]`) != "0"
	run(`/system/logging/add topics=fetch,debug action=memory prefix="online-test"`)
	mode.Store("query")
	before = requests.Load()
	if attempt(nonce) || requests.Load() != before+1 || followed.Load() != 0 {
		t.Fatal("query-bearing redirect was used for a transfer")
	}
	noPublication()
	mode.Store("redirect")
	if attempt(nonce) || followed.Load() != 0 {
		t.Fatal("same-origin redirect was followed")
	}
	debugLogged := run(`:put [:len [/log/find where message~"onlinecanary32901"]]`) != "0"
	t.Logf("native logging retained a rejected Location canary: ordinary=%t fetch/debug=%t", defaultLogged, debugLogged)
	mode.Store("good")
	if !attempt(nonce) {
		t.Fatal("valid staged images failed verification or rename")
	}
	for _, name := range []string{ctl, runner} {
		if fileID(prefix+name) == "" || fileID(prefix+"incoming-"+nonce+"-"+name) != "" {
			t.Fatal("verified pair was not published")
		}
		for off := 0; off < len(blobs[name]); off += 8192 {
			end := min(off+8192, len(blobs[name]))
			raw := run(fmt.Sprintf(`:put [:convert ([/file/read file="%s" offset=%d chunk-size=%d as-value]->"data") from=raw to=base64]`, prefix+name, off, end-off))
			b, err := base64.StdEncoding.DecodeString(raw)
			if err != nil || !bytes.Equal(b, blobs[name][off:end]) {
				t.Fatal("published bytes differ from the intended archive")
			}
		}
	}
	ctlID, runID := fileID(prefix+ctl), fileID(prefix+runner)
	before = requests.Load()
	if !attempt(nonce) || requests.Load() != before || fileID(prefix+ctl) != ctlID || fileID(prefix+runner) != runID {
		t.Fatal("rerun fetched or replaced a verified file")
	}
	checkOwner()
}

func onlineHTTPServer(t *testing.T, h http.Handler, leaf *tls.Certificate) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(h)
	s.Listener.Close()
	ln, e := net.Listen("tcp", "198.51.100.1:0")
	if e != nil {
		t.Fatal("fixture listener unavailable")
	}
	s.Listener = ln
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	if leaf != nil {
		s.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12}
		s.StartTLS()
	} else {
		s.Start()
	}
	t.Cleanup(s.Close)
	return s
}

func archiveServerCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	keys := make([]*ecdsa.PrivateKey, 2)
	for i := range keys {
		var err error
		keys[i], err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal("fixture key unavailable")
		}
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture release authority"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(72 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &keys[0].PublicKey, keys[0])
	if err != nil {
		t.Fatal("fixture authority unavailable")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fixture release endpoint"}, IPAddresses: []net.IP{net.ParseIP("198.51.100.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter}
	signed, err := x509.CreateCertificate(rand.Reader, leaf, ca, &keys[1].PublicKey, keys[0])
	if err != nil {
		t.Fatal("fixture TLS leaf unavailable")
	}
	return tls.Certificate{Certificate: [][]byte{signed, der}, PrivateKey: keys[1]}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
