//go:build lab

// Package m3 probes RouterOS itself on disposable CHRs. It is not linked
// into either container.
package m3

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/test/lab"
	ros "github.com/go-routeros/routeros/v3"
)

type rig struct {
	ctx        context.Context
	version    string
	workDir    string
	chr        *lab.CHR
	net        *lab.Network
	api, admin *ros.Client
}

func (r *rig) mark(t *testing.T, key, verdict, reason string) {
	t.Helper()
	t.Logf("CAP %s %s %s %s", r.version, key, verdict, reason)
	if verdict != "PASS" {
		t.Fail()
	}
}

// The authoritative password comes from the ready cache; never rebuild the
// cache with a different password, or send either account's secret to a log.
func newRig(t *testing.T) *rig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 36*time.Minute)
	t.Cleanup(cancel)
	v := os.Getenv("TIKRAY_LAB_CHANNEL")
	if (v != "7.23.8" && v != "7.25") || os.Getenv("TIKRAY_LAB_ARCH") != "x86_64" || os.Getuid() != 0 {
		t.Fatal("requires root and a pinned x86_64 CHR target")
	}
	pw, err := os.ReadFile(filepath.Join(lab.CacheDir(), "ready", v, "x86_64", "password"))
	if err != nil || len(pw) == 0 {
		t.Fatal("missing private ready-image credential")
	}
	art, err := lab.FetchCHR(ctx, "", lab.CacheDir(), v, lab.ArchX86)
	if err != nil {
		t.Fatal("could not prepare pinned CHR artifact")
	}
	// SetupNetwork clears stale lab devices. Refuse a live shared lab instead.
	if _, err := net.InterfaceByName("tklab-wan"); err == nil {
		t.Fatal("the shared CHR lab is already in use")
	}
	n, err := lab.SetupNetwork(ctx)
	if err != nil {
		t.Fatal("could not prepare isolated lab network")
	}
	t.Cleanup(func() {
		if n.Teardown() != nil {
			t.Error("lab network teardown failed")
		}
	})
	workDir := t.TempDir()
	c, err := lab.BootReadyCHR(ctx, n, lab.BootOptions{Version: v, Arch: lab.ArchX86, Artifacts: art, WorkDir: workDir, Password: string(pw)})
	if err != nil {
		t.Fatal("could not boot pinned ready CHR")
	}
	t.Cleanup(func() {
		if c.Shutdown() != nil {
			t.Error("CHR shutdown failed")
		}
	})
	r := &rig{ctx: ctx, version: v, workDir: workDir, chr: c, net: n}
	read := func(label, cmd string) string {
		t.Helper()
		sub, done := context.WithTimeout(ctx, 60*time.Second)
		defer done()
		out, err := c.RunPrivate(sub, cmd)
		if err != nil {
			t.Fatalf("fixture: %s failed", label)
		}
		return strings.TrimSpace(out)
	}
	version := read("running version", ":put [/system/resource/get version]")
	if !(version == v || strings.HasPrefix(version, v+" ")) || read("architecture", ":put [/system/resource/get architecture-name]") != "x86_64" {
		t.Fatal("unexpected running version or architecture")
	}
	// A .2 endpoint on the isolated NIC stands in for the control container;
	// the restricted account cannot log in from the owner SSH address.
	for _, args := range [][]string{{"addr", "add", "172.31.255.2/32", "dev", "tklab-lan"}, {"route", "add", "172.31.255.1/32", "dev", "tklab-lan", "src", "172.31.255.2"}} {
		if exec.CommandContext(ctx, "ip", args...).Run() != nil {
			t.Fatal("could not attach isolated control IP")
		}
	}
	read("control subnet", "/ip/address/add address=172.31.255.1/29 interface=ether2 comment=m3-spike")
	read("API certificate", "/certificate/add name=m3-cap-api common-name=m3-cap-api subject-alt-name=IP:172.31.255.1 key-size=prime256v1 key-usage=key-cert-sign,digital-signature,tls-server")
	read("certificate signing", "/certificate/sign m3-cap-api")
	read("public certificate export", "/certificate/export-certificate m3-cap-api file-name=m3-cap-public type=pem")
	certPEM := read("public certificate", ":put [/file/get m3-cap-public.crt contents]")
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("invalid public certificate export")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("invalid API certificate")
	}
	read("API service", "/ip/service/set api-ssl certificate=m3-cap-api disabled=no address=172.31.255.2/32")
	read("group", "/user/group/add name=m3-cap-group policy=read,write,api")
	rights := strings.FieldsFunc(read("group policies", ":put [:tostr [/user/group/get [find name=m3-cap-group] policy]]"), func(c rune) bool { return c == ';' || c == ',' || c == ' ' })
	// RouterOS also lists denied capabilities as !policy, !sensitive, etc.
	rights = slices.DeleteFunc(rights, func(right string) bool { return strings.HasPrefix(right, "!") })
	slices.Sort(rights)
	if !slices.Equal(rights, []string{"api", "read", "write"}) {
		t.Fatal("restricted policy set differs")
	}
	// RouterOS expands the local variable on the router. SSH sends only a
	// static command; the random result is consumed privately, never printed.
	password := read("restricted user", `{ :local p [:rndstr length=40 from="abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"]; /user/add name=m3-cap-user group=m3-cap-group address=172.31.255.2/32 password=$p; :put $p }`)
	if len(password) != 40 {
		t.Fatal("invalid ephemeral account setup")
	}
	r.api = dialPinned(t, r, "m3-cap-user", password, cert)
	r.admin = dialPinned(t, r, "admin", string(pw), cert)
	r.auditCanary(t, password)
	t.Logf("CHR %s x86_64; native TLS pinned; source restricted to control IP; verified group read,write,api", v)
	return r
}

func (r *rig) auditCanary(t *testing.T, secret string) {
	t.Cleanup(func() { r.audit(t, secret, r.workDir) })
}

// The password is unique to this overlay. Read diagnostics in private and
// report only whether it was exposed, never the matching value or line.
func (r *rig) audit(t *testing.T, password, dir string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(r.ctx, 20*time.Second)
	defer cancel()
	for _, menu := range []struct{ path, fields string }{
		{"/log/print", "message"}, {"/system/history/print", "action,by,redo,undo"},
	} {
		reply, err := r.admin.RunContext(ctx, menu.path, "=.proplist="+menu.fields)
		if err != nil {
			t.Error("privacy: could not audit router diagnostics")
			return
		}
		for _, row := range reply.Re {
			for _, v := range row.Map {
				if strings.Contains(v, password) {
					t.Error("privacy: ephemeral account value found in router diagnostics")
					return
				}
			}
		}
	}
	for _, file := range []string{"harness.log", "console.log", "console.log.timeline", "qemu.log"} {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil || bytes.Contains(data, []byte(password)) {
			t.Error("privacy: host diagnostic audit failed")
			return
		}
	}
	t.Log("privacy: checked router log/history and host diagnostics for the ephemeral account value")
}

func dialPinned(t *testing.T, r *rig, user, pw string, cert *x509.Certificate) *ros.Client {
	t.Helper()
	return dialPinnedFrom(t, r, user, pw, cert, "172.31.255.2")
}

func dialPinnedFrom(t *testing.T, r *rig, user, pw string, cert *x509.Certificate, source string) *ros.Client {
	t.Helper()
	root := x509.NewCertPool()
	root.AddCert(cert)
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: root, ServerName: "172.31.255.1", VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.PeerCertificates) == 0 || !bytes.Equal(s.PeerCertificates[0].Raw, cert.Raw) {
			return errors.New("unexpected certificate")
		}
		return nil
	}}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 12 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}, Config: tlsCfg}
	ctx, cancel := context.WithTimeout(r.ctx, 20*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "172.31.255.1:8729")
	if err != nil {
		t.Fatal("fixture: pinned API connection failed")
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	cl, err := ros.NewClient(conn)
	if err != nil {
		conn.Close()
		t.Fatal("fixture: native API client failed")
	}
	t.Cleanup(func() { cl.Close() })
	cl.SetLogHandler(slog.NewTextHandler(io.Discard, nil))
	if cl.LoginContext(ctx, user, pw) != nil {
		t.Fatal("fixture: native API login failed")
	}
	_ = conn.SetDeadline(time.Time{})
	cl.AsyncContext(r.ctx)
	return cl
}

// TestProbeSession distinguishes a provisioning failure from a capability
// denial when validating the fixture on a new CHR snapshot.
func TestProbeSession(t *testing.T) {
	r := newRig(t)
	probeAccount(t, r)
	reply, err := r.api.RunContext(r.ctx, "/system/resource/print", "=.proplist=architecture-name,version")
	if err != nil || len(reply.Re) != 1 || reply.Re[0].Map["architecture-name"] != "x86_64" {
		t.Fatal("fixture: restricted native API read failed")
	}
}
