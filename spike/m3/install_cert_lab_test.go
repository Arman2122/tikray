//go:build lab

package m3

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/test/lab"
)

func t4CertTest(t *testing.T, reuse bool) {
	r := newRig(t)
	content, e := os.ReadFile(filepath.Join("..", "..", "routeros", "certificate.rsc"))
	if e != nil {
		t.Fatal("certificate installer is missing")
	}
	script := "{\n" + string(content) + "\n:local result [$tls true 172.31.255.1 172.31.255.2]; :if ([:len $result] != 64) do={:error \"pin unavailable\"}; :put \"OK\"\n}"
	file := filepath.Join(t.TempDir(), "cert-spike.rsc")
	if os.WriteFile(file, []byte(script), 0600) != nil || r.chr.Push(r.ctx, file, "cert-spike.rsc") != nil {
		t.Fatal("could not upload cert installer")
	}
	cmd := func(s string) string {
		t.Helper()
		o, err := r.chr.RunPrivate(r.ctx, s)
		if err != nil {
			t.Fatal("owner command unavailable")
		}
		return strings.TrimSpace(o)
	}
	run := func() {
		t.Helper()
		out := cmd(`:onerror e in={ /import file-name=cert-spike.rsc } do={ :put ("diag=" . [:convert [:tostr $e] to=base64]) }`)
		if i := strings.Index(out, "diag="); i >= 0 {
			d, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(out[i+5:]))
			for _, category := range []string{"cannot verify original api-ssl settings", "cannot prove unrestricted api-ssl baseline", "cannot verify api-ssl port or enabled state", "shared_reference_refuses", "inspect certificate signing", "syntax error"} {
				if strings.Contains(string(d), category) {
					t.Fatalf("certificate operation rejected (%s)", category)
				}
			}
			t.Fatal("certificate operation rejected")
		}
		if !strings.Contains(out, "OK") {
			t.Fatal("missing positive certificate verification")
		}
	}
	var verifyOwner func()
	if !reuse {
		cmd("/ip/service/set api-ssl disabled=yes certificate=none address=192.168.88.0/24")
		cmd("/certificate/remove [find where name=m3-cap-api]")
		cmd("/certificate/add name=owner-nonserver common-name=owner-nonserver key-size=prime256v1 key-usage=key-cert-sign,digital-signature")
		cmd("/certificate/sign owner-nonserver")
		if cmd(`:local c [/certificate/get [find name=owner-nonserver]]; :put ((($c->"private-key") = true) and ([:typeof [:find [:tostr ($c->"key-usage")] "tls-server"]] != "num"))`) != "true" {
			t.Fatal("negative key-usage witness was not established")
		}
	} else {
		cmd(`/ip/service/set api-ssl disabled=no address=""`)
		run()
		if cmd(`:local s [/ip/service/get [:pick [/ip/service/find where name="api-ssl" and !dynamic] 0]]; :put [:len ($s->"address")]`) != "0" || cmd(`:put [:len [/system/script/find where name="tikray-api-access" or name="tikray-api-receipt"]]`) != "0" {
			t.Fatal("unrestricted owner service was narrowed or claimed")
		}
		// A fresh, pinned login from a different source proves the original
		// management grant still works; a previously open socket cannot.
		const ownerIP = "172.31.255.4"
		if exec.CommandContext(r.ctx, "ip", "addr", "add", ownerIP+"/32", "dev", "tklab-lan").Run() != nil {
			t.Fatal("could not attach independent owner endpoint")
		}
		cmd("/ip/service/set api-ssl address=172.31.255.4/32,2001:db8:11::/64")
		block, _ := pem.Decode([]byte(cmd(":put [/file/get m3-cap-public.crt contents]")))
		if block == nil {
			t.Fatal("public certificate unavailable")
		}
		leaf, e := x509.ParseCertificate(block.Bytes)
		pw, read := os.ReadFile(filepath.Join(lab.CacheDir(), "ready", r.version, "x86_64", "password"))
		if e != nil || read != nil {
			t.Fatal("owner endpoint credentials unavailable")
		}
		verifyOwner = func() {
			t.Helper()
			cl := dialPinnedFrom(t, r, "admin", string(pw), leaf, ownerIP)
			rows, e := cl.RunContext(r.ctx, "/system/resource/print", "=.proplist=version")
			if e != nil || len(rows.Re) != 1 {
				t.Fatal("fresh permitted owner login failed")
			}
			_ = cl.Close()
		}
		verifyOwner()
	}

	run()
	receipt := cmd(`:put [/system/script/find where name=tikray-api-receipt]`)
	if (receipt != "") == reuse {
		t.Fatal("certificate ownership not matched to origin")
	}
	cert := cmd(`:put [/ip/service/get api-ssl certificate]`)
	if (cert == "m3-cap-api") != reuse {
		t.Fatal("incorrect certificate selected")
	}
	before := cmd(`:put [/certificate/get [find where name=[/ip/service/get api-ssl certificate]] fingerprint]`)
	run()
	if before != cmd(`:put [/certificate/get [find where name=[/ip/service/get api-ssl certificate]] fingerprint]`) || receipt != cmd(`:put [/system/script/find where name=tikray-api-receipt]`) {
		t.Fatal("repeat import replaced certificate or receipt")
	}
	if reuse {
		verifyOwner()
		o := cmd(`:local r [/ip/service/get [:pick [/ip/service/find where name="api-ssl" and !dynamic] 0]]; :put [:tostr ($r->"address")]`)
		set := strings.FieldsFunc(o, func(c rune) bool { return c == ',' || c == ';' })
		got := map[string]bool{}
		for _, s := range set {
			got[strings.TrimSuffix(s, "/32")] = true
		}
		if len(got) != 3 || !got["172.31.255.4"] || !got["172.31.255.2"] || !got["2001:db8:11::/64"] {
			t.Fatal("enabled owner's original grant set was changed")
		}
		if cmd(`:put [:len [/system/script/find where name="tikray-api-access" and source=""]]`) != "1" {
			t.Fatal("missing isolated service access grant")
		}
		return
	}
	details := cmd(`:put [/system/script/get [find where name=tikray-api-receipt] comment]`)
	b, ok := strings.CutPrefix(details, "tikray:api-receipt ")
	var baseline struct {
		Name, Fingerprint, Certificate, Address string
		Disabled                                bool
	}
	if !ok || json.Unmarshal([]byte(b), &baseline) != nil || baseline.Name != cert || baseline.Fingerprint != before || !baseline.Disabled || baseline.Address != "192.168.88.0/24" {
		t.Fatal("certificate receipt lost its ownership proof or original service settings")
	}
	cmd("/ip/service/set api-ssl certificate=none disabled=yes")
	cmd(`/certificate/remove [find where name="tikray-api"]`)
	cmd(`/certificate/add name=tikray-api common-name=replacement key-size=prime256v1 key-usage=key-cert-sign,digital-signature,tls-server`)
	cmd(`/certificate/sign tikray-api`)
	foreign := cmd(`:put [/certificate/get [find where name="tikray-api"] fingerprint]`)
	if foreign == before || len(foreign) != 64 {
		t.Fatal("replacement certificate control was not established")
	}
	cmd("/ip/service/set api-ssl certificate=tikray-api disabled=no")
	out := cmd(`:onerror e in={/import file-name=cert-spike.rsc} do={:if ($e ~ "shared_reference_refuses") do={:put "refused"}}`)
	if !strings.Contains(out, "refused") || foreign != cmd(`:put [/certificate/get [find where name="tikray-api"] fingerprint]`) || details != cmd(`:put [/system/script/get [find where name=tikray-api-receipt] comment]`) {
		t.Fatal("same-name certificate was adopted or modified")
	}
}
