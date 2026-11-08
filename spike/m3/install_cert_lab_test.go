//go:build lab

package m3

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if !reuse {
		cmd("/ip/service/set api-ssl disabled=yes certificate=none address=192.168.88.0/24")
		cmd("/certificate/remove [find where name=m3-cap-api]")
	}
	run := func() {
		t.Helper()
		if out := cmd("/import file-name=cert-spike.rsc"); !strings.Contains(out, "OK") {
			t.Fatal("certificate setup or reimport failed")
		}
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
