//go:build lab

package m3

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/routeros/adapters"
	routerosfiles "github.com/Arman2122/tikray/routeros"
)

func uninstallFixture(t *testing.T) (*rig, func(string) string, func() string) {
	t.Helper()
	r := newRig(t)
	var body bytes.Buffer
	if err := adapters.BuildUninstaller(&body); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	upload := func(name, source string) {
		t.Helper()
		p := filepath.Join(dir, name)
		if os.WriteFile(p, []byte(source), 0600) != nil || r.chr.Push(r.ctx, p, name) != nil {
			t.Fatal("could not stage owner fixture")
		}
	}
	upload("remove.rsc", body.String())

	command := func(s string) string {
		t.Helper()
		v, e := r.chr.RunPrivate(r.ctx, s)
		if e != nil {
			t.Fatal("private fixture command refused")
		}
		return strings.TrimSpace(v)
	}
	importFile := func(name string) string {
		v := command(`:onerror err in={ /import file-name=` + name + `; :put "tkr-ok" } do={ :put ("tkr-error=" . [:convert [:tostr $err] to=base64]) }`)
		if strings.HasSuffix(v, "tkr-ok") {
			return ""
		}
		_, encoded, ok := strings.Cut(v, "tkr-error=")
		if !ok {
			return "missing acknowledgement"
		}
		d, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		msg := string(d)

		if strings.Contains(msg, "tikray:") {
			for _, line := range strings.Split(body.String(), "\n") {
				for _, literal := range regexp.MustCompile(`:error "(tikray:[^"]+)"`).FindAllStringSubmatch(line, -1) {
					if strings.Contains(msg, literal[1]) {
						return literal[1]
					}
				}
			}
		}
		for _, label := range []string{"syntax error", "expected end of command", "expected command name", "bad command name", "input does not match", "invalid internal item", "expected", "no such item", "no such command", "no such", "failure", "not enough permissions", "argument", "not a valid", "not allowed", "cannot", "invalid", "out of range", "cannot find"} {
			if strings.Contains(msg, label) {
				return label + " " + regexp.MustCompile(`line [0-9]+ column [0-9]+`).FindString(msg)
			}
		}
		return fmt.Sprintf("unclassified refusal (%d bytes) %s", len(msg), regexp.MustCompile(`line [0-9]+ column [0-9]+`).FindString(msg))
	}
	command("/ip/service/set api-ssl disabled=yes certificate=none address=192.168.88.0/24,2001:db8::2/128")
	command("/certificate/remove [find name=m3-cap-api]")
	cert, e := routerosfiles.Sources.ReadFile("certificate.rsc")
	if e != nil {
		t.Fatal(e)
	}
	upload("create-receipt.rsc", "{\n"+string(cert)+"\n:local pin [$tls true 172.31.255.1 172.31.255.2]; :if ([:len $pin]!=64) do={:error \"fixture pin\"}\n}")
	if got := importFile("create-receipt.rsc"); got != "" {
		t.Fatal("certificate fixture:", got)
	}
	return r, command, func() string { return importFile("remove.rsc") }
}

func TestUninstallRestoresAPISettings(t *testing.T) {
	_, cmd, uninstall := uninstallFixture(t)
	if cmd(`:put [:len [/certificate/find where name="tikray-api"]]`) != "1" {
		t.Fatal("missing positive certificate control")
	}
	cmd(`/ip/firewall/filter/add chain=forward action=accept comment=owner-firewall`)
	if got := uninstall(); got != "" {
		t.Fatal("uninstall:", got)
	}
	verify := cmd(`{ :local v [/ip/service/get [find where name="api-ssl" and !dynamic]]; :local a [:tostr ($v->"address")]; :put ((($v->"disabled")=true) and ([:len ($v->"address")]=2) and ([:typeof [:find $a "192.168.88.0/24"]]="num") and ([:typeof [:find $a "2001:db8::2"]]="num") and ([:len [/certificate/find where name="tikray-api"]]=0) and ([:len [/ip/firewall/filter/find where comment=owner-firewall]]=1) and ([:len [/system/script/find where comment~"^tikray:"]]=0)) }`)
	if verify != "true" {
		t.Fatal("service or receipt not restored")
	}
	if got := uninstall(); got != "" {
		t.Fatal("second uninstall:", got)
	}
}
func TestCertificateNameCollisionNeverDeletesReplacement(t *testing.T) {
	_, cmd, uninstall := uninstallFixture(t)
	cmd(`/ip/service/set api-ssl certificate=none disabled=yes; /certificate/remove [find name=tikray-api]; /certificate/add name=tikray-api common-name=other key-size=prime256v1 key-usage=key-cert-sign,digital-signature,tls-server; /certificate/sign tikray-api`)
	before := cmd(`:put [/certificate/get [find name=tikray-api] fingerprint]`)
	if got := uninstall(); !strings.Contains(got, "shared_reference_refuses") {
		t.Fatal("replacement certificate rejection:", got)
	}
	if before != cmd(`:put [/certificate/get [find name=tikray-api] fingerprint]`) || cmd(`:put [:len [/system/script/find where name=tikray-api-receipt]]`) != "1" || cmd(`:put [:len [/system/script/find where name=tikray-uninstall-state]]`) != "0" {
		t.Fatal("refusal changed owner or installation")
	}
}

func TestUninstallRefusesLostServiceProof(t *testing.T) {
	_, cmd, remove := uninstallFixture(t)
	cmd(`/interface/bridge/add name=tikray protocol-mode=none comment="tikray:bridge"; /system/script/remove [find name=tikray-api-receipt]`)
	if got := remove(); !strings.Contains(got, "shared_reference_refuses") {
		t.Fatal("missing service proof did not refuse", got)
	}
	if cmd(`:put [:len [/interface/bridge/find where name=tikray and comment="tikray:bridge"]]`) != "1" ||
		cmd(`:put [:len [/system/script/find where name=tikray-uninstall-state]]`) != "0" {
		t.Fatal("refusal dismantled installation")
	}
}

func TestUninstallRefusesForeignBridgeConsumers(t *testing.T) {
	_, cmd, remove := uninstallFixture(t)
	cmd(`/interface/bridge/add name=tikray protocol-mode=none comment="tikray:bridge"; /interface/veth/add name=tikray-ctl address=172.31.255.2/29 gateway=172.31.255.1 comment="tikray:veth-ctl"`)
	for _, rule := range []struct{ menu, props string }{
		{"/interface/bridge/filter", "chain=input action=accept in-interface=tikray-ctl"},
		{"/interface/bridge/nat", "chain=dstnat action=accept in-interface=tikray-ctl"},
		{"/ip/route", "dst-address=198.18.8.0/24 gateway=tikray"},
		{"/ipv6/route", "dst-address=2001:db8:8::/64 gateway=fe80::1%tikray"},
	} {
		cmd(rule.menu + "/add " + rule.props + " comment=owner-removal-consumer")
		if got := remove(); !strings.Contains(got, "shared_reference_refuses") {
			t.Fatalf("uninstall ignored %s consumer: %s", rule.menu, got)
		}
		if cmd(`:put [:len [/system/script/find where name=tikray-uninstall-state]]`) != "0" || cmd(`:put [/ip/service/get api-ssl certificate]`) != "tikray-api" {
			t.Fatal("late shared reference refusal")
		}
		cmd(rule.menu + "/remove [find comment=owner-removal-consumer]")
	}
}

func TestUninstallPreservesReplacementEmptyRoot(t *testing.T) {
	r := newRig(t)
	data, e := routerosfiles.Sources.ReadFile("uninstall-data.rsc")
	if e != nil {
		t.Fatal(e)
	}
	src := "{\n" + string(data) + `
:local u do={ :return true }
:local v [$cleanData "empty" "purge" "disk1/tikray-empty/data" "11111111111111111111111111111111" "empty" "172.31.255.0/29" $u [:toarray ""]]
:if ([:len [/file/find where name="disk1/tikray-empty/data/state"]] != 1) do={ :error "removed replacement" }; :put "PRESERVED" }`
	p := filepath.Join(t.TempDir(), "empty-removal.rsc")
	if os.WriteFile(p, []byte(src), 0600) != nil || r.chr.Push(r.ctx, p, "empty-removal.rsc") != nil {
		t.Fatal("fixture")
	}
	if _, e := r.chr.RunPrivate(r.ctx, `/file/add name=disk1/tikray-empty type=directory; /file/add name=disk1/tikray-empty/data type=directory; /file/add name=disk1/tikray-empty/data/state type=directory`); e != nil {
		t.Fatal("fixture")
	}
	v, e := r.chr.RunPrivate(r.ctx, `:onerror e in={ /import empty-removal.rsc } do={ :put "REFUSED" }`)
	if e != nil || !strings.Contains(v, "PRESERVED") {
		t.Fatal("resumed empty-phase cleanup failed to preserve replacement directories")
	}
}

func TestUninstallRetiresServiceProofLast(t *testing.T) {
	r, cmd, uninstall := uninstallFixture(t)
	var out bytes.Buffer
	if err := adapters.BuildUninstaller(&out); err != nil {
		t.Fatal(err)
	}
	const boundary = `$drop "/system/script" $inventory "receipt" $requireInstall $lease`
	if strings.Count(out.String(), boundary) != 1 {
		t.Fatal("receipt retirement boundary missing")
	}
	cut := strings.Replace(out.String(), boundary, boundary+`; :error "tikray: fixture loss after receipt retirement"`, 1)
	p := filepath.Join(t.TempDir(), "cut.rsc")
	if os.WriteFile(p, []byte(cut), 0600) != nil || r.chr.Push(r.ctx, p, "cut.rsc") != nil {
		t.Fatal("fixture transfer")
	}
	v := cmd(`:global tikrayUninstallData "keep"; :onerror err in={ /import cut.rsc } do={ :if ([:typeof [:find $err "fixture loss"]] = "num") do={ :put "cut" } }`)
	if !strings.HasSuffix(v, "cut") || cmd(`:put [:len [/system/script/find where name=tikray-api-mode]]`) != "1" || cmd(`:put [:len [/system/script/find where name=tikray-api-receipt]]`) != "0" {
		t.Fatal("teardown did not reach intended retirement boundary")
	}
	cmd(`/ip/service/set api-ssl address=192.168.77.2/32`)
	if got := uninstall(); !strings.Contains(got, "restored API-SSL settings changed") {
		t.Fatal("unverified receipt retirement accepted", got)
	}
	cmd(`/ip/service/set api-ssl address=192.168.88.0/24,2001:db8::2/128`)
	if got := uninstall(); got != "" {
		t.Fatal("verified receipt retirement did not resume", got)
	}
}

func TestUninstallReusedServiceModes(t *testing.T) {
	_, cmd, uninstall := uninstallFixture(t)
	if got := uninstall(); got != "" {
		t.Fatal("fixture teardown:", got)
	}
	cmd(`/certificate/add name=owner-server common-name=owner key-size=prime256v1 key-usage=key-cert-sign,tls-server,digital-signature; /certificate/sign owner-server; /ip/service/set api-ssl certificate=owner-server disabled=no address=""`)
	install := func() {
		t.Helper()
		if strings.Contains(cmd(`:onerror err in={ /import create-receipt.rsc } do={ :put "refused" }`), "refused") {
			t.Fatal("fixture install")
		}
	}
	install()
	if cmd(`:put [/system/script/get [find name=tikray-api-mode] comment]`) != "tikray:api-mode unchanged" || cmd(`:put [:len [/system/script/find where name=tikray-api-receipt or name=tikray-api-access]]`) != "0" {
		t.Fatal("unchanged service acquired a certificate receipt")
	}
	if got := uninstall(); got != "" {
		t.Fatal("positively unchanged service refused", got)
	}
	cmd(`/ip/service/set api-ssl disabled=yes address=192.168.88.0/24`)
	install()
	if cmd(`:put [/system/script/get [find name=tikray-api-mode] comment]`) != "tikray:api-mode access" {
		t.Fatal("missing access-only service proof")
	}
	cmd(`/system/script/remove [find name=tikray-api-access]`)
	if got := uninstall(); !strings.Contains(got, "required API-SSL receipt missing") {
		t.Fatal("missing access-only receipt accepted", got)
	}
	if cmd(`:put [:len [/certificate/find where name=owner-server]]`) != "1" || cmd(`:put [:len [/system/script/find where name=tikray-uninstall-state]]`) != "0" {
		t.Fatal("missing access-only receipt changed installation")
	}
}
