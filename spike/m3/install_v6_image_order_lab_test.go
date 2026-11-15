//go:build lab

package m3

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	routerfiles "github.com/Arman2122/tikray/routeros"
)

// Image updates repeat the owner installer while there is active LAN policy.
// Retain a restrictive IPv6 policy ahead of the private bridge drop without
// putting a bridge packet behind any owner accept or permissive jump.
func TestImageReimportKeepsIPv6GuardOrder(t *testing.T) {
	r := newRig(t)
	run := func(cmd string) string {
		t.Helper()
		s, err := r.chr.RunPrivate(r.ctx, cmd)
		if err != nil {
			t.Fatal("private IPv6 ordering fixture failed")
		}
		return strings.TrimSpace(s)
	}
	const menu = "/ipv6/firewall/filter"
	run(`/interface/bridge/add name=tikray; /interface/list/add name=m3-image-lan`)
	run(menu + `/add chain=tikray-ipv6 action=return comment="tikray:ipv6:fixture"`)
	run(menu + `/add chain=forward in-interface-list=m3-image-lan action=jump jump-target=tikray-ipv6 comment="tikray:ipv6:jump"`)
	run(menu + `/add chain=forward out-interface=tikray action=drop comment="tikray:acl-v6-bridge"`)
	run(menu + `/add chain=forward action=accept comment="owner:v6-permit"`)
	b, err := routerfiles.Sources.ReadFile("install.rsc")
	if err != nil {
		t.Fatal("missing installer")
	}
	code := string(b)
	a := strings.Index(code, ":local ensure do={")
	z := strings.Index(code, ":local dir do={")
	// The entire IPv6 forward ordering step follows the raw hook
	// verification and precedes creation of the control environment.
	from := strings.Index(code, "do={ /ip/firewall/raw/move $hook destination=$first }")
	to := strings.Index(code, `:set i [$ensure "/container/envs" "tikray:env-ctl-data"`)
	if a < 0 || z <= a || from < 0 || to <= from {
		t.Fatal("installer fixture boundaries changed")
	}
	_, v6, _ := strings.Cut(code[from:to], "\n")
	script := "/system/script/add name=m3-image-reimport source={\n" + code[a:z] + "\n" + `:local apply true; :local requireInstall do={:return true}; :local lease ""; :local noKeys [:toarray ""]; :local first ""; :local hook ""; :local lanList "m3-image-lan"
` + v6 + "\n}\n"
	path := filepath.Join(t.TempDir(), "order.rsc")
	if os.WriteFile(path, []byte(script), 0600) != nil || r.chr.Push(r.ctx, path, "m3-image-order.rsc") != nil {
		t.Fatal("cannot stage owner reimport excerpt")
	}
	run("/import file-name=m3-image-order.rsc")
	order := func() string {
		return run(`{:local observed ""; :foreach i in=[/ipv6/firewall/filter/find where chain="forward" and !dynamic] do={:local label [/ipv6/firewall/filter/get $i comment]; :if ([:pick $label 0 12]="tikray:hold:") do={:set observed ($observed . "H")}; :if ($label="tikray:ipv6:jump") do={:set observed ($observed . "G")}; :if ($label="tikray:acl-v6-bridge") do={:set observed ($observed . "B")}; :if ($label="owner:v6-permit") do={:set observed ($observed . "O")}}; :put $observed}`)
	}
	if order() != "GBO" {
		t.Fatal("incorrect established IPv6 fixture order")
	}
	run("/system/script/run m3-image-reimport")
	if order() != "GBO" {
		t.Fatal("repeat import displaced the working restrictive IPv6 guard")
	}
	hold := strings.Repeat("a", 32)
	run(menu + `/add chain=tikray-h` + hold + ` action=drop comment="tikray:hold:` + strings.Repeat("b", 32) + `"`)
	run(menu + `/add chain=forward in-interface-list=m3-image-lan action=jump jump-target=tikray-h` + hold + ` comment="tikray:hold:` + hold + `" place-before=[find where comment="tikray:ipv6:jump"]`)
	run("/system/script/run m3-image-reimport")
	if order() != "HGBO" {
		t.Fatal("reimport displaced a scoped temporary hold")
	}
	run(menu + `/set [find where comment="tikray:ipv6:fixture"] action=accept`)
	run("/system/script/run m3-image-reimport")
	if order() != "HBGO" {
		t.Fatal("bridge drop allowed a permissive owner jump to precede it")
	}
}
