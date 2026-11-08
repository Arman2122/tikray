//go:build lab

package m3

import (
	routerosfiles "github.com/Arman2122/tikray/routeros"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/store"
)

func TestM3SourcePreservation(t *testing.T) {
	r := newRig(t)
	c := &countedNative{Client: newNativeClient(t, r)}
	run := func(cmd string) {
		t.Helper()
		if _, err := r.chr.RunPrivate(r.ctx, cmd); err != nil {
			t.Fatal("owner fixture operation failed")
		}
	}
	run(`/interface/bridge/add name=tikray protocol-mode=none comment="tikray:bridge"; /ip/address/add interface=tikray address=172.30.252.1/29 comment="tikray:addr"; /interface/list/add name=inside; /interface/list/member/add list=inside interface=ether2; /interface/list/add name=outside; /interface/list/member/add list=outside interface=ether1`)
	scope := routeros.InstallScope{Subnet: netip.MustParsePrefix("172.30.252.0/29"), LANList: "inside", LANs: []routeros.LAN{{Interface: "ether2", Prefix: netip.MustParsePrefix("192.168.88.0/24")}}, WAN: routeros.WANPath{Interface: "ether1"}}
	policy := routeros.PolicyInput{Network: store.Network{Subnet: scope.Subnet}, Default: store.Policy{Mode: store.ModeDirect}, Devices: []routeros.PolicyDevice{{Address: netip.MustParsePrefix("192.168.88.21/32"), MAC: "02:00:00:00:00:21", Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}}}}
	check := func(admit bool) (routeros.Actual, []routeros.Object) {
		t.Helper()
		a, err := routeros.Observe(r.ctx, c, scope)
		if err != nil {
			t.Fatal("failed to observe the NAT fixture")
		}
		rs, err := routeros.Desired(policy, a.Topology, nil)
		if (err == nil) != admit {
			t.Fatal("unexpected source preservation decision")
		}
		return a, rs
	}
	run(`/ip/firewall/nat/add chain=srcnat action=masquerade src-address=192.168.88.21 comment="witness:masquerade"`)
	check(false)
	run(`/ip/firewall/nat/set [find where comment="witness:masquerade"] out-interface-list=outside`)
	a, rs := check(true)
	var guards []routeros.Object
	for _, row := range rs {
		if row.Menu == "/ip/firewall/nat" && row.Props["chain"] == "srcnat" {
			guards = append(guards, row)
		}
	}
	ops, err := routeros.Plan(a, guards)
	if err != nil || len(ops) != len(guards) || len(guards) == 0 {
		t.Fatal("missing verified source guards")
	}
	if err = routeros.Execute(r.ctx, c, a, ops); err != nil {
		tag := "none"
		if c.writes > 0 && c.writes <= len(ops) {
			tag = ops[c.writes-1].Comment
		}
		t.Fatalf("native source guard operation failed at %s %s: %v", c.lastMenu, tag, err)
	}
	run(`/ip/firewall/nat/unset [find where comment="witness:masquerade"] out-interface-list`)
	a, _ = check(true)
	if ops, err = routeros.Plan(a, guards); err != nil || len(ops) != 0 {
		t.Fatal("unchanged exemptions require writes")
	}
	// With one of the pair removed, the native planner can use the surviving
	// exact row and repair only the missing one. A repeat writes nothing.
	run(`/ip/firewall/nat/remove [find where comment="tikray:preserve-closed"]`)
	a, _ = check(true)
	ops, err = routeros.Plan(a, guards)
	if err != nil || len(ops) != 1 || ops[0].Comment != "tikray:preserve-closed" {
		t.Fatal("unexpected source repair")
	}
	if err = routeros.Execute(r.ctx, c, a, ops); err != nil {
		t.Fatal("single guard recovery failed", err)
	}
	a, _ = check(true)
	if ops, err = routeros.Plan(a, guards); err != nil || len(ops) != 0 {
		t.Fatal("source guard repair did not converge")
	}
	// These releases can print a protocol name or number and a single port
	// or equivalent range. Compare only fixed fixture categories in evidence.
	native, err := r.chr.RunPrivate(r.ctx, `{ :local tag "tikray:preserve-dns-full-closed-udp"; :local proto "udp"; :local id [/ip/firewall/nat/find where comment=$tag]; :put ([:tostr [/ip/firewall/nat/get $id protocol]] . "|" . [:tostr [/ip/firewall/nat/get $id dst-port]] . "|" . [:len [/ip/firewall/nat/find where comment=$tag and protocol=$proto]] . "|" . [:len [/ip/firewall/nat/find where comment=$tag and dst-port=53]]) }`)
	fields := strings.Split(strings.TrimSpace(native), "|")
	if err != nil || len(fields) != 4 || (fields[0] != "udp" && fields[0] != "17") || (fields[1] != "53" && fields[1] != "53-53") || (fields[2] != "0" && fields[2] != "1") || (fields[3] != "0" && fields[3] != "1") {
		t.Fatal("unrecognized native DNS selector")
	}
	t.Logf("DNS selector: numeric protocol=%t, explicit port range=%t, native protocol find=%t, native port find=%t", fields[0] == "17", fields[1] == "53-53", fields[2] == "1", fields[3] == "1")
	// The owner's offline command preflights and disables each exact rule.
	// A later pass can prove the disabled pairs' positions under the marker.
	body, err := routerosfiles.Sources.ReadFile("emergency-off.rsc")
	if err != nil {
		t.Fatal("missing owner script")
	}
	path := filepath.Join(t.TempDir(), "emergency.rsc")
	if os.WriteFile(path, body, 0600) != nil || r.chr.Push(r.ctx, path, "source-off.rsc") != nil {
		t.Fatal("owner script setup failed")
	}
	run(`/import source-off.rsc`)
	run(`/system/script/run tikray-emergency-off`)
	got, err := r.chr.RunPrivate(r.ctx, `:put [:len [/ip/firewall/nat/find where comment~"^tikray:preserve-" and disabled]]`)
	if err != nil || strings.TrimSpace(got) != strconv.Itoa(len(guards)) {
		t.Fatal("emergency did not suspend every source bypass")
	}
	a, _ = check(true)
	ops, err = routeros.Plan(a, guards)
	if err != nil || len(ops) != len(guards) {
		t.Fatal("emergency bypasses could not be rearmed")
	}
	if err = routeros.Execute(r.ctx, c, a, ops); err != nil {
		t.Fatal("source rearm failed", err)
	}
	run(`/ip/firewall/nat/move [find where comment="witness:masquerade"] destination=[find where comment="tikray:preserve-open"]`)
	check(false)
}
