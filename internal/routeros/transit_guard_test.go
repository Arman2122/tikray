package routeros

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func TestManagedRunnerTransitGuard(t *testing.T) {
	f := newDiffRouter()
	scope := testTransitScope()
	const tag = "tikray:acl-runner-transit"
	keep := f.insert(firewallFilter, "tikray:egress-guard", map[string]string{"action": "jump", "chain": "forward", "jump-target": "tikray-egress", "in-interface-list": "inside", "out-interface": "!tikray"})
	f.insert(firewallFilter, "tikray:egress-drop-marked", map[string]string{"action": "drop", "chain": "tikray-egress"})
	owner := f.insert(firewallFilter, "owner:forward", map[string]string{"action": "accept", "chain": "forward"})
	check := func(repair bool) error { return ReconcileTransitGuard(t.Context(), f, scope, repair, false) }
	if err := check(false); !errors.Is(err, ErrPolicyConflict) || len(f.writes) != 0 {
		t.Fatal("read-only verification admitted or repaired an absent guard")
	}
	if err := check(true); err != nil {
		t.Fatal(err)
	}
	r := f.tag(tag)
	if r == nil || r.Props["src-address"] != "!172.30.252.0/29" || r.Props["in-interface"] != "tikray" || r.Props["out-interface-list"] != "!inside" || r.Props["action"] != "drop" {
		t.Fatal("transit guard is not scoped to the installed bridge and LAN")
	}
	order := func(id string) int { return slices.IndexFunc(f.rows, func(r Observed) bool { return r.ID == id }) }
	if order(keep) >= order(r.ID) || order(owner) <= order(r.ID) {
		t.Fatal("guard displaced safe policy or sat behind owner accept")
	}
	n := len(f.writes)
	if check(false) != nil || check(true) != nil || len(f.writes) != n {
		t.Fatal("stable guard did not converge without writes")
	}
	id := r.ID
	if _, err := f.CommandAt(t.Context(), f.gen, []string{firewallFilter + "/move", "=numbers=" + owner, "=destination=" + id}); err != nil {
		t.Fatal(err)
	}
	f.tag(tag).Props["disabled"] = "true"
	if !errors.Is(check(false), ErrPolicyConflict) || check(true) != nil || order(id) >= order(owner) || onBit(f.tag(tag).Props["disabled"]) {
		t.Fatal("did not repair a disabled or displaced guard by its verified ID")
	}
	f.tag(tag).Props["protocol"] = "tcp"
	n = len(f.writes)
	if !errors.Is(check(true), ErrPolicyConflict) || len(f.writes) != n {
		t.Fatal("altered selector treated as sufficient protection")
	}
	delete(f.tag(tag).Props, "protocol")
	f.tag(tag).Props["layer7-protocol"] = "owner-input"
	if !errors.Is(check(true), ErrPolicyConflict) || len(f.writes) != n {
		t.Fatal("extra matcher allowed without proof")
	}
	delete(f.tag(tag).Props, "layer7-protocol")
	f.insert(firewallFilter, tag, map[string]string{"chain": "input", "action": "accept"})
	if !errors.Is(check(true), ErrPolicyConflict) || len(f.writes) != n {
		t.Fatal("ambiguous owner tag was touched")
	}
}

func TestRunnerTransitGuardDoesNotTrustPermissiveJump(t *testing.T) {
	f := newDiffRouter()
	jump := f.insert(firewallFilter, "tikray:egress-guard", map[string]string{"action": "jump", "chain": "forward", "jump-target": "tikray-egress", "in-interface-list": "inside", "out-interface": "!tikray"})
	f.insert(firewallFilter, "owner:rule", map[string]string{"action": "accept", "chain": "tikray-egress"})
	if err := ReconcileTransitGuard(t.Context(), f, testTransitScope(), true, false); err != nil {
		t.Fatal(err)
	}
	guard := slices.IndexFunc(f.rows, func(r Observed) bool { return r.Comment == transitTag })
	anchor := slices.IndexFunc(f.rows, func(r Observed) bool { return r.ID == jump })
	if guard < 0 || anchor <= guard {
		t.Fatal("permissive jump precedes router-side protection")
	}
}

func TestRunnerTransitGuardFencesInstallation(t *testing.T) {
	f := newDiffRouter()
	f.insert("/system/script", "tikray:uninstall-state", map[string]string{"name": "tikray-uninstall-state"})
	if err := ReconcileTransitGuard(t.Context(), f, testTransitScope(), true, false); !errors.Is(err, ErrUnavailable) || len(f.writes) != 0 {
		t.Fatal("repair raced removal")
	}
}

func TestLegacyDirectBootstrapCannotAdmitSteeringWithoutGuard(t *testing.T) {
	f := newDiffRouter()
	f.insert("/system/script", "tikray:install-lock fixture", map[string]string{"name": "tikray-install-lock"})
	scope := testTransitScope()
	if err := ReconcileTransitGuard(t.Context(), f, scope, false, true); err != nil {
		t.Fatal("historical direct-only bootstrap refused", err)
	}
	if err := ReconcileTransitGuard(t.Context(), f, scope, false, false); !errors.Is(err, ErrPolicyConflict) {
		t.Fatal("a pending steering policy could bypass the native guard")
	}
	if err := ReconcileTransitGuard(t.Context(), f, scope, true, false); !errors.Is(err, ErrUnavailable) || len(f.writes) != 0 {
		t.Fatal("active installer raced a policy admission")
	}
}

func testTransitScope() InstallScope {
	return InstallScope{Subnet: bindingSubnet, LANList: "inside", LANs: []LAN{{Interface: "ether2", Prefix: netip.MustParsePrefix("192.168.88.0/24")}}}
}

func TestTransitGuardBindsReturnDestinations(t *testing.T) {
	scope := testTransitScope()
	scope.LANs = append(scope.LANs, LAN{Interface: "ether3", Prefix: netip.MustParsePrefix("10.5.1.0/24")}, scope.LANs[0])
	f := newDiffRouter()
	check := func() error { return ReconcileTransitGuard(t.Context(), f, scope, true, false) }
	if err := check(); err != nil {
		t.Fatal(err)
	}
	for _, lan := range scope.LANs {
		row := f.tag("tikray:acl-transit-lan:" + lan.Prefix.String())
		if row == nil || row.Props["list"] != "tikray-transit-lans" || row.Props["address"] != lan.Prefix.String() {
			t.Fatal("missing enrolled LAN destination")
		}
	}
	dest := f.tag("tikray:acl-runner-transit-dst")
	if dest == nil || dest.Props["dst-address-list"] != "!tikray-transit-lans" || dest.Props["src-address"] != "!"+scope.Subnet.String() || dest.Props["in-interface"] != "tikray" {
		t.Fatal("WAN/LAN list overlap opens returned packets")
	}
	n := len(f.writes)
	if check() != nil || len(f.writes) != n {
		t.Fatal("duplicate enrolled LANs did not converge")
	}
	member := f.tag("tikray:acl-transit-lan:10.5.1.0/24")
	memberID := member.ID
	member.Props["disabled"] = "true"
	if err := check(); err != nil || onBit(f.tag(member.Comment).Props["disabled"]) || f.tag(member.Comment).ID != memberID {
		t.Fatal("exact disabled enrolled destination was not restored in place")
	}
	n = len(f.writes)
	f.insert(addressListMenu, "owner:permitted", map[string]string{"list": "tikray-transit-lans", "address": "0.0.0.0/0"})
	if !errors.Is(check(), ErrPolicyConflict) || len(f.writes) != n {
		t.Fatal("foreign network expanded return destinations")
	}
}

func TestTransitListNotAdoptedFromOwner(t *testing.T) {
	for _, m := range []string{firewallFilter, firewallNAT, firewallMangle, "/ip/firewall/raw"} {
		f := newDiffRouter()
		f.insert(m, "owner:other", map[string]string{"src-address-list": "!tikray-transit-lans"})
		if err := ReconcileTransitGuard(t.Context(), f, testTransitScope(), true, false); !errors.Is(err, ErrPolicyConflict) || len(f.writes) != 0 {
			t.Fatal("changed a list consumed by an owner rule", m)
		}
	}
}
