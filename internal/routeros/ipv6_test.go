package routeros

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

const macA = "02:00:00:00:00:0A"
const macB = "02:00:00:00:00:0B"

func guardDevice(prefix string, mode store.Mode, mac string) PolicyDevice {
	return PolicyDevice{Address: netip.MustParsePrefix(prefix), Policy: store.Policy{Mode: mode}, MAC: mac}
}

func guardLAN(name, cidr string, dedicated bool) LAN {
	return LAN{Interface: name, Prefix: netip.MustParsePrefix(cidr), Dedicated: dedicated}
}

func boundLease(iface, ip, mac string) Lease {
	return Lease{Interface: iface, Address: netip.MustParseAddr(ip), MAC: mac}
}

// Exercise the compiled RouterOS selectors, including jump and return to the owner's chain.
func guardRejects(t *testing.T, rules []Object, chain, iface, mac string, selected bool) bool {
	t.Helper()
	for _, r := range rules {
		p := r.Props
		if r.Menu != "/ipv6/firewall/filter" || p["chain"] != chain ||
			p["in-interface-list"] != "" && (!selected || p["in-interface-list"] != "LAN") ||
			p["in-interface"] != "" && p["in-interface"] != iface ||
			p["src-mac-address"] != "" && !strings.EqualFold(p["src-mac-address"], mac) {
			continue
		}
		switch p["action"] {
		case "jump":
			if chain != "forward" || p["jump-target"] == chain || p["in-interface-list"] != "LAN" || r.Before != "first:forward" {
				t.Fatal("invalid IPv6 entry point")
			}
			if guardRejects(t, rules, p["jump-target"], iface, mac, selected) {
				return true
			}
		case "reject":
			if p["reject-with"] != "icmp-admin-prohibited" || p["in-interface"] == "" {
				t.Fatal("invalid IPv6 reject selector")
			}
			return true
		case "return":
			return false
		default:
			t.Fatal("unexpected guard action")
		}
	}
	return false
}

func TestIPv6GuardScopeAndLeaseChange(t *testing.T) {
	in := PolicyInput{Default: store.Policy{Mode: store.ModeDirect}, Devices: []PolicyDevice{guardDevice("192.168.10.3/32", store.ModeSmart, "")}}
	obs := Topology{LANList: "LAN", LANs: []LAN{guardLAN("bridge", "192.168.10.0/24", false)}, Leases: []Lease{boundLease("bridge", "192.168.10.3", macA)}}
	rules, err := ipv6Guard(in, obs)
	if err != nil || !guardRejects(t, rules, "forward", "bridge", macA, true) {
		t.Fatal("proxied lease lacks an IPv6 guard")
	}
	for _, chain := range []string{"input", "output"} {
		if guardRejects(t, rules, chain, "bridge", macA, true) {
			t.Fatal("guard reaches router-local traffic or neighbor discovery")
		}
	}
	if guardRejects(t, rules, "forward", "bridge", macB, true) || guardRejects(t, rules, "forward", "guest", macA, false) ||
		guardRejects(t, rules, "forward", "other-lan", macA, true) {
		t.Fatal("guard reaches unrelated clients")
	}

	obs.Leases[0].MAC = macB
	changed, err := ipv6Guard(in, obs)
	if err != nil || !guardRejects(t, changed, "forward", "bridge", macB, true) || guardRejects(t, changed, "forward", "bridge", macA, true) {
		t.Fatal("replacement lease did not replace the exact selector")
	}
	if len(rules) != len(changed) {
		t.Fatal("lease replacement changed guard size")
	}
	for i := range rules {
		if rules[i].Comment != changed[i].Comment {
			t.Fatal("lease replacement lost rule identity")
		}
	}
	obs.Leases = nil
	if rules, err := ipv6Guard(in, obs); err == nil || len(rules) != 0 {
		t.Fatal("missing lease broadened protection")
	}
	in.Devices[0].MAC = macB
	rules, err = ipv6Guard(in, obs)
	if err != nil || !guardRejects(t, rules, "forward", "bridge", macB, true) {
		t.Fatal("configured MAC did not protect a static host")
	}
}

func TestIPv6DedicatedIngressAndDirectExceptions(t *testing.T) {
	in := PolicyInput{Default: store.Policy{Mode: store.ModeFull}, Devices: []PolicyDevice{
		guardDevice("192.168.10.3/32", store.ModeDirect, macA),
		guardDevice("192.168.20.0/24", store.ModeDirect, ""),
	}}
	obs := Topology{LANList: "LAN", LANs: []LAN{
		guardLAN("bridge", "192.168.10.0/24", true),
		guardLAN("vlan20", "192.168.20.0/24", false),
	}}
	rules, err := ipv6Guard(in, obs)
	if err != nil || guardRejects(t, rules, "forward", "bridge", macA, true) || !guardRejects(t, rules, "forward", "bridge", macB, true) ||
		guardRejects(t, rules, "forward", "vlan20", macB, true) {
		t.Fatal("dedicated default and its direct exceptions are not preserved")
	}
	slices.Reverse(in.Devices)
	slices.Reverse(obs.LANs)
	again, err := ipv6Guard(in, obs)
	if err != nil || !reflect.DeepEqual(again, rules) {
		t.Fatal("input order changed IPv6 guard")
	}
	in.Default.Mode = store.ModeDirect
	in.Devices = []PolicyDevice{guardDevice("192.168.10.0/24", store.ModeFull, "")}
	rules, err = ipv6Guard(in, obs)
	if err != nil || !guardRejects(t, rules, "forward", "bridge", macB, true) || guardRejects(t, rules, "forward", "vlan20", macB, true) {
		t.Fatal("subnet guard failed to isolate the dedicated ingress")
	}
}

func TestIPv6GuardRefusesAmbiguousIdentity(t *testing.T) {
	d := guardDevice("192.168.10.3/32", store.ModeFull, macA)
	lan := guardLAN("bridge", "192.168.10.0/24", false)
	for _, tc := range []struct {
		name    string
		mode    store.Mode
		devices []PolicyDevice
		lans    []LAN
		leases  []Lease
	}{
		{"configured DHCP disagreement", store.ModeDirect, []PolicyDevice{d}, []LAN{lan}, []Lease{boundLease("bridge", "192.168.10.3", macB)}},
		{"same MAC direct alias", store.ModeDirect, []PolicyDevice{d}, []LAN{lan}, []Lease{boundLease("bridge", "192.168.10.9", macA)}},
		{"same MAC configured direct", store.ModeDirect, []PolicyDevice{d, guardDevice("192.168.10.4/32", store.ModeDirect, macA)}, []LAN{lan}, nil},
		{"two current bindings", store.ModeDirect, []PolicyDevice{guardDevice("192.168.10.3/32", store.ModeSmart, "")}, []LAN{lan}, []Lease{boundLease("bridge", "192.168.10.3", macA), boundLease("bridge", "192.168.10.3", macB)}},
		{"shared default", store.ModeSmart, nil, []LAN{lan}, nil},
		{"unidentified direct exception", store.ModeSmart, []PolicyDevice{guardDevice("192.168.10.3/32", store.ModeDirect, "")}, []LAN{guardLAN("bridge", "192.168.10.0/24", true)}, nil},
		{"partial dedicated subnet", store.ModeDirect, []PolicyDevice{guardDevice("192.168.10.0/25", store.ModeSmart, "")}, []LAN{guardLAN("bridge", "192.168.10.0/24", true)}, nil},
		{"different networks on same ingress", store.ModeDirect, []PolicyDevice{guardDevice("192.168.10.0/24", store.ModeSmart, "")}, []LAN{guardLAN("bridge", "192.168.10.0/24", true), guardLAN("bridge", "192.168.20.0/24", true)}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := ipv6Guard(PolicyInput{Default: store.Policy{Mode: tc.mode}, Devices: tc.devices}, Topology{LANList: "LAN", LANs: tc.lans, Leases: tc.leases})
			if err == nil || len(rules) != 0 || !strings.HasPrefix(err.Error(), "routeros: ") || strings.Contains(err.Error(), macA) || strings.Contains(err.Error(), "192.168") {
				t.Fatal("ambiguous guard did not refuse cleanly")
			}
		})
	}
}

func TestIPv6MACMayRecurOnSeparateLANs(t *testing.T) {
	in := PolicyInput{Default: store.Policy{Mode: store.ModeDirect}, Devices: []PolicyDevice{guardDevice("192.168.10.3/32", store.ModeFull, macA)}}
	obs := Topology{LANList: "LAN", LANs: []LAN{guardLAN("left", "192.168.10.0/24", false), guardLAN("right", "192.168.20.0/24", false)},
		Leases: []Lease{boundLease("right", "192.168.20.7", macA)}}
	rules, err := ipv6Guard(in, obs)
	if err != nil || !guardRejects(t, rules, "forward", "left", macA, true) || guardRejects(t, rules, "forward", "right", macA, true) {
		t.Fatal("unrelated MAC on another ingress affected protection")
	}
}

func TestIPv6GuardDeduplicatesCompatibleSelectors(t *testing.T) {
	in := PolicyInput{Default: store.Policy{Mode: store.ModeDirect}, Devices: []PolicyDevice{
		guardDevice("192.168.10.3/32", store.ModeSmart, ""),
		guardDevice("192.168.10.4/32", store.ModeFull, macA),
	}}
	obs := Topology{LANList: "LAN", LANs: []LAN{guardLAN("vlan10", "192.168.10.0/24", false)}, Leases: []Lease{
		boundLease("vlan10", "192.168.10.3", macA), boundLease("vlan10", "192.168.10.4", strings.ToLower(macA)),
	}}
	rules, err := ipv6Guard(in, obs)
	if err != nil || len(rules) != 2 || !guardRejects(t, rules, "forward", "vlan10", macA, true) {
		t.Fatal("compatible aliases did not share a guarded selector")
	}
	slices.Reverse(in.Devices)
	slices.Reverse(obs.Leases)
	again, err := ipv6Guard(in, obs)
	if err != nil || !reflect.DeepEqual(again, rules) {
		t.Fatal("equivalent bindings changed rule identity or order")
	}
}

func TestIPv6UnionOfProxiedSubnets(t *testing.T) {
	in := PolicyInput{Default: store.Policy{Mode: store.ModeDirect}, Devices: []PolicyDevice{
		guardDevice("192.168.10.0/25", store.ModeSmart, ""),
		guardDevice("192.168.10.128/25", store.ModeFull, ""),
	}}
	obs := Topology{LANList: "LAN", LANs: []LAN{guardLAN("vlan10", "192.168.10.0/24", true)}}
	rules, err := ipv6Guard(in, obs)
	if err != nil || len(rules) != 2 || !guardRejects(t, rules, "forward", "vlan10", macA, true) {
		t.Fatal("two half-subnets did not cover a dedicated ingress")
	}
	if rules[1].Props["action"] != "jump" || !slices.Equal(rules[1].DependsOn, []string{rules[0].Comment}) {
		t.Fatal("entry point can precede its guard")
	}
}
