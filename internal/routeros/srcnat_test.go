package routeros

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

func TestSourceNATRequiresOriginalClient(t *testing.T) {
	for _, tc := range []struct {
		name, action, out, list, src string
		conflict                     bool
	}{
		{"broad masquerade", "masquerade", "", "", "192.168.88.0/24", true},
		{"explicit translation", "src-nat", "", "", "", true},
		{"netmap", "netmap", "", "", "", true},
		{"UDP endpoint mapping", "endpoint-independent-nat", "", "", "", true},
		{"unproven jump", "jump", "", "", "", true},
		{"normal uplink", "masquerade", "ether1", "", "", false},
		{"WAN list", "masquerade", "", "outside", "", false},
		{"except WAN", "masquerade", "", "!outside", "", true},
		{"private bridge", "masquerade", "tikray", "", "", true},
		{"except private bridge", "masquerade", "!tikray", "", "", false},
		{"other clients", "masquerade", "", "", "192.168.32.0/24", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := observationFixture()
			p.rows["/interface/list"] = append(p.rows["/interface/list"], Row{"name": "outside"})
			p.rows["/interface/list/member"] = append(p.rows["/interface/list/member"], Row{"list": "outside", "interface": "ether1"})
			r := Row{".id": "*A", "chain": "srcnat", "action": tc.action, "out-interface": tc.out, "out-interface-list": tc.list, "src-address": tc.src}
			p.rows[firewallNAT] = []Row{r}
			a, e := Observe(t.Context(), p, p.scope)
			if e != nil {
				t.Fatal(e)
			}
			in := PolicyInput{Network: store.Network{Subnet: p.scope.Subnet}, Default: directPolicy, Devices: []PolicyDevice{{Address: netip.MustParsePrefix("192.168.88.8/32"), Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}}}}
			out, e := Desired(in, a.Topology, nil)
			if (e != nil) != tc.conflict || e != nil && len(out) > 0 {
				t.Fatal("incorrect source NAT admission")
			}
			if _, e = Desired(PolicyInput{Network: in.Network, Default: directPolicy}, a.Topology, nil); e != nil {
				t.Fatal("source NAT prevents direct recovery")
			}
		})
	}
}

func TestAppendedOwnerNATCannotHideSource(t *testing.T) {
	p := observationFixture()
	a, e := Observe(t.Context(), p, p.scope)
	if e != nil {
		t.Fatal(e)
	}
	in := PolicyInput{Network: store.Network{Subnet: p.scope.Subnet}, Default: directPolicy, Devices: []PolicyDevice{{Address: netip.MustParsePrefix("192.168.88.8/32"), Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}}}}
	desired, e := Desired(in, a.Topology, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range desired {
		if r.Menu != firewallNAT || r.Props["chain"] != "srcnat" {
			continue
		}
		if r.Props["action"] != "accept" || r.Props["out-interface"] != "tikray" || !(r.Props["connection-mark"] == "tikray-open" || r.Props["connection-mark"] == "tikray-closed" || r.Props["dst-address"] == "172.31.255.3" && r.Props["dst-port"] == "53" && strings.HasPrefix(r.Props["src-address-list"], "tikray-src-")) {
			t.Fatal("source preservation can change owner traffic")
		}
		row := Row(maps.Clone(r.Props))
		row[".id"] = fmt.Sprintf("*%X", len(p.rows[firewallNAT])+1)
		row["comment"] = r.Comment
		p.rows[firewallNAT] = append(p.rows[firewallNAT], row)
	}
	if len(p.rows[firewallNAT]) == 0 {
		t.Fatal("policy does not protect original sources")
	}
	broad := Row{".id": "*BB", "chain": "srcnat", "action": "masquerade"}
	p.rows[firewallNAT] = append(p.rows[firewallNAT], broad)
	a, e = Observe(t.Context(), p, p.scope)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Desired(in, a.Topology, nil); e != nil {
		t.Fatal("safe appended owner NAT blocked steering")
	}
	// A single deleted guard, including the closed data leg, must leave a
	// live exemption and allow an exact one-row repair before the owner rule.
	all := slices.Clone(p.rows[firewallNAT])
	for _, role := range []string{"preserve-closed", "preserve-dns-full-closed-udp", "preserve-backup-open", "preserve-backup-dns-smart-open-tcp"} {
		idx := slices.IndexFunc(all, func(r Row) bool { return r["comment"] == "tikray:"+role })
		if idx < 0 {
			t.Fatal("missing independent source protection", role)
		}
		p.rows[firewallNAT] = slices.Delete(slices.Clone(all), idx, idx+1)
		a, err := Observe(t.Context(), p, p.scope)
		if err != nil {
			t.Fatal(err)
		}
		wanted, err := Desired(in, a.Topology, nil)
		if err != nil {
			t.Fatal("surviving guard cannot authorize repair", role)
		}
		wanted = slices.DeleteFunc(wanted, func(o Object) bool { return o.Menu != firewallNAT || o.Props["chain"] != "srcnat" })
		ops, err := Plan(a, wanted)
		if err != nil || len(ops) != 1 || ops[0].Kind != "add" || ops[0].Comment != "tikray:"+role {
			t.Fatal("single source guard deletion did not plan exactly one repair")
		}
	}
	p.rows[firewallNAT] = all
	p.rows[firewallNAT] = append([]Row{broad}, p.rows[firewallNAT][:len(p.rows[firewallNAT])-1]...)
	a, e = Observe(t.Context(), p, p.scope)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Desired(in, a.Topology, nil); e == nil {
		t.Fatal("shadowed source protection reported healthy")
	}
}

func TestOnlyNetwatchPrimaryDNSHasVolatileEnabledBit(t *testing.T) {
	for _, tc := range []struct {
		role     string
		volatile bool
	}{
		{"dns-full-open-udp", true}, {"dns-full-closed-tcp", false}, {"dns-router-smart-open-udp", false},
		{"preserve-dns-full-open-udp", false}, {"preserve-open", false},
	} {
		a := Observed{Menu: firewallNAT, Comment: "tikray:" + tc.role, Props: map[string]string{"disabled": "false"}}
		b := a
		b.Props = map[string]string{"disabled": "true"}
		if (equalObserved(a, b) == nil) != tc.volatile {
			t.Fatal("unexpected volatile enabled bit", tc.role)
		}
	}
}

func TestIPv6TableReferencePreventsTeardown(t *testing.T) {
	p := observationFixture()
	p.rows["/ipv6/route"] = []Row{{"routing-table": "tikray-closed", ".id": "*B"}}
	if e := checkReferences(t.Context(), p, p.Generation()); e != errConflict {
		t.Fatal("removal can orphan an owner IPv6 route")
	}
	p.rows["/ipv6/route"][0]["routing-table"] = "owner"
	if e := checkReferences(t.Context(), p, p.Generation()); e != nil {
		t.Fatal("independent IPv6 table blocked teardown")
	}
	for _, q := range p.queries {
		if q[0] == "/ipv6/route/print" && !slices.Contains(q, "=count-only=") {
			t.Fatal("downloaded a foreign IPv6 route")
		}
	}
}

func TestOpaqueNATListOnlyRefusesSteering(t *testing.T) {
	p := observationFixture()
	p.rows["/interface/list"] = append(p.rows["/interface/list"], Row{"name": "outside", "include": "dynamic"})
	p.rows[firewallNAT] = []Row{{".id": "*1", "chain": "srcnat", "action": "masquerade", "out-interface-list": "outside"}}
	a, err := Observe(t.Context(), p, p.scope)
	if err != nil {
		t.Fatal("opaque owner egress disabled ordinary routing and bootstrap")
	}
	in := PolicyInput{Network: store.Network{Subnet: p.scope.Subnet}, Default: directPolicy}
	if _, err = Desired(in, a.Topology, nil); err != nil {
		t.Fatal("direct recovery refused")
	}
	in.Default = store.Policy{Mode: store.ModeFull, KillSwitch: true}
	if _, err = Desired(in, a.Topology, nil); err == nil {
		t.Fatal("opaque policy admitted")
	}
	p.rows[firewallNAT][0] = Row{".id": "*1", "chain": "srcnat", "action": "accept", "comment": "tikray:preserve-other"}
	a, err = Observe(t.Context(), p, p.scope)
	if err != nil || a.Topology.sourceNATConflict {
		t.Fatal("unrelated non-translating rule treated as source NAT")
	}
}
