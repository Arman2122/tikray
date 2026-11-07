package routeros

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestOwnerSelectorsCannotDisappearFromObservation(t *testing.T) {
	cases := []struct {
		menu string
		row  Row
	}{
		{firewallFilter, Row{"action": "fasttrack-connection", "chain": "owner-forward"}},
		{firewallFilter, Row{"action": "jump", "chain": "forward", "comment": "tikray:egress-guard", "time": "8h-12h,mon"}},
		{firewallMangle, Row{"action": "mark-packet", "chain": "prerouting", "in-interface": "ether1", "new-packet-mark": "owner"}},
		{firewallMangle, Row{"action": "mark-connection", "chain": "postrouting", "new-connection-mark": "owner"}},
		{"/ip/firewall/raw", Row{"action": "notrack", "chain": "prerouting", "in-interface": "ether2"}},
		{"/routing/rule", Row{"action": "lookup-only-in-table", "table": "owner-vpn", "src-address": "192.168.88.8/32"}},
	}
	for _, tc := range cases {
		t.Run(tc.menu+"-"+tc.row["action"], func(t *testing.T) {
			p := observationFixture()
			tc.row[".id"] = "*B"
			p.rows[tc.menu] = []Row{tc.row}
			a, e := Observe(context.Background(), p, p.scope)
			if e == nil && len(a.Topology.ForeignRefs) == 0 {
				t.Fatal("unsafe intersecting rule ignored")
			}
		})
	}
}

func TestOwnerDisjointSelectors(t *testing.T) {
	p := observationFixture()
	p.rows["/routing/rule"] = []Row{{"src-address": "10.0.0.0/24", "action": "lookup-only-in-table", "table": "owner"}}
	p.rows[firewallNAT] = []Row{{".id": "*1", "chain": "dstnat", "action": "dst-nat", "to-addresses": "10.0.0.8"}}
	p.rows[firewallMangle] = []Row{{".id": "*1", "chain": "prerouting", "action": "mark-routing", "new-routing-mark": "owner-lan", "in-interface": "ether2", "passthrough": "true"}, {".id": "*2", "chain": "forward", "action": "mark-packet", "src-address": "10.0.0.2", "dst-address": "10.0.0.3"}}
	a, e := Observe(context.Background(), p, p.scope)
	if e != nil || len(a.Topology.ForeignRefs) != 0 || !slices.Contains(a.Topology.ForeignRoutingMarks, "owner-lan") {
		t.Fatal("disjoint owner policy refused")
	}
}

func TestReadEffectiveListPrecedence(t *testing.T) {
	p := observationFixture()
	p.rows["/interface/list"][0]["exclude"] = "guests"
	p.rows["/interface/list"] = append(p.rows["/interface/list"], Row{"name": "guests"})
	p.rows["/interface/list/member"] = append(p.rows["/interface/list/member"], Row{"list": "nested", "interface": "guest"}, Row{"list": "guests", "interface": "guest"})
	a, e := Observe(context.Background(), p, p.scope)
	if e != nil || !slices.Equal(a.Topology.LANMembers, []string{"ether2"}) {
		t.Fatal("nested exclusion not applied")
	}
	p.rows["/interface/list/member"] = append(p.rows["/interface/list/member"], Row{"list": "clients", "interface": "guest"})
	a, e = Observe(context.Background(), p, p.scope)
	if e == nil && slices.Equal(a.Topology.LANMembers, []string{"ether2"}) {
		t.Fatal("direct member did not override exclusion")
	}
}

func TestScopedPointToPointAddressCollisions(t *testing.T) {
	for _, row := range []Row{
		{"address": "10.0.0.1/32", "network": "172.31.255.3", "interface": "tunnel"},
		{"address": "172.31.255.3/32", "network": "10.0.0.2", "interface": "tunnel"},
	} {
		p := observationFixture()
		p.rows["/ip/address"] = append(p.rows["/ip/address"], row)
		if _, e := Observe(context.Background(), p, p.scope); e == nil {
			t.Fatal("foreign peer overlaps bridge")
		}
	}
}
func TestObservedFlagsFailClosed(t *testing.T) {
	p := observationFixture()
	p.rows[firewallMangle] = []Row{{".id": "*2", "chain": "forward", "action": "mark-packet", "disabled": "corrupt"}}
	if _, e := Observe(context.Background(), p, p.scope); e == nil {
		t.Fatal("malformed disabled flag treated as an inactive owner")
	}
}

func TestOwnedRowsPreservePrivateOrder(t *testing.T) {
	p := observationFixture()
	p.rows[firewallFilter] = []Row{
		{".id": "*1", "chain": egressChain, "action": "drop", "comment": "tikray:egress-drop-full"},
		{".id": "*2", "chain": egressChain, "action": "return", "comment": "tikray:egress-skip-local"},
		{".id": "*3", "chain": "forward", "action": "drop", "comment": "tikray:install-isolation"},
	}
	p.rows[routeMenu] = append(p.rows[routeMenu], Row{".id": "*2", "comment": "tikray:route-open-runner", "dst-address": "0.0.0.0/0", "routing-table": "tikray-open"})
	a, e := Observe(context.Background(), p, p.scope)
	if e != nil {
		t.Fatal(e)
	}
	var private []string
	for _, r := range a.Rows {
		if r.Props["chain"] == egressChain {
			private = append(private, r.Comment)
		}
		if r.Menu == routeMenu && r.Comment != "tikray:route-open-runner" {
			t.Fatal("foreign route downloaded")
		}
	}
	if !slices.Equal(private, []string{"tikray:egress-drop-full", "tikray:egress-skip-local"}) {
		t.Fatal("lost private chain order")
	}
}

func TestPendingOwnerFastTrackCannotBeSkipped(t *testing.T) {
	p := observationFixture()
	p.rows[firewallFilter] = []Row{
		{".id": "*1", "chain": "forward", "action": "fasttrack-connection", "invalid": "true", "connection-state": "established,related"},
		{".id": "*2", "chain": "forward", "action": "drop", "invalid": "false"},
		{".id": "*3", "chain": "forward", "action": "accept"},
	}
	if _, e := Observe(context.Background(), p, p.scope); e == nil {
		t.Fatal("reported no enabled FastTrack during compilation")
	}
	p.rows[firewallFilter][0]["invalid"] = "false"
	p.rows[firewallFilter][1]["invalid"] = "true"
	if _, e := Observe(context.Background(), p, p.scope); e == nil {
		t.Fatal("skipped an earlier pending owner deny")
	}
}

func TestReferenceProbeKeepsSimilarOwnerNames(t *testing.T) {
	p := observationFixture()
	p.rows["/queue/simple"] = []Row{{"packet-marks": "owner-a,tikray-proxied"}}
	if err := checkReferences(context.Background(), p, p.generation); err != errConflict {
		t.Fatal("reserved mark in a list was missed")
	}
	p.rows["/queue/simple"] = nil
	p.rows[firewallFilter] = []Row{{".id": "*5", "chain": "tikray-home", "action": "drop"}}
	if err := checkReferences(context.Background(), p, p.generation); err != nil {
		t.Fatal("unrelated owner chain rejected")
	}
}

func TestOwnerMarkWritersRetainOnlyFlowPredicates(t *testing.T) {
	p := observationFixture()
	p.rows[firewallMangle] = []Row{
		{".id": "*1", "chain": "prerouting", "action": "mark-routing", "new-routing-mark": "owner-a", "in-interface": "ether2", "protocol": "udp", "src-port": "32000"},
		{".id": "*2", "chain": "prerouting", "action": "mark-routing", "new-routing-mark": "owner-b", "src-address": "192.168.88.21", "content": "private-fixture"},
		{".id": "*3", "chain": "prerouting", "action": "mark-routing", "new-routing-mark": "owner-c", "in-interface": "guest"},
	}
	a, e := Observe(context.Background(), p, p.scope)
	if e != nil || len(a.Topology.RoutingMarkWriters) != 2 {
		t.Fatal("missing overlapping policy writers")
	}
	writers := a.Topology.RoutingMarkWriters
	if writers[0].Mark != "owner-a" || writers[0].Opaque || writers[0].Match["src-port"] != "32000" || !writers[1].Opaque || len(writers[1].Match) != 1 {
		t.Fatal("writer evidence was lost or overstated")
	}
	for _, q := range p.queries {
		if strings.Contains(q[1], "content") {
			t.Fatal("raw matcher payload was requested")
		}
	}
}

func TestMainDefaultVerifiesActivePath(t *testing.T) {
	p := observationFixture()
	check := func(want string) {
		t.Helper()
		a, e := Observe(context.Background(), p, p.scope)
		if e != nil {
			t.Fatal(e)
		}
		if want == "" {
			if len(a.Topology.WAN) != 0 {
				t.Fatal("ambiguous main default accepted")
			}
			return
		}
		if len(a.Topology.WAN) != 1 || a.Topology.WAN[0].nextHop() != want {
			t.Fatal("fallback did not follow verified route")
		}
	}
	p.rows[routeMenu][0]["gateway"] = "198.51.100.254"
	p.rows[routeMenu][0]["immediate-gw"] = "198.51.100.254%ether1"
	check("198.51.100.254%ether1")
	p.rows["/interface"] = append(p.rows["/interface"], Row{"name": "ether3", "type": "ether", "running": "true"})
	p.rows["/ip/address"] = append(p.rows["/ip/address"], Row{"interface": "ether3", "address": "192.0.2.2/24", "network": "192.0.2.0"})
	p.rows[routeMenu] = []Row{
		{"dst-address": "0.0.0.0/0", "routing-table": "main", "active": "false", "gateway": "198.51.100.254", "immediate-gw": "198.51.100.254%ether1"},
		{"dst-address": "0.0.0.0/0", "routing-table": "owner", "active": "true", "gateway": "198.51.100.1", "immediate-gw": "198.51.100.1%ether1"},
		{"dst-address": "0.0.0.0/0", "routing-table": "main", "active": "true", "gateway": "192.0.2.1%ether3", "immediate-gw": "192.0.2.1%ether3"},
	}
	check("192.0.2.1%ether3")
	p.rows[routeMenu][0]["active"] = "true"
	check("")
	p.rows[routeMenu] = nil
	check("")
	p.rows["/interface"] = append(p.rows["/interface"], Row{"name": "pppoe-out", "type": "pppoe-out", "running": "true"})
	p.rows[routeMenu] = []Row{{"dst-address": "0.0.0.0/0", "routing-table": "main", "active": "true", "gateway": "pppoe-out", "immediate-gw": "pppoe-out"}}
	check("pppoe-out")
	p.rows["/interface"][2]["running"] = "false"
	check("")
	p.rows[routeMenu][0]["gateway"] = "ether1"
	p.rows[routeMenu][0]["immediate-gw"] = "ether1"
	check("")
}
func TestMainDefaultRefusesUnprovenHop(t *testing.T) {
	cases := []struct{ field, v string }{
		{"ecmp", "true"}, {"ecmp", ""}, {"ecmp", "unknown"}, {"gateway", ""}, {"immediate-gw", ""}, {"gateway", "198.51.100.1,198.51.100.2"}, {"gateway", "198.51.100.1%wrong"}, {"immediate-gw", "198.51.100.1%ether1;198.51.100.254%ether1"}, {"immediate-gw", "198.51.100.1"}, {"immediate-gw", "198.51.100.1%tikray"}, {"immediate-gw", "198.51.100.1%ether2"}, {"immediate-gw", "198.51.100.1%ether3"}, {"immediate-gw", "2001:db8::1%ether1"},
	}
	for _, tc := range cases {
		p := observationFixture()
		p.rows[routeMenu][0][tc.field] = tc.v
		a, e := Observe(context.Background(), p, p.scope)
		if e == nil && len(a.Topology.WAN) != 0 {
			t.Fatalf("unsafe main default accepted for %s", tc.field)
		}
	}
	p := observationFixture()
	p.rows[routeMenu][0]["gateway"] = "192.0.2.1"
	p.rows[routeMenu][0]["immediate-gw"] = "192.0.2.1%ether1"
	a, e := Observe(context.Background(), p, p.scope)
	if e == nil && len(a.Topology.WAN) != 0 {
		t.Fatal("off-link next hop accepted")
	}
}
