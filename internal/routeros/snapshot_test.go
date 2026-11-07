package routeros

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

// The fixture executes the native query stack before applying the projection,
// so a missing filter cannot be hidden by code that discards rows locally.
type observationPeer struct {
	scope      InstallScope
	rows       map[string][]Row
	queries    [][]string
	generation uint64
}

func (p *observationPeer) Generation() uint64                                   { return p.generation }
func (p *observationPeer) Listen(context.Context, []string, func(Change)) error { return ErrRequest }
func (p *observationPeer) CommandAt(_ context.Context, g uint64, words []string) ([]Row, error) {
	if g == 0 || g != p.generation {
		return nil, ErrStaleGeneration
	}
	if validateRequest(words, false) != nil || !strings.HasSuffix(words[0], "/print") {
		return nil, ErrRequest
	}
	p.queries = append(p.queries, slices.Clone(words))
	var fields []string
	for _, w := range words {
		if s, ok := strings.CutPrefix(w, "=.proplist="); ok {
			fields = strings.Split(s, ",")
		}
	}
	var out []Row
	for _, row := range p.rows[strings.TrimSuffix(words[0], "/print")] {
		if !matchObservationQuery(row, words[1:]) {
			continue
		}
		r := Row{}
		for _, k := range fields {
			if v, ok := row[k]; ok {
				r[k] = v
			}
		}
		out = append(out, r)
	}
	if slices.Contains(words, "=count-only=") {
		return []Row{{"ret": strconv.Itoa(len(out))}}, nil
	}
	return out, nil
}
func matchObservationQuery(row Row, words []string) bool {
	var stack []bool
	for _, word := range words {
		q, ok := strings.CutPrefix(word, "?")
		if !ok {
			continue
		}
		if ops, ok := strings.CutPrefix(q, "#"); ok {
			for _, op := range ops {
				n := len(stack)
				switch op {
				case '!':
					stack[n-1] = !stack[n-1]
				case '|', '&':
					a, b := stack[n-2], stack[n-1]
					stack = stack[:n-1]
					if op == '|' {
						stack[n-2] = a || b
					} else {
						stack[n-2] = a && b
					}
				default:
					panic("unknown query op")
				}
			}
			continue
		}
		op := ""
		if strings.ContainsAny(q[:1], "<>-") {
			op, q = q[:1], q[1:]
		}
		key, value, eq := strings.Cut(q, "=")
		actual, found := row[key]
		cmp := strings.Compare(actual, value)
		if a, e := netip.ParseAddr(actual); e == nil {
			if b, e := netip.ParseAddr(value); e == nil {
				cmp = a.Compare(b)
			}
		}
		if a, e := netip.ParsePrefix(actual); e == nil {
			if b, e := netip.ParsePrefix(value); e == nil {
				cmp = a.Addr().Compare(b.Addr())
				if cmp == 0 {
					cmp = a.Bits() - b.Bits()
				}
			}
		}
		var yes bool
		switch op {
		case "-":
			yes = !found
		case ">":
			yes = found && cmp > 0
		case "<":
			yes = found && cmp < 0
		default:
			yes = found && (!eq || value == actual)
		}
		stack = append(stack, yes)
	}
	return !slices.Contains(stack, false)
}
func observationFixture() *observationPeer {
	prefix := netip.MustParsePrefix
	p := &observationPeer{generation: 9, rows: map[string][]Row{}, scope: InstallScope{Subnet: prefix("172.31.255.0/29"), LANList: "clients", LANs: []LAN{{Interface: "ether2", Prefix: prefix("192.168.88.0/24"), Dedicated: true}}, WAN: WANPath{Interface: "ether1", Network: prefix("198.51.100.0/24"), Gateway: netip.MustParseAddr("198.51.100.1")}}}
	p.rows["/interface"] = []Row{{"name": "ether1", "type": "ether", "running": "true"}}
	p.rows["/interface/bridge"] = []Row{{".id": "*1", "name": "tikray", "comment": "tikray:bridge", "protocol-mode": "none"}}
	p.rows["/ip/address"] = []Row{
		{".id": "*1", "interface": "tikray", "address": "172.31.255.1/29", "network": "172.31.255.0", "comment": "tikray:addr"},
		{".id": "*2", "interface": "ether2", "address": "192.168.88.1/24", "network": "192.168.88.0"},
		{".id": "*3", "interface": "ether1", "address": "198.51.100.2/24", "network": "198.51.100.0"},
	}
	p.rows["/interface/list"] = []Row{{".id": "*1", "name": "clients", "include": "nested"}, {".id": "*2", "name": "nested"}}
	p.rows["/interface/list/member"] = []Row{{".id": "*1", "list": "nested", "interface": "ether2", "dynamic": "true"}}
	p.rows["/ip/route"] = []Row{{".id": "*1", "routing-table": "main", "dst-address": "0.0.0.0/0", "gateway": "198.51.100.1", "immediate-gw": "198.51.100.1%ether1", "active": "true"}}
	p.rows["/ip/dhcp-server"] = []Row{{".id": "*1", "name": "leases", "interface": "ether2", "relay": "0.0.0.0"}}
	p.rows["/ip/dhcp-server/lease"] = []Row{
		{".id": "*1", "active-server": "leases", "server": "leases", "status": "bound", "active-address": "192.168.88.8", "active-mac-address": "02:11:22:33:44:55", "host-name": "work-laptop"},
		{".id": "*2", "active-server": "elsewhere", "server": "elsewhere", "status": "bound", "active-address": "10.0.0.2", "active-mac-address": "02:11:22:33:44:56", "host-name": "private"},
	}
	return p
}
func TestReadQueriesAreRouterFiltered(t *testing.T) {
	p := observationFixture()
	a, e := Observe(context.Background(), p, p.scope)
	if e != nil {
		t.Fatal(e)
	}
	if a.Generation != 9 || len(a.Leases) != 1 || a.Leases[0].Name != "work-laptop" || len(a.Topology.Leases) != 1 || !slices.Equal(a.Topology.LANMembers, []string{"ether2"}) || len(a.Topology.WAN) != 1 {
		t.Fatal("verified scope or lease missing")
	}
	defaults := 0
	for _, q := range p.queries {
		if validateRequest(q, false) != nil {
			t.Fatal("unscoped observation")
		}
		if q[0] == "/ip/route/print" || q[0] == "/routing/table/print" {
			if !slices.Contains(q, "=count-only=") && !slices.ContainsFunc(q, func(s string) bool { return strings.Contains(s, "comment=tikray") }) {
				if !slices.Equal(q, []string{"/ip/route/print", "=.proplist=gateway,immediate-gw,ecmp", "?routing-table=main", "?dst-address=0.0.0.0/0", "?active=true"}) {
					t.Fatal("foreign routing row query")
				}
				defaults++
			}
		}
		if q[0] == "/ip/dhcp-server/lease/print" && (!slices.Contains(q, "?active-server=leases") || !slices.Contains(q, "?status=bound")) {
			t.Fatal("unscoped lease read")
		}
	}
	if defaults != 1 {
		t.Fatal("missing unique filtered active default observation")
	}
	p.rows["/ip/dhcp-server/lease"][0]["host-name"] = "vless://sensitive.invalid"
	p.rows["/ip/dhcp-server/lease"][0]["active-address"] = "192.168.88.21"
	a, e = Observe(context.Background(), p, p.scope)
	if e != nil || len(a.Leases) != 1 || a.Leases[0].Address.String() != "192.168.88.21" || strings.Contains(a.Leases[0].Name, "sensitive") {
		t.Fatal("lease move or name projection failed")
	}
}
func TestObservationRefusesAmbiguousTopology(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*observationPeer)
	}{
		{"retagged bridge", func(p *observationPeer) { p.rows["/interface/bridge"][0]["comment"] = "owner" }},
		{"extra LAN member", func(p *observationPeer) {
			p.rows["/interface/list/member"] = append(p.rows["/interface/list/member"], Row{"list": "nested", "interface": "ether1"})
		}},
		{"nested cycle", func(p *observationPeer) { p.rows["/interface/list"][1]["include"] = "clients" }},
		{"noncanonical DHCP relay", func(p *observationPeer) { p.rows["/ip/dhcp-server"][0]["relay"] = "192.168.88.2" }},
		{"unselected dedicated alias", func(p *observationPeer) {
			p.rows["/ip/address"] = append(p.rows["/ip/address"], Row{"interface": "ether2", "address": "10.8.0.1/24", "network": "10.8.0.0"})
		}},
		{"bridge overlap", func(p *observationPeer) {
			p.rows["/ip/address"] = append(p.rows["/ip/address"], Row{"interface": "guest", "address": "172.31.254.1/23", "network": "172.31.254.0"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := observationFixture()
			tc.edit(p)
			a, e := Observe(context.Background(), p, p.scope)
			if e == nil && checkTopology(PolicyInput{Network: store.Network{Subnet: p.scope.Subnet}}, a.Topology) == nil {
				t.Fatal("accepted ambiguous router facts")
			}
		})
	}
}
func TestObservationConflictsAndOrder(t *testing.T) {
	for _, tc := range []struct {
		menu string
		row  Row
	}{
		{firewallMangle, Row{"chain": "forward", "action": "mark-packet", "new-packet-mark": "owner-qos"}},
		{firewallMangle, Row{"chain": "prerouting", "action": "jump", "jump-target": "owner-chain"}},
		{firewallNAT, Row{"chain": "dstnat", "action": "dst-nat", "to-addresses": "192.168.88.8"}},
		{"/ip/firewall/address-list", Row{"list": "tikray-local", "address": "93.184.216.1"}},
		{"/routing/rule", Row{"table": "tikray-closed"}},
		{"/ip/route", Row{"routing-table": "tikray-open", "dst-address": "0.0.0.0/0"}},
	} {
		t.Run(tc.menu+tc.row["action"], func(t *testing.T) {
			p := observationFixture()
			tc.row[".id"] = "*A"
			p.rows[tc.menu] = append(p.rows[tc.menu], tc.row)
			a, e := Observe(context.Background(), p, p.scope)
			if e == nil && len(a.Topology.ForeignRefs) == 0 {
				t.Fatal("unverified owner interaction was ignored")
			}
		})
	}
	p := observationFixture()
	p.rows[firewallFilter] = []Row{
		{".id": "*1", "chain": "forward", "action": "passthrough", "dynamic": "true"},
		{".id": "*2", "chain": "forward", "action": "fasttrack-connection", "connection-state": "established,related"},
		{".id": "*3", "chain": "forward", "action": "drop", "disabled": "true"},
		{".id": "*4", "chain": "forward", "action": "accept", "connection-state": "established,related"},
	}
	a, e := Observe(context.Background(), p, p.scope)
	if e != nil || len(a.Topology.FastTrack) != 1 || a.Topology.FastTrack[0].Next == nil || a.Topology.FastTrack[0].Next.ID != "*4" {
		t.Fatal("incorrect FastTrack successor")
	}
	p.rows[firewallFilter][3]["random"] = "4"
	a, e = Observe(context.Background(), p, p.scope)
	if e == nil {
		_, e = fastTrackException(a.Topology.FastTrack)
	}
	if !errors.Is(e, errFastTrack) {
		t.Fatalf("lost unsupported conditional accept: %v", e)
	}
	p.rows[firewallMangle] = []Row{{".id": "*5", "chain": "prerouting", "action": "mark-routing", "new-routing-mark": "owner", "passthrough": "true"}}
	a, e = Observe(context.Background(), p, p.scope)
	if e == nil && !slices.Contains(a.Topology.ForeignRoutingMarks, "owner") {
		t.Fatal("owner routing mark missing")
	}
}

type emergencyPeer struct {
	*observationPeer
	writes int
}

func (p *emergencyPeer) CommandAt(ctx context.Context, g uint64, w []string) ([]Row, error) {
	if w[0] == "/system/script/remove" {
		if p.generation != g || len(w) != 2 || w[1] != "=.id=*B" {
			return nil, ErrRejected
		}
		p.writes++
		p.rows["/system/script"] = nil
		return nil, nil
	}
	return p.observationPeer.CommandAt(ctx, g, w)
}
func TestEmergencyStateUsesExactIdentity(t *testing.T) {
	p := &emergencyPeer{observationPeer: observationFixture()}
	marker := Row{".id": "*B", "name": "tikray-emergency-state", "comment": "tikray:emergency-state", "source": "", "policy": "read,write", "dont-require-permissions": "false"}
	p.rows["/system/script"] = []Row{marker}
	id, busy, e := EmergencyState(context.Background(), p, p.generation)
	if e != nil || id != "*B" || busy {
		t.Fatal("verified marker missing")
	}
	p.rows["/system/script/job"] = []Row{{".id": "*1", "script": "tikray-emergency-off"}}
	if ClearEmergency(context.Background(), p, p.generation, id) == nil || p.writes != 0 {
		t.Fatal("removed active owner's marker")
	}
	p.rows["/system/script/job"] = nil
	for _, k := range []string{"name", "comment", "source", ".id", "policy", "dont-require-permissions"} {
		old := marker[k]
		marker[k] = "owner"
		if ClearEmergency(context.Background(), p, p.generation, id) == nil || p.writes != 0 {
			t.Fatal("removed mismatched marker")
		}
		marker[k] = old
	}
	if e = ClearEmergency(context.Background(), p, p.generation, id); e != nil || p.writes != 1 {
		t.Fatal("verified re-arm did not clear exact marker")
	}
	for _, q := range p.queries {
		if strings.Contains(q[1], "source") {
			t.Fatal("downloaded script source")
		}
	}
}
