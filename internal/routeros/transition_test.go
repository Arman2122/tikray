package routeros

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

func TestPolicyChangeClearsOnlyAffectedConntrack(t *testing.T) {
	p := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	old := policyView{Sources: []sourceClass{{p("10.0.0.0/24"), store.Policy{Mode: store.ModeSmart}}}}
	next := policyView{Sources: []sourceClass{{p("10.0.0.0/25"), store.Policy{Mode: store.ModeSmart}}, {p("10.0.0.128/25"), store.Policy{Mode: store.ModeFull, KillSwitch: true}}}}
	delta := flowChanges(old, next)
	if len(delta) != 1 || delta[0].Source != p("10.0.0.128/25") {
		t.Fatal("policy change swept an unaffected prefix")
	}
	if len(flowChanges(next, next)) != 0 {
		t.Fatal("no-op policy requested conntrack removal")
	}
}

func TestSmartFullTransitionsPreserveSameClassBindings(t *testing.T) {
	p := netip.MustParsePrefix
	ip := netip.MustParseAddr
	src := p("192.168.1.4/32")
	for _, closed := range []bool{false, true} {
		for _, from := range []store.Mode{store.ModeSmart, store.ModeFull} {
			to := store.ModeFull
			if from == store.ModeFull {
				to = store.ModeSmart
			}
			fromPolicy := store.Policy{Mode: from, KillSwitch: closed}
			toPolicy := store.Policy{Mode: to, KillSwitch: closed}
			t.Run(string(from)+"_to_"+string(to)+"_"+policyClass(fromPolicy), func(t *testing.T) {
				old := policyView{LANList: "LAN", Sources: []sourceClass{{src, fromPolicy}}, Local: []netip.Prefix{p("10.0.0.0/8")}, Domestic: []netip.Prefix{p("5.0.0.0/8")}}
				next := old
				next.Sources = []sourceClass{{src, toPolicy}}
				vs := []policyView{old, next}
				changes := flowChanges(old, next)
				if len(changes) != 1 {
					t.Fatal("expected a domestic route change")
				}
				d := affectedClass{changes[0], &old, &next}
				mark := "tikray-" + policyClass(fromPolicy)
				domesticMark := mark
				if from == store.ModeSmart {
					domesticMark = "no-mark"
				}
				for _, tc := range []struct {
					dst, mark, proto, port string
					want                   bool
				}{
					{"8.8.8.8", mark, "tcp", "443", false}, {"5.1.2.3", domesticMark, "tcp", "443", true}, {"10.1.2.3", "no-mark", "tcp", "443", false},
					{"8.8.8.8", "no-mark", "tcp", "53", false}, {"5.1.2.3", "no-mark", "udp", "53", false},
				} {
					r := Row{"connection-mark": tc.mark, "protocol": tc.proto, "dst-port": tc.port}
					if d.includes(src.Addr(), ip(tc.dst), r) != tc.want {
						t.Errorf("incorrect conntrack scope for %s %s/%s", tc.dst, tc.proto, tc.port)
					}
				}
				rows := holdsFor(vs)
				lists := make(map[string][]netip.Prefix)
				var drops []Object
				for _, r := range rows {
					if r.Menu == addressListMenu {
						list := r.Props["list"]
						lists[list] = append(lists[list], p(r.Props["address"]))
						continue
					}
					if r.Menu != firewallFilter || r.Props["chain"] != "forward" || r.Props["protocol"] != "" || r.Props["src-address"] != src.String() {
						t.Errorf("unaffected guard %s", r.Props["chain"])
						continue
					}
					drops = append(drops, r)
				}
				for _, tc := range []struct {
					dst  string
					want bool
				}{{"8.8.8.8", false}, {"5.1.2.3", closed}, {"10.1.2.3", false}} {
					held := false
					for _, r := range drops {
						name := r.Props["dst-address-list"]
						list := strings.TrimPrefix(name, "!")
						held = held || (inPrefixes(lists[list], ip(tc.dst)) != (name != list))
					}
					if held != tc.want {
						t.Errorf("incorrect hold scope for %s", tc.dst)
					}
				}
				// The only domestic prefix is already bypassed on both paths.
				next.Domestic = []netip.Prefix{p("10.1.0.0/16")}
				old.Domestic = next.Domestic
				if len(flowChanges(old, next)) != 0 {
					t.Error("identical effective disposition queried conntrack")
				}
			})
		}
	}
}

func TestChangedIngressKeepsDNSAndDataProtection(t *testing.T) {
	src := netip.MustParsePrefix("192.168.1.4/32")
	closed := store.Policy{Mode: store.ModeFull, KillSwitch: true}
	next := policyView{LANList: "newLAN", Sources: []sourceClass{{src, closed}}}
	old := next
	old.LANList = "oldLAN"
	changes := flowChanges(old, next)
	if len(changes) != 1 {
		t.Fatal("changed ingress omitted")
	}
	for _, dns := range []bool{false, true} {
		if !affectsFlow(changes[0], old, next, netip.MustParseAddr("8.8.8.8"), dns) {
			t.Fatal("changed ingress omitted from binding verification")
		}
	}
	held := map[string]int{}
	for _, r := range holdsFor([]policyView{old, next}) {
		if r.Menu == firewallFilter {
			held[r.Props["in-interface-list"]]++
		}
	}
	if held["oldLAN"] != 5 || held["newLAN"] != 5 {
		t.Fatal("missing data or DNS protection on changed ingress")
	}
}

func TestBypassRepairHoldsOnlyChangedDestinations(t *testing.T) {
	p := netip.MustParsePrefix
	src := p("192.168.1.4/32")
	pol := store.Policy{Mode: store.ModeSmart, KillSwitch: true}
	target := policyView{LANList: "LAN", Sources: []sourceClass{{src, pol}}, Local: []netip.Prefix{p("10.0.0.0/8")}, Domestic: []netip.Prefix{p("4.0.0.0/8"), p("5.0.0.0/8")}}
	before := target
	before.RepairOnly = true
	before.Repairs = []flowChange{{Source: src, From: pol, To: pol}}
	before.Domestic = []netip.Prefix{p("4.0.0.0/9"), p("6.0.0.0/8"), p("10.1.0.0/16")}
	rows := holdsFor([]policyView{before, target})
	if _, err := PlanHolds(Actual{}, rows); err != nil {
		t.Fatal("generated hold failed ownership validation", err)
	}
	var rules []Object
	sets := map[string][]netip.Prefix{}
	for _, r := range rows {
		if r.Menu == addressListMenu {
			list := r.Props["list"]
			sets[list] = append(sets[list], p(r.Props["address"]))
			continue
		}
		if r.Menu != firewallFilter || r.Props["src-address"] != src.String() || r.Props["chain"] != "forward" || r.Props["dst-address-type"] != "!local" || r.Props["dst-port"] != "" {
			t.Fatal("staged unrelated DNS, management, or source guard")
		}
		rules = append(rules, r)
	}
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"4.0.1.1", false}, {"4.128.1.1", true}, {"5.1.2.3", true}, {"6.1.2.3", true}, {"7.1.2.3", false}, {"10.1.2.3", false},
	} {
		dst := netip.MustParseAddr(tc.ip)
		held := false
		for _, r := range rules {
			name := r.Props["dst-address-list"]
			list := strings.TrimPrefix(name, "!")
			held = held || (inPrefixes(sets[list], dst) != (name != list))
		}
		if held != tc.want {
			t.Fatal("wrong temporary guard scope for", tc.ip)
		}
	}
}

func TestDNSRepairHoldsOnlyAffectedTransport(t *testing.T) {
	p := netip.MustParsePrefix
	pol := store.Policy{Mode: store.ModeSmart, KillSwitch: true}
	v := policyView{LANList: "LAN", Sources: []sourceClass{{p("192.168.1.4/32"), pol}}, Local: []netip.Prefix{p("10.0.0.0/8")}, Domestic: []netip.Prefix{p("5.0.0.0/8")}}
	before := v
	before.RepairOnly = true
	before.Repairs = []flowChange{{Source: v.Sources[0].Prefix, From: pol, To: pol, DNSProtocol: "tcp"}}
	rows := holdsFor([]policyView{before, v})
	if len(rows) != 2 {
		t.Fatal("DNS-only repair wrote unused list members or guards", len(rows))
	}
	for _, r := range rows {
		if r.Menu != firewallFilter || r.Props["protocol"] != "tcp" || r.Props["dst-port"] != "53" {
			t.Fatal("unrelated DNS repair hold")
		}
	}
}

func TestValidateRepairBindingScope(t *testing.T) {
	p := netip.MustParsePrefix
	pol := store.Policy{Mode: store.ModeFull, KillSwitch: true}
	v := policyView{RepairOnly: true, LANList: "LAN", Sources: []sourceClass{{p("10.0.0.8/30"), pol}}}
	binding := flowChange{Source: p("10.0.0.10/32"), From: pol, To: pol, DNSProtocol: "tcp"}
	v.Repairs = []flowChange{binding}
	if !validView(v) {
		t.Fatal("valid repair journal rejected")
	}
	for _, mutate := range []func(*flowChange){
		func(c *flowChange) { c.Source = p("10.0.0.8/29") }, func(c *flowChange) { c.To = store.Policy{Mode: store.ModeSmart} }, func(c *flowChange) { c.DNSProtocol = "icmp" }, func(c *flowChange) { c.DataOnly = true },
	} {
		ch := binding
		mutate(&ch)
		v.Repairs = []flowChange{ch}
		if validView(v) {
			t.Fatal("accepted malformed repair journal scope")
		}
	}
}
