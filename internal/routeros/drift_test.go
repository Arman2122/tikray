package routeros

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

func TestRepairWindowAlongsidePolicyChange(t *testing.T) {
	p := netip.MustParsePrefix
	closed := store.Policy{Mode: store.ModeFull, KillSwitch: true}
	open := store.Policy{Mode: store.ModeSmart}
	a, b := p("10.0.0.8/31"), p("10.0.0.10/31")
	verified := policyView{LANList: "LAN", Sources: []sourceClass{{p("10.0.0.8/30"), closed}}}
	target := policyView{LANList: "LAN", Sources: []sourceClass{{a, closed}, {b, open}}}
	var ops []Op
	for _, s := range target.Sources {
		r := appendMembers(nil, srcList(s.Policy), []netip.Prefix{s.Prefix})[0]
		ops = append(ops, Op{Kind: "add", Menu: r.Menu, Comment: r.Comment, target: r})
	}
	for _, pending := range [][]policyView{nil, {verified, target}} {
		v, ok := repairWindow(verified, target, ops, Actual{}, pending)
		if !ok || !v.RepairOnly || len(v.Repairs) != 1 || v.Repairs[0].Source != a || v.Repairs[0].To != closed {
			t.Fatal("missing source was not isolated from the settings change")
		}
		if _, ok := repairWindow(verified, target, ops, Actual{}, []policyView{verified, target, v, target}); ok {
			t.Fatal("retry appended the same outstanding repair")
		}
	}
	// Repartitioning the old list for a new exception is expected when the
	// old row still enforces the same binding for the unchanged half.
	f := newDiffRouter()
	r := appendMembers(nil, srcList(closed), []netip.Prefix{verified.Sources[0].Prefix})[0]
	f.insert(r.Menu, r.Comment, r.Props)
	if _, ok := repairWindow(verified, target, ops, f.actual(), nil); ok {
		t.Fatal("list repartitioning invalidated clients still covered by the old row")
	}
}

func TestTCPDNSRuleRepairPreservesDataAndUDPDNS(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.8/32")
	closed := store.Policy{Mode: store.ModeFull, KillSwitch: true}
	v := policyView{LANList: "LAN", Sources: []sourceClass{{p, closed}}}
	for _, tc := range []struct{ menu, role string }{
		{firewallNAT, "dns-full-closed-tcp"}, {firewallFilter, "egress-dns-full-closed-tcp"}, {firewallMangle, "skip-dns-tcp"},
	} {
		t.Run(tc.role, func(t *testing.T) {
			f := &connectionRouter{diffRouter: newDiffRouter()}
			r := object(tc.menu, tc.role, map[string]string{"protocol": "tcp", "dst-port": "53"})
			missing := []Op{{Kind: "add", Menu: r.Menu, Comment: r.Comment, target: r}}
			before, ok := repairWindow(v, v, missing, f.actual(), nil)
			if !ok {
				t.Fatal("missing TCP DNS rule left cached bindings untouched")
			}
			const dst = "8.8.8.8"
			tcp := f.flow(ct4, p.Addr().String(), dst, "53")
			udp := f.flow(ct4, p.Addr().String(), dst, "53")
			f.row(udp).Props["protocol"] = "udp"
			data := f.flow(ct4, p.Addr().String(), dst, "443")
			f.row(data).Props["connection-mark"] = "tikray-closed"
			n, err := purgeFlows(t.Context(), f, f.actual(), []policyView{before, v})
			if err != nil || n != 1 || f.row(tcp) != nil || f.row(udp) == nil || f.row(data) == nil {
				t.Fatal("TCP DNS repair reset an unrelated binding or left stale TCP DNS", err)
			}
		})
	}
}

func TestSameClassModeEditWithMissingVerifiedSource(t *testing.T) {
	src := netip.MustParsePrefix("192.168.4.3/32")
	from := store.Policy{Mode: store.ModeSmart, KillSwitch: true}
	to := store.Policy{Mode: store.ModeFull, KillSwitch: true}
	old := policyView{LANList: "LAN", Sources: []sourceClass{{src, from}}, Domestic: []netip.Prefix{netip.MustParsePrefix("5.0.0.0/8")}}
	next := old
	next.Sources = []sourceClass{{src, to}}
	member := appendMembers(nil, srcList(to), []netip.Prefix{src})[0]
	ops := []Op{{Menu: member.Menu, Kind: "add", Comment: member.Comment, target: member}}
	for _, role := range []string{"conn-full-closed", "dns-full-closed-tcp", "dns-full-closed-udp", "egress-drop-full"} {
		ops = append(ops, Op{Kind: "add", Menu: firewallMangle, Comment: "tikray:" + role})
	}
	f := newDiffRouter()
	pending := []policyView{old, next}
	v, ok := repairWindow(old, next, ops, f.actual(), pending)
	dst := netip.MustParseAddr("8.8.8.8")
	if !ok || len(v.Repairs) != 1 || !affectsFlow(v.Repairs[0], v, next, dst, false) || !affectsFlow(v.Repairs[0], v, next, dst, true) {
		t.Fatal("missing prior membership suppressed by routine mode edit")
	}
	previous := appendMembers(nil, srcList(from), []netip.Prefix{src})[0]
	f.insert(previous.Menu, previous.Comment, previous.Props)
	if _, ok = repairWindow(old, next, ops, f.actual(), pending); ok {
		t.Fatal("old membership still covers unchanged traffic during mode edit")
	}
}

func TestRepairWindowRestoresVerifiedIPv6Selector(t *testing.T) {
	rule := func(ip, mac string) Object {
		return object(ipv6Filter, "ipv6:host:"+ip, map[string]string{"chain": ipv6Chain, "in-interface": "lan", "src-mac-address": mac, "action": "reject", "reject-with": "icmp-admin-prohibited"})
	}
	a := rule("10.0.0.8", "02:00:00:00:00:08")
	b := rule("10.0.0.9", "02:00:00:00:00:09")
	verified := policyView{LANList: "LAN", V6: []Object{a}}
	target := policyView{LANList: "LAN", V6: []Object{a, b}}
	var ops []Op
	for _, o := range target.V6 {
		ops = append(ops, Op{Menu: o.Menu, Comment: o.Comment, Kind: "add", target: o})
	}
	repair, ok := repairWindow(verified, target, ops, Actual{}, []policyView{verified, target})
	if !ok || len(repair.Repairs) != 0 || !slices.EqualFunc(repair.V6, []Object{b}, func(a, b Object) bool { return a.Comment == b.Comment }) {
		t.Fatal("pending IPv6 admission suppressed the existing guard repair")
	}
	if _, ok = repairWindow(verified, target, ops, Actual{}, []policyView{verified, target, repair, target}); ok {
		t.Fatal("existing guard repair grew the pending journal on retry")
	}
}

func TestBypassRepairWindowsOverlapAcrossRetries(t *testing.T) {
	p := netip.MustParsePrefix
	smart := store.Policy{Mode: store.ModeSmart, KillSwitch: true}
	v := policyView{LANList: "LAN", Sources: []sourceClass{{p("10.0.0.8/32"), smart}}, Domestic: []netip.Prefix{p("1.0.0.0/8"), p("5.0.0.0/8")}}
	next := v
	next.Domestic = slices.Concat(v.Domestic, []netip.Prefix{p("6.0.0.0/8")})
	f := &connectionRouter{diffRouter: newDiffRouter()}
	var ops []Op
	members := appendMembers(nil, "tikray-domestic", next.Domestic)
	for _, r := range members {
		ops = append(ops, Op{Kind: "add", Menu: r.Menu, Comment: r.Comment, target: r})
	}
	before, ok := repairWindow(v, next, ops, f.actual(), []policyView{v, next})
	if !ok {
		t.Fatal("missing bypass windows")
	}
	for _, tc := range []struct {
		dst, mark string
		want      bool
	}{
		{"1.1.1.1", "tikray-closed", true}, {"5.1.1.1", "tikray-closed", true},
		{"6.1.1.1", "tikray-closed", false}, {"8.8.8.8", "tikray-closed", false}, {"1.2.2.2", "no-mark", false},
	} {
		d := affectedClass{before.Repairs[0], &before, &next}
		if d.includes(v.Sources[0].Prefix.Addr(), netip.MustParseAddr(tc.dst), Row{"protocol": "tcp", "dst-port": "443", "connection-mark": tc.mark}) != tc.want {
			t.Fatal("repair did not isolate the previously verified bypass destinations")
		}
	}
	f.insert(members[0].Menu, members[0].Comment, members[0].Props)
	if _, ok := repairWindow(v, next, ops[1:], f.actual(), []policyView{v, next, before, next}); ok {
		t.Fatal("partial list repair appended a narrower copy of the same window")
	}
}

func TestWrongSourceListCanBypassOtherVerifiedClient(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.8/32")
	smart := store.Policy{Mode: store.ModeSmart, KillSwitch: true}
	full := store.Policy{Mode: store.ModeFull}
	v := policyView{LANList: "LAN", Sources: []sourceClass{{p, smart}}, Domestic: []netip.Prefix{netip.MustParsePrefix("1.0.0.0/8")}}
	f := newDiffRouter()
	stray := appendMembers(nil, srcList(full), []netip.Prefix{p})[0]
	id := f.insert(stray.Menu, stray.Comment, stray.Props)
	before, ok := repairWindow(v, v, []Op{{Kind: "remove", Menu: stray.Menu, Comment: stray.Comment, id: id, target: stray}}, f.actual(), nil)
	if !ok {
		t.Fatal("wrong-class stale source list membership ignored")
	}
	d := affectedClass{before.Repairs[0], &before, &v}
	if !d.includes(p.Addr(), netip.MustParseAddr("1.1.1.1"), Row{"protocol": "tcp", "dst-port": "443", "connection-mark": "tikray-open"}) {
		t.Fatal("binding routed by the wrong source list survived")
	}
}

func TestRemovedIPv6ReturnRepairsOnlyExposedMAC(t *testing.T) {
	ingress := object(ipv6Filter, "ipv6:ingress:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", map[string]string{"chain": ipv6Chain, "in-interface": "lan", "action": "reject", "reject-with": "icmp-admin-prohibited"})
	exception := object(ipv6Filter, "ipv6:host:10.1.0.8", map[string]string{"chain": ipv6Chain, "in-interface": "lan", "src-mac-address": "02:00:00:00:00:08", "action": "return"})
	next := policyView{LANList: "LAN", V6: []Object{ingress}}
	ops := []Op{{Kind: "remove", Menu: ipv6Filter, Comment: exception.Comment, target: exception}}
	previous := policyView{LANList: "LAN", V6: []Object{exception, ingress}}
	if _, ok := repairWindow(previous, next, ops, Actual{}, []policyView{previous, next}); ok {
		t.Fatal("removal of the old direct exception was mistaken for guard drift")
	}
	before, ok := repairWindow(next, next, ops, Actual{}, nil)
	if !ok {
		t.Fatal("stray IPv6 return was missed")
	}
	selectors := tightenedSelectors([]policyView{before, next})
	if len(selectors) != 1 || !selectors[v6Selector{"lan", "02:00:00:00:00:08"}] {
		t.Fatal("one stray MAC return forced whole-interface reproof")
	}
	ops[0].target.Props["src-mac-address"] = "!02:00:00:00:00:08"
	before, ok = repairWindow(next, next, ops, Actual{}, nil)
	if !ok || !tightenedSelectors([]policyView{before, next})[v6Selector{iface: "lan"}] {
		t.Fatal("negated return silently skipped ingress reproof")
	}
}

func TestClassifierRepairPreservesHealthyDataAndDNS(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.8/32")
	v := policyView{LANList: "LAN", Sources: []sourceClass{{p, store.Policy{Mode: store.ModeFull, KillSwitch: true}}}}
	o := object(firewallMangle, "conn-full-closed", map[string]string{"action": "mark-connection"})
	before, ok := repairWindow(v, v, []Op{{Kind: "add", Menu: o.Menu, Comment: o.Comment, target: o}}, Actual{}, nil)
	if !ok || len(before.Repairs) != 1 {
		t.Fatal("classifier drift was missed")
	}
	d := affectedClass{before.Repairs[0], &before, &v}
	for _, tc := range []struct {
		mark, fast, port string
		want             bool
	}{
		{"tikray-closed", "false", "443", false}, {"tikray-closed", "true", "443", true}, {"no-mark", "false", "443", true}, {"no-mark", "false", "53", false},
	} {
		r := Row{"protocol": "tcp", "dst-port": tc.port, "fasttrack": tc.fast, "connection-mark": tc.mark}
		if d.includes(p.Addr(), netip.MustParseAddr("8.8.8.8"), r) != tc.want {
			t.Fatal("classifier repair did not isolate stale data bindings", tc.port)
		}
	}
}
