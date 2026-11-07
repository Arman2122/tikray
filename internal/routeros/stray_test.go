package routeros

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

func TestStraySourceRepairPreservesDirectAndOwnerBindings(t *testing.T) {
	f := &connectionRouter{diffRouter: newDiffRouter()}
	fastTrackSettings(f, "false", "0")
	topo := f.actual().Topology
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	scope := InstallScope{Subnet: topo.Subnet, LANList: topo.LANList, LANs: topo.LANs, WAN: topo.WAN[0]}
	session := func() *Engine {
		e := NewEngine(f, scope, dir)
		e.observe = func(context.Context, Native, InstallScope) (Actual, error) { return f.actual(), nil }
		return e
	}
	full := store.Policy{Mode: store.ModeFull}
	target := Target{Revision: 7, Policy: PolicyInput{Network: store.Default().Network, Default: directPolicy, Devices: []PolicyDevice{{Address: netip.MustParsePrefix("10.20.0.6/32"), MAC: "02:00:00:00:00:06", Policy: full}}}, Selection: runnerapi.Selection{Core: "26.10.31", Config: "config/" + strings.Repeat("a", 64) + ".json"}, Verify: func(context.Context) error { return nil }}
	if _, err := session().Reconcile(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	const client, runner = "10.20.0.7", "172.31.255.3"
	p := netip.MustParsePrefix(client + "/32")
	member := appendMembers(nil, srcList(full), []netip.Prefix{p})[0]
	f.insert(member.Menu, member.Comment, member.Props)
	mark := func(src, dst, k string) string {
		id := f.flow(ct4, src, dst, "443")
		f.row(id).Props["connection-mark"] = k
		return id
	}
	dns := func(src, dst, peer string) string {
		id := f.flow(ct4, src, dst, "53")
		r := f.row(id).Props
		r["reply-src-address"], r["reply-src-port"] = peer, "53"
		if dst != peer {
			r["dstnat"] = "true"
		}
		return id
	}
	f.insert(firewallNAT, "owner", map[string]string{"chain": "dstnat", "action": "dst-nat", "dst-address": "203.0.113.44", "protocol": "tcp", "dst-port": "53", "to-addresses": runner, "to-ports": "53"})
	f.insert(firewallNAT, "owner-redirect", map[string]string{"chain": "dstnat", "action": "redirect", "dst-address": "203.0.113.45", "protocol": "tcp", "dst-port": "53", "to-ports": "53"})
	stale := []string{mark(client, "8.8.8.8", "tikray-open"), dns(client, "8.8.4.4", runner), dns(client, "9.9.9.9", "10.20.0.1")}
	keep := []string{mark(client, "1.1.1.1", "no-mark"), mark(client, "1.1.1.2", "owner"), dns(client, "8.8.8.8", "8.8.8.8"), dns(client, "203.0.113.45", "10.20.0.1"), dns(client, "203.0.113.44", runner), mark(client, "10.20.0.1", "tikray-open"), mark("10.20.0.6", "8.8.8.8", "tikray-open"), mark("10.20.0.19", "8.8.8.8", "tikray-open"), dns(client, "10.20.0.1", "10.20.0.1")}
	f.reads = nil
	report, e := session().Reconcile(t.Context(), target)
	if e != nil {
		t.Fatal(e)
	}
	for _, id := range stale {
		if f.row(id) != nil {
			t.Fatal("owned binding survived")
		}
	}
	for i, id := range keep {
		if f.row(id) == nil {
			t.Fatalf("removed unrelated witness %d", i)
		}
	}
	if report.Invalidated != len(stale) {
		t.Fatalf("removed %d bindings, want %d", report.Invalidated, len(stale))
	}
	for _, q := range f.reads {
		if q[0] == ct4+"/print" && !slices.Contains(q, "?src-address="+client) {
			t.Fatal("queried an unaffected client")
		}
	}
	start := len(f.writes)
	if _, e = session().Reconcile(t.Context(), target); e != nil || len(f.writes) != start {
		t.Fatal("repair did not reach a zero-write verified state", e)
	}
}

func TestStrayMemberCannotAuthorizeOffLANReads(t *testing.T) {
	f := &connectionRouter{diffRouter: newDiffRouter()}
	a := f.actual()
	p := netip.MustParsePrefix("0.0.0.0/0")
	full := store.Policy{Mode: store.ModeFull}
	stray := appendMembers(nil, srcList(full), []netip.Prefix{p})[0]
	id := f.insert(stray.Menu, stray.Comment, stray.Props)
	a.Rows = f.actual().Rows
	v := policyView{}
	before, ok := repairWindow(v, v, []Op{{Kind: "remove", Menu: stray.Menu, Comment: stray.Comment, id: id, target: stray}}, a, nil)
	if !ok {
		t.Fatal("missing in-LAN portion of wide stray member")
	}
	lan := a.Topology.LANs[0].Prefix
	for _, ch := range before.Repairs {
		if ch.Source.Bits() < lan.Bits() || !lan.Contains(ch.Source.Addr()) || ch.Source.Contains(a.Topology.RouterIPs[0]) {
			t.Fatal("unverified source authorized")
		}
	}
	if !validView(before) {
		t.Fatal("clipped repair cannot be replayed")
	}
	scope := InstallScope{LANs: a.Topology.LANs, LANList: a.Topology.LANList}
	bad := before
	bad.Repairs = slices.Clone(before.Repairs)
	bad.Repairs[0].Source = p
	if scope.containsView(bad) {
		t.Fatal("restored broad repair accepted")
	}
	if _, e := purgeFlows(t.Context(), f, a, []policyView{bad, v}); e == nil {
		t.Fatal("broad repair query accepted")
	}
	for _, q := range f.reads {
		if q[0] == ct4+"/print" {
			t.Fatal("untrusted connection scope reached transport")
		}
	}
}

func TestStrayRouterDNSProofSurvivesDetachment(t *testing.T) {
	for _, effective := range []bool{true, false} {
		f := &connectionRouter{diffRouter: newDiffRouter()}
		a := f.actual()
		src := netip.MustParsePrefix("10.20.0.7/32")
		policy := store.Policy{Mode: store.ModeFull}
		member := appendMembers(nil, srcList(policy), []netip.Prefix{src})[0]
		id := f.insert(member.Menu, member.Comment, member.Props)
		if !effective {
			f.insert(firewallNAT, "tikray:dns-full-open-tcp", map[string]string{"chain": "dstnat", "action": "dst-nat"})
		}
		f.insert(firewallNAT, "tikray:dns-router-full-open-tcp", map[string]string{"chain": "dstnat", "action": "redirect", "protocol": "tcp", "dst-port": "53", "src-address-list": srcList(policy), "in-interface-list": a.Topology.LANList, "to-ports": "53"})
		direct := policyView{}
		before, ok := repairWindow(direct, direct, []Op{{Menu: member.Menu, Comment: member.Comment, id: id, Kind: "remove", target: member}}, f.actual(), nil)
		if !ok || !validView(before) {
			t.Fatal("missing stray-source repair receipt")
		}
		receipt, err := json.Marshal(before)
		if err != nil {
			t.Fatal(err)
		}
		var recovered policyView
		if err = json.Unmarshal(receipt, &recovered); err != nil || !validView(recovered) {
			t.Fatal("receipt failed recovery")
		}
		f.rows = nil // the old classifier and redirect disappeared before restart
		f.insert(firewallNAT, "owner", map[string]string{"chain": "dstnat", "action": "redirect", "dst-address": "1.1.1.1", "protocol": "tcp"})
		var ids []string
		for _, client := range []struct{ dst, proto string }{{"9.9.9.9", "tcp"}, {"9.9.9.9", "udp"}, {"1.1.1.1", "tcp"}, {"10.20.0.1", "tcp"}} {
			id := f.flow(ct4, src.Addr().String(), client.dst, "53")
			r := f.row(id).Props
			r["protocol"], r["dstnat"], r["reply-src-address"], r["reply-src-port"] = client.proto, "true", "10.20.0.1", "53"
			ids = append(ids, id)
		}
		if _, err = purgeAfterSwitch(t.Context(), f, f.actual(), []policyView{direct, recovered, direct}); err != nil {
			t.Fatal(err)
		}
		for i, id := range ids {
			if (f.row(id) == nil) != (effective && i == 0) {
				t.Fatalf("incorrect recovered DNS verdict for witness %d", i)
			}
		}
	}
}

func TestInitialRepairPurgeKeepsVerifiedRunnerDNS(t *testing.T) {
	for _, tc := range []struct {
		name   string
		closed bool
		watch  string
		admit  bool
		want   int
	}{{"closed", true, "", false, 3}, {"open live", false, "up", false, 3}, {"open down", false, "down", false, 4}, {"overlapping admission", true, "", true, 4}} {
		t.Run(tc.name, func(t *testing.T) {
			f := &connectionRouter{diffRouter: newDiffRouter()}
			a := f.actual()
			p := netip.MustParsePrefix("10.20.0.7/32")
			policy := store.Policy{Mode: store.ModeFull, KillSwitch: tc.closed}
			v := policyView{LANList: a.Topology.LANList, Sources: []sourceClass{{p, policy}}, RouterIPs: a.Topology.RouterIPs}
			filter := object(firewallNAT, "dns-full-"+policyClass(policy)+"-tcp", map[string]string{"chain": "dstnat", "action": "dst-nat"})
			before, ok := repairWindow(v, v, []Op{{Menu: filter.Menu, Comment: filter.Comment, Kind: "add", target: filter}}, a, nil)
			if !ok {
				t.Fatal("missing repair baseline")
			}
			if tc.watch != "" {
				f.insert(watchMenu, "tikray:runner-watch", map[string]string{"host": "172.31.255.3", "type": "simple", "status": tc.watch})
			}
			var ids []string
			for _, kind := range []string{"healthy", "direct", "fasttrack", "foreign mark"} {
				id := f.flow(ct4, p.Addr().String(), "8.8.8.8", "53")
				row := f.row(id).Props
				row["reply-src-address"], row["reply-src-port"], row["dstnat"] = "172.31.255.3", "53", "true"
				if kind == "direct" {
					row["reply-src-address"] = "8.8.8.8"
					row["dstnat"] = "false"
				}
				if kind == "fasttrack" {
					row["fasttrack"] = "true"
				}
				if kind == "foreign mark" {
					row["connection-mark"] = "owner"
				}
				ids = append(ids, id)
			}
			views := []policyView{v, before, v}
			if tc.admit {
				views = append([]policyView{{}}, views...)
			}
			n, e := purgeFlows(t.Context(), f, f.actual(), views)
			if e != nil || n != tc.want {
				t.Fatalf("removed %d bindings, want %d: %v", n, tc.want, e)
			}
			if (f.row(ids[0]) != nil) != (tc.want == 3) {
				t.Fatal("healthy binding verdict wrong")
			}
		})
	}
}

func TestRepairRecognizesActiveOpenRouterDNS(t *testing.T) {
	for _, validRedirect := range []bool{true, false} {
		f := &connectionRouter{diffRouter: newDiffRouter()}
		a := f.actual()
		policy := store.Policy{Mode: store.ModeFull}
		p := netip.MustParsePrefix("10.20.0.7/32")
		target := policyView{LANList: a.Topology.LANList, Sources: []sourceClass{{p, policy}}, RouterIPs: a.Topology.RouterIPs}
		missing := Op{Kind: "add", Menu: firewallNAT, Comment: "tikray:dns-full-open-tcp"}
		before, ok := repairWindow(target, target, []Op{missing}, a, nil)
		if !ok {
			t.Fatal("missing primary was not recorded")
		}
		f.insert(watchMenu, "tikray:runner-watch", map[string]string{"host": "172.31.255.3", "type": "simple", "status": "down"})
		props := map[string]string{"chain": "dstnat", "action": "redirect", "in-interface-list": a.Topology.LANList, "src-address-list": srcList(policy), "protocol": "tcp", "dst-port": "53", "to-ports": "53"}
		if !validRedirect {
			props["disabled"] = "true"
		}
		f.insert(firewallNAT, "tikray:dns-router-full-open-tcp", props)
		id := f.flow(ct4, p.Addr().String(), "8.8.8.8", "53")
		r := f.row(id).Props
		r["dstnat"], r["reply-src-address"], r["reply-src-port"] = "true", "10.20.0.1", "53"
		_, err := purgeFlows(t.Context(), f, f.actual(), []policyView{target, before, target})
		if err != nil || (f.row(id) != nil) != validRedirect {
			t.Fatal("router fallback verdict disagrees with the enabled selector", err)
		}
	}
}
