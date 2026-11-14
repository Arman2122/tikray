package routeros

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

func compiledClosed(t *testing.T) []Object {
	t.Helper()
	in := PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeFull, KillSwitch: true}}
	rows, err := Desired(in, compilerTopology(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestEveryOperationPrefixIsSafe(t *testing.T) {
	objects := compiledClosed(t)
	f := newDiffRouter()
	deny := f.insert(firewallFilter, "owner:deny", map[string]string{"action": "drop", "chain": "forward"})
	allow := f.insert(firewallFilter, "owner:allow", map[string]string{"action": "accept", "chain": "forward"})
	f.afterWrite = func() {
		t.Helper()
		var current []Object
		for _, r := range f.rows {
			current = append(current, Object{Menu: r.Menu, Comment: r.Comment, Props: r.Props})
		}
		local := testPacket{ingress: "trusted", sourceList: "tikray-src-full-closed", destType: "local", connectionMark: "no-mark", state: "new", protocol: "tcp", port: "22"}
		if conn, route := preroute(t, current, local); conn != "no-mark" || route != "" {
			t.Fatal("router management marked during reconcile")
		}
		// A source can start matching an already attached hook immediately.
		for _, r := range f.rows {
			if !strings.HasPrefix(r.Props["list"], "tikray-src-") {
				continue
			}
			for _, tag := range []string{"tikray:egress-guard", "tikray:egress-drop-full", "tikray:ipv6:jump", "tikray:route-closed-fallback", "tikray:dns-full-closed-udp", "tikray:dns-full-closed-tcp"} {
				if f.tag(tag) == nil {
					t.Fatalf("exposed closed member before %s", tag)
				}
			}
		}
		if f.tag("tikray:route-closed") != nil && f.tag("tikray:table-closed") == nil {
			t.Fatal("routing mark without its table")
		}
		a, b := -1, -1
		for i, r := range f.rows {
			if r.ID == deny {
				a = i
			}
			if r.ID == allow {
				b = i
			}
		}
		if a < 0 || b <= a {
			t.Fatal("foreign rows changed")
		}
	}
	a := f.actual()
	ops, err := Plan(a, objects)
	if err != nil {
		t.Fatal(err)
	}
	if err = Execute(context.Background(), f, a, ops); err != nil {
		t.Fatal(err)
	}
	if again, err := Plan(f.actual(), objects); err != nil || len(again) != 0 {
		t.Fatalf("stable policy produced %d writes: %v", len(again), err)
	}
	a = f.actual()
	ops, err = Plan(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = Execute(context.Background(), f, a, ops); err != nil {
		t.Fatal(err)
	}
	if len(f.rows) != 2 {
		t.Fatal("teardown left owned policy or removed foreign rows")
	}
}

func TestRoutePollKeepsClosedGuard(t *testing.T) {
	target := compiledClosed(t)
	f := newDiffRouter()
	ops, err := Plan(f.actual(), target)
	if err != nil {
		t.Fatal(err)
	}
	if err = Execute(context.Background(), f, f.actual(), ops); err != nil {
		t.Fatal(err)
	}
	f.rows = slices.DeleteFunc(f.rows, func(row Observed) bool { return row.Menu == routeMenu && row.Props["routing-table"] == "tikray-closed" })
	// With both routes removed, evaluate the unmarked path of a public
	// packet using the main WAN default. The closed source still drops.
	drop := func() {
		t.Helper()
		chain := "forward"
		packet := map[string]string{"in-interface-list": "trusted", "out-interface": "ether1", "src-address-list": "tikray-src-full-closed", "connection-mark": "no-mark", "protocol": "tcp", "dst-port": "443"}
		for n := 0; n < 2; n++ {
			for _, r := range f.rows {
				if r.Menu != firewallFilter || r.Props["chain"] != chain {
					continue
				}
				match := true
				for k, want := range r.Props {
					switch k {
					case "action", "chain", "jump-target":
						continue
					}
					v, neg := strings.CutPrefix(want, "!")
					if (packet[k] == v) == neg {
						match = false
						break
					}
				}
				if !match {
					continue
				}
				switch r.Props["action"] {
				case "jump":
					chain = r.Props["jump-target"]
				case "drop":
					return
				default:
					t.Fatal("closed egress bypassed the firewall")
				}
				break
			}
		}
		t.Fatal("closed flow could reach WAN via main")
	}
	drop()
	f.afterWrite = drop
	ops, err = Plan(f.actual(), target)
	if err != nil || len(ops) != 2 {
		t.Fatal("route poll touched unaffected policy")
	}
	for _, op := range ops {
		if op.Menu != routeMenu || op.Kind != "add" {
			t.Fatal("route repair rewrote policy")
		}
	}
	if err = Execute(context.Background(), f, f.actual(), ops); err != nil {
		t.Fatal(err)
	}
}

func TestDiffWritesOnlyOwnedChanges(t *testing.T) {
	f := newDiffRouter()
	f.insert(firewallFilter, "tikray:install-bridge-isolation", map[string]string{"action": "drop", "chain": "forward"})
	f.insert("/system/script", "tikray:runner-watch", map[string]string{"name": "foreign"})
	row := object(firewallNAT, "dns-full-open-tcp", map[string]string{"chain": "dstnat", "action": "dst-nat", "src-address-list": "tikray-src-full-open", "dst-port": "53", "protocol": "tcp", "to-addresses": "172.31.255.3", "to-ports": "53"})
	row.InitialDisabled = true
	row.Before = "first:dstnat"
	f.insert(row.Menu, row.Comment, maps.Clone(row.Props))
	f.tag(row.Comment).Props["disabled"] = "true"
	member := object("/ip/firewall/address-list", "src-full-open:10.0.0.3/32", map[string]string{"list": "tikray-src-full-open", "address": "10.0.0.3/32"})
	f.insert(member.Menu, member.Comment, map[string]string{"list": "tikray-src-full-open", "address": "10.0.0.3"})
	want := []Object{row, member}
	ops, err := Plan(f.actual(), want)
	if err != nil || len(ops) != 0 {
		t.Fatalf("normalized target: %d ops %v", len(ops), err)
	}
	f.tag(row.Comment).Props["to-addresses"] = "172.31.255.4"
	ops, err = Plan(f.actual(), want)
	if err != nil || len(ops) != 1 || ops[0].Kind != "set" {
		t.Fatalf("single drift: %d ops %v", len(ops), err)
	}
	if err = Execute(context.Background(), f, f.actual(), ops); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 1 || slices.Contains(f.writes[0], "=disabled=no") {
		t.Fatal("netwatch-owned bit overwritten")
	}
}

func TestReconcileRecoversLostAck(t *testing.T) {
	f := newDiffRouter()
	o := object("/routing/table", "table-closed", map[string]string{"name": "tikray-closed", "fib": "yes"})
	a := f.actual()
	ops, err := Plan(a, []Object{o})
	if err != nil {
		t.Fatal(err)
	}
	f.lose = true
	if err = Execute(context.Background(), f, a, ops); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("lost ack: %v", err)
	}
	ops, err = Plan(f.actual(), []Object{o})
	if err != nil || len(ops) != 0 || len(f.writes) != 1 {
		t.Fatalf("uncertain add replayed: %v", err)
	}
}

func TestStopBeforeAndAfterEveryNativeWrite(t *testing.T) {
	objects := compiledClosed(t)
	empty := newDiffRouter()
	empty.insert(firewallFilter, "owner:allow", map[string]string{"chain": "forward", "action": "accept"})
	empty.insert(firewallFilter, "owner:deny", map[string]string{"chain": "forward", "action": "drop"})
	installed := newDiffRouter()
	installed.serial = empty.serial
	installed.rows = empty.actual().Rows
	ops, err := Plan(installed.actual(), objects)
	if err != nil {
		t.Fatal(err)
	}
	if err = Execute(context.Background(), installed, installed.actual(), ops); err != nil {
		t.Fatal(err)
	}
	for _, td := range []bool{false, true} {
		seed, want := empty, objects
		if td {
			seed, want = installed, nil
		}
		ops, err := Plan(seed.actual(), want)
		if err != nil {
			t.Fatal(err)
		}
		for boundary := 1; boundary <= len(ops); boundary++ {
			for _, after := range []bool{false, true} {
				f := newDiffRouter()
				f.serial = seed.serial
				f.rows = seed.actual().Rows
				if after {
					f.cutAfter = boundary
				} else {
					f.cutBefore = boundary
				}
				a := f.actual()
				if err = Execute(context.Background(), f, a, ops); err == nil {
					t.Fatal("fault was ignored")
				}
				writes := len(f.writes)
				if err = Execute(context.Background(), f, a, ops); !errors.Is(err, ErrStaleGeneration) || len(f.writes) != writes {
					t.Fatal("reused a stale plan after disconnect")
				}
				retry, err := Plan(f.actual(), want)
				if err != nil {
					t.Fatal(err)
				}
				if err = Execute(context.Background(), f, f.actual(), retry); err != nil {
					t.Fatalf("failed recovery at boundary %d: %v", boundary, err)
				}
				if final, err := Plan(f.actual(), want); err != nil || len(final) != 0 || len(f.writes) != len(ops) {
					t.Fatalf("nonminimal recovery at boundary %d", boundary)
				}
				if f.tag("owner:allow") == nil || f.tag("owner:allow").ID != "*1" || f.tag("owner:deny") == nil || f.tag("owner:deny").ID != "*2" {
					t.Fatal("owner identity changed during recovery")
				}
			}
		}
	}
}

func TestMovedSiblingAndChangedFastTrackRefused(t *testing.T) {
	// The selected sibling survives with the same tag and ID, but an
	// owner deny was moved ahead of it since planning.
	f := newDiffRouter()
	primary := object(firewallNAT, "dns-smart-open-tcp", map[string]string{"chain": "dstnat", "action": "dst-nat"})
	fallback := object(firewallNAT, "dns-router-smart-open-tcp", map[string]string{"chain": "dstnat", "action": "redirect"})
	primary.Before, fallback.Before = fallback.Comment, "first:dstnat"
	f.insert(fallback.Menu, fallback.Comment, maps.Clone(fallback.Props))
	f.insert(firewallNAT, "owner:deny", map[string]string{"chain": "dstnat", "action": "accept"})
	a := f.actual()
	ops, err := Plan(a, []Object{primary, fallback})
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(f.rows)
	if err = Execute(context.Background(), f, a, ops); err == nil || len(f.writes) > 0 {
		t.Fatal("used a moved anchor")
	}

	f = newDiffRouter()
	ft := f.insert(firewallFilter, "owner:ft", map[string]string{"chain": "forward", "action": "fasttrack-connection", "connection-state": "established"})
	after := f.insert(firewallFilter, "owner:ok", map[string]string{"chain": "forward", "action": "accept", "connection-state": "established"})
	a = f.actual()
	a.Topology.FastTrack = []FastTrackRule{{ID: ft, Match: map[string]string{"connection-state": "established"}, Next: &ForwardRule{ID: after, Action: "accept", Match: map[string]string{"connection-state": "established"}}}}
	ex, err := fastTrackException(a.Topology.FastTrack)
	if err != nil {
		t.Fatal(err)
	}
	ex.DependsOn = nil
	ops, err = Plan(a, []Object{*ex})
	if err != nil {
		t.Fatal(err)
	}
	f.tag("owner:ok").Props["protocol"] = "udp"
	if err = Execute(context.Background(), f, a, ops); err == nil || len(f.writes) > 0 {
		t.Fatal("used a narrowed slow-path accept")
	}
}
func TestOwnerFastTrackIntroducedBeforeUnchangedDependenciesAttach(t *testing.T) {
	f := newDiffRouter()
	a := f.actual()
	jump := object(firewallMangle, "jump-pre", map[string]string{"chain": "prerouting", "action": "jump", "jump-target": preChain})
	ops, err := Plan(a, []Object{jump})
	if err != nil {
		t.Fatal(err)
	}
	f.insert(firewallFilter, "owner:ft", map[string]string{"chain": "forward", "action": "fasttrack-connection", "connection-state": "established"})
	f.insert(firewallFilter, "owner:accept", map[string]string{"chain": "forward", "action": "accept", "connection-state": "established"})
	if e := Execute(context.Background(), f, a, ops); e == nil || len(f.writes) > 0 {
		t.Fatal("activated steering after new owner FastTrack")
	}
}

func TestForeignRetagOrReference(t *testing.T) {
	for _, change := range []string{"retag", "replacement", "dynamic", "reference"} {
		t.Run(change, func(t *testing.T) {
			f := newDiffRouter()
			o := object("/routing/table", "table-open", map[string]string{"name": "tikray-open", "fib": "yes"})
			f.insert(o.Menu, o.Comment, maps.Clone(o.Props))
			a := f.actual()
			ops, err := Plan(a, nil)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "retag":
				f.rows[0].Comment = "owner:keep"
			case "replacement":
				f.rows[0].ID = "*F"
			case "dynamic":
				f.rows[0].Dynamic = true
			case "reference":
				f.insert("/routing/rule", "owner:keep", map[string]string{"table": "tikray-open"})
			}
			if err = Execute(context.Background(), f, a, ops); err == nil || len(f.writes) > 0 {
				t.Fatal("mutated after ownership or reference changed")
			}
		})
	}
}

func TestForeignConsumerAppearsMidRemoval(t *testing.T) {
	f := newDiffRouter()
	for _, addr := range []string{"10.0.0.2", "10.0.0.3"} {
		f.insert(addressListMenu, "tikray:local:"+addr+"/32", map[string]string{"list": "tikray-local", "address": addr})
	}
	f.afterWrite = func() {
		if len(f.writes) == 1 {
			f.insert(firewallFilter, "owner:keep", map[string]string{"chain": "forward", "action": "accept", "dst-address-list": "!tikray-local"})
		}
	}
	a := f.actual()
	ops, err := Plan(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = Execute(context.Background(), f, a, ops); err == nil || len(f.writes) != 1 {
		t.Fatal("removed a member after a new owner reference appeared")
	}
}

func TestRearmAfterInvalidReadback(t *testing.T) {
	f := newDiffRouter()
	row := object(firewallFilter, "egress-guard", map[string]string{"chain": "forward", "action": "jump", "jump-target": egressChain})
	f.insert(row.Menu, row.Comment, maps.Clone(row.Props))
	f.tag(row.Comment).Props["invalid"] = "true"
	if ops, err := Plan(f.actual(), []Object{row}); err == nil || len(ops) > 0 {
		t.Fatal("an invalid installed guard was verified")
	}
	delete(f.tag(row.Comment).Props, "invalid")
	if ops, err := Plan(f.actual(), []Object{row}); err != nil || len(ops) > 0 {
		t.Fatal("valid guard failed verification")
	}
}
func TestNativePresenceFlags(t *testing.T) {
	for _, o := range []Object{
		object(tableMenu, "table-closed", map[string]string{"name": "tikray-closed", "fib": "yes"}),
		object(routeMenu, "route-closed-fallback", map[string]string{"routing-table": "tikray-closed", "dst-address": "0.0.0.0/0", "blackhole": "yes"}),
	} {
		k := "fib"
		if o.Menu == routeMenu {
			k = "blackhole"
		}
		p := maps.Clone(o.Props)
		p[k] = ""
		r := Observed{Menu: o.Menu, Comment: o.Comment, ID: "*1", Props: p}
		if diff := changes(r, o); len(diff) > 0 {
			t.Fatal("empty, present native flag is enabled")
		}
		delete(p, k)
		if diff := changes(r, o); len(diff) != 1 {
			t.Fatal("absent native flag is disabled")
		}
	}
}

func TestPreroutingHookFollowsOwnerMarks(t *testing.T) {
	f := newDiffRouter()
	hook := object(firewallMangle, "jump-pre", map[string]string{"chain": "prerouting", "action": "jump", "jump-target": preChain, "in-interface-list": "trusted"})
	f.insert(hook.Menu, hook.Comment, maps.Clone(hook.Props))
	id := f.insert(hook.Menu, "owner:route", map[string]string{"chain": "prerouting", "action": "mark-routing", "new-routing-mark": "owner", "passthrough": "yes"})
	a := f.actual()
	a.Topology.ForeignRoutingMarks = []string{"owner"}
	ops, err := Plan(a, []Object{hook})
	if err != nil || len(ops) != 1 || ops[0].Kind != "move" {
		t.Fatal("prerouting hook precedes owner routing decisions")
	}
	if err = Execute(context.Background(), f, a, ops); err != nil {
		t.Fatal(err)
	}
	if f.rows[0].ID != id {
		t.Fatal("owner mark still follows the hook")
	}
}

func TestMangleFastTrackStatisticsCanAppearMidPlan(t *testing.T) {
	f := newDiffRouter()
	hook := object(firewallMangle, "jump-pre", map[string]string{"chain": "prerouting", "action": "jump", "jump-target": preChain})
	a := f.actual()
	ops, err := Plan(a, []Object{hook})
	if err != nil {
		t.Fatal(err)
	}
	f.insert(firewallMangle, "", map[string]string{"chain": "prerouting", "action": "passthrough"})
	f.rows[0].Dynamic = true
	if err = Execute(context.Background(), f, a, ops); err != nil {
		t.Fatal("statistics row prevented safe hook installation")
	}
}

func TestLinkedRepairMinimalAndFirstAnchor(t *testing.T) {
	f := newDiffRouter()
	var want []Object
	for _, key := range []string{"dns-full-open-tcp", "dns-router-full-open-tcp", "dns-full-closed-udp"} {
		proto := "tcp"
		if strings.HasSuffix(key, "udp") {
			proto = "udp"
		}
		action := "dst-nat"
		if strings.Contains(key, "-router-") {
			action = "redirect"
		}
		r := object(firewallNAT, key, map[string]string{"chain": "dstnat", "protocol": proto, "dst-port": "53", "action": action})
		r.Before = "first:dstnat"
		want = append(want, r)
	}
	orderRules(want)
	// One row is at the wrong end. Moving both surviving siblings would be redundant.
	for _, i := range []int{1, 2, 0} {
		f.insert(want[i].Menu, want[i].Comment, maps.Clone(want[i].Props))
	}
	id := f.insert(firewallNAT, "owner:rule", map[string]string{"chain": "dstnat", "action": "accept"})
	ops, err := Plan(f.actual(), want)
	if err != nil || len(ops) != 1 || ops[0].Kind != "move" || ops[0].Comment != want[0].Comment {
		t.Fatal("reordered unaffected DNS rules")
	}
	if err = Execute(context.Background(), f, f.actual(), ops); err != nil {
		t.Fatal(err)
	}
	f.rows = slices.Delete(f.rows, 2, 3)
	ops, err = Plan(f.actual(), want)
	if err != nil || len(ops) != 1 || ops[0].Kind != "add" {
		t.Fatal("tail repair disturbed siblings")
	}
	if err = Execute(context.Background(), f, f.actual(), ops); err != nil {
		t.Fatal(err)
	}
	if f.rows[2].Comment != want[2].Comment || f.rows[3].ID != id {
		t.Fatal("tail escaped leading DNS group")
	}

	// Dynamic FastTrack statistics precede effective forward rules and
	// cannot be used as move destinations.
	f = newDiffRouter()
	f.insert(firewallFilter, "", map[string]string{"chain": "forward", "action": "passthrough"})
	f.rows[0].Dynamic = true
	anchor := f.insert(firewallFilter, "owner:deny", map[string]string{"chain": "forward", "action": "drop"})
	guard := object(firewallFilter, "egress-guard", map[string]string{"chain": "forward", "action": "jump", "jump-target": egressChain})
	guard.Before = "first:forward"
	ops, err = Plan(f.actual(), []Object{guard})
	if err != nil {
		t.Fatal(err)
	}
	if err = Execute(context.Background(), f, f.actual(), ops); err != nil {
		t.Fatal(err)
	}
	if !f.rows[0].Dynamic || f.rows[1].Comment != guard.Comment || f.rows[2].ID != anchor {
		t.Fatal("selected the FastTrack dummy as insertion anchor")
	}
}

func TestObsoleteDNSRuleIsNotAnInsertionAnchor(t *testing.T) {
	f := newDiffRouter()
	old := object(firewallNAT, "dns-full-closed-udp", map[string]string{"action": "dst-nat", "chain": "dstnat"})
	a := object(firewallNAT, "dns-smart-open-tcp", map[string]string{"action": "dst-nat", "chain": "dstnat"})
	b := object(firewallNAT, "dns-router-smart-open-tcp", map[string]string{"action": "redirect", "chain": "dstnat"})
	a.Before, b.Before = b.Comment, "first:dstnat"
	f.insert(old.Menu, old.Comment, maps.Clone(old.Props))
	f.insert(a.Menu, a.Comment, maps.Clone(a.Props))
	f.insert(firewallNAT, "owner:keep", map[string]string{"action": "accept", "chain": "dstnat"})
	want := []Object{a, b}
	actual := f.actual()
	ops, err := Plan(actual, want)
	if err != nil || len(ops) != 2 {
		t.Fatal("obsolete sibling caused extra DNS movement")
	}
	if err = Execute(context.Background(), f, actual, ops); err != nil {
		t.Fatal(err)
	}
	if again, err := Plan(f.actual(), want); err != nil || len(again) > 0 {
		t.Fatal("stale insertion anchor reversed the desired DNS order")
	}
}

func TestDiffScopesAndScriptText(t *testing.T) {
	f := newDiffRouter()
	hook := holdObject(firewallFilter, map[string]string{"action": "drop", "chain": "forward", "in-interface-list": "trusted", "src-address": "10.1.0.1/32", "protocol": "udp", "dst-port": "53"})
	hook.Before = "first:forward"
	w := object(watchMenu, "runner-watch", map[string]string{"host": "172.31.255.3", "type": "simple", "interval": "5s", "timeout": "1s", "startup-delay": "0s", "up-script": ":put \"a b\"\n:put 2"})
	f.insert(w.Menu, w.Comment, maps.Clone(w.Props))
	f.tag(w.Comment).Props["interval"] = "00:00:05"
	f.tag(w.Comment).Props["startup-delay"] = "00:00:00"
	f.tag(w.Comment).Props["up-script"] = ":put \"a b\"\r\n:put 2"
	ops, err := PlanHolds(f.actual(), []Object{hook})
	if err != nil || len(ops) != 1 || ops[0].Comment != hook.Comment {
		t.Fatal("hold stage touched permanent policy")
	}
	if err = Execute(context.Background(), f, f.actual(), ops); err != nil {
		t.Fatal(err)
	}
	if ops, err = Plan(f.actual(), []Object{w}); err != nil || len(ops) != 0 {
		t.Fatal("normal pass removed holds or rewrote normalized fields")
	}
	f.tag(w.Comment).Props["up-script"] = ":put \"ab\"\n:put 2"
	if ops, err = Plan(f.actual(), []Object{w}); err != nil || len(ops) != 1 || ops[0].fields["up-script"] != w.Props["up-script"] {
		t.Fatal("script normalization masked changed command text")
	}
	if ops, err = PlanHolds(f.actual(), nil); err != nil || len(ops) != 1 || ops[0].Comment != hook.Comment {
		t.Fatal("hold cleanup touched permanent policy")
	}
}

func TestChangedHoldIdentityBlocksRemoval(t *testing.T) {
	f := newDiffRouter()
	hold := holdObject(firewallFilter, map[string]string{"chain": "forward", "action": "drop", "in-interface-list": "inside", "src-address": "10.0.0.1/32", "protocol": "udp", "dst-port": "53"})
	p := maps.Clone(hold.Props)
	p["src-address"] = "10.0.0.1"
	f.insert(hold.Menu, hold.Comment, p)
	if ops, err := PlanHolds(f.actual(), []Object{hold}); err != nil || len(ops) > 0 {
		t.Fatal("canonical hold was not recognized")
	}
	f.tag(hold.Comment).Props["src-address"] = "10.0.0.2"
	if ops, err := PlanHolds(f.actual(), nil); err == nil || len(ops) > 0 {
		t.Fatal("tag of a different immutable hold authorized removal")
	}
}
