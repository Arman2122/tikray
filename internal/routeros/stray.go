package routeros

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/store"
)

// Reuse the compiler's client population: selected LANs, without the
// router's own addresses or network/broadcast addresses.
func clientRanges(t Topology) []addrRange {
	for _, lan := range t.LANs {
		if !unicastNetwork(lan.Prefix) {
			return nil
		}
	}
	for _, ip := range t.RouterIPs {
		if !ip.Is4() {
			return nil
		}
	}
	all := store.Policy{Mode: store.ModeFull}
	sets, err := effectiveSources(PolicyInput{Default: all}, t)
	if err != nil {
		return nil
	}
	return prefixRanges(sets[all])
}

func rangeCovers(rs []addrRange, p netip.Prefix) bool {
	lo, hi := span(p)
	i, _ := slices.BinarySearchFunc(rs, lo, func(r addrRange, n uint64) int {
		if r.hi <= n {
			return -1
		}
		if r.lo > n {
			return 1
		}
		return 0
	})
	return i < len(rs) && rs[i].lo <= lo && hi <= rs[i].hi
}

// A reserved member under an otherwise unchanged direct policy can leave
// marks or a runner translation. It cannot prove ownership of unmarked
// connections and must not create a temporary kill switch on this client.
func straySourceRepairs(old, next policyView, t Topology, observed map[string][]netip.Prefix, lists map[string]bool, pending []policyView) []flowChange {
	var members, excluded []netip.Prefix
	for list, ps := range observed {
		if lists[list] && strings.HasPrefix(list, "tikray-src-") {
			members = append(members, ps...)
		}
	}
	if len(members) == 0 {
		return nil
	}
	for _, v := range []policyView{old, next} {
		for _, s := range v.Sources {
			excluded = append(excluded, s.Prefix)
		}
	}
	for _, v := range pending {
		for _, ch := range v.Repairs {
			if ch.StraySource {
				excluded = append(excluded, ch.Source)
			}
		}
	}
	stray, blocked, clients := prefixRanges(members), prefixRanges(excluded), clientRanges(t)
	var cuts []uint64
	for _, rs := range [][]addrRange{stray, blocked, clients} {
		for _, r := range rs {
			cuts = append(cuts, r.lo, r.hi)
		}
	}
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)
	var changes []flowChange
	for i := 1; i < len(cuts); i++ {
		lo := cuts[i-1]
		if !rangeContains(clients, lo) || !rangeContains(stray, lo) || rangeContains(blocked, lo) {
			continue
		}
		for _, p := range appendCIDRs(nil, addrRange{lo, cuts[i]}) {
			changes = append(changes, flowChange{StraySource: true, Source: p, From: directPolicy, To: directPolicy})
		}
	}
	return changes
}

type repairBindings struct {
	topology Topology
	runner   netip.Addr
	owners   []Row
	watch    string
	fallback map[string]Observed
}

func readRepairBindings(o observation, a Actual, views []policyView) (repairBindings, error) {
	proof := repairBindings{topology: a.Topology}
	if validPrefix(a.Topology.Subnet) {
		proof.runner = (store.Network{Subnet: a.Topology.Subnet}).Runner()
	}
	needOwners, needWatch := false, false
	for _, v := range views {
		for _, r := range v.Repairs {
			needOwners = needOwners || r.StraySource
			needWatch = needWatch || !r.StraySource && !r.DataOnly && r.To.Mode != store.ModeDirect && !r.To.KillSwitch
		}
	}
	if needOwners {
		q := append([]string{"?chain=dstnat"}, valuesQuery("action", "dst-nat", "netmap", "jump", "endpoint-independent-nat", "dst-nat-to-hotspot")...)
		rows, err := o.read(firewallNAT, "comment,action,protocol,src-address,dst-address,src-port,dst-port,in-interface,in-interface-list,to-addresses,to-ports", q...)
		if err != nil {
			return proof, err
		}
		for _, r := range rows {
			if !ownedRole(firewallNAT, r["comment"]) {
				proof.owners = append(proof.owners, r)
			}
		}
	}
	if needWatch && proof.runner.IsValid() {
		rows, err := o.read(watchMenu, "status,disabled,invalid", "?comment=tikray:runner-watch", "?type=simple", "?host="+proof.runner.String())
		if err != nil {
			return proof, err
		}
		if len(rows) == 1 && !unavailableRow(rows[0]) {
			proof.watch = rows[0]["status"]
		}
		proof.fallback = map[string]Observed{}
		for _, r := range a.Rows {
			if r.Menu == firewallNAT && strings.HasPrefix(r.Comment, "tikray:dns-router-") && !r.Dynamic && !unavailableRow(Row(r.Props)) {
				proof.fallback[r.Comment] = r
			}
		}
	}
	return proof, nil
}

func (b repairBindings) strayBinding(r Row, src, dst netip.Addr) bool {
	if slices.Contains(b.topology.RouterIPs, src) {
		return false
	}
	if !isDNS(r) {
		return !slices.Contains(b.topology.RouterIPs, dst) && (r["connection-mark"] == "tikray-open" || r["connection-mark"] == "tikray-closed")
	}
	if !b.runner.IsValid() || dst == b.runner || !onBit(r["dstnat"]) || r["reply-src-port"] != "53" || r["reply-src-address"] != b.runner.String() {
		return false
	}
	for _, owner := range b.owners {
		if owner["action"] != "jump" && !addressHitsLAN(owner["to-addresses"], []LAN{{Prefix: netip.PrefixFrom(b.runner, 32)}}) {
			continue
		}
		possible := true
		for _, k := range []string{"protocol", "src-address", "dst-address", "src-port", "dst-port", "in-interface", "in-interface-list"} {
			if value := owner[k]; value != "" && writerPredicate(b.topology, r, src, dst, k, value) == ruleDisjoint {
				possible = false
				break
			}
		}
		if possible && (owner["to-ports"] == "" || writerPredicate(b.topology, r, src, dst, "dst-port", owner["to-ports"]) != ruleDisjoint) {
			return false
		}
	}
	return true
}

func (b repairBindings) healthyDNS(d affectedClass, r Row, src netip.Addr) bool {
	if !d.old.RepairOnly || !isDNS(r) || d.change.To.Mode == store.ModeDirect || !noConnMark(r) || onBit(r["fasttrack"]) || !onBit(r["dstnat"]) || r["reply-src-port"] != "53" {
		return false
	}
	if b.runner.IsValid() && r["reply-src-address"] == b.runner.String() {
		return d.change.To.KillSwitch || b.watch == "up"
	}
	if d.change.To.KillSwitch || b.watch != "down" {
		return false
	}
	proto := r["protocol"]
	p := d.change.To
	fallback := b.fallback["tikray:dns-router-"+string(p.Mode)+"-open-"+proto].Props
	if fallback["chain"] != "dstnat" || fallback["action"] != "redirect" || fallback["protocol"] != proto || fallback["dst-port"] != "53" || fallback["to-ports"] != "53" || fallback["src-address-list"] != srcList(p) || fallback["in-interface-list"] != b.topology.LANList {
		return false
	}
	reply, err := netip.ParseAddr(r["reply-src-address"])
	return err == nil && slices.Contains(b.topology.RouterIPs, reply) && slices.ContainsFunc(b.topology.LANs, func(l LAN) bool { return l.Prefix.Contains(src) && l.Prefix.Contains(reply) })
}
