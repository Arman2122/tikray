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
func straySourceRepairs(old, next policyView, a Actual, observed map[string][]netip.Prefix, lists map[string]bool, pending []policyView) []flowChange {
	members := map[string][]netip.Prefix{}
	for _, mode := range []store.Mode{store.ModeFull, store.ModeSmart} {
		for _, closed := range []bool{false, true} {
			p := store.Policy{Mode: mode, KillSwitch: closed}
			list := srcList(p)
			if !lists[list] || len(observed[list]) == 0 {
				continue
			}
			members[""] = append(members[""], observed[list]...)
			if !closed {
				for _, proto := range []string{"tcp", "udp"} {
					if activeRouterFallback(a, p, proto) {
						members[proto] = append(members[proto], observed[list]...)
					}
				}
			}
		}
	}
	if len(members) == 0 {
		return nil
	}
	var excluded []netip.Prefix
	for _, v := range []policyView{old, next} {
		for _, s := range v.Sources {
			excluded = append(excluded, s.Prefix)
		}
	}
	prior := map[string][]netip.Prefix{}
	for _, v := range pending {
		for _, ch := range v.Repairs {
			if ch.StraySource {
				prior[ch.DNSProtocol] = append(prior[ch.DNSProtocol], ch.Source)
			}
		}
	}
	clients := clientRanges(a.Topology)
	var changes []flowChange
	for _, proto := range []string{"", "tcp", "udp"} {
		if len(members[proto]) == 0 {
			continue
		}
		stray, blocked := prefixRanges(members[proto]), prefixRanges(slices.Concat(excluded, prior[proto]))
		for _, p := range directStrays(clients, stray, blocked) {
			changes = append(changes, flowChange{StraySource: true, Source: p, From: directPolicy, To: directPolicy, DNSProtocol: proto})
		}
	}
	return changes
}

func directStrays(clients, stray, blocked []addrRange) []netip.Prefix {
	var cuts []uint64
	for _, rs := range [][]addrRange{stray, blocked, clients} {
		for _, r := range rs {
			cuts = append(cuts, r.lo, r.hi)
		}
	}
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)
	var prefixes []netip.Prefix
	for i := 1; i < len(cuts); i++ {
		lo := cuts[i-1]
		if !rangeContains(clients, lo) || !rangeContains(stray, lo) || rangeContains(blocked, lo) {
			continue
		}
		prefixes = appendCIDRs(prefixes, addrRange{lo, cuts[i]})
	}
	return prefixes
}

func exactRouterFallback(r Observed, lan string, p store.Policy, proto string) bool {
	want := object(firewallNAT, "dns-router-"+string(p.Mode)+"-open-"+proto, map[string]string{"chain": "dstnat", "action": "redirect", "src-address-list": srcList(p), "in-interface-list": lan, "protocol": proto, "dst-port": "53", "to-ports": "53"})
	return r.Menu == want.Menu && r.Comment == want.Comment && !r.Dynamic && !unavailableRow(Row(r.Props)) && len(changes(r, want)) == 0
}

// Prove the redirect could actually select this source before the member is
// detached. A stale comment or a running primary cannot supply this proof.
func activeRouterFallback(a Actual, p store.Policy, proto string) bool {
	primary := "tikray:dns-" + string(p.Mode) + "-open-" + proto
	for _, r := range a.Rows {
		if r.Menu != firewallNAT {
			continue
		}
		if r.Comment == primary && !onBit(r.Props["disabled"]) {
			return false
		}
		if exactRouterFallback(r, a.Topology.LANList, p, proto) {
			return true
		}
	}
	return false
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
		q := append([]string{"?chain=dstnat"}, valuesQuery("action", "redirect", "dst-nat", "netmap", "jump", "endpoint-independent-nat", "dst-nat-to-hotspot")...)
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

func (b repairBindings) lanRouter(src, reply netip.Addr) bool {
	return slices.Contains(b.topology.RouterIPs, reply) && slices.ContainsFunc(b.topology.LANs, func(l LAN) bool { return l.Prefix.Contains(src) && l.Prefix.Contains(reply) })
}

func (b repairBindings) strayBinding(ch flowChange, r Row, src, dst netip.Addr) bool {
	if slices.Contains(b.topology.RouterIPs, src) {
		return false
	}
	if ch.DNSProtocol != "" && (!isDNS(r) || r["protocol"] != ch.DNSProtocol) {
		return false
	}
	if !isDNS(r) {
		return !slices.Contains(b.topology.RouterIPs, dst) && (r["connection-mark"] == "tikray-open" || r["connection-mark"] == "tikray-closed")
	}
	reply, err := netip.ParseAddr(r["reply-src-address"])
	router := ch.DNSProtocol != ""
	if err != nil || !reply.Is4() || dst == reply || !onBit(r["dstnat"]) || r["reply-src-port"] != "53" {
		return false
	}
	if router && !b.lanRouter(src, reply) || !router && reply != b.runner {
		return false
	}
	for _, owner := range b.owners {
		if owner["action"] == "redirect" && !router {
			continue
		}
		if owner["action"] != "jump" && !addressHitsLAN(owner["to-addresses"], []LAN{{Prefix: netip.PrefixFrom(reply, 32)}}) {
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
	if !exactRouterFallback(b.fallback["tikray:dns-router-"+string(p.Mode)+"-open-"+proto], b.topology.LANList, p, proto) {
		return false
	}
	reply, err := netip.ParseAddr(r["reply-src-address"])
	return err == nil && b.lanRouter(src, reply)
}
