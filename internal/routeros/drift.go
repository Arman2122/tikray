package routeros

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/store"
)

// repairWindow describes bindings that may have been created while an
// already verified rule was missing. A simultaneous settings change has its
// own journal edge, even if its compiler output repartitions the same list.
func repairWindow(verified, target policyView, ops []Op, a Actual, pending []policyView) (policyView, bool) {
	before := target
	before.RepairOnly = true
	if len(ops) == 0 {
		return before, false
	}
	roles := make(map[string]bool)
	lists := make(map[string]bool)
	relocated := make(map[string]bool)
	for _, op := range ops {
		if op.Menu == addressListMenu {
			lists[op.target.Props["list"]] = true
			// A set operation can move a member back from the wrong list.
			if op.Kind == "set" {
				relocated[op.id] = true
			}
		} else if op.Kind != "remove" {
			roles[strings.TrimPrefix(op.Comment, "tikray:")] = true
		}
	}
	for _, r := range a.Rows {
		if r.Menu == addressListMenu && relocated[r.ID] {
			lists[r.Props["list"]] = true
		}
	}
	observed := make(map[string][]netip.Prefix)
	for _, r := range a.Rows {
		list := r.Props["list"]
		if r.Menu != addressListMenu || (!lists[list] && !strings.HasPrefix(list, "tikray-src-")) || !ownedRole(r.Menu, r.Comment) || unavailableRow(Row(r.Props)) {
			continue
		}
		p, err := netip.ParsePrefix(r.Props["address"])
		if err != nil {
			ip, e := netip.ParseAddr(r.Props["address"])
			if e != nil || !ip.Is4() {
				continue
			}
			p = netip.PrefixFrom(ip, 32)
		}
		if validPrefix(p) {
			observed[list] = append(observed[list], p)
		}
	}
	localDrift, domesticDrift := false, false
	if roles["skip-local"] {
		before.Local, localDrift = repairBypass(verified.Local, target.Local, nil)
	} else if lists["tikray-local"] {
		before.Local, localDrift = repairBypass(verified.Local, target.Local, observed["tikray-local"])
	}
	if lists["tikray-domestic"] {
		before.Domestic, domesticDrift = repairBypass(verified.Domestic, target.Domestic, observed["tikray-domestic"])
	}

	var cuts []uint64
	addCut := func(p netip.Prefix) { lo, hi := span(p); cuts = append(cuts, lo, hi) }
	for _, v := range []policyView{verified, target} {
		for _, s := range v.Sources {
			addCut(s.Prefix)
		}
	}
	memberSets := make(map[string][]addrRange)
	for list, members := range observed {
		if strings.HasPrefix(list, "tikray-src-") {
			memberSets[list] = prefixRanges(members)
			for _, p := range members {
				addCut(p)
			}
		}
	}
	prior := make(map[netip.Prefix][]affectedClass)
	for i := 1; i < len(pending); i++ {
		old, next := &pending[i-1], &pending[i]
		for _, ch := range flowChanges(*old, *next) {
			addCut(ch.Source)
			prior[ch.Source] = append(prior[ch.Source], affectedClass{ch, old, next})
		}
	}
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)
	checkedBypass := make(map[bypassEdge]bool)
	for i := 1; i < len(cuts); i++ {
		lo := cuts[i-1]
		p := policyAt(target, lo)
		was := policyAt(verified, lo)
		sameClassEdit := was != p && sameProxyClass(was, p) && verified.LANList == target.LANList
		if p.Mode == store.ModeDirect || (was != p && !sameClassEdit) {
			continue
		}
		list := srcList(p)
		missing := lists[list] && !rangeContains(memberSets[list], lo)
		classifier := p
		if sameClassEdit {
			// Either membership keeps the common mark and DNS path active
			// until the new rules replace the previous set.
			previousMember := rangeContains(memberSets[srcList(was)], lo)
			missing = !previousMember && !rangeContains(memberSets[list], lo)
			if previousMember {
				classifier = was
			}
		}
		key := string(classifier.Mode) + "-" + policyClass(classifier)
		data := roles["jump-pre"] || roles["no-fasttrack"] || roles["conn-"+key] || roles["route-"+policyClass(p)] || roles["packet-"+policyClass(p)] ||
			p.KillSwitch && (roles["egress-guard"] || roles["egress-drop-marked"] || roles["egress-drop-"+string(classifier.Mode)])
		bypass := localDrift || p.Mode == store.ModeSmart && domesticDrift
		for _, prefix := range appendCIDRs(nil, addrRange{lo, cuts[i]}) {
			add := func(ch flowChange) {
				ch.Source, ch.To = prefix, p
				for bits := prefix.Bits(); bits >= 0; bits-- {
					for _, prev := range prior[netip.PrefixFrom(prefix.Addr(), bits).Masked()] {
						if coversRepair(prev, ch, before, target, checkedBypass) {
							return
						}
					}
				}
				before.Repairs = append(before.Repairs, ch)
			}
			if missing || data {
				add(flowChange{From: directPolicy, DataOnly: !missing})
			}
			// An edited or stale tagged member can also classify this source
			// under a second policy, even if its correct member still exists.
			for _, mode := range []store.Mode{store.ModeSmart, store.ModeFull} {
				for _, closed := range []bool{false, true} {
					other := store.Policy{Mode: mode, KillSwitch: closed}
					if other != p && other != was && rangeContains(memberSets[srcList(other)], lo) {
						add(flowChange{From: other})
					}
				}
			}
			if bypass {
				add(flowChange{From: p})
			}
			if missing {
				continue
			}
			for _, proto := range []string{"tcp", "udp"} {
				if roles["dns-"+key+"-"+proto] || roles["dns-router-"+key+"-"+proto] || roles["egress-dns-"+key+"-"+proto] || roles["skip-dns-"+proto] || roles["egress-guard"] {
					add(flowChange{From: p, DNSProtocol: proto})
				}
			}
		}
	}
	before.Repairs = append(before.Repairs, straySourceRepairs(verified, target, a, observed, lists, pending)...)
	var v6Drift bool
	before.V6, v6Drift = repairIPv6(verified, target, ops, a, pending)
	return before, len(before.Repairs) > 0 || v6Drift
}

// A retry need not append another baseline when an outstanding edge already
// covers the same bindings. A DNS repair never covers data on that source.
type bypassEdge struct {
	old, next *policyView
	mode      store.Mode
}

func coversRepair(d affectedClass, ch flowChange, before, target policyView, checked map[bypassEdge]bool) bool {
	prev := d.change
	if prev.To != ch.To {
		return false
	}
	if ch.DNSProtocol != "" {
		return prev.DNSProtocol == ch.DNSProtocol || !prev.DataOnly && prev.DNSProtocol == "" && (prev.From.Mode == store.ModeDirect || prev.From.KillSwitch != prev.To.KillSwitch)
	}
	if prev.DNSProtocol != "" || prev.From != ch.From || prev.DataOnly && !ch.DataOnly {
		return false
	}
	if !slices.Equal(d.next.Local, target.Local) || ch.To.Mode == store.ModeSmart && !slices.Equal(d.next.Domestic, target.Domestic) {
		return false
	}
	if ch.From.Mode == store.ModeDirect || slices.Equal(d.old.Local, before.Local) && (ch.From.Mode != store.ModeSmart || slices.Equal(d.old.Domestic, before.Domestic)) {
		return true
	}
	if ch.From != ch.To {
		return false
	}
	edge := bypassEdge{d.old, d.next, ch.To.Mode}
	if ok, exists := checked[edge]; exists {
		return ok
	}
	bypassed := func(v policyView) []netip.Prefix {
		if ch.To.Mode == store.ModeSmart {
			return slices.Concat(v.Local, v.Domestic)
		}
		return v.Local
	}
	// A partially repaired list has a smaller gap. On destinations where
	// the previous baseline already differed, its purge remains outstanding.
	_, uncovered := repairBypass(bypassed(*d.old), bypassed(target), bypassed(before))
	checked[edge] = !uncovered
	return !uncovered
}

// Collapse nested prefixes before searching by interval. Compiled and live
// bypass lists may each contain both a covering network and individual hosts.
func prefixRanges(ps []netip.Prefix) []addrRange {
	var ranges []addrRange
	for _, p := range uniquePrefixes(ps) {
		lo, hi := span(p)
		if n := len(ranges); n > 0 && lo <= ranges[n-1].hi {
			ranges[n-1].hi = max(ranges[n-1].hi, hi)
		} else {
			ranges = append(ranges, addrRange{lo, hi})
		}
	}
	return ranges
}

func rangeContains(rs []addrRange, n uint64) bool {
	i, _ := slices.BinarySearchFunc(rs, n, func(r addrRange, n uint64) int { return cmp.Compare(r.hi, n+1) })
	return i < len(rs) && rs[i].lo <= n
}

// Where the verified and proposed bypass agree, the observed list tells us
// which destinations may have taken the wrong route. A difference caused by
// the proposed settings is already handled by the normal transition.
func repairBypass(verified, target, actual []netip.Prefix) ([]netip.Prefix, bool) {
	v, t, a := prefixRanges(verified), prefixRanges(target), prefixRanges(actual)
	var cuts []uint64
	for _, set := range [][]addrRange{v, t, a} {
		for _, r := range set {
			cuts = append(cuts, r.lo, r.hi)
		}
	}
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)
	var prior []netip.Prefix
	changed := false
	for i := 1; i < len(cuts); i++ {
		lo := cuts[i-1]
		want := rangeContains(t, lo)
		old := want
		if rangeContains(v, lo) == want {
			old = rangeContains(a, lo)
		}
		changed = changed || old != want
		if old {
			prior = appendCIDRs(prior, addrRange{lo, cuts[i]})
		}
	}
	if !changed {
		return target, false
	}
	return prior, true
}

func repairIPv6(verified, target policyView, ops []Op, a Actual, pending []policyView) ([]Object, bool) {
	seen, want := ipv6Selectors(verified), ipv6Selectors(target)
	covered := tightenedSelectors(pending)
	exposed := make(map[v6Selector]bool)
	changedIDs := make(map[string]bool)
	selector := func(props map[string]string) v6Selector {
		return v6Selector{props["in-interface"], strings.ToUpper(props["src-mac-address"])}
	}
	permissive := func(props map[string]string) {
		if props["chain"] == ipv6Chain && !unavailableRow(Row(props)) && props["action"] != "reject" && props["action"] != "drop" {
			s := selector(props)
			// A negated or absent interface can expose several ingresses.
			// A negated MAC cannot identify an enumerable set of neighbors.
			if !interfaceName(s.iface) {
				s = v6Selector{}
			} else if _, ok := guardMAC(s.mac); !ok {
				s.mac = ""
			}
			exposed[s] = true
		}
	}
	for _, op := range ops {
		if op.Menu != ipv6Filter {
			continue
		}
		switch {
		case op.Comment == "tikray:ipv6:jump":
			exposed[v6Selector{}] = true
		case op.Kind == "remove":
			permissive(op.target.Props)
		default:
			if op.target.Props["action"] == "reject" {
				exposed[selector(op.target.Props)] = true
			}
			if op.Kind == "set" {
				changedIDs[op.id] = true
			}
		}
	}
	for _, r := range a.Rows {
		if r.Menu == ipv6Filter && changedIDs[r.ID] {
			permissive(r.Props)
		}
	}
	var rules []Object
	for _, r := range target.V6 {
		s := selector(r.Props)
		if r.Props["action"] == "reject" && (exposed[s] || exposed[v6Selector{iface: s.iface}] || exposed[v6Selector{}]) && seen.rejects(s) && !covered[s] {
			continue
		}
		rules = append(rules, r)
	}
	// A stray return for one MAC normally overrides a dedicated ingress.
	// Reconstruct that exception in the baseline so neighbor evidence is
	// requested for this MAC alone.
	remaining := ipv6Selectors(policyView{V6: rules})
	var exceptions []Object
	for s := range exposed {
		if s.mac == "" || !seen.rejects(s) || !want.rejects(s) || covered[s] || !remaining.rejects(s) {
			continue
		}
		if _, ok := guardMAC(s.mac); !ok || !interfaceName(s.iface) {
			continue
		}
		props := map[string]string{"chain": ipv6Chain, "action": "return", "in-interface": s.iface, "src-mac-address": s.mac}
		exceptions = append(exceptions, object(ipv6Filter, "ipv6:ingress:"+digest(props), props))
	}
	if len(exceptions) == 0 && len(rules) == len(target.V6) {
		return target.V6, false
	}
	slices.SortFunc(exceptions, func(a, b Object) int { return strings.Compare(a.Comment, b.Comment) })
	rules = slices.Concat(exceptions, rules)
	next := ""
	for i := len(rules) - 1; i >= 0; i-- {
		if rules[i].Props["chain"] == ipv6Chain {
			rules[i].Before = next
			next = rules[i].Comment
		}
	}
	if next == "" {
		return nil, true
	}
	return rules, true
}
