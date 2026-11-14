package routeros

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/store"
)

// The journal stores just resolved policy selectors. It never contains the
// RouterOS password, server state, raw router replies or executable scripts.
type sourceClass struct {
	Prefix netip.Prefix
	Policy store.Policy
}
type policyView struct {
	// RepairOnly marks a synthetic baseline for verified policy that drifted.
	// It is never published as the verified outcome of a transition.
	RepairOnly      bool         `json:",omitempty"`
	Repairs         []flowChange `json:",omitempty"`
	Sources         []sourceClass
	Local, Domestic []netip.Prefix
	RouterIPs       []netip.Addr
	LANList         string
	V6              []Object
}
type flowChange struct {
	StraySource bool `json:",omitempty"`
	DataOnly    bool `json:",omitempty"`
	Source      netip.Prefix
	From, To    store.Policy
	DNSProtocol string `json:",omitempty"`
}

var directPolicy = store.Policy{Mode: store.ModeDirect}

func viewOf(rows []Object, t Topology) policyView {
	var v policyView
	for _, r := range rows {
		if r.Menu == ipv6Filter {
			v.V6 = append(v.V6, r)
			continue
		}
		if r.Menu != addressListMenu {
			continue
		}
		p := netip.MustParsePrefix(r.Props["address"])
		switch list := r.Props["list"]; list {
		case "tikray-local":
			v.Local = append(v.Local, p)
		case "tikray-domestic":
			v.Domestic = append(v.Domestic, p)
		default:
			for _, mode := range []store.Mode{store.ModeSmart, store.ModeFull} {
				for _, closed := range []bool{false, true} {
					pol := store.Policy{Mode: mode, KillSwitch: closed}
					if list == srcList(pol) {
						v.Sources = append(v.Sources, sourceClass{p, pol})
					}
				}
			}
		}
	}
	if len(v.Sources) > 0 {
		v.LANList = t.LANList
		v.RouterIPs = slices.Clone(t.RouterIPs)
		slices.SortFunc(v.RouterIPs, func(a, b netip.Addr) int { return a.Compare(b) })
	}
	slices.SortFunc(v.Sources, func(a, b sourceClass) int { return comparePrefix(a.Prefix, b.Prefix) })
	return v
}
func policyAt(v policyView, n uint64) store.Policy {
	if s, ok := sourceAt(v, n); ok {
		return s.Policy
	}
	return directPolicy
}
func sourceAt(v policyView, n uint64) (sourceClass, bool) {
	i, _ := slices.BinarySearchFunc(v.Sources, n, func(s sourceClass, n uint64) int {
		lo, hi := span(s.Prefix)
		if hi <= n {
			return -1
		}
		if lo > n {
			return 1
		}
		return 0
	})
	if i < len(v.Sources) {
		lo, hi := span(v.Sources[i].Prefix)
		if lo <= n && n < hi {
			return v.Sources[i], true
		}
	}
	return sourceClass{}, false
}

func flowChanges(old, next policyView) []flowChange {
	if next.RepairOnly {
		return nil
	}
	if old.RepairOnly {
		return old.Repairs
	}
	var cuts []uint64
	for _, v := range []policyView{old, next} {
		for _, s := range v.Sources {
			lo, hi := span(s.Prefix)
			cuts = append(cuts, lo, hi)
		}
	}
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)
	localChanged := !slices.Equal(old.Local, next.Local)
	domesticChanged := !slices.Equal(old.Domestic, next.Domestic)
	sameBypass := map[[2]store.Mode]bool{}
	var changes []flowChange
	for i := 1; i < len(cuts); i++ {
		a, b := policyAt(old, cuts[i-1]), policyAt(next, cuts[i-1])
		if a == b && (a.Mode == store.ModeDirect || (!localChanged && old.LANList == next.LANList && (a.Mode != store.ModeSmart || !domesticChanged))) {
			continue
		}
		if sameProxyClass(a, b) && old.LANList == next.LANList {
			modes := [2]store.Mode{a.Mode, b.Mode}
			equal, ok := sameBypass[modes]
			if !ok {
				equal = slices.Equal(prefixRanges(bypassDestinations(old, a.Mode)), prefixRanges(bypassDestinations(next, b.Mode)))
				sameBypass[modes] = equal
			}
			if equal {
				continue
			}
		}
		for _, p := range appendCIDRs(nil, addrRange{cuts[i-1], cuts[i]}) {
			changes = append(changes, flowChange{Source: p, From: a, To: b})
		}
	}
	return changes
}
func inPrefixes(ps []netip.Prefix, a netip.Addr) bool {
	return slices.ContainsFunc(ps, func(p netip.Prefix) bool { return p.Contains(a) })
}
func proxyDestination(v policyView, p store.Policy, dst netip.Addr) bool {
	return p.Mode != store.ModeDirect && !inPrefixes(v.Local, dst) && !(p.Mode == store.ModeSmart && inPrefixes(v.Domestic, dst))
}

// Both proxied modes share a connection mark, routing table and DNS strategy
// within each open or closed class. Only their destination bypasses differ.
func sameProxyClass(a, b store.Policy) bool {
	return a.Mode != store.ModeDirect && b.Mode != store.ModeDirect && a.KillSwitch == b.KillSwitch
}
func affectsFlow(ch flowChange, old, next policyView, dst netip.Addr, dns bool) bool {
	if ch.DNSProtocol != "" {
		return dns
	}
	if dns {
		steered := ch.From.Mode != store.ModeDirect || ch.To.Mode != store.ModeDirect
		return !ch.DataOnly && steered && (!sameProxyClass(ch.From, ch.To) || old.LANList != next.LANList)
	}
	if slices.Contains(old.RouterIPs, dst) || slices.Contains(next.RouterIPs, dst) {
		return false
	}
	a, b := proxyDestination(old, ch.From, dst), proxyDestination(next, ch.To, dst)
	return a != b || (a && b && (ch.From.KillSwitch != ch.To.KillSwitch || old.LANList != next.LANList))
}

func digest(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}
func holdObject(menu string, props map[string]string, deps ...string) Object {
	return object(menu, "hold:"+digest([]any{menu, props}), props, deps...)
}

func bypassDestinations(v policyView, mode store.Mode) []netip.Prefix {
	if mode == store.ModeSmart {
		return uniquePrefixes(slices.Concat(v.Local, v.Domestic))
	}
	return v.Local
}

// Keep the same negated-list guard shape as all other data holds. Only the
// destinations in exactly one bypass set need protection during this edge.
func unchangedBypass(old, next []netip.Prefix) ([]netip.Prefix, bool) {
	a, b := prefixRanges(old), prefixRanges(next)
	if slices.Equal(a, b) {
		return nil, false
	}
	cuts := []uint64{0, 1 << 32}
	for _, rs := range [][]addrRange{a, b} {
		for _, r := range rs {
			cuts = append(cuts, r.lo, r.hi)
		}
	}
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)
	var prefixes []netip.Prefix
	start := uint64(0)
	for i := 1; i < len(cuts); i++ {
		lo := cuts[i-1]
		if rangeContains(a, lo) != rangeContains(b, lo) {
			prefixes = appendCIDRs(prefixes, addrRange{start, lo})
			start = cuts[i]
		}
	}
	return appendCIDRs(prefixes, addrRange{start, 1 << 32}), true
}

type holdExclusions struct {
	list string
	deps []string
}

func stageExclusions(have map[string]Object, ps []netip.Prefix) holdExclusions {
	e := holdExclusions{list: "tikray-h" + digest(ps)}
	for _, p := range ps {
		r := holdObject(addressListMenu, map[string]string{"list": e.list, "address": p.String()})
		have[r.Comment] = r
		e.deps = append(e.deps, r.Comment)
	}
	return e
}

func stageDataHold(have map[string]Object, base map[string]string, exclusions holdExclusions) {
	props := maps.Clone(base)
	props["dst-address-type"] = "!local"
	props["dst-address-list"] = "!" + exclusions.list
	r := holdObject(firewallFilter, props, exclusions.deps...)
	r.Before = "first:forward"
	have[r.Comment] = r
}

// Each temporary drop has its own immutable destination exceptions. Editing
// the live domestic or local lists cannot open a hole in a staged guard.
func holdsFor(views []policyView) []Object {
	have := map[string]Object{}
	for i := 1; i < len(views); i++ {
		old, next := views[i-1], views[i]
		bypassLists := map[[2]store.Mode]holdExclusions{}
		sideLists := [2]map[store.Mode]holdExclusions{{}, {}}
		for _, ch := range flowChanges(old, next) {
			if ch.StraySource {
				continue
			}
			base := map[string]string{"chain": "forward", "src-address": ch.Source.String(), "in-interface-list": next.LANList, "action": "drop"}
			if sameProxyClass(ch.From, ch.To) && old.LANList == next.LANList && ch.DNSProtocol == "" {
				if ch.To.KillSwitch {
					modes := [2]store.Mode{ch.From.Mode, ch.To.Mode}
					exclusions, ok := bypassLists[modes]
					if !ok {
						ps, changed := unchangedBypass(bypassDestinations(old, ch.From.Mode), bypassDestinations(next, ch.To.Mode))
						if changed {
							exclusions = stageExclusions(have, ps)
						}
						bypassLists[modes] = exclusions
					}
					if exclusions.list != "" {
						stageDataHold(have, base, exclusions)
					}
				}
				continue
			}
			for index, side := range []struct {
				v policyView
				p store.Policy
			}{{old, ch.From}, {next, ch.To}} {
				if !side.p.KillSwitch {
					continue
				}
				base["in-interface-list"] = side.v.LANList
				if ch.DNSProtocol == "" {
					exclusions, ok := sideLists[index][side.p.Mode]
					if !ok {
						exclusions = stageExclusions(have, bypassDestinations(side.v, side.p.Mode))
						sideLists[index][side.p.Mode] = exclusions
					}
					stageDataHold(have, base, exclusions)
				}
				if ch.DataOnly {
					continue
				}
				for _, chain := range []string{"input", "forward"} {
					for _, proto := range []string{"tcp", "udp"} {
						if ch.DNSProtocol != "" && proto != ch.DNSProtocol {
							continue
						}
						props := maps.Clone(base)
						props["chain"] = chain
						props["protocol"] = proto
						props["dst-port"] = "53"
						rule := holdObject(firewallFilter, props)
						rule.Before = "first:" + chain
						have[rule.Comment] = rule
					}
				}
			}
		}
		if !reflect.DeepEqual(old.V6, next.V6) {
			for _, v := range []policyView{old, next} {
				stageIPv6(have, v)
			}
		}
	}
	var rows []Object
	for _, r := range have {
		rows = append(rows, r)
	}
	slices.SortFunc(rows, func(a, b Object) int { return strings.Compare(a.Comment, b.Comment) })
	return rows
}

func stageIPv6(have map[string]Object, v policyView) {
	if len(v.V6) == 0 {
		return
	}
	chain := "tikray-h" + digest(v.V6)
	tags := map[string]string{}
	for i := len(v.V6) - 1; i >= 0; i-- {
		old := v.V6[i]
		if old.Props["chain"] == "forward" {
			continue
		}
		props := maps.Clone(old.Props)
		props["chain"] = chain
		r := holdObject(ipv6Filter, props)
		r.Before = tags[old.Before]
		tags[old.Comment] = r.Comment
		have[r.Comment] = r
	}
	deps := make([]string, 0, len(tags))
	for _, tag := range tags {
		deps = append(deps, tag)
	}
	slices.Sort(deps)
	r := holdObject(ipv6Filter, map[string]string{"chain": "forward", "in-interface-list": v.LANList, "action": "jump", "jump-target": chain}, deps...)
	r.Before = "first:forward"
	have[r.Comment] = r
}
