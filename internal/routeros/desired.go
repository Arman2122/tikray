package routeros

import (
	"cmp"
	"encoding/binary"
	"math/bits"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Arman2122/tikray/internal/store"
)

// Desired compiles a complete snapshot without consulting or changing the
// router. An error returns no objects, even when only the IPv6 guard failed.
func Desired(in PolicyInput, obs Topology, geo []netip.Prefix) ([]Object, error) {
	in, err := normalizePolicy(in)
	if err != nil {
		return nil, err
	}
	// An explicitly all-direct target can detach existing steering even
	// during a WAN outage. The executor still preflights owned removals.
	if in.Default.Mode == store.ModeDirect && !slices.ContainsFunc(in.Devices, func(d PolicyDevice) bool { return d.Policy.Mode != store.ModeDirect }) {
		return nil, nil
	}
	if err := checkTopology(in, obs); err != nil {
		return nil, err
	}
	for _, p := range geo {
		if !validPrefix(p) {
			return nil, errPolicy
		}
	}

	obs.LANs = slices.Clone(obs.LANs)
	slices.SortFunc(obs.LANs, func(a, b LAN) int { return comparePrefix(a.Prefix, b.Prefix) })
	sets, err := effectiveSources(in, obs)
	if err != nil {
		return nil, err
	}
	if len(sets) == 0 {
		return nil, nil
	}
	active := make(map[store.Policy]bool, len(sets))
	var objects []Object
	for _, mode := range []store.Mode{store.ModeSmart, store.ModeFull} {
		for _, closed := range []bool{false, true} {
			p := store.Policy{Mode: mode, KillSwitch: closed}
			if ps := sets[p]; len(ps) > 0 {
				active[p] = true
				objects = appendMembers(objects, srcList(p), ps)
			}
		}
	}

	objects = appendMembers(objects, "tikray-local", localDestinations(obs))
	objects = appendMembers(objects, "tikray-domestic", uniquePrefixes(slices.Concat(in.Domestic, geo)))

	guards, err := ipv6Guard(in, obs)
	if err != nil {
		return nil, err
	}
	rules, err := ipv4Policy(in, obs, active)
	if err != nil {
		return nil, err
	}
	objects = append(objects, guards...)
	objects = append(objects, rules...)
	orderRules(objects)
	return objects, nil
}

func localDestinations(obs Topology) []netip.Prefix {
	var local []netip.Prefix
	assignments := netip.MustParsePrefix("192.0.0.0/24")
	for _, p := range store.ReservedRouterPrefixes() {
		if p == assignments {
			// RFC 7723 and RFC 8155 allocate globally reachable anycast
			// addresses inside the otherwise reserved IETF block.
			lo, hi := span(p)
			local = appendCIDRs(local, addrRange{lo, lo + 9})
			local = appendCIDRs(local, addrRange{lo + 11, hi})
		} else {
			local = append(local, p)
		}
	}
	local = append(local, netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"), obs.Subnet)
	for _, lan := range obs.LANs {
		local = append(local, lan.Prefix)
	}
	local = append(local, obs.LocalLANs...)
	return uniquePrefixes(local)
}

// Preserve the position of an individual rule when only that row drifts.
// first:<chain> means before the first row outside the leading group. The
// group is the owned rows linked to that anchor, so rebuilding its tail
// puts it after surviving siblings and before the owner's original entries.
func orderRules(rows []Object) {
	type chainKey struct{ menu, chain string }
	next := make(map[chainKey]string)
	for i := len(rows) - 1; i >= 0; i-- {
		r := &rows[i]
		chain := r.Props["chain"]
		private := strings.HasPrefix(chain, "tikray-")
		leading := r.Before == "first:"+chain
		if !private && !leading {
			continue
		}
		k := chainKey{r.Menu, chain}
		if sibling := next[k]; sibling != "" {
			r.Before = sibling
		}
		next[k] = r.Comment
	}
}

func appendMembers(objects []Object, list string, prefixes []netip.Prefix) []Object {
	for _, p := range prefixes {
		member := p.String()
		objects = append(objects, object("/ip/firewall/address-list", strings.TrimPrefix(list, "tikray-")+":"+member, map[string]string{"list": list, "address": member}))
	}
	return objects
}

func validPrefix(p netip.Prefix) bool {
	return p.IsValid() && p.Addr().Is4() && p == p.Masked()
}
func comparePrefix(a, b netip.Prefix) int {
	if n := a.Addr().Compare(b.Addr()); n != 0 {
		return n
	}
	return cmp.Compare(a.Bits(), b.Bits())
}
func uniquePrefixes(ps []netip.Prefix) []netip.Prefix {
	ps = slices.Clone(ps)
	slices.SortFunc(ps, comparePrefix)
	return slices.Compact(ps)
}

// A leading ! negates several RouterOS matchers. Built-in interface lists
// can silently extend a LAN policy to WAN or newly added interfaces.
func interfaceName(s string) bool {
	if s == "" || len(s) > 255 || !utf8.ValidString(s) || s != strings.TrimSpace(s) {
		return false
	}
	return !strings.HasPrefix(s, "!") && !strings.Contains(s, ",") && !strings.ContainsFunc(s, store.ForbiddenInName)
}

func checkTopology(in PolicyInput, obs Topology) error {
	if len(obs.ForeignRefs) > 0 || obs.sourceNATConflict {
		return errConflict
	}
	if obs.Subnet != in.Network.Subnet || !interfaceName(obs.LANList) || len(obs.LANs) == 0 || len(obs.WAN) != 1 {
		return errTopology
	}
	switch strings.ToLower(obs.LANList) {
	case "all", "none", "dynamic", "static":
		return errTopology
	}
	w := obs.WAN[0]
	if !interfaceName(w.Interface) || installInterface(w.Interface) || w.Network.Overlaps(obs.Subnet) {
		return errTopology
	}
	if w.PointToPoint {
		// A bare interface gateway is valid only on a verified point-to-point
		// link. Reject names which could instead parse as an IP or next-hop
		// expression (gateway%interface or gateway@table).
		_, addrErr := netip.ParseAddr(w.Interface)
		if w.Gateway.IsValid() || (w.Network.IsValid() && !unicastNetwork(w.Network)) || addrErr == nil || strings.ContainsAny(w.Interface, "%@") {
			return errTopology
		}
	} else if !unicastNetwork(w.Network) || !usableHost(w.Network, w.Gateway) || slices.Contains(obs.RouterIPs, w.Gateway) {
		return errTopology
	}
	for _, a := range obs.RouterIPs {
		if !a.Is4() {
			return errTopology
		}
	}
	managed := make(map[string]bool)
	for i, lan := range obs.LANs {
		managed[lan.Interface] = true
		if !interfaceName(lan.Interface) || installInterface(lan.Interface) || lan.Interface == w.Interface {
			return errTopology
		}
		if !unicastNetwork(lan.Prefix) || lan.Prefix.Overlaps(obs.Subnet) || lan.Prefix.Overlaps(w.Network) {
			return errTopology
		}
		if !slices.ContainsFunc(obs.RouterIPs, func(a netip.Addr) bool { return usableHost(lan.Prefix, a) }) {
			return errTopology
		}
		for _, other := range obs.LANs[:i] {
			if lan.Prefix.Overlaps(other.Prefix) {
				return errTopology
			}
		}
	}
	// The name of a custom list alone cannot attest scope: a nested list
	// may add WAN or an unnumbered guest port to an otherwise valid LAN.
	seen := make(map[string]bool)
	for _, name := range obs.LANMembers {
		if !managed[name] {
			return errTopology
		}
		seen[name] = true
	}
	if len(seen) != len(managed) {
		return errTopology
	}
	for _, p := range obs.Connected {
		if !validPrefix(p) || p.Bits() == 0 || p.Overlaps(obs.Subnet) {
			return errTopology
		}
	}
	for _, p := range obs.LocalLANs {
		if !unicastNetwork(p) || p.Overlaps(obs.Subnet) || p.Overlaps(w.Network) {
			return errTopology
		}
	}
	return nil
}

func unicastNetwork(p netip.Prefix) bool {
	if !validPrefix(p) || p.Bits() == 0 {
		return false
	}
	for _, n := range []string{"0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4"} {
		if p.Overlaps(netip.MustParsePrefix(n)) {
			return false
		}
	}
	return true
}

func usableHost(p netip.Prefix, a netip.Addr) bool {
	if !a.Is4() || !p.Contains(a) {
		return false
	}
	if p.Bits() >= 31 {
		return true
	}
	lo, hi := span(p)
	ip := number(a)
	return ip != lo && ip != hi-1
}
func installInterface(name string) bool {
	switch name {
	case "tikray", "tikray-ctl", "tikray-runner":
		return true
	}
	return false
}
func number(a netip.Addr) uint64 { b := a.As4(); return uint64(binary.BigEndian.Uint32(b[:])) }
func span(p netip.Prefix) (uint64, uint64) {
	lo := number(p.Addr())
	return lo, lo + (uint64(1) << uint(32-p.Bits()))
}

type addrRange struct{ lo, hi uint64 } // half-open; hi may be 1<<32

// effectiveSources resolves IPv4 precedence before emitting list entries.
// Subtracting the explicit policies and router addresses from the LAN default
// keeps mangle, NAT and the WAN guard in agreement without expanding hosts.
func effectiveSources(in PolicyInput, obs Topology) (map[store.Policy][]netip.Prefix, error) {
	devices := make(map[netip.Prefix][]PolicyDevice)
	for _, d := range in.Devices {
		i := slices.IndexFunc(obs.LANs, func(l LAN) bool { return l.Prefix.Bits() <= d.Address.Bits() && l.Prefix.Contains(d.Address.Addr()) })
		if i < 0 {
			return nil, errTopology
		}
		p := obs.LANs[i].Prefix
		// A direct exception on a router, network or broadcast address has
		// no IPv4 client. Its MAC would open IPv6 for an unrelated device.
		if d.Address.Bits() == 32 {
			addr := d.Address.Addr()
			if !usableHost(p, addr) || slices.Contains(obs.RouterIPs, addr) {
				return nil, errPolicy
			}
		}
		devices[p] = append(devices[p], d)
	}
	var excluded []uint64
	for _, a := range obs.RouterIPs {
		excluded = append(excluded, number(a))
	}
	for _, lan := range obs.LANs {
		if lan.Prefix.Bits() < 31 {
			lo, hi := span(lan.Prefix)
			excluded = append(excluded, lo, hi-1)
		}
	}
	slices.Sort(excluded)
	excluded = slices.Compact(excluded)

	ranges := make(map[store.Policy][]addrRange)
	add := func(lo, hi uint64, p store.Policy) {
		if lo >= hi || p.Mode == store.ModeDirect {
			return
		}
		rs := ranges[p]
		if n := len(rs); n > 0 && rs[n-1].hi == lo {
			rs[n-1].hi = hi
		} else {
			rs = append(rs, addrRange{lo, hi})
		}
		ranges[p] = rs
	}
	emit := func(lo, hi uint64, p store.Policy) {
		if p.Mode == store.ModeDirect || lo >= hi {
			return
		}
		start, _ := slices.BinarySearch(excluded, lo)
		for _, ip := range excluded[start:] {
			if ip >= hi {
				break
			}
			add(lo, ip, p)
			lo = ip + 1
		}
		add(lo, hi, p)
	}
	for _, lan := range obs.LANs {
		cursor, end := span(lan.Prefix)
		for _, d := range devices[lan.Prefix] {
			begin, next := span(d.Address)
			emit(cursor, begin, in.Default)
			emit(begin, next, d.Policy)
			cursor = next
		}
		emit(cursor, end, in.Default)
	}
	sets := make(map[store.Policy][]netip.Prefix, len(ranges))
	for p, rs := range ranges {
		for _, r := range rs {
			sets[p] = appendCIDRs(sets[p], r)
		}
	}
	return sets, nil
}

// Cover the interval with the largest aligned CIDR that fits at each step.
func appendCIDRs(out []netip.Prefix, r addrRange) []netip.Prefix {
	for r.lo < r.hi {
		shift := min(bits.TrailingZeros32(uint32(r.lo)), bits.Len64(r.hi-r.lo)-1)
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], uint32(r.lo))
		out = append(out, netip.PrefixFrom(netip.AddrFrom4(raw), 32-shift))
		r.lo += uint64(1) << uint(shift)
	}
	return out
}
