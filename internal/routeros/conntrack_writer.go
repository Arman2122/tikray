package routeros

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// A routing mark is per-packet and has no conntrack column. Only predicates
// proved on the original LAN tuple can identify an unchanged owner path.
type ruleMatch uint8

const (
	ruleUncertain ruleMatch = iota
	ruleDisjoint
	ruleMatches
)

func routingWriterMatch(t Topology, r Row, src, dst netip.Addr) ruleMatch {
	result := ruleDisjoint
	observed := map[string]bool{}
	for _, w := range t.RoutingMarkWriters {
		observed[w.Mark] = true
		match := ruleMatches
		if w.Opaque {
			match = ruleUncertain
		}
		for k, v := range w.Match {
			test := writerPredicate(t, r, src, dst, k, v)
			if test == ruleDisjoint {
				match = test
				break
			}
			if test == ruleUncertain {
				match = test
			}
		}
		if match == ruleMatches {
			return match
		}
		if match == ruleUncertain {
			result = match
		}
	}
	if slices.ContainsFunc(t.ForeignRoutingMarks, func(s string) bool { return !observed[s] }) {
		return ruleUncertain
	}
	return result
}

func writerPredicate(t Topology, r Row, src, dst netip.Addr, field, value string) ruleMatch {
	value, negated := strings.CutPrefix(value, "!")
	if value == "" {
		return ruleUncertain
	}
	var hit bool
	switch field {
	case "src-address", "dst-address":
		ip := src
		if field == "dst-address" {
			ip = dst
		}
		if p, e := netip.ParsePrefix(value); e == nil && p.Addr().Is4() {
			hit = p.Contains(ip)
		} else if a, e := netip.ParseAddr(value); e == nil && a.Is4() {
			hit = ip == a
		} else {
			return ruleUncertain
		}
	case "src-port", "dst-port":
		port, e := strconv.ParseUint(r[field], 10, 16)
		if e != nil {
			return ruleUncertain
		}
		for _, s := range strings.Split(value, ",") {
			lo, hi, ranged := strings.Cut(s, "-")
			if !ranged {
				hi = lo
			}
			a, e1 := strconv.ParseUint(lo, 10, 16)
			b, e2 := strconv.ParseUint(hi, 10, 16)
			if e1 != nil || e2 != nil || a > b {
				return ruleUncertain
			}
			hit = hit || port >= a && port <= b
		}
	case "protocol":
		// A RouterOS protocol number and its name can designate the same
		// protocol. Unknown aliases do not prove disjointness.
		protocol := func(p string) string {
			switch p {
			case "6":
				return "tcp"
			case "17":
				return "udp"
			case "1":
				return "icmp"
			default:
				return p
			}
		}
		a, b := protocol(value), protocol(r["protocol"])
		if a != b && (a != "tcp" && a != "udp" && a != "icmp" || b != "tcp" && b != "udp" && b != "icmp") {
			return ruleUncertain
		}
		hit = a == b
	case "connection-mark":
		mark := r[field]
		if mark == "" {
			mark = "no-mark"
		}
		hit = value == mark
	case "in-interface", "in-interface-list":
		var iface string
		for _, lan := range t.LANs {
			if lan.Prefix.Contains(src) {
				if iface != "" && iface != lan.Interface {
					return ruleUncertain
				}
				iface = lan.Interface
			}
		}
		if iface == "" {
			return ruleUncertain
		}
		if field == "in-interface" {
			hit = iface == value
		} else {
			if value != t.LANList {
				return ruleUncertain
			}
			hit = slices.Contains(t.LANMembers, iface)
		}
	default:
		return ruleUncertain
	}
	if hit != negated {
		return ruleMatches
	}
	return ruleDisjoint
}
