package routeros

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/store"
)

const (
	ipv6Filter = "/ipv6/firewall/filter"
	ipv6Chain  = "tikray-ipv6"
)

var errIPv6Guard = errors.New("routeros: ambiguous IPv6 guard")

type guardIngress struct {
	prefixes  []netip.Prefix
	hosts     map[netip.Addr]PolicyDevice
	rejectAll bool
}

func ipv6Guard(in PolicyInput, obs Topology) ([]Object, error) {
	ingresses := make(map[string]*guardIngress)
	for _, lan := range obs.LANs {
		reject, ok := subnetGuard(in, lan.Prefix)
		if !ok || lan.Interface == "" || reject && !lan.Dedicated {
			return nil, errIPv6Guard
		}
		g := ingresses[lan.Interface]
		if g == nil {
			g = &guardIngress{rejectAll: reject, hosts: make(map[netip.Addr]PolicyDevice)}
			ingresses[lan.Interface] = g
		}
		// Multiple IPv4 networks can share an ingress. IPv6 has no selector
		// that can distinguish their IPv4 prefixes on the wire.
		if g.rejectAll != reject {
			return nil, errIPv6Guard
		}
		g.prefixes = append(g.prefixes, lan.Prefix)
	}
	for _, d := range in.Devices {
		if d.Address.Bits() != 32 {
			continue
		}
		for _, g := range ingresses {
			if g.contains(d.Address.Addr()) {
				g.hosts[d.Address.Addr()] = d
			}
		}
	}

	var rules []Object
	for name, g := range ingresses {
		entries, err := g.rules(name, obs.Leases)
		if err != nil {
			return nil, err
		}
		rules = append(rules, entries...)
	}
	if len(rules) == 0 {
		return nil, nil
	}
	if obs.LANList == "" {
		return nil, errIPv6Guard
	}

	// Return direct exceptions to the owner's forward chain before testing
	// the dedicated ingress. No rule can accept on behalf of the owner's ACL.
	slices.SortFunc(rules, func(a, b Object) int {
		if a.Props["action"] != b.Props["action"] {
			if a.Props["action"] == "return" {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Comment, b.Comment)
	})
	deps := make([]string, len(rules))
	for i := range rules {
		deps[i] = rules[i].Comment
		if i+1 < len(rules) {
			rules[i].Before = rules[i+1].Comment
		}
	}
	entry := object(ipv6Filter, "ipv6:jump", map[string]string{
		"chain": "forward", "in-interface-list": obs.LANList, "action": "jump", "jump-target": ipv6Chain,
	}, deps...)
	entry.Before = "first:forward"
	return append(rules, entry), nil
}

// Apart from /32 MAC exceptions, every address on a LAN must have the
// same IPv6 disposition. Count the union of the disjoint device subnets so
// that several prefixes covering a dedicated ingress work as one guard.
func subnetGuard(in PolicyInput, lan netip.Prefix) (reject, ok bool) {
	size := int64(1) << (32 - lan.Bits())
	var different int64
	for _, d := range in.Devices {
		if d.Address.Bits() == 32 || !d.Address.Overlaps(lan) ||
			(d.Policy.Mode == store.ModeDirect) == (in.Default.Mode == store.ModeDirect) {
			continue
		}
		different += int64(1) << (32 - max(d.Address.Bits(), lan.Bits()))
	}
	switch different {
	case 0:
		return in.Default.Mode != store.ModeDirect, true
	case size:
		return in.Default.Mode == store.ModeDirect, true
	default:
		return false, false
	}
}

func (g *guardIngress) contains(addr netip.Addr) bool {
	return slices.ContainsFunc(g.prefixes, func(prefix netip.Prefix) bool { return prefix.Contains(addr) })
}

func guardMAC(s string) (string, bool) {
	mac, err := net.ParseMAC(s)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || slices.Equal(mac, net.HardwareAddr{0, 0, 0, 0, 0, 0}) {
		return "", false
	}
	return strings.ToUpper(mac.String()), true
}

func (g *guardIngress) rules(iface string, leases []Lease) ([]Object, error) {
	needed := g.rejectAll
	for _, host := range g.hosts {
		needed = needed || host.Policy.Mode != store.ModeDirect
	}
	if !needed {
		return nil, nil
	}

	// Two IPv4 addresses with the same L2 identity cannot have opposite
	// IPv6 policies. Check even implicit direct clients and configured static
	// hosts that currently lack a DHCP lease.
	byMAC := make(map[string]bool)
	leaseMAC := make(map[netip.Addr]string)
	for _, lease := range leases {
		if lease.Interface != iface {
			continue
		}
		mac, valid := guardMAC(lease.MAC)
		if !valid || !lease.Address.Is4() || g.rejectAll && !g.contains(lease.Address) {
			return nil, errIPv6Guard
		}
		reject := g.rejectAll
		if host, ok := g.hosts[lease.Address]; ok {
			if other, ok := leaseMAC[lease.Address]; ok && other != mac {
				return nil, errIPv6Guard
			}
			leaseMAC[lease.Address] = mac
			reject = host.Policy.Mode != store.ModeDirect
		}
		if disposition, ok := byMAC[mac]; ok && disposition != reject {
			return nil, errIPv6Guard
		}
		byMAC[mac] = reject
	}

	// The /32 key stays stable across lease replacement. If a host owns
	// several addresses with the same disposition, emit its selector once.
	selectors := make(map[string]netip.Addr)
	for addr, host := range g.hosts {
		reject := host.Policy.Mode != store.ModeDirect
		mac := leaseMAC[addr]
		if host.MAC != "" {
			configured, ok := guardMAC(host.MAC)
			if !ok || mac != "" && mac != configured {
				return nil, errIPv6Guard
			}
			mac = configured
		}
		if mac == "" {
			if reject != g.rejectAll {
				return nil, errIPv6Guard
			}
			continue
		}
		if disposition, ok := byMAC[mac]; ok && disposition != reject {
			return nil, errIPv6Guard
		}
		byMAC[mac] = reject
		if reject != g.rejectAll {
			if prev, ok := selectors[mac]; !ok || addr.Less(prev) {
				selectors[mac] = addr
			}
		}
	}

	var rules []Object
	for mac, addr := range selectors {
		props := map[string]string{"chain": ipv6Chain, "in-interface": iface, "src-mac-address": mac, "action": "return"}
		if !g.rejectAll {
			props["action"] = "reject"
			props["reject-with"] = "icmp-admin-prohibited"
		}
		rules = append(rules, object(ipv6Filter, "ipv6:host:"+addr.String(), props))
	}
	if g.rejectAll {
		// Router-supplied names belong only in typed selectors, never in tags.
		id := sha256.Sum256([]byte(iface))
		rules = append(rules, object(ipv6Filter, "ipv6:ingress:"+hex.EncodeToString(id[:16]), map[string]string{
			"chain": ipv6Chain, "in-interface": iface, "action": "reject", "reject-with": "icmp-admin-prohibited",
		}))
	}
	return rules, nil
}
