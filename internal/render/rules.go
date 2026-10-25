package render

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/store"
)

// sourceSets are the addresses of the explicit devices by policy, each
// sorted by address. Direct devices are in none: their traffic never
// reaches xray. Every address no device lists has the default policy.
type sourceSets struct {
	smartOpen, smartClosed, fullOpen, fullClosed []netip.Prefix
}

// newSourceSets sorts the devices into their source sets.
func newSourceSets(devices []store.Device) sourceSets {
	var s sourceSets
	for _, d := range devices {
		var set *[]netip.Prefix
		switch d.Policy.Mode {
		case store.ModeSmart:
			set = &s.smartOpen
			if d.Policy.KillSwitch {
				set = &s.smartClosed
			}
		case store.ModeFull:
			set = &s.fullOpen
			if d.Policy.KillSwitch {
				set = &s.fullClosed
			}
		default:
			continue
		}
		*set = append(*set, d.Address)
	}
	for _, set := range []*[]netip.Prefix{&s.smartOpen, &s.smartClosed, &s.fullOpen, &s.fullClosed} {
		sortPrefixes(*set)
	}
	return s
}

// sortPrefixes sorts ps by address. Device prefixes never overlap, so no two
// share an address.
func sortPrefixes(ps []netip.Prefix) {
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return cmp.Compare(a.Bits(), b.Bits())
	})
}

// union returns the prefixes of a and b, sorted by address.
func union(a, b []netip.Prefix) []netip.Prefix {
	u := slices.Concat(a, b)
	sortPrefixes(u)
	return u
}

// intersect returns the prefixes of a that are also in b, in a's order.
func intersect(a, b []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range a {
		if slices.Contains(b, p) {
			out = append(out, p)
		}
	}
	return out
}

// cond is one condition of a rule. It sets one of the rule's matchers and
// reports whether that matcher has an entry. A rule whose matcher has none
// must not be emitted at all: the empty list would be left out of the JSON,
// and xray reads a rule without it as matching every source, domain or
// address.
type cond func(*rule) bool

// matchSource matches the traffic from the prefixes ps.
func matchSource(ps []netip.Prefix) cond {
	return func(r *rule) bool {
		if len(ps) == 0 {
			return false
		}
		r.Source = make([]string, len(ps))
		for i, p := range ps {
			r.Source[i] = p.String()
		}
		return true
	}
}

// matchDomain matches the traffic to the domains the matchers ms name.
func matchDomain(ms []string) cond {
	return func(r *rule) bool {
		r.Domain = slices.Clone(ms)
		return len(ms) > 0
	}
}

// matchIP matches the traffic to the addresses the matchers ms name.
func matchIP(ms []string) cond {
	return func(r *rule) bool {
		r.IP = slices.Clone(ms)
		return len(ms) > 0
	}
}

// matchPort matches the traffic to the destination ports in ports, an xray
// port list such as "53".
func matchPort(ports string) cond {
	return func(r *rule) bool {
		r.Port = ports
		return ports != ""
	}
}

// matchAll matches all the traffic: the TUN inbound carries tcp and udp.
func matchAll(r *rule) bool {
	r.Network = "tcp,udp"
	return true
}

// everySource is no condition: the rule applies to every source.
func everySource(*rule) bool { return true }

// toOutbound is the target of a rule that sends its traffic to the outbound
// tag.
func toOutbound(tag string) rule { return rule{OutboundTag: tag} }

// ruleList collects the rules for the traffic from one inbound.
type ruleList struct {
	inbound string
	rules   []rule
}

// add appends a rule that sends the traffic from l's inbound that meets
// every cond to target: a via result, or toOutbound. When a cond's matcher
// has no entry the rule is left out, so that it never matches more than its
// conditions say.
func (l *ruleList) add(target rule, conds ...cond) {
	r := target
	r.InboundTag = []string{l.inbound}
	for _, c := range conds {
		if !c(&r) {
			return
		}
	}
	l.rules = append(l.rules, r)
}

// domestic returns the domestic matchers: the geo data's, when there is
// any, and then the state's own.
func domestic(d store.Domestic, geo *Geo) (domains, ips []string) {
	if geo != nil {
		domains = append(domains, geo.Site...)
		ips = append(ips, geo.IP...)
	}
	return append(domains, d.Domains...), append(ips, d.IPs...)
}

// trafficRules are the rules for the devices' traffic, which arrives on the
// TUN inbound, in the order of spec §5.3. A kill-switch source is never sent
// direct, nor to proxy-open, except by a domestic or a custom direct rule.
func (r *renderer) trafficRules() []rule {
	s := newSourceSets(r.st.Devices)
	def := r.st.DefaultPolicy
	l := &ruleList{inbound: TagTUN}

	// 1. The block list.
	l.add(toOutbound(TagBlock), matchDomain(r.st.Routing.BlockList))

	// 2. The full sources skip the domestic and custom rules.
	l.add(r.via(BalancerOpen), matchSource(s.fullOpen))
	l.add(r.via(BalancerClosed), matchSource(s.fullClosed))

	// While the unlisted are full they skip those rules too, which then
	// apply to the smart sources alone: scope limits a rule to them, and
	// within limits a rule's own sources to them.
	scope, within := cond(everySource), matchSource
	if def.Mode == store.ModeFull {
		smart := union(s.smartOpen, s.smartClosed)
		scope = matchSource(smart)
		within = func(own []netip.Prefix) cond { return matchSource(intersect(own, smart)) }
	}

	// 3, 4. Domestic traffic goes direct.
	l.add(toOutbound(TagDirect), scope, matchDomain(r.domesticDomains))
	l.add(toOutbound(TagDirect), scope, matchIP(r.domesticIPs))

	// 5. The custom rules, in state order. An xray rule matches only when
	// all its lists do, so a rule with domains and IPs becomes one xray rule
	// for each, domains first.
	for _, cr := range r.st.Routing.Rules {
		for _, m := range []cond{matchDomain(cr.Domains), matchIP(cr.IPs)} {
			switch cr.Action {
			case store.ActionDirect:
				l.add(toOutbound(TagDirect), scope, m)
			case store.ActionBlock:
				l.add(toOutbound(TagBlock), scope, m)
			case store.ActionServer:
				// While the server is disabled its outbound is not there:
				// the rule is skipped and its traffic falls through.
				if tag, ok := r.serverTag(cr.Server); ok {
					l.add(toOutbound(tag), scope, m)
				}
			case store.ActionProxy:
				// Each source keeps its own balancer: the first rule takes
				// the sources whose kill switch differs from the default's.
				if def.KillSwitch {
					l.add(r.via(BalancerOpen), within(s.smartOpen), m)
					l.add(r.via(BalancerClosed), scope, m)
				} else {
					l.add(r.via(BalancerClosed), within(s.smartClosed), m)
					l.add(r.via(BalancerOpen), scope, m)
				}
			}
		}
	}

	// 6. Everything else. Rule 2 has caught the full sources already; these
	// rules list them anyway, so that their meaning does not depend on it.
	open := union(s.smartOpen, s.fullOpen)
	closed := union(s.smartClosed, s.fullClosed)
	switch {
	case def.Mode == store.ModeDirect:
		l.add(r.via(BalancerClosed), matchSource(closed))
		l.add(r.via(BalancerOpen), matchSource(open))
		l.add(toOutbound(TagDirect), matchAll)
	case def.KillSwitch:
		l.add(r.via(BalancerOpen), matchSource(open))
		l.add(r.via(BalancerClosed), matchAll)
	default:
		l.add(r.via(BalancerClosed), matchSource(closed))
		l.add(r.via(BalancerOpen), matchAll)
	}
	return l.rules
}

// serverTag returns the outbound tag of the server id, and whether that
// outbound is rendered: whether the server is enabled.
func (r *renderer) serverTag(id string) (string, bool) {
	for _, s := range r.st.Servers {
		if s.ID == id {
			return s.Tag(), !s.Disabled
		}
	}
	return "", false
}

// checkGeo checks the geo matchers. With geo data, it returns an error
// naming the first entry of geo that is not a geosite: or geoip: matcher
// with a code (Geo.check). Without, it returns an error naming the first
// geosite: or geoip: matcher in st: xray loads them from geosite.dat and
// geoip.dat, and refuses the whole config without those files. A matcher in
// a rule that is not rendered, such as one naming a disabled server, counts
// too: enabling that server must not be what breaks the config.
func checkGeo(st store.State, geo *Geo) error {
	if geo != nil {
		return geo.check()
	}
	type matchers struct {
		path string
		list []string
	}
	lists := []matchers{
		{"routing.block_list", st.Routing.BlockList},
		{"routing.domestic.domains", st.Routing.Domestic.Domains},
		{"routing.domestic.ips", st.Routing.Domestic.IPs},
	}
	for i, cr := range st.Routing.Rules {
		lists = append(lists,
			matchers{fmt.Sprintf("routing.rules[%d].domains", i), cr.Domains},
			matchers{fmt.Sprintf("routing.rules[%d].ips", i), cr.IPs})
	}
	for _, l := range lists {
		for j, m := range l.list {
			for _, prefix := range []string{"geosite:", "geoip:"} {
				if strings.HasPrefix(m, prefix) {
					return fmt.Errorf("render: %s[%d]: a %s matcher needs geo data, and none is installed", l.path, j, prefix)
				}
			}
		}
	}
	return nil
}

// check returns an error naming the first entry of g's Site that is not
// geosite:<code>, or of its IP that is not geoip:<code>. The entries join
// the domestic matchers as they are, and an empty or prefix-less domain
// matcher matches every domain: the domestic rule would send all sniffed
// traffic direct, kill-switch traffic among it.
func (g *Geo) check() error {
	for _, l := range []struct {
		path, prefix string
		list         []string
	}{{"geo.site", "geosite:", g.Site}, {"geo.ip", "geoip:", g.IP}} {
		for i, m := range l.list {
			if code, ok := strings.CutPrefix(m, l.prefix); !ok || code == "" {
				return fmt.Errorf("render: %s[%d]: %q is not %s<code>", l.path, i, m, l.prefix)
			}
		}
	}
	return nil
}
