package render

import (
	"net/netip"
	"slices"
)

// queryStrategy keeps xray's DNS to IPv4 answers while the IPv6 leak guard
// is on (spec §5.5).
const queryStrategy = "UseIPv4"

// dns returns xray's DNS (spec §5.4) and the rules for the queries it sends
// itself, which come right after the service rules. The domestic names are
// resolved by the domestic resolver, direct; every other name by the remote
// resolver, through proxy-open.
func (r *renderer) dns() (dnsConfig, []rule) {
	c := dnsConfig{Tag: TagDNS, QueryStrategy: queryStrategy}
	l := &ruleList{inbound: TagDNS}
	if len(r.domesticDomains) > 0 {
		resolver := r.domesticResolver()
		// In xray a server with domains also answers, as a fallback, for
		// every other name, which would send the non-domestic lookups
		// direct. skipFallback keeps it to its domains.
		c.Servers = append(c.Servers, dnsServer{
			Address:      resolver.String(),
			Domains:      slices.Clone(r.domesticDomains),
			SkipFallback: true,
		})
		l.add(toOutbound(TagDirect), matchIP([]string{host(resolver)}))
	}
	c.Servers = append(c.Servers, r.st.DNS.Remote)
	l.add(r.via(BalancerOpen))
	return c, l.rules
}

// domesticResolver is the resolver for the domestic names: the state's, or
// the router's bridge address when the state names none, so that the
// router's own upstream answers them.
func (r *renderer) domesticResolver() netip.Addr {
	if a := r.st.DNS.Domestic; a.IsValid() {
		return a
	}
	return r.st.Network.Router()
}
