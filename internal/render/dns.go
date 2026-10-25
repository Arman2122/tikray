package render

import "slices"

const (
	// queryStrategy keeps xray's DNS to IPv4 answers while the IPv6 leak
	// guard is on (spec §5.5).
	queryStrategy = "UseIPv4"
	// plainDNSPort is the port xray's DNS sends plain queries to when the
	// server names none (app/dns/nameserver_udp.go), as a port list.
	plainDNSPort = "53"
)

// dns returns xray's DNS (spec §5.4) and the rules for the queries it sends
// itself, which come right after the service rules. The domestic names are
// resolved by the domestic resolver, direct; every other name by the remote
// resolver, through proxy-open.
func (r *renderer) dns() (dnsConfig, []rule) {
	c := dnsConfig{Tag: TagDNS, QueryStrategy: queryStrategy}
	l := &ruleList{inbound: TagDNS}
	if len(r.domesticDomains) > 0 {
		// The router's own upstream answers the domestic names unless the
		// state names another resolver.
		resolver := r.st.DomesticResolver()
		// In xray a server with domains also answers, as a fallback, for
		// every other name, which would send the non-domestic lookups
		// direct. skipFallback keeps it to its domains.
		c.Servers = append(c.Servers, dnsServer{
			Address:      resolver.String(),
			Domains:      slices.Clone(r.domesticDomains),
			SkipFallback: true,
		})
		// Only plain DNS to the resolver, on port 53, goes direct. A remote
		// resolver on the same host, such as DoH on 443, still takes the
		// rule below; Validate refuses a remote resolver on port 53 of this
		// address, plain or DoH.
		l.add(toOutbound(TagDirect), matchIP([]string{host(resolver)}), matchPort(plainDNSPort))
	}
	c.Servers = append(c.Servers, r.st.DNS.Remote)
	l.add(r.via(BalancerOpen))
	return c, l.rules
}
