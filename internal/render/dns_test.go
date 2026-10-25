package render

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

// dnsCase is an input and the DNS it renders.
type dnsCase struct {
	name string
	in   Input
	// dns is the whole dns section.
	dns string
	// rules are the rules for the queries xray's DNS sends itself.
	rules []string
	// dnsIn is the address dns-in forwards to.
	dnsIn string
}

// doh is the default remote resolver, as a dns server.
const doh = `"https://1.1.1.1/dns-query"`

// remoteRule sends the remote resolver's queries through proxy-open.
const remoteRule = `{"inboundTag":["dns-internal"],"balancerTag":"proxy-open"}`

// dnsSection is the dns section with servers, each a JSON value.
func dnsSection(servers ...string) string {
	return `{"tag":"dns-internal","queryStrategy":"UseIPv4","servers":[` + strings.Join(servers, ",") + `]}`
}

// domesticServer is the dns server that resolves domains at resolver.
func domesticServer(resolver string, domains ...string) string {
	b, err := json.Marshal(domains)
	if err != nil {
		panic(err)
	}
	return `{"address":"` + resolver + `","domains":` + string(b) + `,"skipFallback":true}`
}

// resolverRule sends the queries to resolver direct.
func resolverRule(resolver string) string {
	return `{"inboundTag":["dns-internal"],"ip":["` + resolver + `/32"],"outboundTag":"direct"}`
}

var dnsCases = []dnsCase{
	{
		// Domestic IPs alone are no domestic names to resolve.
		name:  "no domestic domains",
		in:    input(func(st *store.State) { st.Routing.Domestic.IPs = []string{"203.0.113.20/32"} }),
		dns:   dnsSection(doh),
		rules: []string{remoteRule},
		dnsIn: "1.1.1.1",
	},
	{
		name:  "domestic domains",
		in:    input(func(st *store.State) { st.Routing.Domestic = extras() }),
		dns:   dnsSection(domesticServer("172.31.255.1", "domain:domestic.test"), doh),
		rules: []string{resolverRule("172.31.255.1"), remoteRule},
		dnsIn: "1.1.1.1",
	},
	{
		name: "domestic resolver set",
		in: input(func(st *store.State) {
			st.Routing.Domestic = extras()
			st.DNS.Domestic = netip.MustParseAddr("203.0.113.54")
		}),
		dns:   dnsSection(domesticServer("203.0.113.54", "domain:domestic.test"), doh),
		rules: []string{resolverRule("203.0.113.54"), remoteRule},
	},
	{
		name: "plain remote resolver",
		in: input(func(st *store.State) {
			st.Routing.Domestic = extras()
			st.DNS.Remote = "203.0.113.53"
		}),
		dns:   dnsSection(domesticServer("172.31.255.1", "domain:domestic.test"), `"203.0.113.53"`),
		rules: []string{resolverRule("172.31.255.1"), remoteRule},
		dnsIn: "203.0.113.53",
	},
	{
		name:  "geo data",
		in:    withGeo(input(func(*store.State) {}), testGeo),
		dns:   dnsSection(domesticServer("172.31.255.1", "geosite:category-ir"), doh),
		rules: []string{resolverRule("172.31.255.1"), remoteRule},
	},
	{
		name:  "geo data and domestic extras",
		in:    withGeo(input(func(st *store.State) { st.Routing.Domestic = extras() }), testGeo),
		dns:   dnsSection(domesticServer("172.31.255.1", "geosite:category-ir", "domain:domestic.test"), doh),
		rules: []string{resolverRule("172.31.255.1"), remoteRule},
	},
	{
		name: "another subnet",
		in: input(func(st *store.State) {
			st.Routing.Domestic = extras()
			st.Network.Subnet = netip.MustParsePrefix("10.9.8.0/29")
		}),
		dns:   dnsSection(domesticServer("10.9.8.1", "domain:domestic.test"), doh),
		rules: []string{resolverRule("10.9.8.1"), remoteRule},
	},
	{
		// Without a balancer, the remote resolver's queries take proxy-open's
		// fallback.
		name: "no servers",
		in: input(func(st *store.State) {
			st.Servers = []store.Server{}
			st.Routing.Domestic = extras()
		}),
		dns:   dnsSection(domesticServer("172.31.255.1", "domain:domestic.test"), doh),
		rules: []string{resolverRule("172.31.255.1"), `{"inboundTag":["dns-internal"],"outboundTag":"direct"}`},
	},
}

func TestDNS(t *testing.T) {
	for _, tc := range dnsCases {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := mustRenderInput(t, tc.in)
			jsonEqual(t, "dns", out.DNS, tc.dns)
			dnsRules, _ := splitRules(t, out.Routing.Rules)
			wantRules(t, "DNS rules", dnsRules, tc.rules)
			if tc.dnsIn == "" {
				return
			}
			var dnsIn struct {
				Tag      string `json:"tag"`
				Settings struct {
					Address string `json:"address"`
				} `json:"settings"`
			}
			if err := json.Unmarshal(out.Inbounds[1], &dnsIn); err != nil || dnsIn.Tag != TagDNSIn {
				t.Fatalf("inbound 1 is %s, want dns-in", out.Inbounds[1])
			}
			if dnsIn.Settings.Address != tc.dnsIn {
				t.Fatalf("dns-in forwards to %q, want %q", dnsIn.Settings.Address, tc.dnsIn)
			}
		})
	}
}
