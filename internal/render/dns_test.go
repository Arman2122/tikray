package render

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
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

// resolverRule sends the plain DNS queries to resolver, on port 53, direct.
func resolverRule(resolver string) string {
	return `{"inboundTag":["dns-internal"],"ip":["` + resolver + `/32"],"port":"53","outboundTag":"direct"}`
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
		// The remote resolver's DoH queries go to the same host on port 443,
		// which the resolver rule does not match: they take proxy-open.
		name: "domestic resolver on the DoH remote's host",
		in: input(func(st *store.State) {
			st.Routing.Domestic = extras()
			st.DNS.Domestic = netip.MustParseAddr("1.1.1.1")
		}),
		dns:   dnsSection(domesticServer("1.1.1.1", "domain:domestic.test"), doh),
		rules: []string{resolverRule("1.1.1.1"), remoteRule},
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

// remoteConn is the connection xray's DNS opens to the remote resolver
// remote: udp to port 53 of a plain address, or tcp to a DoH URL's host, on
// its port or 443. A DoH host that is a name has no address: xray routes the
// name, which no ip list matches.
func remoteConn(t *testing.T, remote string) conn {
	t.Helper()
	c := conn{inbound: TagDNS}
	if a, err := netip.ParseAddr(remote); err == nil {
		c.network, c.ip, c.port = "udp", a, 53
		return c
	}
	u, err := url.Parse(remote)
	if err != nil || u.Scheme != "https" {
		t.Fatalf("the remote resolver %q is neither an address nor a DoH URL", remote)
	}
	c.network, c.port = "tcp", 443
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			t.Fatalf("the remote resolver %q has a bad port", remote)
		}
		c.port = uint16(n)
	}
	if a, err := netip.ParseAddr(u.Hostname()); err == nil {
		c.ip = a
	}
	return c
}

// dnsRouteProblem walks rules with the queries xray's DNS sends itself for
// in, and says what is wrong, or "" when nothing is. The remote resolver's
// queries must reach the last DNS rule, which sends them through
// proxy-open. When there are domestic domains, the domestic resolver's
// queries (udp, port 53) must reach the first DNS rule, which sends them
// direct.
func dnsRouteProblem(t *testing.T, in Input, rules []json.RawMessage) string {
	t.Helper()
	const services = 5
	dnsRules, _ := splitRules(t, rules)
	describe := func(idx int, target string) string {
		if idx < 0 {
			return "no rule, to " + target
		}
		return fmt.Sprintf("rule %d %s, to %s", idx, rules[idx], target)
	}

	remote := services + len(dnsRules) - 1
	idx, target, err := route(rules, remoteConn(t, in.State.DNS.Remote))
	if err != nil {
		t.Fatal(err)
	}
	if idx != remote {
		return fmt.Sprintf("the remote resolver %s's queries take %s, not the last DNS rule", in.State.DNS.Remote, describe(idx, target))
	}
	if want := "balancerTag:" + BalancerOpen; ProxyAvailable(in.State) && target != want {
		return fmt.Sprintf("the remote resolver's queries go to %s, want %s", target, want)
	}

	if len(in.State.Routing.Domestic.Domains) == 0 && (in.Geo == nil || len(in.Geo.Site) == 0) {
		return ""
	}
	resolver := in.State.DomesticResolver()
	idx, target, err = route(rules, conn{inbound: TagDNS, network: "udp", ip: resolver, port: 53})
	if err != nil {
		t.Fatal(err)
	}
	if idx != services || target != "outboundTag:"+TagDirect {
		return fmt.Sprintf("the domestic resolver %s's queries take %s, want the first DNS rule, direct", resolver, describe(idx, target))
	}
	return ""
}

// TestDNSResolversRoute checks, over every case and every generated state,
// that the remote resolver's queries never take the domestic resolver's
// direct rule. Some generated states have a DoH remote on the domestic
// resolver's host.
func TestDNSResolversRoute(t *testing.T) {
	inputs := generated(t)
	for _, tc := range allCases() {
		inputs = append(inputs, tc.in)
	}
	for i, in := range inputs {
		out, _ := mustRenderInput(t, in)
		if problem := dnsRouteProblem(t, in, out.Routing.Rules); problem != "" {
			st, _ := json.Marshal(in.State.DNS)
			t.Errorf("input %d (dns %s): %s", i, st, problem)
		}
	}
}

// TestDNSWalkerCatchesLeaks checks dnsRouteProblem against a config broken
// on purpose: the domestic resolver rule without its port, as it was before
// R10, while the DoH remote is on the same host.
func TestDNSWalkerCatchesLeaks(t *testing.T) {
	var tc dnsCase
	for _, c := range dnsCases {
		if c.name == "domestic resolver on the DoH remote's host" {
			tc = c
		}
	}
	out, _ := mustRenderInput(t, tc.in)
	rules := out.Routing.Rules
	if problem := dnsRouteProblem(t, tc.in, rules); problem != "" {
		t.Fatalf("as rendered: %s", problem)
	}
	broken := slices.Clone(rules)
	broken[5] = json.RawMessage(`{"inboundTag":["dns-internal"],"ip":["1.1.1.1/32"],"outboundTag":"direct"}`)
	if problem := dnsRouteProblem(t, tc.in, broken); problem == "" {
		t.Fatal("a resolver rule without its port let the DoH queries out direct, and the walker saw nothing")
	}
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
