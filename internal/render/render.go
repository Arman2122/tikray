// Package render turns tikray's desired state into the xray-core config the
// runner runs: the inbounds, the outbounds of the enabled servers, the
// balancers that choose among them, the routing rules that carry out the
// devices' policies (spec §5.3), and xray's DNS (spec §5.4).
package render

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xrayver"
)

// Inbound tags.
const (
	// TagTUN is the TUN inbound, which receives the devices' traffic.
	TagTUN = "tun-in"
	// TagDNSIn receives the devices' DNS queries and hands them to xray's DNS.
	TagDNSIn = "dns-in"
	// TagSOCKS is the SOCKS inbound tikray probes and fetches through.
	TagSOCKS = "socks-in"
	// TagAPIIn carries connections to xray's gRPC API.
	TagAPIIn = "api-in"
)

// Outbound tags, and the tags of xray's API and DNS.
const (
	// TagBlock drops traffic. It is the first outbound, and so xray's
	// default: traffic that no rule catches is dropped.
	TagBlock = "block"
	// TagDirect sends traffic out without a proxy.
	TagDirect = "direct"
	// TagDNSOut answers DNS queries with xray's DNS.
	TagDNSOut = "dns-out"
	// TagAPI is the tag of xray's gRPC API.
	TagAPI = "api"
	// TagDNS is the tag of the queries xray's DNS makes itself.
	TagDNS = "dns-internal"
	// ServerPrefix starts the tag of every server's outbound: srv-<id>.
	ServerPrefix = "srv-"
)

// Balancer tags. Both choose among the same servers.
const (
	// BalancerOpen sends traffic direct while no server is up.
	BalancerOpen = "proxy-open"
	// BalancerClosed blocks traffic while no server is up.
	BalancerClosed = "proxy-closed"
)

// Ports the runner's inbounds listen on, on its bridge address.
const (
	SOCKSPort = 1080
	APIPort   = 10085
	DNSPort   = 53
)

const (
	// fallbackDNS is where dns-in forwards to when the remote resolver is
	// not a plain address. dns-out rejects every query that is not for an
	// address, so nothing is sent there; xray only needs the field.
	fallbackDNS = "1.1.1.1"
	// probeInterval is how often the observatory probes each server.
	probeInterval = "10s"
)

// balancers are the two balancers, in the order they are written, each with
// the outbound it falls back to while no server is up. While no server is
// even enabled the balancers are left out, and that outbound takes their
// place in every rule.
var balancers = []struct{ tag, fallback string }{
	{BalancerOpen, TagDirect},
	{BalancerClosed, TagBlock},
}

// Geo is the active geo slot.
type Geo struct {
	// Version names the geo data release.
	Version string
	// Site and IP are its domestic matchers, such as "geosite:category-ir"
	// and "geoip:ir". Render refuses an entry of Site that is not
	// geosite:<code>, or of IP that is not geoip:<code>.
	Site, IP []string
}

// Input is everything a config is rendered from.
type Input struct {
	State store.State
	// Core is the xray-core release the config is for.
	Core xrayver.Version
	// Geo is the geo data, or nil when there is none.
	Geo *Geo
}

// ProxyAvailable reports whether the balancers have a member: some server
// is enabled or, when one is pinned, the pinned server is enabled. Without
// one, proxied traffic goes direct or is blocked by its policy.
func ProxyAvailable(st store.State) bool {
	for _, s := range st.Servers {
		if !s.Disabled && (st.Routing.Pinned == "" || s.ID == st.Routing.Pinned) {
			return true
		}
	}
	return false
}

// Render returns the xray-core config for in, as two-space indented JSON
// with a trailing newline. The same input always gives the same bytes. It
// fails if in.Core is too old for the config (see Check), if in.State is not
// valid, if in.State uses a geosite: or geoip: matcher while in.Geo is nil,
// or if in.Geo holds an entry that is not a geosite: or geoip: matcher.
func Render(in Input) ([]byte, error) {
	c, err := build(in)
	if err != nil {
		return nil, err
	}
	return encode(c)
}

// build returns the config for in, before Render checks and encodes it.
func build(in Input) (*config, error) {
	if err := Check(in.Core); err != nil {
		return nil, err
	}
	if err := in.State.Validate(); err != nil {
		return nil, fmt.Errorf("render: invalid state: %w", err)
	}
	if err := checkGeo(in.State, in.Geo); err != nil {
		return nil, err
	}
	r := &renderer{st: in.State, proxy: ProxyAvailable(in.State)}
	r.domesticDomains, r.domesticIPs = domestic(in.State.Routing.Domestic, in.Geo)
	return r.config()
}

// encode returns c as Render's JSON, unless one of its rules has an empty
// matcher list (checkMatchers).
func encode(c *config) ([]byte, error) {
	if err := checkMatchers(c.Routing.Rules); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render: %w", err)
	}
	return append(b, '\n'), nil
}

// checkMatchers returns an internal error if a rule has a matcher list that
// is set but empty. The JSON would leave the list out, and xray reads a rule
// without it as matching everything: a rule meant for a few sources would
// take every source's traffic, kill-switch traffic sent direct among it.
// ruleList.add never makes such a rule; this check makes a mistake there
// fail the render instead of reaching xray.
func checkMatchers(rules []rule) error {
	for i, r := range rules {
		for _, m := range []struct {
			key  string
			list []string
		}{{"inboundTag", r.InboundTag}, {"source", r.Source}, {"domain", r.Domain}, {"ip", r.IP}} {
			if m.list != nil && len(m.list) == 0 {
				return fmt.Errorf("render: internal: routing.rules[%d] has an empty %s list", i, m.key)
			}
		}
	}
	return nil
}

// renderer builds one config.
type renderer struct {
	st store.State
	// proxy is whether the balancers have a member (ProxyAvailable).
	proxy bool
	// domesticDomains and domesticIPs are the domestic matchers, the geo
	// data's and then the state's (domestic).
	domesticDomains, domesticIPs []string
}

// via returns a rule that sends its traffic to the balancer, or, while the
// balancers have no member, to the outbound the balancer falls back to.
// Every reference to a balancer goes through via, so that none is ever left
// naming a balancer that is not there.
func (r *renderer) via(balancer string) rule {
	for _, b := range balancers {
		if b.tag != balancer {
			continue
		}
		if r.proxy {
			return rule{BalancerTag: b.tag}
		}
		return rule{OutboundTag: b.fallback}
	}
	panic("render: no balancer " + balancer)
}

func (r *renderer) config() (*config, error) {
	outbounds, err := r.outbounds()
	if err != nil {
		return nil, err
	}
	dns, dnsRules := r.dns()
	c := &config{
		Log: logConfig{LogLevel: "warning"},
		API: apiConfig{
			Tag:      TagAPI,
			Services: []string{"HandlerService", "RoutingService", "StatsService"},
		},
		Policy:    policyConfig{System: systemPolicy{StatsOutboundUplink: true, StatsOutboundDownlink: true}},
		DNS:       dns,
		Inbounds:  r.inbounds(),
		Outbounds: outbounds,
		// The service rules, then the rules for xray DNS's own queries, then
		// the devices' traffic.
		Routing: routing{Rules: slices.Concat(r.serviceRules(), dnsRules, r.trafficRules())},
	}
	// The observatory and the balancers are there only while the balancers
	// have a member. ObservatoryService is offered only with the observatory:
	// xray refuses to start a config whose ObservatoryService has no
	// observatory to serve ("not all dependencies are resolved"). Without
	// one, callers learn from ProxyAvailable that there is nothing to observe.
	if r.proxy {
		c.API.Services = append(c.API.Services, "ObservatoryService")
		sel := []string{r.selector()}
		c.Observatory = &observatory{
			SubjectSelector:   sel,
			ProbeURL:          r.st.Health.ProbeURL,
			ProbeInterval:     probeInterval,
			EnableConcurrency: true,
		}
		for _, b := range balancers {
			c.Routing.Balancers = append(c.Routing.Balancers, balancer{
				Tag:         b.tag,
				Selector:    sel,
				Strategy:    strategy{Type: "leastPing"},
				FallbackTag: b.fallback,
			})
		}
	}
	return c, nil
}

// selector is the tag prefix of the balancers' members: every server's, or
// only the pinned server's full tag. IDs have a fixed length, so that tag
// is the prefix of no other server's.
func (r *renderer) selector() string {
	if p := r.st.Routing.Pinned; p != "" {
		return ServerPrefix + p
	}
	return ServerPrefix
}

func (r *renderer) inbounds() []inbound {
	listen := r.st.Network.Runner().String()
	return []inbound{
		{
			Tag:      TagTUN,
			Protocol: "tun",
			Settings: tunSettings{Name: "xray0", MTU: 1500},
			Sniffing: &sniffing{Enabled: true, DestOverride: []string{"http", "tls", "quic"}, RouteOnly: true},
		},
		{
			Tag:      TagDNSIn,
			Protocol: "dokodemo-door",
			Listen:   listen,
			Port:     DNSPort,
			Settings: dokodemoSettings{Address: r.dnsInTarget(), Port: DNSPort, Network: "tcp,udp"},
		},
		{
			Tag:      TagSOCKS,
			Protocol: "socks",
			Listen:   listen,
			Port:     SOCKSPort,
			Settings: socksSettings{Auth: "noauth", UDP: false},
		},
		{
			Tag:      TagAPIIn,
			Protocol: "dokodemo-door",
			Listen:   listen,
			Port:     APIPort,
			Settings: dokodemoSettings{Address: "127.0.0.1"},
		},
	}
}

// dnsInTarget is the address dns-in forwards to: the remote resolver when it
// is a plain IPv4 address, or fallbackDNS.
func (r *renderer) dnsInTarget() string {
	if a, err := netip.ParseAddr(r.st.DNS.Remote); err == nil && a.Is4() {
		return a.String()
	}
	return fallbackDNS
}

// outbounds returns block, direct and dns-out, then each enabled server's
// outbound in state order.
func (r *renderer) outbounds() ([]any, error) {
	out := []any{
		outbound{Tag: TagBlock, Protocol: "blackhole"},
		outbound{Tag: TagDirect, Protocol: "freedom"},
		outbound{Tag: TagDNSOut, Protocol: "dns", Settings: dnsOutSettings{NonIPQuery: "reject"}},
	}
	for i, s := range r.st.Servers {
		if s.Disabled {
			continue
		}
		ob, err := tagged(s.Outbound, s.Tag())
		if err != nil {
			return nil, fmt.Errorf("render: servers[%d].outbound: %w", i, err)
		}
		out = append(out, ob)
	}
	return out, nil
}

// tagged returns the outbound object raw with its tag set to tag. It is
// marshalled again, with its keys sorted, so that how raw was indented or
// ordered never shows in the output. Its error never repeats raw, which
// holds credentials.
func tagged(raw json.RawMessage, tag string) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, errors.New("must be a JSON object")
	}
	t, err := json.Marshal(tag)
	if err != nil {
		return nil, err
	}
	obj["tag"] = t
	return json.Marshal(obj)
}

// serviceRules are the rules for render's own inbounds, which come before
// every other rule.
func (r *renderer) serviceRules() []rule {
	tikray := host(r.st.Network.Tikray())
	runner := host(r.st.Network.Runner())
	// tikray's probes and proxied fetches must never pass by going direct.
	socks := r.via(BalancerClosed)
	socks.InboundTag = []string{TagSOCKS}
	socks.Source = []string{tikray}
	return []rule{
		{InboundTag: []string{TagAPIIn}, Source: []string{tikray, runner}, OutboundTag: TagAPI},
		{InboundTag: []string{TagAPIIn}, OutboundTag: TagBlock},
		{InboundTag: []string{TagDNSIn}, OutboundTag: TagDNSOut},
		socks,
		{InboundTag: []string{TagSOCKS}, OutboundTag: TagBlock},
	}
}

// host is the /32 prefix holding only a.
func host(a netip.Addr) string {
	return netip.PrefixFrom(a, a.BitLen()).String()
}
