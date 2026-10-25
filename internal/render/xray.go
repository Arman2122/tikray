package render

// This file models the part of xray-core's JSON config that render writes,
// and nothing more. The field order of each struct is the key order of the
// output. Key names follow xray-core's parser (infra/conf), which reads them
// without regard to case.

// config is a whole xray-core config.
type config struct {
	Log      logConfig    `json:"log"`
	API      apiConfig    `json:"api"`
	Stats    struct{}     `json:"stats"`
	Policy   policyConfig `json:"policy"`
	DNS      dnsConfig    `json:"dns"`
	Inbounds []inbound    `json:"inbounds"`
	// Outbounds holds outbound values for render's own outbounds and, for
	// each server, its tagged json.RawMessage.
	Outbounds   []any        `json:"outbounds"`
	Routing     routing      `json:"routing"`
	Observatory *observatory `json:"observatory,omitempty"`
}

type logConfig struct {
	LogLevel string `json:"loglevel"`
}

// apiConfig enables xray's gRPC API. The api-in inbound carries its
// connections, and a routing rule hands them to the API by its tag.
type apiConfig struct {
	Tag      string   `json:"tag"`
	Services []string `json:"services"`
}

type policyConfig struct {
	System systemPolicy `json:"system"`
}

type systemPolicy struct {
	StatsOutboundUplink   bool `json:"statsOutboundUplink"`
	StatsOutboundDownlink bool `json:"statsOutboundDownlink"`
}

// dnsConfig is xray's DNS, which dns-out answers the devices' queries with.
// Tag is the inbound tag the routing rules see on the queries it sends
// itself.
type dnsConfig struct {
	Tag           string `json:"tag"`
	QueryStrategy string `json:"queryStrategy"`
	// Servers holds a dnsServer for the domestic resolver, when there is
	// one, and last the remote resolver's address as a string.
	Servers []any `json:"servers"`
}

// dnsServer is a resolver that answers for Domains alone: SkipFallback keeps
// xray from asking it about any other name.
type dnsServer struct {
	Address      string   `json:"address"`
	Domains      []string `json:"domains"`
	SkipFallback bool     `json:"skipFallback"`
}

// inbound is one of xray's inbounds. The TUN inbound has no listen address
// or port.
type inbound struct {
	Tag      string    `json:"tag"`
	Protocol string    `json:"protocol"`
	Listen   string    `json:"listen,omitempty"`
	Port     int       `json:"port,omitempty"`
	Settings any       `json:"settings,omitempty"`
	Sniffing *sniffing `json:"sniffing,omitempty"`
}

type tunSettings struct {
	Name string `json:"name"`
	// MTU is written "mtu", the key xray 26.10 renamed it to. Older releases
	// read "MTU" and match it regardless of case.
	MTU int `json:"mtu"`
}

// dokodemoSettings are the settings of a dokodemo-door inbound, which sends
// what it receives to a fixed address.
type dokodemoSettings struct {
	Address string `json:"address"`
	Port    int    `json:"port,omitempty"`
	Network string `json:"network,omitempty"`
}

type socksSettings struct {
	Auth string `json:"auth"`
	UDP  bool   `json:"udp"`
}

type sniffing struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
	RouteOnly    bool     `json:"routeOnly"`
}

// outbound is one of render's own outbounds. A server's outbound is written
// from its stored JSON instead.
type outbound struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Settings any    `json:"settings,omitempty"`
}

type dnsOutSettings struct {
	NonIPQuery string `json:"nonIPQuery"`
}

type routing struct {
	Rules     []rule     `json:"rules"`
	Balancers []balancer `json:"balancers,omitempty"`
}

// rule is one routing rule. It matches when every condition it sets
// matches, and sends the traffic to OutboundTag or to BalancerTag: exactly
// one is set.
//
// A list left empty is left out of the JSON, and xray reads a rule without
// it as matching every inbound, source, domain or address. Rules are made
// by ruleList.add, which never makes one with an empty list, and Render
// refuses any that has one (checkMatchers).
type rule struct {
	InboundTag []string `json:"inboundTag,omitempty"`
	Source     []string `json:"source,omitempty"`
	Domain     []string `json:"domain,omitempty"`
	IP         []string `json:"ip,omitempty"`
	// Port is a list of destination ports, such as "53". Like an empty
	// list, an empty Port is left out and matches every port, so it is set
	// only by matchPort, which refuses an empty one.
	Port string `json:"port,omitempty"`
	// Network is set on the catch-all rule alone, to "tcp,udp": all the
	// traffic the TUN inbound carries.
	Network     string `json:"network,omitempty"`
	OutboundTag string `json:"outboundTag,omitempty"`
	BalancerTag string `json:"balancerTag,omitempty"`
}

// balancer picks one of the outbounds whose tags start with a selector.
type balancer struct {
	Tag      string   `json:"tag"`
	Selector []string `json:"selector"`
	Strategy strategy `json:"strategy"`
	// FallbackTag is the outbound used while no selected outbound is up.
	FallbackTag string `json:"fallbackTag"`
}

type strategy struct {
	Type string `json:"type"`
}

// observatory probes the outbounds whose tags start with a selector, for the
// balancers' leastPing strategy.
type observatory struct {
	SubjectSelector   []string `json:"subjectSelector"`
	ProbeURL          string   `json:"probeURL"`
	ProbeInterval     string   `json:"probeInterval"`
	EnableConcurrency bool     `json:"enableConcurrency"`
}
