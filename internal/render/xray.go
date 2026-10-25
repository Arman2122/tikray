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
type rule struct {
	InboundTag  []string `json:"inboundTag,omitempty"`
	Source      []string `json:"source,omitempty"`
	OutboundTag string   `json:"outboundTag,omitempty"`
	BalancerTag string   `json:"balancerTag,omitempty"`
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
