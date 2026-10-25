// Package store holds tikray's desired state: the model an operator edits
// (servers, subscriptions, devices and their policies, routing, DNS, the
// private network and the health probe) and the checks that keep a bad edit
// from reaching the router or xray.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// Mode says how much of a device's traffic goes through the proxy.
type Mode string

// Policy modes.
const (
	// ModeDirect never touches xray.
	ModeDirect Mode = "direct"
	// ModeSmart sends domestic and local traffic direct and the rest through
	// the proxy.
	ModeSmart Mode = "smart"
	// ModeFull sends everything but local traffic through the proxy.
	ModeFull Mode = "full"
)

// Policy is what applies to a device's traffic.
type Policy struct {
	Mode Mode `json:"mode"`
	// KillSwitch blocks the device's proxied traffic while the proxy is
	// unavailable, instead of letting it out direct. ModeDirect has no proxied
	// traffic, so it cannot have one.
	KillSwitch bool `json:"kill_switch,omitempty"`
}

// Server is one outbound xray can send traffic through.
type Server struct {
	// ID is 8 lowercase hex digits, from NewID.
	ID   string `json:"id"`
	Name string `json:"name"`
	// Disabled keeps the server in the state but out of the generated config.
	Disabled bool `json:"disabled,omitempty"`
	// Link is the share link the server was imported from, if it was.
	Link string `json:"link,omitempty"`
	// Subscription is the ID of the subscription the server came from, if any.
	Subscription string `json:"subscription,omitempty"`
	// Outbound is the xray outbound object, without a tag: Tag supplies one.
	Outbound json.RawMessage `json:"outbound"`
}

// Tag is the tag the server's outbound carries in the generated xray config.
func (s Server) Tag() string { return "srv-" + s.ID }

// Duration is a time.Duration that marshals as text such as "24h0m0s".
type Duration time.Duration

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler. It accepts what
// time.ParseDuration does.
func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("store: invalid duration %q: %w", text, err)
	}
	*d = Duration(v)
	return nil
}

// Subscription is a URL that serves a list of servers.
type Subscription struct {
	// ID is 8 lowercase hex digits, from NewID.
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	// Disabled stops the subscription being fetched.
	Disabled bool `json:"disabled,omitempty"`
	// Interval is how often to fetch it again.
	Interval  Duration  `json:"interval"`
	LastFetch time.Time `json:"last_fetch,omitzero"`
	// LastError is why the last fetch failed; empty when it did not.
	LastError string `json:"last_error,omitempty"`
}

// Device is a LAN client, or a range of them, and the policy that applies to
// it.
type Device struct {
	// Address is the device's IPv4 address as a masked prefix. A single device
	// is a /32.
	Address netip.Prefix `json:"address"`
	Name    string       `json:"name,omitempty"`
	MAC     string       `json:"mac,omitempty"`
	Policy  Policy       `json:"policy"`
}

// Action says where a routing rule sends the traffic it matches.
type Action string

// Rule actions.
const (
	// ActionDirect sends matching traffic out direct.
	ActionDirect Action = "direct"
	// ActionProxy sends it through the proxy.
	ActionProxy Action = "proxy"
	// ActionBlock drops it.
	ActionBlock Action = "block"
	// ActionServer sends it through the server the rule names.
	ActionServer Action = "server"
)

// Rule routes the traffic that matches any of its Domains or IPs.
type Rule struct {
	// Domains are xray domain matchers: "domain:example.com", "full:a.b",
	// "keyword:x", "regexp:...", "geosite:ir", "ext:file:tag" or a bare
	// substring.
	Domains []string `json:"domains,omitempty"`
	// IPs are addresses, CIDR prefixes or "geoip:<code>".
	IPs    []string `json:"ips,omitempty"`
	Action Action   `json:"action"`
	// Server is the ID of the server to use. It is set exactly when Action is
	// ActionServer.
	Server string `json:"server,omitempty"`
}

// Domestic is extra domestic matchers, used beside the geo bundle's own.
type Domestic struct {
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}

// Routing is how traffic is split between direct, proxy and block.
type Routing struct {
	// Pinned is the ID of the server to use instead of the lowest-latency
	// choice.
	Pinned string `json:"pinned,omitempty"`
	// BlockList holds domain matchers whose traffic is dropped.
	BlockList []string `json:"block_list,omitempty"`
	Domestic  Domestic `json:"domestic"`
	// Rules are the user's custom rules, tried in order.
	Rules []Rule `json:"rules,omitempty"`
}

// DNS names the resolvers xray uses.
type DNS struct {
	// Domestic is the resolver for domestic names. The zero address means the
	// router's bridge address.
	Domestic netip.Addr `json:"domestic,omitzero"`
	// Remote is the resolver for everything else: an https:// DoH URL or an
	// IPv4 address.
	Remote string `json:"remote"`
}

// Network is the private subnet that links the router, tikray and the
// runner.
type Network struct {
	// Subnet is an IPv4 prefix of /29 or larger, so that .1 to .3 fit.
	Subnet netip.Prefix `json:"subnet"`
}

// host is the subnet's address number i.
func (n Network) host(i int) netip.Addr {
	a := n.Subnet.Masked().Addr()
	for range i {
		a = a.Next()
	}
	return a
}

// Router is the router's address on the subnet, its .1.
func (n Network) Router() netip.Addr { return n.host(1) }

// Tikray is the control plane's address on the subnet, its .2.
func (n Network) Tikray() netip.Addr { return n.host(2) }

// Runner is the runner's address on the subnet, its .3.
func (n Network) Runner() netip.Addr { return n.host(3) }

// Health configures the connectivity probe.
type Health struct {
	// ProbeURL is fetched through the proxy to tell whether it works.
	ProbeURL string `json:"probe_url"`
}

// State is everything tikray is told to make true.
type State struct {
	Servers       []Server       `json:"servers"`
	Subscriptions []Subscription `json:"subscriptions"`
	Devices       []Device       `json:"devices"`
	// DefaultPolicy applies to every device not listed in Devices.
	DefaultPolicy Policy  `json:"default_policy"`
	Routing       Routing `json:"routing"`
	DNS           DNS     `json:"dns"`
	Network       Network `json:"network"`
	Health        Health  `json:"health"`
}

// DomesticResolver is the address of the resolver for domestic names:
// DNS.Domestic, or the router's bridge address when that is unset.
func (s State) DomesticResolver() netip.Addr {
	if s.DNS.Domestic.IsValid() {
		return s.DNS.Domestic
	}
	return s.Network.Router()
}

// Default returns the state of a fresh install: nothing configured and
// everything direct. Its lists are empty, not nil, so that they marshal as [].
func Default() State {
	return State{
		Servers:       []Server{},
		Subscriptions: []Subscription{},
		Devices:       []Device{},
		DefaultPolicy: Policy{Mode: ModeDirect},
		DNS:           DNS{Remote: "https://1.1.1.1/dns-query"},
		Network:       Network{Subnet: netip.MustParsePrefix("172.31.255.0/29")},
		Health:        Health{ProbeURL: "https://www.gstatic.com/generate_204"},
	}
}

// Clone returns a deep copy: changing the copy never shows in s. A nil list
// stays nil and an empty one stays empty.
func (s State) Clone() State {
	c := s
	c.Servers = slices.Clone(s.Servers)
	for i := range c.Servers {
		c.Servers[i].Outbound = slices.Clone(c.Servers[i].Outbound)
	}
	c.Subscriptions = slices.Clone(s.Subscriptions)
	c.Devices = slices.Clone(s.Devices)
	c.Routing.BlockList = slices.Clone(s.Routing.BlockList)
	c.Routing.Domestic.Domains = slices.Clone(s.Routing.Domestic.Domains)
	c.Routing.Domestic.IPs = slices.Clone(s.Routing.Domestic.IPs)
	c.Routing.Rules = slices.Clone(s.Routing.Rules)
	for i := range c.Routing.Rules {
		c.Routing.Rules[i].Domains = slices.Clone(c.Routing.Rules[i].Domains)
		c.Routing.Rules[i].IPs = slices.Clone(c.Routing.Rules[i].IPs)
	}
	return c
}

// NewID returns a fresh 8-digit lowercase hex ID for a server or a
// subscription.
func NewID() string {
	var b [4]byte
	// Since Go 1.24 Read never fails: it ends the program if the system has
	// no randomness.
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
