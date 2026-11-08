package routeros

import (
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/store"
)

var (
	errPolicy   = errors.New("routeros: invalid router policy")
	errTopology = errors.New("routeros: LAN, bridge or WAN scope is ambiguous")
	errConflict = errors.New("routeros: owner configuration conflicts with steering")
)

// PolicyInput contains only the desired state needed to compile RouterOS rules.
type PolicyInput struct {
	Network  store.Network
	Default  store.Policy
	Devices  []PolicyDevice
	Domestic []netip.Prefix
}
type PolicyDevice struct {
	Address netip.Prefix
	MAC     string
	Policy  store.Policy
}

// LAN associates a managed IPv4 network with its observed ingress. Dedicated
// means that the interface's entire client population is in the listed LANs.
type LAN struct {
	Interface string       `json:"interface"`
	Prefix    netip.Prefix `json:"prefix"`
	Dedicated bool         `json:"dedicated,omitempty"`
}

// Lease identifies a currently bound LAN address and the L2 source visible
// on that ingress. A DHCP relay's interface alone cannot establish the MAC.
type Lease struct {
	Address        netip.Addr
	MAC, Interface string
}
type WANPath struct {
	Interface string       `json:"interface"`
	Gateway   netip.Addr   `json:"gateway,omitzero"`
	Network   netip.Prefix `json:"network,omitzero"`
	// True when the observed main default uses this point-to-point link
	// itself as the gateway (for example PPPoE). Gateway is then empty.
	PointToPoint bool `json:"point_to_point,omitempty"`
	// A live resolved route proves the egress as well as the IP. Keep that
	// interface binding when another connected link can reach the same gateway.
	bindInterface bool
}

func (w WANPath) nextHop() string {
	if w.PointToPoint {
		return w.Interface
	}
	if w.bindInterface {
		return w.Gateway.String() + "%" + w.Interface
	}
	return w.Gateway.String()
}

// Match holds the eligibility predicates of an enabled forward FastTrack row.
type FastTrackRule struct {
	ID     string
	Match  map[string]string
	Logged bool
	// Next is the next enabled rule in the owner's forward chain, observed
	// before inserting the exception. It must prove ordinary slow-path accept.
	Next *ForwardRule
}
type ForwardRule struct {
	ID, Action string
	Match      map[string]string
	Logged     bool
}

// A scoped observation found a foreign use of a reserved resource or an
// intersecting owner rule that makes steering unsafe. This includes packet
// mark writers and terminal forward-mangle rules that can bypass the
// FastTrack exemption, regardless of the names their owner chose. It also
// includes inbound port forwards whose replies a closed egress guard would
// intercept. The observer must refuse unverified intersections.
type ForeignRef struct{ Menu, Property, Value string }

// Opaque means a further configured matcher has no verified flow-table
// equivalent; the visible predicates can exclude a flow but cannot prove a hit.
type RoutingMarkWriter struct {
	Mark   string
	Match  map[string]string
	Opaque bool
}
type Topology struct {
	sourceNATConflict bool
	Subnet            netip.Prefix
	LANList           string
	LANs              []LAN
	// Effective membership includes dynamic members and included/excluded
	// lists. Missing or broader membership is insufficient for a LAN hook.
	LANMembers []string
	// Marks set by overlapping, nonterminal owner routing-mark rules. Any
	// overlapping mark writer that cannot be described must be a ForeignRef.
	ForeignRoutingMarks []string
	RoutingMarkWriters  []RoutingMarkWriter
	// LocalLANs are additional local LAN destinations outside the managed list.
	LocalLANs []netip.Prefix
	// Connected lists occupied non-tikray networks used for collision checks.
	Connected   []netip.Prefix
	RouterIPs   []netip.Addr
	WAN         []WANPath
	Leases      []Lease
	FastTrack   []FastTrackRule
	ForeignRefs []ForeignRef
}

// Object is one desired row, identified by menu and exact ownership comment.
// Member comments also identify their prefix. Before can name an owned
// comment, a foreign anchor ID or first:<chain>. InitialDisabled is used
// only on creation, for rows whose live enabled bit belongs to netwatch.
type Object struct {
	Menu, Comment   string
	Props           map[string]string
	DependsOn       []string
	Before          string
	InitialDisabled bool
}

func object(menu, role string, props map[string]string, deps ...string) Object {
	return Object{Menu: menu, Comment: "tikray:" + role, Props: props, DependsOn: slices.Clone(deps)}
}

func validPolicy(p store.Policy) bool {
	return p.Mode == store.ModeSmart || p.Mode == store.ModeFull || p.Mode == store.ModeDirect && !p.KillSwitch
}
func srcList(p store.Policy) string {
	suffix := "open"
	if p.KillSwitch {
		suffix = "closed"
	}
	return "tikray-src-" + string(p.Mode) + "-" + suffix
}

// Project drops names, outbound configurations, credentials and xray-only
// matchers before the router planner sees the state.
func Project(st store.State) (PolicyInput, error) {
	in := PolicyInput{Network: store.Network{Subnet: st.Network.Subnet}, Default: st.DefaultPolicy}
	for _, d := range st.Devices {
		in.Devices = append(in.Devices, PolicyDevice{Address: d.Address, MAC: d.MAC, Policy: d.Policy})
	}
	for _, value := range st.Routing.Domestic.IPs {
		if code, ok := strings.CutPrefix(value, "geoip:"); ok {
			if code == "" || strings.ContainsAny(code, " \t\r\n") {
				return PolicyInput{}, errPolicy
			}
			continue
		}
		p, e := netip.ParsePrefix(value)
		if e != nil {
			a, err := netip.ParseAddr(value)
			if err != nil || a.Zone() != "" {
				return PolicyInput{}, errPolicy
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4() {
			in.Domestic = append(in.Domestic, p.Masked())
		}
	}
	return normalizePolicy(in)
}

func normalizePolicy(in PolicyInput) (PolicyInput, error) {
	if !validPolicy(in.Default) {
		return PolicyInput{}, errPolicy
	}
	in.Devices = slices.Clone(in.Devices)
	devices := make([]store.Device, 0, len(in.Devices))
	for i, d := range in.Devices {
		if !validPolicy(d.Policy) {
			return PolicyInput{}, errPolicy
		}
		if d.MAC != "" {
			mac, ok := guardMAC(d.MAC)
			if !ok {
				return PolicyInput{}, errPolicy
			}
			in.Devices[i].MAC = mac
		}
		devices = append(devices, store.Device{Address: d.Address})
	}
	if store.ValidateRouterNetwork(in.Network, devices) != nil {
		return PolicyInput{}, errPolicy
	}
	slices.SortFunc(in.Devices, func(a, b PolicyDevice) int { return a.Address.Addr().Compare(b.Address.Addr()) })
	for _, p := range in.Domestic {
		if !validPrefix(p) {
			return PolicyInput{}, errPolicy
		}
	}
	in.Domestic = uniquePrefixes(in.Domestic)
	return in, nil
}
