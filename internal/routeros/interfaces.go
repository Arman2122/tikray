package routeros

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/Arman2122/tikray/internal/auth"
)

// RouterInterface describes one discovered physical, wireless, bridge, VLAN,
// or tunnel interface on the managed MikroTik router. Never carries passwords,
// Wi-Fi passphrases, or arbitrary comments.
type RouterInterface struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Role     string   `json:"role"` // "wan" | "lan" | "bridge-port" | "unassigned"
	Running  bool     `json:"running"`
	Disabled bool     `json:"disabled,omitempty"`
	Bridge   string   `json:"bridge,omitempty"`
	SSID     string   `json:"ssid,omitempty"`
	Subnets  []string `json:"subnets,omitempty"`
	Lists    []string `json:"lists,omitempty"`
	InScope  bool     `json:"in_scope,omitempty"`
	RxBytes  uint64   `json:"rx_bytes,omitempty"`
	TxBytes  uint64   `json:"tx_bytes,omitempty"`
}

// WANUplink describes one discovered IPv4 Internet-in (0.0.0.0/0) default route
// on the router (active primary or standby/backup ISP uplink).
type WANUplink struct {
	Interface    string `json:"interface"`
	Type         string `json:"type,omitempty"`
	Gateway      string `json:"gateway,omitempty"`
	PointToPoint bool   `json:"point_to_point,omitempty"`
	Active       bool   `json:"active"`
	Distance     int    `json:"distance,omitempty"`
	Running      bool   `json:"running"`
}

// NetworkInventory is the live MikroTik interface & Internet-in topology view
// returned by GET /v1/routeros/interfaces.
type NetworkInventory struct {
	Managed    bool              `json:"managed"`
	RouterOS   string            `json:"routeros,omitempty"`
	LANList    string            `json:"lan_list,omitempty"`
	ActiveWAN  string            `json:"active_wan,omitempty"`
	Uplinks    []WANUplink       `json:"uplinks"`
	Interfaces []RouterInterface `json:"interfaces"`
}

var discoverInterfaceTypes = []string{
	"ether", "wifi", "wlan", "bridge", "vlan",
	"pppoe-out", "lte", "wg", "wireguard",
	"l2tp-out", "sstp-out", "ovpn-out", "bonding",
}

// Interfaces reads the router's live Ethernet ports, Wi-Fi radios/SSIDs,
// bridges, VLANs, IPv4 subnets, and WAN uplinks on demand using strictly scoped
// and projected RouterOS native API queries.
func (e *Engine) Interfaces(ctx context.Context) (NetworkInventory, error) {
	gen := e.c.Generation()
	if gen == 0 {
		return NetworkInventory{}, ErrUnavailable
	}
	o := observation{ctx: ctx, c: e.c, gen: gen}

	inv := NetworkInventory{
		Managed:    true,
		LANList:    e.scope.LANList,
		Uplinks:    []WANUplink{},
		Interfaces: []RouterInterface{},
	}

	// 1. Discover physical, wireless, bridge, VLAN and uplink interfaces.
	rows, err := o.read("/interface", "name,type,running,disabled,rx-byte,tx-byte", valuesQuery("type", discoverInterfaceTypes...)...)
	if err != nil {
		return NetworkInventory{}, publicEngineError(err)
	}

	byName := make(map[string]*RouterInterface, len(rows))
	var names, bridges, wifiIfaces, wlanIfaces []string
	for _, r := range rows {
		name := r["name"]
		if !interfaceName(name) || installInterface(name) {
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(r["type"]))
		rx, _ := strconv.ParseUint(r["rx-byte"], 10, 64)
		tx, _ := strconv.ParseUint(r["tx-byte"], 10, 64)
		ri := &RouterInterface{
			Name:     name,
			Type:     typ,
			Role:     "unassigned",
			Running:  onBit(r["running"]),
			Disabled: onBit(r["disabled"]),
			RxBytes:  rx,
			TxBytes:  tx,
		}
		byName[name] = ri
		names = append(names, name)
		switch typ {
		case "bridge":
			bridges = append(bridges, name)
		case "wifi":
			wifiIfaces = append(wifiIfaces, name)
		case "wlan":
			wlanIfaces = append(wlanIfaces, name)
		}
	}

	// 2. Map bridge-port membership (which Ethernet/Wi-Fi ports live in a bridge).
	if len(bridges) > 0 {
		if bports, err := o.read("/interface/bridge/port", "interface,bridge,disabled", valuesQuery("bridge", bridges...)...); err == nil {
			for _, bp := range bports {
				if unavailableRow(bp) {
					continue
				}
				if ri, ok := byName[bp["interface"]]; ok && interfaceName(bp["bridge"]) {
					ri.Bridge = bp["bridge"]
				}
			}
		}
	}

	// 3. Enrich Wi-Fi SSID names (RouterOS 7 wifi + legacy wireless; never read passphrases).
	if len(wifiIfaces) > 0 {
		if wrows, err := o.read("/interface/wifi", "name,configuration.ssid,running,disabled", valuesQuery("name", wifiIfaces...)...); err == nil {
			for _, wr := range wrows {
				if ri, ok := byName[wr["name"]]; ok {
					ri.SSID = safeSSID(wr["configuration.ssid"])
				}
			}
		}
	}
	if len(wlanIfaces) > 0 {
		if wrows, err := o.read("/interface/wireless", "name,ssid,running,disabled", valuesQuery("name", wlanIfaces...)...); err == nil {
			for _, wr := range wrows {
				if ri, ok := byName[wr["name"]]; ok {
					ri.SSID = safeSSID(wr["ssid"])
				}
			}
		}
	}

	// 4. Map IPv4 subnets per interface.
	if len(names) > 0 {
		if addrs, err := o.read("/ip/address", "address,interface,disabled,invalid", valuesQuery("interface", names...)...); err == nil {
			for _, ar := range addrs {
				if unavailableRow(ar) {
					continue
				}
				ri, ok := byName[ar["interface"]]
				if !ok {
					continue
				}
				if p, err := netip.ParsePrefix(ar["address"]); err == nil && p.Addr().Is4() {
					cidr := p.Masked().String()
					if !slices.Contains(ri.Subnets, cidr) {
						ri.Subnets = append(ri.Subnets, cidr)
					}
				}
			}
		}
		if members, err := o.read("/interface/list/member", "interface,list,disabled,invalid", valuesQuery("interface", names...)...); err == nil {
			for _, mr := range members {
				if unavailableRow(mr) {
					continue
				}
				ri, ok := byName[mr["interface"]]
				if !ok || !interfaceName(mr["list"]) {
					continue
				}
				if !slices.Contains(ri.Lists, mr["list"]) {
					ri.Lists = append(ri.Lists, mr["list"])
				}
			}
		}
	}

	// 5. Discover all IPv4 default routes (Internet-in / WAN uplinks).
	wanSet := map[string]bool{}
	if uplinks, err := o.discoverWANUplinks(byName); err == nil {
		inv.Uplinks = uplinks
		for _, u := range uplinks {
			wanSet[u.Interface] = true
			if u.Active && inv.ActiveWAN == "" {
				inv.ActiveWAN = u.Interface
			}
		}
	}
	if inv.ActiveWAN == "" && e.scope.WAN.Interface != "" {
		inv.ActiveWAN = e.scope.WAN.Interface
		wanSet[e.scope.WAN.Interface] = true
	}

	// 6. Classify interface roles and inherit bridge subnets for readability.
	lanScope := map[string]bool{}
	for _, lan := range e.scope.LANs {
		lanScope[lan.Interface] = true
	}
	for _, ri := range byName {
		if ri.Bridge != "" {
			ri.Role = "bridge-port"
			if len(ri.Subnets) == 0 {
				if parent, ok := byName[ri.Bridge]; ok && len(parent.Subnets) > 0 {
					ri.Subnets = slices.Clone(parent.Subnets)
				}
			}
		}
		if lanScope[ri.Name] || (e.scope.LANList != "" && slices.Contains(ri.Lists, e.scope.LANList)) {
			ri.InScope = true
			if ri.Role != "bridge-port" {
				ri.Role = "lan"
			}
		}
		if wanSet[ri.Name] || slices.Contains(ri.Lists, "WAN") {
			ri.Role = "wan"
		}
		if ri.Role == "unassigned" && len(ri.Subnets) > 0 {
			ri.Role = "lan"
		}
		slices.Sort(ri.Subnets)
		slices.Sort(ri.Lists)
		inv.Interfaces = append(inv.Interfaces, *ri)
	}

	slices.SortFunc(inv.Interfaces, func(a, b RouterInterface) int {
		ra, rb := roleOrder(a.Role), roleOrder(b.Role)
		if ra != rb {
			return ra - rb
		}
		return strings.Compare(a.Name, b.Name)
	})
	return inv, nil
}

func roleOrder(role string) int {
	switch role {
	case "wan":
		return 0
	case "lan":
		return 1
	case "bridge-port":
		return 2
	default:
		return 3
	}
}

func safeSSID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return ""
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return ""
		}
	}
	if auth.PublicName(s) != s {
		return ""
	}
	return s
}

func (o observation) discoverWANUplinks(ifaces map[string]*RouterInterface) ([]WANUplink, error) {
	rows, err := o.read(routeMenu, "gateway,immediate-gw,active,distance,disabled,ecmp", "?routing-table=main", "?dst-address=0.0.0.0/0")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []WANUplink
	for _, r := range rows {
		if onBit(r["disabled"]) {
			continue
		}
		gateway, immediate := r["gateway"], r["immediate-gw"]
		if gateway == "" || strings.ContainsAny(gateway+immediate, ",;@") {
			continue
		}
		var iface, gwIP string
		var p2p bool
		if immediate != "" {
			ip, ifn, qualified := strings.Cut(immediate, "%")
			if qualified {
				if addr, err := netip.ParseAddr(ip); err == nil && addr.Is4() {
					gwIP = addr.String()
					iface = ifn
				}
			} else {
				iface = immediate
				p2p = true
			}
		} else if interfaceName(gateway) && !installInterface(gateway) {
			if _, err := netip.ParseAddr(gateway); err != nil {
				iface = gateway
				p2p = true
			}
		}
		if !interfaceName(iface) || installInterface(iface) || seen[iface] {
			continue
		}
		seen[iface] = true
		dist, _ := strconv.Atoi(r["distance"])
		if dist == 0 {
			dist = 1
		}
		u := WANUplink{
			Interface:    iface,
			Gateway:      gwIP,
			PointToPoint: p2p,
			Active:       onBit(r["active"]),
			Distance:     dist,
			Running:      true,
		}
		if ri, ok := ifaces[iface]; ok {
			u.Type = ri.Type
			u.Running = ri.Running && !ri.Disabled
		}
		out = append(out, u)
	}
	slices.SortFunc(out, func(a, b WANUplink) int {
		if a.Active != b.Active {
			if a.Active {
				return -1
			}
			return 1
		}
		if a.Distance != b.Distance {
			return a.Distance - b.Distance
		}
		return strings.Compare(a.Interface, b.Interface)
	})
	return out, nil
}

// resolveWANUplink populates Topology.WANUplinks when the operator pinned a
// specific Internet-in WAN interface that is not already the primary active WAN.
func (e *Engine) resolveWANUplink(ctx context.Context, a *Actual, wanIface string) error {
	if wanIface == "" {
		return nil
	}
	for _, w := range a.Topology.WAN {
		if w.Interface == wanIface {
			return nil
		}
	}
	for _, w := range a.Topology.WANUplinks {
		if w.Interface == wanIface {
			return nil
		}
	}
	o := observation{ctx: ctx, c: e.c, gen: a.Generation}
	rows, err := o.read(routeMenu, "gateway,immediate-gw,active,distance,disabled,ecmp", "?routing-table=main", "?dst-address=0.0.0.0/0")
	if err != nil {
		return publicEngineError(err)
	}
	for _, r := range rows {
		if onBit(r["disabled"]) {
			continue
		}
		immediate := r["immediate-gw"]
		gateway := r["gateway"]
		if immediate == "" {
			immediate = gateway
		}
		ip, iface, qualified := strings.Cut(immediate, "%")
		var next netip.Addr
		if qualified {
			next, err = netip.ParseAddr(ip)
			if err != nil || !next.Is4() {
				continue
			}
		} else {
			iface = immediate
		}
		if iface != wanIface || !interfaceName(iface) || installInterface(iface) || slices.Contains(a.Topology.LANMembers, iface) {
			continue
		}
		if !qualified {
			a.Topology.WANUplinks = append(a.Topology.WANUplinks, WANPath{Interface: iface, PointToPoint: true})
			return nil
		}
		addrs, err := o.interfaceAddrs(iface)
		if err != nil {
			return publicEngineError(err)
		}
		for _, addr := range addrs {
			if addr.Contains(next) {
				a.Topology.WANUplinks = append(a.Topology.WANUplinks, WANPath{
					Interface: iface, Gateway: next, Network: addr.Masked(), bindInterface: true,
				})
				return nil
			}
		}
	}
	return nil
}
