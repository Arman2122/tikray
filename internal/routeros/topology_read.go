package routeros

import (
	"context"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Arman2122/tikray/internal/auth"
	"github.com/Arman2122/tikray/internal/store"
)

// Every observation goes through this generation-bound, projected read. A
// reconnect halfway through a snapshot invalidates even its earlier facts.
type observation struct {
	ctx context.Context
	c   Native
	gen uint64
}

func (o observation) read(menu, fields string, query ...string) ([]Row, error) {
	if fields == "" || len(query) == 0 {
		return nil, ErrRequest
	}
	rows, err := o.c.CommandAt(o.ctx, o.gen, append([]string{menu + "/print", "=.proplist=" + fields}, query...))
	if err != nil {
		return nil, err
	}
	// A malformed bit must never turn an intersecting owner into an apparent
	// disabled row. Some enabled, never-written properties are absent on v7.
	for _, r := range rows {
		for _, k := range []string{"disabled", "dynamic", "invalid", "log", "running"} {
			switch r[k] {
			case "", "true", "false", "yes", "no":
			default:
				return nil, ErrProtocol
			}
		}
	}
	return rows, nil
}
func (o observation) count(menu string, query ...string) (int, error) {
	if len(query) == 0 {
		return 0, ErrRequest
	}
	rows, e := o.read(menu, ".id", append([]string{"=count-only="}, query...)...)
	if e != nil {
		return 0, e
	}
	if len(rows) != 1 {
		return 0, ErrProtocol
	}
	n, e := strconv.Atoi(rows[0]["ret"])
	if e != nil || n < 0 {
		return 0, ErrProtocol
	}
	return n, nil
}

// Each expression consumes its own operands, leaving a single result. Native
// API implicitly ANDs all remaining stack entries when processing an item.
func anyQuery(parts ...[]string) []string {
	var q []string
	for i, p := range parts {
		q = append(q, p...)
		if i > 0 {
			q = append(q, "?#|")
		}
	}
	return q
}
func valuesQuery(field string, values ...string) []string {
	var parts [][]string
	for _, v := range values {
		parts = append(parts, []string{"?" + field + "=" + v})
	}
	return anyQuery(parts...)
}
func prefixQuery(field, prefix string) []string {
	// Only use an ASCII constant ending before DEL. The exclusive upper bound
	// is the next lexicographic prefix (native queries have no regex operator).
	end := prefix[:len(prefix)-1] + string(prefix[len(prefix)-1]+1)
	return []string{"?>" + field + "=" + prefix, "?<" + field + "=" + end, "?#&"}
}
func onBit(value string) bool { return value == "yes" || value == "true" }
func unavailableRow(r Row) bool {
	for _, field := range []string{"disabled", "invalid"} {
		switch r[field] {
		case "", "false", "no":
		default:
			return true
		}
	}
	return false
}

func (o observation) topology(scope InstallScope) (Topology, []LeaseInfo, error) {
	t := Topology{Subnet: scope.Subnet, LANList: scope.LANList, LANs: slices.Clone(scope.LANs), LocalLANs: slices.Clone(scope.LocalLANs)}
	if store.ValidateRouterNetwork(store.Network{Subnet: scope.Subnet}, nil) != nil || len(scope.LANs) == 0 || len(scope.LANs) > 128 || len(scope.LocalLANs) > 128 || !interfaceName(scope.WAN.Interface) {
		return Topology{}, nil, errTopology
	}
	rows, e := o.read("/interface/bridge", "name,comment,protocol-mode,disabled", "?name=tikray")
	if e != nil {
		return Topology{}, nil, e
	}
	if len(rows) != 1 || rows[0]["name"] != "tikray" || rows[0]["comment"] != "tikray:bridge" || rows[0]["protocol-mode"] != "none" || unavailableRow(rows[0]) {
		return Topology{}, nil, errTopology
	}
	bridgeAddr := (store.Network{Subnet: scope.Subnet}).Router()
	rows, e = o.read("/ip/address", "address,interface,comment,disabled,invalid", "?interface=tikray")
	if e != nil {
		return Topology{}, nil, e
	}
	if len(rows) != 1 || unavailableRow(rows[0]) || rows[0]["interface"] != "tikray" || rows[0]["comment"] != "tikray:addr" || rows[0]["address"] != netip.PrefixFrom(bridgeAddr, scope.Subnet.Bits()).String() {
		return Topology{}, nil, errTopology
	}
	t.RouterIPs = append(t.RouterIPs, bridgeAddr)
	members, e := o.lanMembers(scope.LANList)
	if e != nil {
		return Topology{}, nil, e
	}
	var ingresses []string
	for _, lan := range scope.LANs {
		if !unicastNetwork(lan.Prefix) || !interfaceName(lan.Interface) || installInterface(lan.Interface) || lan.Interface == scope.WAN.Interface {
			return Topology{}, nil, errTopology
		}
		ingresses = append(ingresses, lan.Interface)
	}
	slices.Sort(ingresses)
	ingresses = slices.Compact(ingresses)
	if !slices.Equal(ingresses, members) {
		return Topology{}, nil, errTopology
	}
	t.LANMembers = members

	// Scope collision reads to network numbers inside the proposed ranges and
	// their enclosing network numbers. The latter catch a foreign /16 even if
	// both the foreign router IP and the network number lie outside our /29.
	if e = o.checkAddressScope(&t, scope); e != nil {
		return Topology{}, nil, e
	}
	var leases []LeaseInfo
	for _, iface := range ingresses {
		addrs, e := o.interfaceAddrs(iface)
		if e != nil {
			return Topology{}, nil, e
		}
		for _, lan := range t.LANs {
			if lan.Interface == iface && !slices.ContainsFunc(addrs, func(a netip.Prefix) bool { return a.Masked() == lan.Prefix }) {
				return Topology{}, nil, errTopology
			}
		}
		for _, a := range addrs {
			if !slices.ContainsFunc(t.LANs, func(l LAN) bool { return l.Interface == iface && l.Prefix == a.Masked() }) && slices.ContainsFunc(t.LANs, func(l LAN) bool { return l.Interface == iface && l.Dedicated }) {
				return Topology{}, nil, errTopology
			}
			t.RouterIPs = append(t.RouterIPs, a.Addr())
			t.Connected = append(t.Connected, a.Masked())
		}
		got, e := o.lanLeases(iface, t.LANs, t.RouterIPs)
		if e != nil {
			return Topology{}, nil, e
		}
		for _, l := range got {
			t.Leases = append(t.Leases, Lease{Address: l.Address, MAC: l.MAC, Interface: iface})
		}
		leases = append(leases, got...)
	}
	t.WAN, e = o.wan(&t)
	if e != nil {
		return Topology{}, nil, e
	}
	t.Connected = uniquePrefixes(t.Connected)
	slices.SortFunc(t.RouterIPs, func(a, b netip.Addr) int { return a.Compare(b) })
	t.RouterIPs = slices.Compact(t.RouterIPs)
	slices.SortFunc(leases, func(a, b LeaseInfo) int { return a.Address.Compare(b.Address) })
	return t, leases, nil
}
func (o observation) interfaceAddrs(iface string) ([]netip.Prefix, error) {
	rows, e := o.read("/ip/address", "address,network,interface,disabled,invalid", "?interface="+iface)
	if e != nil {
		return nil, e
	}
	var addrs []netip.Prefix
	for _, r := range rows {
		if unavailableRow(r) {
			continue
		}
		a, e := netip.ParsePrefix(r["address"])
		if e != nil || !a.Addr().Is4() || r["interface"] != iface {
			return nil, errTopology
		}
		addrs = append(addrs, a)
	}
	return addrs, nil
}
func (o observation) checkAddressScope(t *Topology, scope InstallScope) error {
	wanted := []netip.Prefix{scope.Subnet}
	for _, lan := range scope.LANs {
		wanted = append(wanted, lan.Prefix)
	}
	wanted = append(wanted, scope.LocalLANs...)
	for _, p := range uniquePrefixes(wanted) {
		if !unicastNetwork(p) {
			return errTopology
		}
		// Distinct possible network numbers of a covering prefix (at most 33).
		ancestors := []string{p.Addr().String()}
		for bits := p.Bits() - 1; bits >= 0; bits-- {
			a := netip.PrefixFrom(p.Addr(), bits).Masked().Addr().String()
			if a != ancestors[len(ancestors)-1] {
				ancestors = append(ancestors, a)
			}
		}
		q := anyQuery(valuesQuery("network", ancestors...), valuesQuery("address", p.Addr().String()+"/32"))
		if p.Bits() < 32 {
			_, hi := span(p)
			upper := netip.AddrFrom4([4]byte{byte(hi >> 24), byte(hi >> 16), byte(hi >> 8), byte(hi)})
			q = anyQuery(q, []string{"?>network=" + p.Addr().String(), "?<network=" + upper.String(), "?#&"},
				[]string{"?>address=" + p.Addr().String() + "/32", "?<address=" + upper.String() + "/32", "?#&"})
		}
		rows, e := o.read("/ip/address", "address,network,interface,disabled,invalid", q...)
		if e != nil {
			return e
		}
		found := false
		for _, r := range rows {
			if unavailableRow(r) {
				continue
			}
			addr, e := netip.ParsePrefix(r["address"])
			if e != nil || !addr.Addr().Is4() {
				return errTopology
			}
			peer, e := netip.ParseAddr(r["network"])
			if e != nil || !peer.Is4() {
				return errTopology
			}
			// A point-to-point /32 can advertise a distinct peer through its
			// network property. Both that peer and the assigned IP occupy scope.
			if peer != addr.Masked().Addr() && p.Contains(peer) {
				return errTopology
			}
			if !addr.Overlaps(p) {
				continue
			}
			if p == scope.Subnet && r["interface"] != "tikray" {
				return errTopology
			}
			for _, l := range scope.LANs {
				if p == l.Prefix && (r["interface"] != l.Interface || addr.Masked() != p) {
					return errTopology
				}
			}
			if addr.Masked() == p {
				found = true
			}
			if r["interface"] != "tikray" {
				t.Connected = append(t.Connected, addr.Masked())
				t.RouterIPs = append(t.RouterIPs, addr.Addr())
			}
		}
		if !found {
			return errTopology
		}
	}
	t.Connected = uniquePrefixes(t.Connected)
	return nil
}

// RouterOS evaluates include first, then exclude, then the list's directly
// assigned members. Re-evaluate every named list, including dynamic members.
func (o observation) lanMembers(root string) ([]string, error) {
	cache := map[string][]string{}
	visiting := map[string]bool{}
	var resolve func(string) ([]string, error)
	resolve = func(name string) ([]string, error) {
		if result, ok := cache[name]; ok {
			return result, nil
		}
		if !interfaceName(name) || visiting[name] || len(visiting)+len(cache) >= 64 {
			return nil, errTopology
		}
		switch strings.ToLower(name) {
		case "all", "dynamic", "static":
			return nil, errTopology
		case "none":
			return nil, nil
		}
		visiting[name] = true
		defer delete(visiting, name)
		rows, e := o.read("/interface/list", "name,include,exclude", "?name="+name)
		if e != nil {
			return nil, e
		}
		if len(rows) != 1 || rows[0]["name"] != name {
			return nil, errTopology
		}
		members := map[string]bool{}
		for _, k := range []string{"include", "exclude"} {
			for _, child := range strings.Split(rows[0][k], ",") {
				if child == "" {
					continue
				}
				sub, e := resolve(child)
				if e != nil {
					return nil, e
				}
				for _, s := range sub {
					members[s] = k == "include"
				}
			}
		}
		direct, e := o.read("/interface/list/member", "interface,list,disabled,invalid", "?list="+name)
		if e != nil {
			return nil, e
		}
		for _, r := range direct {
			if unavailableRow(r) {
				continue
			}
			iface := r["interface"]
			if !interfaceName(iface) || r["list"] != name {
				return nil, errTopology
			}
			members[iface] = true
		}
		var result []string
		for iface, v := range members {
			if v {
				result = append(result, iface)
			}
		}
		slices.Sort(result)
		cache[name] = result
		return result, nil
	}
	return resolve(root)
}

// Only active IPv4 defaults in main can attest the live fallback. A
// standby or a DHCP installation hint can disagree with the selected FIB
// path. Every other route observation remains scoped to tikray ownership.
func (o observation) wan(t *Topology) ([]WANPath, error) {
	rows, err := o.read(routeMenu, "gateway,immediate-gw,ecmp", "?routing-table=main", "?dst-address=0.0.0.0/0", "?active=true")
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, nil
	}
	r := rows[0]
	// RouterOS uses both explicit booleans and presence-only flags. Unknown
	// encodings and an ECMP flag on even a single returned row are ambiguous.
	if v, ok := r["ecmp"]; ok && v != "false" && v != "no" {
		return nil, nil
	}
	gateway, immediate := r["gateway"], r["immediate-gw"]
	if gateway == "" || immediate == "" || strings.ContainsAny(gateway+immediate, ",;@") {
		return nil, nil
	}
	ip, iface, qualified := strings.Cut(immediate, "%")
	var next netip.Addr
	if qualified {
		next, err = netip.ParseAddr(ip)
		if err != nil || !next.Is4() || next.IsMulticast() || next.IsUnspecified() || next.IsLoopback() {
			return nil, nil
		}
	} else {
		iface = immediate
	}
	if !interfaceName(iface) || strings.Contains(iface, "%") || installInterface(iface) || slices.Contains(t.LANMembers, iface) {
		return nil, nil
	}
	// A recursive or table-qualified logical gateway is not sufficient proof
	// that installing its literal value in another table preserves this path.
	interfaceHop := gateway == iface
	if !interfaceHop && (!qualified || gateway != ip && gateway != immediate) {
		return nil, nil
	}
	rows, err = o.read("/interface", "name,type,running,disabled", "?name="+iface)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 || rows[0]["name"] != iface || unavailableRow(rows[0]) || !onBit(rows[0]["running"]) {
		return nil, nil
	}
	linkType := rows[0]["type"]
	addrs, err := o.interfaceAddrs(iface)
	if err != nil {
		return nil, err
	}
	var networks []netip.Prefix
	for _, a := range addrs {
		t.RouterIPs = append(t.RouterIPs, a.Addr())
		t.Connected = append(t.Connected, a.Masked())
		if next.IsValid() && a.Contains(next) {
			networks = append(networks, a.Masked())
		}
	}
	if interfaceHop {
		// An interface itself is a next hop only on a point-to-point link.
		switch linkType {
		case "pppoe-out", "l2tp-out", "pptp-out", "sstp-out", "ovpn-out", "gre-tunnel", "ipip-tunnel":
			return []WANPath{{Interface: iface, PointToPoint: true}}, nil
		}
		return nil, nil
	}
	networks = uniquePrefixes(networks)
	if len(networks) != 1 || !unicastNetwork(networks[0]) || !usableHost(networks[0], next) || slices.Contains(t.RouterIPs, next) {
		return nil, nil
	}
	return []WANPath{{Interface: iface, Gateway: next, Network: networks[0], bindInterface: true}}, nil
}

var leaseLabel = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
var uuidLabel = regexp.MustCompile(`(?i)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`)

func (o observation) lanLeases(iface string, lans []LAN, routerIPs []netip.Addr) ([]LeaseInfo, error) {
	servers, e := o.read("/ip/dhcp-server", "name,interface,relay,invalid,disabled", "?interface="+iface)
	if e != nil {
		return nil, e
	}
	var out []LeaseInfo
	for _, s := range servers {
		if unavailableRow(s) {
			continue
		}
		if !interfaceName(s["name"]) || s["interface"] != iface || s["relay"] != "" && s["relay"] != "0.0.0.0" {
			return nil, errTopology
		}
		rows, e := o.read("/ip/dhcp-server/lease", "active-address,active-mac-address,host-name", "?active-server="+s["name"], "?status=bound")
		if e != nil {
			return nil, e
		}
		for _, r := range rows {
			addr, e := netip.ParseAddr(r["active-address"])
			mac, valid := guardMAC(r["active-mac-address"])
			if e != nil || !valid || !addr.Is4() || slices.Contains(routerIPs, addr) {
				return nil, errTopology
			}
			if !slices.ContainsFunc(lans, func(l LAN) bool { return l.Interface == iface && usableHost(l.Prefix, addr) }) {
				if slices.ContainsFunc(lans, func(l LAN) bool { return l.Interface == iface && l.Dedicated }) {
					return nil, errTopology
				}
				continue
			}
			name := r["host-name"]
			if !leaseLabel.MatchString(name) || uuidLabel.MatchString(name) || auth.PublicName(name) != name {
				name = ""
			}
			out = append(out, LeaseInfo{Address: addr, MAC: mac, Interface: iface, Name: name})
		}
	}
	return out, nil
}
