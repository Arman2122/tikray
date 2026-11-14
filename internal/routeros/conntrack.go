package routeros

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/store"
)

const (
	ipv4Connections = "/ip/firewall/connection"
	ipv6Connections = "/ipv6/firewall/connection"
	// ICMP and keyed GRE use different tuple discriminators from TCP/UDP.
	tupleFields         = ".id," + originalTupleFields
	originalTupleFields = "src-address,dst-address,protocol,src-port,dst-port,icmp-type,icmp-code,icmp-id,gre-protocol,gre-version,gre-key"
	connectionFields    = tupleFields + ",reply-src-address,reply-src-port,reply-dst-address,reply-dst-port"
	ipv4FlowFields      = connectionFields + ",connection-mark,fasttrack,dstnat"
)

var ErrIPv6FlowScope = errors.New("routeros: cannot verify all prior IPv6 FastTrack sources")

type affectedClass struct {
	change    flowChange
	old, next *policyView
}

func isDNS(r Row) bool {
	return (r["protocol"] == "udp" || r["protocol"] == "tcp") && r["dst-port"] == "53"
}

func (d affectedClass) closed(dst netip.Addr, dns bool) bool {
	return d.change.From.KillSwitch && (dns || proxyDestination(*d.old, d.change.From, dst)) || d.change.To.KillSwitch && (dns || proxyDestination(*d.next, d.change.To, dst))
}
func (d affectedClass) includes(src, dst netip.Addr, r Row) bool {
	if slices.Contains(d.old.RouterIPs, src) || slices.Contains(d.next.RouterIPs, src) {
		return false
	}
	dns := isDNS(r)
	if d.change.DataOnly && dns || d.change.DNSProtocol != "" && d.change.DNSProtocol != r["protocol"] {
		return false
	}
	// Repairing a classifier does not change a verified client's policy.
	// A non-accelerated binding with the right mark already follows its route.
	if d.old.RepairOnly && !dns && !onBit(r["fasttrack"]) {
		mark := r["connection-mark"]
		if proxyDestination(*d.next, d.change.To, dst) {
			if mark == "tikray-"+policyClass(d.change.To) {
				return false
			}
		} else if mark != "tikray-open" && mark != "tikray-closed" {
			return false
		}
	}
	if !d.closed(dst, dns) {
		// A foreign connection mark bypasses open mangle. Closed egress
		// and DNS still select this source independently of its mark.
		switch r["connection-mark"] {
		case "", "no-mark", "tikray-open", "tikray-closed":
		default:
			if !dns {
				return false
			}
		}
	}
	return affectsFlow(d.change, *d.old, *d.next, dst, dns)
}

func purgeFlows(ctx context.Context, c Native, a Actual, views []policyView) (int, error) {
	return purgePolicyFlows(ctx, c, a, views, false)
}
func purgeAfterSwitch(ctx context.Context, c Native, a Actual, views []policyView) (int, error) {
	return purgePolicyFlows(ctx, c, a, views, true)
}
func purgePolicyFlows(ctx context.Context, c Native, a Actual, views []policyView, afterSwitch bool) (int, error) {
	if a.Generation == 0 || c.Generation() != a.Generation {
		return 0, ErrStaleGeneration
	}
	o := observation{ctx: ctx, c: c, gen: a.Generation}
	n, v6Err := purgeIPv6(o, a, views)
	if v6Err != nil && !errors.Is(v6Err, ErrIPv6FlowScope) {
		return n, v6Err
	}
	// Existing accelerated packets bypass the newly staged IPv4 guard.
	// Close those bindings even when we cannot release the IPv6 guard,
	// without repeatedly interrupting the open clients on each retry.
	candidates, err := ipv4Candidates(o, a, views, v6Err != nil, afterSwitch)
	if err != nil {
		return n, err
	}
	m, err := removeIPv4Candidates(o, candidates)
	if err != nil {
		return n + m, err
	}
	return n + m, v6Err
}

func ipv4Candidates(o observation, a Actual, views []policyView, closedOnly, keepTargetPath bool) (map[string]Row, error) {
	var dnsRules map[string]Observed
	if keepTargetPath {
		dnsRules = map[string]Observed{}
		for _, r := range a.Rows {
			if r.Menu == firewallNAT && !r.Dynamic && !onBit(r.Props["invalid"]) && strings.HasPrefix(r.Comment, "tikray:dns-") {
				dnsRules[r.Comment] = r
			}
		}
	}
	var clients []addrRange
	scopes := make(map[netip.Prefix][]affectedClass)
	for i := 1; i < len(views); i++ {
		old, next := &views[i-1], &views[i]
		for _, ch := range flowChanges(*old, *next) {
			if closedOnly && !ch.From.KillSwitch && !ch.To.KillSwitch {
				continue
			}
			if ch.StraySource {
				if clients == nil {
					clients = clientRanges(a.Topology)
				}
				if !validPrefix(ch.Source) || !rangeCovers(clients, ch.Source) {
					return nil, errTopology
				}
			}
			scopes[ch.Source] = append(scopes[ch.Source], affectedClass{ch, old, next})
		}
	}
	proof, err := readRepairBindings(o, a, views)
	if err != nil {
		return nil, err
	}
	// Freeze the candidate set before any removals. Re-opening a socket or
	// revisiting a pending view must not put a new binding in this purge.
	candidates := make(map[string]Row)
	var queried netip.Prefix
	for _, p := range slices.SortedFunc(maps.Keys(scopes), comparePrefix) {
		// Sorted prefixes put each enclosing prefix before its children.
		// A later target can narrow the original changed subnet to one host.
		if queried.Contains(p.Addr()) {
			continue
		}
		queried = p
		rows, err := o.readConnections(ipv4Connections, ipv4FlowFields, sourceQuery(p), time.Now().Add(conntrackProofWindow))
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			src, dst, err := parseConnection(r, false)
			if err != nil || !p.Contains(src) {
				return nil, ErrProtocol
			}
			affected, closed := false, false
			for bits := 32; bits >= p.Bits() && !closed; bits-- {
				class := netip.PrefixFrom(src, bits).Masked()
				for _, d := range scopes[class] {
					if d.change.StraySource {
						affected = affected || proof.strayBinding(d.change, r, src, dst)
						continue
					}
					if !proof.healthyDNS(d, r, src) && d.includes(src, dst, r) {
						affected = true
						closed = closed || d.closed(dst, isDNS(r))
					}
				}
			}
			if !affected || closedOnly && !closed || keepTargetPath && onNewPath(a.Topology, dnsRules, views[len(views)-1], r, src, dst) {
				continue
			}
			if !closed && !isDNS(r) && noConnMark(r) && len(a.Topology.ForeignRoutingMarks) > 0 {
				ownership := routingWriterMatch(a.Topology, r, src, dst)
				if ownership == ruleMatches {
					continue
				}
				if ownership == ruleUncertain {
					local, err := routerAddress(o, dst)
					if err != nil {
						return nil, err
					}
					if local {
						continue
					}
					return nil, errConflict
				}
			}
			if prev := candidates[r[".id"]]; prev != nil && !maps.Equal(prev, r) {
				return nil, errDrift
			}
			candidates[r[".id"]] = r
			if len(candidates) > maxReplyRows {
				return nil, ErrLimit
			}
		}
	}
	return candidates, nil
}
func removeIPv4Candidates(o observation, candidates map[string]Row) (int, error) {
	n := 0
	for _, id := range slices.Sorted(maps.Keys(candidates)) {
		r := candidates[id]
		// dst-address-type=local includes addresses on owner interfaces
		// outside the installation's LAN/WAN snapshot. DNS has its own NAT.
		if !isDNS(r) {
			local, err := routerAddress(o, netip.MustParseAddr(r["dst-address"]))
			if err != nil {
				return n, err
			}
			if local {
				continue
			}
		}
		done, err := removeConnection(o, ipv4Connections, r)
		if err != nil {
			return n, err
		}
		if done {
			n++
		}
	}
	return n, nil
}

func noConnMark(r Row) bool { return r["connection-mark"] == "" || r["connection-mark"] == "no-mark" }

// Identify a positive target route class or NAT binding from the observed
// rules and tuple. The engine verifies all permanent rules before release.
func onNewPath(t Topology, dnsRules map[string]Observed, v policyView, r Row, src, dst netip.Addr) bool {
	p := policyAt(v, number(src))
	ownedMark := r["connection-mark"] == "tikray-open" || r["connection-mark"] == "tikray-closed"
	if !isDNS(r) {
		if !proxyDestination(v, p, dst) {
			return !ownedMark
		}
		if !p.KillSwitch && !ownedMark && !noConnMark(r) {
			return true // open mangle leaves existing owner marks alone
		}
		return !onBit(r["fasttrack"]) && r["connection-mark"] == "tikray-"+policyClass(p)
	}
	if ownedMark || r["reply-src-port"] != "53" {
		return false
	}
	reply, e := netip.ParseAddr(r["reply-src-address"])
	if e != nil || !reply.Is4() {
		return false
	}
	if p.Mode == store.ModeDirect {
		return !onBit(r["dstnat"]) && reply == dst
	}
	if onBit(r["fasttrack"]) || !onBit(r["dstnat"]) {
		return false
	}
	key := string(p.Mode) + "-" + policyClass(p) + "-" + r["protocol"]
	primary, ok := dnsRules["tikray:dns-"+key]
	if !ok {
		return false
	}
	if !onBit(primary.Props["disabled"]) {
		return primary.Props["action"] == "dst-nat" && primary.Props["to-addresses"] == reply.String() && primary.Props["to-ports"] == "53"
	}
	fallback, ok := dnsRules["tikray:dns-router-"+key]
	return !p.KillSwitch && ok && !onBit(fallback.Props["disabled"]) && fallback.Props["action"] == "redirect" && slices.Contains(t.RouterIPs, reply) && slices.ContainsFunc(t.LANs, func(l LAN) bool { return l.Prefix.Contains(src) && l.Prefix.Contains(reply) })
}

func sourceQuery(p netip.Prefix) []string {
	if p.Bits() == 32 {
		return []string{"?src-address=" + p.Addr().String()}
	}
	_, end := span(p)
	last := end - 1
	hi := netip.AddrFrom4([4]byte{byte(last >> 24), byte(last >> 16), byte(last >> 8), byte(last)})
	return []string{"?src-address", "?<src-address=" + p.Addr().String(), "?#!", "?>src-address=" + hi.String(), "?#!"}
}

func routerAddress(o observation, addr netip.Addr) (bool, error) {
	menu := "/ip/address"
	if addr.Is6() {
		menu = "/ipv6/address"
	}
	// Address rows include their configured mask, which we do not know.
	// Chunk exact spellings to fit the native sentence limit on IPv6.
	for first := 0; first <= addr.BitLen(); first += 64 {
		var values []string
		for bits := first; bits <= min(addr.BitLen(), first+63); bits++ {
			values = append(values, netip.PrefixFrom(addr, bits).String())
		}
		if first == 0 {
			values = append(values, addr.String())
		}
		rows, err := o.read(menu, "address,disabled,invalid", valuesQuery("address", values...)...)
		if err != nil {
			return false, err
		}
		for _, r := range rows {
			if !slices.Contains(values, r["address"]) {
				return false, ErrProtocol
			}
			if !unavailableRow(r) {
				return true, nil
			}
		}
	}
	return false, nil
}

func parseConnection(r Row, v6 bool) (netip.Addr, netip.Addr, error) {
	src, e1 := netip.ParseAddr(r["src-address"])
	dst, e2 := netip.ParseAddr(r["dst-address"])
	if e1 != nil || e2 != nil || src.Is6() != v6 || dst.Is6() != v6 || src.Is4In6() || dst.Is4In6() || src.Zone() != "" || dst.Zone() != "" || !nativeRowID.MatchString(r[".id"]) {
		return src, dst, ErrProtocol
	}
	for _, k := range []string{"fasttrack", "dstnat"} {
		switch r[k] {
		case "", "true", "false", "yes", "no":
		default:
			return src, dst, ErrProtocol
		}
	}
	proto := r["protocol"]
	if proto == "" || len(proto) > 32 || strings.ContainsFunc(proto, func(c rune) bool { return !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') }) {
		return src, dst, ErrProtocol
	}
	for _, k := range []string{"src-port", "dst-port"} {
		if r[k] == "" && proto != "udp" && proto != "tcp" {
			continue
		}
		if _, err := strconv.ParseUint(r[k], 10, 16); err != nil {
			return src, dst, ErrProtocol
		}
	}
	for _, k := range []string{"icmp-type", "icmp-code", "icmp-id", "gre-protocol", "gre-version", "gre-key"} {
		if v := r[k]; v != "" {
			if _, err := strconv.ParseUint(v, 10, 32); err != nil {
				return src, dst, ErrProtocol
			}
		}
	}
	return src, dst, nil
}

// A projected ID may be retired while its kernel connection is still
// carrying traffic. A different ID on the same tuple needs a fresh policy
// classification; neither its disappearance nor its ownership is proved.
var errBindingChanged = errors.New("routeros: tracked connection identity changed")

const conntrackProofWindow = 4 * time.Second

// RouterOS can expire an entry while it builds even a source-filtered
// connection print, causing a definite trap. A trap proves nothing about
// presence. Retry only the same read on the same authenticated generation.
func (o observation) readConnections(menu, fields string, query []string, deadline time.Time) ([]Row, error) {
	rows, err := o.read(menu, fields, query...)
	if !errors.Is(err, ErrRejected) {
		return rows, err
	}
	retry, cancel := context.WithDeadline(o.ctx, deadline)
	defer cancel()
	o.ctx = retry
	for {
		if o.c.Generation() != o.gen {
			return nil, ErrStaleGeneration
		}
		select {
		case <-retry.Done():
			return nil, errors.Join(ErrRejected, retry.Err())
		case <-time.After(100 * time.Millisecond):
		}
		rows, err = o.read(menu, fields, query...)
		if !errors.Is(err, ErrRejected) {
			return rows, err
		}
	}
}

func removeConnection(o observation, menu string, prior Row) (bool, error) {
	if _, _, err := parseConnection(prior, menu == ipv6Connections); err != nil {
		return false, err
	}
	// A retired ID can make an otherwise valid /print trap on RouterOS.
	// Query the affected source and original tuple; compare the projected
	// ID locally so a new binding using the same tuple survives the purge.
	keys := strings.Split(originalTupleFields, ",")
	var query []string
	for _, k := range keys {
		if v, ok := prior[k]; ok {
			query = append(query, "?"+k+"="+v)
		}
	}
	fields := ipv4FlowFields
	if menu == ipv6Connections {
		fields = connectionFields + ",fasttrack"
	}
	read := func(deadline time.Time) (Row, error) {
		rows, err := o.readConnections(menu, fields, query, deadline)
		if err != nil || len(rows) == 0 {
			return nil, err
		}
		if len(rows) != 1 {
			return nil, errDrift
		}
		r := rows[0]
		if _, _, err := parseConnection(r, menu == ipv6Connections); err != nil {
			return nil, err
		}
		for _, k := range keys {
			if v, ok := prior[k]; ok {
				if got, present := r[k]; !present || got != v {
					return nil, ErrProtocol
				}
			}
		}
		if r[".id"] != prior[".id"] {
			return nil, errBindingChanged
		}
		return r, nil
	}
	row, err := read(time.Now().Add(conntrackProofWindow))
	if err != nil || row == nil {
		return false, err
	}
	if !maps.Equal(row, prior) {
		return false, errDrift
	}

	_, removeErr := o.c.CommandAt(o.ctx, o.gen, []string{menu + "/remove", "=.id=" + prior[".id"]})
	if removeErr != nil && !errors.Is(removeErr, ErrRejected) {
		return false, removeErr
	}
	// The row can expire after our identity check and before RouterOS
	// receives remove. Its native print can also lag an expiry or an
	// acknowledged deletion. Prove absence on this generation without
	// replaying a mutation; only an acknowledgement counts as a removal.
	deadline := time.Now().Add(conntrackProofWindow)
	for {
		row, err = read(deadline)
		if err != nil {
			return false, err
		}
		if row == nil {
			return removeErr == nil, nil
		}
		if !maps.Equal(row, prior) || !time.Now().Before(deadline) {
			if removeErr != nil {
				return false, removeErr
			}
			return false, errDrift
		}
		select {
		case <-o.ctx.Done():
			return false, o.ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type v6Selector struct{ iface, mac string }
type v6Rules map[v6Selector]bool // true rejects, false is an explicit return

func ipv6Selectors(v policyView) v6Rules {
	rules := v6Rules{}
	for _, r := range v.V6 {
		if r.Props["chain"] == ipv6Chain {
			rules[v6Selector{r.Props["in-interface"], r.Props["src-mac-address"]}] = r.Props["action"] == "reject"
		}
	}
	return rules
}
func (r v6Rules) rejects(s v6Selector) bool {
	if reject, ok := r[s]; ok {
		return reject
	}
	return r[v6Selector{iface: s.iface}]
}
func tightenedSelectors(views []policyView) map[v6Selector]bool {
	out := map[v6Selector]bool{}
	var old v6Rules
	for i, v := range views {
		next := ipv6Selectors(v)
		if i > 0 {
			for _, rules := range []v6Rules{old, next} {
				for s := range rules {
					if !old.rejects(s) && next.rejects(s) {
						out[s] = true
					}
				}
			}
		}
		old = next
	}
	return out
}
func offBit(s string) bool { return s == "false" || s == "no" }

// Check the admission condition before persisting or staging a new intent.
// If the evidence changes later, purgeIPv6 repeats it under the staged guard.
func checkFlowScope(ctx context.Context, c Native, a Actual, views []policyView) error {
	if a.Generation == 0 || a.Generation != c.Generation() {
		return ErrStaleGeneration
	}
	o := observation{ctx: ctx, c: c, gen: a.Generation}
	if len(a.Topology.ForeignRoutingMarks) > 0 {
		if _, err := ipv4Candidates(o, a, views, false, false); err != nil {
			return err
		}
	}
	if len(tightenedSelectors(views)) == 0 {
		return nil
	}
	requireCoverage, err := needsIPv6Coverage(o, a)
	if err != nil {
		return err
	}
	if requireCoverage {
		return ErrIPv6FlowScope
	}
	return nil
}

func needsIPv6Coverage(o observation, a Actual) (bool, error) {
	settings, err := o.read("/ipv6/settings", "disable-ipv6,forward,ipv6-fasttrack-active,ipv6-fasttrack-packets", "?forward")
	if err != nil {
		return false, err
	}
	if len(settings) != 1 {
		return false, ErrIPv6FlowScope
	}
	s := settings[0]
	if onBit(s["disable-ipv6"]) || offBit(s["forward"]) {
		return false, nil
	}
	if !offBit(s["disable-ipv6"]) || !onBit(s["forward"]) {
		return false, ErrIPv6FlowScope
	}
	packets, err := strconv.ParseUint(s["ipv6-fasttrack-packets"], 10, 64)
	if err != nil || !onBit(s["ipv6-fasttrack-active"]) && !offBit(s["ipv6-fasttrack-active"]) {
		return false, ErrIPv6FlowScope
	}
	dummy := slices.ContainsFunc(a.Rows, func(r Observed) bool { return r.Menu == ipv6Filter && dummyRule(r) })
	return a.IPv6FastTrack || dummy || onBit(s["ipv6-fasttrack-active"]) || packets != 0, nil
}

func purgeIPv6(o observation, a Actual, views []policyView) (int, error) {
	selectors := tightenedSelectors(views)
	if len(selectors) == 0 {
		return 0, nil
	}
	requireCoverage, err := needsIPv6Coverage(o, a)
	if err != nil || !requireCoverage {
		return 0, err
	}

	// A dedicated interface can have arbitrary SLAAC and delegated sources.
	// Its DHCP or neighbor population cannot authorize a whole-port sweep.
	for selector := range selectors {
		if selector.mac == "" {
			return 0, ErrIPv6FlowScope
		}
	}
	n := 0
	for selector := range selectors {
		neighbors, err := o.read("/ipv6/neighbor", "mac-address,interface,address,status,disabled", "?mac-address="+selector.mac, "?interface="+selector.iface)
		if err != nil {
			return n, err
		}
		for _, neighbor := range neighbors {
			if neighbor["interface"] != selector.iface || !strings.EqualFold(neighbor["mac-address"], selector.mac) {
				return n, ErrProtocol
			}
			address, err := netip.ParseAddr(neighbor["address"])
			if err != nil || !address.Is6() || address.Is4In6() {
				return n, ErrProtocol
			}
			if !address.IsGlobalUnicast() || address.Zone() != "" || !validNeighbor(neighbor) {
				continue
			}
			q := append([]string{"?src-address=" + address.String()}, valuesQuery("fasttrack", "true", "yes")...)
			rows, err := o.readConnections(ipv6Connections, connectionFields+",fasttrack", q, time.Now().Add(conntrackProofWindow))
			if err != nil {
				return n, err
			}
			for _, r := range rows {
				src, dst, err := parseConnection(r, true)
				if err != nil || src != address || !onBit(r["fasttrack"]) {
					return n, ErrProtocol
				}
				if !dst.IsGlobalUnicast() {
					continue
				}
				local, err := routerAddress(o, dst)
				if err != nil {
					return n, err
				}
				if local {
					continue
				}
				// A neighbor may be replaced between discovery and removal.
				// Check uniqueness across interfaces before matching its MAC.
				count, err := o.count("/ipv6/neighbor", "?address="+address.String())
				if err != nil {
					return n, err
				}
				if count != 1 {
					return n, ErrIPv6FlowScope
				}
				bindings, err := o.read("/ipv6/neighbor", "mac-address,interface,address,status,disabled", "?address="+address.String(), "?interface="+selector.iface, "?mac-address="+selector.mac)
				if err != nil {
					return n, err
				}
				if len(bindings) != 1 || bindings[0]["address"] != address.String() || bindings[0]["interface"] != selector.iface || !strings.EqualFold(bindings[0]["mac-address"], selector.mac) || !validNeighbor(bindings[0]) {
					return n, ErrIPv6FlowScope
				}
				done, err := removeConnection(o, ipv6Connections, r)
				if err != nil {
					return n, err
				}
				if done {
					n++
				}
			}
		}
	}
	// A live neighbor is positive evidence for this address only. A former
	// privacy address can have a surviving FastTrack binding after eviction.
	// Without exhaustive origin evidence the staged protection must remain.
	return n, ErrIPv6FlowScope
}
func validNeighbor(r Row) bool {
	return !unavailableRow(r) && (r["status"] == "reachable" || r["status"] == "permanent")
}
