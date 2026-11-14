package routeros

import (
	"context"
	"net/netip"
	"slices"
	"strings"
)

// Observe reads the current session's policy rows and only the owner facts
// used by the compiler, the transition guards or an ordered insertion.
func Observe(ctx context.Context, c Native, scope InstallScope) (Actual, error) {
	o := observation{ctx: ctx, c: c, gen: c.Generation()}
	if o.gen == 0 {
		return Actual{}, ErrStaleGeneration
	}
	t, leases, e := o.topology(scope)
	if e != nil {
		return Actual{}, e
	}
	a := Actual{Generation: o.gen, Topology: t, Leases: leases}
	for _, menu := range managedMenus {
		rows, e := o.ownedRows(menu)
		if e != nil {
			return Actual{}, e
		}
		// The private chains contain only our rows (foreign references are
		// checked separately). Built-in chains also require owner order.
		var chains []string
		switch menu {
		case firewallFilter, ipv6Filter:
			chains = []string{"forward", "input"}
		case firewallNAT:
			chains = []string{"dstnat", "srcnat"}
		case firewallMangle:
			chains = []string{"prerouting", "forward"}
		}
		for _, chain := range chains {
			ordered, e := o.order(menu, chain)
			if e != nil {
				return Actual{}, e
			}
			byID := map[string]Observed{}
			for _, r := range rows {
				if r.Props["chain"] == chain {
					byID[r.ID] = r
				}
			}
			for i, r := range ordered {
				if own, found := byID[r.ID]; found {
					if own.Comment != r.Comment || own.Dynamic != r.Dynamic || own.Props["action"] != r.Props["action"] {
						return Actual{}, errDrift
					}
					ordered[i] = own
					delete(byID, r.ID)
				} else if ownedRole(menu, r.Comment) {
					return Actual{}, errDrift
				}
			}
			if len(byID) != 0 {
				return Actual{}, errDrift
			}
			if menu == firewallFilter && chain == "forward" {
				a.Topology.FastTrack, e = o.fastTrack(ordered)
				if e != nil {
					return Actual{}, e
				}
			}
			if menu == ipv6Filter && chain == "forward" {
				a.IPv6FastTrack = slices.ContainsFunc(ordered, func(r Observed) bool {
					return r.Props["action"] == "fasttrack-connection" && !onBit(r.Props["disabled"])
				})
			}
			a.Rows = append(a.Rows, ordered...)
		}
		for _, r := range rows {
			if !slices.Contains(chains, r.Props["chain"]) {
				a.Rows = append(a.Rows, r)
			}
		}
	}
	if e = checkReferences(ctx, c, o.gen); e != nil {
		if e != errConflict {
			return Actual{}, e
		}
		a.Topology.ForeignRefs = append(a.Topology.ForeignRefs, ForeignRef{Property: "reserved reference"})
	}
	if e = o.ownerInteractions(&a.Topology); e != nil {
		return Actual{}, e
	}
	if c.Generation() != o.gen {
		return Actual{}, ErrStaleGeneration
	}
	return a, nil
}

func (o observation) ownedRows(menu string) ([]Observed, error) {
	q := prefixQuery("comment", "tikray:")
	// The routing data plane can contain a full Internet table. Request the
	// four precise tags even if a table reference has drifted, never its peers.
	switch menu {
	case routeMenu:
		q = valuesQuery("comment", "tikray:route-open-runner", "tikray:route-open-fallback", "tikray:route-closed-runner", "tikray:route-closed-fallback")
	case tableMenu:
		q = valuesQuery("comment", "tikray:table-open", "tikray:table-closed")
	case watchMenu:
		q = []string{"?comment=tikray:runner-watch"}
	}
	fields := managedFields(menu)
	rows, e := o.read(menu, ".id,comment,dynamic,"+strings.Join(fields, ","), q...)
	if e != nil {
		return nil, e
	}
	var out []Observed
	for _, r := range rows {
		if !ownedRole(menu, r["comment"]) {
			continue
		}
		obj := Observed{Menu: menu, ID: r[".id"], Comment: r["comment"], Dynamic: onBit(r["dynamic"]), Props: map[string]string{}}
		if !nativeRowID.MatchString(obj.ID) {
			return nil, ErrProtocol
		}
		// A peer may include extra columns even with a proplist.
		for _, k := range fields {
			if v, ok := r[k]; ok {
				obj.Props[k] = v
			}
		}
		out = append(out, obj)
	}
	return out, nil
}
func (o observation) order(menu, chain string) ([]Observed, error) {
	rows, e := o.read(menu, ".id,comment,dynamic,chain,action,disabled,invalid", "?chain="+chain)
	if e != nil {
		return nil, e
	}
	out := make([]Observed, 0, len(rows))
	for _, r := range rows {
		if !nativeRowID.MatchString(r[".id"]) || r["chain"] != chain {
			return nil, ErrProtocol
		}
		out = append(out, Observed{Menu: menu, ID: r[".id"], Comment: r["comment"], Dynamic: onBit(r["dynamic"]), Props: map[string]string{"chain": chain, "action": r["action"], "disabled": r["disabled"], "invalid": r["invalid"]}})
	}
	return out, nil
}

func readForward(ctx context.Context, c Native, gen uint64) ([]FastTrackRule, error) {
	o := observation{ctx: ctx, c: c, gen: gen}
	rows, e := o.order(firewallFilter, "forward")
	if e != nil {
		return nil, e
	}
	return o.fastTrack(rows)
}
func (o observation) fastTrack(rows []Observed) ([]FastTrackRule, error) {
	var rules []FastTrackRule
	for i, r := range rows {
		if r.Props["action"] != "fasttrack-connection" || onBit(r.Props["disabled"]) {
			continue
		}
		if onBit(r.Props["invalid"]) {
			return nil, errDrift
		}
		f, e := o.forwardDetail(r)
		if e != nil {
			return nil, e
		}
		rule := FastTrackRule{ID: f.ID, Match: f.Match, Logged: f.Logged}
		for _, after := range rows[i+1:] {
			if ownedRole(after.Menu, after.Comment) || dummyRule(after) || onBit(after.Props["disabled"]) {
				continue
			}
			if onBit(after.Props["invalid"]) {
				return nil, errDrift
			}
			next, e := o.forwardDetail(after)
			if e != nil {
				return nil, e
			}
			rule.Next = &next
			break
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

const allowedPredicates = "connection-state,connection-mark,protocol,in-interface,out-interface,in-interface-list,out-interface-list,src-address,dst-address,src-address-list,dst-address-list,src-port,dst-port,connection-nat-state,ipsec-policy,tcp-flags"

// Some matchers are stateful; others can carry arbitrary private text. Read
// only their presence. An accept conditional on any of them cannot establish
// unconditional slow-path eligibility for an inserted FastTrack exception.
var unsupportedPredicates = strings.Fields("src-mac-address src-address-type dst-address-type port ipv4-options ttl dscp packet-size tls-host tcp-mss tcp-option icmp-options ingress-priority priority packet-mark routing-mark hotspot connection-type connection-bytes connection-limit connection-rate content psd layer7-protocol random nth per-connection-classifier limit dst-limit time realm p2p in-bridge-port out-bridge-port in-bridge-port-list out-bridge-port-list fragment")

func (o observation) forwardDetail(r Observed) (ForwardRule, error) {
	q := []string{"?.id=" + r.ID, "?chain=forward", "?action=" + r.Props["action"]}
	rows, e := o.read(firewallFilter, ".id,action,log,disabled,invalid,"+allowedPredicates, q...)
	if e != nil {
		return ForwardRule{}, e
	}
	if len(rows) != 1 || rows[0][".id"] != r.ID || unavailableRow(rows[0]) {
		return ForwardRule{}, errDrift
	}
	f := ForwardRule{ID: r.ID, Action: rows[0]["action"], Logged: onBit(rows[0]["log"]), Match: map[string]string{}}
	for _, k := range strings.Split(allowedPredicates, ",") {
		if v := rows[0][k]; v != "" {
			f.Match[k] = v
		}
	}
	n, e := o.count(firewallFilter, append(q, predicatesPresent(unsupportedPredicates)...)...)
	if e != nil {
		return ForwardRule{}, e
	}
	if n != 0 {
		f.Match["unsupported"] = "present"
	}
	return f, nil
}

func predicatesPresent(fields []string) []string {
	var parts [][]string
	for _, k := range fields {
		parts = append(parts, []string{"?" + k})
	}
	return anyQuery(parts...)
}

// Inspect the presence (never the text) of selectors not owned by the
// compiler. Otherwise an extra time/limit predicate on a closed guard would
// disappear from the projected row and the diff could declare a false no-op.
func (o observation) checkHiddenMatchers() error {
	for _, menu := range []string{firewallFilter, ipv6Filter, firewallMangle, firewallNAT} {
		fields := slices.Clone(unsupportedPredicates)
		if menu == ipv6Filter {
			fields = append(fields, "ipv6-header", "header", "hop-limit", "icmpv6-options")
		}
		managed := managedFields(menu)
		fields = slices.DeleteFunc(fields, func(k string) bool { return slices.Contains(managed, k) })
		q := append(prefixQuery("comment", "tikray:"), predicatesPresent(fields)...)
		rows, e := o.read(menu, "comment", q...)
		if e != nil {
			return e
		}
		for _, r := range rows {
			if ownedRole(menu, r["comment"]) {
				return errConflict
			}
		}
	}
	return nil
}

// Re-run immediately before operations that depend on private resource names.
// A foreign row can refer to a private resource without itself carrying any
// ownership tag. False replies (including protocol errors) are never zeroes.
func checkReferences(ctx context.Context, c Native, gen uint64) error {
	o := observation{ctx: ctx, c: c, gen: gen}
	for _, class := range []string{"open", "closed"} {
		table := "tikray-" + class
		allowed := valuesQuery("comment", "tikray:route-"+class+"-runner", "tikray:route-"+class+"-fallback")
		q := append([]string{"?routing-table=" + table}, allowed...)
		q = append(q, "?#!")
		n, e := o.count(routeMenu, q...)
		if e != nil {
			return e
		}
		if n != 0 {
			return errConflict
		}
		// The FIB is shared by both IP families. M3 owns no IPv6 routes.
		n, e = o.count("/ipv6/route", "?routing-table="+table)
		if e != nil {
			return e
		}
		if n != 0 {
			return errConflict
		}
		n, e = o.count(tableMenu, "?name="+table, "?comment=tikray:table-"+class, "?#!")
		if e != nil {
			return e
		}
		if n != 0 {
			return errConflict
		}
	}
	// Select only references to this namespace. Some installation resources
	// also start with tikray-: positively identify policy names below.
	type probe struct{ menu, fields string }
	probes := []probe{
		{"/routing/rule", "table routing-mark"},
		{addressListMenu, "list"},
		{"/queue/tree", "packet-mark"},
		{"/queue/simple", "packet-marks"},
	}
	for _, m := range []string{firewallFilter, firewallMangle, firewallNAT, "/ip/firewall/raw", ipv6Filter, "/ipv6/firewall/mangle", "/ipv6/firewall/nat", "/ipv6/firewall/raw"} {
		// Shared address lists, chains and marks can be referenced from a
		// different firewall facility than the rule that creates them.
		probes = append(probes, probe{m, "chain jump-target src-address-list dst-address-list address-list connection-mark new-connection-mark routing-mark new-routing-mark packet-mark new-packet-mark"})
	}
	for _, p := range probes {
		fields := strings.Fields(p.fields)
		var alternatives [][]string
		for _, f := range fields {
			alternatives = append(alternatives, prefixQuery(f, "tikray-"), prefixQuery(f, "!tikray-"))
		}
		query := anyQuery(alternatives...)
		if p.menu == "/queue/simple" {
			// A simple queue accepts a comma-separated mark set. A reserved mark
			// may follow another mark, outside either lexicographic prefix range.
			query = []string{"?packet-marks", "?packet-marks=", "?#!"}
		}
		rows, e := o.read(p.menu, "comment,"+strings.Join(fields, ","), query...)
		if e != nil {
			return e
		}
		for _, r := range rows {
			if ownedRole(p.menu, r["comment"]) {
				continue
			}
			for _, f := range fields {
				for _, v := range strings.Split(r[f], ",") {
					if reservedPolicyName(strings.TrimPrefix(v, "!")) {
						return errConflict
					}
				}
			}
		}
	}
	return o.checkHiddenMatchers()
}
func reservedPolicyName(name string) bool {
	switch name {
	case "tikray-open", "tikray-closed", preChain, egressChain, ipv6Chain, proxyPacket, "tikray-local", "tikray-domestic", "tikray-src-full-open", "tikray-src-full-closed", "tikray-src-smart-open", "tikray-src-smart-closed":
		return true
	}
	digest, ok := strings.CutPrefix(name, "tikray-h")
	return ok && isHold("tikray:hold:"+digest)
}

// Only a positive disjoint ingress or address excludes an owner rule. A
// negated address/list or opaque matcher cannot prove disjoint traffic.
func mightOriginateOnLAN(r Row, t *Topology) bool {
	if iface := r["in-interface"]; interfaceName(iface) && !slices.Contains(t.LANMembers, iface) {
		return false
	}
	if r["in-interface-list"] == "!"+t.LANList {
		return false
	}
	if src := r["src-address"]; src != "" && !addressHitsLAN(src, t.LANs) {
		return false
	}
	return true
}
func addressHitsLAN(value string, lans []LAN) bool {
	if a, e := netip.ParseAddr(value); e == nil {
		return slices.ContainsFunc(lans, func(l LAN) bool { return l.Prefix.Contains(a) })
	}
	if p, e := netip.ParsePrefix(value); e == nil {
		return slices.ContainsFunc(lans, func(l LAN) bool { return l.Prefix.Overlaps(p) })
	}
	if low, high, ok := strings.Cut(value, "-"); ok {
		a, e1 := netip.ParseAddr(low)
		b, e2 := netip.ParseAddr(high)
		if e1 == nil && e2 == nil && a.Is4() && b.Is4() && a.Compare(b) <= 0 {
			return slices.ContainsFunc(lans, func(l LAN) bool { lo, hi := span(l.Prefix); return number(a) < hi && number(b) >= lo })
		}
	}
	return true
}
func mightReturnToLAN(r Row, t *Topology) bool {
	iface := r["out-interface"]
	return (!interfaceName(iface) || slices.Contains(t.LANMembers, iface)) && addressHitsLAN(r["dst-address"], t.LANs)
}
func mangleConflict(r Row, t *Topology) bool {
	// A packet/connection mark set on WAN ingress can change an established
	// reply's FastTrack eligibility. Inspect both directions for those actions.
	action, chain := r["action"], r["chain"]
	from, to := mightOriginateOnLAN(r, t), mightReturnToLAN(r, t)
	pass := normalized(firewallMangle, "passthrough", r["passthrough"]) == "yes"
	switch action {
	case "mark-packet":
		return chain != "postrouting" && (from || to)
	case "mark-connection":
		// Only a positive, non-owned connection mark excludes both classes.
		// no-mark is safe too: the owner's first classifier wins a new flow.
		cm := r["connection-mark"]
		if (from || to) && (cm == "" || strings.HasPrefix(cm, "!") || reservedPolicyName(cm)) {
			return true
		}
	case "mark-routing":
		if chain == "prerouting" && from {
			if !pass || !interfaceName(r["new-routing-mark"]) {
				return true
			}
			t.ForeignRoutingMarks = append(t.ForeignRoutingMarks, r["new-routing-mark"])
		}
	case "jump":
		return from || to // effects inside an unverified chain are unknown
	case "passthrough", "log", "change-mss", "change-ttl", "change-dscp", "set-priority", "add-src-to-address-list", "add-dst-to-address-list", "sniff-tzsp", "sniff-pc":
	default:
		return chain == "prerouting" && from || chain == "forward" && (from || to)
	}
	return !pass && (chain == "prerouting" && from || chain == "forward" && (from || to))
}

// Restrict mark evidence to selectors the connection reader can actually
// prove. A private string matcher or a random/time predicate contributes
// only its presence and never its value to a policy snapshot.
func (o observation) routingWriter(r Row) (RoutingMarkWriter, error) {
	const safe = "in-interface,in-interface-list,src-address,dst-address,protocol,src-port,dst-port,connection-mark"
	id, mark := r[".id"], r["new-routing-mark"]
	if !nativeRowID.MatchString(id) {
		return RoutingMarkWriter{}, ErrProtocol
	}
	q := []string{"?.id=" + id, "?chain=prerouting", "?action=mark-routing", "?new-routing-mark=" + mark}
	rows, e := o.read(firewallMangle, ".id,disabled,invalid,passthrough,"+safe, q...)
	if e != nil {
		return RoutingMarkWriter{}, e
	}
	if len(rows) != 1 || rows[0][".id"] != id || onBit(rows[0]["disabled"]) || normalized(firewallMangle, "passthrough", rows[0]["passthrough"]) != "yes" {
		return RoutingMarkWriter{}, errDrift
	}
	writer := RoutingMarkWriter{Mark: mark, Match: map[string]string{}, Opaque: onBit(rows[0]["invalid"])}
	fields := strings.Split(safe, ",")
	for _, f := range fields {
		if v := rows[0][f]; v != "" {
			writer.Match[f] = v
		}
	}
	other := slices.Concat(unsupportedPredicates, strings.Split(allowedPredicates, ","))
	other = slices.DeleteFunc(other, func(f string) bool { return slices.Contains(fields, f) })
	n, e := o.count(firewallMangle, append(q, predicatesPresent(other)...)...)
	if e != nil {
		return RoutingMarkWriter{}, e
	}
	writer.Opaque = writer.Opaque || n != 0
	return writer, nil
}
func (o observation) ownerInteractions(t *Topology) error {
	if err := o.sourceNAT(t); err != nil {
		return err
	}
	conflict := func(menu string) {
		t.ForeignRefs = append(t.ForeignRefs, ForeignRef{Menu: menu, Property: "overlapping owner policy"})
	}
	// Only a connection mark or a jump in postrouting can change a subsequent
	// packet's identity. Packet marks have already passed the forward filter.
	q := anyQuery(valuesQuery("chain", "forward", "prerouting"), append([]string{"?chain=postrouting"}, append(valuesQuery("action", "mark-connection", "jump"), "?#&")...))
	rows, e := o.read(firewallMangle, ".id,comment,chain,action,in-interface,in-interface-list,out-interface,src-address,dst-address,connection-mark,passthrough,new-routing-mark,disabled,invalid", q...)
	if e != nil {
		return e
	}
	for _, r := range rows {
		if onBit(r["disabled"]) || ownedRole(firewallMangle, r["comment"]) {
			continue
		}
		previous := len(t.ForeignRoutingMarks)
		if mangleConflict(r, t) {
			conflict(firewallMangle)
			continue
		}
		if len(t.ForeignRoutingMarks) > previous {
			writer, e := o.routingWriter(r)
			if e != nil {
				return e
			}
			t.RoutingMarkWriters = append(t.RoutingMarkWriters, writer)
		}
	}
	q = append([]string{"?chain=dstnat"}, valuesQuery("action", "dst-nat", "netmap", "jump", "endpoint-independent-nat", "dst-nat-to-hotspot")...)
	rows, e = o.read(firewallNAT, "comment,action,to-addresses,disabled,invalid", q...)
	if e != nil {
		return e
	}
	for _, r := range rows {
		if onBit(r["disabled"]) || ownedRole(firewallNAT, r["comment"]) {
			continue
		}
		if r["action"] == "jump" || addressHitsLAN(r["to-addresses"], t.LANs) {
			conflict(firewallNAT)
		}
	}
	rows, e = o.read("/ip/firewall/raw", "in-interface,in-interface-list,src-address,dst-address,disabled,invalid", "?chain=prerouting", "?action=notrack", "?action=jump", "?#|")
	if e != nil {
		return e
	}
	for _, r := range rows {
		if !onBit(r["disabled"]) && (mightOriginateOnLAN(r, t) || addressHitsLAN(r["dst-address"], t.LANs)) {
			conflict("/ip/firewall/raw")
		}
	}
	// A custom-chain FastTrack cannot supply the forward-chain adjacency
	// proved by the compiler. Never synthesize an exception ahead of a jump.
	for _, menu := range []string{firewallFilter, ipv6Filter} {
		rows, e = o.read(menu, "disabled,invalid", "?action=fasttrack-connection", "?chain=forward", "?#!")
		if e != nil {
			return e
		}
		for _, r := range rows {
			if !onBit(r["disabled"]) {
				conflict(menu)
			}
		}
	}
	q = append(valuesQuery("action", "lookup", "lookup-only-in-table"), anyQuery([]string{"?-interface"}, valuesQuery("interface", append(slices.Clone(t.LANMembers), "")...))...)
	rows, e = o.read("/routing/rule", "src-address,table,disabled,invalid", q...)
	if e != nil {
		return e
	}
	for _, r := range rows {
		if !onBit(r["disabled"]) && r["table"] != "main" && addressHitsLAN(r["src-address"], t.LANs) {
			conflict("/routing/rule")
		}
	}
	return nil
}

// EmergencyState never downloads a script body. A foreign object using either
// half of the marker identity blocks re-arm until the owner resolves it.
func EmergencyState(ctx context.Context, c Native, g uint64) (string, bool, error) {
	o := observation{ctx: ctx, c: c, gen: g}
	jobs, e := o.read("/system/script/job", ".id", "?script=tikray-emergency-off")
	if e != nil {
		return "", false, e
	}
	busy := len(jobs) > 0
	// A durable owner teardown fences a previously planned write even after
	// the import job exits or the router reboots. Never read its journal here.
	teardown, e := o.read("/system/script", ".id", "?name=tikray-uninstall-state")
	if e != nil {
		return "", false, e
	}
	if len(teardown) != 0 {
		return "", true, nil
	}
	rows, e := o.read("/system/script", ".id,name,comment,policy,dont-require-permissions", "?name=tikray-emergency-state", "?comment=tikray:emergency-state", "?#|")
	if e != nil {
		return "", busy, e
	}
	if len(rows) == 0 {
		return "", busy, nil
	}
	if len(rows) != 1 || rows[0]["name"] != "tikray-emergency-state" || rows[0]["comment"] != "tikray:emergency-state" || !inertMarkerRights(rows[0]) || !nativeRowID.MatchString(rows[0][".id"]) {
		return "", busy, errConflict
	}
	id := rows[0][".id"]
	rows, e = o.read("/system/script", ".id", "?.id="+id, "?name=tikray-emergency-state", "?comment=tikray:emergency-state", "?source=", "?-source", "?#|", "?source={}", "?#|")
	if e != nil {
		return "", busy, e
	}
	if len(rows) != 1 || rows[0][".id"] != id {
		return "", busy, errConflict
	}
	return id, busy, nil
}

// The restricted account must be able to inspect a marker's source. An
// absent source on a stronger script does not establish that it is inert.
func inertMarkerRights(r Row) bool {
	switch r["dont-require-permissions"] {
	case "", "false", "no":
	default:
		return false
	}
	rights := strings.FieldsFunc(r["policy"], func(c rune) bool { return c == ',' || c == ';' || c == ' ' })
	rights = slices.DeleteFunc(rights, func(right string) bool { return strings.HasPrefix(right, "!") })
	slices.Sort(rights)
	return slices.Equal(rights, []string{"read", "write"})
}

func ClearEmergency(ctx context.Context, c Native, g uint64, id string) error {
	got, running, e := EmergencyState(ctx, c, g)
	if e != nil {
		return e
	}
	if running || !nativeRowID.MatchString(id) || got != id {
		return errConflict
	}
	_, e = c.CommandAt(ctx, g, []string{"/system/script/remove", "=.id=" + id})
	return e
}
