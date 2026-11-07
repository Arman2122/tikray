package routeros

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/store"
)

const (
	firewallMangle = "/ip/firewall/mangle"
	firewallFilter = "/ip/firewall/filter"
	firewallNAT    = "/ip/firewall/nat"
	preChain       = "tikray-pre"
	egressChain    = "tikray-egress"
	proxyPacket    = "tikray-proxied"
)

var errFastTrack = errors.New("routeros: unsupported FastTrack arrangement")
var nativeRowID = regexp.MustCompile(`^\*[0-9a-fA-F]{1,16}$`)

// ipv4Policy receives disjoint, LAN-scoped source classes. The order within
// each chain is significant even on repair of a single missing rule.
func ipv4Policy(in PolicyInput, obs Topology, active map[store.Policy]bool) ([]Object, error) {
	var policies []store.Policy
	for _, mode := range []store.Mode{store.ModeSmart, store.ModeFull} {
		for _, closed := range []bool{false, true} {
			p := store.Policy{Mode: mode, KillSwitch: closed}
			if active[p] {
				policies = append(policies, p)
			}
		}
	}
	if len(policies) == 0 {
		return nil, nil
	}
	ft, err := fastTrackException(obs.FastTrack)
	if err != nil {
		return nil, err
	}
	runner := in.Network.Runner().String()
	out := policyRoutes(runner, obs.WAN[0].nextHop())
	out = append(out, egressGuard(obs.LANList, policies)...)
	out = append(out, policyDNS(runner, obs.LANList, policies)...)
	for _, class := range []string{"open", "closed"} {
		mark := "tikray-" + class
		out = append(out, object(firewallMangle, "mss-"+class, map[string]string{
			"chain": "forward", "connection-mark": mark, "protocol": "tcp", "tcp-flags": "syn",
			"action": "change-mss", "new-mss": "clamp-to-pmtu", "passthrough": "yes",
		}))
		if ft != nil {
			out = append(out, object(firewallMangle, "packet-"+class, map[string]string{
				"chain": "forward", "connection-mark": mark, "packet-mark": "no-mark",
				"action": "mark-packet", "new-packet-mark": proxyPacket, "passthrough": "yes",
			}))
		}
	}
	if ft != nil {
		out = append(out, *ft)
	}

	out = append(out, object(firewallMangle, "skip-router", map[string]string{
		"chain": preChain, "dst-address-type": "local", "action": "return",
	}))
	// On v7 an unmarked packet does not match routing-mark=main, and
	// routing-mark=no-mark is not a generic matcher. Preserve every mark
	// the observed overlapping owner rules can pass down to our hook.
	foreignMarks := slices.Clone(obs.ForeignRoutingMarks)
	slices.Sort(foreignMarks)
	for _, mark := range slices.Compact(foreignMarks) {
		if !interfaceName(mark) || mark == "tikray-open" || mark == "tikray-closed" {
			return nil, errConflict
		}
		sum := sha256.Sum256([]byte(mark))
		out = append(out, object(firewallMangle, fmt.Sprintf("skip-owner-route:%x", sum[:16]), map[string]string{
			"chain": preChain, "routing-mark": mark, "action": "return",
		}))
	}
	// DNS's destination is translated after mangle. A routing mark here
	// would send the translated runner address into a fallback default route.
	for _, proto := range []string{"tcp", "udp"} {
		out = append(out, object(firewallMangle, "skip-dns-"+proto, map[string]string{
			"chain": preChain, "protocol": proto, "dst-port": "53", "connection-mark": "no-mark", "action": "return",
		}))
	}
	out = append(out, object(firewallMangle, "skip-local", map[string]string{
		"chain": preChain, "connection-mark": "no-mark", "dst-address-list": "tikray-local", "action": "return",
	}))
	for _, p := range policies {
		class := policyClass(p)
		match := map[string]string{
			"chain": preChain, "connection-state": "new", "connection-mark": "no-mark",
			"src-address-list": srcList(p), "action": "mark-connection",
			"new-connection-mark": "tikray-" + class, "passthrough": "yes",
		}
		if p.Mode == store.ModeSmart {
			match["dst-address-list"] = "!tikray-domestic"
		}
		out = append(out, object(firewallMangle, "conn-"+string(p.Mode)+"-"+class, match))
	}
	for _, class := range []string{"open", "closed"} {
		mark := "tikray-" + class
		out = append(out, object(firewallMangle, "route-"+class, map[string]string{
			"chain": preChain, "connection-mark": mark, "action": "mark-routing",
			"new-routing-mark": mark, "passthrough": "no",
		}, "tikray:route-"+class+"-runner", "tikray:route-"+class+"-fallback"))
	}
	// Append after the owner's prerouting marks. Only this verified LAN can
	// start the forward leg; runner replies and WAN replies never enter.
	jump := object(firewallMangle, "jump-pre", map[string]string{
		"chain": "prerouting", "in-interface-list": obs.LANList, "src-address-type": "!local",
		"action": "jump", "jump-target": preChain,
	})
	for _, r := range out {
		jump.DependsOn = append(jump.DependsOn, r.Comment)
	}
	return append(out, jump), nil
}

func policyClass(p store.Policy) string {
	if p.KillSwitch {
		return "closed"
	}
	return "open"
}

func policyRoutes(runner, wanGateway string) []Object {
	var out []Object
	for _, class := range []string{"open", "closed"} {
		table := "tikray-" + class
		tableRow := object("/routing/table", "table-"+class, map[string]string{"name": table, "fib": "yes"})
		primary := object("/ip/route", "route-"+class+"-runner", map[string]string{
			"dst-address": "0.0.0.0/0", "routing-table": table, "distance": "1", "gateway": runner, "check-gateway": "ping",
		}, tableRow.Comment)
		fallback := object("/ip/route", "route-"+class+"-fallback", map[string]string{
			"dst-address": "0.0.0.0/0", "routing-table": table, "distance": "2",
		}, tableRow.Comment)
		if class == "closed" {
			fallback.Props["blackhole"] = "yes"
		} else {
			fallback.Props["gateway"] = wanGateway
		}
		out = append(out, tableRow, primary, fallback)
	}
	return out
}

func egressGuard(lan string, policies []store.Policy) []Object {
	// Translated DNS belongs on the bridge or in router input (open
	// fallback). An owner routing mark can forward either translation out
	// a different interface even if the destination appears local.
	var out []Object
	for _, p := range policies {
		for _, proto := range []string{"tcp", "udp"} {
			out = append(out, object(firewallFilter, "egress-dns-"+string(p.Mode)+"-"+policyClass(p)+"-"+proto, map[string]string{
				"chain": egressChain, "action": "drop", "src-address-list": srcList(p), "connection-nat-state": "dstnat",
				"protocol": proto, "dst-port": "53",
			}))
		}
	}
	// An existing flow keeps its original class until invalidation. The
	// source rules also work if a missing table invalidates mark-routing.
	out = append(out,
		object(firewallFilter, "egress-drop-marked", map[string]string{"chain": egressChain, "connection-mark": "tikray-closed", "action": "drop"}),
		object(firewallFilter, "egress-skip-local", map[string]string{"chain": egressChain, "dst-address-list": "tikray-local", "action": "return"}),
	)
	for _, p := range policies {
		if !p.KillSwitch {
			continue
		}
		match := map[string]string{"chain": egressChain, "action": "drop", "src-address-list": srcList(p)}
		if p.Mode == store.ModeSmart {
			match["dst-address-list"] = "!tikray-domestic"
		}
		out = append(out, object(firewallFilter, "egress-drop-"+string(p.Mode), match))
	}
	jump := object(firewallFilter, "egress-guard", map[string]string{
		"chain": "forward", "in-interface-list": lan, "out-interface": "!tikray",
		"action": "jump", "jump-target": egressChain,
	})
	jump.Before = "first:forward"
	for _, r := range out {
		jump.DependsOn = append(jump.DependsOn, r.Comment)
	}
	return append(out, jump)
}

func policyDNS(runner, lanList string, policies []store.Policy) []Object {
	var out []Object
	var open []string
	for _, p := range policies {
		for _, proto := range []string{"tcp", "udp"} {
			key := string(p.Mode) + "-" + policyClass(p) + "-" + proto
			primary := object(firewallNAT, "dns-"+key, map[string]string{
				"chain": "dstnat", "in-interface-list": lanList, "src-address-list": srcList(p),
				"protocol": proto, "dst-port": "53", "action": "dst-nat", "to-addresses": runner, "to-ports": "53",
			})
			primary.Before = "first:dstnat"
			primary.InitialDisabled = !p.KillSwitch
			out = append(out, primary)
			if !p.KillSwitch {
				open = append(open, primary.Comment)
				// A client with a hardcoded resolver must also use the router's
				// resolver when netwatch disables the preceding runner redirect.
				fallback := object(firewallNAT, "dns-router-"+key, maps.Clone(primary.Props))
				fallback.Props["action"] = "redirect"
				delete(fallback.Props, "to-addresses")
				fallback.Before = "first:dstnat"
				out = append(out, fallback)
			}
		}
	}
	// Only exact, compiler-controlled tags enter scripts. Checking the bit
	// before each mutation makes a healthy periodic probe a read-only pass.
	script := func(verb, disabled string) string {
		var b strings.Builder
		for _, tag := range open {
			fmt.Fprintf(&b, `:foreach id in=[/ip/firewall/nat/find where comment="%s" and disabled=%s] do={/ip/firewall/nat/%s $id};`, tag, disabled, verb)
		}
		return b.String()
	}
	up, down := script("enable", "yes"), script("disable", "no")
	watch := object("/tool/netwatch", "runner-watch", map[string]string{
		"host": runner, "type": "simple", "interval": "5s", "timeout": "1s", "startup-delay": "0s", "start-delay": "0s",
		"up-script": up, "down-script": down,
		// Recreated rows start disabled even if a previous probe was up.
		"test-script": `:if ($status = "up") do={` + up + `} else={` + down + `}`,
	}, open...)
	return append(out, watch)
}

func fastTrackException(rules []FastTrackRule) (*Object, error) {
	var exception *Object
	for _, r := range rules {
		if !nativeRowID.MatchString(r.ID) {
			return nil, errFastTrack
		}
		// A positive owner connection mark (including no-mark) excludes
		// both of our connection classes, so this rule needs no exception.
		if cm := r.Match["connection-mark"]; cm != "" {
			if strings.HasPrefix(cm, "!") || cm == "tikray-open" || cm == "tikray-closed" {
				return nil, errFastTrack
			}
			continue
		}
		if exception != nil || r.Logged {
			return nil, errFastTrack
		}
		switch r.Match["connection-state"] {
		case "established", "related", "established,related", "related,established":
		default:
			return nil, errFastTrack
		}
		// Duplicating a stateful matcher (nth, limit, random, etc.) would
		// change the owner's decision on this very packet. Only copy known
		// stateless eligibility predicates, unchanged.
		for k, v := range r.Match {
			switch k {
			case "connection-state", "protocol", "in-interface", "out-interface", "in-interface-list", "out-interface-list",
				"src-address", "dst-address", "src-address-list", "dst-address-list", "src-port", "dst-port",
				"connection-nat-state", "ipsec-policy", "tcp-flags":
				if v == "" || strings.ContainsAny(v, "\r\n\x00") {
					return nil, errFastTrack
				}
			default:
				return nil, errFastTrack
			}
		}
		// FastTrack leaves some packets on the slow path. Replacing its
		// action by accept is safe only where the owner's immediate next
		// rule already accepts *every* one of those packets.
		if !slowPathAccepts(r) {
			return nil, errFastTrack
		}
		match := maps.Clone(r.Match)
		match["chain"], match["action"], match["packet-mark"] = "forward", "accept", proxyPacket
		accept := object(firewallFilter, "no-fasttrack", match, "tikray:packet-open", "tikray:packet-closed")
		accept.Before = r.ID
		exception = &accept
	}
	return exception, nil
}

func slowPathAccepts(ft FastTrackRule) bool {
	next := ft.Next
	if next == nil || !nativeRowID.MatchString(next.ID) || next.ID == ft.ID || next.Logged || next.Action != "accept" {
		return false
	}
	for key, predicate := range next.Match {
		if key == "connection-state" {
			accepted := strings.Split(predicate, ",")
			for _, state := range accepted {
				switch state {
				case "established", "related", "new", "invalid", "untracked":
				default:
					return false
				}
			}
			for _, state := range strings.Split(ft.Match[key], ",") {
				if !slices.Contains(accepted, state) {
					return false
				}
			}
		} else if predicate == "" || ft.Match[key] != predicate {
			return false
		}
	}
	return true
}
