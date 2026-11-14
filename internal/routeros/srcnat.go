package routeros

import (
	"maps"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/store"
)

// Source NAT runs after routing and destination NAT. A general masquerade
// here would give every xray client the bridge router's identity. Keep the
// exceptions specific to packets actually steered into the private bridge.
// NAT has no connection-nat-state matcher on the supported CHRs. The DNS
// aperture is an active source list, the runner alone, and TCP/UDP port 53.
func preserveSources(runner string) []Object {
	var rows []Object
	add := func(role string, match map[string]string) {
		match["chain"], match["action"], match["out-interface"] = "srcnat", "accept", "tikray"
		// Either row keeps the source visible throughout an entire drift
		// interval if its peer is deleted. The narrower per-leg matches are
		// deliberate: a single generic bypass would also change owner NAT.
		for _, prefix := range []string{"preserve-", "preserve-backup-"} {
			r := object(firewallNAT, prefix+role, maps.Clone(match))
			r.Before = "first:srcnat"
			rows = append(rows, r)
		}
	}
	for _, closed := range []bool{false, true} {
		class := policyClass(store.Policy{KillSwitch: closed})
		add(class, map[string]string{"connection-mark": "tikray-" + class})
		for _, mode := range []store.Mode{store.ModeSmart, store.ModeFull} {
			p := store.Policy{Mode: mode, KillSwitch: closed}
			for _, proto := range []string{"tcp", "udp"} {
				add("dns-"+string(mode)+"-"+class+"-"+proto, map[string]string{
					"src-address-list": srcList(p), "dst-address": runner, "protocol": proto, "dst-port": "53",
				})
			}
		}
	}
	return rows
}

// Read only selector and identity columns on foreign rules. Full matcher
// details are needed only for our own guards preceding an overlapping rule.
func (o observation) sourceNAT(t *Topology) error {
	t.sourceNATConflict = false
	actions := []string{"masquerade", "src-nat", "netmap", "jump", "endpoint-independent-nat"}
	q := append([]string{"?chain=srcnat"}, anyQuery(valuesQuery("action", actions...), prefixQuery("comment", "tikray:preserve-"))...)
	rows, err := o.read(firewallNAT, ".id,comment,action,disabled,in-interface,in-interface-list,out-interface,out-interface-list,src-address", q...)
	if err != nil {
		return err
	}
	before := map[string]string{}
	for _, r := range rows {
		if !slices.Contains(actions, r["action"]) {
			if r["action"] == "accept" && nativeRowID.MatchString(r[".id"]) && ownedRole(firewallNAT, r["comment"]) {
				before[r[".id"]] = r["comment"]
			}
			continue
		}
		if onBit(r["disabled"]) || !mightOriginateOnLAN(r, t) {
			continue
		}
		overlap, err := o.canExitOnPrivateBridge(r)
		if err != nil {
			return err
		}
		if !overlap {
			continue
		}
		protected, err := o.sourceGuardsBefore(t, before)
		t.sourceNATConflict = !protected
		return err
	}
	return nil
}

// Only a positive proof about the actual egress excludes the private bridge.
// An opaque owner list is compatible with detaching every steering rule.
func (o observation) canExitOnPrivateBridge(r Row) (bool, error) {
	out := r["out-interface"]
	if out == "!tikray" || interfaceName(out) && out != "tikray" {
		return false, nil
	}
	raw := r["out-interface-list"]
	if raw == "" {
		return true, nil
	}
	name, negated := strings.CutPrefix(raw, "!")
	switch name {
	case "all":
		return !negated, nil
	case "none":
		return negated, nil
	case "static", "dynamic":
		return true, nil
	}
	members, err := o.lanMembers(name)
	if err == errTopology {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return slices.Contains(members, "tikray") != negated, nil
}

func (o observation) sourceGuardsBefore(t *Topology, before map[string]string) (bool, error) {
	wanted := preserveSources((store.Network{Subnet: t.Subnet}).Runner().String())
	if len(before) < len(wanted)/2 {
		return false, nil
	}
	rows, err := o.read(firewallNAT, ".id,comment,dynamic,"+strings.Join(managedFields(firewallNAT), ","), prefixQuery("comment", "tikray:preserve-")...)
	if err != nil {
		return false, err
	}
	byTag := map[string]Row{}
	for _, r := range rows {
		if before[r[".id"]] == r["comment"] && !onBit(r["invalid"]) && !onBit(r["dynamic"]) {
			byTag[r["comment"]] = r
		}
	}
	// Emergency off disables the bypasses. The next reconcile re-arms
	// these exact rows in the source-NAT chain before attaching steering.
	markerChecked, emergency := false, false
	covered := map[string]bool{}
	for _, g := range wanted {
		r := byTag[g.Comment]
		if r == nil {
			continue
		}
		if onBit(r["disabled"]) {
			if !markerChecked {
				id, busy, err := EmergencyState(o.ctx, o.c, o.gen)
				if err != nil {
					return false, err
				}
				emergency, markerChecked = id != "" && !busy, true
			}
			if !emergency {
				continue
			}
			g.Props["disabled"] = "yes"
		}
		if len(changes(Observed{Menu: firewallNAT, Props: r}, g)) == 0 {
			role := strings.TrimPrefix(g.Comment, "tikray:preserve-")
			covered[strings.TrimPrefix(role, "backup-")] = true
		}
	}
	return len(covered) == len(wanted)/2, nil
}
