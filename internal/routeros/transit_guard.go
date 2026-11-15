package routeros

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/store"
)

const (
	transitTag     = "tikray:acl-runner-transit"
	transitDestTag = "tikray:acl-runner-transit-dst"
	transitList    = "tikray-transit-lans"
	transitMember  = "tikray:acl-transit-lan:"
)

func policySteers(policy *PolicyInput) bool {
	if policy == nil {
		return false
	}
	if policy.Default.Mode == store.ModeSmart || policy.Default.Mode == store.ModeFull {
		return true
	}
	for _, d := range policy.Devices {
		if d.Policy.Mode == store.ModeSmart || d.Policy.Mode == store.ModeFull {
			return true
		}
	}
	return false
}

func (e *Engine) reconcilePrivateNetwork(ctx context.Context, policy, previous *PolicyInput, repair bool) error {
	if !e.managedBindings {
		return nil
	}
	if err := ReconcileBindings(ctx, e.c, e.scope.Subnet, repair); err != nil {
		return err
	}
	unconfigured := !policySteers(policy) && !policySteers(previous)
	return ReconcileTransitGuard(ctx, e.c, e.scope, repair, unconfigured)
}

// ReconcileTransitGuard verifies the installed drop that protects the interval
// before either PID 1 can run. An unconfigured direct-only policy may complete
// a legacy installer's initial bootstrap before this rule is installed.
func ReconcileTransitGuard(ctx context.Context, c Native, scope InstallScope, repair, unconfigured bool) error {
	if !interfaceName(scope.LANList) || store.ValidateRouterNetwork(store.Network{Subnet: scope.Subnet}, nil) != nil {
		return ErrPolicyConflict
	}
	return reconcileInstalledRows(ctx, c, repair, len(scope.LANs)+8, func(o observation) (bindingPlan, error) {
		return observeTransitGuard(o, scope, unconfigured)
	})
}

// RouterOS acknowledges an add before an interface matcher becomes valid.
// Wait only for the same positively identified row on the same generation.
func readTransitGuard(o observation, tag string) (Row, error) {
	const fields = ".id,comment,chain,action,dynamic,disabled,invalid,log," + allowedPredicates
	var settling string
	for {
		rows, err := o.read(firewallFilter, fields, "?comment="+tag)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 && settling == "" {
			return nil, nil
		}
		if len(rows) != 1 || !bindingID(rows[0][".id"]) || (settling != "" && settling != rows[0][".id"]) {
			return nil, ErrPolicyConflict
		}
		if !onBit(rows[0]["invalid"]) {
			return rows[0], nil
		}
		if settling == "" {
			wait, cancel := context.WithTimeout(o.ctx, 2*time.Second)
			defer cancel()
			o.ctx = wait
			settling = rows[0][".id"]
		}
		select {
		case <-o.ctx.Done():
			return nil, ErrPolicyConflict
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type transitDrop struct {
	tag, field, value string
	row               Row
	seen              bool
}

func observeTransitGuard(o observation, scope InstallScope, unconfigured bool) (bindingPlan, error) {
	var p bindingPlan
	drops := []transitDrop{{tag: transitTag, field: "out-interface-list", value: "!" + scope.LANList}, {tag: transitDestTag, field: "dst-address-list", value: "!" + transitList}}
	source := "!" + scope.Subnet.String()
	for i := range drops {
		d := &drops[i]
		row, err := readTransitGuard(o, d.tag)
		if err != nil {
			return p, err
		}
		d.row = row
		if row == nil {
			continue
		}
		if row["comment"] != d.tag || row["chain"] != "forward" || row["action"] != "drop" || onBit(row["dynamic"]) || onBit(row["log"]) {
			return p, ErrPolicyConflict
		}
		want := map[string]string{"in-interface": "tikray", "src-address": source, d.field: d.value}
		for _, k := range strings.Split(allowedPredicates, ",") {
			if row[k] != want[k] {
				return p, ErrPolicyConflict
			}
		}
		q := append([]string{"?comment=" + d.tag}, predicatesPresent(unsupportedPredicates)...)
		n, err := o.count(firewallFilter, q...)
		if err != nil {
			return p, err
		}
		if n != 0 {
			return p, ErrPolicyConflict
		}
		p.identities = append(p.identities, row[".id"])
	}
	if drops[0].row == nil && drops[1].row == nil && unconfigured {
		// A historical owner installer may bootstrap an all-direct service
		// before either rule exists. No managed packet can enter the runner.
		locks, err := o.read("/system/script", ".id,comment", "?name=tikray-install-lock")
		if err != nil {
			return p, err
		}
		if len(locks) > 0 {
			if len(locks) != 1 || !bindingID(locks[0][".id"]) || !strings.HasPrefix(locks[0]["comment"], "tikray:install-lock ") {
				return p, ErrPolicyConflict
			}
			return p, nil
		}
	}
	if err := observeTransitMembers(o, scope, &p, drops[1].row[".id"]); err != nil {
		return p, err
	}
	order, err := o.order(firewallFilter, "forward")
	if err != nil {
		return p, err
	}
	before := ""
	for _, r := range order {
		i := slices.IndexFunc(drops, func(d transitDrop) bool { return d.tag == r.Comment })
		if i >= 0 {
			d := &drops[i]
			if d.row == nil || d.row[".id"] != r.ID || d.seen {
				return p, errDrift
			}
			d.seen = true
			if before != "" {
				p.change(firewallFilter+"/move", "=numbers="+r.ID, "=destination="+before)
			}
			continue
		}
		if before != "" || dummyRule(r) || onBit(r.Props["disabled"]) {
			continue
		}
		switch r.Props["action"] {
		case "drop", "reject":
			continue
		case "jump":
			if r.Comment == "tikray:egress-guard" {
				ok, e := restrictiveEgress(o, r.ID)
				if e != nil {
					return p, e
				}
				if ok {
					continue
				}
			}
		}
		before = r.ID
	}
	for _, d := range drops {
		if d.row == nil {
			words := []string{firewallFilter + "/add", "=chain=forward", "=action=drop", "=comment=" + d.tag, "=in-interface=tikray", "=src-address=" + source, "=" + d.field + "=" + d.value}
			if before != "" {
				words = append(words, "=place-before="+before)
			}
			p.change(words...)
		} else if !d.seen {
			return p, errDrift
		} else if onBit(d.row["disabled"]) {
			p.change(firewallFilter+"/set", "=.id="+d.row[".id"], "=disabled=no")
		}
	}
	return p, nil
}

func observeTransitMembers(o observation, scope InstallScope, p *bindingPlan, destID string) error {
	if len(scope.LANs) == 0 || len(scope.LANs) > 128 {
		return ErrPolicyConflict
	}
	wanted := make(map[string]bool, len(scope.LANs))
	for _, lan := range scope.LANs {
		n := lan.Prefix
		if !n.IsValid() || !n.Addr().Is4() || n.Bits() == 0 || n != n.Masked() || n.Overlaps(scope.Subnet) {
			return ErrPolicyConflict
		}
		wanted[n.String()] = false
	}
	// A writer or consumer outside this exact rule makes the list shared.
	// Match the references on the router; never read an owner's other rules.
	q := anyQuery(valuesQuery("src-address-list", transitList, "!"+transitList), valuesQuery("dst-address-list", transitList, "!"+transitList), []string{"?address-list=" + transitList})
	for _, m := range []string{firewallFilter, firewallNAT, firewallMangle, "/ip/firewall/raw"} {
		refs, err := o.read(m, ".id,comment,address-list", q...)
		if err != nil {
			return err
		}
		for _, r := range refs {
			if m != firewallFilter || destID == "" || r[".id"] != destID || r["comment"] != transitDestTag || r["address-list"] != "" {
				return ErrPolicyConflict
			}
		}
	}
	filter := anyQuery([]string{"?list=" + transitList}, prefixQuery("comment", transitMember))
	n, err := o.count(addressListMenu, filter...)
	if err != nil {
		return err
	}
	if n > len(wanted) {
		return ErrPolicyConflict
	}
	rows, err := o.read(addressListMenu, ".id,list,address,comment,disabled,dynamic,timeout", filter...)
	if err != nil {
		return err
	}
	if len(rows) != n {
		return errDrift
	}
	for _, r := range rows {
		addr := r["address"]
		if ip, e := netip.ParseAddr(addr); e == nil && ip.Is4() {
			addr = netip.PrefixFrom(ip, 32).String()
		}
		seen, ok := wanted[addr]
		if !ok || seen || r["list"] != transitList || r["comment"] != transitMember+addr || !bindingID(r[".id"]) || onBit(r["dynamic"]) || (r["timeout"] != "" && r["timeout"] != "none-static") {
			return ErrPolicyConflict
		}
		wanted[addr] = true
		p.identities = append(p.identities, r[".id"])
		if onBit(r["disabled"]) {
			p.change(addressListMenu+"/set", "=.id="+r[".id"], "=disabled=no")
		}
	}
	// Deterministic even when the scope repeats a network on two interfaces.
	for _, lan := range scope.LANs {
		addr := lan.Prefix.String()
		if !wanted[addr] {
			p.change(addressListMenu+"/add", "=list="+transitList, "=address="+addr, "=comment="+transitMember+addr)
			break
		}
	}
	return nil
}

func restrictiveEgress(o observation, id string) (bool, error) {
	rows, err := o.read(firewallFilter, ".id,jump-target", "?.id="+id, "?comment=tikray:egress-guard", "?chain=forward", "?action=jump")
	if err != nil {
		return false, err
	}
	if len(rows) != 1 || rows[0][".id"] != id || rows[0]["jump-target"] != egressChain {
		return false, nil
	}
	rules, err := o.read(firewallFilter, ".id,action,disabled", "?chain="+egressChain)
	if err != nil {
		return false, err
	}
	for _, r := range rules {
		if onBit(r["disabled"]) {
			continue
		}
		switch r["action"] {
		case "return", "reject", "drop":
		default:
			return false, nil
		}
	}
	return true, nil
}
