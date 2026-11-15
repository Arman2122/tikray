package routeros

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/store"
)

const (
	transitTag     = "tikray:acl-runner-transit"
	transitDestTag = "tikray:acl-runner-transit-dst"
	transitChain   = "tikray-transit"
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
	return reconcileInstalledRows(ctx, c, repair, 2*len(scope.LANs)+12, func(o observation) (bindingPlan, error) {
		return observeTransitGuard(o, scope, unconfigured)
	})
}

// RouterOS acknowledges an add before an interface matcher becomes valid.
// Wait only for the same positively identified row on the same generation.
func readTransitGuard(o observation, tag string) (Row, error) {
	const fields = transitFields
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

const transitFields = ".id,comment,chain,action,jump-target,dynamic,disabled,invalid,log," + allowedPredicates

type transitHead struct {
	tag, action, field, value string
	row                       Row
	seen                      bool
	op                        []string
}

func correctTransitShape(r Row, chain, action string, want map[string]string) bool {
	if !bindingID(r[".id"]) || r["chain"] != chain || r["action"] != action || onBit(r["dynamic"]) || onBit(r["log"]) || r["jump-target"] != want["jump-target"] {
		return false
	}
	for _, k := range strings.Split(allowedPredicates, ",") {
		if normalized(firewallFilter, k, r[k]) != normalized(firewallFilter, k, want[k]) {
			return false
		}
	}
	return true
}

func observeTransitGuard(o observation, scope InstallScope, unconfigured bool) (bindingPlan, error) {
	var p bindingPlan
	heads := []transitHead{{tag: transitTag, action: "drop", field: "out-interface-list", value: "!" + scope.LANList}, {tag: transitDestTag, action: "jump", field: "jump-target", value: transitChain}}
	source := "!" + scope.Subnet.String()
	for i := range heads {
		h := &heads[i]
		row, err := readTransitGuard(o, h.tag)
		if err != nil {
			return p, err
		}
		h.row = row
		if row == nil {
			continue
		}
		want := map[string]string{"in-interface": "tikray", "src-address": source, h.field: h.value}
		if row["comment"] != h.tag || !correctTransitShape(row, "forward", h.action, want) {
			return p, ErrPolicyConflict
		}
		p.identities = append(p.identities, row[".id"])
	}
	if heads[0].row == nil && heads[1].row == nil && unconfigured {
		// A legacy direct-only bootstrap may complete under its owner's
		// install lock. Neither saved nor newly requested policy can steer.
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
	chain, err := observeTransitChain(o, scope, heads[1].row[".id"])
	if err != nil {
		return p, err
	}
	p.identities = append(p.identities, chain.identities...)
	order, err := o.order(firewallFilter, "forward")
	if err != nil {
		return p, err
	}
	before := ""
	for _, r := range order {
		i := slices.IndexFunc(heads, func(h transitHead) bool { return h.tag == r.Comment })
		if i >= 0 {
			h := &heads[i]
			if h.row == nil || h.row[".id"] != r.ID || h.seen {
				return p, errDrift
			}
			h.seen = true
			if before != "" {
				h.op = []string{firewallFilter + "/move", "=numbers=" + r.ID, "=destination=" + before}
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
	for i := range heads {
		h := &heads[i]
		if h.row == nil {
			h.op = []string{firewallFilter + "/add", "=chain=forward", "=action=" + h.action, "=comment=" + h.tag, "=in-interface=tikray", "=src-address=" + source, "=" + h.field + "=" + h.value}
			if before != "" {
				h.op = append(h.op, "=place-before="+before)
			}
		} else if !h.seen {
			return p, errDrift
		} else if len(h.op) == 0 && onBit(h.row["disabled"]) {
			h.op = []string{firewallFilter + "/set", "=.id=" + h.row[".id"], "=disabled=no"}
		}
	}
	// Keep exterior egress closed, then build the complete restrictive
	// chain before making its jump live. Never move an owner's rule.
	p.change(heads[0].op...)
	p.change(chain.first...)
	p.change(heads[1].op...)
	return p, nil
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
