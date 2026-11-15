package routeros

import "strings"

const (
	transitDeny   = "tikray:acl-transit-deny"
	transitBackup = "tikray:acl-transit-deny-backup"
)

// Firewall chain names are local to the IPv4 filter menu. Global IPv4
// address lists can already be in use by routing, DNS and subscriber policy.
func observeTransitChain(o observation, scope InstallScope, headID string) (bindingPlan, error) {
	var p bindingPlan
	if len(scope.LANs) == 0 || len(scope.LANs) > 128 {
		return p, ErrPolicyConflict
	}
	allowed := make(map[string]bool, len(scope.LANs))
	for _, lan := range scope.LANs {
		net := lan.Prefix
		if !net.IsValid() || !net.Addr().Is4() || net.Bits() == 0 || net != net.Masked() || net.Overlaps(scope.Subnet) {
			return p, ErrPolicyConflict
		}
		allowed[net.String()] = true
	}
	// Leave any same-tag artifact from the interim global-list design for
	// owner inspection; a routing service may depend on it.
	legacy, e := o.count(addressListMenu, prefixQuery("comment", transitMember)...)
	if e != nil {
		return p, e
	}
	if legacy != 0 {
		return p, ErrPolicyConflict
	}
	// Prove no other filter can dispatch an owner's traffic into this chain.
	refs, err := o.read(firewallFilter, ".id,comment", "?jump-target="+transitChain)
	if err != nil {
		return p, err
	}
	if headID != "" && len(refs) == 0 {
		return p, errDrift
	}
	for _, r := range refs {
		if headID == "" || r[".id"] != headID || r["comment"] != transitDestTag {
			return p, ErrPolicyConflict
		}
	}
	q := anyQuery([]string{"?chain=" + transitChain}, prefixQuery("comment", transitMember), valuesQuery("comment", transitDeny, transitBackup))
	n, err := o.count(firewallFilter, q...)
	if err != nil {
		return p, err
	}
	if n > len(allowed)+2 {
		return p, ErrPolicyConflict
	}
	rows, err := o.read(firewallFilter, transitFields, q...)
	if err != nil {
		return p, err
	}
	if len(rows) != n {
		return p, errDrift
	}
	// Project only the presence of unsupported and potentially private matchers.
	owned := anyQuery(q, valuesQuery("comment", transitTag, transitDestTag))
	count, err := o.count(firewallFilter, append(owned, predicatesPresent(unsupportedPredicates)...)...)
	if err != nil {
		return p, err
	}
	if count != 0 {
		return p, ErrPolicyConflict
	}

	seen := map[string]Row{}
	var anchor string
	var move []string
	for _, r := range rows {
		tag := r["comment"]
		if seen[tag] != nil {
			return p, ErrPolicyConflict
		}
		addr, member := strings.CutPrefix(tag, transitMember)
		if tag != transitDeny && tag != transitBackup && (!member || !allowed[addr]) {
			return p, ErrPolicyConflict
		}
		if onBit(r["invalid"]) {
			fresh, e := readTransitGuard(o, tag)
			if e != nil {
				return p, e
			}
			if fresh == nil || fresh[".id"] != r[".id"] {
				return p, errDrift
			}
			r = fresh
		}
		switch tag {
		case transitDeny, transitBackup:
			if !correctTransitShape(r, transitChain, "drop", nil) {
				return p, ErrPolicyConflict
			}
			if anchor == "" {
				anchor = r[".id"]
			}
		default:
			if !correctTransitShape(r, transitChain, "return", map[string]string{"dst-address": addr, "out-interface-list": scope.LANList}) {
				return p, ErrPolicyConflict
			}
			if anchor != "" && move == nil {
				move = []string{firewallFilter + "/move", "=numbers=" + r[".id"], "=destination=" + anchor}
			}
		}
		seen[tag] = r
		p.identities = append(p.identities, r[".id"])
	}
	// Retain an unconditional backup if the first terminal row vanishes.
	// A missing LAN return narrows the aperture until its owner row is restored.
	for _, tag := range []string{transitDeny, transitBackup} {
		r := seen[tag]
		if r == nil {
			p.change(firewallFilter+"/add", "=chain="+transitChain, "=comment="+tag, "=action=drop")
		}
	}
	// A disabled terminal can precede a currently working return. Move
	// the return first, while the independent backup continues to drop.
	p.change(move...)
	for _, tag := range []string{transitDeny, transitBackup} {
		if r := seen[tag]; r != nil && onBit(r["disabled"]) {
			p.change(firewallFilter+"/set", "=.id="+r[".id"], "=disabled=no")
		}
	}
	for _, lan := range scope.LANs {
		addr := lan.Prefix.String()
		tag := transitMember + addr
		if r := seen[tag]; r == nil {
			if anchor != "" {
				p.change(firewallFilter+"/add", "=chain="+transitChain, "=action=return", "=comment="+tag, "=dst-address="+addr, "=out-interface-list="+scope.LANList, "=place-before="+anchor)
			}
		} else if onBit(r["disabled"]) {
			p.change(firewallFilter+"/set", "=.id="+r[".id"], "=disabled=no")
		}
	}
	return p, nil
}
