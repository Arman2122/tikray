package routeros

import (
	"context"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"
)

// Execute never retries a mutation, even if its acknowledgement was lost.
// A caller must observe a new generation and plan against what survived.
func Execute(ctx context.Context, c Native, a Actual, ops []Op) error {
	if c.Generation() == 0 || c.Generation() != a.Generation {
		return ErrStaleGeneration
	}
	if len(ops) == 0 {
		return nil
	}
	if len(a.Topology.ForeignRefs) > 0 {
		return errConflict
	}
	e := execution{observation: observation{ctx: ctx, c: c, gen: a.Generation}, actual: a, expected: map[string]Observed{}, chains: map[[2]string][]Observed{}}
	for _, op := range ops {
		if op.placement != nil {
			e.chains[[2]string{op.Menu, op.target.Props["chain"]}] = nil
		}
	}
	for _, r := range a.Rows {
		if ownedRole(r.Menu, r.Comment) {
			e.expected[r.Comment] = r
		}
		key := [2]string{r.Menu, r.Props["chain"]}
		if _, needed := e.chains[key]; needed && !dummyRule(r) {
			e.chains[key] = append(e.chains[key], r)
		}
	}
	if err := checkReferences(ctx, c, a.Generation); err != nil {
		return err
	}
	for key := range e.chains {
		if err := e.verifyOrder(key); err != nil {
			return err
		}
	}
	// Preflight the complete affected set before dismantling any of it.
	seen := make(map[string]bool)
	for _, op := range ops {
		if !ownedRole(op.Menu, op.Comment) || op.target.Menu != op.Menu || op.target.Comment != op.Comment {
			return ErrRequest
		}
		if seen[op.Comment] {
			continue
		}
		if err := e.verifyIdentity(op); err != nil {
			return err
		}
		seen[op.Comment] = true
	}
	for _, op := range ops {
		if err := e.apply(op); err != nil {
			return err
		}
	}
	return nil
}

type execution struct {
	observation
	actual         Actual
	expected       map[string]Observed
	chains         map[[2]string][]Observed
	checkedSources bool
}

func (e *execution) byTag(menu, tag string) (Observed, bool, error) {
	fields := ".id,comment,dynamic," + strings.Join(managedFields(menu), ",")
	rows, err := e.read(menu, fields, "?comment="+tag)
	if err != nil {
		return Observed{}, false, err
	}
	if len(rows) == 0 {
		return Observed{}, false, nil
	}
	if len(rows) != 1 {
		return Observed{}, false, errConflict
	}
	p := rows[0]
	r := Observed{Menu: menu, ID: p[".id"], Comment: p["comment"], Dynamic: onBit(p["dynamic"]), Props: map[string]string(p)}
	if r.Comment != tag || !checkKind(r) {
		return Observed{}, false, errConflict
	}
	return r, true, nil
}

func (e *execution) verifyIdentity(op Op) error {
	r, ok, err := e.byTag(op.Menu, op.Comment)
	if err != nil {
		return err
	}
	if op.Kind == "add" {
		if ok || op.id != "" {
			return errDrift
		}
		return nil
	}
	prior, known := e.expected[op.Comment]
	if !ok || !known || op.id != r.ID || prior.ID != r.ID || prior.Menu != r.Menu {
		return errDrift
	}
	return equalObserved(prior, r)
}

func netwatchPrimary(r Observed) bool {
	return r.Menu == firewallNAT && strings.HasPrefix(r.Comment, "tikray:dns-") && !strings.HasPrefix(r.Comment, "tikray:dns-router-") && strings.Contains(r.Comment, "-open-") && ownedRole(firewallNAT, r.Comment)
}

func equalObserved(prior, now Observed) error {
	openPrimary := netwatchPrimary(now)
	for _, k := range managedFields(now.Menu) {
		if k == "invalid" || k == "disabled" && openPrimary {
			continue
		}
		if observedValue(now, k) != observedValue(prior, k) {
			return errDrift
		}
	}
	return nil
}

func (e *execution) verifyDependency(tag string) error {
	prior, ok := e.expected[tag]
	if !ok {
		return errDrift
	}
	r, found, err := e.byTag(prior.Menu, tag)
	if err != nil {
		return err
	}
	if !found || r.ID != prior.ID || observedValue(r, "invalid") != "no" {
		return errDrift
	}
	return equalObserved(prior, r)
}

func (e *execution) beforeWrite(op Op) error {
	if err := e.ctx.Err(); err != nil {
		return err
	}
	activatingSource := op.Kind != "remove" && op.Menu == addressListMenu && strings.HasPrefix(op.target.Props["list"], "tikray-src-") && !e.checkedSources
	// A reference may have been introduced since preflight, including
	// between two removals from the same large list.
	if op.Menu == addressListMenu && (op.Kind == "remove" || op.Kind == "set") {
		if err := e.checkListConsumers(op.target.Props["list"]); err != nil {
			return err
		}
	} else if activatingSource || op.Kind == "remove" || op.Kind == "set" || op.Kind == "move" || op.Comment == "tikray:jump-pre" || op.Comment == "tikray:no-fasttrack" {
		if err := checkReferences(e.ctx, e.c, e.gen); err != nil {
			return err
		}
	}
	if activatingSource {
		// An already-attached hook can see the very first new member.
		// Revalidate installed guards here even when they needed no writes.
		for _, prior := range e.expected {
			if prior.Menu != firewallFilter && prior.Menu != ipv6Filter && prior.Menu != firewallNAT && prior.Menu != routeMenu {
				continue
			}
			if err := e.verifyDependency(prior.Comment); err != nil {
				return err
			}
		}
		e.checkedSources = true
	}
	if activatingSource || op.Comment == "tikray:jump-pre" && op.Kind != "remove" {
		// The eligible FastTrack rule or a preceding owner routing mark can
		// change while we are constructing otherwise unchanged guard bodies.
		t := e.actual.Topology
		t.ForeignRefs = nil
		t.ForeignRoutingMarks = nil
		if err := e.ownerInteractions(&t); err != nil {
			return err
		}
		got, want := slices.Clone(t.ForeignRoutingMarks), slices.Clone(e.actual.Topology.ForeignRoutingMarks)
		slices.Sort(got)
		slices.Sort(want)
		if len(t.ForeignRefs) != 0 || t.sourceNATConflict || !slices.Equal(slices.Compact(got), slices.Compact(want)) {
			return errConflict
		}
		ft, err := readForward(e.ctx, e.c, e.gen)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(ft, e.actual.Topology.FastTrack) {
			return errDrift
		}
	}
	if op.Comment == "tikray:no-fasttrack" && op.Kind != "remove" {
		rules, err := readForward(e.ctx, e.c, e.gen)
		if err != nil {
			return err
		}
		want, err := fastTrackException(rules)
		if err != nil || want == nil || want.Before != op.target.Before || !maps.Equal(want.Props, op.target.Props) {
			return errConflict
		}
		before := e.actual.Topology.FastTrack
		for _, old := range before {
			if old.ID != want.Before {
				continue
			}
			next := slices.IndexFunc(rules, func(r FastTrackRule) bool { return r.ID == old.ID })
			if next < 0 || old.Next == nil || rules[next].Next == nil || rules[next].Next.ID != old.Next.ID {
				return errDrift
			}
		}
	}
	if op.Kind != "remove" {
		for _, tag := range op.target.DependsOn {
			if err := e.verifyDependency(tag); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *execution) apply(op Op) error {
	if err := e.beforeWrite(op); err != nil {
		return err
	}
	anchor, err := e.anchor(op)
	if err != nil {
		return err
	}
	// Resolve dependencies and placement before this final exact-tag+ID
	// check. Native mutation arguments never contain an item number.
	if err = e.verifyIdentity(op); err != nil {
		return err
	}
	words := []string{op.Menu + "/" + op.Kind}
	switch op.Kind {
	case "add":
		words = append(words, "=comment="+op.Comment)
		if anchor != "" {
			words = append(words, "=place-before="+anchor)
		}
	case "move":
		words = append(words, "=numbers="+op.id)
		if anchor != "" {
			words = append(words, "=destination="+anchor)
		}
	case "set", "remove":
		words = append(words, "=.id="+op.id)
	default:
		return ErrRequest
	}
	for _, k := range slices.Sorted(maps.Keys(op.fields)) {
		words = append(words, "="+k+"="+op.fields[k])
	}
	reply, err := e.c.CommandAt(e.ctx, e.gen, words)
	if err != nil {
		return err
	}
	id := op.id
	if op.Kind == "add" {
		if len(reply) != 1 || !nativeRowID.MatchString(reply[0]["ret"]) {
			return ErrOutcomeUnknown
		}
		id = reply[0]["ret"]
	}
	row, err := e.readBack(op, id)
	if err != nil {
		return err
	}
	if op.Kind == "remove" {
		delete(e.expected, op.Comment)
	} else {
		e.expected[op.Comment] = row
	}
	key := [2]string{op.Menu, op.target.Props["chain"]}
	if chain, needed := e.chains[key]; needed {
		i := slices.IndexFunc(chain, func(r Observed) bool { return r.ID == id })
		if i >= 0 && op.Kind == "set" {
			chain[i] = row
		} else {
			if i >= 0 {
				chain = slices.Delete(chain, i, i+1)
			}
			if op.Kind != "remove" {
				pos := len(chain)
				if anchor != "" {
					pos = slices.IndexFunc(chain, func(r Observed) bool { return r.ID == anchor })
					if pos < 0 {
						return errDrift
					}
				}
				chain = slices.Insert(chain, pos, row)
			}
		}
		e.chains[key] = chain
		if op.placement != nil {
			return e.verifyOrder(key)
		}
	}
	return nil
}

func (e *execution) checkListConsumers(list string) error {
	// Reading every member of a domestic set for each deletion is
	// quadratic. Only the rules referring to this particular set matter.
	q := anyQuery(valuesQuery("src-address-list", list, "!"+list), valuesQuery("dst-address-list", list, "!"+list), valuesQuery("address-list", list))
	for _, menu := range []string{firewallFilter, firewallMangle, firewallNAT, "/ip/firewall/raw", ipv6Filter, "/ipv6/firewall/mangle", "/ipv6/firewall/nat", "/ipv6/firewall/raw"} {
		rows, err := e.read(menu, "comment", q...)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if !ownedRole(menu, r["comment"]) {
				return errConflict
			}
		}
	}
	return nil
}

func (e *execution) readBack(op Op, id string) (Observed, error) {
	// Newly inserted jumps can briefly be invalid while the firewall
	// recompiles. Poll only the exact row and never resend the mutation.
	deadline := time.Now().Add(12 * time.Second)
	for {
		r, found, err := e.byTag(op.Menu, op.Comment)
		if err != nil {
			return Observed{}, err
		}
		if op.Kind == "remove" {
			if found {
				return Observed{}, errDrift
			}
			return Observed{}, nil
		}
		if !found || r.ID != id || len(changes(r, op.target)) != 0 {
			return Observed{}, errDrift
		}
		if normalized(r.Menu, "invalid", r.Props["invalid"]) == "no" {
			return r, nil
		}
		if !time.Now().Before(deadline) {
			return Observed{}, errDrift
		}
		select {
		case <-e.ctx.Done():
			return Observed{}, e.ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (e *execution) anchor(op Op) (string, error) {
	slot := op.placement
	if slot == nil {
		return "", nil
	}
	key := [2]string{op.Menu, op.target.Props["chain"]}
	if err := e.verifyOrder(key); err != nil {
		return "", err
	}
	if strings.HasPrefix(slot.before, "tikray:") {
		prior, ok := e.expected[slot.before]
		if !ok || prior.Menu != op.Menu {
			return "", errDrift
		}
		r, found, err := e.byTag(prior.Menu, prior.Comment)
		if err != nil {
			return "", err
		}
		if !found || prior.ID != r.ID || r.Props["chain"] != op.target.Props["chain"] || equalObserved(prior, r) != nil {
			return "", errDrift
		}
		return r.ID, nil
	}
	if slot.before == "" {
		return "", nil
	}
	for _, r := range e.chains[key] {
		if strings.HasPrefix(slot.before, "first:") {
			if slot.members[r.Comment] || isHold(r.Comment) || slot.stale[r.Comment] && ownedRole(r.Menu, r.Comment) {
				continue
			}
			return r.ID, nil
		}
		if r.ID == slot.before {
			return r.ID, nil
		}
	}
	if strings.HasPrefix(slot.before, "first:") {
		return "", nil
	}
	return "", errDrift
}

// RouterOS move arguments refer to the current list. A stale sibling can
// still have its original ID and tag even after an owner moves a deny
// between it and the original anchor.
func (e *execution) verifyOrder(key [2]string) error {
	rows, err := e.order(key[0], key[1])
	if err != nil {
		return err
	}
	rows = slices.DeleteFunc(rows, dummyRule)
	if !slices.EqualFunc(rows, e.chains[key], func(a, b Observed) bool {
		if a.ID != b.ID || a.Comment != b.Comment || a.Dynamic != b.Dynamic || a.Props["action"] != b.Props["action"] {
			return false
		}
		if netwatchPrimary(a) {
			return true
		}
		return normalized(a.Menu, "disabled", a.Props["disabled"]) == normalized(b.Menu, "disabled", b.Props["disabled"])
	}) {
		return errDrift
	}
	return nil
}
