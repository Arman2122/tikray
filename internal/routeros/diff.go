package routeros

import (
	"errors"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	addressListMenu = "/ip/firewall/address-list"
	routeMenu       = "/ip/route"
	tableMenu       = "/routing/table"
	watchMenu       = "/tool/netwatch"
)

var managedMenus = []string{addressListMenu, tableMenu, routeMenu, ipv6Filter, firewallFilter, firewallNAT, firewallMangle, watchMenu}

var rolePatterns = map[string]*regexp.Regexp{
	firewallFilter: regexp.MustCompile(`^(egress-(guard|skip-local|drop-(marked|smart|full)|dns-(full|smart)-(open|closed)-(tcp|udp))|no-fasttrack)$`),
	firewallMangle: regexp.MustCompile(`^(jump-pre|skip-(router|local|dns-(tcp|udp)|owner-route:[0-9a-f]{32})|(mss|packet|route)-(open|closed)|conn-(full|smart)-(open|closed))$`),
	firewallNAT:    regexp.MustCompile(`^(dns-((smart|full)-(closed|open)|router-(smart|full)-open)-(udp|tcp)|preserve-(backup-)?(open|closed|dns-(smart|full)-(open|closed)-(tcp|udp)))$`),
	ipv6Filter:     regexp.MustCompile(`^ipv6:(jump|ingress:[a-f0-9]{32})$`),
	watchMenu:      regexp.MustCompile(`^runner-watch$`),
	routeMenu:      regexp.MustCompile(`^route-(open|closed)-(fallback|runner)$`),
	tableMenu:      regexp.MustCompile(`^table-(open|closed)$`),
}
var holdPattern = regexp.MustCompile(`^tikray:hold:[a-f0-9]{32}$`)

func isHold(tag string) bool { return holdPattern.MatchString(tag) }

func ownedRole(menu, tag string) bool {
	role, ok := strings.CutPrefix(tag, "tikray:")
	if !ok {
		return false
	}
	if strings.HasPrefix(role, "hold:") {
		return (menu == addressListMenu || menu == firewallFilter || menu == ipv6Filter) && isHold(tag)
	}
	if menu == addressListMenu {
		name, key, ok := strings.Cut(role, ":")
		if !ok {
			return false
		}
		switch name {
		case "local", "domestic", "src-smart-open", "src-smart-closed", "src-full-open", "src-full-closed":
			p, e := netip.ParsePrefix(key)
			return e == nil && validPrefix(p) && p.String() == key
		}
		return false
	}
	if menu == ipv6Filter && strings.HasPrefix(role, "ipv6:host:") {
		key := strings.TrimPrefix(role, "ipv6:host:")
		ip, e := netip.ParseAddr(key)
		return e == nil && ip.Is4() && ip.String() == key
	}
	re := rolePatterns[menu]
	return re != nil && re.MatchString(role)
}

// These columns are configuration owned by the compiler. Counters, active
// route selection and live netwatch probe state never participate in a diff.
func managedFields(menu string) []string {
	fields := "disabled invalid"
	switch menu {
	case addressListMenu:
		fields += " list address timeout"
	case tableMenu:
		fields += " name fib"
	case routeMenu:
		fields += " routing-table dst-address gateway distance check-gateway blackhole"
	case watchMenu:
		fields += " host type interval timeout startup-delay start-delay up-script down-script test-script"
	case firewallFilter, ipv6Filter, firewallNAT, firewallMangle:
		fields += " chain action protocol in-interface out-interface in-interface-list out-interface-list src-address dst-address src-address-list dst-address-list src-address-type dst-address-type src-port dst-port src-mac-address connection-mark packet-mark routing-mark connection-state connection-nat-state ipsec-policy tcp-flags jump-target log log-prefix"
		switch menu {
		case firewallFilter, ipv6Filter:
			fields += " reject-with"
		case firewallMangle:
			fields += " passthrough new-connection-mark new-routing-mark new-packet-mark new-mss"
		case firewallNAT:
			fields += " to-addresses to-ports"
		}
	}
	return strings.Fields(fields)
}

func normalized(menu, key, value string) string {
	switch key {
	case "up-script", "down-script", "test-script":
		return strings.ReplaceAll(value, "\r\n", "\n")
	case "disabled", "invalid", "fib", "blackhole", "log":
		switch value {
		case "", "no", "false":
			return "no"
		case "yes", "true":
			return "yes"
		}
	case "passthrough":
		switch value {
		case "", "yes", "true":
			return "yes"
		case "no", "false":
			return "no"
		}
	case "address", "src-address", "dst-address", "to-addresses":
		if p, e := netip.ParsePrefix(value); e == nil && p.Bits() == p.Addr().BitLen() {
			return p.Addr().String()
		}
	case "src-mac-address":
		return strings.ToUpper(value)
	case "tcp-flags", "connection-state":
		parts := strings.Split(value, ",")
		slices.Sort(parts)
		return strings.Join(parts, ",")
	case "check-gateway":
		if value == "none" {
			return ""
		}
	case "distance":
		if value == "" {
			return "1"
		}
	case "timeout", "interval", "start-delay", "startup-delay":
		if menu == addressListMenu && (value == "none-static" || value == "0s") {
			return ""
		}
		if d, err := time.ParseDuration(value); err == nil {
			return d.String()
		}
		parts := strings.Split(value, ":")
		if len(parts) == 3 {
			h, e1 := strconv.Atoi(parts[0])
			m, e2 := strconv.Atoi(parts[1])
			s, e3 := time.ParseDuration(parts[2] + "s")
			if e1 == nil && e2 == nil && e3 == nil {
				return (time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + s).String()
			}
		}
	}
	return value
}

func changes(r Observed, o Object) map[string]string {
	out := make(map[string]string)
	for _, k := range managedFields(o.Menu) {
		if k == "invalid" || (k == "disabled" && o.InitialDisabled) {
			continue
		}
		want := o.Props[k]
		if normalized(o.Menu, k, want) == observedValue(r, k) {
			continue
		}
		if k == "disabled" && want == "" {
			want = "no"
		}
		out[k] = want
	}
	return out
}

func observedValue(r Observed, k string) string {
	v, present := r.Props[k]
	// Native prints represent these RouterOS flags by an empty property
	// when set. An omitted property means the flag is off.
	if present && v == "" && (k == "fib" || k == "blackhole") {
		return "yes"
	}
	return normalized(r.Menu, k, v)
}

// A tag identifies a role in a particular menu. Selector identity matters
// even when removing stale rows with no desired counterpart.
func checkKind(r Observed) bool {
	if !ownedRole(r.Menu, r.Comment) || r.Dynamic || !nativeRowID.MatchString(r.ID) {
		return false
	}
	props := r.Props
	role := strings.TrimPrefix(r.Comment, "tikray:")
	if isHold(r.Comment) {
		// A hold's tag commits to immutable selectors. RouterOS drops /32
		// in host prints and may add configuration defaults to the row.
		p := map[string]string{}
		for _, k := range strings.Fields("list address chain action src-address in-interface-list in-interface dst-address-type dst-address-list protocol dst-port jump-target src-mac-address reject-with") {
			value := props[k]
			if value == "" {
				continue
			}
			switch k {
			case "src-address", "address":
				if a, e := netip.ParseAddr(value); e == nil {
					value = netip.PrefixFrom(a, a.BitLen()).String()
				}
			case "src-mac-address":
				value = strings.ToUpper(value)
			}
			p[k] = value
		}
		return holdObject(r.Menu, p).Comment == r.Comment
	}
	switch r.Menu {
	case addressListMenu:
		list, key, _ := strings.Cut(role, ":")
		return props["list"] == "tikray-"+list && normalized(r.Menu, "address", props["address"]) == normalized(r.Menu, "address", key)
	case tableMenu:
		return props["name"] == "tikray-"+strings.TrimPrefix(role, "table-")
	case routeMenu:
		parts := strings.Split(role, "-")
		return props["routing-table"] == "tikray-"+parts[1] && props["dst-address"] == "0.0.0.0/0"
	case watchMenu:
		return props["type"] == "simple"
	case ipv6Filter:
		if role == "ipv6:jump" {
			return props["chain"] == "forward" && props["action"] == "jump"
		}
		return props["chain"] == ipv6Chain && (props["action"] == "reject" || props["action"] == "return")
	case firewallFilter:
		switch role {
		case "no-fasttrack":
			return props["chain"] == "forward" && props["action"] == "accept"
		case "egress-guard":
			return props["chain"] == "forward" && props["action"] == "jump"
		case "egress-skip-local":
			return props["chain"] == egressChain && props["action"] == "return"
		default:
			return props["chain"] == egressChain && props["action"] == "drop"
		}
	case firewallNAT:
		if strings.HasPrefix(role, "preserve-") {
			return props["chain"] == "srcnat" && props["action"] == "accept"
		}
		return props["chain"] == "dstnat" && ((strings.HasPrefix(role, "dns-router-") && props["action"] == "redirect") || (!strings.HasPrefix(role, "dns-router-") && props["action"] == "dst-nat"))
	case firewallMangle:
		switch {
		case role == "jump-pre":
			return props["chain"] == "prerouting" && props["action"] == "jump"
		case strings.HasPrefix(role, "mss-"):
			return props["chain"] == "forward" && props["action"] == "change-mss"
		case strings.HasPrefix(role, "packet-"):
			return props["chain"] == "forward" && props["action"] == "mark-packet"
		case strings.HasPrefix(role, "skip-"):
			return props["chain"] == preChain && props["action"] == "return"
		case strings.HasPrefix(role, "conn-"):
			return props["chain"] == preChain && props["action"] == "mark-connection"
		case strings.HasPrefix(role, "route-"):
			return props["chain"] == preChain && props["action"] == "mark-routing"
		}
	}
	return false
}

// Op keeps mutation preconditions private. Its public fields describe the
// operation without exposing native IDs, scripts or firewall predicates.
type Op struct {
	Kind, Menu, Comment string
	id                  string
	target              Object
	fields              map[string]string
	placement           *orderSlot
}

// A slot describes the end of a linked sibling group. Mutation commands
// resolve tag references to session-local IDs immediately before writing.
type orderSlot struct {
	before  string
	members map[string]bool
	stale   map[string]bool
}

var errDrift = errors.New("routeros: scoped configuration changed")

// Plan reconciles the permanent traffic policy while temporary guards protect
// a transition across the router and the runner.
func Plan(actual Actual, desired []Object) ([]Op, error) { return planScope(actual, desired, false) }

// PlanHolds reconciles only temporary guards. An empty target releases them
// after the caller has verified both effective configurations.
func PlanHolds(actual Actual, desired []Object) ([]Op, error) {
	return planScope(actual, desired, true)
}

func phase(o Object) int {
	switch {
	case o.Menu == addressListMenu && strings.HasPrefix(o.Props["list"], "tikray-src-"):
		return 8
	case o.Comment == "tikray:jump-pre":
		return 9
	case o.Menu == tableMenu || o.Menu == addressListMenu:
		return 0
	case o.Menu == routeMenu:
		return 1
	case o.Menu == ipv6Filter || o.Menu == firewallFilter && o.Comment != "tikray:no-fasttrack":
		return 2
	case o.Menu == firewallNAT && o.Props["chain"] == "srcnat":
		return 2
	case o.Menu == firewallNAT:
		return 3
	case o.Menu == watchMenu:
		return 4
	default:
		return 5
	}
}

func removalPhase(r Observed) int {
	o := Object{Menu: r.Menu, Comment: r.Comment, Props: r.Props}
	n := phase(o) * 10
	if r.Props["action"] == "jump" {
		n += 2
	}
	if r.Comment == "tikray:no-fasttrack" {
		n++
	}
	return n
}

func planScope(a Actual, desired []Object, holds bool) ([]Op, error) {
	if len(a.Topology.ForeignRefs) > 0 {
		return nil, errConflict
	}
	live := make(map[string]Observed)
	for _, r := range a.Rows {
		if !ownedRole(r.Menu, r.Comment) {
			continue
		}
		if _, dup := live[r.Comment]; dup || !checkKind(r) {
			return nil, errConflict
		}
		live[r.Comment] = r
	}
	wanted := make(map[string]Object, len(desired))
	for _, o := range desired {
		if isHold(o.Comment) != holds || !checkKind(Observed{Menu: o.Menu, ID: "*0", Comment: o.Comment, Props: o.Props}) {
			return nil, errPolicy
		}
		if _, dup := wanted[o.Comment]; dup {
			return nil, errPolicy
		}
		wanted[o.Comment] = o
	}
	staleTags := make(map[string]bool)
	for tag := range live {
		if _, keep := wanted[tag]; !keep && isHold(tag) == holds {
			staleTags[tag] = true
		}
	}
	slots, keep, err := planOrder(a, desired, wanted, staleTags)
	if err != nil {
		return nil, err
	}
	sorted := slices.Clone(desired)
	sort.SliceStable(sorted, func(i, j int) bool { return phase(sorted[i]) < phase(sorted[j]) })
	var ops []Op
	done := make(map[string]uint8)
	var visit func(string) error
	visit = func(tag string) error {
		if done[tag] == 2 {
			return nil
		}
		o, ok := wanted[tag]
		if !ok || done[tag] == 1 {
			return errPolicy
		}
		done[tag] = 1
		for _, dep := range o.DependsOn {
			if err := visit(dep); err != nil {
				return err
			}
		}
		if strings.HasPrefix(o.Before, "tikray:") {
			if err := visit(o.Before); err != nil {
				return err
			}
		}
		r, ok := live[tag]
		op := Op{Menu: o.Menu, Comment: tag, id: r.ID, target: o, placement: slots[tag]}
		if !ok {
			op.Kind = "add"
			op.fields = maps.Clone(o.Props)
			if o.InitialDisabled {
				op.fields["disabled"] = "yes"
			}
			ops = append(ops, op)
		} else {
			if f := changes(r, o); len(f) > 0 {
				update := op
				update.Kind = "set"
				update.fields = f
				update.placement = nil
				ops = append(ops, update)
			}
			if op.placement != nil && !keep[tag] {
				op.Kind = "move"
				ops = append(ops, op)
			}
		}
		done[tag] = 2
		return nil
	}
	for _, o := range sorted {
		if err = visit(o.Comment); err != nil {
			return nil, err
		}
	}
	var stale []Observed
	for _, r := range live {
		if _, ok := wanted[r.Comment]; !ok && isHold(r.Comment) == holds {
			stale = append(stale, r)
		}
	}
	sort.Slice(stale, func(i, j int) bool {
		pi, pj := removalPhase(stale[i]), removalPhase(stale[j])
		if pi != pj {
			return pi > pj
		}
		return stale[i].Comment < stale[j].Comment
	})
	for _, r := range stale {
		ops = append(ops, Op{Kind: "remove", Menu: r.Menu, Comment: r.Comment, id: r.ID, target: Object{Menu: r.Menu, Comment: r.Comment, Props: r.Props}})
	}
	if len(ops) == 0 {
		for _, o := range desired {
			if normalized(o.Menu, "invalid", live[o.Comment].Props["invalid"]) != "no" {
				return nil, errDrift
			}
		}
	}
	return ops, nil
}

func dummyRule(r Observed) bool {
	if !r.Dynamic || r.Props["action"] != "passthrough" {
		return false
	}
	switch r.Menu {
	case firewallFilter, ipv6Filter:
		return r.Props["chain"] == "forward"
	case firewallMangle:
		return slices.Contains([]string{"prerouting", "forward", "postrouting"}, r.Props["chain"])
	}
	return false
}

func planOrder(a Actual, desired []Object, wanted map[string]Object, stale map[string]bool) (slots map[string]*orderSlot, keep map[string]bool, err error) {
	slots = make(map[string]*orderSlot)
	keep = make(map[string]bool)
	prev := make(map[string]string)
	for _, o := range desired {
		if !strings.HasPrefix(o.Before, "tikray:") {
			continue
		}
		sibling, ok := wanted[o.Before]
		if !ok || sibling.Menu != o.Menu || sibling.Props["chain"] != o.Props["chain"] || prev[o.Before] != "" {
			return nil, nil, errPolicy
		}
		prev[o.Before] = o.Comment
	}
	for _, head := range desired {
		// The LAN hook runs after the owner's prerouting marks. An owner
		// may append a new rule after installation.
		if prev[head.Comment] != "" || head.Before == "" && head.Comment != "tikray:jump-pre" {
			continue
		}
		group := map[string]bool{}
		index := map[string]int{}
		tail := head
		for {
			group[tail.Comment] = true
			index[tail.Comment] = len(index)
			if !strings.HasPrefix(tail.Before, "tikray:") {
				break
			}
			tail = wanted[tail.Before]
		}
		chain := tail.Props["chain"]
		if chain == "" || (tail.Before != "" && tail.Before != "first:"+chain && !nativeRowID.MatchString(tail.Before)) {
			return nil, nil, errPolicy
		}
		for tag := range group {
			slots[tag] = &orderSlot{before: wanted[tag].Before, members: group, stale: stale}
		}
		var run []string
		found := false
		for _, r := range a.Rows {
			if r.Menu != head.Menu || r.Props["chain"] != chain || dummyRule(r) {
				continue
			}
			if stale[r.Comment] && ownedRole(r.Menu, r.Comment) {
				continue
			}
			if group[r.Comment] {
				run = append(run, r.Comment)
				continue
			}
			if tail.Before == "first:"+chain {
				// Temporary drops must stay ahead of permanent hooks. An
				// independent first-position hold is part of the same leading band.
				if isHold(r.Comment) {
					if !isHold(head.Comment) {
						run = nil
					}
					continue
				}
				break
			}
			if tail.Before != "" && r.ID == tail.Before {
				if !validFTAnchor(a.Topology, tail, r) {
					return nil, nil, errConflict
				}
				found = true
				break
			}
			run = nil
		}
		if nativeRowID.MatchString(tail.Before) && !found {
			return nil, nil, errConflict
		}
		// Keep the longest increasing subsequence adjacent to the anchor.
		// Moving any fewer existing rows leaves at least one inversion.
		var ends, at []int
		link := make([]int, len(run))
		for i, tag := range run {
			n := index[tag]
			p, _ := slices.BinarySearch(ends, n)
			link[i] = -1
			if p > 0 {
				link[i] = at[p-1]
			}
			if p == len(ends) {
				ends = append(ends, n)
				at = append(at, i)
			} else {
				ends[p] = n
				at[p] = i
			}
		}
		if len(at) > 0 {
			for i := at[len(at)-1]; i >= 0; i = link[i] {
				keep[run[i]] = true
			}
		}
	}
	return slots, keep, nil
}

func validFTAnchor(t Topology, o Object, r Observed) bool {
	if o.Comment != "tikray:no-fasttrack" || r.Dynamic || r.Props["action"] != "fasttrack-connection" || normalized(r.Menu, "disabled", r.Props["disabled"]) != "no" {
		return false
	}
	ft, err := fastTrackException(t.FastTrack)
	return err == nil && ft != nil && ft.Before == r.ID && maps.Equal(ft.Props, o.Props)
}
