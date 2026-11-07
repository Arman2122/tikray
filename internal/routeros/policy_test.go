package routeros

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

func trafficFixture() (PolicyInput, Topology, map[store.Policy]bool) {
	in := PolicyInput{Network: store.Network{Subnet: netip.MustParsePrefix("172.18.64.0/28")}}
	obs := Topology{
		LANList: "inside", ForeignRoutingMarks: []string{"owner-route", "main"},
		WAN: []WANPath{{Interface: "ether1", Gateway: netip.MustParseAddr("192.0.2.9"), Network: netip.MustParsePrefix("192.0.2.0/24")}},
	}
	active := map[store.Policy]bool{}
	for _, mode := range []store.Mode{store.ModeSmart, store.ModeFull} {
		for _, closed := range []bool{false, true} {
			active[store.Policy{Mode: mode, KillSwitch: closed}] = true
		}
	}
	return in, obs, active
}

type testPacket struct {
	ingress, sourceList, destList, destType, protocol, port string
	state, connectionMark, routingMark                      string
}

// Follow the rendered chain, including its ingress hook. Unknown matchers or
// actions must fail the test instead of silently turning into wildcards.
func preroute(t *testing.T, rules []Object, p testPacket) (string, string) {
	t.Helper()
	for _, chain := range []string{"prerouting", "tikray-pre"} {
		entered := false
		for _, r := range rules {
			v := r.Props
			if r.Menu != "/ip/firewall/mangle" || v["chain"] != chain {
				continue
			}
			packet := map[string]string{
				"in-interface-list": p.ingress, "src-address-list": p.sourceList, "dst-address-list": p.destList, "src-address-type": "unicast",
				"dst-address-type": p.destType, "connection-mark": p.connectionMark, "routing-mark": p.routingMark,
				"connection-state": p.state, "protocol": p.protocol, "dst-port": p.port,
			}
			match := true
			for k, want := range v {
				switch k {
				case "chain", "action", "jump-target", "new-connection-mark", "new-routing-mark", "passthrough":
					continue
				}
				got, ok := packet[k]
				if !ok {
					t.Fatalf("unknown packet matcher %s", k)
				}
				plain, neg := strings.CutPrefix(want, "!")
				if (got == plain) == neg {
					match = false
				}
			}
			if !match {
				continue
			}
			switch v["action"] {
			case "jump":
				if v["jump-target"] != "tikray-pre" {
					t.Fatal("unexpected jump")
				}
				entered = true
			case "return":
				return p.connectionMark, p.routingMark
			case "mark-connection":
				p.connectionMark = v["new-connection-mark"]
			case "mark-routing":
				p.routingMark = v["new-routing-mark"]
			default:
				t.Fatalf("unknown packet action %s", v["action"])
			}
			if v["passthrough"] == "no" {
				break
			}
		}
		if !entered {
			break
		}
	}
	return p.connectionMark, p.routingMark
}

func TestLocalReturnAndConnectionMarks(t *testing.T) {
	in, obs, active := trafficFixture()
	rules, err := ipv4Policy(in, obs, active)
	if err != nil {
		t.Fatal(err)
	}
	first, jumps := true, 0
	for _, r := range rules {
		if r.Menu != "/ip/firewall/mangle" {
			continue
		}
		switch r.Props["chain"] {
		case "prerouting":
			if r.Props["action"] != "jump" || r.Props["in-interface-list"] != obs.LANList {
				t.Fatal("unscoped prerouting hook")
			}
			jumps++
		case "tikray-pre":
			if first && (r.Props["action"] != "return" || r.Props["dst-address-type"] != "local") {
				t.Fatal("router-local return must come first")
			}
			first = false
		}
	}
	if first || jumps != 1 {
		t.Fatal("missing chain or unexpected number of jumps")
	}
	for policy := range active {
		table := "tikray-open"
		if policy.KillSwitch {
			table = "tikray-closed"
		}
		base := testPacket{ingress: "inside", sourceList: srcList(policy), state: "new", connectionMark: "no-mark", routingMark: "", protocol: "tcp", port: "443"}
		check := func(name string, p testPacket, cm, rm string) {
			t.Helper()
			if c, r := preroute(t, rules, p); c != cm || r != rm {
				t.Errorf("%s %v: got marks %q/%q, want %q/%q", name, policy, c, r, cm, rm)
			}
		}
		check("foreign destination", base, table, table)
		p := base
		p.destType = "local"
		check("router", p, "no-mark", "")
		p = base
		p.destList = "tikray-local"
		check("LAN destination", p, "no-mark", "")
		p = base
		p.destList = "tikray-domestic"
		if policy.Mode == store.ModeSmart {
			check("smart domestic", p, "no-mark", "")
		} else {
			check("full domestic", p, table, table)
		}
		p = base
		p.sourceList = ""
		check("explicit direct", p, "no-mark", "")
		p = base
		p.ingress = "guest"
		check("wrong ingress", p, "no-mark", "")
		p = base
		p.connectionMark = "owner-connection"
		check("foreign connection", p, "owner-connection", "")
		p = base
		p.routingMark = "owner-route"
		check("foreign routing", p, "no-mark", "owner-route")
		p.routingMark = "main"
		check("explicit main route", p, "no-mark", "main")
		p = base
		p.state = "established"
		check("existing unmarked", p, "no-mark", "")
		p.connectionMark = table
		p.sourceList = ""
		check("moved client", p, table, table)
		p.ingress = "container-bridge"
		check("runner reply", p, table, "")
		p.ingress = "WAN"
		p.destType = "local"
		check("WAN NAT reply", p, table, "")
		for _, proto := range []string{"tcp", "udp"} {
			p = base
			p.protocol = proto
			p.port = "53"
			check("external DNS", p, "no-mark", "")
		}
	}
}

func TestTablesDNSAndFastTrack(t *testing.T) {
	in, obs, active := trafficFixture()
	obs.FastTrack = []FastTrackRule{{ID: "*A", Match: map[string]string{"connection-state": "established,related", "protocol": "tcp", "out-interface": "ether1"}, Next: &ForwardRule{ID: "*B", Action: "accept", Match: map[string]string{"connection-state": "established,related,untracked"}}}}
	rules, err := ipv4Policy(in, obs, active)
	if err != nil {
		t.Fatal(err)
	}
	var tables, routes, primary, fallbacks, clamps, marks, accepts, guards, redirects, watches int
	var open, closed []string
	var watch Object
	for _, r := range rules {
		v := r.Props
		switch r.Menu {
		case "/routing/table":
			if v["fib"] != "yes" || (v["name"] != "tikray-open" && v["name"] != "tikray-closed") {
				t.Fatal("unexpected FIB")
			}
			tables++
		case "/ip/route":
			if v["dst-address"] != "0.0.0.0/0" || !slices.Contains([]string{"tikray-open", "tikray-closed"}, v["routing-table"]) {
				t.Fatal("unexpected route")
			}
			switch v["distance"] {
			case "1":
				if v["gateway"] != in.Network.Runner().String() || v["check-gateway"] != "ping" {
					t.Fatal("bad primary")
				}
				primary++
			case "2":
				if v["routing-table"] == "tikray-open" && v["gateway"] != obs.WAN[0].Gateway.String() || v["routing-table"] == "tikray-closed" && v["blackhole"] != "yes" {
					t.Fatal("bad fallback")
				}
				fallbacks++
			default:
				t.Fatal("unexpected distance")
			}
			routes++
		case "/ip/firewall/mangle":
			if v["chain"] != "forward" {
				continue
			}
			if !slices.Contains([]string{"tikray-open", "tikray-closed"}, v["connection-mark"]) {
				t.Fatal("foreign mark eligibility")
			}
			switch v["action"] {
			case "change-mss":
				if v["protocol"] != "tcp" || v["tcp-flags"] != "syn" || v["new-mss"] != "clamp-to-pmtu" {
					t.Fatal("bad MSS clamp")
				}
				clamps++
			case "mark-packet":
				if v["packet-mark"] != "no-mark" || v["new-packet-mark"] != "tikray-proxied" || v["in-interface-list"] != "" {
					t.Fatal("packet mark must cover both directions without overriding owner marks")
				}
				marks++
			}
		case "/ip/firewall/filter":
			switch v["action"] {
			case "accept":
				if r.Before != "*A" || v["chain"] != "forward" || v["packet-mark"] != "tikray-proxied" || v["connection-state"] != "established,related" || v["protocol"] != "tcp" || v["out-interface"] != "ether1" {
					t.Fatal("FastTrack eligibility or ordering changed")
				}
				accepts++
			case "jump":
				if v["chain"] != "forward" || v["in-interface-list"] != "inside" || v["out-interface"] != "!tikray" || r.Before != "first:forward" {
					t.Fatal("closed guard scope")
				}
				guards++
			}
		case "/ip/firewall/nat":
			if v["chain"] != "dstnat" || v["dst-port"] != "53" || v["to-ports"] != "53" || !slices.Contains([]string{"tcp", "udp"}, v["protocol"]) || v["in-interface-list"] != "inside" || !strings.HasPrefix(v["src-address-list"], "tikray-src-") {
				t.Fatal("DNS scope or unexpected NAT")
			}
			if v["action"] != "dst-nat" {
				continue
			}
			if v["to-addresses"] != in.Network.Runner().String() {
				t.Fatal("wrong DNS endpoint")
			}
			if _, ok := v["disabled"]; ok {
				t.Fatal("netwatch runtime state included in diff")
			}
			if strings.HasSuffix(v["src-address-list"], "-open") {
				if !r.InitialDisabled {
					t.Fatal("open DNS is unsafe to create enabled on a dead runner")
				}
				open = append(open, r.Comment)
			} else {
				if r.InitialDisabled {
					t.Fatal("closed DNS starts disabled")
				}
				closed = append(closed, r.Comment)
			}
			redirects++
		case "/tool/netwatch":
			watches++
			watch = r
		}
	}
	if tables != 2 || routes != 4 || primary != 2 || fallbacks != 2 || clamps != 2 || marks != 2 || accepts != 1 || guards == 0 || redirects != 8 || watches != 1 {
		t.Fatalf("unexpected object counts: tables=%d routes=%d primaries=%d fallbacks=%d clamps=%d marks=%d accepts=%d guards=%d redirects=%d watches=%d", tables, routes, primary, fallbacks, clamps, marks, accepts, guards, redirects, watches)
	}
	if watch.Comment != "tikray:runner-watch" || watch.Props["host"] != in.Network.Runner().String() || watch.Props["startup-delay"] != "0s" || watch.Props["start-delay"] != "0s" {
		t.Fatal("netwatch host/startup")
	}
	for _, key := range []string{"up-script", "down-script", "test-script"} {
		s := watch.Props[key]
		for _, tag := range open {
			if !strings.Contains(s, `comment="`+tag+`"`) {
				t.Errorf("%s missing exact open DNS identity", key)
			}
		}
		for _, tag := range closed {
			if strings.Contains(s, tag) {
				t.Errorf("%s changes closed DNS", key)
			}
		}
		if strings.Contains(s, "comment~") {
			t.Fatal("broad watch predicate")
		}
	}
	obs.FastTrack = nil
	rules, err = ipv4Policy(in, obs, active)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.Props["action"] == "mark-packet" || r.Menu == "/ip/firewall/filter" && r.Props["action"] == "accept" {
			t.Fatal("unnecessary FastTrack exemption")
		}
	}
	obs.FastTrack = []FastTrackRule{{ID: "*1", Match: map[string]string{"connection-state": "established,related", "nth": "2,1"}}}
	if out, err := ipv4Policy(in, obs, active); err == nil || len(out) != 0 {
		t.Fatal("stateful matcher was copied into a second rule")
	}
}

func TestClosedGuardSurvivesMissingRoutes(t *testing.T) {
	in, obs, active := trafficFixture()
	rules, err := ipv4Policy(in, obs, active)
	if err != nil {
		t.Fatal(err)
	}
	var chain string
	for _, r := range rules {
		if r.Menu == "/ip/firewall/filter" && r.Props["chain"] == "forward" && r.Props["action"] == "jump" {
			chain = r.Props["jump-target"]
		}
	}
	if chain == "" {
		t.Fatal("missing WAN hook")
	}
	dropped := func(source, dest, connection, egress, proto string) bool {
		packet := map[string]string{"src-address-list": source, "dst-address-list": dest, "connection-mark": connection, "out-interface": egress, "in-interface-list": obs.LANList}
		if proto != "" {
			packet["connection-nat-state"] = "dstnat"
			packet["dst-address"] = in.Network.Runner().String()
			packet["dst-port"] = "53"
			packet["protocol"] = strings.TrimPrefix(proto, "router-")
			if strings.HasPrefix(proto, "router-") {
				packet["dst-address"] = "10.20.0.1"
			}
			if proto == "https" {
				packet["protocol"] = "tcp"
				packet["dst-port"] = "443"
			}
		}
		for _, c := range []string{"forward", chain} {
			entered := false
			for _, r := range rules {
				v := r.Props
				if r.Menu != "/ip/firewall/filter" || v["chain"] != c {
					continue
				}
				matched := true
				for k, want := range v {
					switch k {
					case "chain", "action", "jump-target":
						continue
					}
					plain, neg := strings.CutPrefix(want, "!")
					if (packet[k] == plain) == neg {
						matched = false
					}
				}
				if !matched {
					continue
				}
				switch v["action"] {
				case "jump":
					entered = true
				case "return":
					return false
				case "drop":
					return true
				default:
					t.Fatal("unexpected guard action")
				}
			}
			if !entered {
				break
			}
		}
		return false
	}
	for p := range active {
		for _, egress := range []string{"ether1", "owner-tunnel"} {
			for _, dest := range []string{"tikray-domestic", "tikray-local", ""} {
				want := p.KillSwitch && dest != "tikray-local" && (p.Mode == store.ModeFull || dest != "tikray-domestic")
				if got := dropped(srcList(p), dest, "owner", egress, ""); got != want {
					t.Errorf("unexpected guard decision for %v, %s, %s", p, dest, egress)
				}
			}
			for _, proto := range []string{"tcp", "udp", "router-tcp", "router-udp"} {
				if !dropped(srcList(p), "tikray-local", "owner", egress, proto) || dropped(srcList(p), "tikray-local", "owner", "tikray", proto) || dropped("", "tikray-local", "owner", egress, proto) {
					t.Errorf("translated %s DNS protection for %v on %s", proto, p, egress)
				}
			}
			if dropped(srcList(p), "tikray-local", "owner", egress, "https") {
				t.Fatal("unrelated non-DNS DNAT dropped")
			}
		}
	}
	if !dropped("", "", "tikray-closed", "ether1", "") || dropped("", "", "owner", "ether1", "") {
		t.Fatal("existing connections lost their protection or a foreign flow was captured")
	}
}

func TestDNSFallbackForNewTransactions(t *testing.T) {
	in, obs, active := trafficFixture()
	rules, err := ipv4Policy(in, obs, active)
	if err != nil {
		t.Fatal(err)
	}
	// NAT chooses the first matching rule only on the initial packet. Keep
	// that decision for the old socket while resolving a new transaction.
	resolver := func(source, proto string, runnerUp bool) string {
		for _, r := range rules {
			v := r.Props
			if r.Menu != "/ip/firewall/nat" || v["src-address-list"] != source || v["protocol"] != proto {
				continue
			}
			if r.InitialDisabled && !runnerUp {
				continue
			}
			switch v["action"] {
			case "dst-nat":
				return v["to-addresses"]
			case "redirect":
				return "router"
			default:
				t.Fatal("unexpected NAT action")
			}
		}
		return "client-selected"
	}
	for p := range active {
		for _, proto := range []string{"tcp", "udp"} {
			oldBinding := resolver(srcList(p), proto, true)
			newBinding := resolver(srcList(p), proto, false)
			if oldBinding != in.Network.Runner().String() {
				t.Fatal("healthy query escaped runner")
			}
			if p.KillSwitch && newBinding != oldBinding || !p.KillSwitch && newBinding != "router" {
				t.Fatalf("outage resolver for %v %s", p, proto)
			}
			if resolver("", proto, false) != "client-selected" || resolver("", proto, true) != "client-selected" {
				t.Fatal("direct DNS changed")
			}
		}
	}
}

func TestFastTrackRelevantAnchor(t *testing.T) {
	in, obs, active := trafficFixture()
	obs.FastTrack = []FastTrackRule{
		{ID: "*3", Match: map[string]string{"connection-mark": "owner-only"}},
		{ID: "*5", Match: map[string]string{"connection-state": "related,established"}, Next: &ForwardRule{ID: "*7", Action: "accept", Match: map[string]string{"connection-state": "established,related"}}},
	}
	out, err := ipv4Policy(in, obs, active)
	if err != nil {
		t.Fatal(err)
	}
	accepts := 0
	for _, r := range out {
		if r.Menu == "/ip/firewall/filter" && r.Props["action"] == "accept" {
			if r.Before != "*5" {
				t.Fatal("exception bypasses an intervening owner filter")
			}
			accepts++
		}
	}
	if accepts != 1 {
		t.Fatal("unexpected number of FastTrack exceptions")
	}
	second := FastTrackRule{ID: "*6", Match: map[string]string{"connection-state": "established", "in-interface": "different"}}
	obs.FastTrack = append(obs.FastTrack, second)
	if out, err := ipv4Policy(in, obs, active); err == nil || len(out) != 0 {
		t.Fatal("multiple relevant eligibility predicates were collapsed")
	}
}

func TestFastTrackCannotBroadenDownstreamVerdict(t *testing.T) {
	in, obs, active := trafficFixture()
	obs.FastTrack = []FastTrackRule{{ID: "*A", Match: map[string]string{"connection-state": "established,related"}, Logged: true, Next: &ForwardRule{ID: "*B", Action: "accept"}}}
	if rows, err := ipv4Policy(in, obs, active); err == nil || len(rows) > 0 {
		t.Fatal("FastTrack exception suppressed owner logging")
	}
	for _, tc := range []struct {
		label string
		next  *ForwardRule
		safe  bool
	}{
		{"missing", nil, false}, {"denied", &ForwardRule{ID: "*B", Action: "drop"}, false},
		{"logged", &ForwardRule{ID: "*B", Action: "accept", Logged: true}, false},
		{"narrower-state", &ForwardRule{ID: "*B", Action: "accept", Match: map[string]string{"connection-state": "related"}}, false},
		{"negated-state-list", &ForwardRule{ID: "*B", Action: "accept", Match: map[string]string{"connection-state": "!new,established,related"}}, false},
		{"narrower-protocol", &ForwardRule{ID: "*B", Action: "accept", Match: map[string]string{"protocol": "tcp"}}, false},
		{"different-NAT", &ForwardRule{ID: "*B", Action: "accept", Match: map[string]string{"connection-nat-state": "dstnat"}}, false},
		{"matching-NAT", &ForwardRule{ID: "*B", Action: "accept", Match: map[string]string{"connection-nat-state": "srcnat"}}, true},
		{"unconditional", &ForwardRule{ID: "*B", Action: "accept"}, true},
	} {
		obs.FastTrack = []FastTrackRule{{ID: "*A", Match: map[string]string{"connection-state": "established,related", "connection-nat-state": "srcnat"}, Next: tc.next}}
		out, err := ipv4Policy(in, obs, active)
		if (err == nil) != tc.safe || err != nil && len(out) != 0 {
			t.Errorf("successor %s yielded unsafe decision", tc.label)
		}
	}
}
