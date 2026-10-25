package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

// The targets of the rules the tests expect, as JSON members.
const (
	toOpen   = `"balancerTag":"proxy-open"`
	toClosed = `"balancerTag":"proxy-closed"`
	toDirect = `"outboundTag":"direct"`
	toBlock  = `"outboundTag":"block"`
)

// ruleCase is an input and the traffic rules it renders: the rules for the
// TUN inbound, in order.
type ruleCase struct {
	name string
	in   Input
	want []string
}

// input returns an Input for testCore without geo data. Its state is the one
// with a single enabled server, idA, as edit changes it.
func input(edit func(st *store.State)) Input {
	st := smart(testServer(idA, false))
	edit(&st)
	return Input{State: st, Core: testCore}
}

// withGeo returns in with the geo data geo.
func withGeo(in Input, geo *Geo) Input {
	in.Geo = geo
	return in
}

// testGeo is the geo data the tests install.
var testGeo = &Geo{Version: "202610250000", Site: []string{"geosite:category-ir"}, IP: []string{"geoip:ir"}}

// dev is the device at addr with the policy mode, and the kill switch on
// when killSwitch is set.
func dev(addr string, mode store.Mode, killSwitch bool) store.Device {
	return store.Device{Address: netip.MustParsePrefix(addr), Policy: store.Policy{Mode: mode, KillSwitch: killSwitch}}
}

// extras are the domestic matchers the cases add beside the geo data's.
func extras() store.Domestic {
	return store.Domestic{Domains: []string{"domain:domestic.test"}, IPs: []string{"203.0.113.20/32"}}
}

// tun is a traffic rule: an object with inboundTag tun-in and the members in
// body.
func tun(body string) string { return `{"inboundTag":["tun-in"],` + body + `}` }

// catchAll is the final rule, which sends all the traffic that reaches it to
// target.
func catchAll(target string) string { return tun(`"network":"tcp,udp",` + target) }

// fromRule is the rule that sends the traffic of sources to target.
func fromRule(target string, sources ...string) string {
	b, err := json.Marshal(sources)
	if err != nil {
		panic(err)
	}
	return tun(`"source":` + string(b) + `,` + target)
}

// The domestic rules for extras, for every source.
var (
	domesticDomainRule = tun(`"domain":["domain:domestic.test"],` + toDirect)
	domesticIPRule     = tun(`"ip":["203.0.113.20/32"],` + toDirect)
)

// splitRules returns the rules that follow the five service rules: first the
// rules for the queries xray's DNS sends itself, then the traffic rules. It
// fails the test if a rule there is for another inbound, or if a DNS rule
// comes after a traffic rule.
func splitRules(t *testing.T, rules []json.RawMessage) (dnsRules, traffic []json.RawMessage) {
	t.Helper()
	const services = 5
	if len(rules) < services {
		t.Fatalf("routing.rules has %d rules, want at least the %d service rules", len(rules), services)
	}
	rest := rules[services:]
	n := 0
	for n < len(rest) && inboundOf(t, rest[n]) == TagDNS {
		n++
	}
	for _, r := range rest[n:] {
		if got := inboundOf(t, r); got != TagTUN {
			t.Fatalf("rule %s, after the DNS rules, is for inbound %q, want %q", r, got, TagTUN)
		}
	}
	return rest[:n], rest[n:]
}

// inboundOf returns the inbound tag of rule raw, which must name exactly one.
func inboundOf(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var r struct {
		InboundTag []string `json:"inboundTag"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || len(r.InboundTag) != 1 {
		t.Fatalf("rule %s does not name exactly one inbound", raw)
	}
	return r.InboundTag[0]
}

// wantRules fails the test unless got holds exactly the rules in want, in
// order.
func wantRules(t *testing.T, what string, got []json.RawMessage, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d rules, want %d:\n got %s\nwant %s", what, len(got), len(want),
			compactAll(t, got), compactAll(t, toRaw(want)))
	}
	for i := range want {
		jsonEqual(t, fmt.Sprintf("%s[%d]", what, i), got[i], want[i])
	}
}

// toRaw returns list as JSON values.
func toRaw(list []string) []json.RawMessage {
	out := make([]json.RawMessage, len(list))
	for i, s := range list {
		out[i] = json.RawMessage(s)
	}
	return out
}

// compactAll returns list as one compact JSON array, a rule to a line.
func compactAll(t *testing.T, list []json.RawMessage) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("[\n")
	for _, raw := range list {
		var c bytes.Buffer
		if err := json.Compact(&c, raw); err != nil {
			t.Fatalf("invalid JSON %s: %v", raw, err)
		}
		b.WriteString("  " + c.String() + "\n")
	}
	b.WriteString("]")
	return b.String()
}

// checkTraffic renders each case and checks its traffic rules. While the
// balancers have no member, no rule may name one.
func checkTraffic(t *testing.T, cases []ruleCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, b := mustRenderInput(t, tc.in)
			_, traffic := splitRules(t, out.Routing.Rules)
			wantRules(t, "traffic rules", traffic, tc.want)
			if !ProxyAvailable(tc.in.State) && bytes.Contains(b, []byte("balancerTag")) {
				t.Errorf("a rule names a balancer, but the balancers have no member:\n%s", b)
			}
		})
	}
}

var defaultSmartCases = []ruleCase{{
	name: "default smart, no devices",
	in: input(func(st *store.State) {
		st.Routing.BlockList = []string{"domain:ads.test"}
		st.Routing.Domestic = extras()
	}),
	// No source rule: no device has the kill switch, so the source set of
	// the proxy-closed rule is empty and the rule is left out.
	want: []string{
		tun(`"domain":["domain:ads.test"],` + toBlock),
		domesticDomainRule,
		domesticIPRule,
		catchAll(toOpen),
	},
}}

func TestRulesDefaultSmart(t *testing.T) { checkTraffic(t, defaultSmartCases) }

var killSwitchCases = []ruleCase{
	{
		name: "kill switch default, one open device",
		in: input(func(st *store.State) {
			st.DefaultPolicy = store.Policy{Mode: store.ModeSmart, KillSwitch: true}
			st.Devices = []store.Device{dev("192.168.88.10/32", store.ModeSmart, false)}
		}),
		want: []string{
			fromRule(toOpen, "192.168.88.10/32"),
			catchAll(toClosed),
		},
	},
	{
		// The open rule has no source left, so it is left out. With an empty
		// source it would match every device, and send them all direct
		// while no server is up.
		name: "kill switch default, no open device",
		in: input(func(st *store.State) {
			st.DefaultPolicy = store.Policy{Mode: store.ModeSmart, KillSwitch: true}
			st.Devices = []store.Device{
				dev("192.168.88.11/32", store.ModeSmart, true),
				dev("192.168.88.12/32", store.ModeDirect, false),
			}
		}),
		want: []string{catchAll(toClosed)},
	},
	{
		name: "kill switch default, sources sorted by address",
		in: input(func(st *store.State) {
			st.DefaultPolicy = store.Policy{Mode: store.ModeSmart, KillSwitch: true}
			st.Devices = []store.Device{
				dev("192.168.88.100/32", store.ModeSmart, false),
				dev("192.168.88.9/32", store.ModeFull, false),
				dev("10.1.0.0/24", store.ModeSmart, false),
			}
		}),
		want: []string{
			fromRule(toOpen, "192.168.88.9/32"),
			fromRule(toOpen, "10.1.0.0/24", "192.168.88.9/32", "192.168.88.100/32"),
			catchAll(toClosed),
		},
	},
}

func TestRulesKillSwitchDefault(t *testing.T) { checkTraffic(t, killSwitchCases) }

// smartPair are the two smart devices of the full-default cases, listed out
// of address order.
func smartPair() []store.Device {
	return []store.Device{
		dev("192.168.88.21/32", store.ModeSmart, true),
		dev("192.168.88.20/32", store.ModeSmart, false),
	}
}

var fullDefaultCases = []ruleCase{
	{
		name: "full default, smart devices",
		in: input(func(st *store.State) {
			st.DefaultPolicy = store.Policy{Mode: store.ModeFull}
			st.Devices = smartPair()
			st.Routing.Domestic = extras()
		}),
		want: []string{
			tun(`"source":["192.168.88.20/32","192.168.88.21/32"],"domain":["domain:domestic.test"],` + toDirect),
			tun(`"source":["192.168.88.20/32","192.168.88.21/32"],"ip":["203.0.113.20/32"],` + toDirect),
			fromRule(toClosed, "192.168.88.21/32"),
			catchAll(toOpen),
		},
	},
	{
		name: "full default with the kill switch, smart devices",
		in: input(func(st *store.State) {
			st.DefaultPolicy = store.Policy{Mode: store.ModeFull, KillSwitch: true}
			st.Devices = smartPair()
			st.Routing.Domestic = extras()
		}),
		want: []string{
			tun(`"source":["192.168.88.20/32","192.168.88.21/32"],"domain":["domain:domestic.test"],` + toDirect),
			tun(`"source":["192.168.88.20/32","192.168.88.21/32"],"ip":["203.0.113.20/32"],` + toDirect),
			fromRule(toOpen, "192.168.88.20/32"),
			catchAll(toClosed),
		},
	},
	{
		// No smart source is left for the domestic rules, so they are left
		// out. Without a source they would send the full devices' domestic
		// traffic direct.
		name: "full default, no smart device",
		in: input(func(st *store.State) {
			st.DefaultPolicy = store.Policy{Mode: store.ModeFull}
			st.Devices = []store.Device{dev("192.168.88.22/32", store.ModeDirect, false)}
			st.Routing.Domestic = extras()
		}),
		want: []string{catchAll(toOpen)},
	},
}

func TestRulesFullDefault(t *testing.T) { checkTraffic(t, fullDefaultCases) }

var fullDeviceCases = []ruleCase{{
	name: "smart default, full devices",
	in: input(func(st *store.State) {
		st.Devices = []store.Device{
			dev("192.168.88.31/32", store.ModeFull, true),
			dev("192.168.88.30/32", store.ModeFull, false),
		}
		st.Routing.Domestic = extras()
	}),
	// The full sources come before the domestic rules, which they skip.
	want: []string{
		fromRule(toOpen, "192.168.88.30/32"),
		fromRule(toClosed, "192.168.88.31/32"),
		domesticDomainRule,
		domesticIPRule,
		fromRule(toClosed, "192.168.88.31/32"),
		catchAll(toOpen),
	},
}}

func TestRulesFullDevices(t *testing.T) { checkTraffic(t, fullDeviceCases) }

var customCases = []ruleCase{
	{
		name: "one rule of each action",
		in: input(func(st *store.State) {
			st.Servers = []store.Server{testServer(idA, false), testServer(idB, true)}
			st.Devices = []store.Device{dev("192.168.88.40/32", store.ModeSmart, true)}
			st.Routing.Rules = []store.Rule{
				{Domains: []string{"domain:d.test"}, Action: store.ActionDirect},
				{IPs: []string{"198.51.100.0/24"}, Action: store.ActionBlock},
				{Domains: []string{"domain:p.test"}, Action: store.ActionProxy},
				{Domains: []string{"domain:s.test"}, Action: store.ActionServer, Server: idA},
				// idB is disabled: the rule is skipped.
				{Domains: []string{"domain:off.test"}, Action: store.ActionServer, Server: idB},
				{Domains: []string{"domain:both.test"}, IPs: []string{"198.51.100.7/32"}, Action: store.ActionDirect},
			}
		}),
		want: []string{
			tun(`"domain":["domain:d.test"],` + toDirect),
			tun(`"ip":["198.51.100.0/24"],` + toBlock),
			tun(`"source":["192.168.88.40/32"],"domain":["domain:p.test"],` + toClosed),
			tun(`"domain":["domain:p.test"],` + toOpen),
			tun(`"domain":["domain:s.test"],"outboundTag":"srv-` + idA + `"`),
			tun(`"domain":["domain:both.test"],` + toDirect),
			tun(`"ip":["198.51.100.7/32"],` + toDirect),
			fromRule(toClosed, "192.168.88.40/32"),
			catchAll(toOpen),
		},
	},
	{
		name: "proxy, kill switch default",
		in: input(func(st *store.State) {
			st.DefaultPolicy = store.Policy{Mode: store.ModeSmart, KillSwitch: true}
			st.Devices = []store.Device{
				dev("192.168.88.41/32", store.ModeSmart, false),
				dev("192.168.88.42/32", store.ModeSmart, true),
			}
			st.Routing.Rules = []store.Rule{{Domains: []string{"domain:p.test"}, Action: store.ActionProxy}}
		}),
		want: []string{
			tun(`"source":["192.168.88.41/32"],"domain":["domain:p.test"],` + toOpen),
			tun(`"domain":["domain:p.test"],` + toClosed),
			fromRule(toOpen, "192.168.88.41/32"),
			catchAll(toClosed),
		},
	},
	{
		// Each matcher list gets the whole pair, domains first.
		name: "proxy with domains and IPs",
		in: input(func(st *store.State) {
			st.Devices = []store.Device{dev("192.168.88.43/32", store.ModeSmart, true)}
			st.Routing.Rules = []store.Rule{{Domains: []string{"domain:p.test"}, IPs: []string{"198.51.100.9/32"}, Action: store.ActionProxy}}
		}),
		want: []string{
			tun(`"source":["192.168.88.43/32"],"domain":["domain:p.test"],` + toClosed),
			tun(`"domain":["domain:p.test"],` + toOpen),
			tun(`"source":["192.168.88.43/32"],"ip":["198.51.100.9/32"],` + toClosed),
			tun(`"ip":["198.51.100.9/32"],` + toOpen),
			fromRule(toClosed, "192.168.88.43/32"),
			catchAll(toOpen),
		},
	},
	{
		name: "proxy, no kill-switch device",
		in: input(func(st *store.State) {
			st.Routing.Rules = []store.Rule{{Domains: []string{"domain:p.test"}, Action: store.ActionProxy}}
		}),
		want: []string{
			tun(`"domain":["domain:p.test"],` + toOpen),
			catchAll(toOpen),
		},
	},
	{
		name: "full default: only for the smart sources",
		in: input(func(st *store.State) {
			st.DefaultPolicy = store.Policy{Mode: store.ModeFull}
			st.Devices = []store.Device{
				dev("192.168.88.44/32", store.ModeSmart, false),
				dev("192.168.88.45/32", store.ModeFull, true),
			}
			st.Routing.Rules = []store.Rule{
				{Domains: []string{"domain:d.test"}, Action: store.ActionDirect},
				// No smart source has the kill switch, so the pair's
				// proxy-closed rule has an empty intersection and is dropped.
				{Domains: []string{"domain:p.test"}, Action: store.ActionProxy},
			}
		}),
		want: []string{
			fromRule(toClosed, "192.168.88.45/32"),
			tun(`"source":["192.168.88.44/32"],"domain":["domain:d.test"],` + toDirect),
			tun(`"source":["192.168.88.44/32"],"domain":["domain:p.test"],` + toOpen),
			fromRule(toClosed, "192.168.88.45/32"),
			catchAll(toOpen),
		},
	},
	{
		name: "full kill switch default: only for the smart sources",
		in: input(func(st *store.State) {
			st.DefaultPolicy = store.Policy{Mode: store.ModeFull, KillSwitch: true}
			st.Devices = []store.Device{
				dev("192.168.88.47/32", store.ModeSmart, true),
				dev("192.168.88.46/32", store.ModeSmart, false),
			}
			st.Routing.Rules = []store.Rule{
				{Domains: []string{"domain:p.test"}, Action: store.ActionProxy},
				{Domains: []string{"domain:b.test"}, Action: store.ActionBlock},
			}
		}),
		want: []string{
			tun(`"source":["192.168.88.46/32"],"domain":["domain:p.test"],` + toOpen),
			tun(`"source":["192.168.88.46/32","192.168.88.47/32"],"domain":["domain:p.test"],` + toClosed),
			tun(`"source":["192.168.88.46/32","192.168.88.47/32"],"domain":["domain:b.test"],` + toBlock),
			fromRule(toOpen, "192.168.88.46/32"),
			catchAll(toClosed),
		},
	},
	{
		name: "full default, no smart device: no custom rule",
		in: input(func(st *store.State) {
			st.DefaultPolicy = store.Policy{Mode: store.ModeFull}
			st.Devices = []store.Device{dev("192.168.88.48/32", store.ModeFull, false)}
			st.Routing.Rules = []store.Rule{{Domains: []string{"domain:d.test"}, Action: store.ActionDirect}}
		}),
		want: []string{
			fromRule(toOpen, "192.168.88.48/32"),
			catchAll(toOpen),
		},
	},
}

func TestRulesCustom(t *testing.T) { checkTraffic(t, customCases) }

var directDefaultCases = []ruleCase{
	{
		name: "direct default, smart devices",
		in: input(func(st *store.State) {
			st.DefaultPolicy = store.Policy{Mode: store.ModeDirect}
			st.Devices = []store.Device{
				dev("192.168.88.60/32", store.ModeSmart, false),
				dev("192.168.88.61/32", store.ModeSmart, true),
			}
		}),
		want: []string{
			fromRule(toClosed, "192.168.88.61/32"),
			fromRule(toOpen, "192.168.88.60/32"),
			catchAll(toDirect),
		},
	},
	{
		// The final rules list the full devices as well, as the other
		// defaults' do, so that they do not depend on rule 2 to keep a
		// kill-switch device off the catch-all direct rule.
		name: "direct default, smart and full devices",
		in: input(func(st *store.State) {
			st.DefaultPolicy = store.Policy{Mode: store.ModeDirect}
			st.Devices = []store.Device{
				dev("192.168.88.63/32", store.ModeFull, true),
				dev("192.168.88.62/32", store.ModeFull, false),
				dev("192.168.88.61/32", store.ModeSmart, true),
				dev("192.168.88.60/32", store.ModeSmart, false),
			}
		}),
		want: []string{
			fromRule(toOpen, "192.168.88.62/32"),
			fromRule(toClosed, "192.168.88.63/32"),
			fromRule(toClosed, "192.168.88.61/32", "192.168.88.63/32"),
			fromRule(toOpen, "192.168.88.60/32", "192.168.88.62/32"),
			catchAll(toDirect),
		},
	},
	{
		name: "direct default, no devices",
		in: input(func(st *store.State) {
			st.DefaultPolicy = store.Policy{Mode: store.ModeDirect}
		}),
		want: []string{catchAll(toDirect)},
	},
}

func TestRulesDirectDefault(t *testing.T) { checkTraffic(t, directDefaultCases) }

var noServerCases = []ruleCase{
	{
		name: "kill switch default, no servers",
		in: input(func(st *store.State) {
			st.Servers = []store.Server{}
			st.DefaultPolicy = store.Policy{Mode: store.ModeSmart, KillSwitch: true}
			st.Devices = []store.Device{dev("192.168.88.70/32", store.ModeSmart, false)}
		}),
		want: []string{
			fromRule(toDirect, "192.168.88.70/32"),
			catchAll(toBlock),
		},
	},
	{
		name: "kill switch default, only a disabled server",
		in: input(func(st *store.State) {
			st.Servers = []store.Server{testServer(idA, true)}
			st.DefaultPolicy = store.Policy{Mode: store.ModeSmart, KillSwitch: true}
			st.Devices = []store.Device{dev("192.168.88.71/32", store.ModeSmart, false)}
			st.Routing.Rules = []store.Rule{
				{Domains: []string{"domain:p.test"}, Action: store.ActionProxy},
				{Domains: []string{"domain:s.test"}, Action: store.ActionServer, Server: idA},
			}
		}),
		want: []string{
			tun(`"source":["192.168.88.71/32"],"domain":["domain:p.test"],` + toDirect),
			tun(`"domain":["domain:p.test"],` + toBlock),
			fromRule(toDirect, "192.168.88.71/32"),
			catchAll(toBlock),
		},
	},
	{
		name: "smart default, pinned to a disabled server",
		in: input(func(st *store.State) {
			st.Servers = []store.Server{testServer(idA, true), testServer(idB, false)}
			st.Routing.Pinned = idA
			st.Devices = []store.Device{
				dev("192.168.88.73/32", store.ModeFull, true),
				dev("192.168.88.72/32", store.ModeSmart, true),
			}
		}),
		want: []string{
			fromRule(toBlock, "192.168.88.73/32"),
			fromRule(toBlock, "192.168.88.72/32", "192.168.88.73/32"),
			catchAll(toDirect),
		},
	},
	{
		name: "full default, no servers",
		in: input(func(st *store.State) {
			st.Servers = []store.Server{}
			st.DefaultPolicy = store.Policy{Mode: store.ModeFull}
			st.Devices = []store.Device{dev("192.168.88.74/32", store.ModeSmart, true)}
			st.Routing.Domestic = extras()
		}),
		want: []string{
			tun(`"source":["192.168.88.74/32"],"domain":["domain:domestic.test"],` + toDirect),
			tun(`"source":["192.168.88.74/32"],"ip":["203.0.113.20/32"],` + toDirect),
			fromRule(toBlock, "192.168.88.74/32"),
			catchAll(toDirect),
		},
	},
}

func TestRulesNoServers(t *testing.T) { checkTraffic(t, noServerCases) }

var geoCases = []ruleCase{
	{
		name: "geo data and domestic extras",
		in:   withGeo(input(func(st *store.State) { st.Routing.Domestic = extras() }), testGeo),
		want: []string{
			tun(`"domain":["geosite:category-ir","domain:domestic.test"],` + toDirect),
			tun(`"ip":["geoip:ir","203.0.113.20/32"],` + toDirect),
			catchAll(toOpen),
		},
	},
	{
		name: "geo data alone",
		in:   withGeo(input(func(*store.State) {}), testGeo),
		want: []string{
			tun(`"domain":["geosite:category-ir"],` + toDirect),
			tun(`"ip":["geoip:ir"],` + toDirect),
			catchAll(toOpen),
		},
	},
	{
		name: "geo matchers in the state, with geo data",
		in: withGeo(input(func(st *store.State) {
			st.Routing.BlockList = []string{"geosite:category-ads-all"}
			st.Routing.Rules = []store.Rule{{Domains: []string{"geosite:google"}, IPs: []string{"geoip:us"}, Action: store.ActionProxy}}
		}), testGeo),
		want: []string{
			tun(`"domain":["geosite:category-ads-all"],` + toBlock),
			tun(`"domain":["geosite:category-ir"],` + toDirect),
			tun(`"ip":["geoip:ir"],` + toDirect),
			tun(`"domain":["geosite:google"],` + toOpen),
			tun(`"ip":["geoip:us"],` + toOpen),
			catchAll(toOpen),
		},
	},
}

func TestRulesGeo(t *testing.T) {
	checkTraffic(t, geoCases)

	// xray loads geosite: and geoip: matchers from geosite.dat and
	// geoip.dat, and refuses the config without them.
	tests := []struct {
		name string
		edit func(st *store.State)
		path string
	}{
		{"block list", func(st *store.State) { st.Routing.BlockList = []string{"geosite:category-ads-all"} }, "routing.block_list[0]"},
		{"domestic domains", func(st *store.State) {
			st.Routing.Domestic.Domains = []string{"domain:domestic.test", "geosite:category-ir"}
		}, "routing.domestic.domains[1]"},
		{"domestic IPs", func(st *store.State) { st.Routing.Domestic.IPs = []string{"geoip:ir"} }, "routing.domestic.ips[0]"},
		{"rule domains", func(st *store.State) {
			st.Routing.Rules = []store.Rule{{Domains: []string{"geosite:google"}, Action: store.ActionProxy}}
		}, "routing.rules[0].domains[0]"},
		{"rule IPs", func(st *store.State) {
			st.Routing.Rules = []store.Rule{
				{Domains: []string{"domain:d.test"}, Action: store.ActionDirect},
				{IPs: []string{"198.51.100.0/24", "geoip:cn"}, Action: store.ActionBlock},
			}
		}, "routing.rules[1].ips[1]"},
		{"rule naming a disabled server", func(st *store.State) {
			st.Servers = append(st.Servers, testServer(idB, true))
			st.Routing.Rules = []store.Rule{{Domains: []string{"geosite:google"}, Action: store.ActionServer, Server: idB}}
		}, "routing.rules[0].domains[0]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := Render(input(tt.edit))
			if err == nil {
				t.Fatalf("Render without geo data succeeded:\n%s", b)
			}
			if !strings.HasPrefix(err.Error(), "render: ") || !strings.Contains(err.Error(), tt.path) {
				t.Fatalf("Render = %q, want a render: error naming %s", err, tt.path)
			}
		})
	}
}

// allCases are the inputs of every table above and of TestDNS.
func allCases() []ruleCase {
	cases := slices.Concat(defaultSmartCases, killSwitchCases, fullDefaultCases, fullDeviceCases,
		customCases, directDefaultCases, noServerCases, geoCases)
	for _, dc := range dnsCases {
		cases = append(cases, ruleCase{name: "dns: " + dc.name, in: dc.in})
	}
	cases = append(cases, ruleCase{name: "defaults", in: Input{State: store.Default(), Core: testCore}})
	return cases
}

// The generator's seed and the number of states it makes. The seed is fixed,
// so that every run walks the same states.
const (
	genSeed  = 20261025
	genCount = 500
)

// genPolicies are the policies a generated device or default takes: the
// five policy sets.
var genPolicies = []store.Policy{
	{Mode: store.ModeDirect},
	{Mode: store.ModeSmart},
	{Mode: store.ModeSmart, KillSwitch: true},
	{Mode: store.ModeFull},
	{Mode: store.ModeFull, KillSwitch: true},
}

// genActions are the actions a generated custom rule takes.
var genActions = []store.Action{store.ActionDirect, store.ActionProxy, store.ActionBlock, store.ActionServer}

// genServerIDs are the IDs of the generated servers, in order.
var genServerIDs = []string{"a1b2c3d4", "0badf00d", "deadbeef"}

// generated returns genCount valid inputs drawn from genSeed, each with:
//   - up to 8 devices, each in one of the five policy sets, in random order,
//     with prefixes from /28 to /32 that never overlap, all inside
//     192.168.88.0/25;
//   - any default policy;
//   - 0 to 3 servers, each disabled one time in three, and one time in three
//     a pinned one, which may be disabled;
//   - up to 2 block-list entries, 2 domestic domains and 2 domestic IPs, and
//     up to 4 custom rules of any action;
//   - either domestic resolver and either kind of remote one.
//
// Every domain matcher is domain:g<N>.test and every IP matcher
// 10.200.<N>.0/24. None has geo data.
func generated(t *testing.T) []Input {
	t.Helper()
	rng := rand.New(rand.NewPCG(genSeed, genSeed))
	domain := func() string { return fmt.Sprintf("domain:g%d.test", rng.IntN(256)) }
	ip := func() string { return fmt.Sprintf("10.200.%d.0/24", rng.IntN(256)) }
	some := func(max int, draw func() string) []string {
		var list []string
		for range rng.IntN(max + 1) {
			list = append(list, draw())
		}
		return list
	}
	inputs := make([]Input, genCount)
	for i := range inputs {
		st := store.Default()
		st.DefaultPolicy = genPolicies[rng.IntN(len(genPolicies))]
		for k := range rng.IntN(9) {
			// Device k lies in the k-th /28 of 192.168.88.0/24.
			bits := 28 + rng.IntN(5)
			size := 1 << (32 - bits)
			last := byte(16*k + size*rng.IntN(16/size))
			st.Devices = append(st.Devices, store.Device{
				Address: netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 88, last}), bits),
				Policy:  genPolicies[rng.IntN(len(genPolicies))],
			})
		}
		rng.Shuffle(len(st.Devices), func(a, b int) { st.Devices[a], st.Devices[b] = st.Devices[b], st.Devices[a] })
		for _, id := range genServerIDs[:rng.IntN(len(genServerIDs)+1)] {
			st.Servers = append(st.Servers, testServer(id, rng.IntN(3) == 0))
		}
		if len(st.Servers) > 0 && rng.IntN(3) == 0 {
			st.Routing.Pinned = st.Servers[rng.IntN(len(st.Servers))].ID
		}
		st.Routing.BlockList = some(2, domain)
		st.Routing.Domestic = store.Domestic{Domains: some(2, domain), IPs: some(2, ip)}
		for range rng.IntN(5) {
			r := store.Rule{Domains: some(2, domain), IPs: some(2, ip), Action: genActions[rng.IntN(len(genActions))]}
			if len(r.Domains) == 0 && len(r.IPs) == 0 {
				r.Domains = []string{domain()}
			}
			if r.Action == store.ActionServer {
				if len(st.Servers) == 0 {
					r.Action = store.ActionProxy
				} else {
					r.Server = st.Servers[rng.IntN(len(st.Servers))].ID
				}
			}
			st.Routing.Rules = append(st.Routing.Rules, r)
		}
		if rng.IntN(2) == 0 {
			st.DNS.Domestic = netip.MustParseAddr("203.0.113.54")
		}
		if rng.IntN(2) == 0 {
			st.DNS.Remote = "203.0.113.53"
		}
		if err := st.Validate(); err != nil {
			t.Fatalf("generated state %d is invalid: %v", i, err)
		}
		inputs[i] = Input{State: st, Core: testCore}
	}
	return inputs
}

// TestGeneratorCoverage checks that the generated states reach every case
// the property tests are there for, so that a change to the generator cannot
// quietly stop testing one.
func TestGeneratorCoverage(t *testing.T) {
	seen := map[string]int{}
	for _, in := range generated(t) {
		st := in.State
		seen[fmt.Sprintf("default %+v", st.DefaultPolicy)]++
		open, smart := 0, 0
		for _, d := range st.Devices {
			seen[fmt.Sprintf("device %+v", d.Policy)]++
			if d.Policy.Mode != store.ModeDirect && !d.Policy.KillSwitch {
				open++
			}
			if d.Policy.Mode == store.ModeSmart {
				smart++
			}
		}
		if !ProxyAvailable(st) {
			seen["no balancer member"]++
		}
		disabled := map[string]bool{}
		for _, s := range st.Servers {
			disabled[s.ID] = s.Disabled
		}
		if disabled[st.Routing.Pinned] {
			seen["pinned to a disabled server"]++
		}
		for _, r := range st.Routing.Rules {
			seen["rule "+string(r.Action)]++
			if r.Action == store.ActionServer && disabled[r.Server] {
				seen["rule naming a disabled server"]++
			}
		}
		if st.DefaultPolicy.KillSwitch && open == 0 {
			seen["kill switch default, no open device"]++
		}
		if st.DefaultPolicy.Mode == store.ModeFull && smart == 0 && len(st.Routing.Rules) > 0 {
			seen["full default with custom rules, no smart device"]++
		}
	}
	want := []string{"no balancer member", "pinned to a disabled server", "rule naming a disabled server",
		"kill switch default, no open device", "full default with custom rules, no smart device"}
	for _, p := range genPolicies {
		want = append(want, fmt.Sprintf("default %+v", p), fmt.Sprintf("device %+v", p))
	}
	for _, a := range genActions {
		want = append(want, "rule "+string(a))
	}
	for _, w := range want {
		if seen[w] == 0 {
			t.Errorf("no generated state has %s", w)
		}
		t.Logf("%4d × %s", seen[w], w)
	}
}

// TestNoEmptyMatchers checks, over every case above and every generated
// state, that no rule has a matcher list that is there but empty: the JSON
// leaves an empty list out, and xray reads a rule without it as matching
// everything. It checks the rules both as built, before Render's own check
// could refuse them, and as rendered.
func TestNoEmptyMatchers(t *testing.T) {
	check := func(t *testing.T, in Input) {
		t.Helper()
		c, err := build(in)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		var traffic []rule
		for i, r := range c.Routing.Rules {
			for _, m := range []struct {
				key  string
				list []string
			}{{"inboundTag", r.InboundTag}, {"source", r.Source}, {"domain", r.Domain}, {"ip", r.IP}} {
				if m.list != nil && len(m.list) == 0 {
					t.Errorf("built rule %d has an empty %s: %+v", i, m.key, r)
				}
			}
			if slices.Equal(r.InboundTag, []string{TagTUN}) {
				traffic = append(traffic, r)
			}
		}
		// A traffic rule with no source, domain or IP takes all the traffic
		// that reaches it, so only the last rule may be one: the catch-all,
		// which every config has.
		if len(traffic) == 0 {
			t.Errorf("no traffic rule, not even the catch-all")
		}
		for i, r := range traffic {
			unconditional := len(r.Source) == 0 && len(r.Domain) == 0 && len(r.IP) == 0
			if last := i == len(traffic)-1; unconditional != last || last && r.Network != "tcp,udp" {
				t.Errorf("traffic rule %d of %d is %+v: only the last may match every source, and only on network tcp,udp", i, len(traffic), r)
			}
		}

		b, err := Render(in)
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		var out output
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		for i, raw := range out.Routing.Rules {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw, &obj); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"inboundTag", "source", "domain", "ip"} {
				v, ok := obj[key]
				if !ok {
					continue
				}
				var list []string
				if err := json.Unmarshal(v, &list); err != nil || len(list) == 0 {
					t.Errorf("rendered rule %d has an empty or invalid %s: %s", i, key, raw)
				}
			}
		}
	}
	for _, tc := range allCases() {
		t.Run(tc.name, func(t *testing.T) { check(t, tc.in) })
	}
	for i, in := range generated(t) {
		t.Run(fmt.Sprintf("generated %d", i), func(t *testing.T) { check(t, in) })
	}
}

func TestEncodeRefusesEmptyMatchers(t *testing.T) {
	c, err := build(input(func(*store.State) {}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encode(c); err != nil {
		t.Fatalf("encode of the config as built: %v", err)
	}
	tests := []struct {
		name string
		r    rule
	}{
		{"empty source", rule{InboundTag: []string{TagTUN}, Source: []string{}, BalancerTag: BalancerOpen}},
		{"empty domain", rule{InboundTag: []string{TagTUN}, Domain: []string{}, OutboundTag: TagDirect}},
		{"empty ip", rule{InboundTag: []string{TagTUN}, IP: []string{}, OutboundTag: TagDirect}},
		{"empty inbound", rule{InboundTag: []string{}, Source: []string{"192.168.88.10/32"}, OutboundTag: TagDirect}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			broken := *c
			// The broken rule goes before the catch-all, where it would take
			// every source's traffic.
			rules := slices.Clone(c.Routing.Rules)
			broken.Routing.Rules = slices.Insert(rules, len(rules)-1, tt.r)
			b, err := encode(&broken)
			if err == nil {
				t.Fatalf("encode of a rule with an %s succeeded:\n%s", tt.name, b)
			}
			if b != nil {
				t.Errorf("encode returned a config beside its error")
			}
			if !strings.HasPrefix(err.Error(), "render: internal: ") {
				t.Fatalf("encode = %q, want a render: internal: error", err)
			}
		})
	}
}

// TestRulesIgnoreDeviceOrder checks that the order of the devices in the
// state never shows in the output: the source sets are sorted by address.
func TestRulesIgnoreDeviceOrder(t *testing.T) {
	for i, in := range generated(t) {
		want, err := Render(in)
		if err != nil {
			t.Fatal(err)
		}
		in.State = in.State.Clone()
		slices.Reverse(in.State.Devices)
		got, err := Render(in)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("generated state %d: reversing the devices changed the output", i)
		}
	}
}

// route walks rules in order with a tcp connection from src, arriving on the
// TUN inbound for a destination that only the matcher dst names, as xray's
// router would. With dst "", no domain or IP matcher matches it. It returns
// the index of the first rule that matches and that rule's target, such as
// "outboundTag:block", or -1 and xray's default, its first outbound, block,
// when no rule matches.
func route(rules []json.RawMessage, src netip.Addr, dst string) (int, string, error) {
	for i, raw := range rules {
		ok, target, err := matches(raw, src, dst)
		if err != nil {
			return i, "", fmt.Errorf("rule %d %s: %w", i, raw, err)
		}
		if ok {
			return i, target, nil
		}
	}
	return -1, "outboundTag:" + TagBlock, nil
}

// matches reports whether the rule raw matches route's connection, and gives
// its target. A list that is there but empty is no condition, as in xray. It
// fails on a key it does not know, rather than guess whether it matches.
func matches(raw json.RawMessage, src netip.Addr, dst string) (bool, string, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return false, "", err
	}
	match, target := true, ""
	for key, v := range obj {
		switch key {
		case "outboundTag", "balancerTag":
			var tag string
			if err := json.Unmarshal(v, &tag); err != nil {
				return false, "", err
			}
			target = key + ":" + tag
		case "network":
			var network string
			if err := json.Unmarshal(v, &network); err != nil {
				return false, "", err
			}
			if !slices.Contains(strings.Split(network, ","), "tcp") {
				match = false
			}
		case "inboundTag", "source", "domain", "ip":
			var list []string
			if err := json.Unmarshal(v, &list); err != nil {
				return false, "", err
			}
			if len(list) == 0 {
				continue
			}
			switch key {
			case "inboundTag":
				match = match && slices.Contains(list, TagTUN)
			case "source":
				in, err := anyContains(list, src)
				if err != nil {
					return false, "", err
				}
				match = match && in
			default:
				match = match && dst != "" && slices.Contains(list, dst)
			}
		default:
			return false, "", fmt.Errorf("the walker does not know the key %q", key)
		}
	}
	if target == "" {
		return false, "", fmt.Errorf("no target")
	}
	return match, target, nil
}

// anyContains reports whether a prefix or address in list holds a.
func anyContains(list []string, a netip.Addr) (bool, error) {
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return false, fmt.Errorf("source %q is not a prefix or an address", s)
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		if p.Contains(a) {
			return true, nil
		}
	}
	return false, nil
}

// leaks reports whether target can send traffic out direct: the direct
// outbound, or proxy-open, which falls back to it while no server is up.
func leaks(target string) bool {
	return target == "outboundTag:"+TagDirect || target == "balancerTag:"+BalancerOpen
}

// killSwitchSources are addresses whose proxied traffic the kill switch
// covers in st: the first address of each kill-switch device and, when the
// default policy has the kill switch, addresses no device lists.
func killSwitchSources(t *testing.T, st store.State) []netip.Addr {
	t.Helper()
	var srcs []netip.Addr
	for _, d := range st.Devices {
		if d.Policy.KillSwitch {
			srcs = append(srcs, d.Address.Addr())
		}
	}
	if !st.DefaultPolicy.KillSwitch {
		return srcs
	}
	unlisted := 0
	for _, s := range []string{"192.168.88.200", "192.168.99.1", "10.255.255.254"} {
		a := netip.MustParseAddr(s)
		if !slices.ContainsFunc(st.Devices, func(d store.Device) bool { return d.Address.Contains(a) }) {
			srcs = append(srcs, a)
			unlisted++
		}
	}
	if unlisted == 0 {
		t.Fatal("the devices cover every unlisted address the probe tries")
	}
	return srcs
}

// killSwitchLeak walks rules with a kill-switch source's connection and
// returns why it leaks, or "" when it does not: its first matching rule is
// neither the direct outbound nor proxy-open.
func killSwitchLeak(rules []json.RawMessage, src netip.Addr, dst string) (string, error) {
	i, target, err := route(rules, src, dst)
	if err != nil {
		return "", err
	}
	if !leaks(target) {
		return "", nil
	}
	return fmt.Sprintf("kill-switch source %s, destination %q: rule %d %s sends it to %s", src, dst, i, rules[i], target), nil
}

func TestKillSwitchNeverDirect(t *testing.T) {
	inputs := generated(t)
	for _, tc := range allCases() {
		inputs = append(inputs, tc.in)
	}
	probes := 0
	for i, in := range inputs {
		out, _ := mustRenderInput(t, in)
		for _, src := range killSwitchSources(t, in.State) {
			probes++
			leak, err := killSwitchLeak(out.Routing.Rules, src, "")
			if err != nil {
				t.Fatalf("input %d: %v", i, err)
			}
			if leak != "" {
				st, _ := json.Marshal(in.State)
				t.Errorf("input %d: %s\nstate %s", i, leak, st)
			}
		}
	}
	t.Logf("seed %d: %d generated states and %d table cases, %d kill-switch probes", genSeed, genCount, len(inputs)-genCount, probes)
}

// TestKillSwitchMatchedTraffic walks the generated states as
// TestKillSwitchNeverDirect does, but to each destination the state's
// matchers name. A kill-switch source never reaches proxy-open, and goes
// direct only by a domestic rule or a custom direct rule for that
// destination.
func TestKillSwitchMatchedTraffic(t *testing.T) {
	probes := 0
	for i, in := range generated(t) {
		out, _ := mustRenderInput(t, in)
		r := in.State.Routing
		directOK := map[string]bool{}
		for _, m := range slices.Concat(r.Domestic.Domains, r.Domestic.IPs) {
			directOK[m] = true
		}
		var named []string
		named = append(named, r.BlockList...)
		named = append(named, r.Domestic.Domains...)
		named = append(named, r.Domestic.IPs...)
		for _, cr := range r.Rules {
			named = append(named, cr.Domains...)
			named = append(named, cr.IPs...)
			if cr.Action == store.ActionDirect {
				for _, m := range slices.Concat(cr.Domains, cr.IPs) {
					directOK[m] = true
				}
			}
		}
		slices.Sort(named)
		for _, dst := range slices.Compact(named) {
			for _, src := range killSwitchSources(t, in.State) {
				probes++
				idx, target, err := route(out.Routing.Rules, src, dst)
				if err != nil {
					t.Fatalf("generated state %d: %v", i, err)
				}
				if target == "balancerTag:"+BalancerOpen || target == "outboundTag:"+TagDirect && !directOK[dst] {
					st, _ := json.Marshal(in.State)
					t.Errorf("generated state %d: kill-switch source %s, destination %s: rule %d %s sends it to %s\nstate %s",
						i, src, dst, idx, out.Routing.Rules[idx], target, st)
				}
			}
		}
	}
	t.Logf("seed %d: %d generated states, %d kill-switch probes to named destinations", genSeed, genCount, probes)
}

// TestKillSwitchWalkerCatchesLeaks checks the walker of the property tests
// against configs broken on purpose.
func TestKillSwitchWalkerCatchesLeaks(t *testing.T) {
	// A kill-switch default with one open device: an unlisted source must
	// reach the catch-all proxy-closed rule.
	out, _ := mustRenderInput(t, killSwitchCases[0].in)
	rules := out.Routing.Rules
	n := len(rules)
	jsonEqual(t, "the last rule", rules[n-1], catchAll(toClosed))
	jsonEqual(t, "the rule before it", rules[n-2], fromRule(toOpen, "192.168.88.10/32"))
	unlisted := netip.MustParseAddr("192.168.99.1")
	tests := []struct {
		name     string
		edit     func(rules []json.RawMessage)
		wantLeak bool
	}{
		{"as rendered", func([]json.RawMessage) {}, false},
		{"final rule sends the rest direct", func(rs []json.RawMessage) { rs[n-1] = json.RawMessage(catchAll(toDirect)) }, true},
		{"final rule sends the rest to proxy-open", func(rs []json.RawMessage) { rs[n-1] = json.RawMessage(catchAll(toOpen)) }, true},
		// No rule matches, and xray's default, its first outbound, blocks.
		{"final rule for udp alone", func(rs []json.RawMessage) {
			rs[n-1] = json.RawMessage(tun(`"network":"udp",` + toDirect))
		}, false},
		{"the open rule lost its source", func(rs []json.RawMessage) { rs[n-2] = json.RawMessage(tun(toOpen)) }, true},
		{"the open rule has an empty source", func(rs []json.RawMessage) { rs[n-2] = json.RawMessage(tun(`"source":[],` + toOpen)) }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := slices.Clone(rules)
			tt.edit(rs)
			leak, err := killSwitchLeak(rs, unlisted, "")
			if err != nil {
				t.Fatal(err)
			}
			if got := leak != ""; got != tt.wantLeak {
				t.Fatalf("leak = %q, want a leak: %v", leak, tt.wantLeak)
			}
		})
	}
}
