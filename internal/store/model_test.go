package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// wantDefaultJSON is what Default marshals to, compact.
const wantDefaultJSON = `{"servers":[],"subscriptions":[],"devices":[],"default_policy":{"mode":"direct"},"routing":{"domestic":{}},"dns":{"remote":"https://1.1.1.1/dns-query"},"network":{"subnet":"172.31.255.0/29"},"health":{"probe_url":"https://www.gstatic.com/generate_204"}}`

func TestDefaultIsValid(t *testing.T) {
	s := Default()
	if err := s.Validate(); err != nil {
		t.Fatalf("Default().Validate() = %v", err)
	}
	compact, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if string(compact) != wantDefaultJSON {
		t.Errorf("Default() marshals to\n%s\nwant\n%s", compact, wantDefaultJSON)
	}

	var want bytes.Buffer
	if err := json.Indent(&want, []byte(wantDefaultJSON), "", "  "); err != nil {
		t.Fatal(err)
	}
	indented, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(indented) != want.String() {
		t.Errorf("Default() indented is\n%s\nwant\n%s", indented, want.String())
	}
}

func TestNetworkAddresses(t *testing.T) {
	for _, c := range []struct{ subnet, router, tikray, runner string }{
		{"172.31.255.0/29", "172.31.255.1", "172.31.255.2", "172.31.255.3"},
		{"10.9.8.0/28", "10.9.8.1", "10.9.8.2", "10.9.8.3"},
	} {
		n := Network{Subnet: netip.MustParsePrefix(c.subnet)}
		for _, g := range []struct {
			what      string
			got, want netip.Addr
		}{
			{"Router", n.Router(), netip.MustParseAddr(c.router)},
			{"Tikray", n.Tikray(), netip.MustParseAddr(c.tikray)},
			{"Runner", n.Runner(), netip.MustParseAddr(c.runner)},
		} {
			if g.got != g.want {
				t.Errorf("%s: %s() = %v, want %v", c.subnet, g.what, g.got, g.want)
			}
		}
	}
}

func TestDomesticResolver(t *testing.T) {
	for _, c := range []struct{ subnet, domestic, want string }{
		{"172.31.255.0/29", "", "172.31.255.1"},
		{"10.9.8.0/28", "", "10.9.8.1"},
		{"172.31.255.0/29", "192.168.88.1", "192.168.88.1"},
	} {
		s := Default()
		s.Network.Subnet = netip.MustParsePrefix(c.subnet)
		if c.domestic != "" {
			s.DNS.Domestic = netip.MustParseAddr(c.domestic)
		}
		if got := s.DomesticResolver(); got != netip.MustParseAddr(c.want) {
			t.Errorf("subnet %s, dns.domestic %q: DomesticResolver() = %v, want %s", c.subnet, c.domestic, got, c.want)
		}
	}
}

// fixture is a Default-based state with something in every list, so a clone
// that shares memory with it shows up.
func fixture() State {
	s := Default()
	s.Servers = []Server{{ID: "a1b2c3d4", Name: "one", Outbound: json.RawMessage(`{"protocol":"vless"}`)}}
	s.Subscriptions = []Subscription{{
		ID: "00ff00ff", Name: "sub", URL: "https://example.com/s", Interval: Duration(24 * time.Hour),
		LastFetch: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC),
	}}
	s.Devices = []Device{{
		Address: netip.MustParsePrefix("192.168.1.10/32"), Name: "phone",
		Policy: Policy{Mode: ModeFull, KillSwitch: true},
	}}
	s.Routing.Pinned = "a1b2c3d4"
	s.Routing.BlockList = []string{"domain:ads.example"}
	s.Routing.Domestic = Domestic{Domains: []string{"domain:ir"}, IPs: []string{"geoip:ir", "10.0.0.0/8"}}
	s.Routing.Rules = []Rule{{
		Domains: []string{"full:a.b", "keyword:x"}, IPs: []string{"1.2.3.4"}, Action: ActionProxy,
	}}
	return s
}

func TestCloneIsDeep(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(*State)
	}{
		{"server outbound bytes", func(s *State) { s.Servers[0].Outbound[0] = 'X' }},
		{"server", func(s *State) { s.Servers[0].Name = "changed" }},
		{"subscription", func(s *State) { s.Subscriptions[0].Name = "changed" }},
		{"device", func(s *State) { s.Devices[0].Name = "changed" }},
		{"device slice", func(s *State) { s.Devices = append(s.Devices[:0], Device{}) }},
		{"block list", func(s *State) { s.Routing.BlockList[0] = "changed" }},
		{"domestic domains", func(s *State) { s.Routing.Domestic.Domains[0] = "changed" }},
		{"domestic ips", func(s *State) { s.Routing.Domestic.IPs[0] = "changed" }},
		{"rule domains", func(s *State) { s.Routing.Rules[0].Domains[0] = "changed" }},
		{"rule ips", func(s *State) { s.Routing.Rules[0].IPs[0] = "changed" }},
		{"rule", func(s *State) { s.Routing.Rules[0].Action = ActionBlock }},
	} {
		t.Run(c.name, func(t *testing.T) {
			orig := fixture()
			clone := orig.Clone()
			c.mutate(&clone)
			if reflect.DeepEqual(clone, orig) {
				t.Fatal("the mutation changed nothing in the clone: the test is broken")
			}
			if !reflect.DeepEqual(orig, fixture()) {
				t.Errorf("changing the clone changed the original:\n%+v", orig)
			}
		})
	}
}

func TestCloneKeepsShape(t *testing.T) {
	for name, s := range map[string]State{"zero": {}, "default": Default(), "fixture": fixture()} {
		if got := s.Clone(); !reflect.DeepEqual(got, s) {
			t.Errorf("%s: Clone() = %+v, want %+v", name, got, s)
		}
	}
	got, err := json.Marshal(Default().Clone())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != wantDefaultJSON {
		t.Errorf("Default().Clone() marshals to\n%s\nwant\n%s", got, wantDefaultJSON)
	}
}

func TestServerTag(t *testing.T) {
	if got := (Server{ID: "a1b2c3d4"}).Tag(); got != "srv-a1b2c3d4" {
		t.Errorf("Tag() = %q, want srv-a1b2c3d4", got)
	}
}

func TestNewID(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}$`)
	seen := map[string]bool{}
	for range 50 {
		id := NewID()
		if !re.MatchString(id) {
			t.Fatalf("NewID() = %q, want 8 lowercase hex digits", id)
		}
		seen[id] = true
	}
	if len(seen) < 2 {
		t.Errorf("50 calls to NewID() gave %d distinct values", len(seen))
	}
}

func TestDurationText(t *testing.T) {
	b, err := json.Marshal(Duration(24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"24h0m0s"` {
		t.Errorf("Marshal = %s, want \"24h0m0s\"", b)
	}
	for in, want := range map[string]time.Duration{`"24h0m0s"`: 24 * time.Hour, `"90m"`: 90 * time.Minute, `"1h30m"`: 90 * time.Minute} {
		var d Duration
		if err := json.Unmarshal([]byte(in), &d); err != nil {
			t.Errorf("Unmarshal(%s): %v", in, err)
		} else if time.Duration(d) != want {
			t.Errorf("Unmarshal(%s) = %v, want %v", in, time.Duration(d), want)
		}
	}
	for _, in := range []string{`"soon"`, `""`, `3600`} {
		var d Duration
		if json.Unmarshal([]byte(in), &d) == nil {
			t.Errorf("Unmarshal(%s) accepted", in)
		}
	}
}

func TestJSONKeys(t *testing.T) {
	when := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		v    any
		want string
	}{
		{"server minimal", Server{ID: "a1b2c3d4", Name: "n", Outbound: json.RawMessage(`{"protocol":"vless"}`)},
			`{"id":"a1b2c3d4","name":"n","outbound":{"protocol":"vless"}}`},
		{"server full", Server{ID: "a1b2c3d4", Name: "n", Disabled: true, Link: "vless://x", Subscription: "00ff00ff", Outbound: json.RawMessage(`{"protocol":"vless"}`)},
			`{"id":"a1b2c3d4","name":"n","disabled":true,"link":"vless://x","subscription":"00ff00ff","outbound":{"protocol":"vless"}}`},
		{"subscription minimal", Subscription{ID: "00ff00ff", Name: "n", URL: "https://x/s", Interval: Duration(24 * time.Hour)},
			`{"id":"00ff00ff","name":"n","url":"https://x/s","interval":"24h0m0s"}`},
		{"subscription full", Subscription{ID: "00ff00ff", Name: "n", URL: "https://x/s", Disabled: true, Interval: Duration(2 * time.Hour), LastFetch: when, LastError: "boom"},
			`{"id":"00ff00ff","name":"n","url":"https://x/s","disabled":true,"interval":"2h0m0s","last_fetch":"2026-10-25T12:00:00Z","last_error":"boom"}`},
		{"device minimal", Device{Address: netip.MustParsePrefix("192.168.1.5/32"), Policy: Policy{Mode: ModeSmart}},
			`{"address":"192.168.1.5/32","policy":{"mode":"smart"}}`},
		{"device full", Device{Address: netip.MustParsePrefix("192.168.1.5/32"), Name: "tv", MAC: "aa:bb:cc:dd:ee:ff", Policy: Policy{Mode: ModeFull, KillSwitch: true}},
			`{"address":"192.168.1.5/32","name":"tv","mac":"aa:bb:cc:dd:ee:ff","policy":{"mode":"full","kill_switch":true}}`},
		{"rule", Rule{Domains: []string{"full:a.b"}, IPs: []string{"1.2.3.4"}, Action: ActionServer, Server: "a1b2c3d4"},
			`{"domains":["full:a.b"],"ips":["1.2.3.4"],"action":"server","server":"a1b2c3d4"}`},
		{"routing", Routing{Pinned: "a1b2c3d4", BlockList: []string{"x"}, Domestic: Domestic{Domains: []string{"d"}, IPs: []string{"geoip:ir"}}, Rules: []Rule{{Domains: []string{"y"}, Action: ActionBlock}}},
			`{"pinned":"a1b2c3d4","block_list":["x"],"domestic":{"domains":["d"],"ips":["geoip:ir"]},"rules":[{"domains":["y"],"action":"block"}]}`},
		{"dns without domestic", DNS{Remote: "203.0.113.53"}, `{"remote":"203.0.113.53"}`},
		{"dns with domestic", DNS{Domestic: netip.MustParseAddr("10.0.0.53"), Remote: "203.0.113.53"}, `{"domestic":"10.0.0.53","remote":"203.0.113.53"}`},
	} {
		got, err := json.Marshal(c.v)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if string(got) != c.want {
			t.Errorf("%s: marshals to\n%s\nwant\n%s", c.name, got, c.want)
		}
	}
}

func TestJSONRoundTrip(t *testing.T) {
	want := fixture()
	want.DNS.Domestic = netip.MustParseAddr("10.0.0.53")
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got State
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the state:\n got %+v\nwant %+v", got, want)
	}
}

// valid returns a state Validate accepts, with the pieces the reject cases
// each change one thing of: a server, a subscription it came from, and a
// device covering a /24.
func valid() State {
	s := Default()
	s.Servers = []Server{{
		ID: "a1b2c3d4", Name: "Frankfurt", Subscription: "00ff00ff",
		Outbound: json.RawMessage(`{"protocol":"vless","settings":{"vnext":[]}}`),
	}}
	s.Subscriptions = []Subscription{{
		ID: "00ff00ff", Name: "Main", URL: "https://sub.example.com/s/token", Interval: Duration(24 * time.Hour),
	}}
	s.Devices = []Device{{
		Address: netip.MustParsePrefix("192.168.1.0/24"), Name: "LAN", Policy: Policy{Mode: ModeSmart},
	}}
	return s
}

func withRule(r Rule) func(*State) {
	return func(s *State) { s.Routing.Rules = []Rule{r} }
}

func withOutbound(raw string) func(*State) {
	return func(s *State) { s.Servers[0].Outbound = json.RawMessage(raw) }
}

// Outbounds that xray-core 26.7.11 and newer refuse, or accept, as raw JSON
// would give them. The id and the passwords are secrets that no error repeats.
const (
	vlessPlainTo = `{"protocol":"vless","settings":{"vnext":[{"address":"%s","port":443,"users":[{"id":"s3cret-id","encryption":"none"}]}]}}`
	vlessTLSTo   = `{"protocol":"vless","settings":{"vnext":[{"address":"%s","port":443,"users":[{"id":"s3cret-id","encryption":"none"}]}]},"streamSettings":{"security":"tls"}}`
	trojanPlain  = `{"protocol":"trojan","settings":{"servers":[{"address":"%s","port":443,"password":"s3cret-pw"}]}}`
	trojanTLS    = `{"protocol":"trojan","settings":{"servers":[{"address":"%s","port":443,"password":"s3cret-pw"}]},"streamSettings":{"security":"tls"}}`
	// vlessInsecure is VLESS over TLS with allowInsecure set to %t.
	vlessInsecure = `{"protocol":"vless","settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"s3cret-id","encryption":"none"}]}]},"streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":%t}}}`
	ssMethod      = `{"protocol":"shadowsocks","settings":{"servers":[{"address":"1.2.3.4","port":8388,"method":"%s","password":"%s"}]}}`
	// key16 is the base64 of 16 bytes.
	key16 = "AAECAwQFBgcICQoLDA0ODw=="
)

func TestValidBaseIsValid(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid().Validate() = %v", err)
	}
}

// joined splits a Validate error into its joined parts.
func joined(err error) []error {
	if err == nil {
		return nil
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		return j.Unwrap()
	}
	return []error{err}
}

func TestValidateRejects(t *testing.T) {
	type tc struct {
		name   string
		mutate func(*State)
		path   string // every error is prefixed with a path; the case's one error starts with this
	}
	cases := []tc{
		{"server id uppercase", func(s *State) { s.Servers[0].ID = "A1B2C3D4" }, "servers[0].id"},
		{"server id short", func(s *State) { s.Servers[0].ID = "a1b2c3" }, "servers[0].id"},
		{"server id not hex", func(s *State) { s.Servers[0].ID = "a1b2c3dz" }, "servers[0].id"},
		{"server id empty", func(s *State) { s.Servers[0].ID = "" }, "servers[0].id"},
		{"server id duplicate", func(s *State) { s.Servers = append(s.Servers, s.Servers[0]) }, "servers[1].id"},
		{"server name empty", func(s *State) { s.Servers[0].Name = "" }, "servers[0].name"},
		{"server name blank", func(s *State) { s.Servers[0].Name = "  " }, "servers[0].name"},
		{"server name too long", func(s *State) { s.Servers[0].Name = strings.Repeat("a", 129) }, "servers[0].name"},
		{"server name too long in runes", func(s *State) { s.Servers[0].Name = strings.Repeat("é", 129) }, "servers[0].name"},
		{"outbound missing", func(s *State) { s.Servers[0].Outbound = nil }, "servers[0].outbound"},
		{"outbound null", withOutbound(`null`), "servers[0].outbound"},
		{"outbound array", withOutbound(`[{"protocol":"vless"}]`), "servers[0].outbound"},
		{"outbound string", withOutbound(`"vless"`), "servers[0].outbound"},
		{"outbound not json", withOutbound(`{"protocol":`), "servers[0].outbound"},
		{"outbound without protocol", withOutbound(`{"settings":{}}`), "servers[0].outbound.protocol"},
		{"outbound protocol null", withOutbound(`{"protocol":null}`), "servers[0].outbound.protocol"},
		{"outbound protocol empty", withOutbound(`{"protocol":""}`), "servers[0].outbound.protocol"},
		{"outbound protocol number", withOutbound(`{"protocol":7}`), "servers[0].outbound.protocol"},
		{"outbound freedom", withOutbound(`{"protocol":"freedom"}`), "servers[0].outbound.protocol"},
		{"outbound blackhole", withOutbound(`{"protocol":"blackhole"}`), "servers[0].outbound.protocol"},
		{"outbound dns", withOutbound(`{"protocol":"dns"}`), "servers[0].outbound.protocol"},
		{"outbound loopback", withOutbound(`{"protocol":"loopback"}`), "servers[0].outbound.protocol"},
		{"outbound freedom in capitals", withOutbound(`{"protocol":"Freedom"}`), "servers[0].outbound.protocol"},
		{"outbound freedom under a second protocol key", withOutbound(`{"protocol":"vless","Protocol":"freedom"}`), "servers[0].outbound.protocol"},
		// xray's outboundConfigLoader also knows freedom as direct and
		// blackhole as block, and it lower-cases the protocol with
		// strings.ToLower, which makes U+0130 an i and the Kelvin sign
		// U+212A a k.
		{"outbound direct", withOutbound(`{"protocol":"direct"}`), "servers[0].outbound.protocol"},
		{"outbound Direct", withOutbound(`{"protocol":"Direct"}`), "servers[0].outbound.protocol"},
		{"outbound block", withOutbound(`{"protocol":"block"}`), "servers[0].outbound.protocol"},
		{"outbound BLOCK", withOutbound(`{"protocol":"BLOCK"}`), "servers[0].outbound.protocol"},
		{"outbound direct with a dotted capital I", withOutbound(`{"protocol":"dİrect"}`), "servers[0].outbound.protocol"},
		{"outbound block with a Kelvin sign", withOutbound(`{"protocol":"blocK"}`), "servers[0].outbound.protocol"},
		{"outbound loopback with a Kelvin sign", withOutbound(`{"protocol":"loopbacK"}`), "servers[0].outbound.protocol"},
		{"outbound direct under a second protocol key", withOutbound(`{"protocol":"vless","PROTOCOL":"direct"}`), "servers[0].outbound.protocol"},
		{"outbound tag", withOutbound(`{"protocol":"vless","tag":"mine"}`), "servers[0].outbound.tag"},
		{"outbound tag in capitals", withOutbound(`{"protocol":"vless","Tag":"mine"}`), "servers[0].outbound.tag"},
		{"outbound empty tag", withOutbound(`{"protocol":"vless","tag":""}`), "servers[0].outbound.tag"},
		{"outbound vless without tls or encryption to a public IP", withOutbound(fmt.Sprintf(vlessPlainTo, "1.2.3.4")), "servers[0].outbound"},
		{"outbound vless without tls or encryption to a public domain", withOutbound(fmt.Sprintf(vlessPlainTo, "example.com")), "servers[0].outbound"},
		{"outbound trojan without tls to a public IP", withOutbound(fmt.Sprintf(trojanPlain, "1.2.3.4")), "servers[0].outbound"},
		{"outbound shadowsocks method none", withOutbound(fmt.Sprintf(ssMethod, "none", "s3cret-pw")), "servers[0].outbound"},
		{"outbound shadowsocks 2022 with a short key", withOutbound(fmt.Sprintf(ssMethod, "2022-blake3-aes-256-gcm", key16)), "servers[0].outbound"},
		{"outbound tls with allowInsecure", withOutbound(fmt.Sprintf(vlessInsecure, true)), "servers[0].outbound"},
		{"server subscription missing", func(s *State) { s.Servers[0].Subscription = "deadbeef" }, "servers[0].subscription"},

		{"subscription id uppercase", func(s *State) {
			s.Subscriptions[0].ID = "00FF00FF"
			s.Servers[0].Subscription = ""
		}, "subscriptions[0].id"},
		{"subscription id duplicate", func(s *State) { s.Subscriptions = append(s.Subscriptions, s.Subscriptions[0]) }, "subscriptions[1].id"},
		{"subscription name empty", func(s *State) { s.Subscriptions[0].Name = "" }, "subscriptions[0].name"},
		{"subscription name too long", func(s *State) { s.Subscriptions[0].Name = strings.Repeat("a", 129) }, "subscriptions[0].name"},
		{"subscription url ftp", func(s *State) { s.Subscriptions[0].URL = "ftp://x" }, "subscriptions[0].url"},
		{"subscription url relative", func(s *State) { s.Subscriptions[0].URL = "/sub/token" }, "subscriptions[0].url"},
		{"subscription url without scheme", func(s *State) { s.Subscriptions[0].URL = "sub.example.com/token" }, "subscriptions[0].url"},
		{"subscription url empty", func(s *State) { s.Subscriptions[0].URL = "" }, "subscriptions[0].url"},
		{"subscription url without host", func(s *State) { s.Subscriptions[0].URL = "https:///token" }, "subscriptions[0].url"},
		{"subscription interval 59m", func(s *State) { s.Subscriptions[0].Interval = Duration(59 * time.Minute) }, "subscriptions[0].interval"},
		{"subscription interval zero", func(s *State) { s.Subscriptions[0].Interval = 0 }, "subscriptions[0].interval"},
		{"subscription interval negative", func(s *State) { s.Subscriptions[0].Interval = Duration(-2 * time.Hour) }, "subscriptions[0].interval"},

		{"device address ipv6", func(s *State) { s.Devices[0].Address = netip.MustParsePrefix("fe80::1/128") }, "devices[0].address"},
		{"device address mapped ipv6", func(s *State) { s.Devices[0].Address = netip.MustParsePrefix("::ffff:192.168.1.5/128") }, "devices[0].address"},
		{"device address not masked", func(s *State) { s.Devices[0].Address = netip.MustParsePrefix("192.168.1.5/24") }, "devices[0].address"},
		{"device address missing", func(s *State) { s.Devices[0].Address = netip.Prefix{} }, "devices[0].address"},
		{"devices overlap", func(s *State) {
			s.Devices = append(s.Devices, Device{Address: netip.MustParsePrefix("192.168.1.7/32"), Policy: Policy{Mode: ModeDirect}})
		}, "devices[1].address"},
		{"devices repeat an address", func(s *State) { s.Devices = append(s.Devices, s.Devices[0]) }, "devices[1].address"},
		{"device mode vpn", func(s *State) { s.Devices[0].Policy.Mode = "vpn" }, "devices[0].policy.mode"},
		{"device mode empty", func(s *State) { s.Devices[0].Policy.Mode = "" }, "devices[0].policy.mode"},
		{"device direct with kill switch", func(s *State) { s.Devices[0].Policy = Policy{Mode: ModeDirect, KillSwitch: true} }, "devices[0].policy.kill_switch"},
		{"default mode vpn", func(s *State) { s.DefaultPolicy.Mode = "vpn" }, "default_policy.mode"},
		{"default direct with kill switch", func(s *State) { s.DefaultPolicy = Policy{Mode: ModeDirect, KillSwitch: true} }, "default_policy.kill_switch"},

		{"pinned missing server", func(s *State) { s.Routing.Pinned = "deadbeef" }, "routing.pinned"},
		{"block list empty entry", func(s *State) { s.Routing.BlockList = []string{""} }, "routing.block_list[0]"},
		{"block list whitespace", func(s *State) { s.Routing.BlockList = []string{"ads.example", "a b"} }, "routing.block_list[1]"},
		{"block list tab", func(s *State) { s.Routing.BlockList = []string{"a\tb"} }, "routing.block_list[0]"},
		{"block list regexp does not compile", func(s *State) { s.Routing.BlockList = []string{"regexp:("} }, "routing.block_list[0]"},
		{"block list unknown prefix", func(s *State) { s.Routing.BlockList = []string{"domian:example.com"} }, "routing.block_list[0]"},
		{"block list prefix without value", func(s *State) { s.Routing.BlockList = []string{"domain:"} }, "routing.block_list[0]"},
		{"domestic domain with whitespace", func(s *State) { s.Routing.Domestic.Domains = []string{"a b"} }, "routing.domestic.domains[0]"},
		{"domestic domain regexp does not compile", func(s *State) { s.Routing.Domestic.Domains = []string{"regexp:["} }, "routing.domestic.domains[0]"},
		{"domestic ip out of range", func(s *State) { s.Routing.Domestic.IPs = []string{"300.1.1.1"} }, "routing.domestic.ips[0]"},
		{"domestic ip empty", func(s *State) { s.Routing.Domestic.IPs = []string{"10.0.0.0/8", ""} }, "routing.domestic.ips[1]"},
		{"domestic ip with zone", func(s *State) { s.Routing.Domestic.IPs = []string{"fe80::1%eth0"} }, "routing.domestic.ips[0]"},
		{"domestic geoip without code", func(s *State) { s.Routing.Domestic.IPs = []string{"geoip:"} }, "routing.domestic.ips[0]"},
		{"domestic ip bad prefix length", func(s *State) { s.Routing.Domestic.IPs = []string{"10.0.0.0/33"} }, "routing.domestic.ips[0]"},

		{"rule without domains or ips", withRule(Rule{Action: ActionProxy}), "routing.rules[0]"},
		{"rule domain bad", withRule(Rule{Domains: []string{"ok.example", "a b"}, Action: ActionProxy}), "routing.rules[0].domains[1]"},
		{"rule ip bad", withRule(Rule{IPs: []string{"nope"}, Action: ActionProxy}), "routing.rules[0].ips[0]"},
		{"rule action tunnel", withRule(Rule{Domains: []string{"x.example"}, Action: "tunnel"}), "routing.rules[0].action"},
		{"rule action empty", withRule(Rule{Domains: []string{"x.example"}}), "routing.rules[0].action"},
		{"rule server without action server", withRule(Rule{Domains: []string{"x.example"}, Action: ActionProxy, Server: "a1b2c3d4"}), "routing.rules[0].server"},
		{"rule action server naming a missing server", withRule(Rule{Domains: []string{"x.example"}, Action: ActionServer, Server: "deadbeef"}), "routing.rules[0].server"},
		{"rule action server without a server", withRule(Rule{Domains: []string{"x.example"}, Action: ActionServer}), "routing.rules[0].server"},
		{"second rule bad", func(s *State) {
			s.Routing.Rules = []Rule{{Domains: []string{"x.example"}, Action: ActionDirect}, {Action: ActionBlock}}
		}, "routing.rules[1]"},

		{"dns domestic ipv6", func(s *State) { s.DNS.Domestic = netip.MustParseAddr("::1") }, "dns.domestic"},
		{"dns remote http", func(s *State) { s.DNS.Remote = "http://x/dns-query" }, "dns.remote"},
		{"dns remote hostname", func(s *State) { s.DNS.Remote = "example.com" }, "dns.remote"},
		{"dns remote empty", func(s *State) { s.DNS.Remote = "" }, "dns.remote"},
		{"dns remote ipv6", func(s *State) { s.DNS.Remote = "2001:db8::53" }, "dns.remote"},
		{"dns remote https without host", func(s *State) { s.DNS.Remote = "https:///dns-query" }, "dns.remote"},
		// The domestic resolver's queries go out direct, and so would every
		// query to a remote resolver at the same address.
		{"dns remote is the domestic resolver", func(s *State) {
			s.DNS.Domestic = netip.MustParseAddr("203.0.113.53")
			s.DNS.Remote = "203.0.113.53"
		}, "dns.remote"},
		{"dns remote is the router, which is the domestic resolver", func(s *State) { s.DNS.Remote = "172.31.255.1" }, "dns.remote"},
		{"dns remote is the router of another subnet", func(s *State) {
			s.Network.Subnet = netip.MustParsePrefix("10.9.8.0/29")
			s.DNS.Remote = "10.9.8.1"
		}, "dns.remote"},
		// The domestic resolver's port 53 goes out direct, DoH to it as well.
		{"dns remote is DoH on port 53 of the domestic resolver", func(s *State) {
			s.DNS.Domestic = netip.MustParseAddr("203.0.113.53")
			s.DNS.Remote = "https://203.0.113.53:53/dns-query"
		}, "dns.remote"},
		{"dns remote is DoH on port 53 of the router", func(s *State) { s.DNS.Remote = "https://172.31.255.1:53/dns-query" }, "dns.remote"},
		{"dns remote is DoH on port 053 of the router", func(s *State) { s.DNS.Remote = "https://172.31.255.1:053/dns-query" }, "dns.remote"},
		{"dns remote is DoH on port 53 of the router, mapped into IPv6", func(s *State) { s.DNS.Remote = "https://[::ffff:172.31.255.1]:53/dns-query" }, "dns.remote"},

		{"subnet /30", func(s *State) { s.Network.Subnet = netip.MustParsePrefix("172.31.255.0/30") }, "network.subnet"},
		{"subnet ipv6", func(s *State) { s.Network.Subnet = netip.MustParsePrefix("fd00::/64") }, "network.subnet"},
		{"subnet not masked", func(s *State) { s.Network.Subnet = netip.MustParsePrefix("172.31.255.5/29") }, "network.subnet"},
		{"subnet missing", func(s *State) { s.Network.Subnet = netip.Prefix{} }, "network.subnet"},

		{"probe url not a url", func(s *State) { s.Health.ProbeURL = "not a url" }, "health.probe_url"},
		{"probe url empty", func(s *State) { s.Health.ProbeURL = "" }, "health.probe_url"},
		{"probe url ftp", func(s *State) { s.Health.ProbeURL = "ftp://x/204" }, "health.probe_url"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := valid()
			c.mutate(&s)
			err := s.Validate()
			if err == nil {
				t.Fatal("accepted")
			}
			ps := joined(err)
			if len(ps) != 1 {
				t.Fatalf("want one problem, got %d:\n%v", len(ps), err)
			}
			if !strings.HasPrefix(ps[0].Error(), c.path+": ") {
				t.Errorf("problem %q does not start with %q", ps[0], c.path+": ")
			}
		})
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	s := valid()
	s.Devices[0].Address = netip.MustParsePrefix("192.168.1.5/24")
	s.DNS.Remote = "example.com"
	s.Health.ProbeURL = "not a url"
	s.Routing.Rules = []Rule{{Action: "tunnel"}}
	err := s.Validate()
	if err == nil {
		t.Fatal("accepted")
	}
	// The rule is both empty and has a bad action.
	if got := len(joined(err)); got != 5 {
		t.Errorf("want 5 problems, got %d:\n%v", got, err)
	}
	for _, path := range []string{"devices[0].address: ", "dns.remote: ", "health.probe_url: ", "routing.rules[0]: ", "routing.rules[0].action: "} {
		if !strings.Contains(err.Error(), path) {
			t.Errorf("no problem for %s in:\n%v", path, err)
		}
	}
}

func TestValidateKeepsSecretsOutOfErrors(t *testing.T) {
	s := valid()
	s.Subscriptions[0].URL = "ftp://user:s3cret@sub.example.com/token-s3cret"
	s.Health.ProbeURL = "ftp://user:s3cret@probe.example.com/"
	s.DNS.Remote = "ftp://user:s3cret@dns.example.com/"
	s.Servers[0].Outbound = json.RawMessage(`{"protocol":"vless","tag":"s3cret","settings":{"id":"s3cret"}}`)
	s.Servers = append(s.Servers, Server{
		ID: "b2c3d4e5", Name: "Second", Outbound: json.RawMessage(`{"protocol":"freedom","settings":{"id":"s3cret"}} trailing s3cret`),
	})
	err := s.Validate()
	if err == nil {
		t.Fatal("accepted")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("error repeats a secret:\n%v", err)
	}
}

// TestValidateRefusedOutboundsNameTheReason checks that the problem for an
// outbound xray-core refuses says why, and repeats no id, password or key.
func TestValidateRefusedOutboundsNameTheReason(t *testing.T) {
	for _, tt := range []struct{ name, outbound, reason string }{
		{"vless", fmt.Sprintf(vlessPlainTo, "1.2.3.4"), "xray-core refuses VLESS without TLS or encryption to a public address"},
		{"trojan", fmt.Sprintf(trojanPlain, "1.2.3.4"), "xray-core refuses Trojan without TLS to a public address"},
		{"shadowsocks none", fmt.Sprintf(ssMethod, "none", "s3cret-pw"), "xray-core refuses the Shadowsocks methods none and plain"},
		{"shadowsocks 2022", fmt.Sprintf(ssMethod, "2022-blake3-aes-256-gcm", "s3cret-pw"), "xray-core refuses a Shadowsocks 2022 password"},
		{"allowInsecure", fmt.Sprintf(vlessInsecure, true), "xray-core refuses allowInsecure"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := valid()
			withOutbound(tt.outbound)(&s)
			err := s.Validate()
			if err == nil {
				t.Fatal("accepted")
			}
			want := "servers[0].outbound: " + tt.reason
			if !strings.HasPrefix(err.Error(), want) {
				t.Errorf("error %q does not start with %q", err, want)
			}
			for _, secret := range []string{"s3cret", "xraypolicy"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error repeats %q: %v", secret, err)
				}
			}
		})
	}
}

func TestValidateAccepts(t *testing.T) {
	for _, tt := range []struct{ name, outbound string }{
		{"vless without tls or encryption to a private IP", fmt.Sprintf(vlessPlainTo, "203.0.113.10")},
		{"vless without tls or encryption to a private domain", fmt.Sprintf(vlessPlainTo, "foo.test")},
		{"vless with tls to a public IP", fmt.Sprintf(vlessTLSTo, "1.2.3.4")},
		{"trojan without tls to a private IP", fmt.Sprintf(trojanPlain, "10.1.2.3")},
		{"trojan with tls to a public IP", fmt.Sprintf(trojanTLS, "1.2.3.4")},
		{"vless with tls and allowInsecure false", fmt.Sprintf(vlessInsecure, false)},
		{"shadowsocks aes-256-gcm", fmt.Sprintf(ssMethod, "aes-256-gcm", "s3cret-pw")},
		{"shadowsocks 2022 with a 16-byte key", fmt.Sprintf(ssMethod, "2022-blake3-aes-128-gcm", key16)},
	} {
		t.Run("outbound "+tt.name, func(t *testing.T) {
			s := valid()
			withOutbound(tt.outbound)(&s)
			if err := s.Validate(); err != nil {
				t.Error(err)
			}
		})
	}
	for _, m := range []string{
		"domain:example.com", "full:a.b", "keyword:x", `regexp:^a\.b$`, "geosite:category-ir", "example",
		"ext:geo.dat:ads", "geosite:google@cn",
	} {
		t.Run("matcher "+m, func(t *testing.T) {
			s := valid()
			s.Routing.BlockList = []string{m}
			s.Routing.Domestic.Domains = []string{m}
			s.Routing.Rules = []Rule{{Domains: []string{m}, Action: ActionProxy}}
			if err := s.Validate(); err != nil {
				t.Error(err)
			}
		})
	}
	for _, ip := range []string{"10.0.0.0/8", "1.2.3.4", "geoip:ir", "2001:db8::/32", "2001:db8::1", "::ffff:1.2.3.4"} {
		t.Run("ip "+ip, func(t *testing.T) {
			s := valid()
			s.Routing.Domestic.IPs = []string{ip}
			s.Routing.Rules = []Rule{{IPs: []string{ip}, Action: ActionDirect}}
			if err := s.Validate(); err != nil {
				t.Error(err)
			}
		})
	}
	for _, dns := range []string{"203.0.113.53", "https://1.1.1.1/dns-query", "https://dns.example/dns-query"} {
		t.Run("dns remote "+dns, func(t *testing.T) {
			s := valid()
			s.DNS.Remote = dns
			if err := s.Validate(); err != nil {
				t.Error(err)
			}
		})
	}
	for _, tt := range []struct {
		name     string
		domestic string
		remote   string
	}{
		// DoH reaches the domestic resolver's host on another port, which
		// render sends through the proxy.
		{"DoH on the domestic resolver's host", "1.1.1.1", "https://1.1.1.1/dns-query"},
		{"DoH on port 443 of the domestic resolver's host", "203.0.113.53", "https://203.0.113.53:443/dns-query"},
		{"DoH on the router", "", "https://172.31.255.1/dns-query"},
		{"DoH on port 53 of another host", "203.0.113.53", "https://203.0.113.54:53/dns-query"},
		// With a domestic resolver set, the router is not the domestic one.
		{"plain remote at the router beside a domestic resolver", "192.168.88.1", "172.31.255.1"},
	} {
		t.Run("dns "+tt.name, func(t *testing.T) {
			s := valid()
			if tt.domestic != "" {
				s.DNS.Domestic = netip.MustParseAddr(tt.domestic)
			}
			s.DNS.Remote = tt.remote
			if err := s.Validate(); err != nil {
				t.Error(err)
			}
		})
	}

	t.Run("everything at once", func(t *testing.T) {
		s := valid()
		s.Servers = append(s.Servers, Server{
			ID: "0badc0de", Name: strings.Repeat("é", 128), Disabled: true, Link: "vless://x",
			Outbound: json.RawMessage(` {"protocol":"Shadowsocks","settings":{}} `),
		})
		s.Subscriptions[0].Interval = Duration(time.Hour)
		s.Subscriptions[0].URL = "http://sub.example.com/s"
		s.Devices = append(s.Devices[:0],
			Device{Address: netip.MustParsePrefix("192.168.1.5/32"), Name: "tv", MAC: "aa:bb:cc:dd:ee:ff", Policy: Policy{Mode: ModeFull, KillSwitch: true}},
			Device{Address: netip.MustParsePrefix("192.168.1.6/32"), Policy: Policy{Mode: ModeSmart, KillSwitch: true}},
			Device{Address: netip.MustParsePrefix("192.168.2.0/24"), Policy: Policy{Mode: ModeDirect}},
		)
		s.DefaultPolicy = Policy{Mode: ModeFull, KillSwitch: true}
		s.Routing.Pinned = "a1b2c3d4"
		s.Routing.Rules = []Rule{
			{Domains: []string{"x.example"}, Action: ActionDirect},
			{Domains: []string{"y.example"}, Action: ActionProxy},
			{IPs: []string{"10.1.0.0/16"}, Action: ActionBlock},
			{Domains: []string{"z.example"}, IPs: []string{"geoip:ir"}, Action: ActionServer, Server: "0badc0de"},
		}
		s.DNS.Domestic = netip.MustParseAddr("192.168.88.1")
		s.Network.Subnet = netip.MustParsePrefix("10.9.8.0/28")
		s.Health.ProbeURL = "http://connectivitycheck.gstatic.com/generate_204"
		if err := s.Validate(); err != nil {
			t.Error(err)
		}
	})
}
