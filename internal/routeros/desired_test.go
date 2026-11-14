package routeros

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

func compilerTopology() Topology {
	return Topology{
		Subnet: store.Default().Network.Subnet, LANList: "trusted",
		LANs:       []LAN{{Interface: "vlan20", Prefix: netip.MustParsePrefix("10.20.0.0/28"), Dedicated: true}},
		LANMembers: []string{"vlan20"},
		RouterIPs:  []netip.Addr{netip.MustParseAddr("10.20.0.1")},
		WAN:        []WANPath{{Interface: "ether1", Gateway: netip.MustParseAddr("198.51.100.254"), Network: netip.MustParsePrefix("198.51.100.0/24")}},
	}
}

func TestPolicyMatrixAndDefaultExceptions(t *testing.T) {
	policies := []store.Policy{{Mode: store.ModeDirect}, {Mode: store.ModeSmart}, {Mode: store.ModeSmart, KillSwitch: true}, {Mode: store.ModeFull}, {Mode: store.ModeFull, KillSwitch: true}}
	for _, def := range policies {
		for _, override := range policies {
			input := PolicyInput{Network: store.Default().Network, Default: def, Devices: []PolicyDevice{{Address: netip.MustParsePrefix("10.20.0.6/32"), MAC: "02:00:00:00:00:06", Policy: override}}}
			objects, err := Desired(input, compilerTopology(), nil)
			if err != nil {
				t.Fatalf("valid policies %v, %v refused: %v", def, override, err)
			}
			for _, tc := range []struct {
				ip string
				p  store.Policy
			}{{"10.20.0.5", def}, {"10.20.0.6", override}, {"10.20.0.1", policies[0]}, {"10.20.0.0", policies[0]}, {"10.20.0.15", policies[0]}, {"10.21.0.5", policies[0]}, {"172.31.255.2", policies[0]}} {
				var lists []string
				for _, o := range objects {
					if o.Menu != "/ip/firewall/address-list" || !strings.HasPrefix(o.Props["list"], "tikray-src-") {
						continue
					}
					p, e := netip.ParsePrefix(o.Props["address"])
					if e != nil {
						t.Fatal("noncanonical source prefix")
					}
					if p.Contains(netip.MustParseAddr(tc.ip)) {
						lists = append(lists, o.Props["list"])
					}
				}
				want := []string(nil)
				if tc.p.Mode != store.ModeDirect {
					suffix := "open"
					if tc.p.KillSwitch {
						suffix = "closed"
					}
					want = []string{"tikray-src-" + string(tc.p.Mode) + "-" + suffix}
				}
				if !slices.Equal(lists, want) {
					t.Fatalf("default %v, override %v at %s gives %v, want %v", def, override, tc.ip, lists, want)
				}
			}
		}
	}
}

func TestProjectOnlyRouterInputs(t *testing.T) {
	st := store.Default()
	secret := "private-fixture-router-projection"
	st.Servers = []store.Server{{Name: secret, Link: secret, Outbound: json.RawMessage(`{}`)}}
	st.Subscriptions = []store.Subscription{{Name: secret, URL: secret}}
	st.Health.ProbeURL = secret
	st.Devices = []store.Device{{Address: netip.MustParsePrefix("10.20.0.6/32"), MAC: "02:00:00:00:00:06", Name: secret, Policy: store.Policy{Mode: store.ModeSmart}}}
	st.Routing.Domestic.Domains = []string{secret}
	st.Routing.Domestic.IPs = []string{"geoip:ir", "2001:db8::/32", "8.8.8.8", "9.9.9.17/24"}
	in, e := Project(st)
	if e != nil {
		t.Fatal("projection rejected valid router inputs")
	}
	raw, _ := json.Marshal(in)
	if strings.Contains(string(raw), secret) {
		t.Fatal("projection retained a private or irrelevant value")
	}
	objects, e := Desired(in, compilerTopology(), []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")})
	if e != nil {
		t.Fatal(e)
	}
	members := map[string]int{}
	for _, o := range objects {
		if o.Props["list"] == "tikray-domestic" {
			members[o.Props["address"]]++
		}
	}
	if !reflect.DeepEqual(members, map[string]int{"8.8.8.8/32": 1, "9.9.9.0/24": 1}) {
		t.Fatal("incorrect domestic projection")
	}
}

func TestDesiredRefusesUnverifiedTopology(t *testing.T) {
	in := PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeSmart, KillSwitch: true}}
	rows := []func(*Topology){func(o *Topology) { o.LANList = "" }, func(o *Topology) { o.LANs = nil }, func(o *Topology) { o.WAN = append(o.WAN, o.WAN[0]) }, func(o *Topology) { o.WAN[0].Gateway = netip.MustParseAddr("10.20.0.1") }, func(o *Topology) { o.Connected = []netip.Prefix{o.Subnet} }, func(o *Topology) { o.Subnet = netip.MustParsePrefix("10.90.0.0/29") }, func(o *Topology) { o.ForeignRefs = []ForeignRef{{Value: "private-fixture"}} }}
	for i, change := range rows {
		obs := compilerTopology()
		change(&obs)
		objects, e := Desired(in, obs, nil)
		if e == nil || len(objects) != 0 || strings.Contains(e.Error(), "private-fixture") {
			t.Fatalf("unsafe topology accepted or exposed, case %d", i)
		}
	}
}

func TestDesiredStableAcrossObservationOrder(t *testing.T) {
	obs := compilerTopology()
	obs.LANs = append(obs.LANs, LAN{Interface: "vlan21", Prefix: netip.MustParsePrefix("10.21.0.0/24"), Dedicated: true})
	obs.LANMembers = append(obs.LANMembers, "vlan21")
	obs.RouterIPs = append(obs.RouterIPs, netip.MustParseAddr("10.21.0.1"))
	in := PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeSmart}, Devices: []PolicyDevice{{Address: netip.MustParsePrefix("10.20.0.4/32"), Policy: store.Policy{Mode: store.ModeDirect}, MAC: "02:00:00:00:00:04"}, {Address: netip.MustParsePrefix("10.21.0.5/32"), Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}, MAC: "02:00:00:00:00:05"}}}
	geo := []netip.Prefix{netip.MustParsePrefix("9.9.0.0/16"), netip.MustParsePrefix("8.8.8.8/32")}
	one, e := Desired(in, obs, geo)
	if e != nil {
		t.Fatal(e)
	}
	if in.Devices[0].Address.String() != "10.20.0.4/32" || geo[0].String() != "9.9.0.0/16" {
		t.Fatal("compiler mutated input")
	}
	slices.Reverse(in.Devices)
	slices.Reverse(obs.LANs)
	slices.Reverse(obs.RouterIPs)
	slices.Reverse(geo)
	two, e := Desired(in, obs, geo)
	if e != nil || !reflect.DeepEqual(one, two) {
		t.Fatal("equivalent observations produced different plans")
	}
}

func TestDirectPolicyCanDetachWhenWANIsAmbiguous(t *testing.T) {
	in := PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeDirect}}
	got, err := Desired(in, Topology{}, nil)
	if err != nil || len(got) != 0 {
		t.Fatal("direct policy could not request detachment")
	}
}

func TestDesiredRequiresExactLANMembership(t *testing.T) {
	in := PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeFull}}
	for _, members := range [][]string{nil, {"guest", "vlan20"}, {"ether1", "vlan20"}, {"vlan21"}} {
		o := compilerTopology()
		o.LANMembers = members
		if got, err := Desired(in, o, nil); err == nil || len(got) != 0 {
			t.Fatal("unverified or widened LAN list accepted")
		}
	}
}

func TestDesiredRepairHasStableRuleOrder(t *testing.T) {
	in := PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeSmart}, Devices: []PolicyDevice{
		{Address: netip.MustParsePrefix("10.20.0.6/32"), Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}, MAC: "02:00:00:00:00:06"},
	}}
	objects, err := Desired(in, compilerTopology(), nil)
	if err != nil {
		t.Fatal(err)
	}
	chains := make(map[[2]string][]Object)
	for _, row := range objects {
		chain := row.Props["chain"]
		if strings.HasPrefix(chain, "tikray-") || chain == "dstnat" {
			k := [2]string{row.Menu, chain}
			chains[k] = append(chains[k], row)
		}
	}
	for k, chain := range chains {
		for i, missing := range chain {
			order := []string{}
			for _, o := range chain {
				if o.Comment != missing.Comment {
					order = append(order, o.Comment)
				}
			}
			at := len(order)
			if missing.Before != "" && !strings.HasPrefix(missing.Before, "first:") {
				at = slices.Index(order, missing.Before)
				if at < 0 {
					t.Fatalf("missing placement anchor in %s", k[1])
				}
			}
			if at != i {
				t.Fatalf("repair of %s changes %s packet order", missing.Comment, k[1])
			}
		}
	}
}

func TestGloballyReachableAnycastIsOutsideLocalBypass(t *testing.T) {
	in := PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeFull, KillSwitch: true}}
	rows, err := Desired(in, compilerTopology(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip    string
		local bool
	}{
		{"192.0.0.8", true}, {"192.0.0.9", false}, {"192.0.0.10", false}, {"192.0.0.11", true}, {"192.0.0.170", true},
	} {
		found := false
		for _, row := range rows {
			if row.Props["list"] == "tikray-local" && netip.MustParsePrefix(row.Props["address"]).Contains(netip.MustParseAddr(tc.ip)) {
				found = true
			}
		}
		if found != tc.local {
			t.Errorf("local bypass for %s = %t, want %t", tc.ip, found, tc.local)
		}
	}
}

func TestProxiedRouterAddressCannotBecomeIPv6Client(t *testing.T) {
	obs := compilerTopology()
	in := PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeDirect}, Devices: []PolicyDevice{
		{Address: netip.MustParsePrefix("10.20.0.1/32"), MAC: "02:00:00:00:00:01", Policy: store.Policy{Mode: store.ModeFull}},
		{Address: netip.MustParsePrefix("10.20.0.5/32"), MAC: "02:00:00:00:00:05", Policy: store.Policy{Mode: store.ModeSmart}},
	}}
	if rows, err := Desired(in, obs, nil); err == nil || len(rows) > 0 {
		t.Fatal("non-client address authorized an IPv6 MAC guard")
	}
}

func TestNonClientAddressCannotGrantIPv6Exception(t *testing.T) {
	obs := compilerTopology()
	for _, a := range []string{"10.20.0.0/32", "10.20.0.1/32", "10.20.0.15/32"} {
		in := PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeFull, KillSwitch: true}, Devices: []PolicyDevice{
			{Address: netip.MustParsePrefix(a), MAC: "02:00:00:00:00:05", Policy: store.Policy{Mode: store.ModeDirect}},
		}}
		if rows, e := Desired(in, obs, nil); e == nil || len(rows) != 0 {
			t.Fatalf("excluded IPv4 address %s created a direct IPv6 exception", a)
		}
	}
}

func TestWANFallbackUsesObservedNextHop(t *testing.T) {
	in := PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeSmart}}
	for _, tc := range []struct {
		path WANPath
		want string
	}{
		{WANPath{Interface: "ether1", Network: netip.MustParsePrefix("198.51.100.0/24"), Gateway: netip.MustParseAddr("198.51.100.253")}, "198.51.100.253"},
		{WANPath{Interface: "ether1", Network: netip.MustParsePrefix("169.254.11.0/30"), Gateway: netip.MustParseAddr("169.254.11.2")}, "169.254.11.2"},
		{WANPath{Interface: "pppoe-out1", PointToPoint: true}, "pppoe-out1"},
		{WANPath{Interface: "ether1"}, ""},
	} {
		obs := compilerTopology()
		obs.WAN = []WANPath{tc.path}
		rows, e := Desired(in, obs, nil)
		if tc.want == "" {
			if e == nil || len(rows) != 0 {
				t.Fatal("assumed an interface-only broadcast gateway")
			}
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		seen := false
		for _, row := range rows {
			if row.Comment == "tikray:route-open-fallback" {
				seen = row.Props["gateway"] == tc.want
			}
		}
		if !seen {
			t.Fatal("incorrect observed distance-two gateway")
		}
	}
}

func TestLargeLANProducesDisjointCIDRs(t *testing.T) {
	obs := compilerTopology()
	obs.LANs[0].Prefix = netip.MustParsePrefix("10.0.0.0/8")
	in := PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeSmart}, Devices: []PolicyDevice{
		{Address: netip.MustParsePrefix("10.120.0.17/32"), MAC: "02:00:00:00:00:17", Policy: store.Policy{Mode: store.ModeDirect}},
		{Address: netip.MustParsePrefix("10.12.0.33/32"), MAC: "02:00:00:00:00:33", Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}},
	}}
	rows, e := Desired(in, obs, nil)
	if e != nil {
		t.Fatal(e)
	}
	var prefixes []netip.Prefix
	var hosts uint64
	for _, row := range rows {
		if strings.HasPrefix(row.Props["list"], "tikray-src-") {
			p := netip.MustParsePrefix(row.Props["address"])
			for _, prior := range prefixes {
				if prior.Overlaps(p) {
					t.Fatal("overlapping source classes")
				}
			}
			prefixes = append(prefixes, p)
			hosts += uint64(1) << uint(32-p.Bits())
		}
	}
	// The network, broadcast, router and single explicitly direct client
	// are excluded. The other /32 remains part of the full-closed class.
	// Isolating one exceptional address splits at most one CIDR per bit.
	maxPrefixes := 1 + 5*(32-obs.LANs[0].Prefix.Bits())
	if hosts != 1<<24-4 || len(prefixes) > maxPrefixes {
		t.Fatalf("source cover: %d hosts in %d prefixes", hosts, len(prefixes))
	}
	in.Devices = append(in.Devices, PolicyDevice{Address: netip.MustParsePrefix("10.240.0.7/32"), Policy: in.Default})
	same, e := Desired(in, obs, nil)
	if e != nil || !reflect.DeepEqual(same, rows) {
		t.Fatal("redundant same-policy device changed router configuration")
	}
}
