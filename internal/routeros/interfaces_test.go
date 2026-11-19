package routeros

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

func TestDesiredPerInterfaceWiFiAndPortPolicies(t *testing.T) {
	obs := compilerTopology()
	// Add a second dedicated LAN interface representing a VPN Wi-Fi SSID (wifi-vpn)
	// and a third dedicated LAN Ethernet port (ether4).
	wifiNet := netip.MustParsePrefix("192.168.90.0/24")
	portNet := netip.MustParsePrefix("192.168.40.0/24")
	obs.LANs = append(obs.LANs,
		LAN{Interface: "wifi-vpn", Prefix: wifiNet, Dedicated: true},
		LAN{Interface: "ether4", Prefix: portNet, Dedicated: true},
	)
	obs.LANMembers = append(obs.LANMembers, "wifi-vpn", "ether4")
	obs.RouterIPs = append(obs.RouterIPs, netip.MustParseAddr("192.168.90.1"), netip.MustParseAddr("192.168.40.1"))
	obs.Connected = append(obs.Connected, wifiNet, portNet)

	// Main LAN bridge stays Direct; wifi-vpn routes Full + Kill Switch; ether4 routes Smart.
	in := PolicyInput{
		Network: store.Network{Subnet: obs.Subnet},
		Default: store.Policy{Mode: store.ModeDirect},
		Interfaces: []PolicyInterface{
			{Interface: "wifi-vpn", Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}},
			{Interface: "ether4", Policy: store.Policy{Mode: store.ModeSmart}},
		},
	}

	objs, err := Desired(in, obs, nil)
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}

	var hasWifiFullClosed, hasEther4SmartOpen, hasMainBridgeProxied, hasWifiV6Guard bool
	for _, o := range objs {
		if o.Menu == addressListMenu {
			addr, _ := netip.ParsePrefix(o.Props["address"])
			if o.Props["list"] == "tikray-src-full-closed" && wifiNet.Contains(addr.Addr()) {
				hasWifiFullClosed = true
			}
			if o.Props["list"] == "tikray-src-smart-open" && portNet.Contains(addr.Addr()) {
				hasEther4SmartOpen = true
			}
			if (o.Props["list"] == "tikray-src-full-closed" || o.Props["list"] == "tikray-src-smart-open") && obs.LANs[0].Prefix.Contains(addr.Addr()) {
				hasMainBridgeProxied = true
			}
		}
		if o.Menu == ipv6Filter && o.Props["in-interface"] == "wifi-vpn" && o.Props["action"] == "reject" {
			hasWifiV6Guard = true
		}
	}
	if !hasWifiFullClosed {
		t.Fatal("wifi-vpn subnet missing from tikray-src-full-closed")
	}
	if !hasEther4SmartOpen {
		t.Fatal("ether4 subnet missing from tikray-src-smart-open")
	}
	if hasMainBridgeProxied {
		t.Fatal("direct bridge LAN should not be added to proxied source lists")
	}
	if !hasWifiV6Guard {
		t.Fatal("wifi-vpn interface missing IPv6 leak guard")
	}
}

func TestDesiredPinnedWANUplinkForRunner(t *testing.T) {
	obs := compilerTopology()
	obs.WANUplinks = []WANPath{
		obs.WAN[0],
		{Interface: "pppoe-out1", PointToPoint: true},
	}

	in := PolicyInput{
		Network: store.Network{Subnet: obs.Subnet, WANInterface: "pppoe-out1"},
		Default: store.Policy{Mode: store.ModeSmart},
	}

	objs, err := Desired(in, obs, nil)
	if err != nil {
		t.Fatalf("Desired with pinned WAN: %v", err)
	}

	byComment := map[string]Object{}
	for _, o := range objs {
		byComment[o.Comment] = o
	}
	tbl, ok := byComment["tikray:table-wan"]
	if !ok || tbl.Props["name"] != "tikray-wan" || tbl.Props["fib"] != "yes" {
		t.Fatalf("missing or invalid table-wan: %+v", tbl)
	}
	pri, ok := byComment["tikray:route-wan-primary"]
	if !ok || pri.Props["gateway"] != "pppoe-out1" || pri.Props["routing-table"] != "tikray-wan" {
		t.Fatalf("missing or invalid route-wan-primary: %+v", pri)
	}
	fb, ok := byComment["tikray:route-wan-fallback"]
	if !ok || fb.Props["distance"] != "2" || fb.Props["routing-table"] != "tikray-wan" {
		t.Fatalf("missing or invalid route-wan-fallback: %+v", fb)
	}
	m, ok := byComment["tikray:runner-wan"]
	if !ok || m.Props["in-interface"] != "tikray" || m.Props["src-address"] != obs.Subnet.Masked().Addr().Next().Next().Next().String() || m.Props["new-routing-mark"] != "tikray-wan" {
		t.Fatalf("missing or invalid runner-wan mangle: %+v", m)
	}
	if !ownedRole(tableMenu, "tikray:table-wan") || !ownedRole(routeMenu, "tikray:route-wan-primary") || !ownedRole(firewallMangle, "tikray:runner-wan") {
		t.Fatal("ownedRole did not recognize WAN uplink steering tags")
	}
}

func TestEngineInterfacesDiscovery(t *testing.T) {
	p := &observationPeer{
		generation: 1,
		rows: map[string][]Row{
			"/interface": {
				{"name": "ether1", "type": "ether", "running": "true", "disabled": "false", "rx-byte": "102400", "tx-byte": "51200"},
				{"name": "pppoe-out1", "type": "pppoe-out", "running": "true", "disabled": "false", "rx-byte": "800000", "tx-byte": "200000"},
				{"name": "bridge", "type": "bridge", "running": "true", "disabled": "false"},
				{"name": "ether2", "type": "ether", "running": "true", "disabled": "false"},
				{"name": "wifi1", "type": "wifi", "running": "true", "disabled": "false"},
				{"name": "wifi-vpn", "type": "wifi", "running": "true", "disabled": "false"},
				{"name": "tikray", "type": "bridge", "running": "true", "disabled": "false"},
			},
			"/interface/bridge/port": {
				{"interface": "ether2", "bridge": "bridge", "disabled": "false"},
				{"interface": "wifi1", "bridge": "bridge", "disabled": "false"},
			},
			"/interface/wifi": {
				{"name": "wifi1", "configuration.ssid": "Home-5G", "running": "true", "disabled": "false"},
				{"name": "wifi-vpn", "configuration.ssid": "Home-VPN", "running": "true", "disabled": "false"},
			},
			"/ip/address": {
				{"address": "192.168.88.1/24", "interface": "bridge", "disabled": "false"},
				{"address": "192.168.90.1/24", "interface": "wifi-vpn", "disabled": "false"},
			},
			"/interface/list/member": {
				{"interface": "bridge", "list": "LAN", "disabled": "false"},
				{"interface": "wifi-vpn", "list": "LAN", "disabled": "false"},
				{"interface": "pppoe-out1", "list": "WAN", "disabled": "false"},
			},
			"/ip/route": {
				{"routing-table": "main", "dst-address": "0.0.0.0/0", "gateway": "pppoe-out1", "immediate-gw": "pppoe-out1", "active": "true", "distance": "1", "disabled": "false"},
				{"routing-table": "main", "dst-address": "0.0.0.0/0", "gateway": "198.51.100.1", "immediate-gw": "198.51.100.1%ether1", "active": "false", "distance": "2", "disabled": "false"},
			},
		},
	}
	scope := InstallScope{
		Subnet:  netip.MustParsePrefix("172.31.255.0/29"),
		LANList: "LAN",
		LANs: []LAN{
			{Interface: "bridge", Prefix: netip.MustParsePrefix("192.168.88.0/24"), Dedicated: true},
			{Interface: "wifi-vpn", Prefix: netip.MustParsePrefix("192.168.90.0/24"), Dedicated: true},
		},
		WAN: WANPath{Interface: "pppoe-out1", PointToPoint: true},
	}
	e := NewEngine(p, scope, t.TempDir())
	inv, err := e.Interfaces(t.Context())
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}
	if !inv.Managed || inv.ActiveWAN != "pppoe-out1" || len(inv.Uplinks) != 2 {
		t.Fatalf("unexpected uplinks: %+v", inv)
	}
	if slices.ContainsFunc(inv.Interfaces, func(i RouterInterface) bool { return i.Name == "tikray" }) {
		t.Fatal("internal tikray bridge should be excluded from user interface inventory")
	}
	var foundWifiVPN, foundWifi1 bool
	for _, ri := range inv.Interfaces {
		if ri.Name == "wifi-vpn" && ri.Role == "lan" && ri.SSID == "Home-VPN" && ri.InScope && slices.Contains(ri.Subnets, "192.168.90.0/24") {
			foundWifiVPN = true
		}
		if ri.Name == "wifi1" && ri.Role == "bridge-port" && ri.Bridge == "bridge" && ri.SSID == "Home-5G" {
			foundWifi1 = true
		}
	}
	if !foundWifiVPN || !foundWifi1 {
		t.Fatalf("expected wifi-vpn (routed LAN) and wifi1 (bridge-port) in %+v", inv.Interfaces)
	}
}
