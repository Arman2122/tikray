package routeros

import (
	_ "embed"
	"strings"

	"github.com/Arman2122/tikray/internal/store"
)

const (
	openUDP    = "tikray-open-udp"
	openRunner = "tikray-open-runner"
	openWAN    = "tikray-open-wan"
)

//go:embed udp-watch.rsc
var udpWatchSource string

func ownedConnectionMark(mark string) bool {
	switch mark {
	case "tikray-open", "tikray-closed", openUDP, openRunner, openWAN:
		return true
	default:
		return false
	}
}

func connectionMatchesPolicy(mark string, policy store.Policy) bool {
	switch mark {
	case "tikray-closed":
		return policy.KillSwitch
	case "tikray-open", openUDP, openRunner, openWAN:
		return !policy.KillSwitch
	}
	return false
}

func openUDPRules(lan, runner, wan string, fasttrack bool) []Object {
	var out []Object
	for _, path := range []struct {
		side, mark, egress string
	}{{"runner", openRunner, "tikray"}, {"wan", openWAN, "!tikray"}} {
		out = append(out, object(firewallMangle, "udp-birth-"+path.side, map[string]string{
			"chain": "forward", "action": "mark-connection", "protocol": "udp", "in-interface-list": lan,
			"out-interface": path.egress, "connection-mark": openUDP, "new-connection-mark": path.mark, "passthrough": "yes",
		}))
		if fasttrack {
			out = append(out, object(firewallMangle, "packet-udp-"+path.side, map[string]string{
				"chain": "forward", "action": "mark-packet", "protocol": "udp", "connection-mark": path.mark,
				"new-packet-mark": proxyPacket, "packet-mark": "no-mark", "passthrough": "yes",
			}))
		}
	}
	for _, tag := range []struct{ side, mark string }{{"pending", openUDP}, {"runner", openRunner}, {"wan", openWAN}} {
		out = append(out, object(firewallMangle, "route-udp-"+tag.side, map[string]string{
			"chain": preChain, "action": "mark-routing", "connection-mark": tag.mark, "new-routing-mark": "tikray-open", "passthrough": "no",
		}, "tikray:route-open-runner", "tikray:route-open-fallback"))
	}
	// An old generic UDP connection can already have a cached NAT decision.
	// The provisional mark is exclusive to tuples classified by the new rules.
	anchor := "tikray:egress-guard"
	for _, path := range []struct{ side, mark, wrong string }{{"legacy", "tikray-open", ""}, {"pending", openUDP, ""}, {"runner", openRunner, "!tikray"}, {"wan", openWAN, "tikray"}} {
		props := map[string]string{"chain": "forward", "action": "drop", "protocol": "udp", "in-interface-list": lan, "connection-mark": path.mark}
		if path.wrong != "" {
			props["out-interface"] = path.wrong
		}
		row := object(firewallFilter, "udp-guard-"+path.side, props)
		row.Before = anchor
		anchor = row.Comment
		out = append(out, row)
	}
	script := strings.NewReplacer("@RUNNER@", runner, "@WAN@", wan, "@LAN@", strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "$", "\\$").Replace(lan)).Replace(strings.TrimSpace(udpWatchSource))
	out = append(out, object(watchMenu, "udp-watch", map[string]string{
		"host": runner, "type": "simple", "interval": "5s", "timeout": "1s", "start-delay": "0s", "startup-delay": "0s", "test-script": script,
	}, "tikray:udp-guard-legacy", "tikray:udp-guard-pending", "tikray:udp-guard-runner", "tikray:udp-guard-wan"))
	return out
}
