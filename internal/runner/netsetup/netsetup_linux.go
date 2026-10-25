//go:build linux

package netsetup

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// rulePriority is the priority of "iif <ingress> lookup TunTable". It
	// sits far ahead of the main table's rule (32766).
	rulePriority = TunTable
	// keepInterval is how often Keep re-checks the routes. xray0 vanishes
	// whenever xray restarts, and traffic is rejected until the routes are
	// back, so this is also the longest outage a restart causes.
	keepInterval = time.Second

	gatewayFile = "/proc/sys/net/ipv4/icmp_echo_ignore_all"
)

// sysctlWrites is what Sysctls writes, in order. Packets that arrive on the
// ingress link leave through xray0, so forwarding must be on and reverse-path
// filtering off. The last one starts the runner as "not a gateway": the kernel
// answers ping from the moment the container starts, long before xray runs, and
// Keep opens the gateway only when xray and its routes are ready.
var sysctlWrites = []struct{ key, value string }{
	{"net.ipv4.ip_forward", "1"},
	{"net.ipv4.conf.all.rp_filter", "0"},
	{"net.ipv4.conf.default.rp_filter", "0"},
	{"net.ipv4.icmp_echo_ignore_all", GatewaySysctl(false, false)},
}

// Sysctls writes the runner's kernel settings and returns, per setting, the
// error of its write (nil on success).
func Sysctls() map[string]error {
	res := make(map[string]error, len(sysctlWrites))
	for _, s := range sysctlWrites {
		res[s.key] = writeSysctl(s.key, s.value)
	}
	return res
}

func writeSysctl(key, value string) error {
	return os.WriteFile("/proc/sys/"+strings.ReplaceAll(key, ".", "/"), []byte(value), 0o644)
}

// Ingress returns the link that holds the IPv4 default route: where traffic
// from the router arrives. In a RouterOS container it is named after the veth,
// not eth0.
func Ingress() (netlink.Link, error) {
	// RouteList covers the main table only, so the unreachable default in
	// TunTable is never mistaken for the real one.
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	var best *netlink.Route
	for i, r := range routes {
		if !isDefaultDst(r.Dst) || r.Type != unix.RTN_UNICAST || r.LinkIndex == 0 {
			continue
		}
		if best == nil || r.Priority < best.Priority {
			best = &routes[i]
		}
	}
	if best == nil {
		return nil, fmt.Errorf("netsetup: no IPv4 default route")
	}
	return netlink.LinkByIndex(best.LinkIndex)
}

// isDefaultDst reports whether dst is 0.0.0.0/0, which netlink may also give as
// nil.
func isDefaultDst(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, _ := dst.Mask.Size()
	return ones == 0 && dst.IP.IsUnspecified()
}

// Keep keeps the runner's routes in place until ctx ends, checking once a
// second. It holds the "unreachable" default in table TunTable, so packets that
// arrive while xray0 is gone are rejected instead of being sent back to the
// router (which would route them here again). It also holds "iif <ingress>
// lookup TunTable" from the start, and while xray0 exists "default dev xray0
// table TunTable", putting it back after every xray restart. After each check
// it sets the ping answer (see GatewaySysctl) and calls report with whether
// the routes are in place and whether the runner now answers ping. When ctx
// ends the runner stops answering ping.
func Keep(ctx context.Context, ingress netlink.Link, healthy func() bool, report func(routesOK, gatewayUp bool)) {
	k := &keeper{ingress: ingress.Attrs().Name, logged: map[string]string{}}
	defer k.setGateway(GatewaySysctl(false, false))
	ticker := time.NewTicker(keepInterval)
	defer ticker.Stop()
	for {
		k.ensureUnreachable()
		routesOK := k.ensureRoutes()
		value := GatewaySysctl(healthy(), routesOK)
		k.setGateway(value)
		report(routesOK, value == GatewaySysctl(true, true))
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// keeper holds what Keep remembers between checks.
type keeper struct {
	ingress string // name of the ingress link
	// logged is the last message per topic, so a failure that lasts is
	// logged once, not once a second.
	logged map[string]string
}

// note logs msg under topic unless it is what was logged there last. An empty
// msg logs nothing and forgets the topic, so the next failure is logged again.
func (k *keeper) note(topic, msg string) {
	if k.logged[topic] == msg {
		return
	}
	k.logged[topic] = msg
	if msg != "" {
		log.Print(msg)
	}
}

// ensureUnreachable keeps the low-priority "unreachable default" in TunTable.
func (k *keeper) ensureUnreachable() {
	r := &netlink.Route{Dst: defaultDst, Table: TunTable, Type: unix.RTN_UNREACHABLE, Priority: UnreachablePriority}
	if err := netlink.RouteReplace(r); err != nil {
		k.note("unreachable", fmt.Sprintf("unreachable default in table %d: %v", TunTable, err))
		return
	}
	k.note("unreachable", "")
}

var defaultDst = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}

// ensureRoutes keeps "iif <ingress> lookup TunTable" and, while xray0 exists,
// "default dev xray0 table TunTable" in place. It reports whether both are.
// The rule does not wait for xray0: until xray creates it, on an empty runner
// and at boot, TunTable's unreachable default must reject what arrives on the
// ingress link, or the main table would send it back to the router.
func (k *keeper) ensureRoutes() bool {
	ruleOK := k.ensureRule()
	tun, err := netlink.LinkByName(TunName)
	if err != nil { // xray has not created it yet, or has stopped
		k.note("routes", TunName+" is missing")
		return false
	}
	if err := netlink.LinkSetUp(tun); err != nil {
		k.note("routes", fmt.Sprintf("set %s up: %v", TunName, err))
		return false
	}
	// A new xray0 takes its rp_filter from conf.default, which Sysctls
	// cleared; setting it again costs nothing and the effective value is the
	// larger of "all" and the interface's.
	if err := writeSysctl("net.ipv4.conf."+TunName+".rp_filter", "0"); err != nil {
		k.note("rp_filter", fmt.Sprintf("rp_filter of %s: %v", TunName, err))
	}
	route := &netlink.Route{LinkIndex: tun.Attrs().Index, Dst: defaultDst, Table: TunTable}
	if err := netlink.RouteReplace(route); err != nil {
		k.note("routes", fmt.Sprintf("default dev %s table %d: %v", TunName, TunTable, err))
		return false
	}
	if !ruleOK {
		k.note("routes", "")
		return false
	}
	k.note("routes", "routes in place")
	return true
}

// ensureRule keeps "iif <ingress> lookup TunTable" in place. It reports
// whether it is.
func (k *keeper) ensureRule() bool {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		k.note("rule", fmt.Sprintf("list rules: %v", err))
		return false
	}
	for _, r := range rules {
		if r.Priority == rulePriority && r.Table == TunTable && r.IifName == k.ingress {
			k.note("rule", "")
			return true
		}
	}
	rule := netlink.NewRule()
	rule.Priority, rule.Table, rule.IifName = rulePriority, TunTable, k.ingress
	if err := netlink.RuleAdd(rule); err != nil {
		k.note("rule", fmt.Sprintf("rule iif %s lookup %d: %v", k.ingress, TunTable, err))
		return false
	}
	k.note("rule", "")
	return true
}

// setGateway writes value to icmp_echo_ignore_all unless it holds it already.
func (k *keeper) setGateway(value string) {
	if cur, err := os.ReadFile(gatewayFile); err == nil && strings.TrimSpace(string(cur)) == value {
		return
	}
	if err := os.WriteFile(gatewayFile, []byte(value), 0o644); err != nil {
		k.note("gateway", fmt.Sprintf("icmp_echo_ignore_all=%s: %v", value, err))
		return
	}
	k.note("gateway", fmt.Sprintf("answering ping: %v", value == GatewaySysctl(true, true)))
}
