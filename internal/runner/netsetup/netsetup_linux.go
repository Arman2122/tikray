//go:build linux

package netsetup

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
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

	gatewayFile    = "/proc/sys/net/ipv4/icmp_echo_ignore_all"
	forwardingFile = "/proc/sys/net/ipv4/ip_forward"
	confDir        = "/proc/sys/net/ipv4/conf"
)

// StartClosed runs before waiting for the veth or booting xray. Local
// sockets remain reachable. The namespace can inherit forwarding, including
// an interface-specific override even when the global switch reads zero.
func StartClosed() error {
	err := setValue(forwardingFile, "0")
	err = errors.Join(err, setValue(gatewayFile, "1"))
	links, e := os.ReadDir(confDir)
	if e != nil {
		return errors.Join(err, e)
	}
	for _, link := range links {
		if link.Name() == "all" {
			continue
		}
		e = setValue(filepath.Join(confDir, link.Name(), "forwarding"), "0")
		if !errors.Is(e, os.ErrNotExist) {
			err = errors.Join(err, e)
		}
	}
	return err
}

// Checking the existing value also supports a read-only sysctl already set
// correctly by the container runtime. Confirm writes before reporting ready.
func setValue(path, value string) error {
	read := func() (string, error) {
		b, e := os.ReadFile(path)
		return strings.TrimSpace(string(b)), e
	}
	current, err := read()
	if err != nil || current == value {
		return err
	}
	if err = os.WriteFile(path, []byte(value), 0644); err != nil {
		return err
	}
	current, err = read()
	if err != nil {
		return err
	}
	if current != value {
		return fmt.Errorf("netsetup: kernel did not retain %s", path)
	}
	return nil
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
// the routes are in place and whether the runner actually answers ping. When ctx
// ends or a check fails, it closes forwarding and the ping response.
func Keep(ctx context.Context, ingress netlink.Link, healthy func() bool, report func(routesOK, gatewayUp bool)) {
	k := &keeper{ingress: ingress.Attrs().Name, logged: map[string]string{}}
	defer k.closeGateway()
	ticker := time.NewTicker(keepInterval)
	defer ticker.Stop()
	for {
		routesOK := k.ensureUnreachable() && k.ensureRoutes()
		up := false
		if routesOK && healthy() {
			up = k.openGateway()
		}
		if !up {
			k.closeGateway()
		}
		report(routesOK, up)
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
func (k *keeper) ensureUnreachable() bool {
	r := &netlink.Route{Dst: defaultDst, Table: TunTable, Type: unix.RTN_UNREACHABLE, Priority: UnreachablePriority}
	if err := netlink.RouteReplace(r); err != nil {
		k.note("unreachable", fmt.Sprintf("unreachable default in table %d: %v", TunTable, err))
		return false
	}
	k.note("unreachable", "")
	return true
}

var defaultDst = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}

// ensureRoutes keeps "iif <ingress> lookup TunTable" and, while xray0 exists,
// "default dev xray0 table TunTable" in place. It reports whether both are.
// The rule does not wait for xray0: until xray creates it, on an empty runner
// and at boot, TunTable's unreachable default must reject what arrives on the
// ingress link, or the main table would send it back to the router.
func (k *keeper) ensureRoutes() bool {
	if !k.ensureRule() {
		return false
	}
	tun, err := netlink.LinkByName(TunName)
	if err != nil { // xray has not created it yet, or has stopped
		k.note("routes", TunName+" is missing")
		return false
	}
	device, ok := tun.(*netlink.Tuntap)
	if !ok || device.Mode != netlink.TUNTAP_MODE_TUN {
		k.note("routes", TunName+" is not a TUN device")
		return false
	}
	if err := netlink.LinkSetUp(tun); err != nil {
		k.note("routes", fmt.Sprintf("set %s up: %v", TunName, err))
		return false
	}
	route := &netlink.Route{LinkIndex: tun.Attrs().Index, Dst: defaultDst, Table: TunTable}
	if err := netlink.RouteReplace(route); err != nil {
		k.note("routes", fmt.Sprintf("default dev %s table %d: %v", TunName, TunTable, err))
		return false
	}
	// RouteReplace acknowledges our two entries but does not remove some
	// other, more preferred default. It could take over immediately on TUN
	// loss, before the next health check. The runner owns this private table.
	installed, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: TunTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		k.note("routes", fmt.Sprintf("verify table %d: %v", TunTable, err))
		return false
	}
	var viaTun, unreachable bool
	for _, r := range installed {
		switch {
		case isDefaultDst(r.Dst) && r.Type == unix.RTN_UNICAST && r.LinkIndex == tun.Attrs().Index && r.Priority == 0 && len(r.Gw) == 0 && len(r.MultiPath) == 0:
			viaTun = true
		case isDefaultDst(r.Dst) && r.Type == unix.RTN_UNREACHABLE && r.Priority == UnreachablePriority:
			unreachable = true
		default:
			k.note("routes", "unexpected route in the private TUN table")
			return false
		}
	}
	if !viaTun || !unreachable {
		k.note("routes", "TUN or fallback route not present")
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
	rule := netlink.NewRule()
	rule.Priority, rule.Table, rule.IifName = rulePriority, TunTable, k.ingress
	found := false
	for _, r := range rules {
		if r.Priority > rulePriority || r.Table == unix.RT_TABLE_LOCAL || (!r.Invert && r.IifName != "" && r.IifName != k.ingress) {
			continue
		}
		// A matching table with a narrower selector, or an earlier lookup
		// of main, would leave some incoming packets outside the guard.
		expected := *rule
		expected.Family, expected.Protocol = r.Family, r.Protocol
		if r != expected {
			k.note("rule", "netsetup: another IPv4 policy rule can precede the ingress guard")
			return false
		}
		found = true
	}
	if found {
		k.note("rule", "")
		return true
	}
	if err := netlink.RuleAdd(rule); err != nil {
		k.note("rule", fmt.Sprintf("rule iif %s lookup %d: %v", k.ingress, TunTable, err))
		return false
	}
	k.note("rule", "")
	return true
}

// Keep forwarding closed if any part of activation fails. In particular the
// unreachable default must already be effective before ip_forward changes.
func (k *keeper) openGateway() bool {
	if err := setValue(forwardingFile, "1"); err != nil {
		k.note("open", err.Error())
		return false
	}
	// Changing Linux forwarding mode can reset per-interface defaults. Xray
	// traffic can arrive on a different link from the route to its source.
	for _, name := range []string{"all", "default", k.ingress, TunName} {
		if err := setValue(filepath.Join(confDir, name, "rp_filter"), "0"); err != nil {
			k.note("open", err.Error())
			return false
		}
	}
	for _, name := range []string{k.ingress, TunName} {
		if err := setValue(filepath.Join(confDir, name, "forwarding"), "1"); err != nil {
			k.note("open", err.Error())
			return false
		}
	}
	if err := setValue(gatewayFile, GatewaySysctl(true, true)); err != nil {
		k.note("open", err.Error())
		return false
	}
	k.note("open", "")
	k.note("gateway", "answering ping: true")
	return true
}

func (k *keeper) closeGateway() {
	if err := StartClosed(); err != nil {
		k.note("gateway", err.Error())
		return
	}
	k.note("gateway", "answering ping: false")
}
