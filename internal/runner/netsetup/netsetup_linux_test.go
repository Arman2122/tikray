//go:build linux

package netsetup

import (
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// inNewNetns moves the test's goroutine, locked to its thread, into a new
// network namespace. The thread is never unlocked, so it ends with the test
// instead of going back to the runtime in the wrong namespace.
func inNewNetns(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("a network namespace needs root")
	}
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Skipf("no new network namespace: %v", err)
	}
}

// addLink adds a veth named name (its peer is name+"p") and returns it.
func addLink(t *testing.T, name string) netlink.Link {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}); err != nil {
		t.Fatalf("add %s: %v", name, err)
	}
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// wantIngressRules fails unless the rule "iif <ingress> lookup TunTable" is
// in place n times.
func wantIngressRules(t *testing.T, ingress string, n int) {
	t.Helper()
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for _, r := range rules {
		if r.Priority == rulePriority && r.Table == TunTable && r.IifName == ingress {
			got++
		}
	}
	if got != n {
		t.Errorf("rule iif %s lookup %d is in place %d times, want %d (rules %v)", ingress, TunTable, got, n, rules)
	}
}

// The rule that sends what arrives on the ingress link to table 1001 does not
// wait for xray0: on an empty runner, and at boot before xray starts, the
// table's unreachable default must reject that traffic, rather than the main
// table sending it back to the router.
func TestRoutesRuleWithoutTun(t *testing.T) {
	inNewNetns(t)
	addLink(t, "ing0")
	k := &keeper{ingress: "ing0", logged: map[string]string{}}

	k.ensureUnreachable()
	if k.ensureRoutes() {
		t.Error("routes reported in place without xray0")
	}
	wantIngressRules(t, "ing0", 1)

	// xray creates xray0: the default route through it follows, and the rule
	// is not added again.
	tun := addLink(t, TunName)
	for range 2 {
		if !k.ensureRoutes() {
			t.Fatal("routes not in place with xray0")
		}
	}
	wantIngressRules(t, "ing0", 1)
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: TunTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatal(err)
	}
	var viaTun, unreachable bool
	for _, r := range routes {
		viaTun = viaTun || r.LinkIndex == tun.Attrs().Index && r.Type == unix.RTN_UNICAST
		unreachable = unreachable || r.Type == unix.RTN_UNREACHABLE && r.Priority == UnreachablePriority
	}
	if !viaTun || !unreachable {
		t.Errorf("table %d holds %v; want the default via %s and the unreachable default", TunTable, routes, TunName)
	}
}
