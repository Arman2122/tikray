// Package netsetup sets up the runner's networking inside its container: the
// sysctls, the routes that send traffic arriving on the ingress link into xray's
// TUN device, and the ping answer that tells RouterOS whether the runner is a
// usable gateway. The netlink work is Linux only; the decisions are portable.
package netsetup

const (
	// TunName is the TUN device xray's inbound creates.
	TunName = "xray0"
	// TunTable is the routing table that sends traffic into TunName.
	TunTable = 1001
	// UnreachablePriority is the metric of the "unreachable default" in
	// TunTable. It is the lowest-priority route there, so the default via
	// TunName (metric 0) wins whenever that device exists.
	UnreachablePriority = 100
)

// GatewaySysctl is the value for /proc/sys/net/ipv4/icmp_echo_ignore_all. The
// runner answers ping ("0") only while xray runs and its routes are in place;
// RouterOS check-gateway and netwatch probe the runner with ping, so a runner
// that cannot carry traffic withdraws itself and fail-open traffic goes direct.
func GatewaySysctl(healthy, routesOK bool) string {
	if healthy && routesOK {
		return "0"
	}
	return "1"
}
