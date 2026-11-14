//go:build lab

package m3

import (
	"net"
	"testing"
)

// Check actual row identity and tagging on the two supported RouterOS releases.
func TestM3BridgeBindingSchema(t *testing.T) {
	r := newRig(t)
	run := func(args ...string) string {
		t.Helper()
		q, e := r.admin.RunArgsContext(r.ctx, args)
		if e != nil {
			t.Fatal("native fixture refused", args[0])
		}
		if q.Done != nil {
			return q.Done.Map["ret"]
		}
		return ""
	}
	run("/interface/bridge/add", "=name=bind-test", "=protocol-mode=none", "=arp=reply-only", "=comment=tikray:probe-bridge")
	run("/interface/veth/add", "=name=bind-peer", "=address=172.28.201.2/29", "=gateway=172.28.201.1", "=comment=tikray:probe-peer")
	run("/interface/bridge/port/add", "=bridge=bind-test", "=interface=bind-peer", "=learn=no", "=comment=tikray:probe-port")
	v, e := r.admin.RunContext(r.ctx, "/interface/veth/print", "?name=bind-peer", "=.proplist=.id,mac-address,container-mac-address")
	if e != nil || len(v.Re) != 1 {
		t.Fatal("veth missing")
	}
	for _, p := range []string{"mac-address", "container-mac-address"} {
		_, e := net.ParseMAC(v.Re[0].Map[p])
		t.Logf("veth %s available=%t", p, e == nil)
	}
	mac := v.Re[0].Map["container-mac-address"]
	if _, e := net.ParseMAC(mac); e != nil {
		mac = "02:00:00:b1:0d:02"
	}
	run("/ip/arp/add", "=interface=bind-test", "=address=172.28.201.2", "=mac-address="+mac, "=comment=tikray:probe-arp")
	q, e := r.admin.RunContext(r.ctx, "/interface/bridge/host/add", "=bridge=bind-test", "=interface=bind-peer", "=mac-address="+mac, "=comment=tikray:probe-fdb")
	tagged := e == nil && q.Done != nil
	if tagged {
		q, e = r.admin.RunContext(r.ctx, "/interface/bridge/host/print", "?comment=tikray:probe-fdb", "=.proplist=.id,comment,interface,mac-address")
		tagged = e == nil && len(q.Re) == 1 && q.Re[0].Map["interface"] == "bind-peer"
	}
	if !tagged {
		run("/interface/bridge/host/add", "=bridge=bind-test", "=interface=bind-peer", "=mac-address="+mac)
	}
	t.Logf("static native FDB accepts and returns ownership comment=%t", tagged)
	run("/interface/bridge/filter/add", "=chain=output", "=out-interface=bind-peer", "=mac-protocol=ip", "=dst-address=172.28.201.3/32", "=action=drop", "=comment=tikray:probe-output")
}
