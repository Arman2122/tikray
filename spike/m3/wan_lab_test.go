//go:build lab

package m3

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/store"
)

// The restricted account observes and applies only the compiled open table
// and its fallback. The owner changes the main default on a disposable CHR.
func TestM3MainDefaultObservation(t *testing.T) {
	r := newRig(t)
	c := &countedNative{Client: newNativeClient(t, r)}
	run := func(label, cmd string) {
		t.Helper()
		if _, e := r.chr.RunPrivate(r.ctx, cmd); e != nil {
			t.Fatalf("unable to configure %s", label)
		}
	}
	run("bridge and LAN", `/interface/bridge/add name=tikray protocol-mode=none comment="tikray:bridge"; /ip/address/add interface=tikray address=172.30.252.1/29 comment="tikray:addr"; /interface/list/add name=inside; /interface/list/member/add list=inside interface=ether2`)
	scope := routeros.InstallScope{Subnet: netip.MustParsePrefix("172.30.252.0/29"), LANList: "inside", LANs: []routeros.LAN{{Interface: "ether2", Prefix: netip.MustParsePrefix("192.168.88.0/24")}}, WAN: routeros.WANPath{Interface: "ether1", Gateway: netip.MustParseAddr("198.51.100.254")}}
	state := store.Default()
	state.Network.Subnet = scope.Subnet
	state.Devices = []store.Device{{Address: netip.MustParsePrefix("192.168.88.21/32"), MAC: "02:00:00:00:00:21", Policy: store.Policy{Mode: store.ModeFull}}}
	policy, e := routeros.Project(state)
	if e != nil {
		t.Fatal(e)
	}
	await := func(label string, ok func() bool) {
		t.Helper()
		for end := time.Now().Add(12 * time.Second); ; {
			if ok() {
				return
			}
			if time.Now().After(end) {
				t.Fatalf("%s did not converge", label)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	// This independent control uses the owner account and the known fixture;
	// the implementation cannot pass by treating all native defaults as absent.
	ownerView := func() ([]map[string]string, error) {
		rr, e := r.admin.RunContext(r.ctx, "/ip/route/print", "?routing-table=main", "?dst-address=0.0.0.0/0", "?active=true", "=.proplist=gateway,immediate-gw,ecmp")
		if e != nil {
			return nil, e
		}
		var rows []map[string]string
		for _, rr := range rr.Re {
			rows = append(rows, rr.Map)
		}
		return rows, nil
	}
	verify := func(label, expected string) {
		t.Helper()
		var a routeros.Actual
		var wanted []routeros.Object
		await(label, func() bool {
			var err error
			a, err = routeros.Observe(r.ctx, c, scope)
			if err != nil {
				return false
			}
			target, err := routeros.Desired(policy, a.Topology, nil)
			if expected == "" {
				return len(a.Topology.WAN) == 0 && err != nil
			}
			if err != nil {
				return false
			}
			wanted = nil
			for _, o := range target {
				switch o.Comment {
				case "tikray:table-open":
					wanted = append(wanted, o)
				case "tikray:route-open-fallback":
					if o.Props["gateway"] != expected {
						return false
					}
					wanted = append(wanted, o)
				}
			}
			return len(wanted) == 2
		})
		if expected == "" {
			return
		}
		ops, e := routeros.Plan(a, wanted)
		if e != nil {
			t.Fatal(e)
		}
		if e = routeros.Execute(r.ctx, c, a, ops); e != nil {
			t.Fatalf("%s: %v", label, e)
		}
		await(label+" owned route", func() bool {
			rr, e := r.admin.RunContext(r.ctx, "/ip/route/print", "?comment=tikray:route-open-fallback", "?routing-table=tikray-open", "?active=true", "=.proplist=gateway,immediate-gw")
			return e == nil && len(rr.Re) == 1 && rr.Re[0].Map["gateway"] == expected && rr.Re[0].Map["immediate-gw"] == expected
		})
	}
	verify("baseline", "198.51.100.254%ether1")
	run("changed gateway", `/ip/route/set [find where comment="lab:default"] gateway=198.51.100.253`)
	verify("changed gateway", "198.51.100.253%ether1")
	run("standby", `/ip/route/add routing-table=main dst-address=0.0.0.0/0 gateway=198.51.100.254 distance=10 comment="wan:alternate"`)
	verify("inactive standby", "198.51.100.253%ether1")
	run("equal-cost second default", `/ip/route/set [find where comment="wan:alternate"] distance=1`)
	await("independent ECMP control", func() bool { rows, e := ownerView(); return e == nil && len(rows) == 2 })
	verify("ambiguous ECMP", "")
	run("withdraw defaults", `/ip/route/remove [find where comment="wan:alternate"]; /ip/route/disable [find where comment="lab:default"]`)
	await("withdrawn defaults", func() bool { rows, e := ownerView(); return e == nil && len(rows) == 0 })
	verify("no default", "")
	run("replacement interface", `/interface/bridge/add name=wan-proof protocol-mode=none; /ip/address/add interface=wan-proof address=192.0.2.2/24; /ip/route/set [find where comment="lab:default"] gateway=192.0.2.1%wan-proof disabled=no`)
	verify("replacement interface", "192.0.2.1%wan-proof")
	run("point-to-point gateway", `/interface/gre/add name=wan-point local-address=198.51.100.2 remote-address=198.51.100.254; /interface/gre/unset [find where name="wan-point"] keepalive; /ip/route/set [find where comment="lab:default"] gateway=wan-point`)
	verify("point-to-point gateway", "wan-point")
	run("restore main", `/ip/route/set [find where comment="lab:default"] gateway=198.51.100.254`)
	verify("restored default", "198.51.100.254%ether1")
}
