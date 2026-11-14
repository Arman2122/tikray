//go:build lab

package m3

import (
	"encoding/base64"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/routeros"

	routerosfiles "github.com/Arman2122/tikray/routeros"
	ros "github.com/go-routeros/routeros/v3"
)

func TestOwnedBindingRepair(t *testing.T) {
	r := newRig(t)
	run := func(args ...string) *ros.Reply {
		t.Helper()
		q, e := r.admin.RunArgsContext(r.ctx, args)
		if e != nil {
			t.Fatal("binding fixture refused", args[0])
		}
		return q
	}
	module, e := routerosfiles.Sources.ReadFile("bindings.rsc")
	if e != nil {
		t.Fatal(e)
	}
	invoke := func(mode string) string {
		body := "{\n" + string(module) + "\n" + `:local correct [$bindPeers "` + mode + `" "172.30.252.0/29"]; :if ($correct != true) do={ :error "tikray: missing binding acknowledgement" } }`
		old := run("/system/script/print", "?name=binding-fixture", "=.proplist=.id")
		if len(old.Re) > 0 {
			run("/system/script/remove", "=.id="+old.Re[0].Map[".id"])
		}
		run("/system/script/add", "=name=binding-fixture", "=source="+body)
		out, err := r.chr.RunPrivate(r.ctx, `:onerror reason in={/system/script/run binding-fixture;:put "binding-OK"} do={:put ("binding-fail=" . [:convert $reason to=base64])}`)
		if err == nil && strings.TrimSpace(out) == "binding-OK" {
			return ""
		}
		_, encoded, _ := strings.Cut(out, "binding-fail=")
		data, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		msg := string(data)
		if i := strings.Index(msg, "tikray: "); i >= 0 {
			rest := msg[i:]
			if m := regexp.MustCompile(`^tikray: [a-zA-Z ;_-]+`).FindString(rest); m != "" {
				return m
			}
		}
		for _, reason := range []string{"input does not match", "no such item", "invalid internal item", "already have", "permission", "expected", "syntax", "argument", "cannot be changed", "cannot compare", "invalid value"} {
			if strings.Contains(msg, reason) {
				return reason + " " + regexp.MustCompile(`line [0-9]+ column [0-9]+`).FindString(msg)
			}
		}
		return "native binding rejection " + regexp.MustCompile(`line [0-9]+ column [0-9]+`).FindString(msg+out)
	}
	if err := invoke("preflight"); err != "" {
		t.Fatal("first preflight", err)
	}
	run("/interface/bridge/add", "=name=tikray", "=protocol-mode=none", "=comment=tikray:bridge")
	run("/ip/address/add", "=address=172.30.252.1/29", "=interface=tikray", "=comment=tikray:addr")
	for _, p := range []struct{ side, addr string }{{"ctl", "172.30.252.2/29"}, {"runner", "172.30.252.3/29"}} {
		run("/interface/veth/add", "=name=tikray-"+p.side, "=address="+p.addr, "=gateway=172.30.252.1", "=comment=tikray:veth-"+p.side)
	}
	if err := invoke("repair"); err != "" {
		t.Fatal("initial binding", err)
	}
	if err := invoke("check"); err != "" {
		t.Fatal("fresh proof", err)
	}
	get := func(menu, tag string) map[string]string {
		t.Helper()
		q := run(menu+"/print", "?comment="+tag, "=.proplist=.id,bridge,interface,on-interface,vid,mac-address,container-mac-address")
		if len(q.Re) != 1 {
			t.Fatal("missing unique owned row", tag)
		}
		return q.Re[0].Map
	}
	arp := get("/ip/arp", "tikray:arp-runner")
	fdb := get("/interface/bridge/host", "tikray:fdb-runner")
	v := get("/interface/veth", "tikray:veth-runner")
	if fdb["interface"] != "tikray-runner" || fdb["mac-address"] != v["container-mac-address"] || arp["mac-address"] != v["container-mac-address"] {
		t.Fatal("independent static readback")
	}
	// Change just the control-plane view of the new peer identity. No guest
	// traffic is trusted to announce the new MAC.
	const changed = "02:7F:01:22:33:44"
	run("/interface/veth/set", "=.id="+v[".id"], "=container-mac-address="+changed)
	if err := invoke("check"); err == "" {
		t.Fatal("stale bindings accepted")
	}
	if err := invoke("repair"); err != "" {
		t.Fatal("veth replacement binding", err)
	}
	if got := get("/ip/arp", "tikray:arp-runner"); got["mac-address"] != changed || got[".id"] != arp[".id"] {
		t.Fatal("wrong static ARP repair")
	}
	if got := get("/interface/bridge/host", "tikray:fdb-runner"); got["mac-address"] != changed || got[".id"] != fdb[".id"] {
		t.Fatal("wrong static forwarding repair")
	}
	// Deleting the actual veth can delete (or orphan) the associated port
	// and FDB row. Exercise the normal restricted API against what survived.
	native := newNativeClient(t, r)
	subnet := netip.MustParsePrefix("172.30.252.0/29")
	if err := routeros.ReconcileBindings(r.ctx, native, subnet, false); err != nil {
		t.Fatal("native read-only positive", err)
	}
	run("/interface/veth/remove", "=.id="+v[".id"])
	const replacement = "02:7F:01:AA:BB:03"
	run("/interface/veth/add", "=name=tikray-runner", "=comment=tikray:veth-runner", "=address=172.30.252.3/29", "=gateway=172.30.252.1", "=container-mac-address="+replacement)
	if err := routeros.ReconcileBindings(r.ctx, native, subnet, false); err == nil {
		t.Fatal("new veth accepted before repair")
	}
	if err := routeros.ReconcileBindings(r.ctx, native, subnet, true); err != nil {
		t.Fatal("restricted veth recreation repair", err)
	}
	if err := invoke("check"); err != "" {
		t.Fatal("router disagrees with restricted repair", err)
	}
	if get("/ip/arp", "tikray:arp-runner")["mac-address"] != replacement || get("/interface/bridge/host", "tikray:fdb-runner")["mac-address"] != replacement {
		t.Fatal("wrong recreated veth binding")
	}
}

func TestBindingRemovalIsScoped(t *testing.T) {
	body, err := routerosfiles.Sources.ReadFile("uninstall-bindings.rsc")
	if err != nil {
		t.Fatal("owner binding-removal stage missing")
	}
	r := newRig(t)
	run := func(args ...string) *ros.Reply {
		t.Helper()
		q, e := r.admin.RunArgsContext(r.ctx, args)
		if e != nil {
			t.Fatal("binding removal fixture refused", args[0])
		}
		return q
	}
	run("/interface/bridge/add", "=name=tikray", "=protocol-mode=none", "=arp=reply-only", "=comment=tikray:bridge")
	run("/ip/address/add", "=interface=tikray", "=address=172.30.252.1/29", "=comment=tikray:addr")
	for _, p := range []struct{ side, ip, mac string }{{"ctl", "172.30.252.2", "02:22:33:44:55:02"}, {"runner", "172.30.252.3", "02:22:33:44:55:03"}} {
		iface := "tikray-" + p.side
		run("/interface/veth/add", "=name="+iface, "=address="+p.ip+"/29", "=gateway=172.30.252.1", "=container-mac-address="+p.mac, "=comment=tikray:veth-"+p.side)
		run("/interface/bridge/port/add", "=bridge=tikray", "=interface="+iface, "=comment=tikray:port-"+p.side)
		run("/ip/arp/add", "=interface=tikray", "=address="+p.ip, "=mac-address="+p.mac, "=comment=tikray:arp-"+p.side)
		run("/interface/bridge/host/add", "=bridge=tikray", "=interface="+iface, "=mac-address="+p.mac, "=comment=tikray:fdb-"+p.side)
	}
	add := run("/system/script/add", "=name=probe-remove-bindings", "=source="+string(body))
	id := add.Done.Map["ret"]
	call := func() bool { _, e := r.admin.RunContext(r.ctx, "/system/script/run", "=.id="+id); return e == nil }
	// A retagged neighbor is still in use by its owner.
	q := run("/ip/arp/print", "?comment=tikray:arp-runner", "=.proplist=.id")
	rid := q.Re[0].Map[".id"]
	run("/ip/arp/set", "=.id="+rid, "=comment=owner:mine")
	if call() {
		t.Fatal("foreign binding accepted for removal")
	}
	if len(run("/interface/bridge/host/print", "?comment=tikray:fdb-ctl", "=.proplist=.id").Re) != 1 {
		t.Fatal("partial removal before ownership proof")
	}
	run("/ip/arp/set", "=.id="+rid, "=comment=tikray:arp-runner")
	decoy := run("/ip/arp/add", "=address=172.30.252.6", "=mac-address=02:22:33:44:55:06", "=interface=tikray", "=comment=owner:neighbor").Done.Map["ret"]
	if !call() || !call() {
		t.Fatal("binding teardown did not converge")
	}
	for _, s := range []string{"ctl", "runner"} {
		if len(run("/ip/arp/print", "?comment=tikray:arp-"+s, "=.proplist=.id").Re) != 0 || len(run("/interface/bridge/host/print", "?comment=tikray:fdb-"+s, "=.proplist=.id").Re) != 0 {
			t.Fatal("owned binding survived")
		}
	}
	if len(run("/ip/arp/print", "?.id="+decoy, "?comment=owner:neighbor", "=.proplist=.id").Re) != 1 {
		t.Fatal("unrelated neighbor changed")
	}
}
