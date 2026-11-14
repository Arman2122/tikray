//go:build lab

package e2e

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Recreate the control veth with the daemon stopped. An API client cannot
// repair its own stale return path; the actual owner import has to do it.
func TestM3ReimportWithReplacementVeth(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 14*time.Minute)
	defer cancel()
	f := DeployM3(ctx, t)
	f.stage(ctx, t, true)
	f.requireSuccess(ctx, t)
	f.checkReady(ctx, t)
	publicID := f.file(ctx, t, dataRoot+"/state/install.id")
	const newMAC = "02:93:44:12:ab:cd"
	previous := f.mustRun(ctx, t, `:put [/interface/veth/get [find where comment="tikray:veth-ctl"] container-mac-address]`)
	if strings.EqualFold(previous, newMAC) {
		t.Fatal("test MAC must differ")
	}
	peer := f.mustRun(ctx, t, `:put [:tostr [/ip/arp/find where comment="tikray:arp-runner"]]`)
	if peer == "" {
		t.Fatal("runner ARP witness missing")
	}
	f.mustRun(ctx, t, `/system/scheduler/disable [find where comment="tikray:watchdog-scheduler"]`)
	f.mustRun(ctx, t, `/container/stop [find where name="tikray" and comment="tikray:tikray"]`)
	if e := f.waitForContainer(ctx, "tikray", "stopped"); e != nil {
		t.Fatal("control did not stop")
	}
	// Release the old native reference before replacing the interface. The
	// installer sees the still-owned container, original volume and a new
	// veth with the same role and IPv4 address, but a different native ID/MAC.
	f.mustRun(ctx, t, `/interface/veth/add name=m3-holding-veth address=192.0.2.10/29 gateway=192.0.2.9 comment="lab:temporary-detached-port"`)
	f.mustRun(ctx, t, `/container/set [find where name="tikray" and comment="tikray:tikray"] interface=m3-holding-veth`)
	f.mustRun(ctx, t, `/interface/veth/remove [find where name="tikray-ctl" and comment="tikray:veth-ctl"]`)
	f.mustRun(ctx, t, `/interface/veth/add name=tikray-ctl comment="tikray:veth-ctl" address=172.30.252.2/29 gateway=172.30.252.1 container-mac-address=`+newMAC)
	f.mustRun(ctx, t, `/container/set [find where name="tikray" and comment="tikray:tikray"] interface=tikray-ctl`)
	f.mustRun(ctx, t, `/interface/veth/remove [find where name=m3-holding-veth and comment="lab:temporary-detached-port"]`)
	if stale := f.mustRun(ctx, t, `:put [/ip/arp/get [find where comment="tikray:arp-ctl"] mac-address]`); !strings.EqualFold(stale, previous) {
		t.Fatal("stale binding precondition absent")
	}
	f.requireSuccess(ctx, t)
	f.checkReady(ctx, t)
	arp := f.mustRun(ctx, t, `:put [/ip/arp/get [find where comment="tikray:arp-ctl" and address=172.30.252.2 and interface=tikray and !dynamic] mac-address]`)
	host := f.mustRun(ctx, t, `:put [/interface/bridge/host/get [find where comment="tikray:fdb-ctl" and bridge=tikray and interface=tikray-ctl and !dynamic] mac-address]`)
	if !strings.EqualFold(arp, newMAC) || !strings.EqualFold(host, newMAC) {
		t.Fatal("import did not restore both bindings")
	}
	if peer != f.mustRun(ctx, t, `:put [:tostr [/ip/arp/find where comment="tikray:arp-runner"]]`) || publicID != f.file(ctx, t, dataRoot+"/state/install.id") {
		t.Fatal("unaffected peer or installation ID replaced")
	}
	// The daemon also needs a return path when the owner restarts it after
	// emergency off. Restore the private bindings without rearming steering
	// or starting either container on behalf of the owner.
	f.mustRun(ctx, t, `/system/scheduler/disable [find where comment="tikray:watchdog-scheduler"]`)
	f.mustRun(ctx, t, `/container/stop [find where name="tikray" and comment="tikray:tikray"]`)
	if e := f.waitForContainer(ctx, "tikray", "stopped"); e != nil {
		t.Fatal("emergency fixture control did not stop")
	}
	f.mustRun(ctx, t, `/system/script/run tikray-emergency-off`)
	f.mustRun(ctx, t, `/ip/arp/set [find where comment="tikray:arp-ctl"] mac-address=`+previous)
	f.mustRun(ctx, t, `/system/script/run tikray-watchdog`)
	if !strings.EqualFold(f.mustRun(ctx, t, `:put [/ip/arp/get [find where comment="tikray:arp-ctl"] mac-address]`), newMAC) {
		t.Fatal("emergency left control without a return path to its native API")
	}
	if f.mustRun(ctx, t, `:put [:len [/container/find where name="tikray" and stopped]]`) != "1" || f.mustRun(ctx, t, `:put [:len [/system/script/find where comment="tikray:emergency-state"]]`) != "1" {
		t.Fatal("binding repair broke emergency suspension")
	}
}
