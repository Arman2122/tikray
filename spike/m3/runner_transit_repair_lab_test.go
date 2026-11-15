//go:build lab

package m3

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/routeros"
)

func TestRestrictedRunnerTransitRepair(t *testing.T) {
	r := newRig(t)
	client := &countedNative{Client: newNativeClient(t, r)}
	const menu = "/ip/firewall/filter"
	const guard = "tikray:acl-runner-transit"
	const foreign = "owner:transit-witness"
	add := func(words ...string) {
		t.Helper()
		if _, err := r.admin.RunArgsContext(r.ctx, words); err != nil {
			t.Fatal("owner fixture command failed")
		}
	}
	get := func(tag string) map[string]string {
		t.Helper()
		q, err := r.admin.RunContext(r.ctx, menu+"/print", "?comment="+tag, "=.proplist=.id,action,chain,disabled,in-interface,out-interface-list,src-address")
		if err != nil || len(q.Re) != 1 {
			t.Fatal("missing filtered native rule")
		}
		return q.Re[0].Map
	}
	add("/interface/bridge/add", "=name=tikray", "=protocol-mode=none")
	add("/interface/list/add", "=name=m3-transit-lan")
	add("/interface/list/member/add", "=list=m3-transit-lan", "=interface=ether2")
	add("/interface/veth/add", "=name=m3-transit-peer", "=address=172.30.252.2/29", "=gateway=172.30.252.1")
	add("/interface/bridge/port/add", "=bridge=tikray", "=interface=m3-transit-peer")
	add("/ip/address/add", "=interface=tikray", "=address=172.30.252.1/29")
	raw, _ := nativeProbeArchive(t, "transit-peer")
	src := filepath.Join(t.TempDir(), "transit-peer.tar")
	if os.WriteFile(src, raw, 0600) != nil || r.chr.Push(r.ctx, src, "disk1/m3-transit-peer.tar") != nil {
		t.Fatal("cannot stage live peer")
	}
	add("/container/add", "=name=m3-transit-peer", "=interface=m3-transit-peer", "=file=disk1/m3-transit-peer.tar", "=root-dir=disk1/m3-transit-peer-root")
	wait := func(query string) {
		t.Helper()
		if err := ownerWait(r.ctx, 60*time.Second, func(ctx context.Context) (bool, error) {
			s, e := r.chr.RunPrivate(ctx, query)
			return strings.TrimSpace(s) == "1", e
		}); err != nil {
			t.Fatal("live bridge fixture unavailable")
		}
	}
	wait(`:put [:len [/container/find where name=m3-transit-peer and stopped]]`)
	if _, err := r.chr.RunPrivate(r.ctx, `/container/start [find where name=m3-transit-peer]`); err != nil {
		t.Fatal("cannot start live peer")
	}
	wait(`:put [:len [/interface/bridge/find where name=tikray and running]]`)
	add(menu+"/add", "=chain=tikray-egress", "=action=drop", "=comment=tikray:egress-drop-marked", "=connection-mark=tikray-closed")
	add(menu+"/add", "=chain=forward", "=action=jump", "=jump-target=tikray-egress", "=in-interface-list=m3-transit-lan", "=out-interface=!tikray", "=comment=tikray:egress-guard")
	add(menu+"/add", "=chain=forward", "=action=accept", "=comment="+foreign)
	owner := get(foreign)[".id"]
	scope := routeros.InstallScope{Subnet: netip.MustParsePrefix("172.30.252.0/29"), LANList: "m3-transit-lan", LANs: []routeros.LAN{{Interface: "ether2", Prefix: netip.MustParsePrefix("192.168.88.0/24")}}}
	verify := func(repair bool) error { return routeros.ReconcileTransitGuard(r.ctx, client, scope, repair, false) }
	if !errors.Is(verify(false), routeros.ErrPolicyConflict) || client.writes != 0 {
		t.Fatal("missing guard admitted by read-only check")
	}
	if err := verify(true); err != nil {
		t.Fatal("restricted owner-guard creation failed", err)
	}
	first := get(guard)
	id := first[".id"]
	if first["action"] != "drop" || first["src-address"] != "!172.30.252.0/29" || first["in-interface"] != "tikray" || first["out-interface-list"] != "!m3-transit-lan" {
		t.Fatal("unexpected native guard shape")
	}
	dest := get("tikray:acl-runner-transit-dst")
	got, e := r.admin.RunContext(r.ctx, menu+"/print", "?.id="+dest[".id"], "=.proplist=dst-address-list")
	if e != nil || len(got.Re) != 1 || got.Re[0].Map["dst-address-list"] != "!tikray-transit-lans" {
		t.Fatal("unverified returned destination aperture")
	}
	lanRows := func() string {
		t.Helper()
		q, e := r.admin.RunContext(r.ctx, "/ip/firewall/address-list/print", "?list=tikray-transit-lans", "=.proplist=.id,comment,address")
		if e != nil || len(q.Re) != 1 || q.Re[0].Map["comment"] != "tikray:acl-transit-lan:192.168.88.0/24" || q.Re[0].Map["address"] != "192.168.88.0/24" {
			t.Fatal("return list differs from installed LAN scope")
		}
		return q.Re[0].Map[".id"]
	}
	firstLAN := lanRows()
	add("/ip/firewall/address-list/remove", "=.id="+firstLAN)
	if !errors.Is(verify(false), routeros.ErrPolicyConflict) || verify(true) != nil || lanRows() == "" {
		t.Fatal("missing enrolled LAN did not recover")
	}
	add(menu+"/add", "=chain=m3-owner-private", "=action=drop", "=src-address-list=tikray-transit-lans", "=comment=owner:uses-transit")
	beforeConflict := client.writes
	if !errors.Is(verify(true), routeros.ErrPolicyConflict) || beforeConflict != client.writes {
		t.Fatal("shared destination list was claimed")
	}
	add(menu+"/remove", "=.id="+get("owner:uses-transit")[".id"])
	n := client.writes
	if verify(false) != nil || verify(true) != nil || client.writes != n {
		t.Fatal("verified guard was changed on repeat")
	}
	add(menu+"/move", "=numbers="+owner, "=destination="+id)
	add(menu+"/set", "=.id="+id, "=disabled=yes")
	if !errors.Is(verify(false), routeros.ErrPolicyConflict) {
		t.Fatal("displaced disabled guard accepted")
	}
	if err := verify(true); err != nil {
		t.Fatal("verified drift repair failed", err)
	}
	if get(guard)[".id"] != id || get(foreign)[".id"] != owner || verify(false) != nil {
		t.Fatal("repair changed native identities")
	}
	add(menu+"/set", "=.id="+id, "=protocol=tcp")
	n = client.writes
	if !errors.Is(verify(true), routeros.ErrPolicyConflict) || client.writes != n {
		t.Fatal("modified owner predicate was overwritten")
	}
}
