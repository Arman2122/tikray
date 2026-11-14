//go:build lab

package e2e

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

// An owner may already filter bridged frames. A fresh runner attestation
// must still complete while that global firewall policy is in effect.
func checkBridgeIPFirewall(ctx context.Context, t *testing.T, f *installLab) {
	t.Helper()
	const read = `:if ([/interface/bridge/settings/get use-ip-firewall]) do={:put "yes"} else={:put "no"}`
	before := f.mustRun(ctx, t, read)
	if before != "yes" && before != "no" {
		t.Fatal("original bridge filtering state unavailable")
	}
	f.mustRun(ctx, t, "/interface/bridge/settings/set use-ip-firewall=yes")
	defer f.mustRun(ctx, t, "/interface/bridge/settings/set use-ip-firewall="+before)
	if _, err := f.runInstaller(ctx); err != nil {
		t.Fatal("control-to-runner verification failed with owner bridge filtering enabled", err)
	}
	now := f.mustRun(ctx, t, read)
	if now != "yes" {
		t.Fatal("installer changed global bridge filtering")
	}
}

// A different list name cannot hide an owner mount of the future private
// control volume. Prove the independently named container actually consumes
// that list before importing, and that refusal preserves the very same rows.
func checkInstallForeignResources(ctx context.Context, t *testing.T, f *installLab) {
	t.Helper()
	const env = `[find where list="tikray" and key="OWNER_PROBE" and comment="owner:scope-env"]`
	f.mustRun(ctx, t, `/container/envs/add list=tikray key=OWNER_PROBE value=fixture comment=owner:scope-env`)
	original := f.mustRun(ctx, t, `:put [/container/envs/find where key="OWNER_PROBE" and comment="owner:scope-env"]`)
	f.requireRefusal(ctx, t, "tikray: object conflict; unexpected container environment")
	if original == "" || original != f.mustRun(ctx, t, `:put [/container/envs/find where key="OWNER_PROBE" and comment="owner:scope-env"]`) || !f.installClean(ctx) {
		t.Fatal("reserved environment collision touched the owner")
	}
	f.mustRun(ctx, t, `/container/envs/remove `+env)
	f.mustRun(ctx, t, `/interface/veth/add name=owner-scope address=172.28.150.2/29 gateway=172.28.150.1 comment=owner:scope-veth`)
	f.mustRun(ctx, t, `/container/mounts/add list=owner-storage src=disk1/tikray/data dst=/owner-volume mode=ro comment=owner:scope-mount`)
	f.mustRun(ctx, t, fmt.Sprintf(`/container/add name=owner-scope file="disk1/tikray/images/%s" root-dir=disk1/owner-scope interface=owner-scope dns=192.168.88.1 mountlists=owner-storage start-on-boot=no comment=owner:scope-container`, filepath.Base(f.controlTar)))
	if err := waitContainer(ctx, f.CHR, "owner-scope", "stopped"); err != nil {
		t.Fatal("independent owner container was not established")
	}
	const identity = `:put [/container/find where name="owner-scope" and comment="owner:scope-container"]`
	original = f.mustRun(ctx, t, identity)
	if original == "" || f.mustRun(ctx, t, `:put [:tostr [/container/get [find where name="owner-scope"] mountlists]]`) != "owner-storage" {
		t.Fatal("owner list was not attached")
	}
	f.requireRefusal(ctx, t, "tikray: shared_reference_refuses; another container can access private installation files")
	if f.mustRun(ctx, t, identity) != original || !f.installClean(ctx) {
		t.Fatal("foreign volume refusal changed an owner object")
	}
	f.mustRun(ctx, t, `/container/remove [find where name="owner-scope" and comment="owner:scope-container"]`)
	f.mustRun(ctx, t, `/container/mounts/remove [find where list="owner-storage" and comment="owner:scope-mount"]`)
	f.mustRun(ctx, t, `/interface/veth/remove [find where name="owner-scope" and comment="owner:scope-veth"]`)
}
