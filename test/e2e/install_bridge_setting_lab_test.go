//go:build lab

package e2e

import (
	"context"
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
