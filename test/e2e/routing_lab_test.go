//go:build lab

package e2e

import (
	"context"
	"testing"
	"time"
)

// TestM3Routing drives the installed service through its LAN API. Construct
// the fixture lazily so a filtered case has exactly the full suite's baseline.
func TestM3Routing(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 130*time.Minute)
	defer cancel()
	l := &Lab{Version: env("TIKRAY_LAB_CHANNEL", "stable"), Arch: labArch()}
	check := l.recordM3Checks(t, "m3-routing")
	var f *routingLab
	attempted := false
	for _, tc := range []struct {
		id  string
		run func(*routingLab, context.Context, *testing.T)
	}{
		{"policy_paths", (*routingLab).policyPaths},
		{"source_and_fasttrack", (*routingLab).sourceAndFastTrack},
		{"policy_mid_connection", (*routingLab).policyMidConnection},
		{"failover", (*routingLab).failover},
		{"dns_paths", (*routingLab).dnsPaths},
		{"ipv6_guard", (*routingLab).ipv6Guard},
		{"quic_sniff", (*routingLab).quicSniff},
		{"drift_repair", (*routingLab).checkDriftRepair},
		{"emergency_off", (*routingLab).checkEmergencyOff},
	} {
		check(tc.id, func(st *testing.T) {
			if f == nil {
				if attempted {
					st.Fatal("routing fixture failed to initialize")
				}
				attempted = true
				f = deployRouting(ctx, st, t)
				l.Version = f.Version
			}
			f.setClientPolicy(ctx, st, fullOpen)
			tc.run(f, ctx, st)
		})
	}
}
