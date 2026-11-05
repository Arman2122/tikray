//go:build lab

package m3

import "testing"

func TestM3Capabilities(t *testing.T) {
	r := newRig(t)
	for _, probe := range []struct {
		name string
		run  func(*testing.T, *rig)
	}{
		{"A_archive", probeHash},
		{"B_permissions", func(t *testing.T, r *rig) {
			probeAccount(t, r)
			probePermissions(t, r)
		}},
		{"C_tags", func(t *testing.T, r *rig) {
			probeSignedCert(t, r)
			probeOwnership(t, r)
		}},
		{"D_netwatch", probeNetwatch},
	} {
		t.Run(probe.name, func(t *testing.T) { probe.run(t, r) })
	}
}
