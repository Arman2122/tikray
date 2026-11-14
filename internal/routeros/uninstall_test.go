package routeros

import (
	"context"
	"testing"
)

func TestUninstallMarkerFencesPolicyWrites(t *testing.T) {
	p := &observationPeer{generation: 1, rows: map[string][]Row{"/system/script": {{".id": "*1", "name": "tikray-uninstall-state", "comment": "tikray:uninstall-state {}"}}}}
	_, busy, err := EmergencyState(context.Background(), p, 1)
	if err != nil || !busy {
		t.Fatal("uninstall did not fence a pending policy change")
	}
}
