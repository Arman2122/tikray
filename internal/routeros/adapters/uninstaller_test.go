package adapters

import (
	"bytes"
	"strings"
	"testing"
)

func TestUninstallOrderAndPaths(t *testing.T) {
	var out bytes.Buffer
	if err := BuildUninstaller(&out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if strings.Contains(s, "# @TIKRAY_") {
		t.Fatal("unexpanded uninstall source")
	}
	order := []string{"# PREFLIGHT COMPLETE", `$restoreService "restore"`, `$removeBindings "remove"`, `$drop "/interface/bridge/port"`, `$drop "/interface/veth"`, `$drop "/interface/bridge"`, `$drop "/user"`, `$drop "/user/group"`}
	for _, needle := range order {
		i := strings.Index(s, needle)
		if i < 0 {
			t.Fatalf("missing ordered teardown operation %q", needle)
		}
		s = s[i+len(needle):]
	}
}
