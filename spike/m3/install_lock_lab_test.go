//go:build lab

package m3

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestM3InstallExclusiveClaim(t *testing.T) {
	r := newRig(t)
	body, e := os.ReadFile(filepath.Join("..", "..", "routeros", "install-lock.rsc"))
	if e != nil {
		t.Fatal("missing claim implementation")
	}
	program := "{\n" + string(body) + `
    :local first [$acquireInstall]
    $requireInstall $first
    :local refused false
    :onerror e in={ :local other [$acquireInstall] } do={ :set refused true }
    :if (!$refused) do={ :error "two writers entered the installer" }
    $requireInstall $first
    /system/script/job/remove ($first->"job")
    :set refused false
    :onerror e in={ $requireInstall $first } do={ :set refused true }
    :if (!$refused) do={ :error "an expired writer continued" }
    :local later [$acquireInstall]
    $releaseInstall $first
    $requireInstall $later
    $releaseInstall $later
    :if ([:len [/system/script/find where name="tikray-install-lock"]] != 0) do={ :error "claim was not released" }
    :put "exclusive-ok"
}
`
	path := filepath.Join(t.TempDir(), "claim.rsc")
	if os.WriteFile(path, []byte(program), 0600) != nil || r.chr.Push(r.ctx, path, "claim.rsc") != nil {
		t.Fatal("could not stage claim fixture")
	}
	out, e := r.chr.RunPrivate(r.ctx, `:onerror e in={ /import file-name=claim.rsc } do={ :put "claim-check-failed" }`)
	if e != nil || !strings.Contains(out, "exclusive-ok") {
		t.Fatal("could not verify single writer, expired writer or competing cleanup")
	}
}
