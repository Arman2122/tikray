//go:build lab

package m3

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/artifacts"
	routerfiles "github.com/Arman2122/tikray/routeros"
)

// Stop the read-only installer preflight at the next ownership check. There
// are no containers in this fixture, so only a sound lineage may reach it.
func TestImageInstallerValidatesExistingLineage(t *testing.T) {
	r := newRig(t)
	const data = "disk1/m3-lineage"
	id := strings.Repeat("a", 32)
	ref := func(component, digit string) artifacts.ImageRef {
		return artifacts.ImageRef{Component: component, Digest: strings.Repeat(digit, 64), ImageID: strings.Repeat(digit, 64), Chain: strings.Repeat(digit, 128), Size: 2048}
	}
	first, second := ref("tikray", "b"), ref("tikray", "c")
	bootstrap, _ := json.Marshal(artifacts.ImageBootstrap{Version: 1, Arch: "amd64", Tikray: first, Runner: ref("runner", "d")})
	fragment, err := routerfiles.Sources.ReadFile("image-bootstrap.rsc")
	if err != nil {
		t.Fatal("installer preflight missing")
	}
	pre := strings.Replace(string(fragment), "# @TIKRAY_IMAGE_CONSTANTS@", ":local bootstrap "+strconv.Quote(string(bootstrap))+"\n :local signatureFor do={:return \"fixture\"}", 1)
	const state = data + "/state/"
	run := func(t *testing.T, cmd string) string {
		t.Helper()
		s, err := r.chr.RunPrivate(r.ctx, cmd)
		if err != nil {
			t.Fatal("private fixture command failed")
		}
		return strings.TrimSpace(s)
	}
	run(t, "/file/add type=directory name="+data)
	run(t, "/file/add type=directory name="+data+"/state")
	run(t, "/file/add type=file name="+state+"install.id contents="+strconv.Quote(id))
	run(t, "/file/add type=file name="+state+"image-bootstrap.receipt contents="+strconv.Quote(string(bootstrap)))
	run(t, "/file/add type=file name="+state+"image-tikray.receipt")
	cmd := "{\n" + pre + `
	:onerror e in={ :local ok [$imageBaseline false "` + data + `" "disk1" "amd64"]; :put "unexpected" } do={
	    :local msg [:tostr $e]
	    :if ([:typeof [:find $msg "installed image receipt conflict"]]="num") do={:put "invalid"} else={
	      :if ([:typeof [:find $msg "image baseline container ownership conflict"]]="num") do={:put "passed-lineage"} else={:put "unrecognized"}
	    }
	} }`
	script := filepath.Join(t.TempDir(), "lineage.rsc")
	if err := os.WriteFile(script, []byte("/system/script/add name=m3-lineage-test source="+cmd+"\n"), 0600); err != nil || r.chr.Push(r.ctx, script, "m3-lineage.rsc") != nil {
		t.Fatal("cannot stage private preflight fixture")
	}
	run(t, "/import file-name=m3-lineage.rsc")
	for _, tc := range []struct {
		name     string
		active   artifacts.ImageRef
		previous any
		want     string
	}{
		{"original", first, nil, "passed-lineage"},
		{"missing predecessor field", first, nil, "invalid"},
		{"committed", second, first, "passed-lineage"},
		{"lost previous", second, nil, "invalid"},
		{"duplicate", second, second, "invalid"},
		{"cross-component", second, ref("runner", "d"), "invalid"},
		{"incomplete", second, map[string]any{"component": "tikray"}, "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := map[string]any{"version": 1, "installation_id": id, "active": tc.active, "previous": tc.previous}
			if tc.name == "missing predecessor field" {
				delete(row, "previous")
			}
			b, _ := json.Marshal(row)
			run(t, "/file/set [find where name="+strconv.Quote(state+"image-tikray.receipt")+"] contents="+strconv.Quote(string(b)))
			if got := run(t, "/system/script/run m3-lineage-test"); got != tc.want {
				t.Fatal("installer preflight did not enforce component lineage")
			}
		})
	}
}
