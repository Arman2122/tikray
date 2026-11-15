//go:build lab

package m3

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/artifacts"
	routerfiles "github.com/Arman2122/tikray/routeros"
)

func nativeImageReference(t *testing.T, fragment []byte) string {
	t.Helper()
	b, err := routerfiles.Sources.ReadFile("image-reference.rsc")
	if err != nil {
		t.Fatal("native image reference check unavailable")
	}
	return strings.Replace(string(fragment), "        # @TIKRAY_IMAGE_REFERENCE@\n", string(b), 1)
}

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
	pre := strings.Replace(nativeImageReference(t, fragment), "# @TIKRAY_IMAGE_CONSTANTS@", ":local bootstrap "+strconv.Quote(string(bootstrap))+"\n :local signatureFor do={:return \"fixture\"}", 1)
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

// A keep must retire only this installation's public handoff files. Rows
// anywhere else on the disk may have similar names and must survive.
func TestImageUninstallRetiresOwnedReceipts(t *testing.T) {
	r := newRig(t)
	const base = "disk1/tikray-lineage"
	const data = base + "/data"
	const state = data + "/state"
	id := strings.Repeat("a", 32)
	run := func(cmd string) string {
		t.Helper()
		s, err := r.chr.RunPrivate(r.ctx, cmd)
		if err != nil {
			t.Fatal("cannot run private removal fixture")
		}
		return strings.TrimSpace(s)
	}
	for _, dir := range []string{base, data, state} {
		run("/file/add type=directory name=" + dir)
	}
	write := func(name, body string) {
		t.Helper()
		run("/file/add type=file name=" + strconv.Quote(name) + " contents=" + strconv.Quote(body))
	}
	write(state+"/install.id", id)
	const outside = "disk1/m3-unowned-image.receipt"
	write(outside, "owner-file")
	ref := func(component, digit string) artifacts.ImageRef {
		return artifacts.ImageRef{Component: component, Digest: strings.Repeat(digit, 64), ImageID: strings.Repeat(digit, 64), Chain: strings.Repeat(digit, 128), Size: 2048}
	}
	curve := elliptic.P256()
	der, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: curve, X: curve.Params().Gx, Y: curve.Params().Gy})
	if err != nil {
		t.Fatal("fixture public key unavailable")
	}
	boot := artifacts.ImageBootstrap{Version: 1, Arch: "amd64", Publisher: base64.StdEncoding.EncodeToString(der), Tikray: ref("tikray", "b"), Runner: ref("runner", "c")}
	b, _ := json.Marshal(boot)
	write(state+"/image-bootstrap.receipt", string(b))
	record := func(active artifacts.ImageRef, identity string) string {
		b, _ := json.Marshal(map[string]any{"version": 1, "installation_id": identity, "active": active, "previous": nil})
		return string(b)
	}
	write(state+"/image-tikray.receipt", record(boot.Tikray, id))
	const runner = state + "/image-runner.receipt"
	write(runner, record(boot.Runner, strings.Repeat("d", 32)))
	fragment, err := routerfiles.Sources.ReadFile("uninstall-data.rsc")
	if err != nil {
		t.Fatal("missing owner data cleanup")
	}
	script := `/system/script/add name=m3-check-image-keep source={
	:global m3ImageKeepMode
	` + nativeImageReference(t, fragment) + `
	:local guard do={
	    :global m3ImageKeepChange
	    :if ($m3ImageKeepChange="once") do={:set m3ImageKeepChange ""; /file/set [find where name="` + runner + `"] contents="owner-changed"}
	    :return true
	}
	:onerror e in={:local ok [$cleanData $m3ImageKeepMode "keep" "` + data + `" "` + id + `" "files" "172.31.255.0/29" $guard ""]; :if ($ok) do={:put "accepted"}} do={:put "refused"}
}
`
	file := filepath.Join(t.TempDir(), "image-keep.rsc")
	if os.WriteFile(file, []byte(script), 0600) != nil || r.chr.Push(r.ctx, file, "m3-keep.rsc") != nil {
		t.Fatal("cannot stage removal test")
	}
	run("/import file-name=m3-keep.rsc")
	try := func(mode string) string {
		return run(`:global m3ImageKeepMode "` + mode + `"; /system/script/run m3-check-image-keep`)
	}
	if try("apply") != "refused" || run(":put [:len [/file/find where name="+state+"/image-bootstrap.receipt]]") != "1" {
		t.Fatal("foreign component receipt allowed teardown")
	}
	run("/file/set [find where name=" + strconv.Quote(runner) + "] contents=" + strconv.Quote(record(boot.Runner, id)))
	setFile := func(path, value string) {
		run("/file/set [find where name=" + strconv.Quote(path) + "] contents=" + strconv.Quote(value))
	}
	bootPath := state + "/image-bootstrap.receipt"
	for _, tc := range []struct{ path, good, bad string }{
		{runner, record(boot.Runner, id), `{"version":1,"installation_id":"` + id + `","active":{"component":"runner"}}`},
		{bootPath, string(b), `{"version":1,"tikray":{"component":"tikray"},"runner":{"component":"runner"}}`},
		{runner, record(boot.Runner, id), record(ref("runner", "e"), id)},
	} {
		setFile(tc.path, tc.bad)
		if try("inspect") != "refused" || run(":put [/file/get [find where name="+strconv.Quote(tc.path)+"] contents]") != tc.bad {
			t.Error("unverified image receipt was accepted or changed")
		}
		setFile(tc.path, tc.good)
	}
	if try("inspect") != "accepted" {
		t.Fatal("valid signed bootstrap and component receipts were refused")
	}
	run(`:global m3ImageKeepChange "once"`)
	if try("apply") != "refused" || run(":put [/file/get [find where name="+strconv.Quote(runner)+"] contents]") != "owner-changed" {
		t.Fatal("keep removed a changed file after preflight")
	}
	if run(":put [:len [/file/find where name="+strconv.Quote(bootPath)+"]]") != "1" {
		t.Fatal("keep lost the bootstrap needed for resumption")
	}
	// Model loss of power after retiring the other side but before
	// retiring this restored, verified record and its bootstrap anchor.
	setFile(runner, record(boot.Runner, id))
	run(`:foreach id in=[/file/find where name="` + state + `/image-tikray.receipt"] do={/file/remove $id}`)
	if try("inspect") != "accepted" || try("apply") != "accepted" || try("apply") != "accepted" {
		t.Fatal("keep refused valid image receipts or could not resume")
	}
	for _, side := range []string{"bootstrap", "runner", "tikray"} {
		if run(":put [:len [/file/find where name="+state+"/image-"+side+".receipt]]") != "0" {
			t.Fatal("verified image receipt was not retired")
		}
	}
	if run(":put [/file/get [find where name="+outside+"] contents]") != "owner-file" {
		t.Fatal("changed an unrelated receipt")
	}
}
