//go:build lab

package e2e

import (
	"context"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/routeros/adapters"
)

// Start from an actual older release, then import the new packager for that
// same signed image pair. The old script's exact bytes are publisher inputs.
func TestM3ImageBootstrapMigration(t *testing.T) {
	old := os.Getenv("TIKRAY_LAB_PRIOR_INSTALLER")
	if old == "" {
		t.Skip("supply the historical matching signed installer")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Minute)
	defer cancel()
	f := DeployM3(ctx, t)
	newInstaller := f.installer
	f.installer = old
	f.stage(ctx, t, true)
	f.requireSuccess(ctx, t)
	f.checkReady(ctx, t)
	identity := f.checkHealthIdentity(ctx, t)
	original := f.stability(ctx, t)
	const proof = "disk1/tikray/data/state/image-bootstrap.receipt"
	if exists, e := f.exists(ctx, proof); e != nil || exists {
		t.Fatal("old installer already had runtime image trust")
	}
	oldID := f.mustRun(ctx, t, `:put [:tostr [/system/script/find where name=tikray-watchdog and comment="tikray:watchdog-script"]]`)
	oldSched := f.mustRun(ctx, t, `:put [:tostr [/system/scheduler/find where name=tikray-watchdog and comment="tikray:watchdog-scheduler"]]`)
	if oldID == "" || oldSched == "" {
		t.Fatal("historical watchdog baseline absent")
	}
	f.installer = newInstaller
	if f.CHR.Push(ctx, newInstaller, "m3-lab-install.rsc") != nil {
		t.Fatal("cannot deliver updated packager")
	}
	f.mustRun(ctx, t, `/system/script/add name=m3-image-migration-save source=[/system/script/get [find where name=tikray-watchdog] source] comment="fixture:migration"; /system/script/set [find where name=tikray-watchdog] source=":return false"`)
	f.requireRefusal(ctx, t, "tikray: watchdog script has changed")
	if exists, e := f.exists(ctx, proof); e != nil || exists {
		t.Fatal("tampered legacy body authorized new image state")
	}
	f.mustRun(ctx, t, `/system/script/set [find where name=tikray-watchdog] source=[/system/script/get [find where name=m3-image-migration-save] source]; /system/script/remove [find where name=m3-image-migration-save]`)
	f.requireSuccess(ctx, t)
	const findHelper = `[/system/script/find where name="tikray-watchdog-traffic" and comment="tikray:watchdog-traffic" and !dont-require-permissions]`
	helperID := f.mustRun(ctx, t, `:put [:tostr `+findHelper+`]`)
	if !regexp.MustCompile(`^\*[0-9A-Fa-f]+$`).MatchString(helperID) {
		t.Fatal("missing new traffic helper identity")
	}
	rows := append(strings.Split(original[0], "\n"), "/system/script|"+helperID+"|tikray:watchdog-traffic")
	udpID := f.mustRun(ctx, t, `:put [:tostr [/system/script/find where name="tikray-udp-native" and comment="tikray:udp-native-v1" and source="" and !dont-require-permissions]]`)
	if !regexp.MustCompile(`^\*[0-9A-Fa-f]+$`).MatchString(udpID) {
		t.Fatal("missing exact UDP native receipt")
	}
	rows = append(rows, "/system/script|"+udpID+"|tikray:udp-native-v1")
	// The historical installer predates the pre-PID1 return guard. Permit
	// its exact newly enrolled filter rows while every old identity survives.
	for _, role := range []string{"acl-runner-transit", "acl-runner-transit-dst", "acl-transit-deny", "acl-transit-deny-backup", "acl-transit-lan:192.168.88.0/24"} {
		tag := "tikray:" + role
		id := f.mustRun(ctx, t, `:put [:tostr [/ip/firewall/filter/find where comment="`+tag+`"]]`)
		if !regexp.MustCompile(`^\*[0-9A-Fa-f]+$`).MatchString(id) {
			t.Fatal("missing unique migrated pre-start guard", role)
		}
		actual := "/ip/firewall/filter|" + id + "|" + tag
		// This test deliberately uses the same signed binaries on both sides
		// of the native migration. The control process can already repair
		// the return path under the old installer. Preserve that row's ID.
		found := false
		for _, prior := range strings.Split(original[0], "\n") {
			if strings.HasPrefix(prior, "/ip/firewall/filter|") && strings.HasSuffix(prior, "|"+tag) {
				if found || prior != actual {
					t.Fatal("migration changed an existing return guard", role)
				}
				found = true
			}
		}
		if !found {
			rows = append(rows, actual)
		}
	}
	slices.Sort(rows)
	original[0] = strings.Join(rows, "\n")
	f.requireStable(ctx, t, original, "image baseline migration")
	_, helper, e := adapters.WatchdogScripts()
	if e != nil {
		t.Fatal("cannot assemble expected installer helper")
	}
	sum := fmt.Sprintf("%x", sha512.Sum512([]byte(strings.ReplaceAll(strings.TrimRight(helper, "\r\n"), "\n", "\r\n"))))
	helperProof := `{:local id [:pick ` + findHelper + ` 0]; :local readOnly false; :local extras false; :foreach p in=[/system/script/get $id policy] do={:if ([:pick $p 0 1]!="!") do={:if ($p="read") do={:set readOnly true} else={:set extras true}}}; :local text [/system/script/get $id source]; :local n [:len $text]; :while (($n>0) and (([:pick $text ($n-1) $n]="\r") or ([:pick $text ($n-1) $n]="\n"))) do={:set n ($n-1)}; :local h [:convert [:convert [:pick $text 0 $n] from=raw transform=sha512 to=hex] transform=lc]; :put (($id=[:toid "` + helperID + `"]) and $readOnly and (!$extras) and ($h="` + sum + `")) }`
	if f.mustRun(ctx, t, helperProof) != "true" {
		t.Fatal("migrated helper source or rights differ from the installer")
	}
	f.requireSuccess(ctx, t)
	if f.mustRun(ctx, t, helperProof) != "true" {
		t.Fatal("second import changed installed helper")
	}
	f.requireStable(ctx, t, original, "repeat image baseline migration")
	f.mustRun(ctx, t, `/system/script/add name=m3-traffic-save source=[/system/script/get [find where name="tikray-watchdog-traffic"] source] policy=read; /system/script/set [find where name="tikray-watchdog-traffic"] source=":return false"`)
	f.requireRefusal(ctx, t, "tikray: watchdog helper has changed")
	f.requireStable(ctx, t, original, "changed helper refusal")
	f.mustRun(ctx, t, `/system/script/set [find where name="tikray-watchdog-traffic"] source=[/system/script/get [find where name=m3-traffic-save] source]; /system/script/remove [find where name=m3-traffic-save]`)
	var boot artifacts.ImageBootstrap
	if json.Unmarshal([]byte(f.file(ctx, t, proof)), &boot) != nil || !boot.Tikray.Valid() || !boot.Runner.Valid() {
		t.Fatal("migration did not publish valid signed baseline")
	}
	if oldID != f.mustRun(ctx, t, `:put [:tostr [/system/script/find where name=tikray-watchdog and comment="tikray:watchdog-script"]]`) || oldSched != f.mustRun(ctx, t, `:put [:tostr [/system/scheduler/find where name=tikray-watchdog and comment="tikray:watchdog-scheduler"]]`) {
		t.Fatal("migration recreated owner-visible script or scheduler")
	}
	for _, name := range []string{"tikray", "runner"} {
		var r struct {
			InstallationID string              `json:"installation_id"`
			Active         artifacts.ImageRef  `json:"active"`
			Previous       *artifacts.ImageRef `json:"previous"`
		}
		if json.Unmarshal([]byte(f.file(ctx, t, dataRoot+"/state/image-"+name+".receipt")), &r) != nil || r.InstallationID != identity || r.Active.Component != name || r.Previous != nil || !r.Active.Valid() {
			t.Fatal("migrated rollback receipt is unverified")
		}
	}
	rights := f.mustRun(ctx, t, `:put [:tostr [/system/script/get [find name=tikray-watchdog] policy]]`)
	if !strings.Contains(rights, "ftp") || strings.Contains(rights, "!ftp") {
		t.Fatal("watchdog did not gain the tested archive-read right")
	}
	f.mustRun(ctx, t, `/file/remove [find where name="disk1/tikray/data/state/image-runner.receipt"]`)
	f.requireRefusal(ctx, t, "tikray: installed image receipt missing")
	if exists, e := f.exists(ctx, dataRoot+"/state/image-runner.receipt"); e != nil || exists {
		t.Fatal("lost receipt was automatically recreated")
	}
	f.ownerLogin(ctx, t)
}

// Both installers refer to the same archived signed 8b91d54 image pair and
// publisher. No image or policy change may be hidden inside native migration.
func TestM3NativeUDPUpgrade(t *testing.T) {
	prior := os.Getenv("TIKRAY_LAB_PRIOR_UDP_INSTALLER")
	if prior == "" {
		t.Skip("supply the verified Task 6b installer and its exact archives")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Minute)
	defer cancel()
	f := DeployM3(ctx, t)
	current := f.installer
	f.installer = prior
	f.stage(ctx, t, true)
	f.requireSuccess(ctx, t)
	f.checkReady(ctx, t)
	before := f.stability(ctx, t)
	const receipt = `[/system/script/find where name="tikray-udp-native" or comment="tikray:udp-native-v1"]`
	if f.mustRun(ctx, t, `:put [:len `+receipt+`]`) != "0" {
		t.Fatal("historical installer already authorized the new UDP rules")
	}
	f.installer = current
	if f.CHR.Push(ctx, current, "m3-lab-install.rsc") != nil {
		t.Fatal("could not deliver the new native source for unchanged signed images")
	}
	f.mustRun(ctx, t, `/system/script/add name=lab-udp-save source=[/system/script/get [find where name="tikray-emergency-off"] source] policy=read; /system/script/set [find where name="tikray-emergency-off"] source=":return false"`)
	f.requireRefusal(ctx, t, "tikray: inspect changed emergency script before installing")
	if f.mustRun(ctx, t, `:put [:len `+receipt+`]`) != "0" {
		t.Fatal("unverified emergency body authorized the new UDP rules")
	}
	f.mustRun(ctx, t, `/system/script/set [find where name="tikray-emergency-off"] source=[/system/script/get [find where name="lab-udp-save"] source]; /system/script/remove [find where name="lab-udp-save"]`)
	f.requireStable(ctx, t, before, "owner-changed emergency refusal")
	f.requireSuccess(ctx, t)
	id := f.mustRun(ctx, t, `:put [:tostr `+receipt+`]`)
	if !regexp.MustCompile(`^\*[0-9A-Fa-f]+$`).MatchString(id) {
		t.Fatal("verified native migration did not publish its receipt")
	}
	rows := append(strings.Split(before[0], "\n"), "/system/script|"+id+"|tikray:udp-native-v1")
	slices.Sort(rows)
	before[0] = strings.Join(rows, "\n")
	f.requireStable(ctx, t, before, "native upgrade with the original signed images")
	f.requireSuccess(ctx, t)
	f.requireStable(ctx, t, before, "repeat install after native upgrade")
	f.ownerLogin(ctx, t)
}
