//go:build lab

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
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
	const proof = "disk1/tikray/data/state/image-bootstrap.json"
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
	f.requireStable(ctx, t, original, "image baseline migration")
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
		if json.Unmarshal([]byte(f.file(ctx, t, dataRoot+"/state/image-"+name+".json")), &r) != nil || r.InstallationID != identity || r.Active.Component != name || r.Previous != nil || !r.Active.Valid() {
			t.Fatal("migrated rollback receipt is unverified")
		}
	}
	rights := f.mustRun(ctx, t, `:put [:tostr [/system/script/get [find name=tikray-watchdog] policy]]`)
	if !strings.Contains(rights, "ftp") || strings.Contains(rights, "!ftp") {
		t.Fatal("watchdog did not gain the tested archive-read right")
	}
	f.mustRun(ctx, t, `/file/remove [find where name="disk1/tikray/data/state/image-runner.json"]`)
	f.requireRefusal(ctx, t, "tikray: installed image receipt missing")
	if exists, e := f.exists(ctx, dataRoot+"/state/image-runner.json"); e != nil || exists {
		t.Fatal("lost receipt was automatically recreated")
	}
	f.ownerLogin(ctx, t)
}
