//go:build lab

package m3

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/test/lab"
)

func TestNativeImagePowerCutsDuringBothExtractions(t *testing.T) {
	f := newNativeImageCase(t)
	root := strings.TrimSuffix(f.data, "/data") + "/containers/control"
	oldRaw, oldID := nativeProbeArchiveWithFiles(t, "cut-old", 8192)
	nextRaw, newID := nativeProbeArchiveWithFiles(t, "cut-new", 8192)
	old, next := f.buildArchive(oldRaw, oldID), f.buildArchive(nextRaw, newID)
	f.req(strings.Repeat("c", 32), f.first, old)
	if e := f.tick(); e != "" {
		t.Fatal("could not establish native baseline", e)
	}
	if e := f.tick(); e != "" || !f.isLive(old) {
		t.Fatal("native baseline not committed", e)
	}
	// Move only the verified disposable baseline row. An unrelated directory at
	// the canonical path then forces both imports to use their checked alternate.
	f.run(`/container/stop [find where name=tikray and comment="tikray:tikray"]`)
	until := func(wait time.Duration, command, want string) bool {
		t.Helper()
		return ownerWait(f.r.ctx, wait, func(ctx context.Context) (bool, error) {
			s, e := f.r.chr.RunPrivate(ctx, command)
			return strings.TrimSpace(s) == want, e
		}) == nil
	}
	if !until(time.Minute, `:put [:len [/container/find where name=tikray and comment="tikray:tikray" and stopped]]`, "1") {
		t.Fatal("disposable baseline did not stop")
	}
	f.run(`/container/remove [find where name=tikray and comment="tikray:tikray" and stopped]`)
	if !until(time.Minute, `:put [:len [/file/find where name="`+root+`"]]`, "0") {
		t.Fatal("disposable extraction root was not retired")
	}
	f.run(`/file/add name="` + root + `" type=directory; /file/add name="` + root + `/unrelated-owner-file" type=file contents="owner witness"`)
	f.run(`/container/add name=tikray comment="tikray:tikray" file="` + f.data + "/images/tikray-" + old["digest"].(string) + `.tar" root-dir="` + root + "-image-" + oldID + `" mountlists=tikray envlists=tikray interface=tikray-ctl dns=172.27.248.1 start-on-boot=yes restart-policy=on-failure memory-high=134217728 memory-max=201326592 logging=no`)
	if !until(2*time.Minute, `:put [:len [/container/find where name=tikray and comment="tikray:tikray" and stopped]]`, "1") {
		t.Fatal("alternate baseline extraction failed")
	}
	f.run(`/container/unset [find where name=tikray] cmd; /container/start [find where name=tikray and comment="tikray:tikray"]`)
	if !f.isLive(old) {
		t.Fatal("alternate original not healthy")
	}
	certBlock, _ := pem.Decode([]byte(f.run(`:put [/file/get m3-cap-public.crt contents]`)))
	if certBlock == nil {
		t.Fatal("audit pin unavailable")
	}
	cert, e := x509.ParseCertificate(certBlock.Bytes)
	if e != nil {
		t.Fatal("audit pin invalid")
	}
	pw, e := os.ReadFile(filepath.Join(lab.CacheDir(), "ready", f.r.version, "x86_64", "password"))
	if e != nil {
		t.Fatal("private ready credential unavailable")
	}
	f.run(`/system/script/add name=m3-stall-health policy=read source=""`)
	const operation = "dddddddddddddddddddddddddddddddd"
	f.req(operation, old, next)
	// Establish that the unrelated directory and running original were durable
	// before a destructive update. SSH may return before disk1 is remounted.
	witness := `{:local ok false; :do {:local id [/file/find where name="` + root + `/unrelated-owner-file"];:if ([:len $id]=1) do={:set ok ([/file/get [:pick $id 0] contents]="owner witness")}} on-error={};:put $ok}`
	if !until(time.Minute, witness, "true") || f.r.chr.Reboot(f.r.ctx) != nil {
		t.Fatal("unrelated directory did not reach the pre-update durability boundary")
	}
	f.r.reopenAudit(t, string(pw), cert)
	if !until(time.Minute, witness, "true") || !f.isLive(old) {
		t.Fatal("original archive and owner directory did not survive the clean pre-update reboot")
	}
	// SFTP has no fsync request. A missing checkpoint would test a torn
	// fixture upload rather than the real service's fsynced request.
	var request struct {
		Nonce               string
		Previous, Candidate struct {
			ImageID string `json:"image_id"`
		}
	}
	if json.Unmarshal([]byte(f.run(`:put [/file/get "`+f.data+`/state/image-update.request" contents]`)), &request) != nil || request.Nonce != operation || request.Previous.ImageID != oldID || request.Candidate.ImageID != newID {
		t.Fatal("synthetic release request did not survive its durability checkpoint")
	}
	// The scheduler runs the production image program with its normal permissions.
	// The fixture supplies the installation path and control health answer.
	f.run(`/system/script/add name=m3-cut-status source="" policy=read comment="waiting"`)
	// Record only fixed categories. An error value can include peer text.
	source := `{:if ([:len [/system/script/job/find where script="m3-cut-engine"]]!=1) do={:return true}; :local result "finished"; :onerror msg in={/import file-name=m3-watch-images.rsc} do={:set result "refused"; :foreach key in={"invalid json";"unverified container configuration";"private mount changed";"archive content changed";"foreign recovery root";"container content differs";"shared private mount";"not enough permissions";"expected end";"unknown native policy"} do={:if ([:typeof [:find [:tostr $msg] $key]]="num") do={:set result $key}}}; /system/script/set [find name=m3-cut-status] comment=$result}`
	body := f.run(`:put [/file/get m3-watch-images.rsc contents]`)
	if !strings.Contains(body, ":local wdImage do=") || !strings.Contains(body, "native-image-ok") {
		t.Fatal("production engine fixture source unavailable")
	}
	source = strings.Replace(source, "/import file-name=m3-watch-images.rsc", body, 1)
	if _, err := f.r.admin.RunContext(f.r.ctx, "/system/script/add", "=name=m3-cut-engine", "=policy=read,write,test,ftp", "=source="+source); err != nil {
		t.Fatal("could not store scheduled cut fixture")
	}
	f.run(`/system/scheduler/add name=m3-cut-scheduler on-event=m3-cut-engine policy=read,write,test,ftp interval=8s start-time=startup`)
	for _, cut := range []struct {
		direction, id string
		within        time.Duration
	}{{"new", newID, 3 * time.Minute}, {"old", oldID, 10 * time.Minute}} {
		tag := "tikray:image-import:" + operation + ":" + cut.direction
		path := root + "-image-" + cut.id
		// A blank native ID alone can also mean a stale failure. Require
		// this import's marker, profile, new root, and an extraction-in-progress.
		command := `{:local r [/container/find where name=tikray and comment="` + tag + `" and interface=tikray-ctl]; :local seen false; :if ([:len $r]=1) do={:local q [:pick $r 0]; :if (([:len [:tostr [/container/get $q image-id]]]=0) and ([:len [/file/find where name="` + path + `"]]=1) and ([:len [/container/find where .id=$q and running]]=0) and ([:len [/container/find where .id=$q and stopped]]=0)) do={:set seen true}};:put $seen}`
		probe, stop := context.WithTimeout(f.r.ctx, cut.within)
		found := false
		for probe.Err() == nil {
			out, err := f.r.chr.RunPrivate(probe, command)
			if err == nil && strings.TrimSpace(out) == "true" {
				found = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		stop()
		if !found {
			status := f.run(`:put [/system/script/get [find name=m3-cut-status] comment]`)
			safe := "unknown"
			for _, v := range []string{"waiting", "finished", "refused", "invalid json", "unverified container configuration", "private mount changed", "archive content changed", "foreign recovery root", "container content differs", "shared private mount", "not enough permissions", "expected end", "unknown native policy"} {
				if status == v {
					safe = v
				}
			}
			phase := f.run(`{:local j [/system/script/find where name=tikray-image-transition];:if ([:len $j]=1) do={:local tag [/system/script/get [:pick $j 0] comment];:local s [:deserialize from=json options=json.no-string-conversion value=[:pick $tag [:len "tikray:image-transition "] 4096]];:put ($s->"phase")}}`)
			stage := "absent"
			for _, v := range []string{"replace", "verify", "commit", "committed", "restore", "recover", "reverted"} {
				if phase == v {
					stage = v
				}
			}
			t.Fatalf("did not observe scheduled %s extraction before power cut (scheduler %s, phase %s)", cut.direction, safe, stage)
		}
		if f.r.chr.PowerCycle(f.r.ctx) != nil {
			t.Fatalf("physical CHR power cut at %s extraction failed", cut.direction)
		}
		f.r.reopenAudit(t, string(pw), cert)
		if !until(time.Minute, witness, "true") {
			t.Fatal("unrelated directory changed across interruption")
		}
		t.Logf("observed and interrupted %s native extraction on %s x86_64", cut.direction, f.r.version)
	}
	f.run(`/system/script/remove [find where name=m3-stall-health]`)
	if !until(6*time.Minute, `:put [:len [/file/find where name="`+f.data+`/state/image-update.request"]]`, "0") || !f.isLive(old) {
		t.Fatal("scheduled watchdog failed to restore the verified prior archive after both interruptions")
	}
	if !until(20*time.Second, `:put [:len [/system/script/find where name=tikray-image-transition]]`, "0") || !until(time.Minute, witness, "true") {
		t.Fatal("restoration did not retire its native marker or preserve the unrelated root")
	}
	var receipt struct {
		Active struct {
			ImageID string `json:"image_id"`
		}
	}
	if json.Unmarshal([]byte(f.run(`:put [/file/get "`+f.data+`/state/image-tikray.receipt" contents]`)), &receipt) != nil || receipt.Active.ImageID != oldID {
		t.Fatal("committed receipt did not return to the previous archive")
	}
}
