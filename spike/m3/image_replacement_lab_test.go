//go:build lab

package m3

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/routeros/adapters"
	routerfiles "github.com/Arman2122/tikray/routeros"
	"github.com/Arman2122/tikray/test/lab"
)

// Exercise the commands using the same permissions the one-minute job has,
// including native extraction and the identity of the re-created root.
func TestWatchdogImageImportCapability(t *testing.T) {
	r := newRig(t)
	run := func(command string) string {
		t.Helper()
		out, err := r.chr.RunPrivate(r.ctx, command)
		if err != nil {
			t.Fatal("image capability fixture operation refused")
		}
		return strings.TrimSpace(out)
	}
	img, err := containerFixture(t.TempDir())
	if err != nil || r.chr.Push(r.ctx, img, "disk1/m3-image.tar") != nil {
		t.Fatal("could not stage native image fixture")
	}
	run(`/interface/veth/add name=m3-image-veth address=172.26.252.2/29 gateway=172.26.252.1 comment=m3-image-test`)
	run(`/system/script/add name=m3-image-result source="" policy=read comment=idle`)
	body := `{
      /system/scheduler/disable [find where name="m3-image-sched"]; :local result [/system/script/find where name="m3-image-result"]; :local phase "initial"
      :onerror err in={
         :set phase "read-chunk"; :local block ([/file/read file="disk1/m3-image.tar" offset=0 chunk-size=2048 as-value]->"data")
         :set phase "hash"; :if ([:len [:convert $block from=raw transform=sha512 to=hex]]!=128) do={ :error "hash" }
         :set phase "add"; /container/add file="disk1/m3-image.tar" name=m3-image-row root-dir="disk1/m3-image-root" interface=m3-image-veth dns=172.26.252.1 memory-high=67108864 memory-max=134217728 start-on-boot=no restart-policy=on-failure logging=no comment=m3-image-test
         :set phase "extract"; :local n 0; :while (([:len [/container/find where name="m3-image-row" and stopped]]!=1) and ($n<120)) do={ :delay 500ms; :set n ($n+1) }
         :if ($n=120) do={ :error "timeout" }
         :local id [:pick [/container/find where name="m3-image-row" and stopped] 0]
         :local image [/container/get $id]
         :set phase "unset"; /container/unset $id cmd
         :set phase "remove"; /container/remove $id
         :set phase "cleanup"; :set n 0; :while (([:len [/container/find where name="m3-image-row"]]+[:len [/file/find where name="disk1/m3-image-root"]]>0) and ($n<40)) do={:delay 500ms; :set n ($n+1)}
         :local rootPresent ([:len [/file/find where name="disk1/m3-image-root"]]>0)
         :set phase "read-public-schema"
         :local fields ""
         :foreach key,x in=$image do={ :if (($key~"^[a-zA-Z0-9._-]+\$") and ([:len $key]<48)) do={ :set fields ($fields . "," . $key) } }
         /system/script/set $result comment=("done:" . $rootPresent . ":" . $fields)
      } do={ :local category "unknown"; :foreach term in={"not enough permissions";"invalid";"I/O";"file not found";"no such";"expected";"bad command";"empty";"not allowed";"hash";"timeout"} do={:if ([:typeof [:find [:tostr $err] $term]]="num") do={:set category $term}}; /system/script/set $result comment=("failed:" . $phase . ":" . $category) }
}`
	p := filepath.Join(t.TempDir(), "cap.rsc")
	// Import privately so no expanded values from the peer are recorded.
	f, err := os.Open(img)
	if err != nil {
		t.Fatal("fixture archive unavailable")
	}
	tr := tar.NewReader(f)
	var list []struct{ Config string }
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal("bad fixture archive")
		}
		if h.Name == "manifest.json" && json.NewDecoder(tr).Decode(&list) != nil {
			t.Fatal("fixture manifest unavailable")
		}
	}
	f.Close()
	if len(list) != 1 {
		t.Fatal("missing fixture manifest")
	}
	imgID := strings.TrimSuffix(filepath.Base(list[0].Config), ".json")
	body = strings.Replace(body, ":local image [/container/get $id]", `:local image [/container/get $id]; :local got [:tostr ($image->"image-id")]; :set phase "image-id"; :if (($got!="`+imgID+`") and ($got!=("sha256:" . "`+imgID+`"))) do={ :error "invalid" }`, 1)
	source := "/system/script/add name=m3-image-job policy=read,write,test,ftp source=" + body + "\n/system/scheduler/add name=m3-image-sched policy=read,write,test,ftp on-event=m3-image-job interval=1s start-time=startup\n"
	if os.WriteFile(p, []byte(source), 0600) != nil || r.chr.Push(r.ctx, p, "m3-image-cap.rsc") != nil {
		t.Fatal("image script transfer failed")
	}
	run("/import m3-image-cap.rsc")
	ready := ownerWait(r.ctx, 105*time.Second, func(ctx context.Context) (bool, error) {
		s, e := r.chr.RunPrivate(ctx, `:put [/system/script/get [find where name="m3-image-result"] comment]`)
		return strings.HasPrefix(strings.TrimSpace(s), "done:") || strings.HasPrefix(strings.TrimSpace(s), "failed:"), e
	})
	if ready != nil {
		t.Fatal("no native job outcome")
	}
	got := run(`:put [/system/script/get [find where name="m3-image-result"] comment]`)
	for _, phase := range []string{"image-id", "read-chunk", "hash", "add", "extract", "unset", "remove", "cleanup", "read-public-schema"} {
		for _, category := range []string{"not enough permissions", "invalid", "I/O", "file not found", "no such", "expected", "bad command", "empty", "not allowed", "hash", "timeout", "unknown"} {
			if got == "failed:"+phase+":"+category {
				t.Fatalf("native restriction at %s (%s)", phase, category)
			}
		}
	}
	if !strings.HasPrefix(got, "done:") {
		t.Fatal("unrecognized native verdict")
	}
	parts := strings.Split(got, ":")
	if len(parts) != 3 {
		t.Fatal("missing native schema observation")
	}
	t.Log("root survived removal", parts[1] == "true")
	for _, prop := range []string{"file", "tag", "image", "image-id", "root-dir", "mountlists", "envlists", "remote-image", "entrypoint", "start-on-boot", "cmd", "default-cmd"} {
		t.Logf("property %s %t", prop, strings.Contains(parts[2]+",", ","+prop+","))
	}
}

// Exercise the very same uptime accounting and restart sequence used by
// the native job, including a reboot while an image is in its grace window.
func TestWatchdogRestartBackoff(t *testing.T) {
	fragment, err := routerfiles.Sources.ReadFile("watchdog-image.rsc")
	if err != nil {
		t.Fatal("missing native image recovery phase machine")
	}
	_, tail, found := strings.Cut(string(fragment), "    :local advanceAge do={")
	fn, _, end := strings.Cut(tail, "\n    }\n")
	step, e := routerfiles.Sources.ReadFile("watchdog-step.rsc")
	if !found || !end || e != nil {
		t.Fatal("missing bounded native timers")
	}
	r := newRig(t)
	script := "{\n:local advanceAge do={" + fn + "\n}\n" + string(step) + `
	:if (([$advanceAge 60 180 180 false]!=60) or ([$advanceAge 60 60 60 true]!=120) or ([$advanceAge 60 180 205]!=85) or ([$advanceAge 60 180 11]!=71) or ([$advanceAge 60 180 800]!=300)) do={:error "incorrect image window"}
	:local s [:toarray ""]; :local observed [:toarray ""]
	:for n from=1 to=34 do={ :set s [$wdStep $s false ($n*60)]; :if ($s->"restart") do={:set observed ($observed,$n)} }
	:if ([:tostr $observed]!="3;4;6;10;18;33") do={:error "incorrect restart backoff"}
	:put "timer-ok" }`
	p := filepath.Join(t.TempDir(), "image-timer.rsc")
	if os.WriteFile(p, []byte(script), 0600) != nil || r.chr.Push(r.ctx, p, "image-timer.rsc") != nil {
		t.Fatal("timer transfer failed")
	}
	out, err := r.chr.RunPrivate(r.ctx, `:onerror reason in={/import image-timer.rsc} do={:put "timer-refused"}`)
	if err != nil || !strings.Contains(out, "timer-ok") {
		t.Fatal("native image deadline or restart timing failed")
	}
}

const nativeImageIdentity = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const nativeImageNonce = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

type nativeImageCase struct {
	r             *rig
	data          string
	first, second map[string]any
	run           func(string) string
	pub           func(string, []byte)
	write         func(string, any)
	req           func(string, map[string]any, map[string]any)
	tick          func() string
	isLive        func(map[string]any) bool
	diagnose      func()
	buildArchive  func([]byte, string) map[string]any
}

func newNativeImageCase(t *testing.T) *nativeImageCase {
	t.Helper()
	r := newRig(t)
	run := func(command string) string {
		t.Helper()
		out, err := r.chr.RunPrivate(r.ctx, command)
		if err != nil {
			t.Fatal("private image phase fixture failed")
		}
		return strings.TrimSpace(out)
	}
	pub := func(path string, data []byte) {
		t.Helper()
		p := filepath.Join(t.TempDir(), "fixture")
		if os.WriteFile(p, data, 0600) != nil || r.chr.Push(r.ctx, p, path) != nil {
			t.Fatal("image phase fixture transfer failed")
		}
	}
	root := "disk1/tikray-phases"
	data := root + "/data"
	for _, p := range []string{root, root + "/containers", data, data + "/images", data + "/state"} {
		run("/file/add type=directory name=" + p)
	}
	const identity = nativeImageIdentity
	buildArchive := func(container []byte, configID string) map[string]any {
		t.Helper()
		sum := sha256.Sum256(container)
		id := hex.EncodeToString(sum[:])
		chain := ""
		for i := 0; i < len(container); i += 16384 {
			h := sha512.Sum512(container[i:min(i+16384, len(container))])
			step := sha512.Sum512([]byte(chain + hex.EncodeToString(h[:])))
			chain = hex.EncodeToString(step[:])
		}
		pub(data+"/images/tikray-"+id+".tar", container)
		return map[string]any{"component": "tikray", "image_id": configID, "digest": id, "chain": chain, "size": len(container)}
	}
	first, second := buildArchive(nativeProbeArchive(t, "old")), buildArchive(nativeProbeArchive(t, "new"))
	write := func(path string, v any) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal("bad image fixture")
		}
		pub(data+"/state/"+path, b)
	}
	write("image-bootstrap.receipt", map[string]any{"version": 1, "arch": "amd64", "publisher": "fixture", "tikray": first, "runner": nil})
	write("image-tikray.receipt", map[string]any{"version": 1, "installation_id": identity, "active": first, "previous": nil})
	pub(data+"/state/install.id", []byte(identity))
	run(`/interface/veth/add name=tikray-ctl address=172.27.248.2/29 gateway=172.27.248.1 comment="tikray:veth-ctl"; /container/envs/add list=tikray key=TIKRAY_DATA value="/data" comment="tikray:env-ctl-data"; /container/envs/add list=tikray-runner key=TIKRAY_DATA value="/data" comment="tikray:env-runner-data"; /container/mounts/add list=tikray src=disk1/tikray-phases/data dst=/data mode=rw comment="tikray:mount-tikray-data"`)
	for _, part := range []string{"run", "geo", "cores"} {
		mode := "ro"
		if part == "run" {
			mode = "rw"
		}
		run("/file/add type=directory name=" + data + "/" + part + "; /container/mounts/add list=tikray-runner src=" + data + "/" + part + " dst=/data/" + part + " mode=" + mode + " comment=tikray:mount-runner-" + part)
	}
	run(`/container/add name=tikray comment="tikray:tikray" file=` + data + "/images/tikray-" + first["digest"].(string) + `.tar root-dir=disk1/tikray-phases/containers/control mountlists=tikray envlists=tikray interface=tikray-ctl dns=172.27.248.1 start-on-boot=yes restart-policy=on-failure memory-high=134217728 memory-max=201326592 logging=no`)
	if ownerWait(r.ctx, time.Minute, func(ctx context.Context) (bool, error) {
		x, e := r.chr.RunPrivate(ctx, `:put [:len [/container/find where name=tikray and stopped]]`)
		return strings.TrimSpace(x) == "1", e
	}) != nil {
		t.Fatal("initial image not extracted")
	}
	run(`/container/start [find where name=tikray]`)
	if ownerWait(r.ctx, time.Minute, func(ctx context.Context) (bool, error) {
		x, e := r.chr.RunPrivate(ctx, `:put [:len [/container/find where name=tikray and running]]`)
		return strings.TrimSpace(x) == "1", e
	}) != nil {
		t.Fatal("initial native image failed to run")
	}
	watch, e := routerfiles.Sources.ReadFile("watchdog-image.rsc")
	if e != nil {
		t.Fatal("missing image machine")
	}
	traffic, _ := routerfiles.Sources.ReadFile("watchdog-traffic.rsc")
	watch = []byte(strings.ReplaceAll(string(watch), "# @TIKRAY_WATCHDOG_TRAFFIC@", string(traffic)))
	source := `{
` + string(watch) + `
:local ready do={:return ([:len [/system/script/find where name="m3-stall-health"]]=0)}
:local pause do={:return false}
:local emergency ""; :local rows [/system/script/find where name="tikray-emergency-state" and comment="tikray:emergency-state" and source=""]; :if ([:len $rows]=1) do={:set emergency [:tostr [:pick $rows 0]]}
:local ok [$wdImage "disk1/tikray-phases/data" "` + identity + `" 172.27.248.1 $ready $pause $emergency]
:put "native-image-ok"
}`
	pub("m3-watch-images.rsc", []byte(source))
	tick := func() string {
		t.Helper()
		out := run(`:onerror why in={ /import file-name=m3-watch-images.rsc } do={:put ("m3-why=" . [:convert [:tostr $why] to=base64])}`)
		if strings.Contains(out, "native-image-ok") {
			return ""
		}
		_, txt, _ := strings.Cut(out, "m3-why=")
		msg, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(txt))
		for _, m := range regexp.MustCompile(`:error "(image:[^"]+)"`).FindAllStringSubmatch(string(watch), -1) {
			if strings.Contains(string(msg), m[1]) {
				return m[1]
			}
		}
		for _, cat := range []string{"syntax error", "expected end", "expected", "invalid internal", "input does not match", "invalid", "not enough permissions", "no such", "bad command", "failure", "cannot", "not allowed", "argument"} {
			if strings.Contains(string(msg), cat) {
				return cat + " " + regexp.MustCompile(`line [0-9]+ column [0-9]+`).FindString(string(msg))
			}
		}
		return fmt.Sprintf("unclassified native refusal (%d bytes)", len(msg))
	}
	req := func(n string, from, to map[string]any) {
		write("image-update.request", map[string]any{"version": 1, "installation_id": identity, "component": "tikray", "previous": from, "candidate": to, "selection_digest": strings.Repeat("a", 64), "phase": "requested", "nonce": n, "started": 1000, "deadline": 1300})
	}
	isLive := func(ref map[string]any) bool {
		return ownerWait(r.ctx, 25*time.Second, func(ctx context.Context) (bool, error) {
			out, e := r.chr.RunPrivate(ctx, `{:local ids [/container/find where name=tikray and comment="tikray:tikray" and running]; :if ([:len $ids]=1) do={:local row [/container/get [:pick $ids 0]]; :local code [:tostr ($row->"image-id")]; :put (($code="`+ref["image_id"].(string)+`") or ($code="sha256:`+ref["image_id"].(string)+`"))}}`)
			return strings.TrimSpace(out) == "true", e
		}) == nil
	}
	diagnostic := func() {
		t.Helper()
		p := run(`{:local rs [/system/script/find where name=tikray-image-transition];:if ([:len $rs]=1) do={:local st [:deserialize from=json options=json.no-string-conversion value=[:pick [/system/script/get $rs comment] [:len "tikray:image-transition "] 4096]];:put ($st->"phase")}}`)
		for _, phase := range []string{"replace", "verify", "commit", "restore", "recover", "committed", "reverted"} {
			if p == phase {
				t.Log("native progress", phase)
			}
		}
		for _, pred := range []string{"name=tikray and running", "name=tikray and stopped", "name=tikray", "name=tikray and extracting", "name=tikray and removing"} {
			out, e := r.chr.RunPrivate(r.ctx, ":put [:len [/container/find where "+pred+"]]")
			if e == nil {
				t.Log("native positive", pred, strings.TrimSpace(out) == "1")
			}
		}
		out, e := r.chr.RunPrivate(r.ctx, `{:local ids [/container/find where name=tikray];:if ([:len $ids]=1) do={:local row [/container/get [:pick $ids 0]];:local code [:tostr ($row->"image-id")];:put (($code="`+first["image_id"].(string)+`") or ($code="sha256:`+first["image_id"].(string)+`"))}}`)
		if e == nil {
			t.Log("original image still present", strings.TrimSpace(out) == "true")
		}
	}
	return &nativeImageCase{r: r, data: data, first: first, second: second, run: run, pub: pub, write: write, req: req, tick: tick, isLive: isLive, diagnose: diagnostic, buildArchive: buildArchive}
}

func TestNativeImageRecoveryPhases(t *testing.T) {
	f := newNativeImageCase(t)
	first, second, req, tick, isLive, run, diagnostic := f.first, f.second, f.req, f.tick, f.isLive, f.run, f.diagnose
	const nonce = nativeImageNonce
	// The first invocation imports exactly the candidate. A changed staged
	// checksum is refused without stopping or removing the healthy old row.
	f.pub(f.data+"/state/image-update.json", []byte("legacy"))
	req(nonce, first, second)
	if got := tick(); got != "image: legacy transition requires owner inspection" || !isLive(first) {
		t.Fatalf("ambiguous request was not preserved (%s)", got)
	}
	run(`/file/remove [find where name="disk1/tikray-phases/data/state/image-update.json"]`)
	bad := maps.Clone(second)
	bad["chain"] = strings.Repeat("f", 128)
	req(nonce, first, bad)
	if err := tick(); err != "" || !isLive(first) || run(`:put [:len [/file/find where name="disk1/tikray-phases/data/state/image-update.request"]]`) != "0" {
		t.Fatalf("corruption failed to preserve and verify the original image (%s)", err)
	}
	req(nonce, first, second)
	run(`/container/mounts/add list=m3-foreign src=disk1/tikray-phases/data/state dst=/state mode=rw comment=m3-foreign`)
	if got := tick(); got != "image: shared private mount" || !isLive(first) {
		t.Fatalf("owner alias did not refuse before change (%s)", got)
	}
	run(`/container/mounts/remove [find comment=m3-foreign]`)
	if err := tick(); err != "" {
		t.Fatal("switch:", err)
	}
	t.Log("native tick completed")
	if !isLive(second) {
		diagnostic()
		t.Fatal("candidate not running")
	}
	// Simulate losing power after the write-ahead commit decision and in
	// the middle of updating its positively identified current file in place.
	run(`{:local id [/system/script/find where name=tikray-image-transition]; :local prefix "tikray:image-transition "; :local j [:deserialize from=json options=json.no-string-conversion value=[:pick [/system/script/get $id comment] [:len $prefix] 4096]]; :set ($j->"phase") "commit"; /system/script/set $id comment=($prefix . [:serialize to=json options=json.no-string-conversion value=$j]); /file/set [find where name="disk1/tikray-phases/data/state/image-tikray.receipt"] contents="{"}`)
	if err := tick(); err != "" {
		t.Fatal("commit:", err)
	}
	if run(`:put [:len [/file/find where name="disk1/tikray-phases/data/state/image-update.request"]]`) != "0" {
		t.Fatal("healthy committed marker survived")
	}
	req(strings.Repeat("c", 32), second, first)
	if err := tick(); err != "" {
		t.Fatal("new switch:", err)
	}
	run(`/system/script/add name=m3-stall-health source="" policy=read`)
	if err := tick(); err != "" {
		t.Fatal("waiting:", err)
	}
	if !isLive(first) {
		t.Fatal("candidate did not survive test health miss")
	}
	// Keep the test bounded while exercising the exact persisted deadline.
	// The full reboot suite additionally advances the real scheduler clock.
	run(`{:local id [/system/script/find where name=tikray-image-transition]; :local prefix "tikray:image-transition "; :local j [:deserialize from=json options=json.no-string-conversion value=[:pick [/system/script/get $id comment] [:len $prefix] 4096]]; :set ($j->"age") 300; /system/script/set $id comment=($prefix . [:serialize to=json options=json.no-string-conversion value=$j])}`)
	if err := tick(); err != "" {
		t.Fatal("restore:", err)
	}
	t.Log("native tick completed")
	if !isLive(second) {
		diagnostic()
		t.Fatal("deadline did not restore previous verified image")
	}
	if err := tick(); err != "" {
		t.Fatal("failed restore health:", err)
	}
	if run(`:put [:len [/file/find where name="disk1/tikray-phases/data/state/image-update.request"]]`) != "1" {
		t.Fatal("unhealthy recovery cleared its marker")
	}
	run(`/system/script/remove [find name=m3-stall-health]`)
	if err := tick(); err != "" {
		t.Fatal("restore proof:", err)
	}
	if run(`:put [:len [/file/find where name="disk1/tikray-phases/data/state/image-update.request"]]`) != "0" || !isLive(second) {
		t.Fatal("healthy restoration did not finish")
	}
	// An incomplete lineage must never authorize rolling a healthy image back.
	req(strings.Repeat("d", 32), second, first)
	f.write("image-tikray.receipt", map[string]any{"version": 1, "installation_id": nativeImageIdentity, "active": second, "previous": nil})
	if got := tick(); got != "image: invalid current receipt" || !isLive(second) {
		t.Fatalf("incomplete history authorized removal (%s)", got)
	}
	f.write("image-tikray.receipt", map[string]any{"version": 1, "installation_id": nativeImageIdentity, "active": second, "previous": second})
	if got := tick(); got != "image: invalid current receipt" || !isLive(second) {
		t.Fatalf("duplicated history authorized removal (%s)", got)
	}
	f.write("image-tikray.receipt", map[string]any{"version": 1, "installation_id": nativeImageIdentity, "active": second, "previous": first})
	if got := tick(); got != "" || !isLive(first) {
		t.Fatalf("emergency setup failed (%s)", got)
	}
	run(`/container/stop [find where name=tikray]; /system/script/add name=tikray-emergency-state comment="tikray:emergency-state" source="" policy=read`)
	if ownerWait(f.r.ctx, 30*time.Second, func(ctx context.Context) (bool, error) {
		out, e := f.r.chr.RunPrivate(ctx, `:put [:len [/container/find where name=tikray and stopped]]`)
		return strings.TrimSpace(out) == "1", e
	}) != nil {
		t.Fatal("owner could not stop disposable target")
	}
	if got := tick(); got != "" {
		t.Fatal("prepare previous while stopped", got)
	}
	if got := tick(); got != "" || run(`:put [:len [/container/find where name=tikray and stopped and !start-on-boot]]`) != "1" || run(`:put [:len [/file/find where name="disk1/tikray-phases/data/state/image-update.request"]]`) != "1" {
		t.Fatalf("emergency must keep prepared target stopped (%s)", got)
	}
	run(`/container/start [find where name=tikray and stopped]`)
	if ownerWait(f.r.ctx, 30*time.Second, func(ctx context.Context) (bool, error) {
		out, e := f.r.chr.RunPrivate(ctx, `:put [:len [/container/find where name=tikray and running]]`)
		return strings.TrimSpace(out) == "1", e
	}) != nil {
		t.Fatal("owner could not start prepared target")
	}
	if got := tick(); got != "" || !isLive(second) || run(`:put [:len [/system/script/find where name="tikray-emergency-state" and comment="tikray:emergency-state"]]`) != "1" || run(`:put [:len [/file/find where name="disk1/tikray-phases/data/state/image-update.request"]]`) != "0" {
		t.Fatalf("suspended proof failed (%s)", got)
	}
	t.Log("signed-content identities, tamper refusal, commit, deadline rollback and verified recovery passed")
}

func nativeProbeArchive(t *testing.T, label string) ([]byte, string) {
	t.Helper()
	return nativeProbeArchiveWithFiles(t, label, 0)
}

func nativeProbeArchiveWithFiles(t *testing.T, label string, count int) ([]byte, string) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if os.WriteFile(src, []byte("package main\nimport \"time\"\nfunc main(){for {time.Sleep(time.Hour)}}\n"), 0600) != nil {
		t.Fatal("cannot stage native fixture executable")
	}
	output := filepath.Join(dir, "pause")
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", output, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if cmd.Run() != nil {
		t.Fatal("cannot build native fixture executable")
	}
	bin, e := os.ReadFile(output)
	if e != nil {
		t.Fatal("missing native fixture executable")
	}
	tarFile := func(files map[string][]byte) []byte {
		t.Helper()
		var b bytes.Buffer
		w := tar.NewWriter(&b)
		for name, data := range files {
			if w.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(data))}) != nil {
				t.Fatal("fixture tar failed")
			}
			if _, e := w.Write(data); e != nil {
				t.Fatal("fixture tar data failed")
			}
		}
		if w.Close() != nil {
			t.Fatal("fixture tar close failed")
		}
		return b.Bytes()
	}
	files := map[string][]byte{"pause": bin}
	for i := range count {
		files[fmt.Sprintf("ordinary-file-%05d", i)] = nil
	}
	layer := tarFile(files)
	hash := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	cfg, _ := json.Marshal(map[string]any{"architecture": "amd64", "os": "linux", "config": map[string]any{"Cmd": []string{"/pause"}, "Labels": map[string]string{"witness": label}}, "rootfs": map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + hash(layer)}}, "history": []map[string]string{{"created_by": "fixture"}}})
	id := hash(cfg)
	configName := id + ".json"
	layerName := hash(layer) + "/layer.tar"
	manifest, _ := json.Marshal([]map[string]any{{"Config": configName, "RepoTags": []string{"m3/phase:" + label}, "Layers": []string{layerName}}})
	return tarFile(map[string][]byte{"manifest.json": manifest, configName: cfg, layerName: layer}), id
}

func TestUninstallRefusesActiveImageJournal(t *testing.T) {
	_, cmd, remove := uninstallFixture(t)
	cmd(`/system/script/add name=tikray-image-transition comment="tikray:image-transition fixture" source="" policy=read`)
	if !strings.Contains(remove(), "image transition active") || cmd(`:put [/ip/service/get api-ssl certificate]`) != "tikray-api" || cmd(`:put [:len [/system/script/find where name=tikray-uninstall-state]]`) != "0" {
		t.Fatal("owner uninstall ignored active image handoff")
	}
}

func TestImageUpdateBootWitness(t *testing.T) {
	r := newRig(t)
	run := func(cmd string) string {
		t.Helper()
		s, e := r.chr.RunPrivate(r.ctx, cmd)
		if e != nil {
			t.Fatal("boot witness fixture rejected")
		}
		return strings.TrimSpace(s)
	}
	run(`/system/script/add name=m3-clock-state source="" policy=read comment="start"; /system/script/add name=m3-clock-job policy=read,write,test,ftp source={:local rec [/system/script/find where name=m3-clock-state];:local old [/system/script/get $rec comment];:if ($old="start") do={:local keep [:execute {:delay 10m}]; :local born [:tostr [/system/script/job/get $keep started]]; /system/script/set $rec comment=([:tostr $keep] . "|" . $born) } else={:local cut [:find $old "|"]; :local candidate [:toid [:pick $old 0 $cut]]; :local born [:pick $old ($cut+1) [:len $old]]; :local live [/system/script/job/find where .id=$candidate]; :put ([:len [/system/script/job/find where script="m3-clock-job"]] . "|" . (([:len $live]=1) and ([:tostr [/system/script/job/get $live started]]=$born)))}} `)
	run(`/system/script/run m3-clock-job`)
	if got := run(`/system/script/run m3-clock-job`); got != "1|true" {
		t.Fatalf("background fixed-delay lost boot identity or counted as a second foreground job: single=%t present=%t", strings.HasPrefix(got, "1|"), strings.HasSuffix(got, "true"))
	}
	certPEM := run(`:put [/file/get m3-cap-public.crt contents]`)
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("missing audit pin")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal("invalid audit pin")
	}
	pw, e := os.ReadFile(filepath.Join(lab.CacheDir(), "ready", r.version, "x86_64", "password"))
	if e != nil {
		t.Fatal("cannot reopen owner audit session")
	}
	if r.chr.Reboot(r.ctx) != nil {
		t.Fatal("reboot did not complete")
	}
	// Connection cleanups run after the secret audit, including after a reboot.
	r.reopenAudit(t, string(pw), cert)
	if run(`{:local text [/system/script/get [find where name=m3-clock-state] comment]; :local cut [:find $text "|"]; :local id [:toid [:pick $text 0 $cut]]; :local jobs [/system/script/job/find where .id=$id]; :if ([:len $jobs]=0) do={:put "gone"} else={:if ([:tostr [/system/script/job/get $jobs started]]!=[:pick $text ($cut+1) [:len $text]]) do={:put "gone"}}}`) != "gone" {
		t.Fatal("stale boot witness survived a reboot")
	}
}

func TestNativeRunnerImageTrafficFence(t *testing.T) {
	r := newRig(t)
	run := func(cmd string) string {
		t.Helper()
		s, e := r.chr.RunPrivate(r.ctx, cmd)
		if e != nil {
			t.Fatal("private traffic fence fixture rejected")
		}
		return strings.TrimSpace(s)
	}
	run(`/interface/list/add name=m3-images-lan; /interface/list/member/add interface=ether2 list=m3-images-lan`)
	if run(`:put [:len [/ip/route/find where routing-table="main" and dst-address="0.0.0.0/0" and active]]`) == "0" {
		run(`/ip/route/add dst-address=0.0.0.0/0 gateway=198.51.100.254 comment=wan-fixture`)
	}
	if run(`:put [:len [/ip/route/find where routing-table="main" and dst-address="0.0.0.0/0" and active]]`) != "1" {
		t.Fatal("WAN positive control missing")
	}
	gw := run(`:put [:tostr [/ip/route/get [:pick [/ip/route/find where routing-table="main" and dst-address="0.0.0.0/0" and active] 0] gateway]]`)
	if !regexp.MustCompile(`^[0-9.]+(%ether1)?$`).MatchString(gw) {
		t.Fatal("fixture gateway unavailable")
	}
	for _, cl := range []string{"open", "closed"} {
		run(`/routing/table/add name=tikray-` + cl + ` fib comment="tikray:table-` + cl + `"`)
		run(`/ip/route/add comment="tikray:route-` + cl + `-runner" dst-address=0.0.0.0/0 gateway=172.31.255.3 check-gateway=ping distance=1 routing-table=tikray-` + cl)
		kind := "gateway=" + gw
		if cl == "closed" {
			kind = "blackhole"
		}
		run(`/ip/route/add comment="tikray:route-` + cl + `-fallback" dst-address=0.0.0.0/0 distance=2 routing-table=tikray-` + cl + " " + kind)
	}
	run(`/ip/firewall/mangle/add chain=tikray-pre action=mark-connection new-connection-mark=tikray-open passthrough=yes src-address=192.0.2.1 comment="tikray:conn-full-open"`)
	run(`/ip/firewall/mangle/add chain=tikray-pre action=mark-routing connection-mark=tikray-open new-routing-mark=tikray-open passthrough=no comment="tikray:route-open"`)
	run(`/tool/netwatch/add host=172.31.255.3 type=simple comment="tikray:runner-watch"`)
	for _, proto := range []string{"tcp", "udp"} {
		run(`/ip/firewall/filter/add chain=tikray-bridge-fw action=accept connection-nat-state=dstnat in-interface-list=m3-images-lan dst-address=172.31.255.3 protocol=` + proto + ` dst-port=53 comment="tikray:acl-dns-` + proto + `"`)
		run(`/ip/firewall/nat/add chain=dstnat action=dst-nat in-interface-list=m3-images-lan src-address-list=tikray-src-full-open to-addresses=172.31.255.3 to-ports=53 protocol=` + proto + ` dst-port=53 comment="tikray:dns-full-open-` + proto + `"`)
		run(`/ip/firewall/nat/add chain=dstnat action=redirect in-interface-list=m3-images-lan src-address-list=tikray-src-full-open to-ports=53 protocol=` + proto + ` dst-port=53 comment="tikray:dns-router-full-open-` + proto + `"`)
		run(`/ip/firewall/nat/add chain=dstnat action=dst-nat in-interface-list=m3-images-lan src-address-list=tikray-src-full-closed to-addresses=172.31.255.3 to-ports=53 protocol=` + proto + ` dst-port=53 comment="tikray:dns-full-closed-` + proto + `"`)
	}
	compiled, helper, err := adapters.WatchdogScripts()
	if err != nil {
		t.Fatal("native watchdog source unavailable")
	}
	start := strings.Index(compiled, ":local imageTraffic do={")
	end := strings.Index(compiled, ":local grant {")
	if start < 0 || end <= start {
		t.Fatal("missing deployed traffic binding")
	}
	body := compiled[start:end]
	if _, e := r.admin.RunContext(r.ctx, "/system/script/add", "=name=tikray-watchdog-traffic", "=comment=tikray:watchdog-traffic", "=policy=read", "=source="+strings.ReplaceAll(helper, "\n", "\r\n")); e != nil {
		t.Fatal("cannot install exact reviewed traffic helper")
	}
	read, e := r.admin.RunContext(r.ctx, "/system/script/print", "?name=tikray-watchdog-traffic", "=.proplist=source")
	if e != nil || len(read.Re) != 1 {
		t.Fatal("saved helper source unavailable")
	}
	wire := read.Re[0].Map["source"]
	canonical := strings.TrimRight(wire, "\r\n")
	asLF := strings.TrimRight(helper, "\r\n")
	asCRLF := strings.ReplaceAll(asLF, "\n", "\r\n")
	if canonical != asCRLF {
		t.Fatal("native assignment changed pinned helper bytes")
	}
	script := "{\n" + body + `
	:local lease do={:return true}
	:local controls [$imageTraffic "read" [:toarray ""] 172.31.255.3 "m3-images-lan" $lease true false]
	:foreach k in={"tikray:route-open-runner";"tikray:route-closed-runner";"tikray:runner-watch";"tikray:acl-dns-udp";"tikray:acl-dns-tcp";"tikray:dns-full-open-udp";"tikray:dns-full-open-tcp"} do={:if ([:typeof ($controls->$k)]!="bool") do={:put ("bad-role|" . $k . "|end")}}
	:if ([:len $controls]!=8) do={:error "missing native controls"}
	:local held [$imageTraffic "hold" $controls 172.31.255.3 "m3-images-lan" $lease true false]
	:if (([:len [/ip/route/find where comment~"^tikray:route-(open|closed)-runner" and disabled]]!=2) or ([:len [/ip/firewall/nat/find where comment~"^tikray:dns-full-open" and disabled]]!=2) or ([:len [/ip/firewall/filter/find where comment~"^tikray:acl-dns-" and disabled]]!=2) or ([:len [/tool/netwatch/find where comment="tikray:runner-watch" and disabled]]!=1) or ([:len [/ip/firewall/nat/find where comment~"^tikray:dns-full-closed" and !disabled]]!=2) or ([:len [/ip/firewall/nat/find where comment~"^tikray:dns-router-full-open" and !disabled]]!=2)) do={:error "incorrect native hold"}
	# A lease can change while Go reconciliation is intentionally suspended. Mutate only the owned test fallback to simulate the old gateway; the active main is still the working packet path.
	/ip/route/set [find where comment="tikray:route-open-fallback"] gateway=198.51.100.253
	:local changed [$imageTraffic "hold" $controls 172.31.255.3 "m3-images-lan" $lease true false]
	:if (([:len [/ip/firewall/mangle/find where comment="tikray:route-open" and disabled]]!=1) or ([:len [/ip/route/find where comment="tikray:route-closed-fallback" and blackhole and !disabled]]!=1)) do={:error "WAN change broke closed protection or open main routing"}
	:local resumedWAN [$imageTraffic "release" $controls 172.31.255.3 "m3-images-lan" $lease true false]
	:if ([:len [/ip/firewall/mangle/find where comment="tikray:route-open" and disabled]]!=1) do={:error "stale WAN fallback rearmed"}
	/ip/route/set [find where comment="tikray:route-open-fallback"] gateway=` + gw + `
	:local heldAgain [$imageTraffic "hold" $controls 172.31.255.3 "m3-images-lan" $lease true false]
	:local off [$imageTraffic "release" $controls 172.31.255.3 "m3-images-lan" $lease true true]
	:if (([:len [/ip/route/find where comment~"^tikray:route-(open|closed)-runner" and disabled]]!=2) or ([:len [/ip/firewall/filter/find where comment~"^tikray:acl-dns-" and !disabled]]!=2)) do={:error "emergency fence release changed steering"}
	:local resumed [$imageTraffic "release" $controls 172.31.255.3 "m3-images-lan" $lease true false]
	:if (([:len [/ip/route/find where comment~"^tikray:route-(open|closed)-runner" and !disabled]]!=2) or ([:len [/tool/netwatch/find where comment="tikray:runner-watch" and !disabled]]!=1) or ([:len [/ip/firewall/nat/find where comment~"^tikray:dns-full-open" and !disabled]]!=2)) do={:error "native fence failed to rearm"}
	:put "fence-ok" }`
	p := filepath.Join(t.TempDir(), "fence.rsc")
	if os.WriteFile(p, []byte(script), 0600) != nil || r.chr.Push(r.ctx, p, "m3-image-fence.rsc") != nil {
		t.Fatal("cannot stage egress probe")
	}
	out := run(`:onerror why in={ /import file-name=m3-image-fence.rsc } do={ :put ("m3-why=" . [:convert [:tostr $why] to=base64]) }`)
	if !strings.Contains(out, "fence-ok") {
		_, b, _ := strings.Cut(out, "m3-why=")
		m, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(b))
		cat := "unclassified"
		for _, re := range regexp.MustCompile(`:error "([^"$]+)"`).FindAllStringSubmatch(script, -1) {
			if strings.Contains(string(m), re[1]) {
				cat = re[1]
			}
		}
		for _, e := range []string{"syntax error", "expected end", "no such", "invalid", "not enough permissions", "input does not match"} {
			if strings.Contains(string(m), e) {
				cat = e
			}
		}
		for _, key := range []string{"tikray:route-open-runner", "tikray:route-closed-runner", "tikray:runner-watch", "tikray:acl-dns-udp", "tikray:acl-dns-tcp", "tikray:dns-full-open-tcp", "tikray:dns-full-open-udp"} {
			if strings.Contains(out, "bad-role|"+key+"|end") {
				t.Log("missing fixture role", key)
			}
		}
		t.Fatal("native runner traffic fence refused", cat, regexp.MustCompile(`line [0-9]+ column [0-9]+`).FindString(string(m)))
	}
	run(`/system/script/add name=m3-helper-verdict policy=read source="" comment=waiting`)
	scheduled := "{\n" + body + `
	/system/scheduler/disable [find where name="m3-helper-schedule"]
	:local check do={:return true}
	:local verdict "denied"
	:do { :local q [$imageTraffic "read" [:toarray ""] 172.31.255.3 "m3-images-lan" $check true false]; :if ([:len $q]=8) do={:set verdict "verified"} } on-error={}
	/system/script/set [find where name="m3-helper-verdict"] comment=$verdict
}`
	if _, e := r.admin.RunContext(r.ctx, "/system/script/add", "=name=m3-helper-probe", "=policy=read,write,test,ftp", "=source="+scheduled); e != nil {
		t.Fatal("cannot stage restricted helper probe")
	}
	run(`/system/scheduler/add name=m3-helper-schedule policy=read,write,test,ftp interval=2s start-time=startup on-event=m3-helper-probe`)
	if ownerWait(r.ctx, 12*time.Second, func(ctx context.Context) (bool, error) {
		v, e := r.chr.RunPrivate(ctx, `:put [/system/script/get [find where name="m3-helper-verdict"] comment]`)
		return strings.TrimSpace(v) != "waiting", e
	}) != nil || run(`:put [/system/script/get [find where name="m3-helper-verdict"] comment]`) != "verified" {
		t.Fatal("restricted native scheduler could not authenticate and call the installer helper")
	}
	// The installer supplied source is a separate read-only object. A changed
	// body must never be executed under the native scheduler's authority.
	run(`/system/script/set [find where name="tikray-watchdog-traffic"] source=":error \"unexpected-test-program\""`)
	out = run(`:onerror why in={/import file-name=m3-image-fence.rsc} do={:put ([:find [:tostr $why] "image: traffic helper content changed"]!=nil)}`)
	if strings.TrimSpace(out) != "true" {
		t.Fatal("changed helper was accepted or wrong refusal")
	}
}
