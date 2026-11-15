//go:build lab

package m3

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

	routerfiles "github.com/Arman2122/tikray/routeros"
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
	fn, _, end := strings.Cut(tail, "    :local now (")
	step, e := routerfiles.Sources.ReadFile("watchdog-step.rsc")
	if !found || !end || e != nil {
		t.Fatal("missing bounded native timers")
	}
	r := newRig(t)
	script := "{\n:local advanceAge do={" + fn + "\n" + string(step) + `
	:if (([$advanceAge 60 180 180]!=60) or ([$advanceAge 60 180 205]!=85) or ([$advanceAge 60 180 11]!=71) or ([$advanceAge 60 180 800]!=300)) do={:error "incorrect image window"}
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
func TestNativeImageRecoveryPhases(t *testing.T) {
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
	const identity = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const nonce = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	buildImage := func(label string) map[string]any {
		t.Helper()
		container, configID := nativeProbeArchive(t, label)
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
	first, second := buildImage("old"), buildImage("new")
	write := func(path string, v any) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal("bad image fixture")
		}
		pub(data+"/state/"+path, b)
	}
	write("image-bootstrap.json", map[string]any{"version": 1, "arch": "amd64", "publisher": "fixture", "tikray": first, "runner": nil})
	write("image-tikray.json", map[string]any{"version": 1, "installation_id": identity, "active": first, "previous": nil})
	pub(data+"/state/install.id", []byte(identity))
	run(`/interface/veth/add name=tikray-ctl address=172.27.248.2/29 gateway=172.27.248.1 comment="tikray:veth-ctl"; /container/envs/add list=tikray key=TIKRAY_DATA value="/data" comment="tikray:env-ctl-data"; /container/mounts/add list=tikray src=disk1/tikray-phases/data dst=/data mode=rw comment="tikray:mount-tikray-data"`)
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
	source := `{
` + string(watch) + `
:local ready do={:return ([:len [/system/script/find where name="m3-stall-health"]]=0)}
:local pause do={:return false}
:local ok [$wdImage "disk1/tikray-phases/data" "` + identity + `" 172.27.248.1 $ready $pause]
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
		write("image-update.json", map[string]any{"version": 1, "installation_id": identity, "component": "tikray", "previous": from, "candidate": to, "selection_digest": strings.Repeat("a", 64), "phase": "requested", "nonce": n, "started": 1000, "deadline": 1300})
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
	// The first invocation imports exactly the candidate. A changed staged
	// checksum is refused without stopping or removing the healthy old row.
	bad := maps.Clone(second)
	bad["chain"] = strings.Repeat("f", 128)
	req(nonce, first, bad)
	if err := tick(); err != "" || !isLive(first) || run(`:put [:len [/file/find where name="disk1/tikray-phases/data/state/image-update.json"]]`) != "0" {
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
	if err := tick(); err != "" {
		t.Fatal("commit:", err)
	}
	if run(`:put [:len [/file/find where name="disk1/tikray-phases/data/state/image-update.json"]]`) != "0" {
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
	if run(`:put [:len [/file/find where name="disk1/tikray-phases/data/state/image-update.json"]]`) != "1" {
		t.Fatal("unhealthy recovery cleared its marker")
	}
	run(`/system/script/remove [find name=m3-stall-health]`)
	if err := tick(); err != "" {
		t.Fatal("restore proof:", err)
	}
	if run(`:put [:len [/file/find where name="disk1/tikray-phases/data/state/image-update.json"]]`) != "0" || !isLive(second) {
		t.Fatal("healthy restoration did not finish")
	}
	t.Log("signed-content identities, tamper refusal, commit, deadline rollback and verified recovery passed")
}

func nativeProbeArchive(t *testing.T, label string) ([]byte, string) {
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
	layer := tarFile(map[string][]byte{"pause": bin})
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
