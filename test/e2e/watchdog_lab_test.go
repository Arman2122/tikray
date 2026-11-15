//go:build lab

package e2e

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/test/lab"
)

const (
	healthyImageVersion = "6.0.1"
	offlineImageVersion = "6.0.2"
	imageRequestFile    = dataRoot + "/state/image-update.json"
)

func TestM3Watchdog(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Minute)
	defer cancel()
	// make lab can build a temporary signed publisher directly on the
	// Linux host. An isolated wrapper receives an already published set.
	if os.Getenv("TIKRAY_LAB_IMAGES") == "" {
		channel, err := lab.ResolveChannel(ctx, "", env("TIKRAY_LAB_CHANNEL", "stable"))
		if err != nil {
			t.Fatal("could not resolve signed watchdog lab target")
		}
		dest := filepath.Join(t.TempDir(), "bundles")
		build := exec.CommandContext(ctx, "bash", "scripts/build-watchdog-lab.sh", dest, labArch().GOARCH())
		build.Dir = repoRoot()
		if build.Run() != nil {
			t.Fatal("could not build signed watchdog lab fixtures; see scripts/build-watchdog-lab.sh")
		}
		t.Setenv("TIKRAY_LAB_IMAGES", filepath.Join(dest, channel+"-"+string(labArch())))
	}
	if os.Getenv("TIKRAY_LAB_INSTALLER") == "" {
		t.Setenv("TIKRAY_LAB_INSTALLER", filepath.Join(os.Getenv("TIKRAY_LAB_IMAGES"), "install.rsc"))
	}
	l := &Lab{Version: env("TIKRAY_LAB_CHANNEL", "stable"), Arch: labArch()}
	check := l.recordM3Checks(t, "m3-watchdog")
	for _, tc := range []struct {
		name string
		run  func(context.Context, *testing.T, *routingLab)
	}{
		{"control_restart", func(ctx context.Context, t *testing.T, f *routingLab) { f.checkedRestart(ctx, t, "tikray") }},
		{"runner_restart", func(ctx context.Context, t *testing.T, f *routingLab) { f.checkedRestart(ctx, t, "runner") }},
		{"control_update_and_revert", func(ctx context.Context, t *testing.T, f *routingLab) { f.checkedImages(ctx, t, "tikray") }},
		{"runner_update_and_revert", func(ctx context.Context, t *testing.T, f *routingLab) { f.checkedImages(ctx, t, "runner") }},
		{"reboot_mid_update", func(ctx context.Context, t *testing.T, f *routingLab) { f.checkedImageReboot(ctx, t) }},
	} {
		check(tc.name, func(st *testing.T) {
			// Reboot and rollback each need a known baseline. A case never
			// edits another case's previous-image lineage or peer policy.
			f := deployRouting(ctx, st, st)
			l.Version = f.Version
			f.setClientPolicy(ctx, st, fullOpen)
			tc.run(ctx, st, f)
		})
	}
}

func imageContainer(component string) string {
	if component == "runner" {
		return "tikray-runner"
	}
	return "tikray"
}

type imageAcceptance = artifacts.ImageOperation
type imageStatus = artifacts.ImageStatus

var archiveDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var imageNonce = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (f *routingLab) imageAPI() authLabClient {
	return authLabClient{base: f.api.BaseURL, http: f.api.HTTPClient(), bearer: f.api.Token}
}
func (f *routingLab) imageStatus(ctx context.Context, t *testing.T, component string) imageStatus {
	t.Helper()
	var s imageStatus
	f.imageAPI().call(t, ctx, http.MethodGet, "/v1/images/"+component, nil, http.StatusOK).decode(t, &s)
	if s.Component != component || !archiveDigest.MatchString(s.Active) || s.Previous != "" && !archiveDigest.MatchString(s.Previous) {
		t.Fatal("could not verify the active image receipt")
	}
	return s
}
func (f *routingLab) imageRequest(ctx context.Context, t *testing.T, component, op, version string, code int) imageAcceptance {
	t.Helper()
	var body any
	if op == "update" {
		body = map[string]string{"version": version}
	}
	res := f.imageAPI().call(t, ctx, http.MethodPost, "/v1/images/"+component+"/"+op, body, code)
	var accepted imageAcceptance
	if code == http.StatusAccepted {
		res.decode(t, &accepted)
		if accepted.Component != component || !imageNonce.MatchString(accepted.OperationID) || !archiveDigest.MatchString(accepted.From) || !archiveDigest.MatchString(accepted.To) || accepted.From == accepted.To {
			t.Fatal("missing image operation or verified distinct release identities")
		}
	}
	return accepted
}

type testedArchive struct{ digest, imageID string }

// The saved Docker config hash identifies the actual imported image. Its tar
// digest separately identifies the bytes authenticated by the controller.
func identifyArchive(t *testing.T, file string) testedArchive {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal("signed lab image fixture unavailable; build it with scripts/build-watchdog-lab.sh")
	}
	defer f.Close()
	sum := sha256.New()
	tee := io.TeeReader(f, sum)
	reader := tar.NewReader(tee)
	var config string
	for {
		h, e := reader.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal("invalid saved lab archive")
		}
		if h.Name != "manifest.json" {
			continue
		}
		if config != "" || h.Typeflag != tar.TypeReg || h.Size <= 0 || h.Size > 1<<20 {
			t.Fatal("ambiguous Docker save manifest")
		}
		var entries []struct{ Config string }
		if json.NewDecoder(io.LimitReader(reader, 1<<20)).Decode(&entries) != nil || len(entries) != 1 {
			t.Fatal("unusable image manifest")
		}
		config = strings.TrimSuffix(path.Base(entries[0].Config), ".json")
	}
	if _, err = io.Copy(io.Discard, tee); err != nil || !archiveDigest.MatchString(config) {
		t.Fatal("unable to identify lab image")
	}
	return testedArchive{hex.EncodeToString(sum.Sum(nil)), config}
}

func (f *routingLab) stageImageFixture(ctx context.Context, t *testing.T, component, version string, corrupt bool) testedArchive {
	t.Helper()
	name := imageContainer(component) + "-" + f.Arch.GOARCH() + ".tar"
	dir := filepath.Join(filepath.Dir(f.controlTar), "updates", version)
	image := filepath.Join(dir, name)
	ref := identifyArchive(t, image)
	if corrupt {
		testCopy := filepath.Join(t.TempDir(), "damaged.tar")
		in, err := os.Open(image)
		if err != nil {
			t.Fatal("cannot open signature control")
		}
		out, err := os.Create(testCopy)
		if err != nil {
			in.Close()
			t.Fatal("cannot stage signature control")
		}
		_, copyErr := io.Copy(out, in)
		_, appendErr := out.Write([]byte("damaged after signing"))
		closeErr := out.Close()
		in.Close()
		if copyErr != nil || appendErr != nil || closeErr != nil {
			t.Fatal("could not alter signed archive for negative control")
		}
		image = testCopy
	}
	dst := dataRoot + "/inbox"
	for _, part := range []string{"images", version} {
		dst += "/" + part
		f.mustRun(ctx, t, `:if ([:len [/file/find where name="`+dst+`"]] = 0) do={/file/add type=directory name="`+dst+`"}`)
	}
	if f.CHR.Push(ctx, image, dst+"/"+name) != nil || f.CHR.Push(ctx, filepath.Join(dir, name+".sig"), dst+"/"+name+".sig") != nil {
		t.Fatal("could not stage the public signed image fixture")
	}
	return ref
}

type containerWitness struct {
	id, imageID, root string
	settings          map[string]string
}

const containerProps = ".id,name,comment,image-id,root-dir,interface,envlists,mountlists,dns,hostname,memory-high,memory-max,start-on-boot,restart-policy,cmd"

func (f *routingLab) containerImage(ctx context.Context, component string) (containerWitness, bool) {
	name := imageContainer(component)
	rows, e := f.ros.CommandAt(ctx, f.ros.Generation(), []string{"/container/print", "?name=" + name, "?comment=tikray:" + component, "=.proplist=" + containerProps})
	if e != nil || len(rows) != 1 {
		return containerWitness{}, false
	}
	r := rows[0]
	if r[".id"] == "" || r["name"] != name || r["comment"] != "tikray:"+component {
		return containerWitness{}, false
	}
	id := strings.TrimPrefix(strings.TrimSpace(r["image-id"]), "sha256:")
	w := containerWitness{id: r[".id"], imageID: id, root: strings.TrimPrefix(r["root-dir"], "/"), settings: map[string]string{}}
	for _, k := range strings.Split("interface,envlists,mountlists,dns,hostname,memory-high,memory-max,start-on-boot,restart-policy,cmd", ",") {
		w.settings[k] = r[k]
	}
	return w, archiveDigest.MatchString(id) && w.root != ""
}

func (f *routingLab) requireImage(ctx context.Context, t *testing.T, c string, want testedArchive) containerWitness {
	t.Helper()
	var row containerWitness
	_, ok := poll(ctx, 5*time.Minute, time.Second, func() bool {
		var present bool
		row, present = f.containerImage(ctx, c)
		return present && row.imageID == want.imageID
	})
	if !ok {
		t.Fatal("selected container did not report the expected Docker config digest", c)
	}
	return row
}

func (f *routingLab) scheduler(ctx context.Context, t *testing.T, enabled bool) {
	t.Helper()
	id := f.taggedID(ctx, t, "/system/scheduler", "tikray:watchdog-scheduler")
	if id == "" {
		t.Fatal("production watchdog scheduler missing")
	}
	f.routingWrite(ctx, t, "/system/scheduler/set", "=.id="+id, "=disabled="+strconv.FormatBool(!enabled))
	out := f.readROS(ctx, t, "/system/scheduler", "name,disabled,on-event,interval", "?.id="+id)
	if len(out) != 1 || out[0]["name"] != "tikray-watchdog" || out[0]["on-event"] != "tikray-watchdog" || out[0]["disabled"] != strconv.FormatBool(!enabled) {
		t.Fatal("production scheduler state not verified")
	}
	if !enabled {
		_, ok := poll(ctx, 30*time.Second, 250*time.Millisecond, func() bool {
			return f.mustRun(ctx, t, `:put [:len [/system/script/job/find where script="tikray-watchdog"]]`) == "0"
		})
		if !ok {
			t.Fatal("watchdog did not idle before owner fixture")
		}
	}
}
func (f *routingLab) containerAction(ctx context.Context, t *testing.T, component, action, state string) {
	t.Helper()
	id := f.taggedID(ctx, t, "/container", "tikray:"+component)
	if id == "" {
		t.Fatal("owned container missing")
	}
	f.routingWrite(ctx, t, "/container/"+action, "=.id="+id)
	if f.waitForContainer(ctx, imageContainer(component), state) != nil {
		t.Fatal("container state change did not complete", component, state)
	}
}

func (f *routingLab) imageOperation(ctx context.Context, t *testing.T, component, op, version string, from, to string) imageAcceptance {
	t.Helper()
	f.scheduler(ctx, t, false)
	q := f.imageRequest(ctx, t, component, op, version, http.StatusAccepted)
	if q.From != from || q.To != to {
		t.Fatal("accepted digests differ from independently verified archives")
	}
	var m struct {
		Version                 int `json:"version"`
		Phase, Component, Nonce string
		InstallationID          string `json:"installation_id"`
		Candidate, Previous     struct{ Digest string }
	}
	if json.Unmarshal(f.exactFile(ctx, t, imageRequestFile), &m) != nil || m.InstallationID != f.checkHealthIdentity(ctx, t) || m.Version != 1 || m.Component != component || m.Nonce != q.OperationID || m.Candidate.Digest != to || m.Previous.Digest != from || m.Phase != "requested" {
		t.Fatal("durable private request does not identify exactly the two image choices")
	}
	if got := f.imageStatus(ctx, t, component); got.Pending == nil || *got.Pending != q || got.Active != from {
		t.Fatal("pending operation did not match the durable request")
	}
	other := "runner"
	if component == "runner" {
		other = "tikray"
	}
	f.imageRequest(ctx, t, component, "update", healthyImageVersion, http.StatusConflict)
	f.imageRequest(ctx, t, other, "update", healthyImageVersion, http.StatusConflict)
	t.Logf("%s %s: explicit operation accepted with both digests and exclusive ownership", component, op)
	f.scheduler(ctx, t, true)
	return q
}

func (f *routingLab) waitImageCompletion(ctx context.Context, t *testing.T, component string, expected testedArchive, wantPrev string, baseline containerWitness) {
	t.Helper()
	_, ok := poll(ctx, 13*time.Minute, 2*time.Second, func() bool {
		pending, e := f.exists(ctx, imageRequestFile)
		if e != nil || pending {
			return false
		}
		r, ok := f.containerImage(ctx, component)
		return ok && r.imageID == expected.imageID
	})
	if !ok {
		// Never include router replies, pending data or the unfiltered log.
		rows := f.readROS(ctx, t, "/system/script", "comment", "?name=tikray-image-transition")
		phase := "absent"
		age := -1
		if len(rows) == 1 {
			phase = "unclassified"
			var j struct {
				Phase string
				Age   int
			}
			if json.Unmarshal([]byte(strings.TrimPrefix(rows[0]["comment"], "tikray:image-transition ")), &j) == nil && j.Age >= 0 && j.Age <= 300 {
				for _, allowed := range []string{"replace", "verify", "restore", "recover", "commit", "committed", "reverted"} {
					if j.Phase == allowed {
						phase, age = allowed, j.Age
						break
					}
				}
			}
		}
		r, visible := f.containerImage(ctx, component)
		t.Fatalf("image verification timed out: component=%s phase=%s age=%d native_visible=%t expected_image=%t", component, phase, age, visible, r.imageID == expected.imageID)
	}
	t.Logf("%s: verified runtime bytes and retired operation", component)
	f.checkReady(ctx, t)
	s := f.imageStatus(ctx, t, component)
	if s.Active != expected.digest || s.Previous != wantPrev || s.Pending != nil {
		t.Fatal("committed image receipt is inconsistent with the recovered container")
	}
	row := f.requireImage(ctx, t, component, expected)
	if !maps.Equal(row.settings, baseline.settings) {
		t.Fatal("image replacement changed the owned container settings", component)
	}
}

type proxyStream struct {
	count  atomic.Uint64
	failed atomic.Bool
}

func (f *routingLab) imageStream(ctx context.Context, t *testing.T, port int) *proxyStream {
	t.Helper()
	flow := f.tcpFlow(ctx, t, false, port)
	if !isRoutingProxy(flow.echo(t)) {
		t.Fatal("existing stream did not cross a live proxy")
	}
	scan, stop := context.WithCancel(ctx)
	s := new(proxyStream)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for scan.Err() == nil {
			if !isRoutingProxy(flow.exchange()) {
				s.failed.Store(true)
				return
			}
			s.count.Add(1)
			if sleep(scan, 500*time.Millisecond) != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		stop()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("proxy stream worker did not finish")
		}
	})
	return s
}
func (s *proxyStream) requireSince(t *testing.T, before uint64) {
	t.Helper()
	if s.failed.Load() || s.count.Load() <= before {
		t.Fatal("established proxied traffic stopped across control image change")
	}
}

// Exercise simultaneous open and closed clients using fresh UDP tuples.
func (f *routingLab) imageWAN(ctx context.Context, t *testing.T) *routingWAN {
	t.Helper()
	f.setClientPolicy(ctx, t, store.Policy{Mode: store.ModeFull, KillSwitch: true})
	if _, err := f.api.SetDevice(ctx, store.Device{Address: netip.MustParsePrefix(routingPeer + "/32"), MAC: f.peerMAC, Policy: fullOpen}); err != nil {
		t.Fatal("could not set open LAN control")
	}
	f.checkReady(ctx, t)
	if !isRoutingProxy(f.peerEgress(ctx, routingRemote)) {
		t.Fatal("open peer did not demonstrate a real proxy before outage")
	}
	wan := newRoutingWAN(ctx, t, f)
	// Fresh source ports force independent bindings across the loss and return.
	emit := `import socket,sys,time
while True:
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
  s.bind((sys.argv[1],0));s.sendto(sys.argv[2].encode(),(sys.argv[3],31947))
 time.sleep(.15)`
	startRoutingProcess(t, f.Net.Client(ctx, "python3", "-c", emit, "192.168.88.10", "C", routingRemote))
	startRoutingProcess(t, f.peer(ctx, "python3", "-c", emit, routingPeer, "D", routingRemote))
	_, ok := poll(ctx, 20*time.Second, 300*time.Millisecond, func() bool { return wan.sample(t).closedProxy > 0 })
	if !ok || wan.sample(t).closedDirect != 0 {
		t.Fatal("missing healthy positive closed-path control")
	}
	return wan
}

// f.protocolDNS requires a real DNS answer. During an unverified runner
// replacement only open clients may use the router's WAN DNS. Observe the
// unique query labels on the WAN wire before kernel packet filtering.
func (f *routingLab) imageDNSFallback(ctx context.Context, t *testing.T) {
	t.Helper()
	capture := filepath.Join(t.TempDir(), "dns-count")
	listen := f.Net.Inet(ctx, "python3", "-c", `import socket,sys,struct
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800));s.bind(("wan0",0))
with open(sys.argv[1],"wb",buffering=0) as log:
 while True:
  packet=s.recv(65535)
  if len(packet)<42 or packet[12:14]!=b"\x08\x00" or packet[23] not in (6,17):continue
  start=14+4*(packet[14]&15)
  if len(packet)<start+8 or packet[start+2:start+4]!=b"\x00\x35":continue
  if b"wd-open-lookup" in packet[start+8:]:log.write(b"O")
  if b"wd-closed-lookup" in packet[start+8:]:log.write(b"C")`, capture)
	startRoutingProcess(t, listen)
	for _, proto := range []string{"udp", "tcp"} {
		now := strconv.FormatInt(time.Now().UnixNano(), 10)
		n := f.packets(ctx, t, "/ip/firewall/nat", "tikray:dns-router-full-open-"+proto)
		got := f.protocolDNS(ctx, t, true, now+".wd-open-lookup.routing-probe.test.", "A", proto, "203.0.113.53")
		if !slices.Equal(got, []string{"198.18.54.1"}) || f.packets(ctx, t, "/ip/firewall/nat", "tikray:dns-router-full-open-"+proto) <= n {
			t.Fatal("open DNS did not reach the owner's resolver through verified redirect", proto)
		}
		args := []string{"+noall", "+answer", "+time=2", "+tries=1", "@203.0.113.53", now + ".wd-closed-lookup.routing-probe.test.", "A"}
		if proto == "tcp" {
			args = append(args, "+tcp")
		}
		out, _ := f.Net.Client(ctx, "dig", args...).Output()
		if hasIPv4Answer(out) {
			t.Fatal("closed client received a DNS answer through an unavailable runner", proto)
		}
	}
	read := func() string { b, _ := os.ReadFile(capture); return string(b) }
	_, positive := poll(ctx, 5*time.Second, 250*time.Millisecond, func() bool { return strings.Count(read(), "O") >= 2 })
	if !positive || strings.Contains(read(), "C") {
		t.Fatal("WAN DNS capture lacked both open controls or observed a direct closed query")
	}
}

func (f *routingLab) checkedRestart(ctx context.Context, t *testing.T, component string) {
	t.Helper()
	kind := "runner"
	if component == "runner" {
		kind = "control-start"
	}
	f.scheduler(ctx, t, false)
	tick := f.watchdogTicker(ctx, t)
	tick()
	other := f.probe(ctx, t, kind)
	active := f.activeImageSelection(ctx, t)
	ssh := f.ownerLANSSH(ctx, t)
	var wan *routingWAN
	var openBase int
	var stream *proxyStream
	if component == "runner" {
		wan = f.imageWAN(ctx, t)
		active = f.activeImageSelection(ctx, t)
		openBase = wan.sample(t).peerDirect
	} else {
		stream = f.imageStream(ctx, t, 31874)
	}
	f.containerAction(ctx, t, component, "stop", "stopped")
	if wan != nil {
		_, ok := poll(ctx, 80*time.Second, time.Second, func() bool { return wan.sample(t).peerDirect > openBase })
		if !ok || wan.sample(t).closedDirect != 0 || f.peerEgress(ctx, routingRemote) != egressDirect {
			t.Fatal("runner loss did not distinguish closed and open WAN egress")
		}
	}
	count := func() int {
		rows := f.readROS(ctx, t, "/system/scheduler", "run-count", "?name=tikray-watchdog", "?comment=tikray:watchdog-scheduler")
		if len(rows) != 1 {
			t.Fatal("missing scheduler count")
		}
		v, e := strconv.Atoi(rows[0]["run-count"])
		if e != nil {
			t.Fatal("unreadable scheduler count")
		}
		return v
	}
	last := count()
	f.scheduler(ctx, t, true)
	for miss := 1; miss <= 3; miss++ {
		_, ok := poll(ctx, 85*time.Second, 300*time.Millisecond, func() bool {
			n := count()
			if n < last {
				last = n
				return false
			}
			if n == last {
				return false
			}
			if n != last+1 {
				t.Fatal("could not establish consecutive scheduler invocations")
			}
			last = n
			return true
		})
		if !ok {
			t.Fatal("missing production minute execution", component, miss)
		}
		if miss < 3 {
			if sleep(ctx, 2*time.Second) != nil {
				t.Fatal("watchdog observation cancelled")
			}
			_, ok = poll(ctx, 20*time.Second, 300*time.Millisecond, func() bool {
				return f.mustRun(ctx, t, `:put [:len [/system/script/job/find where script="tikray-watchdog"]]`) == "0"
			})
			rows := f.readROS(ctx, t, "/container", ".id", "?name="+imageContainer(component), "?comment=tikray:"+component, "?stopped=true")
			if !ok || len(rows) != 1 {
				t.Fatal("component recovered before its third consecutive scheduler miss", component, miss)
			}
			ssh()
		}
	}
	if f.waitForContainer(ctx, imageContainer(component), "running") != nil {
		t.Fatal("component did not recover at the third missed probe")
	}
	f.checkReady(ctx, t)
	if f.probe(ctx, t, kind) != other || f.activeImageSelection(ctx, t) != active {
		t.Fatal("independent component or saved selection changed during restart")
	}
	ssh()
	f.expectPath(ctx, t, routingRemote, true)
	if stream != nil {
		stream.requireSince(t, 0)
	}
	if wan != nil {
		// A running xray can precede RouterOS's next gateway check. Keep
		// both emitters alive through that interval and verify fresh egress.
		_, restored := poll(ctx, f.proxiedWithin(), time.Second, func() bool { return isRoutingProxy(f.peerEgress(ctx, routingRemote)) })
		s := wan.sample(t)
		if !restored || s.closedDirect != 0 || s.unknown != 0 || s.peerDirect <= openBase {
			t.Fatalf("runner recovery proof failed: open_proxy=%t closed_wan=%d unknown=%d open_wan=%d", restored, s.closedDirect, s.unknown, s.peerDirect-openBase)
		}
	}
}

func (f *routingLab) activeImageSelection(ctx context.Context, t *testing.T) runnerapi.Selection {
	t.Helper()
	var a runnerapi.Selection
	if json.Unmarshal(f.exactFile(ctx, t, dataRoot+"/run/active.json"), &a) != nil || a.Validate() != nil {
		t.Fatal("cannot verify the current committed runner selection")
	}
	return a
}

func (f *routingLab) checkedImages(ctx context.Context, t *testing.T, component string) {
	t.Helper()
	var wan *routingWAN
	if component == "runner" {
		wan = f.imageWAN(ctx, t)
	}
	initial := identifyArchive(t, map[string]string{"tikray": f.controlTar, "runner": f.runnerTar}[component])
	receipt := f.imageStatus(ctx, t, component)
	if receipt.Active != initial.digest || receipt.Pending != nil || receipt.Previous != "" {
		t.Fatal("installed baseline is not the verified image")
	}
	// A fresh installation has no authorized rollback target yet.
	f.imageRequest(ctx, t, component, "rollback", "", http.StatusConflict)
	base := f.requireImage(ctx, t, component, initial)
	selection := f.activeImageSelection(ctx, t)
	statePath := dataRoot + "/state/state.v" + strconv.Itoa(store.Current) + ".json"
	beforeState := sha256.Sum256(f.exactFile(ctx, t, statePath))
	ownerSSH := f.ownerLANSSH(ctx, t)
	generation := f.ros.Generation()
	other, kind := "runner", "runner"
	if component == "runner" {
		other, kind = "tikray", "control-start"
	}
	otherImage, ok := f.containerImage(ctx, other)
	if !ok {
		t.Fatal("missing independent component before replacement")
	}
	otherProcess := f.probe(ctx, t, kind)
	changedProbe := "control-start"
	if component == "runner" {
		changedProbe = "runner"
	}
	priorProcess := f.probe(ctx, t, changedProbe)
	verifySibling := func() {
		t.Helper()
		ownerSSH()
		r, ok := f.containerImage(ctx, other)
		if f.ros.Generation() != generation || !ok || r.id != otherImage.id || r.imageID != otherImage.imageID || f.probe(ctx, t, kind) != otherProcess || f.activeImageSelection(ctx, t) != selection {
			t.Fatal("replacement changed its sibling, selection or owner session")
		}
		f.checkOwnerRules(ctx, t)
	}
	// Run the authenticated owner operation with a byte changed AFTER
	// signing. No request, row replacement or slot claim may result.
	f.stageImageFixture(ctx, t, component, healthyImageVersion, true)
	f.imageRequest(ctx, t, component, "update", healthyImageVersion, http.StatusUnprocessableEntity)
	if p, e := f.exists(ctx, imageRequestFile); e != nil || p {
		t.Fatal("tampered archive created an update marker")
	}
	if row, _ := f.containerImage(ctx, component); row.id != base.id {
		t.Fatal("tampered archive disrupted the installed component")
	}
	valid := f.stageImageFixture(ctx, t, component, healthyImageVersion, false)
	bad := f.stageImageFixture(ctx, t, component, offlineImageVersion, false)
	var stream *proxyStream
	if component == "tikray" {
		stream = f.imageStream(ctx, t, 31875)
	}
	f.imageOperation(ctx, t, component, "update", healthyImageVersion, initial.digest, valid.digest)
	f.waitImageCompletion(ctx, t, component, valid, initial.digest, base)
	updated := f.requireImage(ctx, t, component, valid)
	if f.probe(ctx, t, changedProbe) == priorProcess || f.file(ctx, t, updated.root+"/m3-qa-image-version") != healthyImageVersion {
		t.Fatal("candidate bytes were not imported and run")
	}
	f.expectPath(ctx, t, routingRemote, true)
	verifySibling()
	// Re-import the same signed installer while the newer release is
	// active. A baseline image in the installer must not replace it.
	f.requireSuccess(ctx, t)
	reimported := f.requireImage(ctx, t, component, valid)
	if reimported.id != updated.id || f.imageStatus(ctx, t, component).Active != valid.digest {
		t.Fatal("reimport replaced an already verified updated container")
	}
	verifySibling()
	if stream != nil {
		stream.requireSince(t, 0)
	}
	if component == "runner" {
		// The owner must be able to choose the verified previous release
		// even when the process in the current image cannot answer.
		f.scheduler(ctx, t, false)
		f.containerAction(ctx, t, component, "stop", "stopped")
	}
	f.imageOperation(ctx, t, component, "rollback", "", valid.digest, initial.digest)
	f.waitImageCompletion(ctx, t, component, initial, valid.digest, base)
	verifySibling()
	start := time.Now()
	q := f.imageOperation(ctx, t, component, "update", offlineImageVersion, initial.digest, bad.digest)
	trial := f.requireImage(ctx, t, component, bad)
	if f.waitForContainer(ctx, imageContainer(component), "running") != nil {
		t.Fatal("signed negative control never actually started")
	}
	t.Logf("%s: signed unhealthy candidate actually running", component)
	if f.file(ctx, t, trial.root+"/m3-qa-image-version") != offlineImageVersion {
		t.Fatal("unhealthy candidate not positively installed")
	}
	pending, e := f.exists(ctx, imageRequestFile)
	if e != nil || !pending {
		t.Fatal("unhealthy candidate cleared the request")
	}
	if component == "runner" {
		if f.mustRun(ctx, t, `:put ([/ping 172.30.252.3 count=3 interval=500ms]>0)`) != "true" {
			t.Fatal("unhealthy runner positive ping control missing")
		}
		if s := f.imageStatus(ctx, t, component); s.Active != initial.digest || s.Pending == nil || s.Pending.OperationID != q.OperationID {
			t.Fatal("a mere ping admitted a runner without its data path")
		}
		openBase := wan.sample(t).peerDirect
		_, fallback := poll(ctx, 55*time.Second, time.Second, func() bool {
			return f.peerEgress(ctx, routingRemote) == egressDirect && wan.sample(t).peerDirect > openBase
		})
		if !fallback || wan.sample(t).closedDirect != 0 || wan.sample(t).unknown != 0 {
			t.Fatal("unverified running runner failed its open WAN or closed leak check")
		}
		f.imageDNSFallback(ctx, t)
		ownerSSH()
		f.ownerPortForward(ctx, t)
		if pending, e := f.exists(ctx, imageRequestFile); e != nil || !pending {
			t.Fatal("unverified runner was accepted during fallback tests")
		}
	} else {
		pctx, done := context.WithTimeout(ctx, 2*time.Second)
		err := f.api.Healthz(pctx)
		done()
		if err == nil {
			t.Fatal("intentionally unavailable control answered its pinned health probe")
		}
		future := dataRoot + "/state/state.v" + strconv.Itoa(store.Current+1) + ".json"
		if f.file(ctx, t, future) != `{"lab":"future schema"}` || sha256.Sum256(f.exactFile(ctx, t, statePath)) != beforeState {
			t.Fatal("simulated migration failed to preserve the previous version's state")
		}
		stream.requireSince(t, 0)
	}
	f.waitImageCompletion(ctx, t, component, initial, valid.digest, base)
	if time.Since(start) < 4*time.Minute || time.Since(start) > 16*time.Minute {
		t.Fatal("unhealthy image did not honor the bounded recovery window")
	}
	if sha256.Sum256(f.exactFile(ctx, t, statePath)) != beforeState {
		t.Fatal("rollback did not preserve the prior versioned state")
	}
	f.expectPath(ctx, t, routingRemote, true)
	verifySibling()
	if stream != nil {
		stream.requireSince(t, 0)
	}
	if wan != nil {
		_, ok := poll(ctx, f.proxiedWithin(), time.Second, func() bool { return isRoutingProxy(f.peerEgress(ctx, routingRemote)) })
		if !ok || wan.sample(t).closedDirect != 0 || wan.sample(t).unknown != 0 {
			t.Fatal("runner update or restore leaked from a closed client or lost the recovered open path")
		}
	}
}

// The service's immutable request says what to attempt; RouterOS alone
// stores the current phase and monotonic time spent checking the candidate.
func (f *routingLab) imageTrialAge(ctx context.Context, nonce string) (int, bool) {
	const prefix = "tikray:image-transition "
	rows, err := f.ros.CommandAt(ctx, f.ros.Generation(), []string{"/system/script/print", "?name=tikray-image-transition", "=.proplist=source,comment"})
	if err != nil || len(rows) != 1 || rows[0]["source"] != "" {
		return 0, false
	}
	b, ok := strings.CutPrefix(rows[0]["comment"], prefix)
	var j struct {
		Nonce, Phase string
		Age          int
	}
	if !ok || len(b) > 4096 || json.Unmarshal([]byte(b), &j) != nil || j.Nonce != nonce || j.Phase != "verify" || j.Age < 0 || j.Age >= 300 {
		return 0, false
	}
	return j.Age, true
}

func (f *routingLab) checkedImageReboot(ctx context.Context, t *testing.T) {
	t.Helper()
	const c = "tikray"
	before := f.imageStatus(ctx, t, c)
	initial := identifyArchive(t, f.controlTar)
	if before.Active != initial.digest {
		t.Fatal("reboot fixture requires verified baseline")
	}
	base := f.requireImage(ctx, t, c, initial)
	bad := f.stageImageFixture(ctx, t, c, offlineImageVersion, false)
	active := f.activeImageSelection(ctx, t)
	started := time.Now()
	q := f.imageOperation(ctx, t, c, "update", offlineImageVersion, initial.digest, bad.digest)
	broken := f.requireImage(ctx, t, c, bad)
	if f.waitForContainer(ctx, imageContainer(c), "running") != nil {
		t.Fatal("reboot candidate never ran")
	}
	if f.file(ctx, t, broken.root+"/m3-qa-image-version") != offlineImageVersion {
		t.Fatal("power interruption missed the candidate image")
	}
	age := 0
	_, ok := poll(ctx, 3*time.Minute, 500*time.Millisecond, func() bool {
		n, visible := f.imageTrialAge(ctx, q.OperationID)
		if visible && n >= 50 && n < 180 {
			age = n
			return true
		}
		return false
	})
	if !ok {
		t.Fatal("native scheduler did not durably measure candidate time")
	}
	// Move wall time past the requested deadline while the candidate is
	// still unhealthy. One actual subsequent tick must spend only its
	// elapsed uptime and must not consume the six-hour clock jump.
	wall := time.Now().UTC().Add(6 * time.Hour)
	f.mustRun(ctx, t, "/system/clock/set date="+wall.Format("2006-01-02")+" time="+wall.Format("15:04:05"))
	_, ok = poll(ctx, 85*time.Second, 500*time.Millisecond, func() bool {
		n, visible := f.imageTrialAge(ctx, q.OperationID)
		if visible && n > age && n <= age+60 {
			age = n
			return true
		}
		return false
	})
	if !ok {
		t.Fatal("clock change expired or froze a live update")
	}
	// Prove no service on either veth can be responsible for the native
	// scheduler at the interruption. Never manufacture or edit its journal.
	f.containerAction(ctx, t, "runner", "stop", "stopped")
	f.containerAction(ctx, t, c, "stop", "stopped")
	if pending, e := f.exists(ctx, imageRequestFile); e != nil || !pending {
		t.Fatal("no durable operation at power cut")
	}
	f.ros.Close()
	if f.CHR.PowerCycle(ctx) != nil {
		t.Fatal("real CHR power cycle failed")
	}
	f.ros = f.ownerSession(ctx, t)
	post, retained := f.imageTrialAge(ctx, q.OperationID)
	if !retained || post < age || post > age+60 {
		t.Fatal("reboot reset or prematurely spent the native image budget")
	}
	now := time.Now().UTC()
	f.mustRun(ctx, t, "/system/clock/set date="+now.Format("2006-01-02")+" time="+now.Format("15:04:05"))
	f.waitImageCompletion(ctx, t, c, initial, before.Previous, base)
	if time.Since(started) < 4*time.Minute || time.Since(started) > 17*time.Minute {
		t.Fatal("reboot produced an unbounded or premature image fallback")
	}
	if f.activeImageSelection(ctx, t) != active {
		t.Fatal("reboot recovery lost the previously committed xray selection")
	}
	f.expectPath(ctx, t, routingRemote, true)
	f.ownerLogin(ctx, t)
	f.checkOwnerRules(ctx, t)
}
