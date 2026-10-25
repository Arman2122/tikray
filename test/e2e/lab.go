//go:build lab

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xrayver"
	"github.com/Arman2122/tikray/test/lab"
	"github.com/Arman2122/tikray/test/lab/fixtures/labinet"
)

// The runner's control API, which the host reaches through the lab's host
// route to the tikray bridge.
const runnerURL = "http://172.31.255.3:8080"

// xrayAPI is where xray's gRPC API listens, on the runner's address: the
// "api" block of config/xray-client.json says so (JSON cannot refer to this
// constant, so the two must agree), and so does the state-derived default of
// tikray's health check (TIKRAY_XRAY_API).
const xrayAPI = "172.31.255.3:10085"

// Paths on the router.
const (
	dataRoot      = lab.DataRoot
	lastResult    = dataRoot + "/state/last-result.json"
	indexKey      = dataRoot + "/state/index.pub"
	runnerToken   = dataRoot + "/run/runner.token"
	candidateFile = dataRoot + "/run/candidate.json"
	coresDir      = dataRoot + "/cores"
	inboxDir      = dataRoot + "/inbox"
)

// statePath is the state file on the router, where tikray reads it.
var statePath = fmt.Sprintf("%s/state/state.v%d.json", dataRoot, store.Current)

// clientConfig is the xray client config as the tikray container sees it.
const clientConfig = "/data/inbox/xray-client.json"

// The xray-core releases the test installs, besides the newest one.
const (
	oldestXray   = "26.1.18" // the first release with the TUN inbound
	previousXray = "26.3.27"
	rejectedXray = "99.0.1" // a fake that fails xray run -test; no .dgst anywhere, only ever in the inbox
	crashingXray = "99.0.2" // a fake that exits 2 s after it starts
)

// Lab is a CHR with tikray deployed: the tikray-runner and tikray containers
// from the real images, the RouterOS objects of routeros/m1-setup.rsc, and
// the fake internet with a fake GitHub (203.0.113.40) and a mirror with a
// signed hash index (203.0.113.41) serving Releases.
type Lab struct {
	Net     *lab.Network
	CHR     *lab.CHR
	Arch    lab.Arch
	Version string // RouterOS
	Newest  string // the newest xray-core release, such as 26.10.21
	Asset   string // the release zip for the CHR's arch, such as Xray-linux-64.zip
	// Releases is the root the fake GitHub and the mirror serve. Flag files
	// in it switch them (see labinet.ReleasesHandler).
	Releases string
	// Zips holds every zip the test built, by version, including the one
	// kept out of Releases.
	Zips map[string]string
}

// runnerAPI is the runner's control API with the token the runner wrote. Deploy
// sets it once the runner answers.
var runnerAPI *runnerapi.Client

func e2eDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

func repoRoot() string { return filepath.Join(e2eDir(), "..", "..") }

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// labArch is the CHR architecture under test: $TIKRAY_LAB_ARCH, x86_64 by
// default.
func labArch() lab.Arch { return lab.Arch(env("TIKRAY_LAB_ARCH", string(lab.ArchX86))) }

// Deploy brings the lab up for $TIKRAY_LAB_CHANNEL (default stable) and
// $TIKRAY_LAB_ARCH (default x86_64) and tears it down when t ends. The work
// dir, with the VM's console.log and harness.log and the releases, is kept
// when the test fails.
func Deploy(ctx context.Context, t *testing.T) *Lab {
	t.Helper()
	runnerAPI = nil
	l := &Lab{Arch: labArch(), Zips: map[string]string{}}
	var err error
	if l.Version, err = lab.ResolveChannel(ctx, "", env("TIKRAY_LAB_CHANNEL", "stable")); err != nil {
		t.Fatal(err)
	}
	art, err := lab.FetchCHR(ctx, "", lab.CacheDir(), l.Version, l.Arch)
	if err != nil {
		t.Fatal(err)
	}
	goarch := l.Arch.GOARCH()
	if l.Asset, err = xrayver.AssetName(goarch); err != nil {
		t.Fatal(err)
	}

	wd, err := os.MkdirTemp("", "tikray-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("kept work dir %s", wd)
			return
		}
		os.RemoveAll(wd)
	})
	runnerImage, tikrayImage, err := buildImages(ctx, goarch)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := l.buildReleases(ctx, wd, goarch)
	if err != nil {
		t.Fatal(err)
	}
	pubFile := filepath.Join(wd, "index.pub")
	if err := os.WriteFile(pubFile, pub, 0o644); err != nil {
		t.Fatal(err)
	}

	if l.Net, err = lab.SetupNetwork(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Net.Teardown() })
	stopInet, err := lab.StartInetWith(ctx, l.Net, lab.InetOptions{ReleasesDir: l.Releases})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stopInet)

	if l.CHR, err = lab.BootReadyCHR(ctx, l.Net, lab.BootOptions{
		Version: l.Version, Arch: l.Arch, Artifacts: art, WorkDir: filepath.Join(wd, "vm"), Password: "tikray-lab",
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.CHR.Shutdown() })
	c := l.CHR
	if err := c.EnableContainers(ctx); err != nil {
		t.Fatal(err)
	}
	// The runner's read-only geo mount needs its source directory.
	if ok, err := l.exists(ctx, dataRoot+"/geo"); err != nil {
		t.Fatal(err)
	} else if !ok {
		if _, err := c.Run(ctx, fmt.Sprintf(`/file/add type=directory name="%s/geo"`, dataRoot)); err != nil {
			t.Fatal(err)
		}
	}
	for local, remote := range map[string]string{
		runnerImage: "disk1/tikray/images/" + filepath.Base(runnerImage),
		tikrayImage: "disk1/tikray/images/" + filepath.Base(tikrayImage),
		pubFile:     indexKey,
		filepath.Join(e2eDir(), "config", "xray-client.json"): inboxDir + "/xray-client.json",
	} {
		if err := c.Push(ctx, local, remote); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Import(ctx, filepath.Join(e2eDir(), "routeros", "lab.rsc")); err != nil {
		t.Fatal(err)
	}
	setup, err := os.ReadFile(filepath.Join(e2eDir(), "routeros", "m1-setup.rsc"))
	if err != nil {
		t.Fatal(err)
	}
	withArch := filepath.Join(wd, "m1-setup.rsc")
	if err := os.WriteFile(withArch, append([]byte(fmt.Sprintf(":global tikrayArch %q\n", goarch)), setup...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.Import(ctx, withArch); err != nil {
		t.Fatal(err)
	}
	if err := l.startContainers(ctx); err != nil {
		t.Fatal(err)
	}
	return l
}

// buildImages builds the tikray-runner and tikray images for goarch with
// scripts/build-images.sh into out/ and returns their archives.
func buildImages(ctx context.Context, goarch string) (runnerTar, tikrayTar string, err error) {
	out := filepath.Join(repoRoot(), "out")
	cmd := exec.CommandContext(ctx, "bash", filepath.Join(repoRoot(), "scripts", "build-images.sh"), goarch, out)
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("build images: %v\n%s", err, b)
	}
	return filepath.Join(out, "tikray-runner-"+goarch+".tar"), filepath.Join(out, "tikray-"+goarch+".tar"), nil
}

// moduleVersion is the Go module version of an xray-core release, which the
// lab builds from the module proxy: 26.1.18 is v1.260118.0.
func moduleVersion(v string) (string, error) {
	p, err := xrayver.Parse(v)
	if err != nil {
		return "", err
	}
	if p.Major > 99 || p.Minor > 99 || p.Patch > 99 {
		return "", fmt.Errorf("xray-core %s has no v1.YYMMDD.0 module version", v)
	}
	return fmt.Sprintf("v1.%02d%02d%02d.0", p.Major, p.Minor, p.Patch), nil
}

// fakeXray builds internal/runner/testdata/fakexray in mode for goarch into dir.
func fakeXray(ctx context.Context, dir, mode, goarch string) (string, error) {
	out := filepath.Join(dir, "fakexray-"+mode)
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags", "-X main.mode="+mode, "-o", out, "./internal/runner/testdata/fakexray")
	cmd.Dir = repoRoot()
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build fake xray %s: %v\n%s", mode, err, b)
	}
	return out, nil
}

// buildReleases builds a release zip per version: the real xray-core 26.1.18,
// 26.3.27 and the newest release, and the fakes 99.0.1 (badconfig) and 99.0.2
// (exit2s). All but 99.0.1 go into Releases with their .dgst, and LATEST
// names the newest release. 99.0.1 has no .dgst and is never published: an
// unverified core is only installed from the inbox. The signed hash index
// lists only 26.3.27; buildReleases returns the PEM key it is signed with.
func (l *Lab) buildReleases(ctx context.Context, wd, goarch string) ([]byte, error) {
	newestTag, err := lab.ResolveXrayVersion(ctx, "latest")
	if err != nil {
		return nil, err
	}
	if l.Newest, err = lab.XrayCoreVersion(newestTag); err != nil {
		return nil, err
	}
	newest, _ := xrayver.Parse(l.Newest)
	if prev, _ := xrayver.Parse(previousXray); !prev.Less(newest) {
		return nil, fmt.Errorf("the newest xray-core release %s is not newer than %s, which the test installs as an older one", l.Newest, previousXray)
	}
	bins := map[string]string{}
	for _, v := range []string{oldestXray, previousXray} {
		mod, err := moduleVersion(v)
		if err != nil {
			return nil, err
		}
		if bins[v], err = lab.XrayBinaryVersion(ctx, lab.CacheDir(), mod, goarch); err != nil {
			return nil, err
		}
	}
	if bins[l.Newest], err = lab.XrayBinaryVersion(ctx, lab.CacheDir(), newestTag, goarch); err != nil {
		return nil, err
	}
	for v, mode := range map[string]string{rejectedXray: "badconfig", crashingXray: "exit2s"} {
		if bins[v], err = fakeXray(ctx, filepath.Join(wd, "fakes"), mode, goarch); err != nil {
			return nil, err
		}
	}

	l.Releases = filepath.Join(wd, "releases")
	sums := map[string]string{}
	for v, bin := range bins {
		dir := filepath.Join(l.Releases, "v"+v)
		if v == rejectedXray {
			dir = filepath.Join(wd, "inbox-only", v)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		zip := filepath.Join(dir, l.Asset)
		if sums[v], err = labinet.MakeReleaseZip(zip, bin); err != nil {
			return nil, err
		}
		l.Zips[v] = zip
		if v == rejectedXray {
			continue
		}
		if err := labinet.WriteDgst(zip+".dgst", sums[v]); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(l.Releases, "LATEST"), []byte("v"+l.Newest+"\n"), 0o644); err != nil {
		return nil, err
	}
	return signIndex(filepath.Join(l.Releases, "index"), map[string]map[string]string{
		"v" + previousXray: {l.Asset: sums[previousXray]},
	})
}

// signIndex writes index.json and index.json.sig into dir, signed with a new
// ECDSA P-256 key the way tikray's CI signs the hash index (a cosign key-pair
// blob signature: base64 ASN.1 ECDSA over the SHA-256 of the file), and
// returns the public key as PEM.
func signIndex(dir string, files map[string]map[string]string) ([]byte, error) {
	data, err := json.MarshalIndent(artifacts.Index{Version: 1, Files: files}, "", "  ")
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), data, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json.sig"), []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// startContainers starts the runner and waits for its control API with the
// token it wrote, and waits for the tikray image to be extracted. Extraction
// takes minutes under emulation.
func (l *Lab) startContainers(ctx context.Context) error {
	d := 15 * time.Minute
	if l.Arch == lab.ArchARM64 {
		d = 45 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	c := l.CHR
	for {
		if runnerAPI == nil {
			if tok, err := c.Get(ctx, fileContents(runnerToken)); err == nil && tok != "" {
				runnerAPI = &runnerapi.Client{BaseURL: runnerURL, Token: tok, HTTP: &http.Client{Timeout: 30 * time.Second}}
			}
		}
		if runnerAPI != nil {
			if _, err := runnerStatus(ctx); err == nil {
				break
			}
		}
		c.Run(ctx, "/container/start [find name=tikray-runner]")
		if err := sleep(ctx, 10*time.Second); err != nil {
			out, _ := c.Run(context.Background(), "/container/print detail")
			return fmt.Errorf("tikray-runner did not come up: %v\n%s", err, out)
		}
	}
	if err := waitContainer(ctx, c, "tikray", "stopped"); err != nil {
		out, _ := c.Run(context.Background(), "/container/print detail")
		return fmt.Errorf("tikray image not extracted: %v\n%s", err, out)
	}
	return nil
}

// runnerStatus is the runner's GET /v1/status.
func runnerStatus(ctx context.Context) (runnerapi.Status, error) {
	if runnerAPI == nil {
		return runnerapi.Status{}, errors.New("the runner's token has not been read yet")
	}
	return runnerAPI.Status(ctx)
}

// runTikray runs the tikray CLI once: it sets the tikray container's cmd to
// args (the image's ENTRYPOINT is /tikray), starts it, waits for it to stop,
// and returns the result it saved in state/last-result.json. The CLI removes
// that file before it does anything else and writes it last, so a missing
// file after the container stopped means the run did not finish.
func runTikray(ctx context.Context, c *lab.CHR, args string) (artifacts.Result, error) {
	var res artifacts.Result
	d := 5 * time.Minute
	if labArch() == lab.ArchARM64 {
		d = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	if err := waitContainer(ctx, c, "tikray", "stopped"); err != nil {
		return res, err
	}
	// The run's own removal of the file comes too late for this loop, which
	// must not read the previous run's result before the container started.
	if _, err := c.Run(ctx, fmt.Sprintf(`/file/remove [find name="%s"]`, lastResult)); err != nil {
		return res, err
	}
	if _, err := c.Run(ctx, fmt.Sprintf(`/container/set [find name=tikray] cmd="%s"`, rosEscape(args))); err != nil {
		return res, err
	}
	if _, err := c.Run(ctx, "/container/start [find name=tikray]"); err != nil {
		return res, err
	}
	start, ran := time.Now(), false
	for {
		st, err := containerStatus(ctx, c, "tikray")
		switch {
		case err != nil:
		case st != "stopped":
			ran = true
		default:
			body, err := c.Get(ctx, fileContents(lastResult))
			if err == nil && body != "" {
				if err := json.Unmarshal([]byte(body), &res); err != nil {
					return res, fmt.Errorf("tikray %s: last-result.json: %v: %q", args, err, body)
				}
				return res, nil
			}
			// A container that stopped before this loop saw it run may
			// not have been started at all.
			if ran || time.Since(start) > time.Minute {
				return res, fmt.Errorf("tikray %s stopped without a result (%v); container log:\n%s", args, err, containerLog(c, 30))
			}
		}
		if err := sleep(ctx, 2*time.Second); err != nil {
			return res, fmt.Errorf("tikray %s: %w; container log:\n%s", args, err, containerLog(c, 30))
		}
	}
}

// containerStatus is "running" or "stopped" for the named container, after
// the flags RouterOS sets on it (R and S in /container/print), and "" for
// any state in between, such as extracting or starting. RouterOS 7.25 has no
// status property.
func containerStatus(ctx context.Context, c *lab.CHR, name string) (string, error) {
	for _, flag := range []string{"running", "stopped"} {
		n, err := c.Get(ctx, fmt.Sprintf("[:len [/container/find where name=%s and %s]]", name, flag))
		if err != nil {
			return "", err
		}
		if n == "1" {
			return flag, nil
		}
	}
	return "", nil
}

// waitContainer waits until the named container's status is want.
func waitContainer(ctx context.Context, c *lab.CHR, name, want string) error {
	for {
		st, err := containerStatus(ctx, c, name)
		if err == nil && st == want {
			return nil
		}
		if err := sleep(ctx, 3*time.Second); err != nil {
			return fmt.Errorf("container %s is %q (%v), want %s: %w", name, st, err, want, ctx.Err())
		}
	}
}

// containerLog is the last n lines RouterOS logged under the container topic,
// where the containers' output goes (logging=yes).
func containerLog(c *lab.CHR, n int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := c.Run(ctx, `/log/print where topics~"container"`)
	if err != nil {
		return err.Error()
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

// fileContents is the RouterOS expression for the contents of a file.
func fileContents(path string) string {
	return fmt.Sprintf(`/file/get [find name="%s"] contents`, path)
}

// rosEscape escapes s for a double-quoted RouterOS string.
func rosEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, `?`, `\?`, "\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(s)
}

// whoami is what the target web server sees as the LAN client's address:
// 203.0.113.10 through the proxy, 198.51.100.2 direct.
func (l *Lab) whoami(ctx context.Context) string {
	b, _ := l.Net.Client(ctx, "curl", "-s", "--noproxy", "*", "--max-time", "5", "http://203.0.113.30/whoami").Output()
	return strings.TrimSpace(string(b))
}

// waitProxied waits up to d for the LAN client's traffic to go through the
// proxy and returns how long that took.
func (l *Lab) waitProxied(ctx context.Context, d time.Duration) (time.Duration, bool) {
	return poll(ctx, d, 2*time.Second, func() bool { return l.whoami(ctx) == "203.0.113.10" })
}

// setFlag creates or removes one of the releases root's flag files.
func (l *Lab) setFlag(name string, on bool) error {
	p := filepath.Join(l.Releases, name)
	if on {
		return os.WriteFile(p, nil, 0o644)
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// toInbox puts the zip of version in the inbox under the release asset's
// name, as an operator's manual upload.
func (l *Lab) toInbox(ctx context.Context, version string) error {
	return l.CHR.Push(ctx, l.Zips[version], inboxDir+"/"+l.Asset)
}

// writeStateFile saves st in dir as revision 1, in the format of the state
// file, and returns its path. It is the store that writes it, with the checks
// of Validate, so that what the lab pushes is what the daemon would have saved.
func writeStateFile(dir string, st store.State) (string, error) {
	s, err := store.Open(dir)
	if err != nil {
		return "", err
	}
	if _, _, err := s.Update(0, func(next *store.State) error {
		*next = st
		return nil
	}); err != nil {
		return "", err
	}
	return filepath.Join(dir, fmt.Sprintf("state.v%d.json", store.Current)), nil
}

// pushState puts st on the router as the state tikray reads, replacing the one
// there. It refuses a state that does not validate.
func (l *Lab) pushState(ctx context.Context, st store.State) error {
	if err := st.Validate(); err != nil {
		return fmt.Errorf("pushing the state: %w", err)
	}
	dir, err := os.MkdirTemp("", "tikray-state-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	local, err := writeStateFile(dir, st)
	if err != nil {
		return err
	}
	// Replace the file rather than count on the fetch overwriting it.
	if _, err := l.CHR.Run(ctx, fmt.Sprintf(`:foreach f in=[/file/find where name="%s"] do={/file/remove $f}`, statePath)); err != nil {
		return err
	}
	return l.CHR.Push(ctx, local, statePath)
}

// clearInbox removes the release zip from the inbox.
func (l *Lab) clearInbox(ctx context.Context) error {
	_, err := l.CHR.Run(ctx, fmt.Sprintf(`/file/remove [find name="%s/%s"]`, inboxDir, l.Asset))
	return err
}

// children returns the names of the entries directly in dir on the router,
// sorted.
func (l *Lab) children(ctx context.Context, dir string) ([]string, error) {
	out, err := l.CHR.Run(ctx, fmt.Sprintf(`:foreach f in=[/file/find where name~"^%s/[^/]+\$"] do={:put [/file/get $f name]}`, dir))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			names = append(names, strings.TrimPrefix(line, dir+"/"))
		}
	}
	sort.Strings(names)
	return names, nil
}

// routerClock is the router's wall clock, which the containers share. The
// lab's CHR has no NTP, and its clock can be minutes away from the host's
// (4.5 minutes behind in the first M1 run).
func (l *Lab) routerClock(ctx context.Context) (time.Time, error) {
	// One expression, so that the date and the time are read together.
	s, err := l.CHR.Run(ctx, `:put ([/system/clock/get date] . " " . [/system/clock/get time] . " " . [/system/clock/get gmt-offset])`)
	if err != nil {
		return time.Time{}, err
	}
	var date, clock string
	var offset int
	if _, err := fmt.Sscan(s, &date, &clock, &offset); err != nil {
		return time.Time{}, fmt.Errorf("router clock %q: %w", s, err)
	}
	t, err := time.Parse("2006-01-02 15:04:05", date+" "+clock)
	if err != nil {
		return time.Time{}, fmt.Errorf("router clock %q: %w", s, err)
	}
	return t.Add(-time.Duration(offset) * time.Second), nil
}

// exists reports whether path exists on the router.
func (l *Lab) exists(ctx context.Context, path string) (bool, error) {
	n, err := l.CHR.Get(ctx, fmt.Sprintf(`:len [/file/find name="%s"]`, path))
	return n != "0", err
}

// poll calls f every interval until it returns true or d passes, and returns
// how long it took.
func poll(ctx context.Context, d, interval time.Duration, f func() bool) (time.Duration, bool) {
	start := time.Now()
	for time.Since(start) < d && ctx.Err() == nil {
		if f() {
			return time.Since(start), true
		}
		sleep(ctx, interval)
	}
	return time.Since(start), false
}

// sleep waits d, or until ctx ends.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
