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
	"flag"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/sharelink"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xrayver"
	"github.com/Arman2122/tikray/test/lab"
	"github.com/Arman2122/tikray/test/lab/fixtures/labinet"
)

// The runner's control API, which the host reaches through the lab's host
// route to the tikray bridge.
const runnerURL = "http://172.31.255.3:8080"

// apiURL is the tikray service's API, which the host reaches the same way. The
// service listens on TIKRAY_LISTEN's default, :443, and the lab does not set
// it.
const apiURL = "https://172.31.255.2:443"

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
	apiToken      = dataRoot + "/state/api.token"
	apiCert       = dataRoot + "/state/tls.crt"
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

// egressDirect is the address the fake internet's web server sees as the LAN
// client's when a request went direct: the router's WAN address, which NAT
// gives it.
const egressDirect = "198.51.100.2"

// serverEgress is the address each VLESS server of the fake internet sends
// from, and so the one the web server sees through it, by the name
// lab.Inet.SetServer takes.
var serverEgress = map[string]string{"a": "203.0.113.10", "b": "203.0.113.11"}

// Lab is a CHR with tikray deployed: the tikray-runner and tikray containers
// from the real images, the RouterOS objects of routeros/m1-setup.rsc, and
// the fake internet with its two VLESS servers, a fake GitHub (203.0.113.40)
// and a mirror with a signed hash index (203.0.113.41) serving Releases, and
// subscriptions (http://203.0.113.30/sub/<name>) serving Subs.
type Lab struct {
	Net *lab.Network
	// Inet is the fake internet, whose VLESS servers a test can stop and
	// start.
	Inet    *lab.Inet
	CHR     *lab.CHR
	Arch    lab.Arch
	Version string // RouterOS
	Newest  string // the newest xray-core release, such as 26.10.21
	Asset   string // the release zip for the CHR's arch, such as Xray-linux-64.zip
	// Releases is the root the fake GitHub and the mirror serve. Flag files
	// in it switch them (see labinet.ReleasesHandler).
	Releases string
	// Subs is the root the fake internet serves at http://203.0.113.30/sub/:
	// the file Subs/<name> is the subscription <name>. setSub changes them.
	Subs string
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
	l.Subs = filepath.Join(wd, "subs")
	if err := os.MkdirAll(l.Subs, 0o755); err != nil {
		t.Fatal(err)
	}
	if l.Inet, err = lab.StartInetLab(ctx, l.Net, lab.InetOptions{ReleasesDir: l.Releases, SubsDir: l.Subs}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Inet.Stop)

	if l.CHR, err = lab.BootReadyCHR(ctx, l.Net, lab.BootOptions{
		Version: l.Version, Arch: l.Arch, Artifacts: art, WorkDir: filepath.Join(wd, "vm"), Password: "tikray-lab",
		// What the harness worked around, such as a push it had to retry,
		// shows in a run that passes too.
		Notef: t.Logf,
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

// tikray runs the tikray CLI with args (see runTikray), notes its result and
// how long it took, and ends the check when the run gave no result.
func (l *Lab) tikray(ctx context.Context, t *testing.T, note func(string, ...any), args string) artifacts.Result {
	t.Helper()
	start := time.Now()
	res, err := runTikray(ctx, l.CHR, args)
	note("tikray %s: %s (%.0fs)", args, describe(res), time.Since(start).Seconds())
	if err != nil {
		t.Fatalf("tikray %s: %v", args, err)
	}
	return res
}

// checkCore checks that the runner runs version, the core of active.json, and
// returns its status.
func checkCore(ctx context.Context, t *testing.T, note func(string, ...any), version string) runnerapi.Status {
	t.Helper()
	st, err := runnerStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	active := "<none>"
	if st.Active != nil {
		active = st.Active.Core
	}
	note("runner %s, active %s, xray_version %q, gateway_up %v", st.State, active, st.XrayVersion, st.GatewayUp)
	if st.State != runnerapi.StateRunning || active != version || !strings.HasPrefix(st.XrayVersion, "Xray "+version+" ") {
		t.Errorf("runner state %s, active core %s, xray_version %q: want running on %s", st.State, active, st.XrayVersion, version)
	}
	return st
}

// result is one check's outcome, as written to the results file of its suite.
type result struct {
	ID      string  `json:"id"`
	Pass    bool    `json:"pass"`
	Detail  string  `json:"detail"`
	Seconds float64 `json:"seconds"`
}

// recordChecks returns check, which runs f as the subtest id of t and records
// its outcome, with the lines f noted as its detail. When t ends the outcomes
// are written, passed or not, to results/<routeros>-<arch>-<suite>.json; a
// run filtered to some of the checks writes <...>-<suite>-partial.json, so
// that it never replaces a full run's results.
func (l *Lab) recordChecks(t *testing.T, suite string) (check func(id string, f func(t *testing.T, note func(string, ...any)))) {
	var results []result
	t.Cleanup(func() {
		dir := filepath.Join(e2eDir(), "results")
		os.MkdirAll(dir, 0o755)
		b, _ := json.MarshalIndent(results, "", "  ")
		name := fmt.Sprintf("%s-%s-%s", l.Version, l.Arch, suite)
		if f := flag.Lookup("test.run"); f != nil && strings.Contains(f.Value.String(), "/") {
			name += "-partial"
		}
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Error(err)
		}
		t.Logf("results: %s", path)
	})
	return func(id string, f func(t *testing.T, note func(string, ...any))) {
		t.Run(id, func(t *testing.T) {
			var notes []string
			note := func(format string, args ...any) { notes = append(notes, fmt.Sprintf(format, args...)) }
			start := time.Now()
			defer func() {
				results = append(results, result{ID: id, Pass: !t.Failed(), Detail: strings.Join(notes, "; "), Seconds: time.Since(start).Round(100 * time.Millisecond).Seconds()})
			}()
			f(t, note)
		})
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

// curl fetches a URL from the LAN client, with at most 5 s for the whole
// request, and returns the body; "" when the request failed.
func (l *Lab) curl(ctx context.Context, args ...string) string {
	b, _ := l.Net.Client(ctx, "curl", append([]string{"-s", "--noproxy", "*", "--max-time", "5"}, args...)...).Output()
	return strings.TrimSpace(string(b))
}

// whoami is what the target web server sees as the LAN client's address:
// the egress address of a VLESS server through the proxy (203.0.113.10 or
// .11), 198.51.100.2 direct, and "" when the request failed.
func (l *Lab) whoami(ctx context.Context) string {
	return l.curl(ctx, "http://203.0.113.30/whoami")
}

// proxiedVia names the VLESS server ("a" or "b") the LAN client's traffic
// goes through, after whoami, and is "" when it is not proxied. got is what
// whoami answered.
func (l *Lab) proxiedVia(ctx context.Context) (server, got string) {
	got = l.whoami(ctx)
	for name, addr := range serverEgress {
		if got == addr {
			return name, got
		}
	}
	return "", got
}

// waitProxied waits up to d for the LAN client's traffic to go through the
// proxy, by either VLESS server, and returns how long that took and the
// server whoami came through then.
func (l *Lab) waitProxied(ctx context.Context, d time.Duration) (took time.Duration, server string, ok bool) {
	took, ok = poll(ctx, d, 2*time.Second, func() bool {
		server, _ = l.proxiedVia(ctx)
		return server != ""
	})
	return took, server, ok
}

// proxiedWithin is how long the LAN client may take to be proxied once a
// trial is over: CHR's check-gateway pings every 10 s, and a trial that
// restarts or reverts xray takes the runner off the air for a few seconds.
func (l *Lab) proxiedWithin() time.Duration {
	if l.Arch == lab.ArchARM64 {
		return 5 * time.Minute
	}
	return 3 * time.Minute
}

// lanProxied checks that the LAN client's traffic goes through a VLESS server
// within proxiedWithin, and returns the server ("a" or "b").
func (l *Lab) lanProxied(ctx context.Context, t *testing.T, note func(string, ...any)) string {
	t.Helper()
	d := l.proxiedWithin()
	took, server, ok := l.waitProxied(ctx, d)
	note("LAN proxied after %.0fs: %v (server %q)", took.Seconds(), ok, server)
	if !ok {
		t.Errorf("the LAN client was not proxied within %s: whoami %q, want %s or %s", d, l.whoami(ctx), serverEgress["a"], serverEgress["b"])
	}
	return server
}

// dig is the LAN client's A lookup of name, through the router, which sends
// a proxied device's queries to the runner: the answer, or "" for none.
func (l *Lab) dig(ctx context.Context, name string) string {
	b, _ := l.Net.Client(ctx, "dig", "+short", "+time=3", "+tries=2", "@192.168.88.1", name).Output()
	return strings.TrimSpace(string(b))
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

// setSub makes http://203.0.113.30/sub/<name> answer with body from now on,
// as a subscription provider changing its list. name is a plain file name. The
// file is replaced in one step, so that a fetch never sees half of it.
func (l *Lab) setSub(name, body string) error {
	if name == "" || strings.HasPrefix(name, ".") || filepath.Base(name) != name {
		return fmt.Errorf("subscription name %q: want a plain file name without a leading dot", name)
	}
	if l.Subs == "" {
		return errors.New("setSub: the lab has no subscriptions directory (Deploy sets Subs)")
	}
	// The dot keeps the file under construction out of reach of labinet.
	tmp := filepath.Join(l.Subs, "."+name+".tmp")
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(l.Subs, name))
}

// api returns a client for the tikray service's API: the token the service
// wrote to state/api.token, and the fingerprint of the certificate in
// state/tls.crt as the one to trust, which the service made when it first
// started. It reads both from the router (the service owns them, and the host
// has no other way to them) and waits for the service to have written them,
// until ctx ends: the files are there a moment after `tikray serve` starts, and
// never when nothing started it.
func (l *Lab) api(ctx context.Context) (*apiclient.Client, error) {
	for {
		tok, crt, err := l.apiFiles(ctx)
		if err == nil {
			return apiClient(tok, crt)
		}
		if serr := sleep(ctx, 2*time.Second); serr != nil {
			return nil, fmt.Errorf("the tikray service has not written its token and certificate: %v (%w)", err, serr)
		}
	}
}

// apiFiles reads the API token and the certificate from the router; an error
// means one is not there yet.
func (l *Lab) apiFiles(ctx context.Context) (token, cert string, err error) {
	if token, err = l.CHR.Get(ctx, fileContents(apiToken)); err != nil {
		return "", "", err
	}
	if cert, err = l.CHR.Get(ctx, fileContents(apiCert)); err != nil {
		return "", "", err
	}
	if token == "" || cert == "" {
		return "", "", errors.New("a file is empty")
	}
	return token, cert, nil
}

// apiClient is the client of the service at apiURL for the contents of its
// token and certificate files, as the router gave them. The fingerprint is
// the one the service prints and the CLI pins (apiclient.FingerprintOfPEM).
func apiClient(token, certPEM string) (*apiclient.Client, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("the API token is empty")
	}
	// FingerprintOfPEM takes CRLF line ends, which a console may give the
	// file's lines back with, as it takes LF.
	fp, err := apiclient.FingerprintOfPEM([]byte(certPEM))
	if err != nil {
		return nil, err
	}
	return &apiclient.Client{BaseURL: apiURL, Token: token, Fingerprint: fp}, nil
}

// toInbox puts the zip of version in the inbox under the release asset's
// name, as an operator's manual upload.
func (l *Lab) toInbox(ctx context.Context, version string) error {
	return l.CHR.Push(ctx, l.Zips[version], inboxDir+"/"+l.Asset)
}

// The share links of the fake internet's two VLESS servers. Plain VLESS
// without TLS is refused by xray-core 26.7.11 and later for a public address,
// but 203.0.113.0/24 is on its private list (see internal/xraypolicy).
const (
	linkA = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?type=tcp&security=none#lab-a"
	linkB = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.11:443?type=tcp&security=none#lab-b"
)

// labProbeURL is the state's probe URL in the lab: the observatory fetches it
// through each server to tell whether the server is up. The lab has no
// internet, so the default probe URL would fail through every server and
// make the balancers fall back (direct, or block) with both servers up. It is
// the same target as tikray's own SOCKS probe (TIKRAY_PROBE_URL in
// routeros/m1-setup.rsc).
const labProbeURL = "http://203.0.113.30/whoami"

// lanClient is the lab's LAN client as a device.
var lanClient = netip.MustParsePrefix("192.168.88.10/32")

// labState is the default state with what every lab state has: the M1
// fixture's domestic names and address, its two resolvers (labinet's, on
// 203.0.113.53 and .54), and labProbeURL. The subnet stays the default, which
// is the lab's.
func labState() store.State {
	st := store.Default()
	st.Routing.Domestic = store.Domestic{Domains: []string{"domain:domestic.test"}, IPs: []string{"203.0.113.20/32"}}
	st.DNS = store.DNS{Remote: "203.0.113.53", Domestic: netip.MustParseAddr("203.0.113.54")}
	st.Health.ProbeURL = labProbeURL
	return st
}

// serverFromLink is the server a share link gives, with a new ID, as it is
// added to the state.
func serverFromLink(link string) (store.Server, error) {
	srv, err := sharelink.Parse(link)
	if err != nil {
		return store.Server{}, err
	}
	return store.Server{ID: store.NewID(), Name: srv.Name, Link: link, Outbound: srv.Outbound}, nil
}

// writeStateFile saves st in dir as revision 1, in the format of the state
// file, and returns its path. It is the store that writes it, with the checks
// of Validate, so that what the lab pushes is what the daemon would have saved.
func writeStateFile(dir string, st store.State) (string, error) {
	s, err := store.Open(dir)
	if err != nil {
		return "", err
	}
	if _, _, err := s.Update(store.AnyRevision, func(next *store.State) error {
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
