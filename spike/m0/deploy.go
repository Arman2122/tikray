//go:build lab

package m0

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/test/lab"
)

// Lab is a CHR with the M0 data path deployed: runner and control
// prototypes in containers, the tikray RouterOS objects from setup.rsc, and
// the fake internet behind ether1.
type Lab struct {
	Net         *lab.Network
	CHR         *lab.CHR
	Arch        lab.Arch
	Version     string // RouterOS
	XrayVersion string // xray release, e.g. 26.3.27
	StopInet    func()
}

// RunnerStatus is runnerproto's /v0/status.
type RunnerStatus struct {
	Sysctl        map[string]string `json:"sysctl"`
	Ingress       string            `json:"ingress"`
	XrayPID       int               `json:"xray_pid"`
	XrayRSSKB     int               `json:"xray_rss_kb"`
	RoutesOK      bool              `json:"routes_ok"`
	XrayRestarts  int               `json:"xray_restarts"`
	ExecFromMount string            `json:"exec_from_mount"`
	XrayVersion   string            `json:"xray_version"`
}

const (
	runnerURL = "http://172.31.255.3:8080"
	ctlURL    = "http://172.31.255.2:8080"
)

func spikeDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Deploy brings the whole lab up for $TIKRAY_LAB_CHANNEL (default stable),
// $TIKRAY_LAB_ARCH (default x86_64) and $TIKRAY_LAB_XRAY (see
// lab.LabXrayVersion) and tears it down when t ends. The VM work dir is kept
// when the test fails.
func Deploy(ctx context.Context, t *testing.T) *Lab {
	t.Helper()
	l := &Lab{Arch: lab.Arch(env("TIKRAY_LAB_ARCH", string(lab.ArchX86)))}
	var err error
	if l.Version, err = lab.ResolveChannel(ctx, "", env("TIKRAY_LAB_CHANNEL", "stable")); err != nil {
		t.Fatal(err)
	}
	art, err := lab.FetchCHR(ctx, "", lab.CacheDir(), l.Version, l.Arch)
	if err != nil {
		t.Fatal(err)
	}
	goarch := l.Arch.GOARCH()
	if l.XrayVersion, err = lab.XrayCoreVersion(lab.LabXrayVersion()); err != nil {
		t.Fatal(err)
	}
	xray, err := lab.XrayBinary(ctx, lab.CacheDir(), goarch)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := exec.CommandContext(ctx, "bash", filepath.Join(spikeDir(), "build-images.sh"), goarch).CombinedOutput(); err != nil {
		t.Fatalf("build images: %v\n%s", err, b)
	}

	if l.Net, err = lab.SetupNetwork(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Net.Teardown() })
	if l.StopInet, err = lab.StartInet(ctx, l.Net); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.StopInet)

	wd, err := os.MkdirTemp("", "tikray-lab-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("kept VM work dir %s", wd)
			return
		}
		os.RemoveAll(wd)
	})
	if l.CHR, err = lab.BootCHR(ctx, l.Net, lab.BootOptions{
		Version: l.Version, Arch: l.Arch, Artifacts: art, WorkDir: wd, Password: "tikray-lab",
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.CHR.Shutdown() })
	c := l.CHR
	if err := c.EnableContainers(ctx); err != nil {
		t.Fatal(err)
	}

	for local, remote := range map[string]string{
		xray: lab.DataRoot + "/cores/" + l.XrayVersion + "/xray",
		filepath.Join(spikeDir(), "config", "xray-client.json"):        lab.DataRoot + "/run/config.json",
		filepath.Join(spikeDir(), "out", "runnerproto-"+goarch+".tar"): "disk1/tikray/images/runnerproto-" + goarch + ".tar",
		filepath.Join(spikeDir(), "out", "ctlproto-"+goarch+".tar"):    "disk1/tikray/images/ctlproto-" + goarch + ".tar",
	} {
		if err := c.Push(ctx, local, remote); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Import(ctx, filepath.Join(spikeDir(), "routeros", "lab-fasttrack.rsc")); err != nil {
		t.Fatal(err)
	}
	setup, err := os.ReadFile(filepath.Join(spikeDir(), "routeros", "setup.rsc"))
	if err != nil {
		t.Fatal(err)
	}
	withArch := filepath.Join(wd, "setup.rsc")
	header := fmt.Sprintf(":global tikrayArch %q\n:global tikrayXrayVersion %q\n", goarch, l.XrayVersion)
	if err := os.WriteFile(withArch, append([]byte(header), setup...), 0o644); err != nil {
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

// startContainers starts both containers once their images are extracted,
// which takes minutes under emulation, and waits for their HTTP endpoints.
func (l *Lab) startContainers(ctx context.Context) error {
	d := 15 * time.Minute
	if l.Arch == lab.ArchARM64 {
		d = 45 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	for name, url := range map[string]string{"tikray-runner": runnerURL + "/v0/status", "tikray-ctl": ctlURL + "/v0/write"} {
		for {
			if resp, err := http.Get(url); err == nil {
				resp.Body.Close()
				break
			}
			l.CHR.Run(ctx, fmt.Sprintf("/container/start [find name=%s]", name))
			select {
			case <-ctx.Done():
				out, _ := l.CHR.Run(context.Background(), "/container/print detail")
				return fmt.Errorf("%s did not come up: %v\n%s", name, ctx.Err(), out)
			case <-time.After(10 * time.Second):
			}
		}
	}
	return nil
}

// RunnerStatus fetches runnerproto's status from the host.
func (l *Lab) RunnerStatus(ctx context.Context) (RunnerStatus, error) {
	var s RunnerStatus
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, runnerURL+"/v0/status", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	return s, json.NewDecoder(resp.Body).Decode(&s)
}

// ClientCurl runs curl in the LAN client namespace (15 s max time unless the
// args set another) and returns its stdout.
func (l *Lab) ClientCurl(ctx context.Context, args ...string) (string, error) {
	b, err := l.Net.Client(ctx, "curl", append([]string{"-s", "--noproxy", "*", "--max-time", "15"}, args...)...).Output()
	return strings.TrimSpace(string(b)), err
}

// SetSourcePolicy moves the proxied test device to another source list
// (tikray-src-smart-open or tikray-src-smart-closed).
func (l *Lab) SetSourcePolicy(ctx context.Context, list string) error {
	_, err := l.CHR.Run(ctx, fmt.Sprintf(`/ip/firewall/address-list/set [find where comment="tikray:src"] list=%s`, list))
	return err
}
