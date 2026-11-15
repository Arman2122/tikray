//go:build lab

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/test/lab"
)

//go:embed testdata/watchdog_wire.py
var watchdogWire string

type imageWANProof struct {
	gateway, tap            *routingWAN
	nonce, burst, alternate string
}

func (f *routingLab) newImageWire(ctx context.Context, t *testing.T) *imageWANProof {
	t.Helper()
	dir := t.TempDir()
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal("cannot identify synthetic UDP probes")
	}
	w := &imageWANProof{gateway: &routingWAN{filepath.Join(dir, "gateway")}, tap: &routingWAN{filepath.Join(dir, "tap")}, nonce: hex.EncodeToString(id[:]), burst: filepath.Join(dir, "rapid-restart"), alternate: filepath.Join(dir, "alternate")}
	gateway, e := f.Net.Inet(ctx, "cat", "/sys/class/net/wan0/address").Output()
	router := f.readROS(ctx, t, "/interface/ethernet", "mac-address", "?name=ether1")
	if e != nil || len(router) != 1 || router[0]["mac-address"] == "" {
		t.Fatal("independent WAN interfaces unavailable")
	}
	args := func(mode, device, path string) []string {
		return []string{"-c", watchdogWire, mode, device, strings.TrimSpace(string(gateway)), router[0]["mac-address"], routingRemote, w.nonce, path, egressDirect, "192.168.88.10", routingPeer, serverEgress["a"], serverEgress["b"], w.alternate, alternateImageGatewayMAC}
	}
	startRoutingProcess(t, f.Net.Inet(ctx, "python3", args("gateway", "wan0", w.gateway.trace)...))
	startRoutingProcess(t, exec.CommandContext(ctx, "python3", args("tap", lab.TapWAN, w.tap.trace)...))
	_, ok := poll(ctx, 5*time.Second, 100*time.Millisecond, func() bool {
		_, a := os.Stat(w.gateway.trace)
		_, b := os.Stat(w.tap.trace)
		return a == nil && b == nil
	})
	if !ok {
		t.Fatal("both external WAN observers did not bind")
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, capture := range []*routingWAN{w.gateway, w.tap} {
			data, _ := os.ReadFile(capture.trace + ".violations")
			for _, line := range strings.Split(string(data), "\n") {
				if imageWireDetail.MatchString(line) {
					t.Logf("%s synthetic WAN witness: %s", filepath.Base(capture.trace), line)
				}
			}
		}
	})
	return w
}

var imageWireDetail = regexp.MustCompile(`^[CD] [0-9] (router|gateway|other) (router|gateway|other) (wan|peer|closed|proxy|veth|other) [0-9]{1,5} [0-9]{1,5} [0-9]{1,3}$`)

func (w *imageWANProof) sample(t *testing.T) wanSample {
	t.Helper()
	gateway := w.gateway.sample(t)
	tap := w.tap.sample(t)
	gateway.closedDirect = max(gateway.closedDirect, tap.closedDirect)
	gateway.unknown = max(gateway.unknown, tap.unknown)
	// Both external interfaces must positively see the actual open control.
	gateway.peerDirect = min(gateway.peerDirect, tap.peerDirect)
	return gateway
}

func (w *imageWANProof) directCounts(t *testing.T) [2]int {
	t.Helper()
	return [2]int{w.gateway.sample(t).peerDirect, w.tap.sample(t).peerDirect}
}

func newWirePackets(before, after [2]int) int {
	return min(after[0]-before[0], after[1]-before[1])
}

func (w *imageWANProof) originalGatewayCounts(t *testing.T) [2]int {
	t.Helper()
	count := func(path string) int {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("original WAN gateway trace unavailable")
		}
		return bytes.Count(data, []byte{'g'})
	}
	return [2]int{count(w.gateway.trace), count(w.tap.trace)}
}

func (f *routingLab) checkQuickRunnerRestarts(ctx context.Context, t *testing.T, w *imageWANProof, owner func()) {
	t.Helper()
	f.scheduler(ctx, t, false)
	defer f.scheduler(ctx, t, true)
	if os.WriteFile(w.burst, []byte("active"), 0600) != nil {
		t.Fatal("could not enable rapid-restart WAN witnesses")
	}
	defer os.Remove(w.burst)
	for _, gap := range []time.Duration{0, 250 * time.Millisecond, time.Second} {
		start := w.sample(t)
		f.containerAction(ctx, t, "runner", "stop", "stopped")
		if sleep(ctx, gap) != nil {
			t.Fatal("rapid-restart observation cancelled")
		}
		f.containerAction(ctx, t, "runner", "start", "running")
		f.checkReady(ctx, t)
		_, ok := poll(ctx, f.proxiedWithin(), time.Second, func() bool {
			return w.sample(t).closedProxy >= start.closedProxy+4 && isRoutingProxy(f.peerEgress(ctx, routingRemote))
		})
		now := w.sample(t)
		if !ok || now.closedDirect != 0 || now.unknown != 0 {
			t.Fatalf("rapid runner restart: proxy_recovered=%t closed_wan=%d unexpected_open=%d", ok, now.closedDirect, now.unknown)
		}
		owner()
	}
}
