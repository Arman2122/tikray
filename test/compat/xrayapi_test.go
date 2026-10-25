//go:build compat

package compat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/xray"
	"github.com/Arman2122/tikray/test/lab"
)

const (
	// apiReady bounds the wait for a started xray to answer on its API.
	apiReady = 20 * time.Second
	// probeWait bounds the wait for the observatory's first probe of srv-a.
	probeWait = 30 * time.Second
)

// TestXrayAPIAgainstReleases starts each release compatVersions gives with a
// config that has the api-in inbound, the stats, an observatory over one
// freedom outbound (srv-a) that probes a local HTTP server, and a leastPing
// balancer over srv-. It then checks that internal/xray's Client gets the
// answers the health monitor needs: the system stats, the outbound counters,
// srv-a alive in the observatory, and srv-a as the balancer's target. It
// needs no root: there is no TUN device in the config.
func TestXrayAPIAgainstReleases(t *testing.T) {
	ctx := t.Context()
	versions, err := compatVersions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// What the probe asks for: any answer is an alive srv-a.
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(probe.Close)

	for _, v := range versions {
		core, err := lab.XrayCoreVersion(v)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(core, func(t *testing.T) {
			bin, err := lab.XrayBinaryVersion(ctx, lab.CacheDir(), v, runtime.GOARCH)
			if err != nil {
				t.Fatalf("build xray-core %s: %v", v, err)
			}
			port := freePort(t)
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			x := startXray(t, bin, apiConfig(port, probe.URL))
			c := &xray.Client{Addr: addr, Timeout: 5 * time.Second}
			waitForAPI(ctx, t, x, c)
			checkAPI(ctx, t, x, c)
		})
	}
}

// apiConfig is an xray config with its API on 127.0.0.1:port and srv-a
// probed at probeURL.
func apiConfig(port int, probeURL string) []byte {
	config := map[string]any{
		"log":    map[string]any{"loglevel": "warning"},
		"stats":  map[string]any{},
		"policy": map[string]any{"system": map[string]any{"statsOutboundUplink": true, "statsOutboundDownlink": true}},
		"api": map[string]any{
			"tag":      "api",
			"services": []string{"StatsService", "ObservatoryService", "RoutingService"},
		},
		"inbounds": []any{map[string]any{
			"tag": "api-in", "protocol": "dokodemo-door", "listen": "127.0.0.1", "port": port,
			"settings": map[string]any{"address": "127.0.0.1"},
		}},
		"outbounds": []any{map[string]any{"tag": "srv-a", "protocol": "freedom"}},
		"routing": map[string]any{
			"rules": []any{map[string]any{"type": "field", "inboundTag": []string{"api-in"}, "outboundTag": "api"}},
			"balancers": []any{map[string]any{
				"tag": "proxy-open", "selector": []string{"srv-"}, "strategy": map[string]any{"type": "leastPing"},
			}},
		},
		// One probe at start and the next one after the test is over, so the
		// counters stay put while it reads and resets them.
		"observatory": map[string]any{
			"subjectSelector": []string{"srv-"}, "probeURL": probeURL, "probeInterval": "60s", "enableConcurrency": true,
		},
	}
	b, err := json.Marshal(config)
	if err != nil {
		panic(err)
	}
	return b
}

// freePort returns a TCP port on 127.0.0.1 that nothing listens on.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// runningXray is a started xray process.
type runningXray struct {
	out  *syncBuffer
	done chan struct{} // closed when the process has exited
	err  error         // its exit status, valid after done
}

// syncBuffer is a bytes.Buffer that the process's output copier writes to
// while the test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startXray runs bin with config. The process is killed and reaped when the
// test ends.
func startXray(t *testing.T, bin string, config []byte) *runningXray {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "config.json")
	if err := os.WriteFile(file, config, 0o600); err != nil {
		t.Fatal(err)
	}
	x := &runningXray{out: &syncBuffer{}, done: make(chan struct{})}
	cmd := exec.Command(bin, "run", "-c", file)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+dir)
	cmd.Stdout, cmd.Stderr = x.out, x.out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start xray: %v", err)
	}
	go func() {
		x.err = cmd.Wait()
		close(x.done)
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
		<-x.done
	})
	return x
}

// waitForAPI waits until xray answers a SysStats call, and fails with xray's
// output if it exits first or takes too long.
func waitForAPI(ctx context.Context, t *testing.T, x *runningXray, c *xray.Client) {
	t.Helper()
	deadline := time.Now().Add(apiReady)
	for {
		_, err := c.SysStats(ctx)
		if err == nil {
			return
		}
		select {
		case <-x.done:
			t.Fatalf("xray exited (%v) before its API answered (%v):\n%s", x.err, err, x.out)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("xray's API did not answer in %v: %v\n%s", apiReady, err, x.out)
		}
	}
}

// checkAPI runs the Client's calls against the running xray.
func checkAPI(ctx context.Context, t *testing.T, x *runningXray, c *xray.Client) {
	t.Helper()
	fatal := func(format string, args ...any) {
		t.Helper()
		t.Fatalf(format+"\nxray's output:\n%s", append(args, x.out)...)
	}

	sys, err := c.SysStats(ctx)
	if err != nil {
		fatal("SysStats: %v", err)
	}
	if sys.NumGoroutine == 0 || sys.Alloc == 0 {
		fatal("SysStats = %+v, want goroutines and memory in use", sys)
	}
	t.Logf("SysStats: %+v", sys)

	stats, err := c.QueryStats(ctx, "outbound>>>", false)
	if err != nil {
		fatal("QueryStats: %v", err)
	}
	const uplink = "outbound>>>srv-a>>>traffic>>>uplink"
	if !slices.ContainsFunc(stats, func(s xray.Stat) bool { return s.Name == uplink }) {
		fatal("QueryStats(outbound>>>) = %+v, want an entry %q", stats, uplink)
	}
	if other, err := c.QueryStats(ctx, "no-such-counter", false); err != nil || len(other) != 0 {
		fatal("QueryStats(no-such-counter) = %+v, %v; want nothing", other, err)
	}

	// The observatory probes at start; wait for it to find srv-a alive.
	var srv *xray.OutboundStatus
	deadline := time.Now().Add(probeWait)
	for srv == nil {
		st, err := c.OutboundStatus(ctx)
		if err != nil {
			fatal("OutboundStatus: %v", err)
		}
		for _, s := range st {
			if s.Tag == "srv-a" && s.Alive {
				srv = &s
			}
		}
		if srv == nil {
			if time.Now().After(deadline) {
				fatal("srv-a is not alive in %v: %+v", probeWait, st)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	t.Logf("OutboundStatus: %+v", *srv)
	if srv.Delay < 0 || srv.Delay > 10*time.Second {
		fatal("srv-a's delay is %v", srv.Delay)
	}
	if srv.LastError != "" {
		fatal("srv-a is alive with the error %q", srv.LastError)
	}
	if d := time.Since(srv.LastSeen); srv.LastSeen.IsZero() || d < -2*time.Second || d > probeWait {
		fatal("srv-a was last seen %v (%v ago), want a time just now", srv.LastSeen, d)
	}
	if srv.LastTry.IsZero() || srv.LastTry.Before(srv.LastSeen) {
		fatal("srv-a's last try %v is before its last sighting %v", srv.LastTry, srv.LastSeen)
	}

	override, targets, err := c.BalancerTargets(ctx, "proxy-open")
	if err != nil {
		fatal("BalancerTargets: %v", err)
	}
	if override != "" || !slices.Equal(targets, []string{"srv-a"}) {
		fatal("BalancerTargets(proxy-open) = %q, %q; want no override and [srv-a]", override, targets)
	}
	t.Logf("BalancerTargets: override %q, targets %q", override, targets)
	_, _, err = c.BalancerTargets(ctx, "no-such-balancer")
	var se *xray.StatusError
	if !errors.As(err, &se) || se.Code == 0 {
		fatal("BalancerTargets(no-such-balancer) = %v, want a *StatusError", err)
	}
	t.Logf("BalancerTargets(no-such-balancer): %v", err)

	// The probe sent bytes through srv-a. Reading with reset returns them and
	// sets the counter back to 0, and nothing is sent through srv-a until the
	// next probe.
	before, err := counter(ctx, c, uplink, false)
	if err != nil {
		fatal("%v", err)
	}
	if before <= 0 {
		fatal("%s = %d after a probe, want bytes", uplink, before)
	}
	if reset, err := counter(ctx, c, uplink, true); err != nil || reset != before {
		fatal("%s read with reset = %d, %v; want %d", uplink, reset, err, before)
	}
	if after, err := counter(ctx, c, uplink, false); err != nil || after != 0 {
		fatal("%s after the reset = %d, %v; want 0", uplink, after, err)
	}
}

// counter returns the value of the one counter name.
func counter(ctx context.Context, c *xray.Client, name string, reset bool) (int64, error) {
	stats, err := c.QueryStats(ctx, name, reset)
	if err != nil {
		return 0, err
	}
	if len(stats) != 1 || stats[0].Name != name {
		return 0, fmt.Errorf("QueryStats(%s) = %+v, want that one counter", name, stats)
	}
	return stats[0].Value, nil
}
