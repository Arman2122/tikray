package artifacts

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

const (
	defaultProbeTimeout = 10 * time.Second
	defaultStatsServer  = "127.0.0.1:10085"
	// xrayAPIProbeTimeout is the least HTTP timeout XrayAPIProbe calls the
	// runner with: the runner gives xray api 10 s, which is also
	// runnerapi.Client's default timeout.
	xrayAPIProbeTimeout = 20 * time.Second
)

// HealthChecker tells whether xray carries traffic. During a trial it runs
// against the candidate.
type HealthChecker interface {
	Check(ctx context.Context) error
}

// SOCKSProbe fetches URL through the SOCKS5 proxy at Addr, which resolves the
// name; any 2xx answer passes and redirects are not followed. Timeout (10 s)
// bounds one check.
type SOCKSProbe struct {
	Addr, URL string
	Timeout   time.Duration
}

func (p SOCKSProbe) Check(ctx context.Context) error {
	d, err := proxy.SOCKS5("tcp", p.Addr, nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("socks probe %s: %w", p.Addr, err)
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return fmt.Errorf("socks probe %s: dialer cannot take a context", p.Addr)
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// No Proxy func: the environment's proxy settings never apply here.
	tr := &http.Transport{DialContext: cd.DialContext, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	hc := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		return fmt.Errorf("socks probe: %w", err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("socks probe through %s: %w", p.Addr, err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("socks probe through %s: GET %s: HTTP %s", p.Addr, p.URL, resp.Status)
	}
	return nil
}

// XrayAPIProbe runs "xray api statssys --server=<Server>" in the runner, with
// the running core, and passes when it exits 0, which needs xray's gRPC API to
// answer. Server defaults to 127.0.0.1:10085. Runner is called through a copy
// whose HTTP timeout is at least 20 s, longer than the runner's own 10 s
// bound on the call.
type XrayAPIProbe struct {
	Runner *runnerapi.Client
	Server string
}

func (p XrayAPIProbe) Check(ctx context.Context) error {
	if p.Runner == nil {
		return errors.New("xray api probe: no runner")
	}
	server := p.Server
	if server == "" {
		server = defaultStatsServer
	}
	resp, err := withTimeout(p.Runner, xrayAPIProbeTimeout).XrayAPI(ctx, "statssys", "--server="+server)
	if err != nil {
		return fmt.Errorf("xray api probe: %w", err)
	}
	if resp.ExitCode != 0 {
		return fmt.Errorf("xray api statssys --server=%s: exit status %d: %s", server, resp.ExitCode, strings.TrimSpace(resp.Stderr))
	}
	return nil
}

// AllOf passes when every checker passes. They run in order, and the first
// failure is the result.
func AllOf(cs ...HealthChecker) HealthChecker {
	return allOf(append([]HealthChecker(nil), cs...))
}

type allOf []HealthChecker

func (a allOf) Check(ctx context.Context) error {
	for _, c := range a {
		if err := c.Check(ctx); err != nil {
			return err
		}
	}
	return nil
}

// withTimeout returns a copy of c whose HTTP client allows a call at least d.
// A client without a timeout keeps none.
func withTimeout(c *runnerapi.Client, d time.Duration) *runnerapi.Client {
	cc := *c
	hc := http.Client{Timeout: d}
	if c.HTTP != nil {
		hc = *c.HTTP
		if hc.Timeout != 0 && hc.Timeout < d {
			hc.Timeout = d
		}
	}
	cc.HTTP = &hc
	return &cc
}
