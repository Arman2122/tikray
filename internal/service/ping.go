package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/Arman2122/tikray/internal/health"
	"github.com/Arman2122/tikray/internal/store"
)

const (
	pingTCPTimeout     = 4 * time.Second
	pingHTTPTimeout    = 6 * time.Second
	pingMaxConcurrency = 8
	pingHTTPURL        = "http://cp.cloudflare.com/generate_204"
)

// PingResult holds on-demand v2rayN-style latency measurements for one server:
// TCPMs is the direct 1-RTT TCP connect time to host:port; HTTPMs is the warm
// HTTP 204 round-trip through xray's SOCKS5 inbound when the server is active;
// ObsMs is the last cold end-to-end observatory delay reported by xray-core.
type PingResult struct {
	ID       string    `json:"id"`
	TCPMs    int64     `json:"tcp_ms,omitempty"`
	HTTPMs   int64     `json:"http_ms,omitempty"`
	ObsMs    int64     `json:"obs_ms,omitempty"`
	Alive    bool      `json:"alive"`
	Error    string    `json:"error,omitempty"`
	TestedAt time.Time `json:"tested_at"`
}

// PingServer measures TCP handshake RTT (and warm HTTP 204 real delay when
// routed through the active SOCKS5 tunnel) for one server on demand.
func (s *Service) PingServer(ctx context.Context, id string) (PingResult, error) {
	st, _ := s.store.State()
	var srv *store.Server
	enabledCount := 0
	for i := range st.Servers {
		if !st.Servers[i].Disabled && st.Servers[i].Invalid == "" {
			enabledCount++
		}
		if st.Servers[i].ID == id {
			srv = &st.Servers[i]
		}
	}
	if srv == nil {
		return PingResult{}, ErrNotFound
	}
	if srv.Invalid != "" {
		return PingResult{}, &Refused{Reason: "cannot test an invalid server"}
	}
	snap := s.health()
	redact := RedactorFor(st)
	isActive := snap.Selected == id || (snap.Selected == "" && enabledCount == 1 && !srv.Disabled)
	res := s.measureServer(ctx, *srv, newHealthDelayAdapter(snap), isActive, redact)
	s.storePing(res)
	return res, nil
}

// PingAllServers tests all enabled, valid servers concurrently (bounded to
// pingMaxConcurrency for router memory and CPU safety) in state order.
func (s *Service) PingAllServers(ctx context.Context) []PingResult {
	st, _ := s.store.State()
	snap := s.health()
	redact := RedactorFor(st)

	var targets []store.Server
	for _, srv := range st.Servers {
		if srv.Disabled || srv.Invalid != "" {
			continue
		}
		targets = append(targets, srv)
	}
	if len(targets) == 0 {
		return []PingResult{}
	}

	out := make([]PingResult, len(targets))
	adapter := newHealthDelayAdapter(snap)
	sem := make(chan struct{}, pingMaxConcurrency)
	var wg sync.WaitGroup
	for i, srv := range targets {
		wg.Add(1)
		go func(idx int, item store.Server) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				out[idx] = PingResult{ID: item.ID, Error: "canceled", TestedAt: s.now().UTC()}
				return
			}
			isActive := snap.Selected == item.ID || (snap.Selected == "" && len(targets) == 1)
			res := s.measureServer(ctx, item, adapter, isActive, redact)
			s.storePing(res)
			out[idx] = res
		}(i, srv)
	}
	wg.Wait()
	return out
}

func (s *Service) storePing(res PingResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pings == nil {
		s.pings = make(map[string]PingResult)
	}
	s.pings[res.ID] = res
}

func (s *Service) snapshotPings(servers []store.Server) map[string]PingResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pings) == 0 {
		return nil
	}
	out := make(map[string]PingResult, len(servers))
	for _, srv := range servers {
		if r, ok := s.pings[srv.ID]; ok {
			out[srv.ID] = r
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *Service) measureServer(
	ctx context.Context,
	srv store.Server,
	snap interface{ ServerDelay(id string) (int64, bool) },
	isActive bool,
	redact func(string) string,
) PingResult {
	now := s.now().UTC()
	res := PingResult{ID: srv.ID, TestedAt: now}

	if obsMs, obsAlive := snap.ServerDelay(srv.ID); obsAlive && obsMs > 0 {
		res.ObsMs = obsMs
	}

	host, port, ok := outboundEndpoint(srv.Outbound)
	if !ok {
		res.Error = "server endpoint could not be determined"
		return res
	}

	// 1. Direct TCP 1-RTT handshake to server host:port.
	dialCtx, cancel := context.WithTimeout(ctx, pingTCPTimeout)
	t0 := time.Now()
	d := net.Dialer{Timeout: pingTCPTimeout}
	conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	cancel()
	if err != nil {
		res.Error = redact(classifyDialErr(err))
		return res
	}
	_ = conn.Close()
	tcpMs := time.Since(t0).Milliseconds()
	if tcpMs < 1 {
		tcpMs = 1
	}
	res.TCPMs = tcpMs
	res.Alive = true

	// 2. When this server is the active SOCKS exit, measure warm HTTP 204 RTT
	// through the live tunnel (v2rayN-style real delay without 5x cold TLS).
	if isActive && s.socks != "" && !s.repairBridge {
		if httpMs, httpErr := measureWarmHTTP(ctx, s.socks, pingHTTPURL); httpErr == nil && httpMs > 0 {
			res.HTTPMs = httpMs
		}
	}
	return res
}

func measureWarmHTTP(ctx context.Context, socksAddr, targetURL string) (int64, error) {
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return 0, err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return 0, errors.New("service: socks dialer does not support context")
	}
	tr := &http.Transport{
		DialContext:         cd.DialContext,
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     10 * time.Second,
	}
	defer tr.CloseIdleConnections()

	hc := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	doOne := func() (int64, error) {
		rctx, cancel := context.WithTimeout(ctx, pingHTTPTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(rctx, http.MethodGet, targetURL, nil)
		if err != nil {
			return 0, err
		}
		t0 := time.Now()
		resp, err := hc.Do(req)
		if err != nil {
			return 0, err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return 0, errors.New("unexpected HTTP status")
		}
		ms := time.Since(t0).Milliseconds()
		if ms < 1 {
			ms = 1
		}
		return ms, nil
	}

	// First request warms the tunnel; second request reuses keep-alive to measure
	// true HTTP round-trip latency through the proxy.
	first, err := doOne()
	if err != nil {
		return 0, err
	}
	if second, err := doOne(); err == nil {
		return second, nil
	}
	return first, nil
}

func classifyDialErr(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "TCP connect timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "TCP connect timeout"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		return "TCP connection refused"
	case strings.Contains(msg, "no such host"):
		return "DNS lookup failed"
	case strings.Contains(msg, "network is unreachable"), strings.Contains(msg, "no route to host"):
		return "network unreachable"
	default:
		return "TCP connect failed"
	}
}

func outboundEndpoint(raw json.RawMessage) (string, int, bool) {
	if len(raw) == 0 {
		return "", 0, false
	}
	var top map[string]any
	if json.Unmarshal(raw, &top) != nil {
		return "", 0, false
	}
	settings, ok := ciMap(top, "settings")
	if !ok {
		return "", 0, false
	}
	if h, p, ok := hostPortFromMap(settings); ok {
		return h, p, true
	}
	for _, listKey := range []string{"vnext", "servers"} {
		if arr, ok := ciSlice(settings, listKey); ok && len(arr) > 0 {
			if m, ok := arr[0].(map[string]any); ok {
				if h, p, ok := hostPortFromMap(m); ok {
					return h, p, true
				}
			}
		}
	}
	return "", 0, false
}

func ciMap(m map[string]any, key string) (map[string]any, bool) {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			out, ok := v.(map[string]any)
			return out, ok
		}
	}
	return nil, false
}

func ciSlice(m map[string]any, key string) ([]any, bool) {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			out, ok := v.([]any)
			return out, ok
		}
	}
	return nil, false
}

func hostPortFromMap(m map[string]any) (string, int, bool) {
	var host string
	var port int
	for k, v := range m {
		switch {
		case strings.EqualFold(k, "address"):
			if s, ok := v.(string); ok {
				host = strings.TrimSpace(s)
			}
		case strings.EqualFold(k, "port"):
			switch n := v.(type) {
			case float64:
				port = int(n)
			case string:
				port, _ = strconv.Atoi(strings.TrimSpace(n))
			}
		}
	}
	if host == "" || port <= 0 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

func newHealthDelayAdapter(snap health.Snapshot) healthDelayAdapter {
	delays := make(map[string]int64, len(snap.Servers))
	for _, s := range snap.Servers {
		if s.Alive && s.Delay > 0 {
			ms := s.Delay.Milliseconds()
			if ms < 1 {
				ms = 1
			}
			delays[s.ID] = ms
		}
	}
	return healthDelayAdapter{delays: delays}
}

// healthDelayAdapter wraps health.Snapshot so measureServer stays decoupled.
type healthDelayAdapter struct {
	delays map[string]int64
}

func (a healthDelayAdapter) ServerDelay(id string) (int64, bool) {
	ms, ok := a.delays[id]
	return ms, ok
}
