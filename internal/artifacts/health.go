package artifacts

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
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
	label := "artifacts: socks probe"
	// The numeric gateway is useful when diagnosing a config override.
	// Never echo an unvalidated address or the remote target URL.
	if addr, err := netip.ParseAddrPort(p.Addr); err == nil && addr.Addr().Zone() == "" {
		label += " through " + addr.String()
	}
	d, err := proxy.SOCKS5("tcp", p.Addr, nil, proxy.Direct)
	if err != nil {
		return errors.New("artifacts: socks probe could not configure the proxy")
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return errors.New("artifacts: socks probe dialer cannot take a context")
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
		return errors.New("artifacts: invalid socks probe URL")
	}
	resp, err := hc.Do(req)
	if err != nil {
		// net/http includes the requested URL in its error, and the peer
		// controls the underlying diagnostic: only its cause is named. Only
		// context errors need their identity preserved for cancellation and
		// retries.
		if cause := ctx.Err(); cause != nil {
			return fmt.Errorf("%s: %w", label, cause)
		}
		return fmt.Errorf("%s: %s", label, probeCause(err))
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: unexpected HTTP status %d", label, resp.StatusCode)
	}
	return nil
}

// probeCause names why a request through the SOCKS proxy failed, in fixed
// words: the proxy refused the connection or reset it, closed it before an
// answer (EOF, which is how xray's SOCKS inbound reports an outbound that
// failed), a SOCKS reply, a DNS lookup of the proxy's name, a timeout, or a
// TLS handshake.
func probeCause(err error) string {
	var dns *net.DNSError
	switch {
	case errors.As(err, &dns):
		return "DNS lookup failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	}
	if reply := socksReply(err); reply != "" {
		return reply
	}
	var timeout interface{ Timeout() bool }
	var verify *tls.CertificateVerificationError
	var header tls.RecordHeaderError
	var alert tls.AlertError
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), closedUnanswered(err):
		return "connection closed (EOF)"
	case errors.As(err, &timeout) && timeout.Timeout():
		return "timeout"
	case errors.As(err, &verify), errors.As(err, &header), errors.As(err, &alert):
		return "TLS handshake failed"
	}
	return "request failed"
}

// closedUnanswered reports whether err is net/http's for a connection that
// closed before it took the request, which it gives instead of io.EOF.
func closedUnanswered(err error) bool {
	for ; err != nil; err = errors.Unwrap(err) {
		if err.Error() == "http: server closed idle connection" {
			return true
		}
	}
	return false
}

// socksReplies are the SOCKS5 reply codes (RFC 1928) by the text x/net/proxy
// gives them.
var socksReplies = map[string]int{
	"general SOCKS server failure":      1,
	"connection not allowed by ruleset": 2,
	"network unreachable":               3,
	"host unreachable":                  4,
	"connection refused":                5,
	"TTL expired":                       6,
	"command not supported":             7,
	"address type not supported":        8,
}

// socksReply names the reply code of a SOCKS server that refused the
// connection, "" when err is no such refusal. x/net/proxy reports one as
// "unknown error <reply>" inside the dial's *net.OpError.
func socksReply(err error) string {
	var op *net.OpError
	if !errors.As(err, &op) || !strings.HasPrefix(op.Op, "socks ") || op.Err == nil {
		return ""
	}
	text, ok := strings.CutPrefix(op.Err.Error(), "unknown error ")
	if !ok {
		return ""
	}
	if code, ok := socksReplies[text]; ok {
		return fmt.Sprintf("SOCKS reply %d (%s)", code, text)
	}
	n, ok := strings.CutPrefix(text, "unknown code: ")
	if code, err := strconv.Atoi(n); ok && err == nil && code > 0 && code <= 255 {
		return fmt.Sprintf("SOCKS reply %d", code)
	}
	return ""
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
		// The client keeps only a fixed cause, such as the gRPC status code
		// name, of what xray api printed.
		msg := fmt.Sprintf("xray api statssys --server=%s: exit status %d", server, resp.ExitCode)
		if cause := strings.TrimSpace(resp.Stderr); cause != "" {
			msg += ": " + cause
		}
		return errors.New(msg)
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
