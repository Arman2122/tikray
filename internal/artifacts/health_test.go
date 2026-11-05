package artifacts

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

// healthFunc is a HealthChecker made of a function.
type healthFunc func(ctx context.Context) error

func (f healthFunc) Check(ctx context.Context) error { return f(ctx) }

func TestSOCKSProbe(t *testing.T) {
	origin := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/generate_204":
			w.WriteHeader(http.StatusNoContent)
		case "/ok":
			w.Write([]byte("hello"))
		case "/blocked":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/moved":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		default:
			http.NotFound(w, r)
		}
	})
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	// The name cannot resolve locally: only the SOCKS server can map it.
	host := "probe.invalid:" + port
	socks, asked := startSOCKS5(t, map[string]string{host: origin.Listener.Addr().String()})

	for _, path := range []string{"/generate_204", "/ok"} {
		if err := (SOCKSProbe{Addr: socks, URL: "http://" + host + path}).Check(bg); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
	for _, h := range asked() {
		if h != host {
			t.Errorf("SOCKS server was asked for %q, want %q", h, host)
		}
	}
	for path, want := range map[string]string{"/blocked": "503", "/moved": "302", "/nowhere": "404"} {
		err := (SOCKSProbe{Addr: socks, URL: "http://" + host + path}).Check(bg)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want HTTP %s", path, err, want)
		}
	}

	start := time.Now()
	err := (SOCKSProbe{Addr: socks, URL: "http://" + host + "/slow", Timeout: 100 * time.Millisecond}).Check(bg)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("slow origin: err = %v after %s, want a timeout after 100ms", err, time.Since(start))
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()
	if err := (SOCKSProbe{Addr: dead, URL: "http://" + host + "/ok"}).Check(bg); err == nil {
		t.Error("a probe through a dead SOCKS port passed")
	}
}

// The probe's errors go into health snapshots and trial history. The
// request URL, net/http's wrapped error and the peer's reason phrase can
// each carry secrets. Only the outcome and status code belong there.
func TestSOCKSProbeDiagnosticPrivacy(t *testing.T) {
	const secret = "private-probe-fixture"
	origin := serve(t, func(w http.ResponseWriter, r *http.Request) {
		c, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error("could not send test HTTP status")
			return
		}
		defer c.Close()
		fmt.Fprintf(buf, "HTTP/1.1 503 %s\r\nContent-Length: 0\r\n\r\n", secret)
		buf.Flush()
	})
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	host := "probe.invalid:" + port
	socks, _ := startSOCKS5(t, map[string]string{host: origin.Listener.Addr().String()})
	target := "http://operator:" + secret + "@" + host + "/ping?token=" + secret
	for _, tc := range []struct{ name, target, socks string }{
		{"invalid target", target + "%zz", socks},
		{"transport failure", target, "127.0.0.1:1"},
		{"peer status", target, socks},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := (SOCKSProbe{Addr: tc.socks, URL: tc.target}).Check(t.Context())
			if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "operator") {
				t.Fatal("the failed probe must return a credential-free diagnostic")
			}
			if tc.name == "peer status" && !strings.Contains(err.Error(), "unexpected HTTP status 503") {
				t.Error("the probe should retain the HTTP status code")
			}
		})
	}
	for _, exp := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		if exp {
			deadline, end := context.WithDeadline(ctx, time.Now().Add(-time.Second))
			ctx = deadline
			end()
		} else {
			cancel()
		}
		err := (SOCKSProbe{Addr: socks, URL: target}).Check(ctx)
		cancel()
		if !errors.Is(err, ctx.Err()) || strings.Contains(err.Error(), secret) {
			t.Error("probe cancellation must retain context identity without its target URL")
		}
	}
}

func TestXrayAPIProbe(t *testing.T) {
	f := newFakeRunner(t, t.TempDir(), &runnerapi.Selection{Core: "26.10.21", Config: "config/" + strings.Repeat("ab", 32) + ".json"})
	var got [][]string
	answer := runnerapi.XrayAPIResponse{}
	f.script(func(f *fakeRunner) {
		f.onXrayAPI = func(w http.ResponseWriter, args []string) {
			got = append(got, args)
			writeJSONReply(w, http.StatusOK, answer)
		}
	})

	if err := (XrayAPIProbe{Runner: f.client()}).Check(bg); err != nil {
		t.Fatal(err)
	}
	if err := (XrayAPIProbe{Runner: f.client(), Server: "127.0.0.1:9999"}).Check(bg); err != nil {
		t.Fatal(err)
	}
	f.script(func(*fakeRunner) {
		want := [][]string{{"statssys", "--server=127.0.0.1:10085"}, {"statssys", "--server=127.0.0.1:9999"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("xray api args = %q, want %q", got, want)
		}
		answer = runnerapi.XrayAPIResponse{ExitCode: 1, Stderr: "failed to dial: connection refused\n"}
	})
	err := (XrayAPIProbe{Runner: f.client()}).Check(bg)
	if err == nil || strings.Contains(err.Error(), "connection refused") || !strings.Contains(err.Error(), "exit status 1") {
		t.Error("expected the exit status without process stderr")
	}

	f.script(func(f *fakeRunner) {
		f.onXrayAPI = func(w http.ResponseWriter, args []string) {
			fakeError(w, http.StatusServiceUnavailable, "no_xray", "no xray is running")
		}
	})
	if err := (XrayAPIProbe{Runner: f.client()}).Check(bg); err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Errorf("err = %v, want the runner's refusal", err)
	}

	// The runner gives xray api 10 s, as long as the client's default
	// timeout, so the probe must wait longer than its client would.
	f.script(func(f *fakeRunner) {
		f.delay["xray-api"] = 300 * time.Millisecond
		f.onXrayAPI = nil
	})
	hc := &http.Client{Timeout: 100 * time.Millisecond, Transport: f.srv.Client().Transport}
	c := f.client()
	c.HTTP = hc
	if err := (XrayAPIProbe{Runner: c}).Check(bg); err != nil {
		t.Errorf("slow xray api: %v", err)
	}
	if c.HTTP != hc || hc.Timeout != 100*time.Millisecond {
		t.Errorf("the caller's client was changed: %+v", c.HTTP)
	}

	if err := (XrayAPIProbe{}).Check(bg); err == nil {
		t.Error("a probe without a runner passed")
	}
}

func TestAllOf(t *testing.T) {
	var ran []string
	pass := func(name string) HealthChecker {
		return healthFunc(func(context.Context) error { ran = append(ran, name); return nil })
	}
	boom := errors.New("boom")
	fail := healthFunc(func(context.Context) error { ran = append(ran, "fail"); return boom })

	if err := AllOf(pass("a"), pass("b")).Check(bg); err != nil || !reflect.DeepEqual(ran, []string{"a", "b"}) {
		t.Errorf("AllOf(a, b) = %v, ran %v", err, ran)
	}
	ran = nil
	if err := AllOf(pass("a"), fail, pass("c")).Check(bg); !errors.Is(err, boom) || !reflect.DeepEqual(ran, []string{"a", "fail"}) {
		t.Errorf("AllOf(a, fail, c) = %v, ran %v; want the failure and c skipped", err, ran)
	}
	if err := AllOf().Check(bg); err != nil {
		t.Errorf("AllOf() = %v", err)
	}
}

// The health probe that decides whether a trial is healthy says why xray's
// API did not answer, in fixed words, and never ends in an empty reason.
func TestReviewXrayAPIProbeLosesItsReason(t *testing.T) {
	const private = "fixture-private-fragment"
	for _, tc := range []struct{ name, stderr, want string }{
		{"a gRPC status", "rpc error: code = Unavailable desc = connection refused " + private,
			"xray api statssys --server=127.0.0.1:10085: exit status 1: rpc error: code = Unavailable"},
		{"no API", "failed to dial 127.0.0.1:10085\n",
			"xray api statssys --server=127.0.0.1:10085: exit status 1: failed to dial xray's API"},
		{"nothing known", private, "xray api statssys --server=127.0.0.1:10085: exit status 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(runnerapi.XrayAPIResponse{ExitCode: 1, Stderr: tc.stderr})
			}))
			defer srv.Close()
			p := XrayAPIProbe{Runner: &runnerapi.Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}}
			err := p.Check(t.Context())
			if err == nil || err.Error() != tc.want {
				t.Errorf("probe error %v, want %q", err, tc.want)
			}
		})
	}
}

// socksThen serves SOCKS5: it accepts a CONNECT for any target, answers with
// reply, and when that is 0 (succeeded) hands the connection to then.
func socksThen(t *testing.T, reply byte, then func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				if _, err := socks5Connect(c); err != nil {
					return
				}
				c.Write([]byte{5, reply, 0, 1, 0, 0, 0, 0, 0, 0})
				if reply == 0 {
					then(c)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// A failed probe names its cause in fixed words: what the probe's request
// met through the proxy, never the URL or what the peer said.
func TestSOCKSProbeCauses(t *testing.T) {
	origin := serve(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	host := "probe.invalid:" + port
	routed, _ := startSOCKS5(t, map[string]string{host: origin.Listener.Addr().String()})
	const dead = "127.0.0.1:1" // nothing listens on a port below 1024 here
	// Closing a socket with unread data resets it: read the request first.
	drain := func(c net.Conn) {
		c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		io.Copy(io.Discard, c)
	}
	closes := socksThen(t, 0, drain)
	resets := socksThen(t, 0, func(c net.Conn) {
		drain(c)
		c.(*net.TCPConn).SetLinger(0)
	})
	stalls := socksThen(t, 0, func(c net.Conn) { io.Copy(io.Discard, c) })
	for _, tc := range []struct {
		name, socks, url string
		timeout          time.Duration
		want             string
	}{
		{"an unexpected status", routed, "http://" + host + "/x", 0, "unexpected HTTP status 503"},
		{"a SOCKS reply", routed, "http://unrouted.invalid/x", 0, "SOCKS reply 4 (host unreachable)"},
		{"a refused SOCKS reply", socksThen(t, 5, nil), "http://probe.invalid/x", 0, "SOCKS reply 5 (connection refused)"},
		{"an unknown SOCKS reply", socksThen(t, 9, nil), "http://probe.invalid/x", 0, "SOCKS reply 9"},
		{"a refused connection", dead, "http://probe.invalid/x", 0, "connection refused"},
		{"a closed connection", closes, "http://probe.invalid/x", 0, "connection closed (EOF)"},
		{"a closed TLS connection", closes, "https://probe.invalid/x", 0, "connection closed (EOF)"},
		{"a reset connection", resets, "http://probe.invalid/x", 0, "connection reset"},
		{"a timeout", stalls, "http://probe.invalid/x", 100 * time.Millisecond, "context deadline exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := (SOCKSProbe{Addr: tc.socks, URL: tc.url, Timeout: tc.timeout}).Check(t.Context())
			if want := "artifacts: socks probe through " + tc.socks + ": " + tc.want; err == nil || err.Error() != want {
				t.Errorf("probe error %v, want %q", err, want)
			}
		})
	}
}

// probeCause reads the errors net/http and x/net/proxy give.
func TestProbeCause(t *testing.T) {
	dial := func(err error) error {
		return &url.Error{Op: "Get", URL: "https://operator:secret@probe.example/x", Err: &net.OpError{Op: "socks connect", Net: "tcp", Err: err}}
	}
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"refused", dial(&net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}), "connection refused"},
		{"reset", &url.Error{Op: "Get", URL: "x", Err: &net.OpError{Op: "read", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}}}, "connection reset"},
		{"EOF", &url.Error{Op: "Get", URL: "x", Err: io.EOF}, "connection closed (EOF)"},
		{"closed before the request", &url.Error{Op: "Get", URL: "x", Err: errors.New("http: server closed idle connection")}, "connection closed (EOF)"},
		{"unexpected EOF", &url.Error{Op: "Get", URL: "x", Err: io.ErrUnexpectedEOF}, "connection closed (EOF)"},
		{"DNS", dial(&net.DNSError{Err: "no such host", Name: "socks.example", IsNotFound: true}), "DNS lookup failed"},
		{"timeout", dial(&net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}), "timeout"},
		{"SOCKS reply", dial(errors.New("unknown error connection not allowed by ruleset")), "SOCKS reply 2 (connection not allowed by ruleset)"},
		{"SOCKS code", dial(errors.New("unknown error unknown code: 200")), "SOCKS reply 200"},
		{"SOCKS code out of range", dial(errors.New("unknown error unknown code: 300")), "request failed"},
		{"TLS", &url.Error{Op: "Get", URL: "x", Err: &tls.CertificateVerificationError{Err: errors.New("x509: secret")}}, "TLS handshake failed"},
		{"anything else", &url.Error{Op: "Get", URL: "x", Err: errors.New("secret")}, "request failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := probeCause(tc.err); got != tc.want {
				t.Errorf("probeCause = %q, want %q", got, tc.want)
			}
		})
	}
}
