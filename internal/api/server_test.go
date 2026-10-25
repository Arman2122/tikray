package api

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// pinnedClient trusts exactly the certificate with this fingerprint, as the
// CLI does; tune changes its TLS settings.
func pinnedClient(fingerprint string, tune ...func(*tls.Config)) *http.Client {
	cfg := &tls.Config{
		// The certificate is self-signed: it is checked below, by its
		// fingerprint, instead of by a chain.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != fingerprint {
				return errors.New("the certificate is not the pinned one")
			}
			return nil
		},
	}
	for _, f := range tune {
		f(cfg)
	}
	tr := &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// running is a Serve that a test started.
type running struct {
	url  string
	fp   string
	stop context.CancelFunc
	done chan error
}

func start(t *testing.T, h http.Handler) *running {
	t.Helper()
	cert, fp, err := LoadOrCreateCert(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	r := &running{url: "https://" + ln.Addr().String(), fp: fp, stop: stop, done: make(chan error, 1)}
	go func() { r.done <- ServeListener(ctx, ln, h, cert) }()
	t.Cleanup(func() {
		stop()
		select {
		case <-r.done:
		case <-time.After(15 * time.Second):
			t.Error("Serve did not return")
		}
	})
	return r
}

func get(t *testing.T, c *http.Client, url, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestServeTLS(t *testing.T) {
	r := start(t, NewHandler(newFake(), testToken))
	good := pinnedClient(r.fp)

	if code, body := get(t, good, r.url+"/healthz", ""); code != 200 || strings.TrimSpace(body) != `{"ok":true}` {
		t.Errorf("/healthz = %d %q", code, body)
	}
	if code, _ := get(t, good, r.url+"/v1/status", testToken); code != 200 {
		t.Errorf("/v1/status with the token = %d, want 200", code)
	}
	if code, _ := get(t, good, r.url+"/v1/status", ""); code != 401 {
		t.Errorf("/v1/status without the token = %d, want 401", code)
	}

	t.Run("a client pinned to another certificate", func(t *testing.T) {
		other := pinnedClient(strings.Repeat("0", 64))
		if _, err := other.Get(r.url + "/healthz"); err == nil {
			t.Error("the handshake succeeded")
		}
	})

	t.Run("TLS 1.2 is the oldest", func(t *testing.T) {
		old := pinnedClient(r.fp, func(c *tls.Config) { c.MinVersion, c.MaxVersion = tls.VersionTLS10, tls.VersionTLS11 })
		if _, err := old.Get(r.url + "/healthz"); err == nil {
			t.Error("a TLS 1.1 handshake succeeded")
		}
		v12 := pinnedClient(r.fp, func(c *tls.Config) { c.MinVersion, c.MaxVersion = tls.VersionTLS12, tls.VersionTLS12 })
		if code, _ := get(t, v12, r.url+"/healthz", ""); code != 200 {
			t.Errorf("a TLS 1.2 client got %d, want 200", code)
		}
	})

	r.stop()
	select {
	case err := <-r.done:
		if err != nil {
			t.Errorf("Serve returned %v after a clean stop", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
	r.done <- nil // for the cleanup
	if _, err := good.Get(r.url + "/healthz"); err == nil {
		t.Error("the server still answers after Serve returned")
	}
}

func TestServeLetsARequestInFlightFinish(t *testing.T) {
	f := newFake()
	entered, release := make(chan struct{}), make(chan struct{})
	f.onStatus = func() {
		close(entered)
		<-release
	}
	r := start(t, NewHandler(f, testToken))
	client := pinnedClient(r.fp)

	type reply struct {
		code int
		err  error
	}
	got := make(chan reply, 1)
	go func() {
		req, _ := http.NewRequest("GET", r.url+"/v1/status", nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		resp, err := client.Do(req)
		if err != nil {
			got <- reply{err: err}
			return
		}
		resp.Body.Close()
		got <- reply{code: resp.StatusCode}
	}()
	<-entered

	r.stop()
	select {
	case err := <-r.done:
		t.Fatalf("Serve returned (%v) with a request still running", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)

	if rep := <-got; rep.err != nil || rep.code != 200 {
		t.Errorf("the request in flight got %d, %v; want 200", rep.code, rep.err)
	}
	select {
	case err := <-r.done:
		if err != nil {
			t.Errorf("Serve returned %v, want nil", err)
		}
		r.done <- nil
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return once the request was done")
	}
}

func TestServeCutsOffARequestThatOutlastsTheShutdown(t *testing.T) {
	old := shutdownTimeout
	shutdownTimeout = 200 * time.Millisecond
	defer func() { shutdownTimeout = old }()

	f := newFake()
	entered, release := make(chan struct{}), make(chan struct{})
	f.onStatus = func() {
		close(entered)
		<-release
	}
	r := start(t, NewHandler(f, testToken))
	t.Cleanup(func() { close(release) })
	client := pinnedClient(r.fp)
	go func() {
		req, _ := http.NewRequest("GET", r.url+"/v1/status", nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	<-entered

	r.stop()
	select {
	case err := <-r.done:
		if err == nil || !strings.HasPrefix(err.Error(), "api: ") {
			t.Errorf("Serve returned %v, want an api: error that says the shutdown was cut short", err)
		}
		r.done <- nil
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestServerSettings(t *testing.T) {
	cert, _, err := LoadOrCreateCert(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(NewHandler(newFake(), testToken), cert)
	if s.ReadHeaderTimeout != 10*time.Second || s.IdleTimeout != 60*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, IdleTimeout = %v; want 10s and 60s", s.ReadHeaderTimeout, s.IdleTimeout)
	}
	// A request must arrive within a minute, a body of 1 MiB included. Core
	// updates and applies take minutes to answer: nothing may cut a response
	// short.
	if s.ReadTimeout != time.Minute {
		t.Errorf("ReadTimeout = %v, want 1m", s.ReadTimeout)
	}
	if s.WriteTimeout != 0 {
		t.Errorf("WriteTimeout = %v, want none", s.WriteTimeout)
	}
	if s.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2", s.TLSConfig.MinVersion)
	}
	if len(s.TLSConfig.Certificates) != 1 {
		t.Errorf("%d certificates, want 1", len(s.TLSConfig.Certificates))
	}
}

func TestServeFailsToListen(t *testing.T) {
	cert, _, err := LoadOrCreateCert(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(newFake(), testToken)

	if err := Serve(context.Background(), "127.0.0.1:notaport", h, cert); err == nil || !strings.HasPrefix(err.Error(), "api: ") {
		t.Errorf("a bad address gave %v, want an api: error", err)
	}

	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if err := Serve(context.Background(), busy.Addr().String(), h, cert); err == nil || !strings.HasPrefix(err.Error(), "api: ") {
		t.Errorf("an address in use gave %v, want an api: error", err)
	}
}

func TestServeStopsWithItsContext(t *testing.T) {
	// Serve itself, on an address it opens: it is up when it answers.
	cert, fp, err := LoadOrCreateCert(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, addr, NewHandler(newFake(), testToken), cert) }()

	client := pinnedClient(fp)
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get("https://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		select {
		case e := <-done:
			t.Fatalf("Serve returned %v", e)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("Serve never answered: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

// A caller can declare a body and never send it. net/http reads what is left
// of a body before it answers, so without a ReadTimeout that holds the
// connection, and the goroutine, for good: with or without the token.
func TestServeBoundsABodyThatNeverComes(t *testing.T) {
	old := readTimeout
	readTimeout = 300 * time.Millisecond
	defer func() { readTimeout = old }()
	r := start(t, NewHandler(newFake(), testToken))
	host := strings.TrimPrefix(r.url, "https://")
	auth := "Authorization: Bearer " + testToken + "\r\n"

	for _, c := range []struct{ name, request string }{
		{"no token, a length and no body", "POST /v1/apply HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n"},
		{"no token, chunked and no chunk", "POST /v1/apply HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"},
		{"the token, a route that ignores the body", "POST /v1/apply HTTP/1.1\r\nHost: x\r\n" + auth + "Content-Length: 100\r\n\r\n"},
		{"the token, a body that stops half way", "PUT /v1/policy HTTP/1.1\r\nHost: x\r\n" + auth + "Content-Length: 100\r\n\r\n{\"mode\""},
	} {
		t.Run(c.name, func(t *testing.T) {
			conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := io.WriteString(conn, c.request); err != nil {
				t.Fatal(err)
			}
			began := time.Now()
			conn.SetReadDeadline(began.Add(5 * time.Second))
			_, err = io.Copy(io.Discard, conn) // until the server closes it
			if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("the server still held the connection after 5 s")
			}
			if took := time.Since(began); took > 3*time.Second {
				t.Errorf("the server closed the connection after %v, with a ReadTimeout of 300ms", took)
			}
		})
	}
}

// The ReadTimeout is for the request. Once it has been read, an operation may
// take as long as it takes.
func TestServeAnOperationMayOutlastTheReadTimeout(t *testing.T) {
	old := readTimeout
	readTimeout = 300 * time.Millisecond
	defer func() { readTimeout = old }()
	f := newFake()
	f.onStatus = func() { time.Sleep(900 * time.Millisecond) }
	f.gate = func(string, context.Context) { time.Sleep(900 * time.Millisecond) }
	r := start(t, NewHandler(f, testToken))
	client := pinnedClient(r.fp)

	if code, body := get(t, client, r.url+"/v1/status", testToken); code != 200 {
		t.Errorf("a request without a body: %d %s", code, body)
	}
	// With a body, which is read to its end before the handler goes on.
	req, _ := http.NewRequest("PUT", r.url+"/v1/policy", strings.NewReader(`{"mode":"full"}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("a request with a body: %d", resp.StatusCode)
	}
}
