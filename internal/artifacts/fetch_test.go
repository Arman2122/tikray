package artifacts

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/xrayver"
)

const payload = "PK-test-payload"

var testReq = Request{
	Version: xrayver.Version{Major: 26, Minor: 10, Patch: 21},
	File:    "Xray-linux-64.zip",
	Arch:    "amd64",
}

func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func status(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }
}

func text(s string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, s) }
}

// streamForever answers 200 and keeps sending until the client goes away.
func streamForever(w http.ResponseWriter, r *http.Request) {
	chunk := make([]byte, 32<<10)
	for {
		if _, err := w.Write(chunk); err != nil {
			return
		}
		select {
		case <-r.Context().Done():
			return
		default:
		}
	}
}

// mirrorOf returns a mirror source for srv serving every file under /mirror.
func mirrorOf(srv *httptest.Server) Source {
	return Mirror(srv.URL+"/mirror/{version}/{file}", srv.Client())
}

// payloadCheck accepts a part file that holds exactly payload.
func payloadCheck(t *testing.T, dst string) func(string) error {
	t.Helper()
	return func(path string) error {
		if path != dst+".part" {
			t.Errorf("check got %q, want the part file %q", path, dst+".part")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if string(b) != payload {
			return fmt.Errorf("unexpected content %.20q", b)
		}
		return nil
	}
}

type funcSource struct {
	name  string
	fn    func(ctx context.Context, r Request, w io.Writer) error
	calls int
}

func (s *funcSource) Name() string { return s.name }
func (s *funcSource) Fetch(ctx context.Context, r Request, w io.Writer) error {
	s.calls++
	return s.fn(ctx, r, w)
}

func writes(s string) func(context.Context, Request, io.Writer) error {
	return func(_ context.Context, _ Request, w io.Writer) error {
		_, err := io.WriteString(w, s)
		return err
	}
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func wantOnly(t *testing.T, dir, name string) {
	t.Helper()
	if got := dirNames(t, dir); len(got) != 1 || got[0] != name {
		t.Errorf("directory holds %v, want only %q", got, name)
	}
}

func TestChainOrderAndFallback(t *testing.T) {
	var directHits atomic.Int32
	direct := serve(t, func(w http.ResponseWriter, r *http.Request) {
		directHits.Add(1)
		if want := "/releases/download/v26.10.21/Xray-linux-64.zip"; r.URL.Path != want {
			t.Errorf("direct path %q, want %q", r.URL.Path, want)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	mirror := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if want := "/mirror/26.10.21/Xray-linux-64.zip"; r.URL.Path != want {
			t.Errorf("mirror path %q, want %q", r.URL.Path, want)
		}
		io.WriteString(w, payload)
	})
	inboxDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(inboxDir, testReq.File), []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	inbox := Inbox(inboxDir)
	spy := &funcSource{name: "inbox", fn: inbox.Fetch}

	dst := filepath.Join(t.TempDir(), "xray.zip")
	src, err := Chain{Sources: []Source{
		Direct(direct.URL, direct.Client()),
		mirrorOf(mirror),
		spy,
	}}.Fetch(context.Background(), testReq, dst, payloadCheck(t, dst))
	if err != nil {
		t.Fatal(err)
	}
	if want := "mirror " + mirror.Listener.Addr().String(); src != want {
		t.Errorf("source %q, want %q", src, want)
	}
	if n := directHits.Load(); n != 1 {
		t.Errorf("direct hit %d times, want 1", n)
	}
	if spy.calls != 0 {
		t.Errorf("inbox read %d times after the mirror worked", spy.calls)
	}
	if b, _ := os.ReadFile(dst); string(b) != payload {
		t.Errorf("dst holds %q", b)
	}
	wantOnly(t, filepath.Dir(dst), "xray.zip")
}

func TestChainCheckRejects(t *testing.T) {
	html := serve(t, text("<html><body>Please log in</body></html>"))
	good := serve(t, text(payload))
	dst := filepath.Join(t.TempDir(), "xray.zip")
	var rejected int
	check := payloadCheck(t, dst)
	src, err := Chain{Sources: []Source{
		Direct(html.URL, html.Client()),
		Mirror(good.URL+"/{file}", good.Client()),
	}}.Fetch(context.Background(), testReq, dst, func(p string) error {
		err := check(p)
		if err != nil {
			rejected++
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(src, "mirror ") {
		t.Errorf("source %q, want the mirror", src)
	}
	if rejected != 1 {
		t.Errorf("check rejected %d files, want 1", rejected)
	}
	wantOnly(t, filepath.Dir(dst), "xray.zip")
}

func TestChainSizeCap(t *testing.T) {
	endless := serve(t, streamForever)
	good := serve(t, text(payload))
	dir := t.TempDir()
	dst := filepath.Join(dir, "xray.zip")
	chain := Chain{
		Sources:  []Source{Direct(endless.URL, endless.Client()), Mirror(good.URL+"/{file}", good.Client())},
		MaxBytes: 1 << 20,
	}
	src, err := chain.Fetch(context.Background(), testReq, dst, payloadCheck(t, dst))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(src, "mirror ") {
		t.Errorf("source %q, want the mirror", src)
	}
	wantOnly(t, dir, "xray.zip")

	// With nothing else to try, the cap is what the error says.
	dir = t.TempDir()
	dst = filepath.Join(dir, "xray.zip")
	chain.Sources = chain.Sources[:1]
	_, err = chain.Fetch(context.Background(), testReq, dst, payloadCheck(t, dst))
	if err == nil || !strings.Contains(err.Error(), "direct:") || !strings.Contains(err.Error(), "1048576") {
		t.Errorf("error %v, want the direct attempt to exceed 1048576 bytes", err)
	}
	if got := dirNames(t, dir); len(got) != 0 {
		t.Errorf("directory holds %v after the failure", got)
	}
}

func TestChainSizeBoundary(t *testing.T) {
	for _, tc := range []struct {
		size int
		ok   bool
	}{{999, true}, {1000, true}, {1001, false}} {
		dir := t.TempDir()
		dst := filepath.Join(dir, "xray.zip")
		s := &funcSource{name: "fake", fn: writes(strings.Repeat("a", tc.size))}
		_, err := Chain{Sources: []Source{s}, MaxBytes: 1000}.Fetch(context.Background(), testReq, dst, func(string) error { return nil })
		if (err == nil) != tc.ok {
			t.Errorf("size %d: err = %v, want ok = %v", tc.size, err, tc.ok)
		}
		if tc.ok {
			wantOnly(t, dir, "xray.zip")
		} else if got := dirNames(t, dir); len(got) != 0 {
			t.Errorf("size %d: directory holds %v", tc.size, got)
		}
	}
}

func TestChainAllFail(t *testing.T) {
	direct := serve(t, status(http.StatusServiceUnavailable))
	mirror := serve(t, status(http.StatusNotFound))
	empty := t.TempDir()
	dir := t.TempDir()
	dst := filepath.Join(dir, "xray.zip")
	_, err := Chain{Sources: []Source{
		Direct(direct.URL, direct.Client()),
		mirrorOf(mirror),
		Inbox(empty),
	}}.Fetch(context.Background(), testReq, dst, payloadCheck(t, dst))
	if err == nil {
		t.Fatal("no error with every source failing")
	}
	for _, want := range []string{
		"direct: HTTP 503",
		"mirror " + mirror.Listener.Addr().String() + ": HTTP 404",
		"inbox: ",
		"no such file",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if got := dirNames(t, dir); len(got) != 0 {
		t.Errorf("directory holds %v after total failure", got)
	}
}

func TestChainTimeout(t *testing.T) {
	release := make(chan struct{})
	stall := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) }) // runs before stall.Close
	good := serve(t, text(payload))
	dir := t.TempDir()
	dst := filepath.Join(dir, "xray.zip")
	chain := Chain{
		Sources: []Source{Direct(stall.URL, stall.Client()), Mirror(good.URL+"/{file}", good.Client())},
		Timeout: 200 * time.Millisecond,
	}
	start := time.Now()
	src, err := chain.Fetch(context.Background(), testReq, dst, payloadCheck(t, dst))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(src, "mirror ") {
		t.Errorf("source %q, want the mirror", src)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v with a 200ms timeout", d)
	}
	wantOnly(t, dir, "xray.zip")

	chain.Sources = chain.Sources[:1]
	_, err = chain.Fetch(context.Background(), testReq, dst+"2", payloadCheck(t, dst+"2"))
	if err == nil || !strings.Contains(err.Error(), "direct:") || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Errorf("error %v, want the direct attempt to hit its deadline", err)
	}
	wantOnly(t, dir, "xray.zip")
}

func TestChainContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &funcSource{name: "fake", fn: writes(payload)}
	dir := t.TempDir()
	dst := filepath.Join(dir, "xray.zip")
	_, err := Chain{Sources: []Source{s}}.Fetch(ctx, testReq, dst, payloadCheck(t, dst))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v, want context.Canceled", err)
	}
	if s.calls != 0 {
		t.Errorf("source tried %d times after cancellation", s.calls)
	}

	// Cancellation during an attempt stops the chain before the next source.
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	first := &funcSource{name: "first", fn: func(context.Context, Request, io.Writer) error {
		cancel()
		return errors.New("interrupted")
	}}
	second := &funcSource{name: "second", fn: writes(payload)}
	_, err = Chain{Sources: []Source{first, second}}.Fetch(ctx, testReq, dst, payloadCheck(t, dst))
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "first: interrupted") {
		t.Errorf("error %v, want context.Canceled naming first", err)
	}
	if second.calls != 0 {
		t.Errorf("second source tried after cancellation")
	}
	if got := dirNames(t, dir); len(got) != 0 {
		t.Errorf("directory holds %v", got)
	}
}

func TestChainExistingDst(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "xray.zip")
	if err := os.WriteFile(dst, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := &funcSource{name: "bad", fn: func(context.Context, Request, io.Writer) error { return errors.New("boom") }}
	if _, err := (Chain{Sources: []Source{bad}}).Fetch(context.Background(), testReq, dst, payloadCheck(t, dst)); err == nil {
		t.Fatal("no error from a failing source")
	}
	if b, _ := os.ReadFile(dst); string(b) != "old" {
		t.Errorf("a failed fetch changed dst to %q", b)
	}
	good := &funcSource{name: "good", fn: writes(payload)}
	if _, err := (Chain{Sources: []Source{good}}).Fetch(context.Background(), testReq, dst, payloadCheck(t, dst)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != payload {
		t.Errorf("dst holds %q after a good fetch", b)
	}
	wantOnly(t, dir, "xray.zip")
}

func TestChainNoSources(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "xray.zip")
	if _, err := (Chain{}).Fetch(context.Background(), testReq, dst, payloadCheck(t, dst)); err == nil {
		t.Error("no error from a chain with no sources")
	}
}

func TestChainUnwritableDst(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "missing", "xray.zip")
	s := &funcSource{name: "fake", fn: writes(payload)}
	_, err := Chain{Sources: []Source{s}}.Fetch(context.Background(), testReq, dst, payloadCheck(t, dst))
	if err == nil {
		t.Fatal("no error when the part file cannot be created")
	}
	if s.calls != 0 {
		t.Errorf("source tried %d times with nowhere to write", s.calls)
	}
}

func TestDirectURL(t *testing.T) {
	var got []string
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		got = append(got, r.URL.String())
		return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(payload)), Request: r}, nil
	})
	hc := &http.Client{Transport: rt}
	for _, repo := range []string{"", "https://example.test/o/r/", "https://example.test/o/r"} {
		s := Direct(repo, hc)
		if s.Name() != "direct" {
			t.Errorf("name %q", s.Name())
		}
		if err := s.Fetch(context.Background(), testReq, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"https://github.com/XTLS/Xray-core/releases/download/v26.10.21/Xray-linux-64.zip",
		"https://example.test/o/r/releases/download/v26.10.21/Xray-linux-64.zip",
		"https://example.test/o/r/releases/download/v26.10.21/Xray-linux-64.zip",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("requested\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDirectFollowsRedirects(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/releases/download/") {
			http.Redirect(w, r, "/blob/abc", http.StatusFound)
			return
		}
		io.WriteString(w, payload)
	})
	var b strings.Builder
	if err := Direct(srv.URL, srv.Client()).Fetch(context.Background(), testReq, &b); err != nil {
		t.Fatal(err)
	}
	if b.String() != payload {
		t.Errorf("got %q", b.String())
	}
}

func TestMirrorTemplate(t *testing.T) {
	paths := make(chan string, 1)
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
		io.WriteString(w, payload)
	})
	r := Request{Version: testReq.Version, File: "Xray-linux-arm64-v8a.zip", Arch: "arm64"}
	s := Mirror(srv.URL+"/x/v{version}/{arch}/{file}", srv.Client())
	if err := s.Fetch(context.Background(), r, io.Discard); err != nil {
		t.Fatal(err)
	}
	if want, got := "/x/v26.10.21/arm64/Xray-linux-arm64-v8a.zip", <-paths; got != want {
		t.Errorf("mirror requested %q, want %q", got, want)
	}
	if want := "mirror " + srv.Listener.Addr().String(); s.Name() != want {
		t.Errorf("name %q, want %q", s.Name(), want)
	}
	if got := Mirror("http://m/x/v{version}/{arch}/{file}", nil).Name(); got != "mirror m" {
		t.Errorf("name %q, want %q", got, "mirror m")
	}
}

func TestMirrorRejectsBadTemplates(t *testing.T) {
	for _, tmpl := range []string{
		"http://m/x/v{version}",   // nothing names the file
		"ftp://m/{file}",          // not http(s)
		"{file}",                  // no host
		"http://m:badport/{file}", // unparsable
		"",
	} {
		s := Mirror(tmpl, nil)
		err := s.Fetch(context.Background(), testReq, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "mirror template") {
			t.Errorf("template %q: error %v, want a template error", tmpl, err)
		}
		if !strings.HasPrefix(s.Name(), "mirror") {
			t.Errorf("template %q: name %q", tmpl, s.Name())
		}
	}
}

func TestInbox(t *testing.T) {
	dir := t.TempDir()
	s := Inbox(dir)
	if s.Name() != "inbox" {
		t.Errorf("name %q", s.Name())
	}
	var b strings.Builder
	if err := s.Fetch(context.Background(), testReq, &b); err == nil {
		t.Error("no error for a missing file")
	}
	if err := os.WriteFile(filepath.Join(dir, testReq.File), []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Fetch(context.Background(), testReq, &b); err != nil || b.String() != payload {
		t.Errorf("Fetch = %v, %q", err, b.String())
	}
	for _, name := range []string{"../" + testReq.File, "sub/" + testReq.File, "", "."} {
		r := testReq
		r.File = name
		if err := s.Fetch(context.Background(), r, io.Discard); err == nil {
			t.Errorf("file name %q accepted", name)
		}
	}
}

func TestProxySkippedWhenUnhealthy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if c, err := ln.Accept(); err == nil {
			c.Close()
			t.Error("the SOCKS address was dialed while unhealthy")
		}
	}()
	defer func() {
		ln.Close()
		<-done
	}()

	var asked int
	s := Proxy(ln.Addr().String(), "http://github.invalid/o/r", func(context.Context) bool {
		asked++
		return false
	})
	if s.Name() != "proxy" {
		t.Errorf("name %q", s.Name())
	}
	if err := s.Fetch(context.Background(), testReq, io.Discard); !errors.Is(err, errProxyUnavailable) {
		t.Errorf("Fetch error %v, want errProxyUnavailable", err)
	}
	if _, err := Latest(context.Background(), s); err == nil || !strings.Contains(err.Error(), "proxy: ") {
		t.Errorf("Latest error %v, want the proxy named", err)
	}
	if asked != 2 {
		t.Errorf("healthy asked %d times, want 2", asked)
	}

	// A chain reports the skip and moves on.
	good := &funcSource{name: "good", fn: writes(payload)}
	dst := filepath.Join(t.TempDir(), "xray.zip")
	src, err := Chain{Sources: []Source{s, good}}.Fetch(context.Background(), testReq, dst, payloadCheck(t, dst))
	if err != nil || src != "good" {
		t.Errorf("Fetch = %q, %v", src, err)
	}

	// A nil healthy never allows the proxy.
	if err := Proxy(ln.Addr().String(), "", nil).Fetch(context.Background(), testReq, io.Discard); !errors.Is(err, errProxyUnavailable) {
		t.Errorf("nil healthy: error %v, want errProxyUnavailable", err)
	}
}

func TestProxyThroughSOCKS5(t *testing.T) {
	origin := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/o/r/releases/download/v26.10.21/Xray-linux-64.zip":
			io.WriteString(w, payload)
		case "/o/r/releases/latest":
			http.Redirect(w, r, "/o/r/releases/tag/v26.10.22", http.StatusFound)
		default:
			t.Errorf("origin got %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	// The name cannot resolve locally: only the SOCKS server can map it.
	host := "github.invalid:" + port
	socks, asked := startSOCKS5(t, map[string]string{host: origin.Listener.Addr().String()})

	s := Proxy(socks, "http://"+host+"/o/r", func(context.Context) bool { return true })
	var b strings.Builder
	if err := s.Fetch(context.Background(), testReq, &b); err != nil {
		t.Fatal(err)
	}
	if b.String() != payload {
		t.Errorf("got %q", b.String())
	}
	v, err := Latest(context.Background(), s)
	if err != nil || v != (xrayver.Version{Major: 26, Minor: 10, Patch: 22}) {
		t.Errorf("Latest = %v, %v", v, err)
	}
	for _, h := range asked() {
		if h != host {
			t.Errorf("SOCKS server was asked for %q, want %q", h, host)
		}
	}
	if n := len(asked()); n != 2 {
		t.Errorf("SOCKS server saw %d connections, want 2", n)
	}
}

func TestLatest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler func(w http.ResponseWriter, r *http.Request)
		want    xrayver.Version
		wantErr string
	}{
		{"relative", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/XTLS/Xray-core/releases/tag/v26.10.21", http.StatusFound)
		}, xrayver.Version{Major: 26, Minor: 10, Patch: 21}, ""},
		{"absolute", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://"+r.Host+"/XTLS/Xray-core/releases/tag/v26.10.21", http.StatusFound)
		}, xrayver.Version{Major: 26, Minor: 10, Patch: 21}, ""},
		{"nightly", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/tag/nightly", http.StatusFound)
		}, xrayver.Version{}, "nightly"},
		{"no redirect", text("<html>"), xrayver.Version{}, "HTTP 200"},
		{"server error", status(http.StatusServiceUnavailable), xrayver.Version{}, "HTTP 503"},
		{"redirect without location", status(http.StatusFound), xrayver.Version{}, "Location"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var paths []string
			var mu sync.Mutex
			srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				paths = append(paths, r.URL.Path)
				mu.Unlock()
				tc.handler(w, r)
			})
			v, err := Latest(context.Background(), Direct(srv.URL, srv.Client()))
			if tc.wantErr == "" {
				if err != nil || v != tc.want {
					t.Errorf("Latest = %v, %v, want %v", v, err, tc.want)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Latest error %v, want %q", err, tc.wantErr)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(paths) != 1 || paths[0] != "/releases/latest" {
				t.Errorf("server saw %v, want one request for /releases/latest and no redirect followed", paths)
			}
		})
	}
}

func TestLatestRedirectCodes(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/tag/v1.2.3", code)
		})
		v, err := Latest(context.Background(), Direct(srv.URL, srv.Client()))
		if err != nil || v != (xrayver.Version{Major: 1, Minor: 2, Patch: 3}) {
			t.Errorf("status %d: Latest = %v, %v", code, v, err)
		}
	}
}

func TestLatestSources(t *testing.T) {
	down := serve(t, status(http.StatusServiceUnavailable))
	up := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/tag/v26.10.21", http.StatusFound)
	})
	mirror := serve(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("a mirror was asked for the latest version")
	})

	// Sources that cannot answer are skipped; a failed one falls through.
	v, err := Latest(context.Background(),
		Inbox(t.TempDir()),
		mirrorOf(mirror),
		Direct(down.URL, down.Client()),
		Direct(up.URL, up.Client()),
	)
	if err != nil || v != (xrayver.Version{Major: 26, Minor: 10, Patch: 21}) {
		t.Errorf("Latest = %v, %v", v, err)
	}

	// All failing: every attempt is reported.
	_, err = Latest(context.Background(), Direct(down.URL, down.Client()), Direct(down.URL, down.Client()))
	if err == nil || strings.Count(err.Error(), "direct: HTTP 503") != 2 {
		t.Errorf("error %v, want both attempts listed", err)
	}

	// Nothing to ask.
	if _, err := Latest(context.Background(), Inbox(t.TempDir()), mirrorOf(mirror)); err == nil {
		t.Error("no error when no source can look up the latest release")
	}
	if _, err := Latest(context.Background()); err == nil {
		t.Error("no error with no sources")
	}
}

// startSOCKS5 runs a minimal SOCKS5 server (no authentication, CONNECT only).
// route maps the host:port a client asks for to the address it connects to. The
// returned func lists the host:port values clients asked for.
func startSOCKS5(t *testing.T, route map[string]string) (addr string, asked func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		conns []net.Conn
		seen  []string
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				want, err := socks5Connect(c)
				if err != nil {
					return
				}
				mu.Lock()
				seen = append(seen, want)
				mu.Unlock()
				target, err := net.Dial("tcp", route[want])
				if err != nil {
					c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer target.Close()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				done := make(chan struct{})
				go func() {
					io.Copy(target, c)
					target.Close()
					close(done)
				}()
				io.Copy(c, target)
				c.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// socks5Connect reads the greeting and CONNECT request and returns the
// requested host:port.
func socks5Connect(c net.Conn) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != 5 {
		return "", fmt.Errorf("socks version %d", hdr[0])
	}
	if _, err := io.ReadFull(c, make([]byte, hdr[1])); err != nil {
		return "", err
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return "", err
	}
	if req[1] != 1 {
		return "", fmt.Errorf("socks command %d", req[1])
	}
	var host string
	switch req[3] {
	case 1, 4: // IPv4, IPv6
		ip := make([]byte, 4)
		if req[3] == 4 {
			ip = make([]byte, 16)
		}
		if _, err := io.ReadFull(c, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return "", err
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		return "", fmt.Errorf("socks address type %d", req[3])
	}
	var p [2]byte
	if _, err := io.ReadFull(c, p[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}
