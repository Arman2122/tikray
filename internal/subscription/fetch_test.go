package subscription

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// subURL is the address every test fetches. No such host exists: clientTo sends
// the request to a test server whatever the host is. It carries a token that
// no error may repeat.
const (
	subToken = "SeCrEtToKeN"
	subURL   = "http://sub.example/sub?token=" + subToken
)

// peer is an httptest server that counts the requests it gets.
type peer struct {
	*httptest.Server
	hits   atomic.Int32
	mu     sync.Mutex
	agents []string
}

func newPeer(t *testing.T, h http.HandlerFunc) *peer {
	t.Helper()
	p := &peer{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.hits.Add(1)
		p.mu.Lock()
		p.agents = append(p.agents, r.Header.Get("User-Agent"))
		p.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *peer) userAgents() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.agents...)
}

// clientTo returns a client that sends every request, whatever its host, to p.
// It is how two test servers stand in for the direct route and the proxy.
func clientTo(p *peer) *http.Client { return clientToWith(p, 0) }

func clientToWith(p *peer, timeout time.Duration) *http.Client {
	_, addr, _ := strings.Cut(p.URL, "://")
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
}

func answer(code int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		io.WriteString(w, body)
	}
}

// hold never answers, until the client goes away.
func hold(w http.ResponseWriter, r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-time.After(10 * time.Second):
	}
}

func healthy(v bool) func(context.Context) bool {
	return func(context.Context) bool { return v }
}

// checkNoURL fails if the error repeats any piece of the URL.
func checkNoURL(t *testing.T, err error, pieces ...string) {
	t.Helper()
	for _, p := range pieces {
		if strings.Contains(err.Error(), p) {
			t.Errorf("error %q repeats %q from the URL", err, p)
		}
	}
}

func TestFetch(t *testing.T) {
	for _, tc := range []struct {
		name string
		// direct and proxy are what the two routes answer; a nil proxy leaves
		// Fetcher.Proxy nil.
		direct, proxy http.HandlerFunc
		proxyHealthy  func(context.Context) bool
		maxBytes      int64

		wantVia    string
		wantBody   string
		wantErr    []string // each must be in the error
		wantNoErr  []string // none may be in the error
		wantDirect int32    // requests to the direct route
		wantProxy  int32    // requests to the proxy route
	}{
		{
			name:   "direct succeeds",
			direct: answer(200, "LIST"), proxy: answer(200, "PROXY"), proxyHealthy: healthy(true),
			wantVia: "direct", wantBody: "LIST", wantDirect: 1,
		},
		{
			name:   "direct fails, proxy succeeds",
			direct: answer(500, "oops"), proxy: answer(200, "PROXY"), proxyHealthy: healthy(true),
			wantVia: "proxy", wantBody: "PROXY", wantDirect: 1, wantProxy: 1,
		},
		{
			name:   "any 2xx is an answer",
			direct: answer(204, ""), proxy: answer(200, "PROXY"), proxyHealthy: healthy(true),
			wantVia: "direct", wantBody: "", wantDirect: 1,
		},
		{
			name: "a redirect is followed",
			direct: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/final" {
					io.WriteString(w, "LIST")
					return
				}
				http.Redirect(w, r, "/final", http.StatusFound)
			},
			proxy: answer(200, "PROXY"), proxyHealthy: healthy(true),
			wantVia: "direct", wantBody: "LIST", wantDirect: 2,
		},
		{
			name:   "not 2xx: a 3xx without a place to go",
			direct: answer(304, ""), proxy: answer(200, "PROXY"), proxyHealthy: healthy(true),
			wantVia: "proxy", wantBody: "PROXY", wantDirect: 1, wantProxy: 1,
		},
		{
			name:   "the proxy is not healthy: the direct error alone",
			direct: answer(500, "oops"), proxy: answer(200, "PROXY"), proxyHealthy: healthy(false),
			wantErr: []string{"subscription: direct: ", "500"}, wantNoErr: []string{"proxy"}, wantDirect: 1,
		},
		{
			name:   "no health check: the proxy is not used",
			direct: answer(500, "oops"), proxy: answer(200, "PROXY"), proxyHealthy: nil,
			wantErr: []string{"direct", "500"}, wantNoErr: []string{"proxy"}, wantDirect: 1,
		},
		{
			name:   "no proxy client",
			direct: answer(404, "gone"), proxy: nil, proxyHealthy: healthy(true),
			wantErr: []string{"direct", "404"}, wantNoErr: []string{"proxy"}, wantDirect: 1,
		},
		{
			name:   "both fail: the error names both",
			direct: answer(500, "oops"), proxy: answer(503, "later"), proxyHealthy: healthy(true),
			wantErr: []string{"direct", "500", "proxy", "503"}, wantDirect: 1, wantProxy: 1,
		},
		{
			name:   "a body over MaxBytes is an error",
			direct: answer(200, "0123456"), proxy: answer(200, "PROXY"), proxyHealthy: healthy(false), maxBytes: 6,
			wantErr: []string{"direct", "6 bytes"}, wantDirect: 1,
		},
		{
			name:   "a body of MaxBytes is fine",
			direct: answer(200, "012345"), proxy: answer(200, "PROXY"), proxyHealthy: healthy(true), maxBytes: 6,
			wantVia: "direct", wantBody: "012345", wantDirect: 1,
		},
		{
			name:   "too large directly, the proxy has a smaller one",
			direct: answer(200, "0123456"), proxy: answer(200, "012"), proxyHealthy: healthy(true), maxBytes: 6,
			wantVia: "proxy", wantBody: "012", wantDirect: 1, wantProxy: 1,
		},
		{
			name: "too large, announced by Content-Length",
			direct: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "1000000")
				w.WriteHeader(200)
			},
			proxy: answer(200, "PROXY"), proxyHealthy: healthy(false), maxBytes: 6,
			wantErr: []string{"direct", "6 bytes"}, wantDirect: 1,
		},
		{
			name: "a connection that breaks in the body",
			direct: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "100")
				io.WriteString(w, "short")
				w.(http.Flusher).Flush()
				panic(http.ErrAbortHandler)
			},
			proxy: answer(200, "PROXY"), proxyHealthy: healthy(true),
			wantVia: "proxy", wantBody: "PROXY", wantDirect: 1, wantProxy: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := newPeer(t, tc.direct)
			pp := newPeer(t, answer(200, "unused"))
			if tc.proxy != nil {
				pp = newPeer(t, tc.proxy)
			}
			f := Fetcher{Direct: clientTo(dp), ProxyHealthy: tc.proxyHealthy, MaxBytes: tc.maxBytes}
			if tc.proxy != nil {
				f.Proxy = clientTo(pp)
			}

			body, via, err := f.Fetch(context.Background(), subURL)

			if len(tc.wantErr) == 0 {
				if err != nil {
					t.Fatalf("Fetch: %v", err)
				}
				if via != tc.wantVia || string(body) != tc.wantBody {
					t.Errorf("Fetch = %q via %q, want %q via %q", body, via, tc.wantBody, tc.wantVia)
				}
			} else {
				if err == nil {
					t.Fatalf("Fetch = %q via %q, want an error", body, via)
				}
				if body != nil || via != "" {
					t.Errorf("Fetch = %q via %q on error, want nothing", body, via)
				}
				for _, w := range tc.wantErr {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("error %q lacks %q", err, w)
					}
				}
				for _, w := range tc.wantNoErr {
					if strings.Contains(err.Error(), w) {
						t.Errorf("error %q has %q", err, w)
					}
				}
				if !strings.HasPrefix(err.Error(), "subscription: ") {
					t.Errorf("error %q lacks the package prefix", err)
				}
				checkNoURL(t, err, subToken, "sub.example", dp.URL, pp.URL)
			}
			if got := dp.hits.Load(); got != tc.wantDirect {
				t.Errorf("direct got %d requests, want %d", got, tc.wantDirect)
			}
			if got := pp.hits.Load(); got != tc.wantProxy {
				t.Errorf("proxy got %d requests, want %d", got, tc.wantProxy)
			}
		})
	}
}

func TestFetchRefusesOtherURLs(t *testing.T) {
	dp := newPeer(t, answer(200, "LIST"))
	pp := newPeer(t, answer(200, "LIST"))
	f := Fetcher{Direct: clientTo(dp), Proxy: clientTo(pp), ProxyHealthy: healthy(true)}

	for _, raw := range []string{
		"ftp://sub.example/list?token=" + subToken,
		"FTP://sub.example/list",
		"file:///etc/passwd",
		"gopher://sub.example/",
		"ws://sub.example/",
		"//sub.example/list?token=" + subToken,
		"sub.example/list?token=" + subToken,
		"/list?token=" + subToken,
		"http://",
		"https:///list?token=" + subToken,
		"http:",
		"http:opaque?token=" + subToken,
		"",
		"  ",
		"http://sub.example/\x7f?token=" + subToken,
		"http://[::1/list?token=" + subToken,
		"%zz://sub.example/?token=" + subToken,
	} {
		body, via, err := f.Fetch(context.Background(), raw)
		if err == nil || body != nil || via != "" {
			t.Errorf("Fetch(%q) = %q, %q, %v; want an error", raw, body, via, err)
			continue
		}
		if !strings.HasPrefix(err.Error(), "subscription: ") {
			t.Errorf("Fetch(%q) error %q lacks the package prefix", raw, err)
		}
		checkNoURL(t, err, subToken, "sub.example", "passwd")
	}
	if n := dp.hits.Load() + pp.hits.Load(); n != 0 {
		t.Errorf("%d requests were made for URLs that are refused", n)
	}
}

func TestFetchAcceptsHTTPAndHTTPS(t *testing.T) {
	plain := newPeer(t, answer(200, "PLAIN"))
	secure := httptest.NewTLSServer(answer(200, "TLS"))
	t.Cleanup(secure.Close)

	if body, via, err := (Fetcher{Direct: plain.Client()}).Fetch(context.Background(), plain.URL+"/a?b=c"); err != nil || string(body) != "PLAIN" || via != "direct" {
		t.Errorf("http: %q via %q, %v", body, via, err)
	}
	capitals := "HTTPS" + secure.URL[len("https"):]
	if body, via, err := (Fetcher{Direct: secure.Client()}).Fetch(context.Background(), capitals); err != nil || string(body) != "TLS" || via != "direct" {
		t.Errorf("https (scheme in capitals): %q via %q, %v", body, via, err)
	}
}

func TestFetchUserAgent(t *testing.T) {
	for _, tc := range []struct{ set, want string }{
		{"", "tikray"},
		{"tikray", "tikray"},
		{"clash.meta", "clash.meta"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			dp := newPeer(t, answer(500, ""))
			pp := newPeer(t, answer(200, "LIST"))
			f := Fetcher{Direct: clientTo(dp), Proxy: clientTo(pp), ProxyHealthy: healthy(true), UserAgent: tc.set}
			if _, via, err := f.Fetch(context.Background(), subURL); err != nil || via != "proxy" {
				t.Fatalf("Fetch via %q, %v; want the proxy to answer", via, err)
			}
			for name, p := range map[string]*peer{"direct": dp, "proxy": pp} {
				got := p.userAgents()
				if len(got) != 1 || got[0] != tc.want {
					t.Errorf("the %s request carried %q, want one %q", name, got, tc.want)
				}
			}
		})
	}
}

// The default limit is 8 MiB.
func TestFetchDefaultMaxBytes(t *testing.T) {
	const limit = 8 << 20
	for _, tc := range []struct {
		size int
		ok   bool
	}{{limit, true}, {limit + 1, false}} {
		p := newPeer(t, answer(200, strings.Repeat("x", tc.size)))
		body, _, err := (Fetcher{Direct: clientTo(p)}).Fetch(context.Background(), subURL)
		if tc.ok && (err != nil || len(body) != tc.size) {
			t.Errorf("%d bytes: got %d bytes, %v", tc.size, len(body), err)
		}
		if !tc.ok && (err == nil || !strings.Contains(err.Error(), "8388608 bytes")) {
			t.Errorf("%d bytes: got %d bytes, %v; want an error naming the limit", tc.size, len(body), err)
		}
	}
}

// An error names the attempt and what went wrong, never the URL, whose query
// often holds a token, nor the host.
func TestFetchErrorsDoNotRepeatTheURL(t *testing.T) {
	gone := httptest.NewServer(answer(200, ""))
	goneAddr := gone.Listener.Addr().String()
	gone.Close() // an address nothing listens on

	refuse := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, goneAddr)
		},
	}}
	unresolvable := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
		},
	}}
	loop := newPeer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"?"+r.URL.RawQuery+"&x", http.StatusFound)
	})
	slow := newPeer(t, hold)
	bad := newPeer(t, answer(502, "echo "+subToken))

	for _, tc := range []struct {
		name   string
		client *http.Client
		url    string
		want   string
	}{
		{"status", clientTo(bad), subURL, "502"},
		{"connection refused", refuse, subURL, "refused"},
		{"name lookup", unresolvable, "http://" + subToken + ".sub.example/sub", "name"},
		{"timeout", clientToWith(slow, 50*time.Millisecond), subURL, "timed out"},
		{"redirect loop", clientTo(loop), subURL, ""},
		{"userinfo in the URL", clientTo(bad), "http://user:" + subToken + "@sub.example/sub", "502"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Fetcher{Direct: tc.client}.Fetch(context.Background(), tc.url)
			if err == nil {
				t.Fatal("no error")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q lacks %q", err, tc.want)
			}
			if !strings.HasPrefix(err.Error(), "subscription: direct: ") {
				t.Errorf("error %q does not name the attempt", err)
			}
			checkNoURL(t, err, subToken, "sub.example", goneAddr, "127.0.0.1")
		})
	}
}

// A client's own timeout fails the attempt; it is not a cancelled fetch, so
// the proxy gets its turn.
func TestFetchTimeout(t *testing.T) {
	slow := newPeer(t, hold)
	good := newPeer(t, answer(200, "LIST"))

	f := Fetcher{Direct: clientToWith(slow, 50*time.Millisecond), Proxy: clientTo(good), ProxyHealthy: healthy(true)}
	body, via, err := f.Fetch(context.Background(), subURL)
	if err != nil || via != "proxy" || string(body) != "LIST" {
		t.Errorf("Fetch = %q via %q, %v; want the proxy to answer after the direct timeout", body, via, err)
	}

	f.Proxy = clientToWith(slow, 50*time.Millisecond)
	_, _, err = f.Fetch(context.Background(), subURL)
	if err == nil || !strings.Contains(err.Error(), "direct: timed out") || !strings.Contains(err.Error(), "proxy: timed out") {
		t.Errorf("error %v, want both attempts timed out", err)
	}
}

// A cancelled fetch is not a reason to try the proxy.
func TestFetchCancelledDoesNotTryProxy(t *testing.T) {
	t.Run("cancelled while waiting for the direct answer", func(t *testing.T) {
		started := make(chan struct{})
		var once sync.Once
		dp := newPeer(t, func(w http.ResponseWriter, r *http.Request) {
			once.Do(func() { close(started) })
			<-r.Context().Done()
		})
		pp := newPeer(t, answer(200, "PROXY"))
		var asked atomic.Int32
		f := Fetcher{
			Direct: clientTo(dp),
			Proxy:  clientTo(pp),
			ProxyHealthy: func(context.Context) bool {
				asked.Add(1)
				return true
			},
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-started
			cancel()
		}()
		body, via, err := f.Fetch(ctx, subURL)
		if err == nil || body != nil || via != "" {
			t.Fatalf("Fetch = %q via %q, %v; want an error", body, via, err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error %v does not wrap context.Canceled", err)
		}
		checkNoURL(t, err, subToken, "sub.example")
		if strings.Contains(err.Error(), "proxy") {
			t.Errorf("error %q mentions the proxy", err)
		}
		if pp.hits.Load() != 0 || asked.Load() != 0 {
			t.Errorf("the proxy got %d requests and %d health checks after the cancel, want none", pp.hits.Load(), asked.Load())
		}
	})

	t.Run("cancelled before the call", func(t *testing.T) {
		dp := newPeer(t, answer(200, "LIST"))
		pp := newPeer(t, answer(200, "PROXY"))
		f := Fetcher{Direct: clientTo(dp), Proxy: clientTo(pp), ProxyHealthy: healthy(true)}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _, err := f.Fetch(ctx, subURL)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error %v, want one wrapping context.Canceled", err)
		}
		if n := dp.hits.Load() + pp.hits.Load(); n != 0 {
			t.Errorf("%d requests after the cancel, want none", n)
		}
	})

	t.Run("deadline passed while waiting", func(t *testing.T) {
		dp := newPeer(t, hold)
		pp := newPeer(t, answer(200, "PROXY"))
		f := Fetcher{Direct: clientTo(dp), Proxy: clientTo(pp), ProxyHealthy: healthy(true)}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, _, err := f.Fetch(ctx, subURL)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error %v, want one wrapping context.DeadlineExceeded", err)
		}
		if pp.hits.Load() != 0 {
			t.Errorf("the proxy got %d requests after the deadline", pp.hits.Load())
		}
	})

	t.Run("cancelled while waiting for the proxy", func(t *testing.T) {
		started := make(chan struct{})
		dp := newPeer(t, answer(500, ""))
		pp := newPeer(t, func(w http.ResponseWriter, r *http.Request) {
			close(started)
			<-r.Context().Done()
		})
		f := Fetcher{Direct: clientTo(dp), Proxy: clientTo(pp), ProxyHealthy: healthy(true)}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-started
			cancel()
		}()
		_, _, err := f.Fetch(ctx, subURL)
		if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "500") {
			t.Errorf("error %v, want the direct 500 and a cancel", err)
		}
		checkNoURL(t, err, subToken, "sub.example")
	})

	// The context is cancelled between the failed attempt and the health check.
	t.Run("cancelled by the health check", func(t *testing.T) {
		dp := newPeer(t, answer(500, ""))
		pp := newPeer(t, answer(200, "PROXY"))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f := Fetcher{Direct: clientTo(dp), Proxy: clientTo(pp), ProxyHealthy: func(context.Context) bool {
			cancel()
			return true
		}}
		_, _, err := f.Fetch(ctx, subURL)
		if err == nil {
			t.Error("no error")
		}
		if pp.hits.Load() != 0 {
			t.Errorf("the proxy got %d requests after the cancel", pp.hits.Load())
		}
	})
}

func TestFetchProxyHealthyGetsTheContext(t *testing.T) {
	type key struct{}
	dp := newPeer(t, answer(500, ""))
	var got any
	f := Fetcher{Direct: clientTo(dp), Proxy: clientTo(dp), ProxyHealthy: func(ctx context.Context) bool {
		got = ctx.Value(key{})
		return false
	}}
	f.Fetch(context.WithValue(context.Background(), key{}, "ctx"), subURL)
	if got != "ctx" {
		t.Errorf("ProxyHealthy got a context without the caller's values: %v", got)
	}
}

func TestFetchWithoutClients(t *testing.T) {
	p := newPeer(t, answer(200, "LIST"))
	if _, _, err := (Fetcher{}).Fetch(context.Background(), subURL); err == nil || !strings.HasPrefix(err.Error(), "subscription: ") {
		t.Errorf("error %v, want a subscription error", err)
	}
	// A nil Direct leaves the proxy.
	f := Fetcher{Proxy: clientTo(p), ProxyHealthy: healthy(true)}
	if body, via, err := f.Fetch(context.Background(), subURL); err != nil || via != "proxy" || string(body) != "LIST" {
		t.Errorf("Fetch = %q via %q, %v; want the proxy's answer", body, via, err)
	}
	f.ProxyHealthy = healthy(false)
	if _, _, err := f.Fetch(context.Background(), subURL); err == nil {
		t.Error("no error with no direct client and an unhealthy proxy")
	}
	if n := p.hits.Load(); n != 1 {
		t.Errorf("%d requests, want 1", n)
	}
}
