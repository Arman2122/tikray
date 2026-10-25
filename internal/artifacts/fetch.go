// Package artifacts obtains xray-core release files for the control plane.
package artifacts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/Arman2122/tikray/internal/xrayver"
)

const (
	defaultRepo     = "https://github.com/XTLS/Xray-core"
	defaultMaxBytes = 200 << 20
	defaultTimeout  = 10 * time.Minute
	defaultStall    = time.Minute
	// latestTimeout bounds one source's release lookup.
	latestTimeout = 30 * time.Second
)

// The bounds of every network source's transport (see newTransport). They are
// variables so that tests can shorten them.
var (
	dialTimeout           = 30 * time.Second
	tlsHandshakeTimeout   = 20 * time.Second
	responseHeaderTimeout = 30 * time.Second
)

// errProxyUnavailable is the proxy source's refusal while xray is not healthy.
var errProxyUnavailable = errors.New("proxy unavailable: xray is not healthy")

// Request names one release file.
type Request struct {
	Version xrayver.Version
	File    string // such as Xray-linux-arm64-v8a.zip
	Arch    string // GOARCH, such as arm64
}

// Source is one place a release file can come from.
type Source interface {
	Name() string
	// Fetch writes the file to w. It succeeds only if the source answered with
	// the whole file; whether the file is the right one is for the caller to check.
	Fetch(ctx context.Context, r Request, w io.Writer) error
}

// latester is implemented by the sources that can look up the newest release.
type latester interface {
	latest(ctx context.Context) (xrayver.Version, error)
}

// upstream is the XTLS release server, reached directly or through the proxy.
type upstream struct {
	name string
	repo string
	hc   *http.Client
	gate func(context.Context) bool // reports whether the source may be used; nil allows it
	err  error                      // why the source cannot work at all
}

// Direct fetches from the upstream release server at repo, which defaults to
// https://github.com/XTLS/Xray-core. A nil hc means a client with the
// bounds of newTransport, which honours the environment's proxy settings.
func Direct(repo string, hc *http.Client) Source {
	if hc == nil {
		hc = &http.Client{Transport: newTransport(nil, http.ProxyFromEnvironment)}
	}
	return &upstream{name: "direct", repo: repoOrDefault(repo), hc: hc}
}

// newTransport is the HTTP transport of every network source. dial makes the
// connections, nil meaning a plain TCP dial, and proxyFn chooses an HTTP
// proxy, nil meaning none. The dial (dialTimeout), the TLS handshake
// (tlsHandshakeTimeout) and the wait for the response headers
// (responseHeaderTimeout) each have a bound, so a peer that accepts the
// connection and then holds it, as xray's SOCKS inbound does in front of a
// dead or throttled outbound, fails the attempt in seconds rather than at the
// chain's Timeout. A body that stops is the chain's watchdog's (Chain.Stall).
func newTransport(dial func(ctx context.Context, network, addr string) (net.Conn, error), proxyFn func(*http.Request) (*url.URL, error)) *http.Transport {
	if dial == nil {
		dial = (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext
	}
	return &http.Transport{
		Proxy: proxyFn,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, dialTimeout)
			defer cancel()
			return dial(ctx, network, addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
	}
}

// Proxy fetches from the same server through the SOCKS5 proxy at socksAddr.
// Names are resolved by the proxy. It fails at once with errProxyUnavailable
// unless healthy reports true, so a nil healthy never allows it.
func Proxy(socksAddr, repo string, healthy func(context.Context) bool) Source {
	if healthy == nil {
		healthy = func(context.Context) bool { return false }
	}
	u := &upstream{name: "proxy", repo: repoOrDefault(repo), gate: healthy}
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		u.err = fmt.Errorf("socks5 proxy %s: %w", socksAddr, err)
		return u
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		u.err = fmt.Errorf("socks5 proxy %s: dialer cannot take a context", socksAddr)
		return u
	}
	// No Proxy func: the environment's proxy settings never apply here.
	tr := newTransport(cd.DialContext, nil)
	tr.DisableKeepAlives = true
	u.hc = &http.Client{Transport: tr}
	return u
}

func repoOrDefault(repo string) string {
	if repo == "" {
		return defaultRepo
	}
	return strings.TrimRight(repo, "/")
}

func (u *upstream) Name() string { return u.name }

func (u *upstream) ready(ctx context.Context) error {
	if u.err != nil {
		return u.err
	}
	if u.gate != nil && !u.gate(ctx) {
		return errProxyUnavailable
	}
	return nil
}

func (u *upstream) Fetch(ctx context.Context, r Request, w io.Writer) error {
	if err := u.ready(ctx); err != nil {
		return err
	}
	return get(ctx, u.hc, u.repo+"/releases/download/"+r.Version.Tag()+"/"+r.File, w)
}

// latest reads the newest release from the redirect of {repo}/releases/latest.
func (u *upstream) latest(ctx context.Context) (xrayver.Version, error) {
	if err := u.ready(ctx); err != nil {
		return xrayver.Version{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, latestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.repo+"/releases/latest", nil)
	if err != nil {
		return xrayver.Version{}, err
	}
	hc := *u.hc
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		return xrayver.Version{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return xrayver.Version{}, fmt.Errorf("HTTP %s, want a redirect to the release", resp.Status)
	}
	loc, err := resp.Location()
	if err != nil {
		return xrayver.Version{}, err
	}
	v, err := xrayver.Parse(path.Base(loc.Path))
	if err != nil {
		return xrayver.Version{}, fmt.Errorf("redirect to %q: %w", loc.Path, err)
	}
	return v, nil
}

// get writes the body of a 2xx answer to w.
func get(ctx context.Context, hc *http.Client, rawURL string, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

// mirror is a user-configured download location.
type mirror struct {
	name     string
	template string
	hc       *http.Client
	err      error // why the template is unusable
}

// Mirror fetches from a URL template in which {version} (26.10.21), {arch}
// (GOARCH) and {file} are replaced. The template must be an http(s) URL with a
// host and must contain {file}; a bad template gives a source that always
// fails. A nil hc means a client like Direct's.
func Mirror(template string, hc *http.Client) Source {
	if hc == nil {
		hc = &http.Client{Transport: newTransport(nil, http.ProxyFromEnvironment)}
	}
	m := &mirror{name: "mirror", template: template, hc: hc}
	u, err := url.Parse(template)
	switch {
	case err != nil:
		m.err = fmt.Errorf("mirror template %q: %w", template, err)
	case u.Scheme != "http" && u.Scheme != "https", u.Host == "":
		m.err = fmt.Errorf("mirror template %q: want an http(s) URL with a host", template)
	case !strings.Contains(template, "{file}"):
		m.err = fmt.Errorf("mirror template %q: lacks {file}", template)
	default:
		m.name = "mirror " + u.Host
	}
	return m
}

func (m *mirror) Name() string { return m.name }

func (m *mirror) Fetch(ctx context.Context, r Request, w io.Writer) error {
	if m.err != nil {
		return m.err
	}
	rawURL := strings.NewReplacer(
		"{version}", r.Version.String(),
		"{arch}", r.Arch,
		"{file}", r.File,
	).Replace(m.template)
	return get(ctx, m.hc, rawURL, w)
}

// inbox is the directory where the operator drops files by hand.
type inbox struct{ dir string }

// Inbox serves the file <dir>/<file>.
func Inbox(dir string) Source { return inbox{dir} }

func (inbox) Name() string { return "inbox" }

func (i inbox) Fetch(_ context.Context, r Request, w io.Writer) error {
	if r.File == "" || r.File == "." || r.File != filepath.Base(r.File) {
		return fmt.Errorf("invalid file name %q", r.File)
	}
	f, err := os.Open(filepath.Join(i.dir, r.File))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

// Chain tries Sources in order until one supplies a file that passes the check.
type Chain struct {
	Sources  []Source
	MaxBytes int64         // most bytes one attempt may write; 0 means 200 MiB
	Timeout  time.Duration // longest one attempt may take; 0 means 10 minutes
	Stall    time.Duration // longest one attempt may go without receiving a byte; 0 means 1 minute
}

// Fetch writes the first acceptable file to dst and returns the name of the
// source that supplied it. Each attempt goes to dst+".part", where check, which
// must not be nil, inspects it; an attempt that fails, exceeds MaxBytes,
// outlasts Timeout or receives nothing for Stall is discarded and the next
// source is tried. On total failure the error lists every "source: reason",
// and dst and the part file are not left behind (a dst that already existed is
// untouched). A canceled ctx stops the chain.
func (c Chain) Fetch(ctx context.Context, r Request, dst string, check func(path string) error) (string, error) {
	if len(c.Sources) == 0 {
		return "", errors.New("no fetch sources configured")
	}
	b := bounds{limit: c.MaxBytes, timeout: c.Timeout, stall: c.Stall}
	if b.limit <= 0 {
		b.limit = defaultMaxBytes
	}
	if b.timeout <= 0 {
		b.timeout = defaultTimeout
	}
	if b.stall <= 0 {
		b.stall = defaultStall
	}
	part := dst + ".part"
	var failed []string
	stopped := func(cause error) error {
		if len(failed) == 0 {
			return fmt.Errorf("fetch %s: %w", r.File, cause)
		}
		return fmt.Errorf("fetch %s: %w (%s)", r.File, cause, strings.Join(failed, "; "))
	}
	for _, s := range c.Sources {
		if err := ctx.Err(); err != nil {
			return "", stopped(err)
		}
		f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return "", fmt.Errorf("fetch %s: %w", r.File, err)
		}
		if err := attempt(ctx, s, r, f, b, check); err != nil {
			os.Remove(part)
			failed = append(failed, s.Name()+": "+err.Error())
			if cerr := ctx.Err(); cerr != nil {
				return "", stopped(cerr)
			}
			continue
		}
		if err := os.Rename(part, dst); err != nil {
			os.Remove(part)
			return "", fmt.Errorf("fetch %s: %w", r.File, err)
		}
		return s.Name(), nil
	}
	return "", fmt.Errorf("fetch %s: no source worked: %s", r.File, strings.Join(failed, "; "))
}

// bounds are the limits of one attempt (see Chain).
type bounds struct {
	limit          int64
	timeout, stall time.Duration
}

// errStalled is why the watchdog cancels an attempt.
var errStalled = errors.New("stalled")

// attempt has s write f, closes f, and runs check on it. A watchdog cancels
// the attempt once it has received nothing for b.stall, from its start or
// from the last byte written.
func attempt(ctx context.Context, s Source, r Request, f *os.File, b bounds, check func(string) error) error {
	actx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	actx, stop := context.WithCancelCause(actx)
	defer stop(nil)
	watchdog := time.AfterFunc(b.stall, func() { stop(errStalled) })
	defer watchdog.Stop()
	cw := &capWriter{w: f, left: b.limit, wrote: func() { watchdog.Reset(b.stall) }}
	err := s.Fetch(actx, r, cw)
	switch {
	case cw.over:
		err = fmt.Errorf("file is larger than %d bytes", b.limit)
	case err != nil && errors.Is(context.Cause(actx), errStalled):
		err = fmt.Errorf("no data for %s: %w", b.stall, err)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return check(f.Name())
}

// capWriter fails the write that would take the total past the cap. wrote,
// if set, is called after each write of at least one byte.
type capWriter struct {
	w     io.Writer
	left  int64
	over  bool
	wrote func()
}

func (c *capWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.left {
		c.over = true
		return 0, errors.New("size cap exceeded")
	}
	n, err := c.w.Write(p)
	c.left -= int64(n)
	if n > 0 && c.wrote != nil {
		c.wrote()
	}
	return n, err
}

// Latest asks the first of the sources that can (direct and proxy) for the
// newest release, without downloading anything. Other sources are skipped.
func Latest(ctx context.Context, sources ...Source) (xrayver.Version, error) {
	var failed []string
	for _, s := range sources {
		l, ok := s.(latester)
		if !ok {
			continue
		}
		if err := ctx.Err(); err != nil {
			return xrayver.Version{}, fmt.Errorf("latest release lookup: %w", err)
		}
		v, err := l.latest(ctx)
		if err == nil {
			return v, nil
		}
		failed = append(failed, s.Name()+": "+err.Error())
	}
	if len(failed) == 0 {
		return xrayver.Version{}, errors.New("latest release lookup: no source can do it")
	}
	return xrayver.Version{}, fmt.Errorf("latest release lookup: %s", strings.Join(failed, "; "))
}
