package subscription

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
)

const (
	defaultMaxBytes  = 8 << 20
	defaultUserAgent = "tikray"
)

// Fetcher downloads subscriptions: directly, and when that fails through the
// proxy. The clients set the timeouts, so that a server that holds the
// connection fails the attempt (see artifacts.HTTPClient).
type Fetcher struct {
	// Direct is the client for the first attempt. When it is nil there is no
	// direct attempt.
	Direct *http.Client
	// Proxy is the client for the second attempt, which goes through xray. When
	// it is nil there is no second attempt.
	Proxy *http.Client
	// ProxyHealthy reports whether the proxy works. It is asked only after the
	// direct attempt failed, and a nil ProxyHealthy says no.
	ProxyHealthy func(context.Context) bool
	// MaxBytes is the most a body may hold; 0 means 8 MiB.
	MaxBytes int64
	// UserAgent is sent with every request; empty means "tikray".
	UserAgent string
	// Accept, if set, checks the body of a 2xx answer. A body it refuses fails
	// that attempt, as an error status would: the proxy still gets its turn,
	// and Fetch's error names the attempt with Accept's reason, which must not
	// repeat the body, since a body holds the servers' credentials. A nil
	// Accept takes every body.
	//
	// A refresh should pass an Accept that refuses a body Parse finds no
	// entries in. An ISP's block page or a provider's notice that the account
	// has expired comes with a 200 too, and merging it would remove every
	// server of the subscription.
	Accept func(body []byte) error
}

// Fetch downloads the body of the subscription at rawURL, which must be an
// absolute http or https URL. The answer must be 2xx, and its body no longer
// than MaxBytes and taken by Accept. via says which route supplied it:
// "direct" or "proxy".
//
// Fetch tries Direct first. When that fails it tries Proxy, if there is one and
// ProxyHealthy says it works. A fetch that ctx cancelled, or whose deadline
// passed, stops there, with an error that wraps the context's. When no attempt
// worked, the error names each attempt that was made and what went wrong with
// it: the status, or the kind of failure. It never repeats rawURL, which
// carries a token as a rule, or the address of the server.
func (f Fetcher) Fetch(ctx context.Context, rawURL string) (body []byte, via string, err error) {
	if u, err := url.Parse(rawURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, "", errors.New("subscription: want an absolute http or https URL")
	}
	maxBytes := f.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	agent := f.UserAgent
	if agent == "" {
		agent = defaultUserAgent
	}

	var failed []string
	// ended is the error for a fetch that ctx ended during the attempt.
	ended := func(attempt string) error {
		return fmt.Errorf("subscription: %s: %w", strings.Join(append(failed, attempt), "; "), ctx.Err())
	}
	// try is one attempt with hc: the download, then Accept.
	try := func(hc *http.Client) ([]byte, error) {
		body, err := get(ctx, hc, rawURL, agent, maxBytes)
		if err != nil || f.Accept == nil {
			return body, err
		}
		if err := f.Accept(body); err != nil {
			return nil, errors.New("body refused: " + err.Error())
		}
		return body, nil
	}

	if f.Direct != nil {
		body, err := try(f.Direct)
		if err == nil {
			return body, "direct", nil
		}
		if ctx.Err() != nil {
			return nil, "", ended("direct")
		}
		failed = append(failed, "direct: "+err.Error())
	}

	if f.Proxy != nil && f.ProxyHealthy != nil && f.ProxyHealthy(ctx) {
		body, err := try(f.Proxy)
		if err == nil {
			return body, "proxy", nil
		}
		if ctx.Err() != nil {
			return nil, "", ended("proxy")
		}
		failed = append(failed, "proxy: "+err.Error())
	}

	if len(failed) == 0 {
		return nil, "", errors.New("subscription: no route to fetch by: there is no direct client, and the proxy is missing or not healthy")
	}
	return nil, "", errors.New("subscription: " + strings.Join(failed, "; "))
}

// get downloads rawURL with hc. The error it returns is safe to show: it says
// what happened without the URL, the address of the server or anything the
// server sent but its status.
func get(ctx context.Context, hc *http.Client, rawURL, agent string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("request not valid")
	}
	req.Header.Set("User-Agent", agent)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, errors.New(kind(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	tooLarge := fmt.Errorf("body is larger than %d bytes", maxBytes)
	if resp.ContentLength > maxBytes {
		return nil, tooLarge
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, errors.New(kind(err))
	}
	if int64(len(body)) > maxBytes {
		return nil, tooLarge
	}
	return body, nil
}

// kind names what went wrong with a request or with reading its body. The text
// of the error itself would carry the URL, or the address that was dialed.
func kind(err error) string {
	var ne net.Error
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timed out"
	case errors.As(err, &dns):
		return "name lookup failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "connection closed early"
	case errors.As(err, &cert):
		return "TLS certificate not trusted"
	}
	return "network error"
}
