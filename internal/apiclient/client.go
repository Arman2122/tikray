// Package apiclient calls the tikray service's HTTPS API (internal/api).
//
// The service's certificate is self-signed, so the client trusts the one
// certificate whose SHA-256 fingerprint it is given and nothing else: the
// chain, the names and the dates are not looked at. A connection to any other
// certificate fails in the handshake, before a request is sent, so that the
// token never reaches a server that is not the pinned one.
//
// Each method makes one request and returns the API's answer as it came
// (Response), for a caller that prints it, or decodes it. An answer with an
// error status is an *Error.
package apiclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/store"
)

// maxResponse bounds what the client reads: the state, credentials and all,
// is the largest answer.
var maxResponse = 32 << 20 // a variable for the tests

// dialTimeout bounds making a connection, and its TLS handshake.
const dialTimeout = 10 * time.Second

// Client calls the API of the tikray service at BaseURL.
type Client struct {
	// BaseURL is the service's address, such as https://127.0.0.1:443.
	BaseURL string
	// Token is the bearer token. GET /healthz is the one call that does not
	// send it.
	Token string
	// Fingerprint is the SHA-256 of the service's certificate (its DER), as
	// hex, in either case and with or without colons. An empty or malformed
	// one trusts no certificate: every call fails in the handshake.
	Fingerprint string
	// HTTP, if set, makes the requests instead of a client that is pinned to
	// Fingerprint. Its Transport then does the TLS, and the pin is no longer
	// the client's; the CLI leaves it nil. A client without a CheckRedirect
	// follows redirects.
	HTTP *http.Client
}

// Response is the API's answer to a call that succeeded.
type Response struct {
	// Revision is the ETag: the revision of the state as it is, or the new one
	// after a change. It is 0 when the answer carries none.
	Revision uint64
	// Body is the JSON as the API sent it, empty for an answer with no
	// content.
	Body json.RawMessage
}

// Decode reads the body into v.
func (r Response) Decode(v any) error {
	if len(r.Body) == 0 {
		return errors.New("apiclient: the answer has no body")
	}
	if err := json.Unmarshal(r.Body, v); err != nil {
		return fmt.Errorf("apiclient: reading the answer: %w", err)
	}
	return nil
}

// Error is an answer with an error status: the API's {"error", "detail"}
// body. The detail is redacted by the service. Code and Detail are empty when
// the body is not such an error. Result is how an apply, an update or a
// rollback ended when it failed with an outcome (the body's "result"), and
// nil for every other error.
type Error struct {
	Status int
	Code   string
	Detail string
	Result *artifacts.Result
}

func (e *Error) Error() string {
	s := "apiclient: " + strconv.Itoa(e.Status)
	if e.Code != "" {
		s += " " + e.Code
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// NormalizeFingerprint returns s as 64 lowercase hex digits: the form a
// fingerprint is compared in. It accepts either case, colons between the
// bytes, and white space around it.
func NormalizeFingerprint(s string) (string, error) {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
	if b, err := hex.DecodeString(s); err != nil || len(b) != sha256.Size {
		return "", errors.New("apiclient: a fingerprint is the SHA-256 of the certificate: 64 hex digits, colons between the bytes allowed")
	}
	return s, nil
}

// FingerprintOfPEM returns the fingerprint of the first certificate in
// pemBytes: the SHA-256 of its DER, as lowercase hex, which is what Client
// pins and what the service prints at start.
func FingerprintOfPEM(pemBytes []byte) (string, error) {
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return "", errors.New("apiclient: no certificate in the PEM data")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "", fmt.Errorf("apiclient: reading the certificate: %w", err)
		}
		sum := sha256.Sum256(block.Bytes)
		return hex.EncodeToString(sum[:]), nil
	}
}

// httpClient is the client that makes the requests: c.HTTP, or one that trusts
// the pinned certificate alone, with a connection of its own for each call (a
// resumed session would skip the pin), and that follows no redirect.
func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	want, err := NormalizeFingerprint(c.Fingerprint)
	return &http.Client{
		Transport: &http.Transport{
			Proxy:             nil, // the service is on the router's own network
			DialContext:       (&net.Dialer{Timeout: dialTimeout}).DialContext,
			DisableKeepAlives: true,
			// The answer to an apply or an update comes when it is done, which
			// takes minutes: there is no limit on that, the caller's context
			// is the limit.
			TLSHandshakeTimeout: dialTimeout,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// The pin below replaces the check of the chain, which a
				// self-signed certificate can't pass.
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
					return pinned(want, err, raw)
				},
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// pinned checks the certificate the server presented against the pin. A pin
// that could not be read (perr) admits nothing. It is checked in the
// handshake and not before the dial, so that a caller can tell a service that
// is not there (the dial fails) from one it can't trust.
func pinned(want string, perr error, raw [][]byte) error {
	if perr != nil {
		return perr
	}
	if len(raw) == 0 {
		return errors.New("apiclient: the server presented no certificate")
	}
	sum := sha256.Sum256(raw[0])
	got := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("apiclient: the server's certificate (SHA-256 %s) is not the pinned one", got)
	}
	return nil
}

// Healthz asks whether the service answers. It needs no token, and sends
// none.
func (c *Client) Healthz(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodGet, "/healthz", nil, false)
	return err
}

// do makes one request. in, if not nil, is the JSON body.
func (c *Client) do(ctx context.Context, method, path string, in any, auth bool) (Response, error) {
	var body io.Reader
	if in != nil {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(in); err != nil {
			return Response{}, fmt.Errorf("apiclient: %s %s: %w", method, path, err)
		}
		body = &buf
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, body)
	if err != nil {
		return Response{}, fmt.Errorf("apiclient: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return Response{}, fmt.Errorf("apiclient: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxResponse)+1))
	switch {
	case err != nil:
		return Response{}, fmt.Errorf("apiclient: reading the answer to %s %s: %w", method, path, err)
	case len(b) > maxResponse:
		return Response{}, fmt.Errorf("apiclient: the answer to %s %s is over %d MiB", method, path, maxResponse>>20)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &Error{Status: resp.StatusCode}
		var body struct {
			Error  string            `json:"error"`
			Detail string            `json:"detail"`
			Result *artifacts.Result `json:"result"`
		}
		if json.Unmarshal(b, &body) == nil {
			e.Code, e.Detail, e.Result = body.Error, body.Detail, body.Result
		}
		return Response{}, e
	}
	out := Response{Body: json.RawMessage(b)}
	if len(bytes.TrimSpace(b)) == 0 {
		out.Body = nil
	}
	if v := strings.Trim(resp.Header.Get("ETag"), `"`); v != "" {
		out.Revision, _ = strconv.ParseUint(v, 10, 64)
	}
	return out, nil
}

// get and send are what the methods are made of.
func (c *Client) get(ctx context.Context, path string) (Response, error) {
	return c.do(ctx, http.MethodGet, path, nil, true)
}

func (c *Client) send(ctx context.Context, method, path string, in any) (Response, error) {
	return c.do(ctx, method, path, in, true)
}

// --- reads

// Status is GET /v1/status: a service.Status.
func (c *Client) Status(ctx context.Context) (Response, error) { return c.get(ctx, "/v1/status") }

// State is GET /v1/state: the whole state, credentials included.
func (c *Client) State(ctx context.Context) (Response, error) { return c.get(ctx, "/v1/state") }

// Events is GET /v1/events: the events whose Seq is above after, as a list of
// service.Event.
func (c *Client) Events(ctx context.Context, after uint64) (Response, error) {
	path := "/v1/events"
	if after > 0 {
		path += "?after=" + strconv.FormatUint(after, 10)
	}
	return c.get(ctx, path)
}

// Core is GET /v1/core: the active core, the installed ones and the history.
func (c *Client) Core(ctx context.Context) (Response, error) { return c.get(ctx, "/v1/core") }

// Health is GET /v1/health: the settings of the connectivity probe.
func (c *Client) Health(ctx context.Context) (Response, error) { return c.get(ctx, "/v1/health") }

// --- servers

// NewServer is a server to add: from a share link, or from an xray outbound
// object, exactly one. An outbound needs a Name.
type NewServer struct {
	Link     string          `json:"link,omitempty"`
	Name     string          `json:"name,omitempty"`
	Outbound json.RawMessage `json:"outbound,omitempty"`
}

// ServerPatch changes a server: each field that is set replaces the server's.
type ServerPatch struct {
	Name     *string         `json:"name,omitempty"`
	Disabled *bool           `json:"disabled,omitempty"`
	Link     *string         `json:"link,omitempty"`
	Outbound json.RawMessage `json:"outbound,omitempty"`
}

// Servers is GET /v1/servers: a list of store.Server, credentials included.
func (c *Client) Servers(ctx context.Context) (Response, error) { return c.get(ctx, "/v1/servers") }

// AddServer is POST /v1/servers; the answer is the store.Server.
func (c *Client) AddServer(ctx context.Context, n NewServer) (Response, error) {
	return c.send(ctx, http.MethodPost, "/v1/servers", n)
}

// UpdateServer is PATCH /v1/servers/{id}; the answer is the store.Server.
func (c *Client) UpdateServer(ctx context.Context, id string, p ServerPatch) (Response, error) {
	return c.send(ctx, http.MethodPatch, "/v1/servers/"+url.PathEscape(id), p)
}

// RemoveServer is DELETE /v1/servers/{id}.
func (c *Client) RemoveServer(ctx context.Context, id string) (Response, error) {
	return c.send(ctx, http.MethodDelete, "/v1/servers/"+url.PathEscape(id), nil)
}

// --- subscriptions

// NewSubscription is a subscription to add. A zero Interval is left to the
// service (24 h).
type NewSubscription struct {
	Name     string         `json:"name"`
	URL      string         `json:"url"`
	Interval store.Duration `json:"interval,omitempty"`
}

// SubscriptionPatch changes a subscription: each field that is set replaces
// the subscription's.
type SubscriptionPatch struct {
	Name     *string         `json:"name,omitempty"`
	URL      *string         `json:"url,omitempty"`
	Disabled *bool           `json:"disabled,omitempty"`
	Interval *store.Duration `json:"interval,omitempty"`
}

// RefreshResult is the answer to a refresh: what it did to the subscription's
// servers.
type RefreshResult struct {
	Added   int       `json:"added"`
	Updated int       `json:"updated"`
	Removed int       `json:"removed"`
	Kept    int       `json:"kept"`
	Skipped []Skipped `json:"skipped"`
	// Via is the route the list came by: "direct" or "proxy".
	Via string `json:"via"`
}

// Skipped is a line of a subscription that gave no server, and why. Line is
// the service's label for it, never the line.
type Skipped struct {
	Line   string `json:"line"`
	Reason string `json:"reason"`
}

// Subscriptions is GET /v1/subscriptions: a list of store.Subscription, with
// their URLs.
func (c *Client) Subscriptions(ctx context.Context) (Response, error) {
	return c.get(ctx, "/v1/subscriptions")
}

// AddSubscription is POST /v1/subscriptions; the answer is the
// store.Subscription.
func (c *Client) AddSubscription(ctx context.Context, n NewSubscription) (Response, error) {
	return c.send(ctx, http.MethodPost, "/v1/subscriptions", n)
}

// UpdateSubscription is PATCH /v1/subscriptions/{id}; the answer is the
// store.Subscription.
func (c *Client) UpdateSubscription(ctx context.Context, id string, p SubscriptionPatch) (Response, error) {
	return c.send(ctx, http.MethodPatch, "/v1/subscriptions/"+url.PathEscape(id), p)
}

// RemoveSubscription is DELETE /v1/subscriptions/{id}.
func (c *Client) RemoveSubscription(ctx context.Context, id string) (Response, error) {
	return c.send(ctx, http.MethodDelete, "/v1/subscriptions/"+url.PathEscape(id), nil)
}

// RefreshSubscription is POST /v1/subscriptions/{id}/refresh; the answer is a
// RefreshResult. The service fetches the subscription before it answers.
func (c *Client) RefreshSubscription(ctx context.Context, id string) (Response, error) {
	return c.send(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(id)+"/refresh", nil)
}

// --- devices and settings

// Devices is GET /v1/devices: a list of store.Device.
func (c *Client) Devices(ctx context.Context) (Response, error) { return c.get(ctx, "/v1/devices") }

// devicePath is the route of the device at addr: the prefix, whose slash is
// escaped.
func devicePath(addr netip.Prefix) string { return "/v1/devices/" + url.PathEscape(addr.String()) }

// SetDevice is PUT /v1/devices/{address}: it adds the device or replaces the
// one with its address.
func (c *Client) SetDevice(ctx context.Context, d store.Device) (Response, error) {
	return c.send(ctx, http.MethodPut, devicePath(d.Address), d)
}

// RemoveDevice is DELETE /v1/devices/{address}.
func (c *Client) RemoveDevice(ctx context.Context, addr netip.Prefix) (Response, error) {
	return c.send(ctx, http.MethodDelete, devicePath(addr), nil)
}

// SetPolicy is PUT /v1/policy: the policy of the devices that are not listed.
func (c *Client) SetPolicy(ctx context.Context, p store.Policy) (Response, error) {
	return c.send(ctx, http.MethodPut, "/v1/policy", p)
}

// SetRouting is PUT /v1/routing.
func (c *Client) SetRouting(ctx context.Context, r store.Routing) (Response, error) {
	return c.send(ctx, http.MethodPut, "/v1/routing", r)
}

// SetDNS is PUT /v1/dns.
func (c *Client) SetDNS(ctx context.Context, d store.DNS) (Response, error) {
	return c.send(ctx, http.MethodPut, "/v1/dns", d)
}

// SetHealth is PUT /v1/health.
func (c *Client) SetHealth(ctx context.Context, h store.Health) (Response, error) {
	return c.send(ctx, http.MethodPut, "/v1/health", h)
}

// --- operations

// Apply is POST /v1/apply: it applies the state now. The service answers when
// the trial is over, which can take minutes; the answer is an
// artifacts.Result.
func (c *Client) Apply(ctx context.Context) (Response, error) {
	return c.send(ctx, http.MethodPost, "/v1/apply", nil)
}

// CoreUpdate is POST /v1/core/update: it switches to xray-core version
// ("latest" or a release). The answer is an artifacts.Result.
func (c *Client) CoreUpdate(ctx context.Context, version string, allowUnverified bool) (Response, error) {
	return c.send(ctx, http.MethodPost, "/v1/core/update", struct {
		Version         string `json:"version"`
		AllowUnverified bool   `json:"allow_unverified,omitempty"`
	}{version, allowUnverified})
}

// CoreRollback is POST /v1/core/rollback; the answer is an artifacts.Result.
func (c *Client) CoreRollback(ctx context.Context) (Response, error) {
	return c.send(ctx, http.MethodPost, "/v1/core/rollback", nil)
}
