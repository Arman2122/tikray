package apiclient

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/store"
)

const testToken = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// seen is a request as the test server got it.
type seen struct {
	Method, Path, RawPath, Query string
	Auth, IfMatch, ContentType   string
	Body                         string
}

// recorder is a TLS test server that records its requests and answers each
// with reply.
type recorder struct {
	srv   *httptest.Server
	mu    sync.Mutex
	reqs  []seen
	reply func(w http.ResponseWriter, r *http.Request)
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	rec := &recorder{}
	rec.reply = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"8"`)
		io.WriteString(w, `{"ok":true}`+"\n")
	}
	rec.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.reqs = append(rec.reqs, seen{
			Method: r.Method, Path: r.URL.Path, RawPath: r.URL.EscapedPath(), Query: r.URL.RawQuery,
			Auth: r.Header.Get("Authorization"), IfMatch: r.Header.Get("If-Match"),
			ContentType: r.Header.Get("Content-Type"), Body: string(body),
		})
		rec.mu.Unlock()
		rec.reply(w, r)
	}))
	// A client that refuses the certificate makes the server log the failed
	// handshake: the tests do that on purpose.
	rec.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	rec.srv.StartTLS()
	t.Cleanup(rec.srv.Close)
	return rec
}

func (rec *recorder) requests() []seen {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]seen(nil), rec.reqs...)
}

// last is the one request a call made.
func (rec *recorder) last(t *testing.T) seen {
	t.Helper()
	reqs := rec.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests, want 1: %+v", len(reqs), reqs)
	}
	return reqs[0]
}

func fingerprintOf(srv *httptest.Server) string {
	sum := sha256.Sum256(srv.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

// client is a Client pinned to the test server's certificate.
func (rec *recorder) client() *Client {
	return &Client{BaseURL: rec.srv.URL, Token: testToken, Fingerprint: fingerprintOf(rec.srv)}
}

func TestPinnedFingerprintWorks(t *testing.T) {
	rec := newRecorder(t)
	resp, err := rec.client().Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Revision != 8 {
		t.Errorf("revision %d, want 8 (the ETag)", resp.Revision)
	}
	if got := string(resp.Body); got != `{"ok":true}`+"\n" {
		t.Errorf("body %q, want the API's bytes as they came", got)
	}
	r := rec.last(t)
	if r.Method != "GET" || r.Path != "/v1/status" || r.Auth != "Bearer "+testToken {
		t.Errorf("request %+v, want GET /v1/status with the bearer token", r)
	}
}

func TestFingerprintForms(t *testing.T) {
	rec := newRecorder(t)
	fp := fingerprintOf(rec.srv)
	var colons []string
	for i := 0; i < len(fp); i += 2 {
		colons = append(colons, strings.ToUpper(fp[i:i+2]))
	}
	for name, form := range map[string]string{
		"upper case":      strings.ToUpper(fp),
		"colon separated": strings.Join(colons, ":"),
	} {
		c := rec.client()
		c.Fingerprint = form
		if _, err := c.Status(context.Background()); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestWrongFingerprintIsATLSErrorAndSendsNothing(t *testing.T) {
	rec := newRecorder(t)
	for name, fp := range map[string]string{
		"another certificate": strings.Repeat("ab", 32),
		"none":                "",
		"not hex":             "tikray",
		"too short":           "abcd",
	} {
		c := rec.client()
		c.Fingerprint = fp
		_, err := c.Status(context.Background())
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if !strings.HasPrefix(err.Error(), "apiclient: ") {
			t.Errorf("%s: error %q lacks the package prefix", name, err)
		}
		if strings.Contains(err.Error(), testToken) {
			t.Errorf("%s: the error repeats the token", name)
		}
	}
	// The handshake fails before any request: the token is never sent to a
	// server that is not the pinned one.
	if reqs := rec.requests(); len(reqs) != 0 {
		t.Errorf("the server got %d requests from clients with a wrong pin, want none: %+v", len(reqs), reqs)
	}
	// The error says which certificate it met, so that a person can compare.
	c := rec.client()
	c.Fingerprint = strings.Repeat("ab", 32)
	if _, err := c.Status(context.Background()); err == nil || !strings.Contains(err.Error(), fingerprintOf(rec.srv)) {
		t.Errorf("error %v does not show the fingerprint it met", err)
	}
}

// A server that presents any other certificate, one that a CA would vouch
// for included, is refused: the pin is the only trust.
func TestPinIgnoresTheCertificateChain(t *testing.T) {
	rec := newRecorder(t)
	c := rec.client()
	c.Fingerprint = fingerprintOf(rec.srv)
	// httptest's certificate is self-signed and not trusted by the system
	// roots, yet the pin admits it.
	if err := c.Healthz(context.Background()); err != nil {
		t.Fatalf("a pinned self-signed certificate was refused: %v", err)
	}
}

func TestHealthzSendsNoToken(t *testing.T) {
	rec := newRecorder(t)
	if err := rec.client().Healthz(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := rec.last(t)
	if r.Method != "GET" || r.Path != "/healthz" || r.Auth != "" {
		t.Errorf("request %+v, want GET /healthz with no Authorization", r)
	}
}

func TestErrorBodiesDecode(t *testing.T) {
	rec := newRecorder(t)
	rec.reply = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, `{"error":"refused","detail":"servers[0].name: must not be empty"}`+"\n")
	}
	_, err := rec.client().AddServer(context.Background(), NewServer{Link: "vless://x"})
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("error %T %v, want an *Error", err, err)
	}
	if apiErr.Status != 422 || apiErr.Code != "refused" || apiErr.Detail != "servers[0].name: must not be empty" {
		t.Errorf("got %+v", *apiErr)
	}
	if msg := err.Error(); !strings.Contains(msg, "422") || !strings.Contains(msg, "refused") || !strings.Contains(msg, "must not be empty") || !strings.HasPrefix(msg, "apiclient: ") {
		t.Errorf("message %q lacks the status, the code, the detail or the prefix", msg)
	}

	// A body that is no error body gives the status alone.
	rec.reply = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, "<html>upstream down</html>")
	}
	_, err = rec.client().Status(context.Background())
	if !errors.As(err, &apiErr) || apiErr.Status != 502 || apiErr.Code != "" || apiErr.Detail != "" {
		t.Errorf("error %v (%+v), want an *Error with status 502 and nothing else", err, apiErr)
	}
	if strings.Contains(err.Error(), "upstream down") {
		t.Errorf("error %q repeats a body it could not read as an error", err)
	}

	// An error without a detail.
	rec.reply = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"unauthorized"}`)
	}
	_, err = rec.client().Status(context.Background())
	if !errors.As(err, &apiErr) || apiErr.Status != 401 || apiErr.Code != "unauthorized" || apiErr.Detail != "" {
		t.Errorf("error %v (%+v), want 401 unauthorized with no detail", err, apiErr)
	}
}

// The error of an apply, an update or a rollback that ran to an outcome
// carries the result, which the CLI reports as the direct path's.
func TestErrorCarriesTheResult(t *testing.T) {
	rec := newRecorder(t)
	rec.reply = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, `{"error":"refused","detail":"rejected: xray says no","result":`+
			`{"from":"26.3.27","to":"26.10.21","outcome":"rejected","kind":"config","detail":"xray says no","at":"2026-10-25T12:00:00Z"}}`+"\n")
	}
	_, err := rec.client().Apply(context.Background())
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("error %T %v, want an *Error", err, err)
	}
	want := artifacts.Result{From: "26.3.27", To: "26.10.21", Outcome: "rejected", Kind: artifacts.KindConfig, Detail: "xray says no",
		At: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)}
	if apiErr.Status != 422 || apiErr.Code != "refused" || apiErr.Detail != "rejected: xray says no" || apiErr.Result == nil || *apiErr.Result != want {
		t.Errorf("got %+v (result %+v), want 422 refused with the result %+v", *apiErr, apiErr.Result, want)
	}

	// An error without a result has none.
	rec.reply = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"error":"runner_unavailable","detail":"service: the runner can't be reached"}`)
	}
	_, err = rec.client().Apply(context.Background())
	if !errors.As(err, &apiErr) || apiErr.Code != "runner_unavailable" || apiErr.Result != nil {
		t.Errorf("error %v (%+v), want runner_unavailable with no result", err, apiErr)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	rec := newRecorder(t)
	rec.reply = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.invalid/", http.StatusFound)
	}
	_, err := rec.client().Status(context.Background())
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusFound {
		t.Fatalf("error %v, want an *Error with status 302", err)
	}
	if n := len(rec.requests()); n != 1 {
		t.Errorf("%d requests, want 1", n)
	}
}

func TestTransportErrorsKeepTheirCauseAndNotTheToken(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	c := &Client{BaseURL: "https://" + addr, Token: testToken, Fingerprint: strings.Repeat("ab", 32)}
	err = c.Healthz(context.Background())
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("error %v: errors.Is(ECONNREFUSED) is false, so a caller can't tell that nothing listens", err)
	}
	if err != nil && strings.Contains(err.Error(), testToken) {
		t.Errorf("error %q repeats the token", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := newRecorder(t)
	if _, err := rec.client().Status(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("error %v, want context.Canceled", err)
	}
}

func TestDeadline(t *testing.T) {
	rec := newRecorder(t)
	rec.reply = func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := rec.client().Healthz(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v, want context.DeadlineExceeded", err)
	}
}

// Every method sends the request Task 10's route takes.
func TestRoutes(t *testing.T) {
	ptr := func(s string) *string { return &s }
	flag := func(b bool) *bool { return &b }
	interval := store.Duration(6 * time.Hour)
	dev := store.Device{Address: netip.MustParsePrefix("192.168.88.0/24"), Name: "lan", Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}}
	outbound := json.RawMessage(`{"protocol":"vless","settings":{"address":"203.0.113.10","port":443}}`)

	cases := []struct {
		name   string
		call   func(c *Client, ctx context.Context) error
		method string
		path   string // as sent, escaped
		query  string
		body   string // "" for none, else JSON compared structurally
	}{
		{"Status", func(c *Client, ctx context.Context) error { _, err := c.Status(ctx); return err }, "GET", "/v1/status", "", ""},
		{"State", func(c *Client, ctx context.Context) error { _, err := c.State(ctx); return err }, "GET", "/v1/state", "", ""},
		{"Events", func(c *Client, ctx context.Context) error { _, err := c.Events(ctx, 0); return err }, "GET", "/v1/events", "", ""},
		{"Events after", func(c *Client, ctx context.Context) error { _, err := c.Events(ctx, 12); return err }, "GET", "/v1/events", "after=12", ""},
		{"Core", func(c *Client, ctx context.Context) error { _, err := c.Core(ctx); return err }, "GET", "/v1/core", "", ""},
		{"Servers", func(c *Client, ctx context.Context) error { _, err := c.Servers(ctx); return err }, "GET", "/v1/servers", "", ""},
		{"AddServer link", func(c *Client, ctx context.Context) error {
			_, err := c.AddServer(ctx, NewServer{Link: "vless://u@h:1#n", Name: "n"})
			return err
		}, "POST", "/v1/servers", "", `{"link":"vless://u@h:1#n","name":"n"}`},
		{"AddServer outbound", func(c *Client, ctx context.Context) error {
			_, err := c.AddServer(ctx, NewServer{Name: "n", Outbound: outbound})
			return err
		}, "POST", "/v1/servers", "", `{"name":"n","outbound":` + string(outbound) + `}`},
		{"UpdateServer", func(c *Client, ctx context.Context) error {
			_, err := c.UpdateServer(ctx, "5ab3c4d5", ServerPatch{Disabled: flag(true)})
			return err
		}, "PATCH", "/v1/servers/5ab3c4d5", "", `{"disabled":true}`},
		{"UpdateServer enable", func(c *Client, ctx context.Context) error {
			_, err := c.UpdateServer(ctx, "5ab3c4d5", ServerPatch{Disabled: flag(false), Name: ptr("x")})
			return err
		}, "PATCH", "/v1/servers/5ab3c4d5", "", `{"name":"x","disabled":false}`},
		{"RemoveServer", func(c *Client, ctx context.Context) error { _, err := c.RemoveServer(ctx, "5ab3c4d5"); return err }, "DELETE", "/v1/servers/5ab3c4d5", "", ""},
		{"Subscriptions", func(c *Client, ctx context.Context) error { _, err := c.Subscriptions(ctx); return err }, "GET", "/v1/subscriptions", "", ""},
		{"AddSubscription", func(c *Client, ctx context.Context) error {
			_, err := c.AddSubscription(ctx, NewSubscription{Name: "lab", URL: "https://sub.example/feed", Interval: interval})
			return err
		}, "POST", "/v1/subscriptions", "", `{"name":"lab","url":"https://sub.example/feed","interval":"6h0m0s"}`},
		{"AddSubscription default interval", func(c *Client, ctx context.Context) error {
			_, err := c.AddSubscription(ctx, NewSubscription{Name: "lab", URL: "https://sub.example/feed"})
			return err
		}, "POST", "/v1/subscriptions", "", `{"name":"lab","url":"https://sub.example/feed"}`},
		{"UpdateSubscription", func(c *Client, ctx context.Context) error {
			_, err := c.UpdateSubscription(ctx, "9be8f7a6", SubscriptionPatch{Interval: &interval})
			return err
		}, "PATCH", "/v1/subscriptions/9be8f7a6", "", `{"interval":"6h0m0s"}`},
		{"RemoveSubscription", func(c *Client, ctx context.Context) error {
			_, err := c.RemoveSubscription(ctx, "9be8f7a6")
			return err
		}, "DELETE", "/v1/subscriptions/9be8f7a6", "", ""},
		{"RefreshSubscription", func(c *Client, ctx context.Context) error {
			_, err := c.RefreshSubscription(ctx, "9be8f7a6")
			return err
		}, "POST", "/v1/subscriptions/9be8f7a6/refresh", "", ""},
		{"Devices", func(c *Client, ctx context.Context) error { _, err := c.Devices(ctx); return err }, "GET", "/v1/devices", "", ""},
		{"SetDevice CIDR", func(c *Client, ctx context.Context) error { _, err := c.SetDevice(ctx, dev); return err },
			"PUT", "/v1/devices/192.168.88.0%2F24", "", `{"address":"192.168.88.0/24","name":"lan","policy":{"mode":"full","kill_switch":true}}`},
		{"RemoveDevice CIDR", func(c *Client, ctx context.Context) error {
			_, err := c.RemoveDevice(ctx, netip.MustParsePrefix("192.168.88.0/24"))
			return err
		}, "DELETE", "/v1/devices/192.168.88.0%2F24", "", ""},
		{"RemoveDevice host", func(c *Client, ctx context.Context) error {
			_, err := c.RemoveDevice(ctx, netip.MustParsePrefix("192.168.88.10/32"))
			return err
		}, "DELETE", "/v1/devices/192.168.88.10%2F32", "", ""},
		{"SetPolicy", func(c *Client, ctx context.Context) error {
			_, err := c.SetPolicy(ctx, store.Policy{Mode: store.ModeSmart, KillSwitch: true})
			return err
		}, "PUT", "/v1/policy", "", `{"mode":"smart","kill_switch":true}`},
		{"SetRouting", func(c *Client, ctx context.Context) error {
			_, err := c.SetRouting(ctx, store.Routing{Pinned: "5ab3c4d5"})
			return err
		}, "PUT", "/v1/routing", "", `{"pinned":"5ab3c4d5","domestic":{}}`},
		{"SetDNS", func(c *Client, ctx context.Context) error {
			_, err := c.SetDNS(ctx, store.DNS{Remote: "9.9.9.9"})
			return err
		}, "PUT", "/v1/dns", "", `{"remote":"9.9.9.9"}`},
		{"Health", func(c *Client, ctx context.Context) error { _, err := c.Health(ctx); return err }, "GET", "/v1/health", "", ""},
		{"SetHealth", func(c *Client, ctx context.Context) error {
			_, err := c.SetHealth(ctx, store.Health{ProbeURL: "https://probe.example/204"})
			return err
		}, "PUT", "/v1/health", "", `{"probe_url":"https://probe.example/204"}`},
		{"Apply", func(c *Client, ctx context.Context) error { _, err := c.Apply(ctx); return err }, "POST", "/v1/apply", "", ""},
		{"CoreUpdate", func(c *Client, ctx context.Context) error { _, err := c.CoreUpdate(ctx, "26.10.21", false); return err },
			"POST", "/v1/core/update", "", `{"version":"26.10.21"}`},
		{"CoreUpdate allow", func(c *Client, ctx context.Context) error { _, err := c.CoreUpdate(ctx, "latest", true); return err },
			"POST", "/v1/core/update", "", `{"version":"latest","allow_unverified":true}`},
		{"CoreRollback", func(c *Client, ctx context.Context) error { _, err := c.CoreRollback(ctx); return err }, "POST", "/v1/core/rollback", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := newRecorder(t)
			if err := tc.call(rec.client(), context.Background()); err != nil {
				t.Fatal(err)
			}
			r := rec.last(t)
			if r.Method != tc.method || r.RawPath != tc.path || r.Query != tc.query {
				t.Errorf("sent %s %s?%s, want %s %s?%s", r.Method, r.RawPath, r.Query, tc.method, tc.path, tc.query)
			}
			if r.Auth != "Bearer "+testToken {
				t.Errorf("Authorization %q, want the bearer token", r.Auth)
			}
			if r.IfMatch != "" {
				t.Errorf("If-Match %q: the client changes the state as it is", r.IfMatch)
			}
			if tc.body == "" {
				if r.Body != "" {
					t.Errorf("body %q, want none", r.Body)
				}
				return
			}
			if r.ContentType != "application/json" {
				t.Errorf("Content-Type %q, want application/json", r.ContentType)
			}
			var got, want any
			if err := json.Unmarshal([]byte(r.Body), &got); err != nil {
				t.Fatalf("body %q: %v", r.Body, err)
			}
			if err := json.Unmarshal([]byte(tc.body), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("body %s, want %s", r.Body, tc.body)
			}
		})
	}
}

func TestNoContentGivesAnEmptyBodyAndTheRevision(t *testing.T) {
	rec := newRecorder(t)
	rec.reply = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"9"`)
		w.WriteHeader(http.StatusNoContent)
	}
	resp, err := rec.client().RemoveServer(context.Background(), "5ab3c4d5")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Revision != 9 || len(resp.Body) != 0 {
		t.Errorf("got revision %d, body %q; want 9 and none", resp.Revision, resp.Body)
	}
}

func TestDecode(t *testing.T) {
	rec := newRecorder(t)
	rec.reply = func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"added":2,"updated":1,"removed":0,"kept":5,"skipped":[{"line":"vless://…","reason":"no"}],"via":"proxy"}`)
	}
	resp, err := rec.client().RefreshSubscription(context.Background(), "9be8f7a6")
	if err != nil {
		t.Fatal(err)
	}
	var got RefreshResult
	if err := resp.Decode(&got); err != nil {
		t.Fatal(err)
	}
	want := RefreshResult{Added: 2, Updated: 1, Kept: 5, Via: "proxy", Skipped: []Skipped{{Line: "vless://…", Reason: "no"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if err := (Response{}).Decode(&got); err == nil {
		t.Error("decoding an empty body did not fail")
	}
}

func TestResponseIsBounded(t *testing.T) {
	defer func(old int) { maxResponse = old }(maxResponse)
	maxResponse = 1 << 20
	rec := newRecorder(t)
	rec.reply = func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("a", 2<<20)))
	}
	if _, err := rec.client().State(context.Background()); err == nil || !strings.Contains(err.Error(), "apiclient: ") {
		t.Errorf("error %v, want one for a response over the limit", err)
	}
	rec.reply = func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("a", 1<<20)))
	}
	if _, err := rec.client().State(context.Background()); err != nil {
		t.Errorf("a response of exactly the limit: %v", err)
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	good := strings.Repeat("ab12", 16)
	for in, want := range map[string]string{
		good:                      good,
		strings.ToUpper(good):     good,
		" " + good + "\n":         good,
		"AB:12:AB:12:" + good[8:]: good,
	} {
		if got, err := NormalizeFingerprint(in); err != nil || got != want {
			t.Errorf("NormalizeFingerprint(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "abc", good + "00", strings.Repeat("zz", 32)} {
		if got, err := NormalizeFingerprint(in); err == nil {
			t.Errorf("NormalizeFingerprint(%q) = %q, want an error", in, got)
		}
	}
}

func TestFingerprintOfPEM(t *testing.T) {
	rec := newRecorder(t)
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rec.srv.Certificate().Raw})
	got, err := FingerprintOfPEM(crt)
	if err != nil || got != fingerprintOf(rec.srv) {
		t.Errorf("FingerprintOfPEM = %q, %v; want %q", got, err, fingerprintOf(rec.srv))
	}
	// The first certificate of a file with a chain.
	other := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not looked at")})
	if got, err := FingerprintOfPEM(append(crt, other...)); err != nil || got != fingerprintOf(rec.srv) {
		t.Errorf("with a second block: %q, %v", got, err)
	}
	for name, in := range map[string][]byte{
		"empty":      nil,
		"no PEM":     []byte("hello"),
		"only a key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}),
		"bad DER":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}),
	} {
		if got, err := FingerprintOfPEM(in); err == nil {
			t.Errorf("%s: got %q, want an error", name, got)
		}
	}
}

// The client's own TLS: a version floor, and a connection of its own for each
// call, so that no resumed session skips the pin.
func TestTLSConfig(t *testing.T) {
	c := &Client{BaseURL: "https://127.0.0.1:1", Fingerprint: strings.Repeat("ab", 32)}
	tr, ok := c.httpClient().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport %T", c.httpClient().Transport)
	}
	if tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion %x, want TLS 1.2 or newer", tr.TLSClientConfig.MinVersion)
	}
	if !tr.DisableKeepAlives {
		t.Error("connections are kept alive: each call should be pinned afresh")
	}
}
