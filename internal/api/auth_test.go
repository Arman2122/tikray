package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/auth"
)

const (
	adminName = "alice"
	adminPass = "correct horse battery"
	otherPass = "another long password"
)

// testClock is the limiter's clock: it moves when a test says so.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// authEnv is the API over a fake backend, a real auth store (in dir) and a
// limiter that reads a clock of its own.
type authEnv struct {
	f     *fakeBackend
	store *auth.Store
	dir   string
	clock *testClock
	h     http.Handler
	srv   *httptest.Server
}

// newAuthEnv makes an authEnv. With claimed the admin is alice, with
// adminPass; otherwise the store waits for its setup code.
func newAuthEnv(t *testing.T, claimed bool) *authEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := auth.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if claimed {
		code, err := st.SetupCode()
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Claim(context.Background(), code, adminName, adminPass); err != nil {
			t.Fatal(err)
		}
	}
	clk := &testClock{now: t0}
	f := newFake()
	h := NewHandler(f, testToken, st, auth.NewLimiter(clk.Now))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &authEnv{f: f, store: st, dir: dir, clock: clk, h: h, srv: srv}
}

// signIn starts a session on the store itself, with no request.
func (e *authEnv) signIn(t *testing.T) auth.Session { return e.signInAs(t, adminPass) }

func (e *authEnv) signInAs(t *testing.T, password string) auth.Session {
	t.Helper()
	s, err := e.store.SignIn(context.Background(), adminName, password)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// token makes a named token on the store and returns it with its info.
func (e *authEnv) token(t *testing.T, name string) (auth.TokenInfo, string) {
	t.Helper()
	info, tok, err := e.store.CreateToken(name, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return info, tok
}

// do sends a request.
func (e *authEnv) do(t *testing.T, method, path, body string, h http.Header) response {
	t.Helper()
	return request(t, e.srv, method, path, body, h)
}

// events are the events the handlers recorded, as "kind: message".
func (e *authEnv) events() []string {
	var out []string
	for _, ev := range e.f.loggedEvents() {
		out = append(out, ev.Kind+": "+ev.Message)
	}
	return out
}

// hdr makes headers from name, value pairs.
func hdr(pairs ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Add(pairs[i], pairs[i+1])
	}
	return h
}

func bearer(tok string) http.Header { return hdr("Authorization", "Bearer "+tok) }

// cookieOnly is the headers of a browser that holds the session's cookie and
// sends no CSRF token.
func cookieOnly(s auth.Session) http.Header { return hdr("Cookie", "tikray_session="+s.ID) }

// withCSRF adds the session's CSRF token.
func withCSRF(s auth.Session) http.Header {
	return hdr("Cookie", "tikray_session="+s.ID, "X-Tikray-CSRF", s.CSRF)
}

func loginBody(t testing.TB, user, pass string) string {
	return mustJSON(t, map[string]string{"username": user, "password": pass})
}

func setupBody(t testing.TB, code, user, pass string) string {
	return mustJSON(t, map[string]string{"code": code, "username": user, "password": pass})
}

// setCookie is the one Set-Cookie header of a response, parsed.
func setCookie(t *testing.T, r response) (*http.Cookie, string) {
	t.Helper()
	vals := r.header.Values("Set-Cookie")
	if len(vals) != 1 {
		t.Fatalf("%d Set-Cookie headers, want 1", len(vals))
	}
	c, err := http.ParseSetCookie(vals[0])
	if err != nil {
		t.Fatalf("Set-Cookie does not parse: %v", err)
	}
	return c, vals[0]
}

// checkSessionCookie checks that r sets the cookie of a session with the fixed
// flags, exactly, and returns its value. It never prints the value.
func checkSessionCookie(t *testing.T, r response) string {
	t.Helper()
	c, raw := setCookie(t, r)
	if c.Name != "tikray_session" || len(c.Value) != 43 {
		t.Fatalf("the cookie is %q with a value of %d bytes, want tikray_session and 43", c.Name, len(c.Value))
	}
	want := "tikray_session=<id>; Path=/; Max-Age=604800; HttpOnly; Secure; SameSite=Strict"
	if got := strings.Replace(raw, c.Value, "<id>", 1); got != want {
		t.Errorf("Set-Cookie = %q\nwant         %q", got, want)
	}
	return c.Value
}

// checkCookieCleared checks that r tells the browser to drop the cookie.
func checkCookieCleared(t *testing.T, r response) {
	t.Helper()
	c, raw := setCookie(t, r)
	if c.Name != "tikray_session" || c.Value != "" {
		t.Errorf("the cookie is %q = %q, want tikray_session emptied", c.Name, c.Value)
	}
	if want := "tikray_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"; raw != want {
		t.Errorf("Set-Cookie = %q, want %q", raw, want)
	}
}

// signedIn is a response of the sign-in routes.
type signedIn struct {
	CSRFToken string    `json:"csrf_token"`
	Expires   time.Time `json:"expires"`
}

func decodeAs[T any](t *testing.T, r response) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(r.body, &v); err != nil {
		t.Fatalf("status %d: the body is not what it should be: %v", r.status, err)
	}
	return v
}

// sessionsInFile is how many sessions auth.json holds.
func sessionsInFile(t *testing.T, dir string) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Sessions []json.RawMessage `json:"sessions"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return len(d.Sessions)
}

// serveAs sends a request straight to h, from the remote address remote.
func serveAs(h http.Handler, remote, method, path, body string, header http.Header) response {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = remote
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return response{res.StatusCode, res.Header, b}
}

// --- the chain of credentials

func TestAuthChain(t *testing.T) {
	e := newAuthEnv(t, true)
	sess := e.signIn(t)
	_, named := e.token(t, "ci")
	revoked, gone := e.token(t, "old")
	if err := e.store.RevokeToken(revoked.ID); err != nil {
		t.Fatal(err)
	}
	ended := e.signIn(t)
	e.store.SignOut(ended.ID)
	_, short, err := e.store.CreateToken("short", time.Now().Add(40*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)

	for _, rt := range routes(t) {
		t.Run(rt.name, func(t *testing.T) {
			for _, c := range []struct {
				who    string
				h      http.Header
				status int
			}{
				{"the root token", authed(), rt.status},
				{"a named token", bearer(named), rt.status},
				{"a session cookie with its CSRF token", withCSRF(sess), rt.status},
				{"nothing", nil, 401},
				{"a revoked token", bearer(gone), 401},
				{"an expired token", bearer(short), 401},
				{"an ended session", withCSRF(ended), 401},
				{"a cookie that is no session", hdr("Cookie", "tikray_session="+strings.Repeat("a", 43), "X-Tikray-CSRF", "x"), 401},
			} {
				r := e.do(t, rt.method, rt.path, rt.body, c.h)
				if r.status != c.status {
					t.Errorf("%s: status = %d, want %d (%.200s)", c.who, r.status, c.status, r.body)
				}
				if c.status == 401 {
					if code, _ := errorOf(t, r); code != "unauthorized" {
						t.Errorf("%s: code = %q, want unauthorized", c.who, code)
					}
					if r.header.Get("ETag") != "" {
						t.Errorf("%s: a 401 carries an ETag", c.who)
					}
				}
			}
		})
	}

	t.Run("the first credential that works decides", func(t *testing.T) {
		// A bearer that is wrong falls through to the cookie, as the chain
		// says; a valid one does not need it.
		if r := e.do(t, "GET", "/v1/status", "", merge(bearer("nope"), cookieOnly(sess))); r.status != 200 {
			t.Errorf("a bad bearer with a good cookie: status = %d, want 200", r.status)
		}
		if r := e.do(t, "GET", "/v1/status", "", merge(bearer(named), hdr("Cookie", "tikray_session=junk"))); r.status != 200 {
			t.Errorf("a good token with a bad cookie: status = %d, want 200", r.status)
		}
	})
}

// merge joins headers.
func merge(hs ...http.Header) http.Header {
	out := http.Header{}
	for _, h := range hs {
		for k, v := range h {
			out[k] = append(out[k], v...)
		}
	}
	return out
}

// Every route but the four public ones needs a credential, and a caller
// without one learns nothing about the routes.
func TestAnonymousSeesOnlyThePublicRoutes(t *testing.T) {
	e := newAuthEnv(t, true)
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/auth/session"},
		{"POST", "/v1/auth/logout"},
		{"PUT", "/v1/auth/password"},
		{"POST", "/v1/auth/reset"},
		{"GET", "/v1/tokens"},
		{"POST", "/v1/tokens"},
		{"DELETE", "/v1/tokens/1a2b3c4d"},
		// A public path with another method is no public route.
		{"GET", "/v1/auth/login"},
		{"GET", "/v1/auth/setup"},
		{"PUT", "/v1/auth/login"},
		{"POST", "/v1/auth/state"},
		{"DELETE", "/v1/auth/state"},
		{"POST", "/healthz"},
		{"GET", "/v1/auth/login/"},
		{"GET", "/v1/nope"},
		{"GET", "/"},
		// The mux reads a %2F as part of a segment, so these are not the
		// public routes they look like, and a caller without a credential
		// must not be answered by the route that is left (the 404 has an
		// ETag).
		{"POST", "/v1/auth%2Fsetup"},
		{"POST", "/v1/auth%2flogin"},
		{"GET", "/v1/auth%2Fstate"},
		{"GET", "/v1%2Fauth/state"},
		{"GET", "/v1%2Fauth%2Fstate"},
		{"GET", "/%2Fhealthz"},
		{"GET", "/healthz%2F"},
		{"POST", "/v1/auth/login%2F"},
		{"POST", "/v1%2Fauth%2Flogin"},
		// A path that is not clean is no public route either.
		{"GET", "/v1//status"},
		{"GET", "/v1/auth/../status"},
	} {
		r := e.do(t, c.method, c.path, "", nil)
		if r.status != 401 {
			t.Errorf("%s %s: status = %d, want 401", c.method, c.path, r.status)
			continue
		}
		if code, _ := errorOf(t, r); code != "unauthorized" {
			t.Errorf("%s %s: code = %q, want unauthorized", c.method, c.path, code)
		}
		if r.header.Get("ETag") != "" {
			t.Errorf("%s %s: an anonymous answer carries an ETag", c.method, c.path)
		}
	}
	// What the mux itself matches to a public route is one, however the path is
	// spelled: the check goes by the route that is served.
	for _, c := range []struct {
		method, path string
		status       int
		code         string
	}{
		{"GET", "/%68ealthz", 200, ""},
		{"GET", "/v1/auth/%73tate", 200, ""},
		{"GET", "/v1/%61uth/state", 200, ""},
		{"POST", "/v1/auth/%6Cogin", 400, "bad_request"},
		{"POST", "/v1/auth/%73etup", 400, "bad_request"},
	} {
		r := e.do(t, c.method, c.path, "", nil)
		if r.status != c.status {
			t.Errorf("%s %s: status = %d, want %d", c.method, c.path, r.status, c.status)
		}
		if c.code != "" {
			if code, _ := errorOf(t, r); code != c.code {
				t.Errorf("%s %s: code = %q, want %s", c.method, c.path, code, c.code)
			}
		}
		if r.header.Get("ETag") != "" {
			t.Errorf("%s %s: a public answer carries an ETag", c.method, c.path)
		}
	}
	// A path that is not clean is redirected by the mux; for a route that
	// needs a credential, not before the credential is asked for. The
	// redirect's status is the mux's own: 301 before Go 1.26, 307 from it.
	bare := http.NewServeMux()
	bare.HandleFunc("GET /v1/auth/state", func(http.ResponseWriter, *http.Request) {})
	muxRedirect := serveAs(bare, "192.0.2.1:1", "GET", "/v1//auth/state", "", nil).status
	if muxRedirect/100 != 3 {
		t.Fatalf("a bare mux answers GET /v1//auth/state with %d, not a redirect", muxRedirect)
	}
	for _, c := range []struct {
		method, path string
		status       int
		location     string
	}{
		{"GET", "/v1//status", 401, ""},
		{"GET", "/v1/auth/../status", 401, ""},
		{"GET", "/v1//auth/state", muxRedirect, "/v1/auth/state"},
	} {
		r := serveAs(e.h, "192.0.2.1:1", c.method, c.path, "", nil)
		if r.status != c.status {
			t.Errorf("%s %s (the mux's own redirect): status = %d, want %d", c.method, c.path, r.status, c.status)
		}
		if loc := r.header.Get("Location"); loc != c.location {
			t.Errorf("%s %s: Location = %q, want %q", c.method, c.path, loc, c.location)
		}
		if r.header.Get("ETag") != "" {
			t.Errorf("%s %s: an anonymous answer carries an ETag", c.method, c.path)
		}
	}
	// With the root token those are the plain 404 of a wrong method.
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/auth/login"}, {"GET", "/v1/auth/setup"}, {"POST", "/v1/auth/state"},
	} {
		if r := e.do(t, c.method, c.path, "", authed()); r.status != 404 {
			t.Errorf("%s %s with the token: status = %d, want 404", c.method, c.path, r.status)
		}
	}
	// And the public ones are open.
	for _, c := range []struct {
		method, path string
		status       int
		code         string
	}{
		{"GET", "/healthz", 200, ""},
		{"HEAD", "/healthz", 200, ""},
		{"GET", "/v1/auth/state", 200, ""},
		{"POST", "/v1/auth/login", 400, "bad_request"},
		{"POST", "/v1/auth/setup", 400, "bad_request"},
	} {
		r := e.do(t, c.method, c.path, "", nil)
		if r.status != c.status {
			t.Errorf("%s %s: status = %d, want %d", c.method, c.path, r.status, c.status)
		}
		if c.code != "" {
			if code, _ := errorOf(t, r); code != c.code {
				t.Errorf("%s %s: code = %q, want %s", c.method, c.path, code, c.code)
			}
		}
	}
}

func TestAuthState(t *testing.T) {
	e := newAuthEnv(t, false)
	r := e.do(t, "GET", "/v1/auth/state", "", nil)
	sameJSON(t, r.body, `{"setup_required":true,"signed_in":false}`)
	if r.header.Get("ETag") != "" {
		t.Error("the state of the sign-in carries the revision of the state")
	}

	code, err := e.store.SetupCode()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.Claim(context.Background(), code, adminName, adminPass); err != nil {
		t.Fatal(err)
	}
	sess := e.signIn(t)
	ended := e.signIn(t)
	e.store.SignOut(ended.ID)
	_, named := e.token(t, "ci")
	for _, c := range []struct {
		who  string
		h    http.Header
		want bool
	}{
		{"nobody", nil, false},
		{"a wrong bearer", bearer("nope"), false},
		{"a cookie that is no session", hdr("Cookie", "tikray_session=junk"), false},
		{"an ended session", cookieOnly(ended), false},
		{"a session", cookieOnly(sess), true},
		{"the root token", authed(), true},
		{"a named token", bearer(named), true},
	} {
		r := e.do(t, "GET", "/v1/auth/state", "", c.h)
		sameJSON(t, r.body, fmt.Sprintf(`{"setup_required":false,"signed_in":%t}`, c.want))
		if r.status != 200 {
			t.Errorf("%s: status = %d, want 200", c.who, r.status)
		}
	}
}

// --- CSRF

func TestCSRFRequiredForCookies(t *testing.T) {
	e := newAuthEnv(t, true)
	sess, other := e.signIn(t), e.signIn(t)
	info, _ := e.token(t, "ci")

	// Each of these changes something, and has a success to compare with.
	for _, c := range []struct {
		method, path, body string
		status             int
		calls              string // the backend call that a success makes, "" for none
	}{
		{"PUT", "/v1/policy", `{"mode":"full"}`, 200, "SetDefaultPolicy"},
		{"POST", "/v1/servers", `{"link":"vless://x"}`, 201, "AddServer"},
		{"PATCH", "/v1/servers/5ab3c4d5", `{"disabled":true}`, 200, "UpdateServer"},
		{"DELETE", "/v1/servers/5ab3c4d5", "", 204, "RemoveServer"},
		{"PUT", "/v1/devices/192.168.88.10", `{"policy":{"mode":"smart"}}`, 200, "SetDevice"},
		{"POST", "/v1/apply", "", 200, "ApplyNow"},
		{"POST", "/v1/core/rollback", "", 200, "CoreRollback"},
		{"POST", "/v1/subscriptions/9be8f7a6/refresh", "", 200, "RefreshSubscription"},
		{"POST", "/v1/tokens", `{"name":"x"}`, 201, ""},
		{"DELETE", "/v1/tokens/" + info.ID, "", 204, ""},
	} {
		name := c.method + " " + c.path
		for what, h := range map[string]http.Header{
			"no header":               cookieOnly(sess),
			"an empty header":         merge(cookieOnly(sess), hdr("X-Tikray-CSRF", "")),
			"garbage":                 merge(cookieOnly(sess), hdr("X-Tikray-CSRF", "AAAA")),
			"another session's token": merge(cookieOnly(sess), hdr("X-Tikray-CSRF", other.CSRF)),
			"the token and more":      merge(cookieOnly(sess), hdr("X-Tikray-CSRF", sess.CSRF+"x")),
			"the id for the token":    merge(cookieOnly(sess), hdr("X-Tikray-CSRF", sess.ID)),
		} {
			before := len(e.f.recorded())
			r := e.do(t, c.method, c.path, c.body, h)
			if r.status != 403 {
				t.Errorf("%s, %s: status = %d, want 403", name, what, r.status)
				continue
			}
			if code, _ := errorOf(t, r); code != "csrf" {
				t.Errorf("%s, %s: code = %q, want csrf", name, what, code)
			}
			if r.header.Get("ETag") != "" {
				t.Errorf("%s, %s: a refused request carries an ETag", name, what)
			}
			if got := len(e.f.recorded()); got != before {
				t.Errorf("%s, %s: the backend was called", name, what)
			}
		}
		r := e.do(t, c.method, c.path, c.body, withCSRF(sess))
		if r.status != c.status {
			t.Errorf("%s with the header: status = %d, want %d (%.200s)", name, r.status, c.status, r.body)
		}
		if c.calls != "" {
			if got := e.f.recorded(); len(got) == 0 || got[len(got)-1].Method != c.calls {
				t.Errorf("%s with the header: the backend saw %+v, want %s", name, got, c.calls)
			}
		}
	}

	t.Run("a read needs none", func(t *testing.T) {
		for _, c := range []struct{ method, path string }{
			{"GET", "/v1/state"}, {"GET", "/v1/status"}, {"HEAD", "/v1/status"}, {"GET", "/v1/tokens"}, {"GET", "/v1/auth/session"},
		} {
			if r := e.do(t, c.method, c.path, "", cookieOnly(sess)); r.status != 200 {
				t.Errorf("%s %s: status = %d, want 200", c.method, c.path, r.status)
			}
		}
	})

	// The session is looked up first: a request without one is no CSRF
	// failure, whatever token it brings (even the one it would have had).
	t.Run("a session that has ended is 401, not a CSRF failure", func(t *testing.T) {
		gone := e.signIn(t)
		e.store.SignOut(gone.ID)
		for what, h := range map[string]http.Header{
			"with the token it had": withCSRF(gone),
			"with no token":         cookieOnly(gone),
			"with a bad token":      merge(cookieOnly(gone), hdr("X-Tikray-CSRF", "x")),
			"never a session":       hdr("Cookie", "tikray_session=junk", "X-Tikray-CSRF", "x"),
		} {
			before := len(e.f.recorded())
			r := e.do(t, "PUT", "/v1/policy", `{"mode":"full"}`, h)
			if r.status != 401 {
				t.Errorf("%s: status = %d, want 401", what, r.status)
				continue
			}
			if code, _ := errorOf(t, r); code != "unauthorized" {
				t.Errorf("%s: code = %q, want unauthorized", what, code)
			}
			checkCookieCleared(t, r)
			if len(e.f.recorded()) != before {
				t.Errorf("%s: the backend was called", what)
			}
		}
	})

	t.Run("a request with no cookie has none to clear", func(t *testing.T) {
		r := e.do(t, "GET", "/v1/status", "", nil)
		if r.status != 401 || len(r.header.Values("Set-Cookie")) != 0 {
			t.Errorf("status = %d, Set-Cookie = %q, want 401 and none", r.status, r.header.Values("Set-Cookie"))
		}
	})
}

func TestBearerNeedsNoCSRF(t *testing.T) {
	e := newAuthEnv(t, true)
	sess := e.signIn(t)
	_, named := e.token(t, "ci")
	for what, h := range map[string]http.Header{
		"the root token":                      authed(),
		"a named token":                       bearer(named),
		"a token and a session's cookie":      merge(bearer(named), cookieOnly(sess)),
		"the root token and a session cookie": merge(authed(), cookieOnly(sess)),
	} {
		before := len(e.f.recorded())
		r := e.do(t, "PUT", "/v1/policy", `{"mode":"full"}`, h)
		if r.status != 200 {
			t.Errorf("%s: status = %d, want 200 (%s)", what, r.status, r.body)
		}
		if len(e.f.recorded()) != before+1 {
			t.Errorf("%s: the backend was not called once", what)
		}
		if r := e.do(t, "POST", "/v1/tokens", `{"name":"made by `+what+`"}`, h); r.status != 201 {
			t.Errorf("%s: POST /v1/tokens status = %d, want 201", what, r.status)
		}
	}

	// The exemption is for a bearer that works. One that does not leaves the
	// cookie to authenticate, and with it the CSRF check.
	before := len(e.f.recorded())
	r := e.do(t, "PUT", "/v1/policy", `{"mode":"full"}`, merge(bearer("nope"), cookieOnly(sess)))
	if r.status != 403 {
		t.Errorf("a wrong bearer and a cookie: status = %d, want 403", r.status)
	}
	if len(e.f.recorded()) != before {
		t.Error("a wrong bearer and a cookie without the CSRF token reached the backend")
	}
}

// --- setup and login

func TestSetupAndLogin(t *testing.T) {
	e := newAuthEnv(t, false)
	code, err := e.store.SetupCode()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("a wrong code", func(t *testing.T) {
		r := e.do(t, "POST", "/v1/auth/setup", setupBody(t, "K9K9-M8M8-Q7Q7", adminName, adminPass), nil)
		if r.status != 401 {
			t.Fatalf("status = %d, want 401 (%s)", r.status, r.body)
		}
		if c, _ := errorOf(t, r); c != "bad_code" {
			t.Errorf("code = %q, want bad_code", c)
		}
		if len(r.header.Values("Set-Cookie")) != 0 || r.header.Get("ETag") != "" {
			t.Error("a refused setup sets a cookie or carries an ETag")
		}
		if !e.store.NeedsSetup() {
			t.Error("a wrong code claimed the admin")
		}
	})

	t.Run("the right code with a password that breaks the rules", func(t *testing.T) {
		const tooShort = "Sh0rt-PW"
		r := e.do(t, "POST", "/v1/auth/setup", setupBody(t, code, adminName, tooShort), nil)
		if r.status != 400 {
			t.Fatalf("status = %d, want 400 (%s)", r.status, r.body)
		}
		c, detail := errorOf(t, r)
		if c != "bad_request" || !strings.Contains(detail, "password") {
			t.Errorf("code = %q, detail = %q, want bad_request and the rule", c, detail)
		}
		if strings.Contains(string(r.body), tooShort) {
			t.Error("the detail echoes the password")
		}
		if !e.store.NeedsSetup() {
			t.Error("a bad password claimed the admin")
		}
	})

	t.Run("the right code claims the admin and signs in", func(t *testing.T) {
		// Another form of the code, as people type it.
		typed := strings.ToLower(strings.ReplaceAll(code, "-", " "))
		r := e.do(t, "POST", "/v1/auth/setup", setupBody(t, typed, adminName, adminPass), nil)
		if r.status != 200 {
			t.Fatalf("status = %d, want 200 (%s)", r.status, r.body)
		}
		id := checkSessionCookie(t, r)
		body := decodeAs[signedIn](t, r)
		if !e.store.CheckCSRF(id, body.CSRFToken) {
			t.Error("csrf_token is not the CSRF token of the session")
		}
		if left := time.Until(body.Expires); left < 11*time.Hour || left > 12*time.Hour+time.Minute {
			t.Errorf("expires is %v from now, want about 12h", left)
		}
		if _, ok := e.store.Session(id); !ok {
			t.Error("the cookie is not a session of the store")
		}
		if e.store.NeedsSetup() {
			t.Error("the admin was not claimed")
		}
		if r.header.Get("ETag") != "" {
			t.Error("a public response carries an ETag")
		}
		// The code is the one use.
		if got, err := os.ReadFile(filepath.Join(e.dir, "setup.code")); err == nil {
			t.Errorf("setup.code is still there: %d bytes", len(got))
		}

		// The cookie is the sign-in.
		sameJSON(t, e.do(t, "GET", "/v1/auth/state", "", hdr("Cookie", "tikray_session="+id)).body, `{"setup_required":false,"signed_in":true}`)
		sameJSON(t, e.do(t, "GET", "/v1/auth/state", "", nil).body, `{"setup_required":false,"signed_in":false}`)
	})

	t.Run("setup again", func(t *testing.T) {
		for _, c := range []string{code, "K9K9-M8M8-Q7Q7", ""} {
			r := e.do(t, "POST", "/v1/auth/setup", setupBody(t, c, "mallory", "mallory's password"), nil)
			if r.status != 409 {
				t.Errorf("status = %d, want 409", r.status)
				continue
			}
			if got, _ := errorOf(t, r); got != "already_claimed" {
				t.Errorf("code = %q, want already_claimed", got)
			}
			if len(r.header.Values("Set-Cookie")) != 0 {
				t.Error("a refused setup sets a cookie")
			}
		}
		if e.store.Username() != adminName {
			t.Error("a second setup changed the admin")
		}
	})

	t.Run("a wrong password and an unknown user get the same answer", func(t *testing.T) {
		e.clock.Advance(time.Hour) // the wrong code at the start is forgiven by now
		var answers []string
		for _, c := range []struct{ user, pass string }{
			{adminName, "not the password"},
			{"nobody", adminPass},
			{"nobody", "not the password"},
			{"", ""},
			{strings.Repeat("x", 100), adminPass},
		} {
			r := e.do(t, "POST", "/v1/auth/login", loginBody(t, c.user, c.pass), nil)
			if r.status != 401 {
				t.Fatalf("%q: status = %d, want 401 (%s)", c.user, r.status, r.body)
			}
			if code, _ := errorOf(t, r); code != "bad_credentials" {
				t.Errorf("code = %q, want bad_credentials", code)
			}
			if len(r.header.Values("Set-Cookie")) != 0 || r.header.Get("ETag") != "" {
				t.Error("a refused sign-in sets a cookie or carries an ETag")
			}
			answers = append(answers, string(r.body))
		}
		for _, a := range answers[1:] {
			if a != answers[0] {
				t.Errorf("answers differ: %q and %q", answers[0], a)
			}
		}
	})

	t.Run("the right password signs in", func(t *testing.T) {
		e.clock.Advance(time.Hour) // the five wrong ones before are forgiven by now
		r := e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, adminPass), nil)
		if r.status != 200 {
			t.Fatalf("status = %d, want 200 (%s)", r.status, r.body)
		}
		id := checkSessionCookie(t, r)
		body := decodeAs[signedIn](t, r)
		if !e.store.CheckCSRF(id, body.CSRFToken) {
			t.Error("csrf_token is not the CSRF token of the session")
		}
		if left := time.Until(body.Expires); left < 11*time.Hour || left > 12*time.Hour+time.Minute {
			t.Errorf("expires is %v from now, want about 12h", left)
		}
		if r.header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q", r.header.Get("Content-Type"))
		}
		// The session works, with its token.
		sess := auth.Session{ID: id, CSRF: body.CSRFToken}
		if got := e.do(t, "PUT", "/v1/policy", `{"mode":"full"}`, withCSRF(sess)); got.status != 200 {
			t.Errorf("a change with the session: status = %d, want 200", got.status)
		}
	})

	t.Run("bad bodies", func(t *testing.T) {
		for _, c := range []struct{ path, body string }{
			{"/v1/auth/login", ``},
			{"/v1/auth/login", `{"username":"alice"`},
			{"/v1/auth/login", `{"username":"alice","password":"x","extra":1}`},
			{"/v1/auth/login", `{"username":5}`},
			{"/v1/auth/login", `{"username":"a","password":"b"} {"username":"a"}`},
			{"/v1/auth/login", `{"username":"` + strings.Repeat("a", 1<<20) + `"}`},
			{"/v1/auth/setup", `{"code":"x","user":"alice"}`},
			{"/v1/auth/setup", ``},
		} {
			r := e.do(t, "POST", c.path, c.body, nil)
			if r.status != 400 {
				t.Errorf("%s %.40q: status = %d, want 400", c.path, c.body, r.status)
				continue
			}
			if code, _ := errorOf(t, r); code != "bad_request" {
				t.Errorf("%s %.40q: code = %q, want bad_request", c.path, c.body, code)
			}
		}
	})
}

// --- the limiter

func TestRateLimited429(t *testing.T) {
	t.Run("sign-in", func(t *testing.T) {
		e := newAuthEnv(t, true)
		for i := range 5 {
			if r := e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, "wrong password "+fmt.Sprint(i)), nil); r.status != 401 {
				t.Fatalf("failure %d: status = %d, want 401", i+1, r.status)
			}
		}
		// The sixth is refused before anything is checked: the right password
		// gets the 429 too, and no session is made.
		r := e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, adminPass), nil)
		if r.status != 429 {
			t.Fatalf("status = %d, want 429 (%s)", r.status, r.body)
		}
		if code, _ := errorOf(t, r); code != "rate_limited" {
			t.Errorf("code = %q, want rate_limited", code)
		}
		if got := r.header.Get("Retry-After"); got != "60" {
			t.Errorf("Retry-After = %q, want 60", got)
		}
		if len(r.header.Values("Set-Cookie")) != 0 || r.header.Get("ETag") != "" {
			t.Error("a limited request sets a cookie or carries an ETag")
		}
		if n := sessionsInFile(t, e.dir); n != 0 {
			t.Errorf("%d sessions after a limited sign-in, want none: the password was checked", n)
		}

		// The setup route draws on the same bucket.
		r = e.do(t, "POST", "/v1/auth/setup", setupBody(t, "K9K9-M8M8-Q7Q7", adminName, adminPass), nil)
		if r.status != 429 || r.header.Get("Retry-After") != "60" {
			t.Errorf("setup: status = %d, Retry-After = %q, want 429 and 60", r.status, r.header.Get("Retry-After"))
		}

		// What is left of the wait, rounded up to the second.
		e.clock.Advance(29500 * time.Millisecond)
		r = e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, adminPass), nil)
		if r.status != 429 || r.header.Get("Retry-After") != "31" {
			t.Errorf("after 29.5 s: status = %d, Retry-After = %q, want 429 and 31", r.status, r.header.Get("Retry-After"))
		}

		// Only the sign-in is limited.
		if r := e.do(t, "GET", "/v1/status", "", authed()); r.status != 200 {
			t.Errorf("the root token while limited: status = %d, want 200", r.status)
		}
		if r := e.do(t, "GET", "/v1/auth/state", "", nil); r.status != 200 {
			t.Errorf("the state while limited: status = %d, want 200", r.status)
		}

		e.clock.Advance(31 * time.Second)
		r = e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, adminPass), nil)
		if r.status != 200 {
			t.Fatalf("once the wait is over: status = %d, want 200 (%s)", r.status, r.body)
		}
		checkSessionCookie(t, r)
	})

	t.Run("setup", func(t *testing.T) {
		e := newAuthEnv(t, false)
		code, err := e.store.SetupCode()
		if err != nil {
			t.Fatal(err)
		}
		for i := range 5 {
			if r := e.do(t, "POST", "/v1/auth/setup", setupBody(t, "K9K9-M8M8-Q7Q"+fmt.Sprint(i), adminName, adminPass), nil); r.status != 401 {
				t.Fatalf("failure %d: status = %d, want 401", i+1, r.status)
			}
		}
		r := e.do(t, "POST", "/v1/auth/setup", setupBody(t, code, adminName, adminPass), nil)
		if r.status != 429 {
			t.Fatalf("status = %d, want 429 (%s)", r.status, r.body)
		}
		if got := r.header.Get("Retry-After"); got != "60" {
			t.Errorf("Retry-After = %q, want 60", got)
		}
		if !e.store.NeedsSetup() {
			t.Error("the right code claimed the admin though the sender was limited")
		}
		e.clock.Advance(time.Minute)
		if r := e.do(t, "POST", "/v1/auth/setup", setupBody(t, code, adminName, adminPass), nil); r.status != 200 {
			t.Errorf("once the wait is over: status = %d, want 200 (%s)", r.status, r.body)
		}
	})
}

// Only a wrong code and a wrong password count against the sender: a request
// that is refused before any credential is checked, and a success, give their
// token back.
func TestLimiterCountsOnlyCredentialFailures(t *testing.T) {
	e := newAuthEnv(t, false)
	code, err := e.store.SetupCode()
	if err != nil {
		t.Fatal(err)
	}
	const n = 8 // more than the bucket holds
	for i := range n {
		for what, c := range map[string]struct {
			path, body string
			status     int
		}{
			"a body that is not JSON":    {"/v1/auth/login", `{`, 400},
			"an empty body":              {"/v1/auth/setup", ``, 400},
			"a field that is not known":  {"/v1/auth/setup", `{"nope":1}`, 400},
			"a username that is no name": {"/v1/auth/setup", setupBody(t, code, "bad\x07name", adminPass), 400},
			"a password that is short":   {"/v1/auth/setup", setupBody(t, code, adminName, "short"), 400},
		} {
			if r := e.do(t, "POST", c.path, c.body, nil); r.status != c.status {
				t.Fatalf("%s, try %d: status = %d, want %d (%s)", what, i+1, r.status, c.status, r.body)
			}
		}
	}

	// A success gives its token back, so any number of sign-ins work.
	if r := e.do(t, "POST", "/v1/auth/setup", setupBody(t, code, adminName, adminPass), nil); r.status != 200 {
		t.Fatalf("setup: status = %d, want 200 (%s)", r.status, r.body)
	}
	for i := range n {
		if r := e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, adminPass), nil); r.status != 200 {
			t.Fatalf("sign-in %d: status = %d, want 200 (%s)", i+1, r.status, r.body)
		}
	}
	// So does an attempt at a setup that is claimed already.
	for i := range n {
		if r := e.do(t, "POST", "/v1/auth/setup", setupBody(t, code, adminName, adminPass), nil); r.status != 409 {
			t.Fatalf("setup %d after the claim: status = %d, want 409", i+1, r.status)
		}
	}

	// After all that the sender still has its five failures.
	for i := range 5 {
		if r := e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, "wrong"+fmt.Sprint(i)), nil); r.status != 401 {
			t.Fatalf("failure %d: status = %d, want 401", i+1, r.status)
		}
	}
	if r := e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, adminPass), nil); r.status != 429 {
		t.Errorf("the sixth failure's successor: status = %d, want 429", r.status)
	}
}

// The limit is by the client's address: an IPv4 address exactly, an IPv6 one
// by its /64, so that one client can't get a bucket for each address of its
// range, and an IPv4-mapped address is the IPv4 one.
func TestRateLimitKeys(t *testing.T) {
	failures := func(h http.Handler, remote string, n int) {
		t.Helper()
		for range n {
			r := serveAs(h, remote, "POST", "/v1/auth/login", loginBody(t, adminName, "wrong password"), nil)
			if r.status != 401 {
				t.Fatalf("%s: status = %d, want 401", remote, r.status)
			}
		}
	}
	status := func(h http.Handler, remote string) int {
		t.Helper()
		return serveAs(h, remote, "POST", "/v1/auth/login", loginBody(t, adminName, "wrong password"), nil).status
	}

	t.Run("an IPv6 /64 is one client", func(t *testing.T) {
		e := newAuthEnv(t, true)
		failures(e.h, "[2001:db8:1:2::1]:5000", 3)
		failures(e.h, "[2001:db8:1:2:ffff:ffff:ffff:ffff]:6000", 2)
		if got := status(e.h, "[2001:db8:1:2:aaaa::7]:1"); got != 429 {
			t.Errorf("another address of the /64: status = %d, want 429", got)
		}
		if got := status(e.h, "[2001:db8:1:3::1]:1"); got != 401 {
			t.Errorf("an address of another /64: status = %d, want 401 (its own bucket)", got)
		}
		if got := status(e.h, "192.0.2.1:1"); got != 401 {
			t.Errorf("an IPv4 address: status = %d, want 401 (its own bucket)", got)
		}
	})

	t.Run("a zone is no part of who the client is", func(t *testing.T) {
		e := newAuthEnv(t, true)
		failures(e.h, "[fe80::1%eth0]:1", 3)
		failures(e.h, "[fe80::1%eth1]:1", 2)
		if got := status(e.h, "[fe80::1]:1"); got != 429 {
			t.Errorf("status = %d, want 429", got)
		}
	})

	t.Run("IPv4 is exact", func(t *testing.T) {
		e := newAuthEnv(t, true)
		failures(e.h, "203.0.113.9:1000", 5)
		if got := status(e.h, "203.0.113.9:2000"); got != 429 {
			t.Errorf("the same address, another port: status = %d, want 429", got)
		}
		if got := status(e.h, "203.0.113.10:1000"); got != 401 {
			t.Errorf("the next address: status = %d, want 401", got)
		}
	})

	t.Run("an IPv4-mapped address is the IPv4 one", func(t *testing.T) {
		e := newAuthEnv(t, true)
		failures(e.h, "[::ffff:203.0.113.9]:1", 3)
		failures(e.h, "203.0.113.9:2", 2)
		if got := status(e.h, "[::ffff:203.0.113.9]:3"); got != 429 {
			t.Errorf("status = %d, want 429", got)
		}
		if got := status(e.h, "203.0.113.9:4"); got != 429 {
			t.Errorf("status = %d, want 429", got)
		}
	})

	t.Run("an address that does not parse shares one bucket", func(t *testing.T) {
		e := newAuthEnv(t, true)
		failures(e.h, "@", 3)
		failures(e.h, "somewhere", 2)
		if got := status(e.h, ""); got != 429 {
			t.Errorf("status = %d, want 429", got)
		}
	})
}

func TestClientIP(t *testing.T) {
	for _, c := range []struct{ remote, ip, key string }{
		{"192.0.2.1:443", "192.0.2.1", "192.0.2.1"},
		{"[::ffff:192.0.2.1]:443", "192.0.2.1", "192.0.2.1"},
		{"[2001:db8:1:2:3:4:5:6]:443", "2001:db8:1:2:3:4:5:6", "2001:db8:1:2::"},
		{"[fe80::1%eth0]:443", "fe80::1", "fe80::"},
		{"[::1]:443", "::1", "::"},
		{"garbage", "", ""},
		{"", "", ""},
		{"192.0.2.1", "", ""}, // no port
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		ip := clientIP(r)
		got, key := "", ""
		if ip.IsValid() {
			got, key = ip.String(), limiterKey(ip).String()
		} else if limiterKey(ip).IsValid() {
			t.Errorf("%q: the key of no address is %v", c.remote, limiterKey(ip))
		}
		if got != c.ip || key != c.key {
			t.Errorf("%q: ip = %q, key = %q, want %q and %q", c.remote, got, key, c.ip, c.key)
		}
	}
}

// --- the session routes

func TestSessionRoutes(t *testing.T) {
	e := newAuthEnv(t, true)
	sess := e.signIn(t)
	_, named := e.token(t, "ci")

	t.Run("the session", func(t *testing.T) {
		r := e.do(t, "GET", "/v1/auth/session", "", cookieOnly(sess))
		if r.status != 200 {
			t.Fatalf("status = %d, want 200 (%s)", r.status, r.body)
		}
		body := decodeAs[struct {
			Username  string    `json:"username"`
			CSRFToken string    `json:"csrf_token"`
			Expires   time.Time `json:"expires"`
		}](t, r)
		if body.Username != adminName || body.CSRFToken != sess.CSRF {
			t.Errorf("username = %q, csrf_token is the session's: %t", body.Username, body.CSRFToken == sess.CSRF)
		}
		if left := time.Until(body.Expires); left < 11*time.Hour || left > 12*time.Hour+time.Minute {
			t.Errorf("expires is %v from now, want about 12h", left)
		}
	})

	t.Run("a bearer has no session", func(t *testing.T) {
		for who, h := range map[string]http.Header{"the root token": authed(), "a named token": bearer(named)} {
			for _, c := range []struct{ method, path string }{{"GET", "/v1/auth/session"}, {"POST", "/v1/auth/logout"}} {
				r := e.do(t, c.method, c.path, "", h)
				if r.status != 403 {
					t.Errorf("%s, %s %s: status = %d, want 403", who, c.method, c.path, r.status)
					continue
				}
				if code, _ := errorOf(t, r); code != "forbidden" {
					t.Errorf("%s, %s %s: code = %q, want forbidden", who, c.method, c.path, code)
				}
			}
		}
	})

	t.Run("logout", func(t *testing.T) {
		s := e.signIn(t)
		if r := e.do(t, "POST", "/v1/auth/logout", "", cookieOnly(s)); r.status != 403 {
			t.Errorf("without the CSRF token: status = %d, want 403", r.status)
		}
		if _, ok := e.store.Session(s.ID); !ok {
			t.Fatal("a logout without the CSRF token ended the session")
		}
		r := e.do(t, "POST", "/v1/auth/logout", "", withCSRF(s))
		if r.status != 204 || len(r.body) != 0 {
			t.Fatalf("status = %d, body %q, want 204 and none", r.status, r.body)
		}
		checkCookieCleared(t, r)
		if _, ok := e.store.Session(s.ID); ok {
			t.Error("the session is still valid")
		}
		// The cookie the browser may still send is no use, and is dropped.
		r = e.do(t, "GET", "/v1/auth/session", "", cookieOnly(s))
		if r.status != 401 {
			t.Errorf("after the logout: status = %d, want 401", r.status)
		}
		checkCookieCleared(t, r)
		// The other session is not touched.
		if r := e.do(t, "GET", "/v1/auth/session", "", cookieOnly(sess)); r.status != 200 {
			t.Errorf("another session: status = %d, want 200", r.status)
		}
	})
}

func TestPasswordChangeEndsOtherSessions(t *testing.T) {
	e := newAuthEnv(t, true)
	a, b := e.signIn(t), e.signIn(t)
	_, named := e.token(t, "ci")
	change := func(h http.Header, current, next string) response {
		return e.do(t, "PUT", "/v1/auth/password", mustJSON(t, map[string]string{"current": current, "new": next}), h)
	}

	t.Run("a wrong current password changes nothing", func(t *testing.T) {
		r := change(withCSRF(a), "not the password", otherPass)
		if r.status != 403 {
			t.Fatalf("status = %d, want 403 (%s)", r.status, r.body)
		}
		if code, _ := errorOf(t, r); code != "bad_password" {
			t.Errorf("code = %q, want bad_password", code)
		}
		if _, ok := e.store.Session(b.ID); !ok {
			t.Error("a refused change ended another session")
		}
	})

	t.Run("a new password that breaks the rules", func(t *testing.T) {
		r := change(withCSRF(a), adminPass, "short")
		if r.status != 400 {
			t.Fatalf("status = %d, want 400 (%s)", r.status, r.body)
		}
		if code, _ := errorOf(t, r); code != "bad_request" {
			t.Errorf("code = %q, want bad_request", code)
		}
		if _, ok := e.store.Session(b.ID); !ok {
			t.Error("a refused change ended another session")
		}
	})

	t.Run("it needs the CSRF token", func(t *testing.T) {
		if r := change(cookieOnly(a), adminPass, otherPass); r.status != 403 {
			t.Errorf("status = %d, want 403", r.status)
		}
		if _, ok := e.store.Session(b.ID); !ok {
			t.Error("a change without the CSRF token went through")
		}
	})

	t.Run("a session keeps itself and ends the others", func(t *testing.T) {
		r := change(withCSRF(a), adminPass, otherPass)
		if r.status != 204 {
			t.Fatalf("status = %d, want 204 (%s)", r.status, r.body)
		}
		if r := e.do(t, "GET", "/v1/auth/session", "", cookieOnly(a)); r.status != 200 {
			t.Errorf("the session that changed it: status = %d, want 200", r.status)
		}
		r = e.do(t, "GET", "/v1/auth/session", "", cookieOnly(b))
		if r.status != 401 {
			t.Errorf("the other session: status = %d, want 401", r.status)
		}
		checkCookieCleared(t, r)
		if r := e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, adminPass), nil); r.status != 401 {
			t.Errorf("the old password: status = %d, want 401", r.status)
		}
		if r := e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, otherPass), nil); r.status != 200 {
			t.Errorf("the new password: status = %d, want 200", r.status)
		}
		// A named token is no session.
		if r := e.do(t, "GET", "/v1/status", "", bearer(named)); r.status != 200 {
			t.Errorf("a named token: status = %d, want 200", r.status)
		}
	})

	// Only a session may change the password: a token that leaked would
	// otherwise be a way to guess it.
	t.Run("a token may not, the root token either", func(t *testing.T) {
		c := e.signInAs(t, otherPass)
		before := len(e.events())
		for who, h := range map[string]http.Header{"the root token": authed(), "a named token": bearer(named)} {
			// The right current password: it is the caller that is refused.
			r := change(h, otherPass, adminPass)
			if r.status != 403 {
				t.Errorf("%s: status = %d, want 403 (%s)", who, r.status, r.body)
				continue
			}
			if code, _ := errorOf(t, r); code != "forbidden" {
				t.Errorf("%s: code = %q, want forbidden", who, code)
			}
		}
		if _, err := e.store.SignIn(context.Background(), adminName, otherPass); err != nil {
			t.Errorf("the password was changed by a bearer: %v", err)
		}
		if _, ok := e.store.Session(c.ID); !ok {
			t.Error("a refused change ended a session")
		}
		if got := len(e.events()); got != before {
			t.Errorf("%d events after refused changes, want none", got-before)
		}
	})
}

// A wrong current password is a failed sign-in as far as the limiter goes: the
// same bucket, and nothing is hashed once it is empty.
func TestPasswordChangeIsLimited(t *testing.T) {
	change := func(e *authEnv, s auth.Session, current, next string) response {
		return e.do(t, "PUT", "/v1/auth/password", mustJSON(t, map[string]string{"current": current, "new": next}), withCSRF(s))
	}

	t.Run("five wrong ones, then 429", func(t *testing.T) {
		e := newAuthEnv(t, true)
		s := e.signIn(t)
		for i := range 5 {
			r := change(e, s, "wrong password "+fmt.Sprint(i), otherPass)
			if r.status != 403 {
				t.Fatalf("failure %d: status = %d, want 403 (%s)", i+1, r.status, r.body)
			}
			if code, _ := errorOf(t, r); code != "bad_password" {
				t.Errorf("failure %d: code = %q, want bad_password", i+1, code)
			}
		}
		// The right current password is turned away before it is checked.
		r := change(e, s, adminPass, otherPass)
		if r.status != 429 {
			t.Fatalf("status = %d, want 429 (%s)", r.status, r.body)
		}
		if code, _ := errorOf(t, r); code != "rate_limited" {
			t.Errorf("code = %q, want rate_limited", code)
		}
		if got := r.header.Get("Retry-After"); got != "60" {
			t.Errorf("Retry-After = %q, want 60", got)
		}
		if _, err := e.store.SignIn(context.Background(), adminName, adminPass); err != nil {
			t.Errorf("the password was changed though the caller was limited: %v", err)
		}
		// Sign-in draws on the same bucket.
		if r := e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, adminPass), nil); r.status != 429 {
			t.Errorf("a sign-in after five wrong current passwords: status = %d, want 429", r.status)
		}
		want := slices.Repeat([]string{"auth: password change failed from 127.0.0.1"}, 5)
		if got := e.events(); !slices.Equal(got, want) {
			t.Errorf("events = %q\nwant %q", got, want)
		}
		e.clock.Advance(time.Minute)
		if r := change(e, s, adminPass, otherPass); r.status != 204 {
			t.Errorf("once the wait is over: status = %d, want 204 (%s)", r.status, r.body)
		}
	})

	t.Run("sign-in failures count too", func(t *testing.T) {
		e := newAuthEnv(t, true)
		s := e.signIn(t)
		for range 3 {
			e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, "wrong password"), nil)
		}
		for i := range 2 {
			if r := change(e, s, "wrong password", otherPass); r.status != 403 {
				t.Fatalf("failure %d: status = %d, want 403", i+1, r.status)
			}
		}
		if r := change(e, s, adminPass, otherPass); r.status != 429 {
			t.Errorf("status = %d, want 429", r.status)
		}
	})

	t.Run("only the failures count", func(t *testing.T) {
		e := newAuthEnv(t, true)
		s := e.signIn(t)
		const n = 6 // more than the bucket holds
		// Refused before the current password is looked at.
		for i := range n {
			if r := change(e, s, adminPass, "short"); r.status != 400 {
				t.Fatalf("a short password, try %d: status = %d, want 400", i+1, r.status)
			}
			if r := e.do(t, "PUT", "/v1/auth/password", `{"current":`, withCSRF(s)); r.status != 400 {
				t.Fatalf("a body that breaks, try %d: status = %d, want 400", i+1, r.status)
			}
		}
		// Changes that work give their token back.
		pass := adminPass
		for i := range n {
			next := fmt.Sprintf("a new long password %d", i)
			if r := change(e, s, pass, next); r.status != 204 {
				t.Fatalf("change %d: status = %d, want 204 (%s)", i+1, r.status, r.body)
			}
			pass = next
		}
		// So the sender still has its five failures.
		for i := range 5 {
			if r := change(e, s, "wrong password", otherPass); r.status != 403 {
				t.Fatalf("failure %d: status = %d, want 403", i+1, r.status)
			}
		}
		if r := change(e, s, pass, otherPass); r.status != 429 {
			t.Errorf("status = %d, want 429", r.status)
		}
	})

	t.Run("a token is refused before the limiter is asked", func(t *testing.T) {
		e := newAuthEnv(t, true)
		_, named := e.token(t, "ci")
		for range 8 {
			r := e.do(t, "PUT", "/v1/auth/password", mustJSON(t, map[string]string{"current": "wrong password", "new": otherPass}), bearer(named))
			if r.status != 403 {
				t.Fatalf("status = %d, want 403", r.status)
			}
			if code, _ := errorOf(t, r); code != "forbidden" {
				t.Fatalf("code = %q, want forbidden", code)
			}
		}
		// Nothing was taken from the sender.
		for i := range 5 {
			if r := e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, "wrong"+fmt.Sprint(i)), nil); r.status != 401 {
				t.Fatalf("failure %d: status = %d, want 401", i+1, r.status)
			}
		}
	})
}

// An admin that a reset removed between the check of a session and the change
// is 409, and not the 500 of an error nobody told apart.
func TestNoAdminIsSetupRequired(t *testing.T) {
	for _, err := range []error{auth.ErrNoAdmin, fmt.Errorf("while changing it: %w", auth.ErrNoAdmin)} {
		status, code, _ := classify(err)
		if status != 409 || code != "setup_required" {
			t.Errorf("classify(%v) = %d %s, want 409 setup_required", err, status, code)
		}
	}
}

// --- the token routes

var apiTokenForm = regexp.MustCompile(`^tkr_[0-9a-f]{8}_[A-Za-z0-9_-]{43}$`)

type tokenInfoBody struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Created  time.Time  `json:"created"`
	Expires  *time.Time `json:"expires"`
	LastUsed *time.Time `json:"last_used"`
}

func TestTokenRoutes(t *testing.T) {
	e := newAuthEnv(t, true)
	sess := e.signIn(t)
	var secrets []string  // every token made, and the secret part of each
	var bodies []response // every response but a create that worked

	do := func(method, path, body string, h http.Header) response {
		t.Helper()
		r := e.do(t, method, path, body, h)
		if !(method == "POST" && path == "/v1/tokens" && r.status == 201) {
			bodies = append(bodies, r)
		}
		return r
	}
	create := func(h http.Header, body string) response {
		t.Helper()
		return do("POST", "/v1/tokens", body, h)
	}

	r := create(authed(), `{"name":"ci","expires_in":"720h"}`)
	if r.status != 201 {
		t.Fatalf("status = %d, want 201 (%s)", r.status, r.body)
	}
	if r.header.Get("Location") != "/v1/tokens" || r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Location = %q, Cache-Control = %q", r.header.Get("Location"), r.header.Get("Cache-Control"))
	}
	made := decodeAs[struct {
		Token string        `json:"token"`
		Info  tokenInfoBody `json:"info"`
	}](t, r)
	if !apiTokenForm.MatchString(made.Token) {
		t.Fatalf("token is %d bytes, not the form of a token", len(made.Token))
	}
	secrets = append(secrets, made.Token, made.Token[13:])
	if made.Info.ID != made.Token[4:12] || made.Info.Name != "ci" {
		t.Errorf("info = %+v, want the id of the token and its name", made.Info)
	}
	if made.Info.Expires == nil || time.Until(*made.Info.Expires) < 719*time.Hour || time.Until(*made.Info.Expires) > 721*time.Hour {
		t.Errorf("expires = %v, want 720h from now", made.Info.Expires)
	}
	if made.Info.LastUsed != nil {
		t.Errorf("last_used = %v of a token that was never used", made.Info.LastUsed)
	}
	// The secret is in the response and nowhere else in it.
	if strings.Count(string(r.body), made.Token[13:]) != 1 {
		t.Error("the secret is not in the create response exactly once")
	}

	t.Run("the token works", func(t *testing.T) {
		if r := do("GET", "/v1/status", "", bearer(made.Token)); r.status != 200 {
			t.Errorf("status = %d, want 200", r.status)
		}
	})

	t.Run("one that never expires has no expiry", func(t *testing.T) {
		r := create(authed(), `{"name":"forever"}`)
		if r.status != 201 {
			t.Fatalf("status = %d, want 201 (%s)", r.status, r.body)
		}
		var raw struct {
			Token string
			Info  map[string]any
		}
		if err := json.Unmarshal(r.body, &raw); err != nil {
			t.Fatal(err)
		}
		secrets = append(secrets, raw.Token, raw.Token[13:])
		if _, has := raw.Info["expires"]; has {
			t.Errorf("info = %v, want no expires", raw.Info)
		}
		if _, has := raw.Info["last_used"]; has {
			t.Errorf("info = %v, want no last_used", raw.Info)
		}
	})

	t.Run("the list has no secret", func(t *testing.T) {
		r := do("GET", "/v1/tokens", "", authed())
		if r.status != 200 {
			t.Fatalf("status = %d, want 200", r.status)
		}
		list := decodeAs[[]tokenInfoBody](t, r)
		if len(list) != 2 || list[0].ID != made.Info.ID || list[0].Name != "ci" {
			t.Fatalf("list = %+v, want the two tokens, the oldest first", list)
		}
		if list[0].LastUsed == nil {
			t.Error("the token that was used has no last_used")
		}
		if list[1].Name != "forever" || list[1].Expires != nil {
			t.Errorf("list[1] = %+v", list[1])
		}
		var raw []map[string]any
		if err := json.Unmarshal(r.body, &raw); err != nil {
			t.Fatal(err)
		}
		for _, item := range raw {
			for k := range item {
				if !slices.Contains([]string{"id", "name", "created", "expires", "last_used"}, k) {
					t.Errorf("the list shows a field %q", k)
				}
			}
		}
	})

	t.Run("an empty list is a list", func(t *testing.T) {
		e2 := newAuthEnv(t, true)
		if r := e2.do(t, "GET", "/v1/tokens", "", authed()); strings.TrimSpace(string(r.body)) != "[]" {
			t.Errorf("body = %s, want []", r.body)
		}
	})

	t.Run("a token can make one", func(t *testing.T) {
		r := create(bearer(made.Token), `{"name":"made by a token"}`)
		if r.status != 201 {
			t.Fatalf("status = %d, want 201 (%s)", r.status, r.body)
		}
		var raw struct{ Token string }
		if err := json.Unmarshal(r.body, &raw); err != nil {
			t.Fatal(err)
		}
		secrets = append(secrets, raw.Token, raw.Token[13:])
	})

	t.Run("a session needs its CSRF token to make or revoke", func(t *testing.T) {
		if r := create(cookieOnly(sess), `{"name":"x"}`); r.status != 403 {
			t.Errorf("create: status = %d, want 403", r.status)
		}
		if r := do("DELETE", "/v1/tokens/"+made.Info.ID, "", cookieOnly(sess)); r.status != 403 {
			t.Errorf("revoke: status = %d, want 403", r.status)
		}
		if r := do("GET", "/v1/tokens", "", cookieOnly(sess)); r.status != 200 {
			t.Errorf("list: status = %d, want 200", r.status)
		}
		r := create(withCSRF(sess), `{"name":"by session"}`)
		if r.status != 201 {
			t.Fatalf("create with the token: status = %d, want 201 (%s)", r.status, r.body)
		}
		var raw struct{ Token string }
		if err := json.Unmarshal(r.body, &raw); err != nil {
			t.Fatal(err)
		}
		secrets = append(secrets, raw.Token, raw.Token[13:])
	})

	t.Run("bad requests make nothing", func(t *testing.T) {
		before := len(e.store.Tokens())
		for _, c := range []struct{ what, body string }{
			{"no name", `{}`},
			{"an empty name", `{"name":""}`},
			{"a name of 65 characters", `{"name":"` + strings.Repeat("n", 65) + `"}`},
			{"a name with a control character", `{"name":"a\u0007b"}`},
			{"an expiry that is no duration", `{"name":"x","expires_in":"soon"}`},
			{"an expiry in the past", `{"name":"x","expires_in":"-1h"}`},
			{"an expiry of nothing", `{"name":"x","expires_in":"0s"}`},
			{"an expiry that is a number", `{"name":"x","expires_in":3600}`},
			{"a field that is not known", `{"name":"x","scope":"all"}`},
			{"no body", ``},
		} {
			r := create(authed(), c.body)
			if r.status != 400 {
				t.Errorf("%s: status = %d, want 400 (%s)", c.what, r.status, r.body)
				continue
			}
			if code, _ := errorOf(t, r); code != "bad_request" {
				t.Errorf("%s: code = %q, want bad_request", c.what, code)
			}
			if strings.Contains(string(r.body), "tkr_") {
				t.Errorf("%s: the body holds a token", c.what)
			}
		}
		if got := len(e.store.Tokens()); got != before {
			t.Errorf("%d tokens after the bad requests, want %d", got, before)
		}
	})

	t.Run("revoke", func(t *testing.T) {
		r := do("DELETE", "/v1/tokens/"+made.Info.ID, "", authed())
		if r.status != 204 || len(r.body) != 0 {
			t.Fatalf("status = %d, body %q, want 204 and none", r.status, r.body)
		}
		if r := do("GET", "/v1/status", "", bearer(made.Token)); r.status != 401 {
			t.Errorf("the revoked token: status = %d, want 401", r.status)
		}
		for _, id := range []string{made.Info.ID, "00000000", "zz", "tkr_0000"} {
			r := do("DELETE", "/v1/tokens/"+id, "", authed())
			if r.status != 404 {
				t.Errorf("revoking %q: status = %d, want 404", id, r.status)
				continue
			}
			if code, _ := errorOf(t, r); code != "not_found" {
				t.Errorf("revoking %q: code = %q, want not_found", id, code)
			}
		}
	})

	t.Run("fifty at most", func(t *testing.T) {
		e3 := newAuthEnv(t, true)
		for i := range 50 {
			if r := e3.do(t, "POST", "/v1/tokens", fmt.Sprintf(`{"name":"t%d"}`, i), authed()); r.status != 201 {
				t.Fatalf("token %d: status = %d, want 201 (%s)", i+1, r.status, r.body)
			}
		}
		r := e3.do(t, "POST", "/v1/tokens", `{"name":"one too many"}`, authed())
		if r.status != 409 {
			t.Fatalf("status = %d, want 409 (%s)", r.status, r.body)
		}
		if code, _ := errorOf(t, r); code != "token_limit" {
			t.Errorf("code = %q, want token_limit", code)
		}
	})

	// No response but the creates holds a secret: not the list, not the errors.
	for _, r := range bodies {
		for _, s := range secrets {
			if strings.Contains(string(r.body), s) {
				t.Error("a response other than the create shows a token")
			}
		}
	}
}

// --- reset

func TestResetRootOnly(t *testing.T) {
	e := newAuthEnv(t, true)
	sess := e.signIn(t)
	_, named := e.token(t, "ci")

	if r := e.do(t, "POST", "/v1/auth/reset", "", nil); r.status != 401 {
		t.Errorf("no credential: status = %d, want 401", r.status)
	}
	for what, c := range map[string]struct {
		h    http.Header
		code string
	}{
		"a named token":                 {bearer(named), "forbidden"},
		"a session with its CSRF token": {withCSRF(sess), "forbidden"},
		"a session without it":          {cookieOnly(sess), "csrf"},
	} {
		r := e.do(t, "POST", "/v1/auth/reset", "", c.h)
		if r.status != 403 {
			t.Errorf("%s: status = %d, want 403", what, r.status)
			continue
		}
		if code, _ := errorOf(t, r); code != c.code {
			t.Errorf("%s: code = %q, want %s", what, code, c.code)
		}
	}
	if e.store.NeedsSetup() {
		t.Fatal("a caller that may not reset it reset the admin")
	}
	if _, ok := e.store.Session(sess.ID); !ok {
		t.Fatal("a refused reset ended the session")
	}
	if got := e.events(); len(got) != 0 {
		t.Errorf("events %v after refused resets, want none", got)
	}

	r := e.do(t, "POST", "/v1/auth/reset", "", authed())
	if r.status != 204 || len(r.body) != 0 {
		t.Fatalf("the root token: status = %d, body %q, want 204 and none", r.status, r.body)
	}
	if !e.store.NeedsSetup() {
		t.Error("the admin was not reset")
	}
	if r := e.do(t, "GET", "/v1/auth/session", "", cookieOnly(sess)); r.status != 401 {
		t.Errorf("the session after the reset: status = %d, want 401", r.status)
	}
	if r := e.do(t, "GET", "/v1/status", "", bearer(named)); r.status != 200 {
		t.Errorf("a named token after the reset: status = %d, want 200 (the tokens stay)", r.status)
	}
	sameJSON(t, e.do(t, "GET", "/v1/auth/state", "", nil).body, `{"setup_required":true,"signed_in":false}`)
	if r := e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, adminPass), nil); r.status != 401 {
		t.Errorf("the old password: status = %d, want 401", r.status)
	}
	// The new code, which only the file and the CLI show, claims it again.
	code, err := e.store.SetupCode()
	if err != nil {
		t.Fatal(err)
	}
	if r := e.do(t, "POST", "/v1/auth/setup", setupBody(t, code, "bob", "bob's new password"), nil); r.status != 200 {
		t.Errorf("setup after the reset: status = %d, want 200 (%s)", r.status, r.body)
	}
	if strings.Contains(string(r.body), code) {
		t.Error("the reset response shows the setup code")
	}
}

// --- headers

func TestSecurityHeaders(t *testing.T) {
	e := newAuthEnv(t, true)
	sess := e.signIn(t)
	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"Cache-Control":           "no-store",
	}
	check := func(what string, r response) {
		t.Helper()
		for k, v := range want {
			if got := r.header.Values(k); len(got) != 1 || got[0] != v {
				t.Errorf("%s (status %d): %s = %q, want %q", what, r.status, k, got, v)
			}
		}
	}

	check("healthz", e.do(t, "GET", "/healthz", "", nil))
	check("the state of the sign-in", e.do(t, "GET", "/v1/auth/state", "", nil))
	check("a read", e.do(t, "GET", "/v1/status", "", authed()))
	check("a change", e.do(t, "PUT", "/v1/policy", `{"mode":"full"}`, authed()))
	check("a 204", e.do(t, "DELETE", "/v1/servers/5ab3c4d5", "", authed()))
	check("a 401", e.do(t, "GET", "/v1/status", "", nil))
	check("a 401 that clears the cookie", e.do(t, "GET", "/v1/status", "", hdr("Cookie", "tikray_session=junk")))
	check("a 403 for the CSRF token", e.do(t, "PUT", "/v1/policy", `{"mode":"full"}`, cookieOnly(sess)))
	check("a 403 for the root only", e.do(t, "POST", "/v1/auth/reset", "", withCSRF(sess)))
	check("a 404", e.do(t, "GET", "/v1/nope", "", authed()))
	check("a 400", e.do(t, "POST", "/v1/auth/login", "{", nil))
	check("a sign-in", e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, adminPass), nil))
	check("a failed sign-in", e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, "wrong"), nil))
	// What the mux itself answers, such as the redirect of a path that is not
	// clean.
	redirect := serveAs(e.h, "192.0.2.1:1", "GET", "/v1/../v1/status", "", authed())
	if redirect.status < 300 || redirect.status > 399 {
		t.Errorf("the unclean path: status = %d, want a redirect", redirect.status)
	}
	check("a redirect", redirect)
	for range 5 {
		e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, "wrong"), nil)
	}
	limited := e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, "wrong"), nil)
	if limited.status != 429 {
		t.Fatalf("status = %d, want 429", limited.status)
	}
	check("a 429", limited)
}

// --- events

func TestAuthEvents(t *testing.T) {
	e := newAuthEnv(t, false)
	code, err := e.store.SetupCode()
	if err != nil {
		t.Fatal(err)
	}
	const ip = "127.0.0.1"
	last := func() []string {
		got := e.events()
		e.f.mu.Lock()
		e.f.logs = nil
		e.f.mu.Unlock()
		return got
	}
	expect := func(what string, want ...string) {
		t.Helper()
		got := last()
		if !slices.Equal(got, want) {
			t.Errorf("%s: events = %q\nwant %q", what, got, want)
		}
	}

	e.do(t, "POST", "/v1/auth/setup", setupBody(t, code, adminName, adminPass), nil)
	expect("setup", `auth: setup completed: admin "alice" created from `+ip)

	e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, adminPass), nil)
	expect("sign-in", `auth: signed in: "alice" from `+ip)

	e.do(t, "POST", "/v1/auth/login", loginBody(t, adminName, "wrong password"), nil)
	expect("a failed sign-in", `auth: sign-in failed for "alice" from `+ip)

	// Only the admin's own name is in the event of a failed sign-in: any other
	// is whatever a caller typed, and a person types a password there.
	for what, name := range map[string]string{
		"a name that is not the admin's":   "bob",
		"a long name":                      strings.Repeat("ü", 100),
		"a name with control characters":   "bob\nauth: signed in: \"alice\"\x1b[31m\xe2\x80\xae",
		"no name":                          "",
		"the admin's name in another case": "ALICE",
	} {
		e.do(t, "POST", "/v1/auth/login", loginBody(t, name, "wrong password"), nil)
		expect(what, `auth: sign-in failed for an unknown user from `+ip)
		e.clock.Advance(time.Hour) // the bucket holds five failures, and these are six
	}

	// No event for what was refused before a credential was looked at.
	e.do(t, "POST", "/v1/auth/login", `{`, nil)
	e.do(t, "POST", "/v1/auth/setup", setupBody(t, code, adminName, adminPass), nil)
	expect("requests that were refused")

	sess := e.signIn(t)
	e.do(t, "PUT", "/v1/auth/password", mustJSON(t, map[string]string{"current": adminPass, "new": otherPass}), withCSRF(sess))
	expect("a password change", `auth: password changed from `+ip)

	e.do(t, "PUT", "/v1/auth/password", mustJSON(t, map[string]string{"current": "wrong password", "new": adminPass}), withCSRF(sess))
	expect("a password change that failed", `auth: password change failed from `+ip)

	e.do(t, "PUT", "/v1/auth/password", mustJSON(t, map[string]string{"current": otherPass, "new": "short"}), withCSRF(sess))
	expect("a password change that broke a rule")

	e.do(t, "PUT", "/v1/auth/password", mustJSON(t, map[string]string{"current": otherPass, "new": adminPass}), bearer(testToken))
	expect("a password change by the root token")

	r := e.do(t, "POST", "/v1/tokens", `{"name":"ci \"nightly\""}`, authed())
	made := decodeAs[struct {
		Info tokenInfoBody `json:"info"`
	}](t, r)
	expect("a new token", `auth: API token "ci \"nightly\"" (`+made.Info.ID+`) created`)

	e.do(t, "POST", "/v1/tokens", `{"name":""}`, authed())
	expect("a refused token")

	e.do(t, "DELETE", "/v1/tokens/"+made.Info.ID, "", authed())
	expect("a revoked token", `auth: API token "ci \"nightly\"" (`+made.Info.ID+`) revoked`)

	e.do(t, "DELETE", "/v1/tokens/"+made.Info.ID, "", authed())
	expect("a token that is not there")

	e.do(t, "POST", "/v1/auth/logout", "", withCSRF(sess))
	expect("a logout", `auth: signed out: "alice" from `+ip)

	e.do(t, "POST", "/v1/auth/reset", "", authed())
	expect("a reset", `auth: admin reset from `+ip)
}

// An IP in an event is the client's address, as it is (an IPv6 address in
// full, an IPv4-mapped one as IPv4), not the key of its bucket.
func TestAuthEventsNameTheClient(t *testing.T) {
	e := newAuthEnv(t, true)
	serveAs(e.h, "[::ffff:203.0.113.9]:1", "POST", "/v1/auth/login", loginBody(t, adminName, "wrong password"), nil)
	serveAs(e.h, "[2001:db8:1:2:3:4:5:6]:1", "POST", "/v1/auth/login", loginBody(t, adminName, "wrong password"), nil)
	serveAs(e.h, "nonsense", "POST", "/v1/auth/login", loginBody(t, adminName, "wrong password"), nil)
	want := []string{
		`auth: sign-in failed for "alice" from 203.0.113.9`,
		`auth: sign-in failed for "alice" from 2001:db8:1:2:3:4:5:6`,
		`auth: sign-in failed for "alice" from an address that is not known`,
	}
	if got := e.events(); !slices.Equal(got, want) {
		t.Errorf("events = %q\nwant %q", got, want)
	}
}

// Drive every route with distinctive secrets. None of them is in any event,
// or in any response but the one that hands it to its owner: the session's
// own cookie and CSRF token to the sign-in that made it, a token to the
// request that made it.
func TestAuthEventsHaveNoSecrets(t *testing.T) {
	const (
		wrongCode = "K9K9-M8M8-Q7Q7"
		adminPW   = "Sn3aky-Admin-Pass-1"
		wrongPW   = "Wr0ng-Guess-Pass-2"
		newPW     = "N3w-Sneaky-Pass-3"
	)
	e := newAuthEnv(t, false)
	code, err := e.store.SetupCode()
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{
		"the setup code":                    code,
		"the setup code without its dashes": strings.ReplaceAll(code, "-", ""),
		"the wrong code":                    wrongCode,
		"the admin's password":              adminPW,
		"the wrong password":                wrongPW,
		"the new password":                  newPW,
		"the root token":                    testToken,
	}
	type seen struct {
		what    string
		r       response
		allowed []string // the labels of the secrets this response may hold
	}
	var all []seen
	call := func(what string, allowed []string, method, path, body string, h http.Header) response {
		t.Helper()
		r := e.do(t, method, path, body, h)
		all = append(all, seen{what, r, allowed})
		return r
	}
	// learn records the secrets a sign-in handed out, which are in its response:
	// the id in the cookie, the CSRF token in the body.
	learn := func(n string, r response) auth.Session {
		t.Helper()
		id := checkSessionCookie(t, r)
		body := decodeAs[signedIn](t, r)
		if body.CSRFToken == "" {
			t.Fatalf("the response that made %s's session has no CSRF token", n)
		}
		secrets["the session id of "+n] = id
		secrets["the CSRF token of "+n] = body.CSRFToken
		return auth.Session{ID: id, CSRF: body.CSRFToken}
	}
	own := func(n string) []string { return []string{"the session id of " + n, "the CSRF token of " + n} }

	call("state", nil, "GET", "/v1/auth/state", "", nil)
	call("a wrong code", nil, "POST", "/v1/auth/setup", setupBody(t, wrongCode, adminName, adminPW), nil)
	call("a short password", nil, "POST", "/v1/auth/setup", setupBody(t, code, adminName, "short"), nil)
	r := call("setup", own("setup"), "POST", "/v1/auth/setup", setupBody(t, strings.ToLower(code), adminName, adminPW), nil)
	setup := learn("setup", r)
	call("setup again", nil, "POST", "/v1/auth/setup", setupBody(t, code, adminName, adminPW), nil)
	call("a wrong password", nil, "POST", "/v1/auth/login", loginBody(t, adminName, wrongPW), nil)
	call("an unknown user", nil, "POST", "/v1/auth/login", loginBody(t, "nobody", wrongPW), nil)
	// A password typed into the username field: it is no event's business.
	call("a password for a username", nil, "POST", "/v1/auth/login", loginBody(t, newPW, wrongPW), nil)
	call("a body that breaks", nil, "POST", "/v1/auth/login", `{"username":"alice","password":"`+adminPW, nil)
	call("a body of the wrong type", nil, "POST", "/v1/auth/login", `{"username":"alice","password":["`+adminPW+`"]}`, nil)
	// The name of the field is shown, as it is of any body that is refused;
	// what a field holds never is.
	call("a field that is not known", nil, "POST", "/v1/auth/login", `{"username":"alice","password":"`+adminPW+`","pasword":"`+wrongPW+`"}`, nil)
	r = call("login", own("login"), "POST", "/v1/auth/login", loginBody(t, adminName, adminPW), nil)
	login := learn("login", r)
	e.clock.Advance(time.Hour) // the failures so far are forgiven

	call("the session", []string{"the CSRF token of login"}, "GET", "/v1/auth/session", "", cookieOnly(login))
	call("a request without the CSRF token", nil, "PUT", "/v1/policy", `{"mode":"full"}`, cookieOnly(login))
	call("a request with it", nil, "PUT", "/v1/policy", `{"mode":"full"}`, withCSRF(login))

	r = call("a new token", []string{"the token", "the token's secret"}, "POST", "/v1/tokens", `{"name":"ci"}`, withCSRF(login))
	var made struct {
		Token string
		Info  tokenInfoBody
	}
	if err := json.Unmarshal(r.body, &made); err != nil || !apiTokenForm.MatchString(made.Token) {
		t.Fatalf("the create response is no token (%v)", err)
	}
	secrets["the token"], secrets["the token's secret"] = made.Token, made.Token[13:]
	call("the token's use", nil, "GET", "/v1/status", "", bearer(made.Token))
	call("the token lists", nil, "GET", "/v1/tokens", "", bearer(made.Token))
	call("a refused token", nil, "POST", "/v1/tokens", `{"name":"`+wrongPW+`","expires_in":"`+adminPW+`"}`, authed())
	call("a password change that is refused", nil, "PUT", "/v1/auth/password", mustJSON(t, map[string]string{"current": wrongPW, "new": newPW}), withCSRF(login))
	call("a password that is too short", nil, "PUT", "/v1/auth/password", mustJSON(t, map[string]string{"current": adminPW, "new": "short"}), withCSRF(login))
	call("a password change that breaks", nil, "PUT", "/v1/auth/password", `{"current":"`+adminPW+`","new":"`+newPW, withCSRF(login))
	call("a password change by a token", nil, "PUT", "/v1/auth/password", mustJSON(t, map[string]string{"current": adminPW, "new": newPW}), bearer(made.Token))
	call("a password change", nil, "PUT", "/v1/auth/password", mustJSON(t, map[string]string{"current": adminPW, "new": newPW}), withCSRF(login))
	call("the other session, ended", nil, "GET", "/v1/auth/session", "", cookieOnly(setup))
	call("a revoke", nil, "DELETE", "/v1/tokens/"+made.Info.ID, "", withCSRF(login))
	call("the revoked token", nil, "GET", "/v1/status", "", bearer(made.Token))
	call("a revoke again", nil, "DELETE", "/v1/tokens/"+made.Info.ID, "", authed())
	call("a logout", nil, "POST", "/v1/auth/logout", "", withCSRF(login))
	call("the session after it", nil, "GET", "/v1/status", "", withCSRF(login))
	call("a reset by a token", nil, "POST", "/v1/auth/reset", "", bearer(made.Token))
	call("the root token", nil, "GET", "/v1/status", "", authed())
	call("a wrong bearer", nil, "GET", "/v1/status", "", bearer(wrongPW))
	call("a reset", nil, "POST", "/v1/auth/reset", "", authed())
	for range 5 {
		call("a failure", nil, "POST", "/v1/auth/login", loginBody(t, adminName, wrongPW), nil)
	}
	call("a sign-in that is limited", nil, "POST", "/v1/auth/login", loginBody(t, adminName, newPW), nil)
	call("a setup that is limited", nil, "POST", "/v1/auth/setup", setupBody(t, code, adminName, newPW), nil)

	for _, s := range all {
		var text strings.Builder
		text.Write(s.r.body)
		for k, vs := range s.r.header {
			text.WriteString(k + ": " + strings.Join(vs, ", ") + "\n")
		}
		for label, secret := range secrets {
			if strings.Contains(text.String(), secret) && !slices.Contains(s.allowed, label) {
				t.Errorf("%s: the response shows %s", s.what, label)
			}
		}
	}
	events := e.events()
	if len(events) == 0 {
		t.Fatal("no event was recorded")
	}
	for _, ev := range events {
		for label, secret := range secrets {
			if strings.Contains(ev, secret) {
				t.Errorf("an event shows %s", label)
			}
		}
	}
}
