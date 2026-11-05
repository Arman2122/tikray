//go:build lab

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/apiclient"
)

var setupPattern = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){2}$`)
var tokenPattern = regexp.MustCompile(`^tkr_([0-9a-f]{8})_([A-Za-z0-9_-]{43})$`)

// TestAuth exercises first setup through a real restart of the control
// container. The rate-limit check follows the restart so that the three bad
// setup codes cannot consume any of its five allowed attempts.
func TestAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Minute)
	defer cancel()
	l := Deploy(ctx, t)
	check := l.recordChecks(t, "m2c-auth")
	const setupPath = dataRoot + "/state/setup.code"
	const admin = "lab-admin"
	password := rand.Text()
	var code string
	var pinned *apiclient.Client
	waitHealthy := func(t *testing.T, ctx context.Context) {
		t.Helper()
		if pinned == nil {
			t.Fatal("setup_required did not obtain the pinned client")
		}
		start, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		_, up := poll(start, time.Minute, time.Second, func() bool { return pinned.Healthz(start) == nil })
		if !up {
			t.Fatal("the pinned API did not answer /healthz within a minute")
		}
	}
	var anonymous, root, session, survivingToken authLabClient

	check("setup_required", func(t *testing.T, note func(string, ...any)) {
		if err := l.startServe(ctx); err != nil {
			t.Fatal("could not start tikray serve")
		}
		start, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		api, err := l.api(start)
		if err != nil {
			t.Fatal("could not read the service's credentials")
		}
		pinned = api
		waitHealthy(t, start)
		anonymous = authLabClient{base: api.BaseURL, http: api.HTTPClient()}
		root = anonymous
		root.bearer = api.Token
		anonymous.wantState(t, ctx, true, false)

		out, err := l.CHR.RunPrivate(ctx, ":put ["+fileContents(setupPath)+"]")
		if err != nil {
			t.Fatal("could not read setup.code on RouterOS")
		}
		code = strings.TrimSpace(out)
		if !setupPattern.MatchString(code) {
			t.Fatal("setup.code does not have the 12-symbol Crockford shape")
		}
		l.wantSetupCLI(ctx, t, code)
		// The HTTPS response can arrive before RouterOS publishes the container
		// messages. Stop at once on a leak even if startup is still in progress.
		logCtx, stop := context.WithTimeout(ctx, 20*time.Second)
		defer stop()
		var seen startupLog
		var read bool
		poll(logCtx, 20*time.Second, time.Second, func() bool {
			logs, err := readContainerLog(logCtx, l.CHR)
			if err != nil {
				return false
			}
			read = true
			seen = setupLogEvidence(logs, code)
			return seen.ordered || seen.exposed
		})
		note("container log read=%t lines=%d; hint start=%t command=%t end=%t complete=%t; listener=%t; order correct=%t; setup code exposed=%t",
			read, seen.lines, seen.start, seen.command, seen.end, seen.hint, seen.listener, seen.ordered, seen.exposed)
		if !read || !seen.ordered {
			t.Errorf("setup hint must precede listener: read=%t lines=%d hint start=%t command=%t end=%t complete=%t listener=%t",
				read, seen.lines, seen.start, seen.command, seen.end, seen.hint, seen.listener)
		}
		if seen.exposed {
			t.Error("the container log leaked the setup code")
		}
		note("fresh API requires setup; file and CLI agreed on a 12-symbol code; CLI exited 0")
	})

	check("claim_admin", func(t *testing.T, note func(string, ...any)) {
		if code == "" {
			t.Fatal("setup_required did not obtain the code")
		}
		wrong := "0000-0000-0000"
		if code == wrong {
			wrong = "1111-1111-1111"
		}
		in := map[string]string{"username": admin, "password": password, "code": wrong}
		for range 3 {
			anonymous.call(t, ctx, "POST", "/v1/auth/setup", in, 401).wantError(t, "bad_code")
		}
		in["code"] = code
		reply := anonymous.call(t, ctx, "POST", "/v1/auth/setup", in, 200)
		session = anonymous.withSession(t, reply)
		session.wantState(t, ctx, false, true)
		if exists, err := l.exists(ctx, setupPath); err != nil || exists {
			t.Error("setup.code should be absent after claim")
		}
		l.wantSetupCLI(ctx, t, "the admin has been claimed")
		note("three wrong codes returned 401 bad_code; claim returned 200 with a secure, HttpOnly, SameSite=Strict cookie for / with a 7-day Max-Age; setup file consumed")
	})

	check("session_and_csrf", func(t *testing.T, note func(string, ...any)) {
		cookieOnly := session
		cookieOnly.csrf = ""
		before := cookieOnly.revision(t, ctx)
		policy := map[string]string{"mode": "smart"}
		cookieOnly.call(t, ctx, "PUT", "/v1/policy", policy, 403).wantError(t, "csrf")
		if cookieOnly.revision(t, ctx) != before {
			t.Fatal("policy changed without a CSRF header")
		}
		session.call(t, ctx, "PUT", "/v1/policy", policy, 200)
		after := cookieOnly.revision(t, ctx)
		if after != before+1 {
			t.Fatalf("cookie policy update moved revision from %d to %d, want one change", before, after)
		}
		root.call(t, ctx, "PUT", "/v1/policy", map[string]string{"mode": "direct"}, 200)
		if rev := cookieOnly.revision(t, ctx); rev != after+1 {
			t.Fatalf("root bearer policy update moved revision from %d to %d, want one change", after, rev)
		}
		note("cookie GET 200; missing-CSRF PUT 403 at revision %d; cookie with CSRF and root bearer without CSRF each wrote one revision", before)
	})

	check("api_token", func(t *testing.T, note func(string, ...any)) {
		// A second token proves persistence after revoking the first.
		revoked, revokeID := session.createToken(t, ctx, "revoked")
		survivor, keepID := session.createToken(t, ctx, "survivor")
		revoked.revision(t, ctx)
		survivor.revision(t, ctx)
		list := session.call(t, ctx, "GET", "/v1/tokens", nil, 200)
		var tokens []struct{ ID, Name string }
		list.decode(t, &tokens)
		names := map[string]string{}
		for _, tok := range tokens {
			names[tok.ID] = tok.Name
		}
		if len(tokens) != 2 || names[revokeID] != "revoked" || names[keepID] != "survivor" {
			t.Fatal("token list did not identify the two named tokens")
		}
		for _, tok := range []string{revoked.bearer, survivor.bearer} {
			if bytes.Contains(list.body, []byte(tokenPattern.FindStringSubmatch(tok)[2])) {
				t.Error("token list leaked a token secret")
			}
		}
		session.call(t, ctx, "DELETE", "/v1/tokens/"+revokeID, nil, 204)
		revoked.call(t, ctx, "GET", "/v1/status", nil, 401).wantError(t, "unauthorized")
		survivingToken = survivor
		note("two tokens created and used; list returned both names without their secrets; revoked token received 401")
	})

	check("restart_keeps_auth", func(t *testing.T, note func(string, ...any)) {
		if err := l.stopServe(ctx); err != nil {
			t.Fatal("could not stop tikray serve")
		}
		if err := l.startServe(ctx); err != nil {
			t.Fatal("could not restart tikray serve")
		}
		// Use the original pin, cookie and bearer on fresh connections.
		waitHealthy(t, ctx)
		session.revision(t, ctx)
		survivingToken.revision(t, ctx)
		session.wantState(t, ctx, false, true)
		note("after a container stop and start the old session and token each received 200; signed in, setup not required")
	})

	check("login_rate_limit", func(t *testing.T, note func(string, ...any)) {
		in := map[string]string{"username": admin, "password": password + "x"}
		for range 5 {
			anonymous.call(t, ctx, "POST", "/v1/auth/login", in, 401).wantError(t, "bad_credentials")
		}
		blocked := anonymous.call(t, ctx, "POST", "/v1/auth/login", in, 429)
		blocked.retrySeconds(t)
		in["password"] = password
		wait := anonymous.call(t, ctx, "POST", "/v1/auth/login", in, 429).retrySeconds(t)
		if err := sleep(ctx, time.Duration(wait+1)*time.Second); err != nil {
			t.Fatal("context ended during the rate-limit wait")
		}
		reply := anonymous.call(t, ctx, "POST", "/v1/auth/login", in, 200)
		anonymous.withSession(t, reply).revision(t, ctx)
		note("five bad passwords received 401; the sixth and the right password received 429; login succeeded after Retry-After %d s", wait)
	})
}

// Startup log diagnostics contain only counts and predicates: a regression
// could put the setup code in any line, including one from another container.
type startupLog struct {
	lines                                                 int
	start, command, end, hint, listener, ordered, exposed bool
}

func setupLogEvidence(logs, code string) startupLog {
	const start = "tikray: no admin yet: run "
	const command = `"tikray setup-code"`
	const end = " in this container to get the setup code"
	hint := strings.Index(logs, start+command+end)
	listener := strings.Index(logs, "tikray: serving on ")
	seen := startupLog{
		start: strings.Contains(logs, start), command: strings.Contains(logs, command), end: strings.Contains(logs, end),
		hint: hint >= 0, listener: listener >= 0, ordered: hint >= 0 && listener > hint,
		exposed: strings.Contains(logs, code),
	}
	for line := range strings.Lines(logs) {
		if strings.TrimSpace(line) != "" {
			seen.lines++
		}
	}
	return seen
}

// These fixtures exercise the startup-log assertion independently of CHR.
// A fragment or a reversed pair must still fail after bypassing table output.
func TestSetupLogEvidence(t *testing.T) {
	const marker = "private-fixture-value"
	const hint = `tikray: no admin yet: run "tikray setup-code" in this container to get the setup code`
	const listener = "tikray: serving on :443, certificate sha256"
	for _, tc := range []struct {
		name, log        string
		ordered, exposed bool
	}{
		{"complete", "unrelated\ncontainer: " + hint + "\ncontainer: " + listener + "\n", true, false},
		{"reversed", listener + "\n" + hint, false, false},
		{"cut hint", strings.TrimSuffix(hint, " code") + "\n" + listener, false, false},
		{"missing listener", hint, false, false},
		{"leak on another line", hint + "\n" + listener + "\n" + marker, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := setupLogEvidence(tc.log, marker)
			if got.ordered != tc.ordered || got.exposed != tc.exposed {
				t.Error("incorrect startup log assessment")
			}
		})
	}
}

func (l *Lab) wantSetupCLI(ctx context.Context, t *testing.T, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	// RouterOS's SSH exec exits 0 even for a failed command. The marker
	// comes from the container's shell only when the CLI itself exited 0.
	const command = `/container/shell [find name=tikray] cmd="tikray setup-code && echo cli-succeeded"`
	out, err := l.CHR.RunPrivate(ctx, command)
	if err != nil || strings.TrimSpace(out) != want+"\ncli-succeeded" {
		t.Fatal("tikray setup-code did not return the expected output and exit 0")
	}
}

// Credentials are sent separately so a bearer cannot mask a failing session
// cookie. Every client shares the service's pinned transport.
type authLabClient struct {
	base         string
	http         *http.Client
	cookie       *http.Cookie
	csrf, bearer string
}

type authLabReply struct {
	response *http.Response
	body     []byte
}

func (a authLabClient) call(t *testing.T, ctx context.Context, method, path string, in any, want int) authLabReply {
	t.Helper()
	if a.http == nil {
		t.Fatal("an earlier auth check did not establish this client")
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatal("could not encode auth request")
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, body)
	if err != nil {
		t.Fatal("could not construct auth request")
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.cookie != nil {
		req.AddCookie(a.cookie)
	}
	if a.csrf != "" {
		req.Header.Set("X-Tikray-CSRF", a.csrf)
	}
	if a.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+a.bearer)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		t.Fatalf("%s %s: transport failure (%T)", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("%s %s returned %d, want %d", method, path, resp.StatusCode, want)
	}
	const limit = 1 << 20
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || len(b) > limit {
		t.Fatalf("could not read a bounded response from %s %s", method, path)
	}
	return authLabReply{response: resp, body: b}
}

func (r authLabReply) decode(t *testing.T, out any) {
	t.Helper()
	if json.Unmarshal(r.body, out) != nil {
		t.Fatal("auth response had an unexpected JSON format")
	}
}

func (r authLabReply) wantError(t *testing.T, want string) {
	t.Helper()
	var e struct{ Error string }
	r.decode(t, &e)
	if e.Error != want {
		t.Fatalf("response did not carry error code %q", want)
	}
}

func (r authLabReply) retrySeconds(t *testing.T) int {
	t.Helper()
	r.wantError(t, "rate_limited")
	secs, err := strconv.Atoi(r.response.Header.Get("Retry-After"))
	if err != nil || secs < 1 || secs > 60 {
		t.Fatal("Retry-After must be a whole number of seconds from 1 to 60")
	}
	return secs
}

func (a authLabClient) wantState(t *testing.T, ctx context.Context, setup, signedIn bool) {
	t.Helper()
	var state struct {
		Setup    *bool `json:"setup_required"`
		SignedIn *bool `json:"signed_in"`
	}
	a.call(t, ctx, "GET", "/v1/auth/state", nil, 200).decode(t, &state)
	if state.Setup == nil || state.SignedIn == nil || *state.Setup != setup || *state.SignedIn != signedIn {
		t.Fatalf("unexpected auth state; wanted setup_required=%v, signed_in=%v", setup, signedIn)
	}
}

func (a authLabClient) revision(t *testing.T, ctx context.Context) uint64 {
	t.Helper()
	var st struct {
		Revision *uint64 `json:"revision"`
	}
	a.call(t, ctx, "GET", "/v1/status", nil, 200).decode(t, &st)
	if st.Revision == nil {
		t.Fatal("status omitted the revision")
	}
	return *st.Revision
}

func (a authLabClient) withSession(t *testing.T, r authLabReply) authLabClient {
	t.Helper()
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	r.decode(t, &session)
	cookies := r.response.Cookies()
	if len(cookies) != 1 || session.CSRF == "" {
		t.Fatal("expected one session cookie and a CSRF value")
	}
	c := cookies[0]
	if c.Name != "tikray_session" || c.Value == "" || c.Path != "/" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.MaxAge != 7*24*60*60 {
		t.Fatal("session cookie lacks the required name, value or attributes")
	}
	a.cookie, a.csrf = c, session.CSRF
	return a
}

func (a authLabClient) createToken(t *testing.T, ctx context.Context, name string) (authLabClient, string) {
	t.Helper()
	var result struct {
		Token string
		Info  struct{ ID string }
	}
	a.call(t, ctx, "POST", "/v1/tokens", map[string]string{"name": name}, 201).decode(t, &result)
	parts := tokenPattern.FindStringSubmatch(result.Token)
	if parts == nil || parts[1] != result.Info.ID {
		t.Fatal("new token had an unexpected shape or ID")
	}
	return authLabClient{base: a.base, http: a.http, bearer: result.Token}, result.Info.ID
}
