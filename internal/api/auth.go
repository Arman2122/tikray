package api

// Who may call the API: the credential of a request, the CSRF check of a
// cookie, the routes that sign people in and out, the named tokens, and the
// headers every response has. The rules are in the package comment; the
// secrets (a password, the setup code, a session id, a CSRF token, an API
// token) are in no error, event or body here, but where they are handed to
// their owner.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Arman2122/tikray/internal/auth"
	"github.com/Arman2122/tikray/internal/service"
)

const (
	// sessionCookie is the name of the cookie that holds a session's id.
	sessionCookie = "tikray_session"
	// csrfHeader is the header that carries the CSRF token of a session.
	csrfHeader = "X-Tikray-CSRF"
	// maxNameRunes is how much of a username an event holds.
	maxNameRunes = 64
)

// who says what a request was authenticated by.
type who int

const (
	byRoot who = iota + 1
	byToken
	bySession
)

// caller is the credential of an authenticated request: what it was
// authenticated by, and the token or the session that was.
type caller struct {
	who     who
	token   auth.TokenInfo // byToken
	session auth.Session   // bySession
}

type callerKey struct{}

// callerOf is the caller of a request that guard let in.
func callerOf(r *http.Request) caller {
	c, _ := r.Context().Value(callerKey{}).(caller)
	return c
}

// isPublic reports whether a request needs no credential: GET /healthz, the
// state of the sign-in, and the two routes that start a session, which a
// Limiter holds. Any other method on those paths is no public route.
func isPublic(r *http.Request) bool {
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	switch r.URL.Path {
	case "/healthz", "/v1/auth/state":
		return read
	case "/v1/auth/setup", "/v1/auth/login":
		return r.Method == http.MethodPost
	}
	return false
}

// guard is the check in front of the routes. Every response has the security
// headers. A request to a public route goes through; any other must have a
// credential (authenticate), or is 401, and one made with a session's cookie
// that is not a read must have its CSRF token, or is 403. It checks that the
// session is there before it looks at the token, so that a request with no
// session is never a CSRF failure. The body of every request is capped.
func (h *handler) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w.Header())
		if isPublic(r) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
			next.ServeHTTP(w, r)
			return
		}
		c, ok := h.authenticate(r)
		if !ok {
			// A cookie that is no session is no use to the browser either.
			if _, err := r.Cookie(sessionCookie); err == nil {
				clearSessionCookie(w)
			}
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, errorBody{Error: codeUnauthorized})
			return
		}
		if c.who == bySession && r.Method != http.MethodGet && r.Method != http.MethodHead &&
			!h.a.CheckCSRF(c.session.ID, r.Header.Get(csrfHeader)) {
			writeJSON(w, http.StatusForbidden, errorBody{Error: codeCSRF, Detail: "the " + csrfHeader + " header is missing or is not this session's token"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, c)))
	})
}

// setSecurityHeaders sets what every response has: it is not a page to sniff,
// frame or send on as a referrer, and nothing it may load, and it is not kept
// (a body may hold a credential).
func setSecurityHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	h.Set("Cache-Control", "no-store")
}

// authenticate finds the credential of r, the first of these that holds: the
// root token, an API token, the cookie of a session. A bearer that is neither
// leaves the cookie to decide, and so the CSRF check with it: the exemption
// of a bearer is for one that works.
//
// The root token is compared as the hashes of both sides, in constant time, so
// that neither the content nor the length of what the caller sent shows in the
// time it takes.
func (h *handler) authenticate(r *http.Request) (caller, bool) {
	const scheme = "Bearer "
	if v := r.Header.Get("Authorization"); len(v) >= len(scheme) && strings.EqualFold(v[:len(scheme)], scheme) {
		presented := v[len(scheme):]
		got := sha256.Sum256([]byte(presented))
		if h.hasRoot && subtle.ConstantTimeCompare(got[:], h.root[:]) == 1 {
			return caller{who: byRoot}, true
		}
		if info, ok := h.a.CheckToken(presented); ok {
			return caller{who: byToken, token: info}, true
		}
	}
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		if s, ok := h.a.Session(c.Value); ok {
			return caller{who: bySession, session: s}, true
		}
	}
	return caller{}, false
}

// --- the cookie

// startSessionCookie sets the cookie of a new session: Secure, HttpOnly and
// SameSite=Strict, for the whole site, for as long as a session can last.
func startSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		MaxAge:   int(auth.SessionLife / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearSessionCookie tells the browser to drop the cookie.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// --- the client

// clientIP is the address the request came from: its remote address, with an
// IPv4-mapped IPv6 address as the IPv4 one and no zone. It is the zero Addr
// when the remote address is no address and port. The API sits behind no
// proxy, and M3's firewall decides who can reach the port, so nothing a
// caller sends says who it is.
func clientIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap().WithZone("")
}

// limiterKey is the address a client is counted by: an IPv4 address as it is,
// an IPv6 one by its /64, so that one client can't get a bucket of its own for
// each address of the range it was given. The zero Addr (a remote address that
// is none) is one client of its own.
func limiterKey(ip netip.Addr) netip.Addr {
	if ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().Addr()
	}
	return ip
}

// ipText is an address for an event.
func ipText(ip netip.Addr) string {
	if !ip.IsValid() {
		return "an address that is not known"
	}
	return ip.String()
}

// quoteName is a username or a token name for an event: cut to 64 runes (a
// caller can send a megabyte) and quoted, so that a control character or a
// line break in it can't forge a line of the log.
func quoteName(s string) string {
	if utf8.RuneCountInString(s) > maxNameRunes {
		s = string([]rune(s)[:maxNameRunes])
	}
	return strconv.Quote(s)
}

// record keeps an event of the kind auth. It is told what happened, never
// what was sent: no password, no code, no id, token or CSRF token is in any
// of them.
func (h *handler) record(format string, args ...any) {
	h.b.Record(service.KindAuth, fmt.Sprintf(format, args...))
}

// --- answers

// refuse answers a caller that has no credential (the public routes) with an
// error: as writeError, but with no ETag, since the revision of the state is
// for the callers that may read it.
func (h *handler) refuse(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, errorBody{Error: code, Detail: h.redact(detail)})
}

// refuseErr is refuse for an error of the backend or the store.
func (h *handler) refuseErr(w http.ResponseWriter, err error) {
	status, code, detail := classify(err)
	h.refuse(w, status, code, detail)
}

// tooMany answers a caller that the Limiter turned away: 429, and Retry-After
// in whole seconds, rounded up, so that a caller that waits that long is let
// in.
func (h *handler) tooMany(w http.ResponseWriter, wait time.Duration) {
	secs := max(int64((wait+time.Second-1)/time.Second), 1)
	w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
	h.refuse(w, http.StatusTooManyRequests, codeRateLimited, "too many failed attempts from this address: try again later")
}

// forbid answers a caller whose credential may not do this.
func (h *handler) forbid(w http.ResponseWriter, detail string) {
	h.writeError(w, http.StatusForbidden, codeForbidden, detail)
}

// --- the public routes

func (h *handler) authState(w http.ResponseWriter, r *http.Request) {
	_, signedIn := h.authenticate(r)
	writeJSON(w, http.StatusOK, authStateResponse{SetupRequired: h.a.NeedsSetup(), SignedIn: signedIn})
}

// startSession answers a setup or a sign-in that made a session: its cookie,
// and the token its changes carry. They are the one answer in which a session's
// secrets are shown, to the caller that made it.
func (h *handler) startSession(w http.ResponseWriter, s auth.Session) {
	startSessionCookie(w, s.ID)
	writeJSON(w, http.StatusOK, sessionResponse{CSRFToken: s.CSRF, Expires: s.Expires})
}

// setup makes the admin with the setup code, and signs it in.
//
// The Limiter is asked before anything is read or hashed, so that a caller it
// turns away costs nothing. What it lets in counts against the caller when
// its code was wrong, and when it ended in a way that is not known: the paths
// that are no failed attempt (a body that is no good, a claim that comes too
// late, a name or a password that breaks a rule, a success) say so with
// failed = false, and done is deferred, so that it is called once, whichever
// way the handler leaves.
func (h *handler) setup(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	done, ok, wait := h.lim.Allow(limiterKey(ip))
	if !ok {
		h.tooMany(w, wait)
		return
	}
	failed := true // unless a path below says it was no failed attempt
	defer func() { done(failed) }()

	var in setupRequest
	if problem := decodeBody(r, &in); problem != "" {
		failed = false
		h.refuse(w, http.StatusBadRequest, codeBadRequest, problem)
		return
	}
	err := h.a.Claim(r.Context(), in.Code, in.Username, in.Password)
	switch {
	case err == nil, errors.Is(err, auth.ErrAlreadyClaimed), errors.Is(err, auth.ErrInvalid):
		// Not a code that was wrong: a claim, one that was late, or one that
		// broke a rule of the username or the password.
		failed = false
	}
	if err != nil {
		h.refuseErr(w, err)
		return
	}
	h.record("setup completed: admin %s created from %s", quoteName(in.Username), ipText(ip))
	// The password was just checked and saved: this is the same one, and not
	// a guess for the Limiter to count.
	s, err := h.a.SignIn(r.Context(), in.Username, in.Password)
	if err != nil {
		h.refuseErr(w, err)
		return
	}
	h.startSession(w, s)
}

// login starts a session when the password is the admin's. A name that is not
// the admin's gets the answer and the time of a wrong password, and nothing
// here decides it sooner: the store does (auth.Store.SignIn).
func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	done, ok, wait := h.lim.Allow(limiterKey(ip))
	if !ok {
		h.tooMany(w, wait)
		return
	}
	failed := true // as in setup: a password that is wrong, or an end that is not known
	defer func() { done(failed) }()

	var in loginRequest
	if problem := decodeBody(r, &in); problem != "" {
		failed = false
		h.refuse(w, http.StatusBadRequest, codeBadRequest, problem)
		return
	}
	s, err := h.a.SignIn(r.Context(), in.Username, in.Password)
	switch {
	case err == nil:
		failed = false
		h.record("signed in: %s from %s", quoteName(in.Username), ipText(ip))
	case errors.Is(err, auth.ErrBadCredentials):
		h.record("sign-in failed: %s from %s", quoteName(in.Username), ipText(ip))
	}
	if err != nil {
		h.refuseErr(w, err)
		return
	}
	h.startSession(w, s)
}

// --- the session routes

// session answers a signed-in browser with who it is and its CSRF token, so
// that a page that has lost it (it was reloaded) can send it again. A bearer
// has no session.
func (h *handler) session(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if c.who != bySession {
		h.forbid(w, "this needs a signed-in session, which a token is not")
		return
	}
	_, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, whoamiResponse{Username: h.a.Username(), CSRFToken: c.session.CSRF, Expires: c.session.Expires})
}

// logout ends the session of the request and drops its cookie.
func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if c.who != bySession {
		h.forbid(w, "this needs a signed-in session, which a token is not")
		return
	}
	h.a.SignOut(c.session.ID)
	clearSessionCookie(w)
	h.record("signed out: %s from %s", quoteName(h.a.Username()), ipText(clientIP(r)))
	_, rev := h.b.State()
	h.noContent(w, rev)
}

// password changes the admin's. A session keeps itself and ends the others; a
// token has no session to keep, so every one ends.
func (h *handler) password(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	var in passwordRequest
	if !h.decode(w, r, &in) {
		return
	}
	if h.a.NeedsSetup() {
		h.writeError(w, http.StatusConflict, codeSetupRequired, "there is no admin: set it up first")
		return
	}
	keep := ""
	if c.who == bySession {
		keep = c.session.ID
	}
	if err := h.a.ChangePassword(r.Context(), keep, in.Current, in.New); err != nil {
		h.fail(w, err)
		return
	}
	h.record("password changed from %s", ipText(clientIP(r)))
	_, rev := h.b.State()
	h.noContent(w, rev)
}

// reset removes the admin and every session, and makes a new setup code,
// which only `tikray setup-code` and setup.code show. Only the root token may:
// whoever holds a session or a named token is who a reset is for.
func (h *handler) reset(w http.ResponseWriter, r *http.Request) {
	if callerOf(r).who != byRoot {
		h.forbid(w, "only the root token may reset the admin")
		return
	}
	if err := h.a.Reset(); err != nil {
		h.fail(w, err)
		return
	}
	h.record("admin reset from %s", ipText(clientIP(r)))
	_, rev := h.b.State()
	h.noContent(w, rev)
}

// --- the token routes

func (h *handler) listTokens(w http.ResponseWriter, _ *http.Request) {
	list := h.a.Tokens()
	out := make([]tokenInfo, 0, len(list))
	for _, t := range list {
		out = append(out, newTokenInfo(t))
	}
	_, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, out)
}

// createToken makes a named token, and answers with it: the one time its
// secret is shown.
func (h *handler) createToken(w http.ResponseWriter, r *http.Request) {
	var in newTokenRequest
	if !h.decode(w, r, &in) {
		return
	}
	var expires time.Time
	if in.ExpiresIn != "" {
		d, err := time.ParseDuration(in.ExpiresIn)
		if err != nil {
			// Not the parser's message, which shows what it was given.
			h.writeError(w, http.StatusBadRequest, codeBadRequest, `expires_in must be a duration such as "720h"`)
			return
		}
		expires = h.now().Add(d)
	}
	info, token, err := h.a.CreateToken(in.Name, expires)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.record("API token %s (%s) created", quoteName(info.Name), info.ID)
	w.Header().Set("Location", "/v1/tokens")
	_, rev := h.b.State()
	h.reply(w, http.StatusCreated, rev, newTokenResponse{Token: token, Info: newTokenInfo(info)})
}

// revokeToken removes the token of the path's id.
func (h *handler) revokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var name string
	for _, t := range h.a.Tokens() {
		if t.ID == id {
			name = t.Name
		}
	}
	if err := h.a.RevokeToken(id); err != nil {
		h.fail(w, err)
		return
	}
	h.record("API token %s (%s) revoked", quoteName(name), id)
	_, rev := h.b.State()
	h.noContent(w, rev)
}
