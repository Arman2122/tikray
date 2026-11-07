// Package api serves the tikray service over HTTPS: the servers,
// subscriptions, devices, policy, routing, DNS and health settings, the
// apply, the xray-core update and rollback, and the status and the events,
// and who may call them: the admin signing in, and named API tokens.
//
// A request is authenticated by the first of these that holds, and is 401
// when none does (auth.go): the root token (Authorization: Bearer <token>,
// the one in state/api.token), a named API token (Authorization: Bearer
// tkr_...), or the session cookie of a signed-in admin. The routes without a
// credential are GET /healthz, GET /v1/auth/state, and the two that start a
// session, POST /v1/auth/setup and POST /v1/auth/login, which a Limiter holds
// to a few failures by client address. A request made with a cookie that
// changes anything must carry X-Tikray-CSRF.
//
// Bodies are JSON, with snake_case names like the store's. Every response to
// an authenticated request, an error included, carries ETag: "<revision>": the
// revision of the state as it is, or the new one after a change. A change
// honours If-Match: "<revision>" and fails with 409 conflict when the state
// has moved on; without the header it is made on the state as it is. The
// routes that do not change the state on a revision a caller read (apply, core
// update and rollback, refresh) take none and ignore the header, and run
// detached from the request: a caller that disconnects does not stop them,
// and the end of Serve does.
//
// An error is {"error": code, "detail": text}, the text redacted of every
// secret of the state. An apply, an update or a rollback that failed with an
// outcome adds "result": the artifacts.Result, its detail redacted. No
// credential is ever in a body, nor in an event, but where it is handed to
// its owner (a session's own CSRF token, a new API token), and nothing here
// logs a request. Every response carries headers that keep a browser from
// treating it as a page, and from keeping it.
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/auth"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
)

// maxBody is the largest request body.
const maxBody = 1 << 20

// Backend is what the handlers call. *service.Service implements it; the
// tests use a fake.
type Backend interface {
	State() (store.State, uint64)
	Status(ctx context.Context) service.Status
	Events(after uint64) []service.Event
	Core(ctx context.Context) (service.CoreInfo, error)
	ApplyNow(ctx context.Context) (artifacts.Result, error)
	CoreUpdate(ctx context.Context, version string, o artifacts.UpdateOptions) (artifacts.Result, error)
	CoreRollback(ctx context.Context) (artifacts.Result, error)
	// Redactor returns the function that hides the state's secrets in a text.
	Redactor() func(string) string
	// Record keeps an event of kind with msg, as the service's own are: the
	// API's way to log who signed in, a password changed, a token made.
	Record(kind, msg string)

	AddServer(ctx context.Context, rev uint64, n service.NewServer) (store.Server, uint64, error)
	UpdateServer(ctx context.Context, rev uint64, id string, p service.ServerPatch) (store.Server, uint64, error)
	RemoveServer(ctx context.Context, rev uint64, id string) (uint64, error)

	AddSubscription(ctx context.Context, rev uint64, n service.NewSubscription) (store.Subscription, uint64, error)
	UpdateSubscription(ctx context.Context, rev uint64, id string, p service.SubscriptionPatch) (store.Subscription, uint64, error)
	RemoveSubscription(ctx context.Context, rev uint64, id string) (uint64, error)
	RefreshSubscription(ctx context.Context, id string) (service.RefreshResult, error)

	SetDevice(ctx context.Context, rev uint64, d store.Device) (uint64, error)
	RemoveDevice(ctx context.Context, rev uint64, addr netip.Prefix) (uint64, error)
	RepairNetwork(ctx context.Context, rev uint64, fix service.NetworkRepair) (bool, uint64, error)
	SetDefaultPolicy(ctx context.Context, rev uint64, p store.Policy) (uint64, error)
	SetRouting(ctx context.Context, rev uint64, r store.Routing) (uint64, error)
	SetDNS(ctx context.Context, rev uint64, d store.DNS) (uint64, error)
	SetHealth(ctx context.Context, rev uint64, h store.Health) (uint64, error)
}

type handler struct {
	b   Backend
	a   *auth.Store
	lim *auth.Limiter
	// root is the SHA-256 of the root token, and hasRoot says there is one:
	// an empty token admits nobody.
	root    [sha256.Size]byte
	rootLen int
	hasRoot bool
	now     func() time.Time
}

// NewHandler returns the API over b, for the callers that auth.go lets in:
// the root token root (an empty one admits nobody), a named token or a
// session of a, and the sign-in routes held to lim (neither may be nil). The
// check sits in front of the routes, so that a caller without a credential
// learns nothing about them.
func NewHandler(b Backend, root string, a *auth.Store, lim *auth.Limiter) http.Handler {
	h := &handler{b: b, a: a, lim: lim, root: sha256.Sum256([]byte(root)), rootLen: len(root), hasRoot: root != "", now: time.Now}
	mux := http.NewServeMux()
	// The routes that need no credential, by their pattern: the one list. A
	// request is public when the pattern the mux matches it to is on it, so
	// that no way of spelling a path makes a public route of another (guard).
	public := map[string]bool{}
	handlePublic := func(pattern string, f http.HandlerFunc) {
		public[pattern] = true
		mux.HandleFunc(pattern, f)
	}
	handlePublic("GET /healthz", healthz)

	mux.HandleFunc("GET /v1/status", h.status)
	mux.HandleFunc("GET /v1/state", h.state)
	mux.HandleFunc("GET /v1/events", h.events)

	mux.HandleFunc("GET /v1/servers", h.listServers)
	mux.HandleFunc("POST /v1/servers", h.addServer)
	mux.HandleFunc("PATCH /v1/servers/{id}", h.patchServer)
	mux.HandleFunc("DELETE /v1/servers/{id}", remove(h, b.RemoveServer))

	mux.HandleFunc("GET /v1/subscriptions", h.listSubscriptions)
	mux.HandleFunc("POST /v1/subscriptions", h.addSubscription)
	mux.HandleFunc("PATCH /v1/subscriptions/{id}", h.patchSubscription)
	mux.HandleFunc("DELETE /v1/subscriptions/{id}", remove(h, b.RemoveSubscription))
	mux.HandleFunc("POST /v1/subscriptions/{id}/refresh", h.refreshSubscription)

	mux.HandleFunc("GET /v1/devices", h.listDevices)
	mux.HandleFunc("PUT /v1/devices/{address}", h.setDevice)
	mux.HandleFunc("DELETE /v1/devices/{address}", h.removeDevice)
	mux.HandleFunc("PUT /v1/network", h.repairNetwork)

	mux.HandleFunc("PUT /v1/policy", set(h, b.SetDefaultPolicy))
	mux.HandleFunc("PUT /v1/routing", set(h, b.SetRouting))
	mux.HandleFunc("PUT /v1/dns", set(h, b.SetDNS))
	mux.HandleFunc("GET /v1/health", h.getHealth)
	mux.HandleFunc("PUT /v1/health", set(h, b.SetHealth))

	mux.HandleFunc("POST /v1/apply", h.apply)
	mux.HandleFunc("POST /v1/core/update", h.coreUpdate)
	mux.HandleFunc("POST /v1/core/rollback", h.coreRollback)
	mux.HandleFunc("GET /v1/core", h.core)

	// Who may call them (auth.go). The state of the sign-in, setup and login
	// are public.
	handlePublic("GET /v1/auth/state", h.authState)
	handlePublic("POST /v1/auth/setup", h.setup)
	handlePublic("POST /v1/auth/login", h.login)
	mux.HandleFunc("GET /v1/auth/session", h.session)
	mux.HandleFunc("POST /v1/auth/logout", h.logout)
	mux.HandleFunc("PUT /v1/auth/password", h.password)
	mux.HandleFunc("POST /v1/auth/reset", h.reset)
	mux.HandleFunc("GET /v1/tokens", h.listTokens)
	mux.HandleFunc("POST /v1/tokens", h.createToken)
	mux.HandleFunc("DELETE /v1/tokens/{id}", h.revokeToken)

	// What the ServeMux would answer in plain text, in JSON. A wrong method
	// on a route lands here too.
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		h.writeError(w, http.StatusNotFound, codeNotFound, "no such route")
	})
	return h.guard(mux, public)
}

// healthz answers that the service runs: the handler exists only once it does.
func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- reads

func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	st := h.b.Status(r.Context())
	h.reply(w, http.StatusOK, st.Revision, st)
}

// state returns the editable settings and public server metadata.
func (h *handler) state(w http.ResponseWriter, _ *http.Request) {
	st, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, h.visibleState(st))
}

func (h *handler) events(w http.ResponseWriter, r *http.Request) {
	var after uint64
	if v := r.URL.Query().Get("after"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, codeBadRequest, "after must be a whole number, 0 or more")
			return
		}
		after = n
	}
	evs := orEmpty(h.b.Events(after))
	_, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, evs)
}

func (h *handler) listServers(w http.ResponseWriter, _ *http.Request) {
	st, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, h.visibleServers(st, service.RedactorFor(st)))
}

func (h *handler) listSubscriptions(w http.ResponseWriter, _ *http.Request) {
	st, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, h.visibleSubscriptions(st, service.RedactorFor(st)))
}

func (h *handler) listDevices(w http.ResponseWriter, _ *http.Request) {
	st, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, h.visibleDevices(st, service.RedactorFor(st)))
}

// getHealth answers with the settings of the connectivity probe. The
// snapshot of what it saw is in the status.
func (h *handler) getHealth(w http.ResponseWriter, _ *http.Request) {
	st, rev := h.b.State()
	st.Health.ProbeURL = h.publicURL(st.Health.ProbeURL, service.RedactorFor(st))
	h.reply(w, http.StatusOK, rev, st.Health)
}

func (h *handler) core(w http.ResponseWriter, r *http.Request) {
	info, err := h.b.Core(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	_, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, newCoreResponse(info, h.redact))
}

// --- servers

func (h *handler) addServer(w http.ResponseWriter, r *http.Request) {
	rev, ok := h.revision(w, r)
	if !ok {
		return
	}
	var in newServerRequest
	if !h.decode(w, r, &in) || h.maskedRequest(w, in.Name) {
		return
	}
	srv, newRev, err := h.b.AddServer(r.Context(), rev, service.NewServer{Link: in.Link, Name: in.Name, Outbound: present(in.Outbound)})
	if err != nil {
		h.fail(w, err)
		return
	}
	// The collection, where a GET finds it: no route reads one server alone.
	w.Header().Set("Location", "/v1/servers")
	st, _ := h.b.State()
	st.Servers = append(st.Servers, srv)
	h.reply(w, http.StatusCreated, newRev, h.visibleServer(srv, service.RedactorFor(st)))
}

func (h *handler) patchServer(w http.ResponseWriter, r *http.Request) {
	rev, ok := h.revision(w, r)
	if !ok {
		return
	}
	var in serverPatchRequest
	if !h.decode(w, r, &in) || h.maskedRequest(w, in.Name) {
		return
	}
	patch := service.ServerPatch{Name: in.Name, Disabled: in.Disabled, Link: in.Link, Outbound: present(in.Outbound)}
	srv, newRev, err := h.b.UpdateServer(r.Context(), rev, r.PathValue("id"), patch)
	if err != nil {
		h.fail(w, err)
		return
	}
	st, _ := h.b.State()
	st.Servers = append(st.Servers, srv)
	h.reply(w, http.StatusOK, newRev, h.visibleServer(srv, service.RedactorFor(st)))
}

// --- subscriptions

func (h *handler) addSubscription(w http.ResponseWriter, r *http.Request) {
	rev, ok := h.revision(w, r)
	if !ok {
		return
	}
	var in newSubscriptionRequest
	if !h.decode(w, r, &in) || h.maskedRequest(w, in.Name) {
		return
	}
	sub, newRev, err := h.b.AddSubscription(r.Context(), rev, service.NewSubscription{Name: in.Name, URL: in.URL, Interval: in.Interval})
	if err != nil {
		h.fail(w, err)
		return
	}
	// The collection, as for a server.
	w.Header().Set("Location", "/v1/subscriptions")
	st, _ := h.b.State()
	st.Subscriptions = append(st.Subscriptions, sub)
	h.reply(w, http.StatusCreated, newRev, h.visibleSub(sub, service.RedactorFor(st)))
}

func (h *handler) patchSubscription(w http.ResponseWriter, r *http.Request) {
	rev, ok := h.revision(w, r)
	if !ok {
		return
	}
	var in subscriptionPatchRequest
	if !h.decode(w, r, &in) || h.maskedRequest(w, in.Name) {
		return
	}
	patch := service.SubscriptionPatch{Name: in.Name, URL: in.URL, Disabled: in.Disabled, Interval: in.Interval}
	sub, newRev, err := h.b.UpdateSubscription(r.Context(), rev, r.PathValue("id"), patch)
	if err != nil {
		h.fail(w, err)
		return
	}
	st, _ := h.b.State()
	st.Subscriptions = append(st.Subscriptions, sub)
	h.reply(w, http.StatusOK, newRev, h.visibleSub(sub, service.RedactorFor(st)))
}

// detached is the context of an operation that must run to its end whether
// or not the caller waits: an apply, an update or a rollback has a trial open
// on the router, and a caller that is interrupted would stop it half way. It
// has the request's values and none of its cancellation. It ends with the
// server that serves the request (ServeListener's ctx, which is tikray
// serve's lifetime), so that the updater aborts the trial in the shutdown's
// time rather than die with the process, and otherwise when the updater's
// deadlines say. done releases it once the operation has returned.
func detached(r *http.Request) (ctx context.Context, done func()) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
	if life, ok := r.Context().Value(lifetimeKey{}).(context.Context); ok {
		unhook := context.AfterFunc(life, cancel)
		return ctx, func() { unhook(); cancel() }
	}
	return ctx, cancel
}

// refreshSubscription fetches the subscription now, detached from the
// request. It is no change a caller makes on a revision: the refresh merges
// into the state as it is.
func (h *handler) refreshSubscription(w http.ResponseWriter, r *http.Request) {
	ctx, done := detached(r)
	defer done()
	res, err := h.b.RefreshSubscription(ctx, r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	_, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, newRefreshResponse(res, h.redact))
}

// --- devices

// setDevice adds the device at the address in the path or replaces it. The
// body may leave its address out; if it names one, it is the path's.
func (h *handler) setDevice(w http.ResponseWriter, r *http.Request) {
	addr, ok := h.address(w, r)
	if !ok {
		return
	}
	rev, ok := h.revision(w, r)
	if !ok {
		return
	}
	var d store.Device
	if !h.decode(w, r, &d) || h.maskedRequest(w, d) {
		return
	}
	if d.Address.IsValid() && d.Address != addr {
		h.writeError(w, http.StatusBadRequest, codeBadRequest, "the address in the body is not the one in the path")
		return
	}
	d.Address = addr
	newRev, err := h.b.SetDevice(r.Context(), rev, d)
	if err != nil {
		h.fail(w, err)
		return
	}
	d.Name = h.shown(d.Name, h.redact, callerOf(r).session)
	h.reply(w, http.StatusOK, newRev, d)
}

func (h *handler) removeDevice(w http.ResponseWriter, r *http.Request) {
	addr, ok := h.address(w, r)
	if !ok {
		return
	}
	rev, ok := h.revision(w, r)
	if !ok {
		return
	}
	newRev, err := h.b.RemoveDevice(r.Context(), rev, addr)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.noContent(w, newRev)
}

// repairNetwork accepts only a complete fix of a previously permitted overlap.
func (h *handler) repairNetwork(w http.ResponseWriter, r *http.Request) {
	rev, ok := h.revision(w, r)
	if !ok {
		return
	}
	var fix service.NetworkRepair
	if !h.decode(w, r, &fix) || h.maskedRequest(w, fix) {
		return
	}
	restart, next, err := h.b.RepairNetwork(r.Context(), rev, fix)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.reply(w, http.StatusOK, next, struct {
		RestartRequired bool `json:"restart_required"`
	}{restart})
}

// address reads the device address of the path: a CIDR prefix (its slash
// escaped as %2F, which the ServeMux has unescaped in PathValue) or a bare
// IP, which is that address alone.
func (h *handler) address(w http.ResponseWriter, r *http.Request) (netip.Prefix, bool) {
	s := r.PathValue("address")
	var p netip.Prefix
	var err error
	if strings.Contains(s, "/") {
		p, err = netip.ParsePrefix(s)
	} else {
		var a netip.Addr
		if a, err = netip.ParseAddr(s); err == nil {
			p = netip.PrefixFrom(a, a.BitLen())
		}
	}
	if err != nil || !p.IsValid() {
		h.writeError(w, http.StatusBadRequest, codeBadRequest, "the device address must be an IP or a CIDR prefix, such as 192.168.88.10 or 192.168.88.0%2F24")
		return netip.Prefix{}, false
	}
	return p, true
}

// --- settings

// set serves a PUT that replaces one of the state's settings with its body.
func set[T any](h *handler, do func(ctx context.Context, rev uint64, v T) (uint64, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rev, ok := h.revision(w, r)
		if !ok {
			return
		}
		var v T
		if !h.decode(w, r, &v) || h.maskedRequest(w, v) {
			return
		}
		newRev, err := do(r.Context(), rev, v)
		if err != nil {
			h.fail(w, err)
			return
		}
		switch settings := any(v).(type) {
		case store.Routing:
			h.reply(w, http.StatusOK, newRev, h.visibleRouting(settings, h.redact))
		case store.Health:
			settings.ProbeURL = h.publicURL(settings.ProbeURL, h.redact)
			h.reply(w, http.StatusOK, newRev, settings)
		case store.DNS:
			settings.Remote = h.publicURL(settings.Remote, h.redact)
			h.reply(w, http.StatusOK, newRev, settings)
		default:
			h.reply(w, http.StatusOK, newRev, v)
		}
	}
}

// remove serves a DELETE of the server or the subscription of the path's id.
func remove(h *handler, do func(ctx context.Context, rev uint64, id string) (uint64, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rev, ok := h.revision(w, r)
		if !ok {
			return
		}
		newRev, err := do(r.Context(), rev, r.PathValue("id"))
		if err != nil {
			h.fail(w, err)
			return
		}
		h.noContent(w, newRev)
	}
}

// --- the operations on the core

func (h *handler) apply(w http.ResponseWriter, r *http.Request) {
	ctx, done := detached(r)
	defer done()
	res, err := h.b.ApplyNow(ctx)
	h.outcome(w, res, err)
}

func (h *handler) coreUpdate(w http.ResponseWriter, r *http.Request) {
	var in coreUpdateRequest
	if !h.decode(w, r, &in) {
		return
	}
	if in.Version == "" {
		h.writeError(w, http.StatusBadRequest, codeBadRequest, `version is required: "latest" or a release such as "26.10.21"`)
		return
	}
	ctx, done := detached(r)
	defer done()
	res, err := h.b.CoreUpdate(ctx, in.Version, artifacts.UpdateOptions{AllowUnverified: in.AllowUnverified})
	h.outcome(w, res, err)
}

func (h *handler) coreRollback(w http.ResponseWriter, r *http.Request) {
	ctx, done := detached(r)
	defer done()
	res, err := h.b.CoreRollback(ctx)
	h.outcome(w, res, err)
}

// outcome answers for an apply, an update or a rollback: the result when it
// committed (or found nothing to do), else the error. A result that ended in
// another outcome, such as a config that xray rejected, comes back with an
// error that has no other class: it is for the person to fix, not a fault of
// the service, so it is 422 refused and not 500. An error that comes with an
// outcome carries the result in its body, so that the client can report how
// the operation ended, as the direct path does.
func (h *handler) outcome(w http.ResponseWriter, res artifacts.Result, err error) {
	if err != nil {
		status, code, detail := classify(err)
		if code == codeInternal && res.Outcome != "" {
			status, code = http.StatusUnprocessableEntity, codeRefused
		}
		body := errorBody{Error: code, Detail: h.redact(detail)}
		if res.Outcome != "" {
			r := redactResult(res, h.redact)
			body.Result = &r
		}
		_, rev := h.b.State()
		h.reply(w, status, rev, body)
		return
	}
	_, rev := h.b.State()
	h.reply(w, http.StatusOK, rev, redactResult(res, h.redact))
}

// --- requests

// revision reads the If-Match header: the revision a change is made on, or
// store.AnyRevision when there is none. A header that is there must hold one
// revision in quotes.
func (h *handler) revision(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	vals, ok := r.Header["If-Match"]
	if !ok {
		return store.AnyRevision, true
	}
	if len(vals) == 1 {
		if v := vals[0]; len(v) > 2 && v[0] == '"' && v[len(v)-1] == '"' {
			if n, err := strconv.ParseUint(v[1:len(v)-1], 10, 64); err == nil && n != store.AnyRevision {
				return n, true
			}
		}
	}
	// The detail does not repeat the header.
	h.writeError(w, http.StatusBadRequest, codeBadRequest, `If-Match must hold one revision in quotes, such as "7"`)
	return 0, false
}

var errTrailing = errors.New("the request body holds more than one JSON value")

// decode reads the body into v as one JSON value, in which a field v does not
// have is an error. It answers 400 itself when the body is no good.
func (h *handler) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if problem := decodeBody(r, v); problem != "" {
		h.writeError(w, http.StatusBadRequest, codeBadRequest, problem)
		return false
	}
	return true
}

// decodeBody is decode without the answer: it returns what is wrong with the
// body, for the person who sent it, or "" when v has been read from it. The
// routes that have no credential to show for it answer with refuse.
func decodeBody(r *http.Request, v any) (problem string) {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		// Only space may follow.
		if _, terr := dec.Token(); terr != io.EOF {
			err = errTrailing
			if isTooBig(terr) {
				err = terr
			}
		}
	}
	if err == nil {
		return ""
	}
	return bodyProblem(err)
}

func isTooBig(err error) bool {
	var tooBig *http.MaxBytesError
	return errors.As(err, &tooBig)
}

// bodyProblem says what is wrong with a body, for the person who sent it.
func bodyProblem(err error) string {
	var syntax *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case isTooBig(err):
		return "the request body is over 1 MiB"
	case errors.Is(err, io.EOF):
		return "the request body is empty"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.As(err, &syntax):
		return "the request body is not valid JSON"
	case errors.Is(err, errTrailing):
		return err.Error()
	case errors.As(err, &typ):
		return "the request body has a field of the wrong type: " + typ.Field
	}
	// An unknown field, or a value its type refuses, such as a bad interval.
	if strings.HasPrefix(err.Error(), "json: unknown field ") {
		return "the request body contains an unknown field"
	}
	return "the request body contains an invalid value"
}

// --- responses

// reply answers with v as JSON, and the revision as the ETag.
func (h *handler) reply(w http.ResponseWriter, status int, rev uint64, v any) {
	w.Header().Set("ETag", etag(rev))
	writeJSON(w, status, v)
}

// noContent answers a change that has nothing to return but its revision.
func (h *handler) noContent(w http.ResponseWriter, rev uint64) {
	w.Header().Set("ETag", etag(rev))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// fail answers with the error as classify maps it.
func (h *handler) fail(w http.ResponseWriter, err error) {
	status, code, detail := classify(err)
	h.writeError(w, status, code, detail)
}

// writeError answers with an error body whose detail is redacted. It carries
// the revision as it is now, so that a caller that lost a race can read again.
func (h *handler) writeError(w http.ResponseWriter, status int, code, detail string) {
	_, rev := h.b.State()
	h.reply(w, status, rev, errorBody{Error: code, Detail: h.redact(detail)})
}

// redact hides the secrets of the state in text.
func (h *handler) redact(text string) string {
	if text == "" {
		return ""
	}
	if f := h.b.Redactor(); f != nil {
		return f(text)
	}
	return text
}

func etag(rev uint64) string { return `"` + strconv.FormatUint(rev, 10) + `"` }

// writeJSON answers with v as JSON. A response is not kept: it may hold
// credentials.
func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// Only a raw message that is no JSON gets here; nothing of it is said.
		status = http.StatusInternalServerError
		buf.Reset()
		buf.WriteString(`{"error":"` + codeInternal + `","detail":"the response could not be encoded"}` + "\n")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// A write fails only when the caller has gone, and nobody is left to tell.
	_, _ = w.Write(buf.Bytes())
}
