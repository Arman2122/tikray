package runner

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

const (
	// maxRequestBody bounds what the server reads from a caller; the largest
	// request is the argument list of xray api.
	maxRequestBody = 64 << 10
	// maxTestBody bounds the config of POST /v1/test instead.
	maxTestBody = 1 << 20
	// xrayAPITimeout bounds one xray api call.
	xrayAPITimeout = 10 * time.Second
)

// server is the runner's control API.
type server struct {
	r       *Runner
	token   string
	xrayAPI func(ctx context.Context, args []string) runnerapi.XrayAPIResponse
}

// errResponse is the JSON error body that runnerapi.Client decodes.
type errResponse struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// NewServer returns the runner's control API, the routes documented in package
// runnerapi. Every request needs "Authorization: Bearer <token>", and an empty
// token admits nobody. xrayAPI runs "xray api <args>" with the running core;
// the server calls it only while an xray runs, with a context that ends after
// 10 s, and reports its result whatever the exit code.
func NewServer(r *Runner, token string, xrayAPI func(ctx context.Context, args []string) runnerapi.XrayAPIResponse) http.Handler {
	s := &server{r: r, token: token, xrayAPI: xrayAPI}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("POST /v1/trial", act(r.Trial))
	mux.HandleFunc("POST /v1/commit", act(func(context.Context) error { return r.Commit() }))
	mux.HandleFunc("POST /v1/abort", act(func(context.Context) error { return r.Abort() }))
	mux.HandleFunc("POST /v1/restart", act(r.Restart))
	mux.HandleFunc("POST /v1/reload", act(r.Reload))
	mux.HandleFunc("POST /v1/xray-api", s.xrayAPIRoute)
	mux.HandleFunc("POST /v1/test", s.test)
	return s.authenticated(mux)
}

// authenticated answers 401 unless the request carries the token. It sits in
// front of the mux, so a caller without the token learns nothing about routes.
func (s *server) authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !s.authorized(req) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthorized", "")
			return
		}
		limit := int64(maxRequestBody)
		if req.URL.Path == "/v1/test" {
			limit = maxTestBody
		}
		req.Body = http.MaxBytesReader(w, req.Body, limit)
		next.ServeHTTP(w, req)
	})
}

func (s *server) authorized(req *http.Request) bool {
	const scheme = "Bearer "
	h := req.Header.Get("Authorization")
	if s.token == "" || len(h) < len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h[len(scheme):]), []byte(s.token)) == 1
}

func (s *server) status(w http.ResponseWriter, _ *http.Request) {
	reply(w, http.StatusOK, s.r.Status())
}

// act serves a route that answers 204 when fn succeeds. fn gets the request's
// context, so a caller that hangs up cancels what has not started yet.
func act(fn func(context.Context) error) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if err := fn(req.Context()); err != nil {
			writeFailure(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *server) xrayAPIRoute(w http.ResponseWriter, req *http.Request) {
	var in runnerapi.XrayAPIRequest
	if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusBadRequest, "bad_request", "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return
	}
	if len(in.Args) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "args is empty")
		return
	}
	if _, ok := s.r.RunningBinary(); !ok {
		writeError(w, http.StatusServiceUnavailable, "no_xray", "no xray is running")
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), xrayAPITimeout)
	defer cancel()
	reply(w, http.StatusOK, s.xrayAPI(ctx, in.Args))
}

// test serves POST /v1/test: the body is the config to test, see
// Runner.TestConfig.
func (s *server) test(w http.ResponseWriter, req *http.Request) {
	config, err := io.ReadAll(req.Body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "the config is over 1 MiB")
			return
		}
		writeError(w, http.StatusBadRequest, "bad_request", "reading the body: "+err.Error())
		return
	}
	if !json.Valid(config) {
		writeError(w, http.StatusBadRequest, "bad_request", "the body is not a JSON value")
		return
	}
	res, err := s.r.TestConfig(req.Context(), config)
	if err != nil {
		writeFailure(w, err)
		return
	}
	reply(w, http.StatusOK, res)
}

// writeFailure maps an error from the runner to its status code.
func writeFailure(w http.ResponseWriter, err error) {
	var tf *runnerapi.TestFailedError
	switch {
	case errors.As(err, &tf):
		writeError(w, http.StatusUnprocessableEntity, "test_failed", tf.Output)
	case errors.Is(err, ErrInvalidCandidate):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, runnerapi.ErrBusy):
		writeError(w, http.StatusConflict, "busy", "")
	case errors.Is(err, runnerapi.ErrNoTrial):
		writeError(w, http.StatusConflict, "no_trial", "")
	case errors.Is(err, runnerapi.ErrNoCore):
		writeError(w, http.StatusConflict, "no_core", "")
	default:
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
	}
}

func writeError(w http.ResponseWriter, status int, code, detail string) {
	reply(w, status, errResponse{Error: code, Detail: detail})
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// A write fails only when the caller has gone, and nobody is left to tell.
	_ = json.NewEncoder(w).Encode(v)
}
