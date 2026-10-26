package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
)

// The codes of an error body, with the status each goes with.
const (
	codeBadRequest        = "bad_request"        // 400
	codeUnauthorized      = "unauthorized"       // 401
	codeNotFound          = "not_found"          // 404
	codeConflict          = "conflict"           // 409: the revision is not the current one
	codeBusy              = "busy"               // 409: another update holds the lock
	codeRefused           = "refused"            // 422
	codeFetchFailed       = "fetch_failed"       // 502
	codeRunnerUnavailable = "runner_unavailable" // 503
	codeUnavailable       = "unavailable"        // 503: the request ended before the work did
	codeInternal          = "internal"           // 500
)

// errorBody is the JSON body of every error: a code for a program, and the
// detail for a person. The detail is redacted when it is written. Result is
// how an apply, an update or a rollback ended when it failed with an outcome,
// its Detail redacted too: the result the direct path would print.
type errorBody struct {
	Error  string            `json:"error"`
	Detail string            `json:"detail,omitempty"`
	Result *artifacts.Result `json:"result,omitempty"`
}

// classify maps an error from the backend to a status, a code and the
// detail. The detail is the error's own text, not yet redacted, apart from a
// request that ended, whose error says nothing the caller needs. It is never
// the output field of a runnerapi.TestFailedError, which unwrapping reaches
// raw: err.Error() has been through the service's redactor, and the handler
// redacts again.
//
// The order matters: ErrRunnerUnavailable and ErrFetchFailed wrap the
// timeout or the cancellation that caused them.
func classify(err error) (status int, code, detail string) {
	var refused *service.Refused
	switch {
	case errors.As(err, &refused):
		return http.StatusUnprocessableEntity, codeRefused, refused.Reason
	case errors.Is(err, service.ErrNotFound):
		return http.StatusNotFound, codeNotFound, err.Error()
	case errors.Is(err, store.ErrConflict):
		return http.StatusConflict, codeConflict, err.Error()
	case errors.Is(err, artifacts.ErrLocked), errors.Is(err, runnerapi.ErrBusy):
		return http.StatusConflict, codeBusy, err.Error()
	case errors.Is(err, service.ErrRunnerUnavailable):
		return http.StatusServiceUnavailable, codeRunnerUnavailable, err.Error()
	case errors.Is(err, service.ErrFetchFailed):
		return http.StatusBadGateway, codeFetchFailed, err.Error()
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return http.StatusServiceUnavailable, codeUnavailable, "the request was cancelled or timed out"
	}
	return http.StatusInternalServerError, codeInternal, err.Error()
}
