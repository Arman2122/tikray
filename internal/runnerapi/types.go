// Package runnerapi holds the wire types of the runner's control API and the
// HTTP client the control plane uses to call it. The runner serves exactly
// these routes, all behind "Authorization: Bearer <token>":
//
//	GET  /v1/status
//	POST /v1/trial, /v1/commit, /v1/abort, /v1/restart, /v1/reload, /v1/xray-api
//	POST /v1/test (the body is an xray config, at most 1 MiB)
//
// Errors are JSON bodies {"error": "<code>", "detail": "<text>"} with the
// codes busy, no_trial and no_core (409), test_failed (422), too_large (413),
// bad_request and unauthorized.
package runnerapi

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/xrayver"
)

var (
	geoRE    = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$`)
	configRE = regexp.MustCompile(`^config/[0-9a-f]{64}\.json$`)
)

// Selection names the files xray runs from: a core slot, an optional geo slot
// and a config. The runner resolves each under its own mounts, so every field
// is a plain name, never a path that could leave them.
type Selection struct {
	// Core is a version directory under /data/cores, such as 26.10.21.
	Core string `json:"core"`
	// Geo is a directory under /data/geo. Empty means no geo data.
	Geo string `json:"geo,omitempty"`
	// Config is config/<64 lowercase hex>.json, relative to /data/run.
	Config string `json:"config"`
}

// Validate refuses a selection whose fields could name anything but a slot or
// a content-addressed config.
func (s Selection) Validate() error {
	v, err := xrayver.Parse(s.Core)
	if err != nil || v.String() != s.Core {
		return fmt.Errorf("runnerapi: invalid core %q: want a version such as 26.10.21", s.Core)
	}
	if s.Geo != "" && (!geoRE.MatchString(s.Geo) || strings.Contains(s.Geo, "..")) {
		return fmt.Errorf("runnerapi: invalid geo %q", s.Geo)
	}
	if !configRE.MatchString(s.Config) {
		return fmt.Errorf("runnerapi: invalid config %q: want config/<64 hex>.json", s.Config)
	}
	return nil
}

// Candidate is a selection on trial until Deadline.
type Candidate struct {
	Selection
	Deadline time.Time `json:"deadline"`
}

// Trial outcomes.
const (
	OutcomeCommitted = "committed"
	OutcomeRejected  = "rejected" // xray run -test failed
	OutcomeExited    = "exited"   // the candidate exited during the trial
	OutcomeDeadline  = "deadline"
	OutcomeAborted   = "aborted"
	OutcomeReboot    = "reboot" // the runner started while a trial was open
)

// TrialResult records how the last trial ended.
type TrialResult struct {
	Candidate Candidate `json:"candidate"`
	Outcome   string    `json:"outcome"`
	Detail    string    `json:"detail,omitempty"`
	At        time.Time `json:"at"`
}

// Runner states.
const (
	StateEmpty      = "empty" // no active selection
	StateRunning    = "running"
	StateRestarting = "restarting" // backoff after a crash
	StateTrial      = "trial"
)

// Status is the runner's answer to GET /v1/status.
type Status struct {
	State       string       `json:"state"`
	Active      *Selection   `json:"active,omitempty"`
	Candidate   *Candidate   `json:"candidate,omitempty"`
	XrayPID     int          `json:"xray_pid"`
	XrayVersion string       `json:"xray_version,omitempty"`
	RoutesOK    bool         `json:"routes_ok"`
	GatewayUp   bool         `json:"gateway_up"`
	LastTrial   *TrialResult `json:"last_trial,omitempty"`
}

// XrayAPIRequest is the body of POST /v1/xray-api: arguments for "xray api".
type XrayAPIRequest struct {
	Args []string `json:"args"`
}

// XrayAPIResponse is the result of running "xray api" in the runner.
type XrayAPIResponse struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// TestResult is the answer to POST /v1/test: whether "xray run -test"
// accepted the config, and what xray printed, at most 8 KiB of it.
type TestResult struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

// Errors the runner reports with a 409.
var (
	// ErrBusy means the runner is occupied, for example by an open trial.
	ErrBusy = errors.New("runnerapi: runner is busy")
	// ErrNoTrial means commit or abort found no open trial.
	ErrNoTrial = errors.New("runnerapi: no trial is open")
	// ErrNoCore means a config could not be tested because no xray runs,
	// and so there is no core to test it with.
	ErrNoCore = errors.New("runnerapi: no xray is running to test with")
)

// TestFailedError is what Trial returns when "xray run -test" rejects the
// candidate. Output is what xray printed.
type TestFailedError struct{ Output string }

func (e *TestFailedError) Error() string {
	return "runnerapi: xray run -test failed: " + e.Output
}
