// Package runnerapi holds the wire types of the runner's control API and the
// HTTP client the control plane uses to call it. The runner serves exactly
// these routes, all behind "Authorization: Bearer <token>":
//
//	GET  /v1/status
//	POST /v1/trial, /v1/commit, /v1/abort, /v1/restart, /v1/reload, /v1/xray-api
//	POST /v1/test (the body is an xray config, at most 1 MiB)
//	POST /v1/adopt (the body is {"config": "config/<64 hex>.json"})
//
// Errors are JSON bodies {"error": "<code>", "detail": "<text>"} with the
// codes busy, no_trial and no_core (409), test_failed (422), too_large (413),
// bad_request, unauthorized and internal (500). Adopt answers 400 bad_request
// for a config name that is invalid or a file that does not exist. A trial or
// test whose xray run -test gave no verdict on the config is a 500 whose
// detail is one of the Fault phrases (see PublicTestError).
package runnerapi

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
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
	return ValidateConfig(s.Config)
}

// ValidateConfig refuses a config name that is not config/<64 lowercase
// hex>.json, the only form Selection.Config takes, so that it can name nothing
// but a content-addressed file under the runner's run directory.
func ValidateConfig(config string) error {
	if !configRE.MatchString(config) {
		return errors.New("runnerapi: invalid config: want config/<64 hex>.json")
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
	State     string     `json:"state"`
	Active    *Selection `json:"active,omitempty"`
	Candidate *Candidate `json:"candidate,omitempty"`
	XrayPID   int        `json:"xray_pid"`
	// XrayInstance identifies this process even when a runner restart reuses
	// its numeric PID. An older runner omits it.
	XrayInstance string       `json:"xray_instance,omitempty"`
	XrayVersion  string       `json:"xray_version,omitempty"`
	RoutesOK     bool         `json:"routes_ok"`
	GatewayUp    bool         `json:"gateway_up"`
	LastTrial    *TrialResult `json:"last_trial,omitempty"`
}

// XrayAPIRequest is the body of POST /v1/xray-api: arguments for "xray api".
type XrayAPIRequest struct {
	Args []string `json:"args"`
}

// AdoptRequest is the body of POST /v1/adopt: the config, in the form of
// Selection.Config, that the running xray already runs.
type AdoptRequest struct {
	Config string `json:"config"`
}

// XrayAPIResponse is the result of running "xray api" in the runner.
type XrayAPIResponse struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// MaxTestBody is the largest config accepted by POST /v1/test, in bytes.
const MaxTestBody = 1 << 20

// TestOutputTruncated marks runner output whose final line may be a partial credential.
const TestOutputTruncated = "\n[output truncated]"

// TestResult is the verdict of POST /v1/test and its public diagnostic.
type TestResult struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

// ExitConfigRefused is the status "xray run -test" exits with when it refuses
// the config, after printing "Failed to start: <why>": main/run.go of every
// xray release from 26.1.18 to 26.10.31. A test that ends any other way (with
// another status, by a signal, or not at all) says nothing about the config.
const ExitConfigRefused = 23

// A runner reports a test of a config that ended without xray's verdict as an
// error, never as a refusal, in one of these phrases: the core could not be
// staged, the config could not be written for the test, xray could not be
// started, a signal killed it, it exited with a status other than
// ExitConfigRefused, or it did not finish in time. Only a signal name, an exit
// status, a duration or a TestCause follows the phrase, never xray's output or
// a path, so the client can pass such a text on (PublicTestError).
const (
	FaultStage   = "staging the core failed"
	FaultPrepare = "preparing the test config failed"
	FaultStart   = "xray could not be started"
	FaultKilled  = "xray was killed by a signal"
	FaultExited  = "xray exited with status"
	FaultTimeout = "xray config test did not finish within"
)

// testCauses are the errno texts (Linux's, as syscall.Errno gives them) that a
// runner may name after a fault: the ones a router owner can act on.
var testCauses = []string{
	"no space left on device",
	"disk quota exceeded",
	"read-only file system",
	"input/output error",
	"no such file or directory",
	"permission denied",
	"operation not permitted",
	"cannot allocate memory",
	"too many open files",
	"too many open files in system",
	"exec format error",
	"text file busy",
	"resource temporarily unavailable",
}

// TestCause is the errno text of err when it is one a runner may name after a
// fault, and "" otherwise.
func TestCause(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) && slices.Contains(testCauses, errno.Error()) {
		return errno.Error()
	}
	return ""
}

var testFaultRE = func() *regexp.Regexp {
	causes := make([]string, len(testCauses))
	for i, c := range testCauses {
		causes[i] = regexp.QuoteMeta(c)
	}
	cause := `(?:: (?:` + strings.Join(causes, "|") + `))?`
	return regexp.MustCompile(`^(?:` +
		`(?:` + FaultStage + `|` + FaultPrepare + `|` + FaultStart + `)` + cause +
		`|` + FaultKilled + `(?: \(SIG[A-Z0-9]{2,8}\))?` +
		`|` + FaultExited + ` (?:[1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])` +
		`|` + FaultTimeout + ` (?:the trial's )?(?:[0-9]{1,9}(?:\.[0-9]{1,9})?(?:h|m|s|ms|µs|ns)){1,3}` +
		`)$`)
}()

// PublicTestError reports whether text is a runner's report of a test that
// ended without xray's verdict, in the form the Fault phrases describe. Exit
// status 23 is a verdict and never such a report.
func PublicTestError(text string) bool {
	return testFaultRE.MatchString(text) && text != FaultExited+" "+strconv.Itoa(ExitConfigRefused)
}

// ConfigVerdict is the verdict of a test that xray passed (exitCode 0), with
// fixed words in place of xray's output: even a successful test can print an
// entire raw outbound. For any other exitCode it is how the previous runner
// reported a refusal, which the client still reads; a runner now reports one
// with ConfigRefusal.
func ConfigVerdict(exitCode int) TestResult {
	if exitCode == 0 {
		return TestResult{OK: true, Output: "Configuration OK."}
	}
	return TestResult{Output: fmt.Sprintf("xray failed to load config (exit %d)", exitCode)}
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

// ErrNoToken is what a Client's TokenFunc returns, or wraps, while it has no
// token to give: the runner makes its token when it starts. The call fails
// with it before anything is sent, as a call to a runner that can't be reached
// fails, and its error, which wraps it, carries "runnerapi:" and the route.
var ErrNoToken = errors.New("waiting for the runner token")

// TestFailedError is what Trial returns when "xray run -test" rejects the
// candidate. Output describes the rejection without echoing private configuration.
type TestFailedError struct{ Output string }

func (e *TestFailedError) Error() string {
	return "runnerapi: xray run -test failed: " + e.Output
}
