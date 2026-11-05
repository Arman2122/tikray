package runner

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

// Only exit status 23 is xray's verdict on a config (main/run.go). A test
// that ends any other way said nothing about the config: the trial is not
// rejected, nothing is recorded, and the error names the cause in fixed
// words, without xray's output or a path.

// wantTestError checks that a trial or test that ended without a verdict
// came back as a runner error saying want, and not as a refusal.
func wantTestError(t *testing.T, err error, want string) {
	t.Helper()
	var tf *runnerapi.TestFailedError
	switch {
	case err == nil:
		t.Fatalf("got no error; want a runner error saying %q", want)
	case errors.As(err, &tf):
		t.Fatalf("got a config refusal %q; want a runner error saying %q", tf.Output, want)
	case !strings.Contains(err.Error(), want):
		t.Fatalf("error %q; want it to say %q", err, want)
	}
	for _, private := range []string{"partial diagnostic", "fatal error", "/"} {
		if strings.Contains(strings.TrimPrefix(err.Error(), "runnerapi: POST /v1/"), private) {
			t.Errorf("error %q repeats xray's output or a path (%q)", err, private)
		}
	}
}

// An xray run -test that a signal killed (an OOM kill on a small router) is
// not a config refusal.
func TestReviewKilledTrialTestIsReportedAsConfigRefusal(t *testing.T) {
	g := runningRig(t)
	pid := g.r.Status().XrayPID
	g.candidate(t, "killedtest", 10*time.Second)
	a := newAPI(t, g, nil)
	err := a.c.Trial(t.Context())
	wantTestError(t, err, "xray was killed by a signal (SIGKILL)")
	g.wantState(t, runnerapi.StateRunning, oldCore)
	if got := g.r.Status().XrayPID; got != pid {
		t.Errorf("PID %d, want the active xray %d untouched", got, pid)
	}
	g.wantNoLastTrial(t)
	g.wantNoCandidate(t)
}

// A core that cannot be staged is not a config refusal either.
func TestReviewStageFailureIsReportedAsConfigRefusal(t *testing.T) {
	g := runningRig(t)
	cand := g.candidate(t, "ok", 10*time.Second)
	if err := os.Remove(g.d.CoreBinary(cand.Core)); err != nil {
		t.Fatal(err)
	}
	a := newAPI(t, g, nil)
	err := a.c.Trial(t.Context())
	wantTestError(t, err, "staging the core failed: no such file or directory")
	g.wantState(t, runnerapi.StateRunning, oldCore)
	g.wantNoLastTrial(t)
	g.wantNoCandidate(t)
}

// A Go runtime fatal error ends xray with status 2, whatever the config.
func TestTrialTestExit2IsNotARejection(t *testing.T) {
	g := runningRig(t)
	g.candidate(t, "crashtest", 10*time.Second)
	a := newAPI(t, g, nil)
	err := a.c.Trial(t.Context())
	wantTestError(t, err, "xray exited with status 2")
	g.wantState(t, runnerapi.StateRunning, oldCore)
	g.wantNoLastTrial(t)
	g.wantNoCandidate(t)
}

func TestTestConfigExit2IsNotAVerdict(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "crashtest")
	g.boot(t)
	res, err := g.r.TestConfig(t.Context(), []byte(`{}`))
	if res != (runnerapi.TestResult{}) {
		t.Errorf("TestConfig = %+v; want no verdict", res)
	}
	wantTestError(t, err, "xray exited with status 2")

	a := newAPI(t, g, nil)
	res, err = a.c.Test(t.Context(), []byte(`{}`))
	if res != (runnerapi.TestResult{}) {
		t.Errorf("Test = %+v; want no verdict", res)
	}
	wantTestError(t, err, "xray exited with status 2")
	resp, body := send(t, a.url, http.MethodPost, "/v1/test", "Bearer "+testToken, `{}`)
	if resp.StatusCode != http.StatusInternalServerError || !strings.Contains(body, `"detail":"xray exited with status 2"`) {
		t.Errorf("POST /v1/test = %d %s; want 500 with the fixed cause", resp.StatusCode, body)
	}
}

func TestTestConfigKilledIsNotAVerdict(t *testing.T) {
	g := newRig(t, nil)
	g.active(t, "killedtest")
	g.boot(t)
	a := newAPI(t, g, nil)
	res, err := a.c.Test(t.Context(), []byte(`{}`))
	if res != (runnerapi.TestResult{}) {
		t.Errorf("Test = %+v; want no verdict", res)
	}
	wantTestError(t, err, "xray was killed by a signal (SIGKILL)")
}

// The texts name an errno, never the path the error came with.
func TestTestErrorTexts(t *testing.T) {
	stage := &fs.PathError{Op: "write", Path: "/run/xray/26.10.21/.xray.tmp-1", Err: syscall.ENOSPC}
	for _, tc := range []struct {
		name string
		err  *testError
		want string
	}{
		{"stage out of space", stageError(stage), "staging the core failed: no space left on device"},
		{"stage, no errno", stageError(errors.New("/data/cores/x/xray is not a regular file")), "staging the core failed"},
		{"stage, other errno", stageError(&fs.PathError{Op: "open", Path: "/x", Err: syscall.EBADMSG}), "staging the core failed"},
		{"exec", startError(&fs.PathError{Op: "fork/exec", Path: "/run/xray/x/xray", Err: syscall.ENOEXEC}), "xray could not be started: exec format error"},
		{"prepare", prepareError(&fs.PathError{Op: "open", Path: "/run/xray/.test-config-1.json", Err: syscall.EROFS}), "preparing the test config failed: read-only file system"},
		{"signal", killedError(syscall.SIGSEGV), "xray was killed by a signal (SIGSEGV)"},
		{"unnamed signal", killedError(syscall.Signal(63)), "xray was killed by a signal"},
		{"status", exitedError(255), "xray exited with status 255"},
		{"unfinished", unfinishedError("20s", errors.New("context deadline exceeded")), "xray config test did not finish within 20s"},
		{"unfinished trial", unfinishedError("the trial's 1m30s", errors.New("context deadline exceeded")), "xray config test did not finish within the trial's 1m30s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.text != tc.want || tc.err.Error() != "runner: "+tc.want {
				t.Errorf("text %q, error %q; want %q", tc.err.text, tc.err.Error(), tc.want)
			}
			if !runnerapi.PublicTestError(tc.err.text) {
				t.Errorf("the client would not pass %q on", tc.err.text)
			}
		})
	}
	if !errors.Is(stageError(stage), syscall.ENOSPC) {
		t.Error("a test error should unwrap to its cause")
	}
}
