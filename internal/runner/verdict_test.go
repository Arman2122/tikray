package runner

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
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

// On exit status 23 the runner reads xray's refusal itself, and passes on
// only the srv- tags of the outbounds xray names and a fixed category, in a
// trial, in its record and in POST /v1/test.
func TestRefusalNamesTheServerAndCategory(t *testing.T) {
	const (
		want    = "xray rejected the config: outbound srv-deadbeef: unsupported flow"
		private = "fixture-private-value"
	)
	config := `{"outbounds":[{"protocol":"vless","tag":"srv-deadbeef","settings":{"vnext":[{"users":[{"id":"` + private + `","flow":"xtls-rprx-direct"}]}]}}]}`
	g := runningRig(t)
	cand := g.candidate(t, "flowtest", 10*time.Second)
	writeFile(t, g.d.ConfigPath(cand.Config), config)
	a := newAPI(t, g, nil)
	err := a.c.Trial(t.Context())
	var tf *runnerapi.TestFailedError
	if !errors.As(err, &tf) || tf.Output != want {
		t.Fatalf("Trial = %v; want the refusal %q", err, want)
	}
	g.wantLastTrial(t, runnerapi.OutcomeRejected, cand)
	if st, err := a.c.Status(t.Context()); err != nil || st.LastTrial == nil || st.LastTrial.Detail != want {
		t.Errorf("Status = %+v, %v; want the last trial's detail %q", st.LastTrial, err, want)
	}
	if last, err := ReadLastTrial(g.d); err != nil || last == nil || last.Detail != want {
		t.Errorf("last-trial.json = %+v, %v; want the detail %q", last, err, want)
	}

	g = newRig(t, nil)
	g.active(t, "flowtest")
	g.boot(t)
	a = newAPI(t, g, nil)
	res, err := a.c.Test(t.Context(), []byte(config))
	if err != nil || res != (runnerapi.TestResult{Output: want}) {
		t.Errorf("Test = %+v, %v; want the refusal %q", res, err, want)
	}
	resp, body := send(t, a.url, http.MethodPost, "/v1/test", "Bearer "+testToken, config)
	if resp.StatusCode != http.StatusOK || strings.Contains(body, private) || !strings.Contains(body, want) {
		t.Errorf("POST /v1/test = %d %s; want 200 with the refusal and nothing of the config", resp.StatusCode, body)
	}
}

// realRefusals are the refusals of the configs in testdata/refusals, the
// ones the runnerapi tests' xray output came from.
var realRefusals = map[string]string{
	"flow":             "outbound srv-deadbeef: unsupported flow",
	"plainvless":       "outbound srv-0000beef: transport needs TLS or encryption",
	"plainvlessdomain": "outbound srv-0000beef: transport needs TLS or encryption",
	"plaintrojan":      "outbound srv-1234abcd: transport needs TLS or encryption",
	"insecure":         "outbound srv-0000cafe: allowInsecure refused",
	"reality":          "outbound srv-00001111: invalid TLS or REALITY settings",
	"fp":               "outbound srv-00006666: invalid TLS or REALITY settings",
	"network":          "outbound srv-00002222: unsupported transport or security",
	"security":         "outbound srv-00003333: unsupported transport or security",
	"proto":            "outbound srv-00000f0f: unknown protocol",
	"ssmethod":         "outbound srv-0000bbbb: unsupported cipher",
	"sspass":           "outbound srv-0000cccc: missing or invalid password",
	"trojanpass":       "outbound srv-0000eeee: missing or invalid password",
	"ss2022":           "missing or invalid password",
	"vlessenc":         "outbound srv-00004444: unsupported VLESS encryption",
	"port0":            "outbound srv-00000a0a: invalid port or address",
	"portbig":          "outbound srv-00000b0b: invalid port or address",
	"portstr":          "outbound srv-00000c0c: invalid port or address",
	"badaddr":          "outbound srv-00000e0e: invalid port or address",
	"baduuid":          "outbound srv-0badc0de: invalid user",
	"json":             "invalid JSON",
	"jsonsyntax":       "invalid JSON",
	"jsontype":         "outbound srv-0000aaac: invalid config",
	"hysteria":         "outbound srv-00005555: invalid config",
}

// TestRealXrayRefusals has a real xray, $TIKRAY_TEST_XRAY, test the configs
// in testdata/refusals. A config it refuses must give the refusal above, and
// one it accepts (a release without the rule) is logged.
func TestRealXrayRefusals(t *testing.T) {
	bin := os.Getenv("TIKRAY_TEST_XRAY")
	if bin == "" {
		t.Skip("set TIKRAY_TEST_XRAY to an xray binary to test its refusals")
	}
	paths, err := filepath.Glob(filepath.Join("testdata", "refusals", "*.json"))
	if err != nil || len(paths) != len(realRefusals) {
		t.Fatalf("testdata/refusals has %d configs (%v); want %d", len(paths), err, len(realRefusals))
	}
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".json")
		t.Run(name, func(t *testing.T) {
			res, err := runTest(t.Context(), bin, os.Environ(), path)
			switch {
			case err != nil:
				t.Fatalf("runTest: %v", err)
			case res.OK:
				t.Logf("this xray accepts %s", name)
			case res.Output != "xray rejected the config: "+realRefusals[name]:
				t.Errorf("refusal %q, want %q", res.Output, "xray rejected the config: "+realRefusals[name])
			}
		})
	}
}
