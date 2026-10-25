package runner

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

// syncBuffer is a Log that the test can read while xray is still writing.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitLog waits until xray has written want to the log.
func waitLog(t *testing.T, log *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(log.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("log never contained %q; it holds:\n%s", want, log.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type fixture struct {
	d   Dirs
	sup *Supervisor
	log *syncBuffer
	sel runnerapi.Selection
}

// newFixture installs the fake xray of a mode as core 26.10.21 (no execute
// bit), writes a config for it and returns a supervisor over it. tune may
// change the supervisor's config before it is built.
func newFixture(t *testing.T, mode string, tune func(*SupervisorConfig)) *fixture {
	t.Helper()
	f := &fixture{d: newDirs(t), log: &syncBuffer{}, sel: testSel}
	f.sel.Geo = ""
	installFake(t, f.d, f.sel.Core, mode)
	writeFile(t, f.d.ConfigPath(f.sel.Config), "{}")
	cfg := SupervisorConfig{Dirs: f.d, StageDir: t.TempDir(), StopGrace: 2 * time.Second, Log: f.log}
	if tune != nil {
		tune(&cfg)
	}
	f.sup = NewSupervisor(cfg)
	t.Cleanup(func() { f.sup.Stop() })
	return f
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// noExit fails if an exit is delivered within d.
func noExit(t *testing.T, s *Supervisor, d time.Duration) {
	t.Helper()
	select {
	case e := <-s.Exits():
		t.Fatalf("unexpected exit delivered: %+v", e)
	case <-time.After(d):
	}
}

// gone reports whether no process has the pid any more.
func gone(pid int) bool { return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) }

func TestStageRunsWithoutExecBit(t *testing.T) {
	f := newFixture(t, "ok", func(c *SupervisorConfig) { c.GoMemLimit = "128MiB" })
	if fi, err := os.Stat(f.d.CoreBinary(f.sel.Core)); err != nil || fi.Mode().Perm()&0o111 != 0 {
		t.Fatalf("installed core mode = %v, err %v; want no execute bit", fi.Mode(), err)
	}
	if err := f.sup.Start(f.sel); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if f.sup.PID() <= 0 {
		t.Fatalf("PID = %d after Start, want > 0", f.sup.PID())
	}
	waitLog(t, f.log, "env GOMEMLIMIT=128MiB")
	waitLog(t, f.log, "config "+f.d.ConfigPath(f.sel.Config))
}

func TestStageCopiesWithExecBit(t *testing.T) {
	f := newFixture(t, "ok", nil)
	path, err := f.sup.Stage(f.sel)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if want := filepath.Join(f.sup.cfg.StageDir, f.sel.Core, "xray"); path != want {
		t.Errorf("staged path = %q, want %q", path, want)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("staged mode = %v, err %v; want 0755", fi.Mode(), err)
	}
	src, err := os.ReadFile(f.d.CoreBinary(f.sel.Core))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, src) {
		t.Errorf("staged copy differs from the core (err %v)", err)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".*"))
	if len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}
}

func TestStageReusesSameSizeCopy(t *testing.T) {
	f := newFixture(t, "ok", nil)
	path, err := f.sup.Stage(f.sel)
	if err != nil {
		t.Fatal(err)
	}
	first, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sup.Stage(f.sel); err != nil {
		t.Fatal(err)
	}
	if second, err := os.Stat(path); err != nil || !os.SameFile(first, second) {
		t.Fatalf("a copy of the same size was staged again (err %v)", err)
	}

	// A core of another size under the same version replaces the staged copy.
	src := f.d.CoreBinary(f.sel.Core)
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, src, string(b)+"padding")
	if _, err := f.sup.Stage(f.sel); err != nil {
		t.Fatal(err)
	}
	third, err := os.Stat(path)
	if err != nil || os.SameFile(first, third) || third.Size() != int64(len(b)+len("padding")) {
		t.Fatalf("staged copy was not replaced: %v, err %v", third, err)
	}
}

func TestStageMissingCore(t *testing.T) {
	f := newFixture(t, "ok", nil)
	sel := f.sel
	sel.Core = "26.10.22"
	if _, err := f.sup.Stage(sel); err == nil {
		t.Fatal("Stage of a missing core succeeded")
	}
	if err := f.sup.Start(sel); err == nil {
		t.Fatal("Start of a missing core succeeded")
	}
	if pid := f.sup.PID(); pid != 0 {
		t.Errorf("PID = %d after a failed Start, want 0", pid)
	}
}

func TestTestReportsFailure(t *testing.T) {
	f := newFixture(t, "badconfig", nil)
	out, err := f.sup.Test(t.Context(), f.sel)
	if err == nil {
		t.Fatal("Test accepted a bad config")
	}
	if !strings.Contains(out, "failed to load config") {
		t.Errorf("output = %q, want it to contain %q", out, "failed to load config")
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 23 {
		t.Errorf("err = %v, want an *exec.ExitError with code 23", err)
	}
}

func TestTestAcceptsGoodConfig(t *testing.T) {
	f := newFixture(t, "ok", nil)
	out, err := f.sup.Test(t.Context(), f.sel)
	if err != nil || !strings.Contains(out, "Configuration OK.") {
		t.Fatalf("Test = %q, %v; want Configuration OK. and no error", out, err)
	}
	if f.sup.PID() != 0 {
		t.Errorf("Test started a supervised process (PID %d)", f.sup.PID())
	}
}

func TestTestRenamesTunDevice(t *testing.T) {
	// xray before 26.10 opens the TUN device while it tests a config, and
	// the running xray holds xray0 (M1 lab): -test must use another name.
	f := newFixture(t, "ok", nil)
	orig := f.d.ConfigPath(f.sel.Config)
	writeFile(t, orig, `{"inbounds": [{"tag": "tun-in", "protocol": "tun", "settings": {"name": "xray0", "MTU": 1500}}]}`)
	out, err := f.sup.Test(t.Context(), f.sel)
	if err != nil {
		t.Fatalf("Test: %v\n%s", err, out)
	}
	// The fake prints the path it tested and the config it read there.
	path, _, _ := strings.Cut(strings.TrimPrefix(out, "config "), "\n")
	if path == orig || !strings.Contains(out, `"name":"xray-test0"`) || strings.Contains(out, "xray0") {
		t.Errorf("xray run -test ran on %s with output\n%s\nwant a copy of the config with the TUN device named xray-test0", path, out)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the tested copy %s is still there after Test (%v)", path, err)
	}
	if b, err := os.ReadFile(orig); err != nil || !strings.Contains(string(b), `"name": "xray0"`) {
		t.Errorf("the selection's config changed: %s (%v)", b, err)
	}
}

func TestTestUsesConfigWithoutTunAsIs(t *testing.T) {
	f := newFixture(t, "ok", nil)
	out, err := f.sup.Test(t.Context(), f.sel)
	if err != nil {
		t.Fatalf("Test: %v\n%s", err, out)
	}
	if want := "config " + f.d.ConfigPath(f.sel.Config) + "\n"; !strings.HasPrefix(out, want) {
		t.Errorf("Test output %q, want xray run -test on the selection's config (%q)", out, want)
	}
}

func TestVersion(t *testing.T) {
	f := newFixture(t, "ok", nil)
	got, err := f.sup.Version(f.sel)
	if err != nil || got != "Xray 99.0.0 (fake ok)" {
		t.Fatalf("Version = %q, %v; want the first line of xray version", got, err)
	}
	sel := f.sel
	sel.Core = "26.10.22"
	if _, err := f.sup.Version(sel); err == nil {
		t.Error("Version of a missing core succeeded")
	}
}

func TestUnexpectedExitReported(t *testing.T) {
	f := newFixture(t, "exit2s", nil)
	if err := f.sup.Start(f.sel); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-f.sup.Exits():
		if e.Ran < 1500*time.Millisecond || e.Ran > 5*time.Second {
			t.Errorf("Ran = %v, want between 1.5s and 5s", e.Ran)
		}
		var ee *exec.ExitError
		if !errors.As(e.Err, &ee) || ee.ExitCode() != 1 {
			t.Errorf("Err = %v, want exit status 1", e.Err)
		}
		if e.Selection != f.sel {
			t.Errorf("Selection = %+v, want %+v", e.Selection, f.sel)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("the crash was never reported")
	}
	if pid := f.sup.PID(); pid != 0 {
		t.Errorf("PID = %d after the exit, want 0", pid)
	}
	noExit(t, f.sup, 100*time.Millisecond)
}

func TestStopIsNotAnExit(t *testing.T) {
	f := newFixture(t, "ok", nil)
	if err := f.sup.Start(f.sel); err != nil {
		t.Fatal(err)
	}
	pid := f.sup.PID()
	if err := f.sup.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !gone(pid) || f.sup.PID() != 0 {
		t.Errorf("after Stop: process %d gone = %v, PID() = %d", pid, gone(pid), f.sup.PID())
	}
	noExit(t, f.sup, time.Second)
}

func TestStopWithNothingRunning(t *testing.T) {
	f := newFixture(t, "ok", nil)
	if err := f.sup.Stop(); err != nil {
		t.Fatalf("Stop on an idle supervisor: %v", err)
	}
	if pid := f.sup.PID(); pid != 0 {
		t.Errorf("PID = %d on an idle supervisor, want 0", pid)
	}
}

func TestStopKillsAfterGrace(t *testing.T) {
	f := newFixture(t, "stubborn", func(c *SupervisorConfig) { c.StopGrace = 300 * time.Millisecond })
	if err := f.sup.Start(f.sel); err != nil {
		t.Fatal(err)
	}
	pid := f.sup.PID()
	waitLog(t, f.log, "env GOMEMLIMIT=") // it ignores SIGTERM by now
	start := time.Now()
	if err := f.sup.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if took := time.Since(start); took < 250*time.Millisecond || took > 3*time.Second {
		t.Errorf("Stop took %v, want about the 300ms grace period", took)
	}
	if !gone(pid) {
		t.Errorf("process %d survived Stop", pid)
	}
	noExit(t, f.sup, 200*time.Millisecond)
}

func TestStartReplacesRunning(t *testing.T) {
	f := newFixture(t, "ok", nil)
	if err := f.sup.Start(f.sel); err != nil {
		t.Fatal(err)
	}
	first := f.sup.PID()
	if err := f.sup.Start(f.sel); err != nil {
		t.Fatal(err)
	}
	second := f.sup.PID()
	if second <= 0 || second == first {
		t.Errorf("PID = %d after the second Start, first was %d", second, first)
	}
	if !gone(first) {
		t.Errorf("the first process %d still runs", first)
	}
	noExit(t, f.sup, 300*time.Millisecond)
}

func TestFailedStartLeavesRunningProcess(t *testing.T) {
	f := newFixture(t, "ok", nil)
	if err := f.sup.Start(f.sel); err != nil {
		t.Fatal(err)
	}
	pid := f.sup.PID()
	missing := f.sel
	missing.Core = "26.10.22"
	if err := f.sup.Start(missing); err == nil {
		t.Fatal("Start of a missing core succeeded")
	}
	if got := f.sup.PID(); got != pid || gone(pid) {
		t.Errorf("PID = %d, process %d gone = %v; the running process should be left alone", got, pid, gone(pid))
	}
}

func TestGeoEnv(t *testing.T) {
	f := newFixture(t, "ok", nil)
	f.sel.Geo = "g1"
	if err := os.MkdirAll(f.d.GeoDir("g1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := f.sup.Start(f.sel); err != nil {
		t.Fatal(err)
	}
	waitLog(t, f.log, "XRAY_LOCATION_ASSET="+filepath.Join(f.d.Data, "geo", "g1"))
}

func TestEnvWithoutLimitOrGeo(t *testing.T) {
	// The runner's own limit and asset location must not leak into xray.
	t.Setenv("GOMEMLIMIT", "1GiB")
	t.Setenv("XRAY_LOCATION_ASSET", "/elsewhere")
	f := newFixture(t, "ok", nil)
	if err := f.sup.Start(f.sel); err != nil {
		t.Fatal(err)
	}
	waitLog(t, f.log, "env GOMEMLIMIT= XRAY_LOCATION_ASSET=\n")
}

// TestStageWhileForking stages fresh cores and runs them while another
// goroutine keeps forking, as the control API's xray api calls will. A child
// that inherited the copy's write descriptor would make the exec fail with
// ETXTBSY.
func TestStageWhileForking(t *testing.T) {
	f := newFixture(t, "ok", nil)
	src, err := os.ReadFile(f.d.CoreBinary(f.sel.Core))
	if err != nil {
		t.Fatal(err)
	}
	// Running the core on the mount forks, then fails to exec it for want of
	// the execute bit: as many forks as possible, at no cost.
	noexec := f.d.CoreBinary(f.sel.Core)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				exec.Command(noexec).Run()
			}
		}()
	}
	defer func() { close(stop); wg.Wait() }()
	for i := range 40 {
		sel := f.sel
		sel.Core = fmt.Sprintf("26.10.%d", 100+i)
		writeFile(t, f.d.CoreBinary(sel.Core), string(src))
		if _, err := f.sup.Test(t.Context(), sel); err != nil {
			t.Fatalf("core %s: %v", sel.Core, err)
		}
	}
}

func TestConcurrentUse(t *testing.T) {
	f := newFixture(t, "ok", nil)
	if _, err := f.sup.Stage(f.sel); err != nil { // stage before the goroutines race
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 3 {
				if err := f.sup.Start(f.sel); err != nil {
					t.Error(err)
				}
				f.sup.PID()
				if err := f.sup.Stop(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if pid := f.sup.PID(); pid != 0 {
		t.Errorf("PID = %d after the last Stop, want 0", pid)
	}
	noExit(t, f.sup, 100*time.Millisecond)
}
