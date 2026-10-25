package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

const (
	defaultStopGrace = 5 * time.Second
	versionTimeout   = 10 * time.Second
	exitsBuffer      = 16
)

// SupervisorConfig configures a Supervisor.
type SupervisorConfig struct {
	Dirs Dirs
	// StageDir is where cores are staged, /run/xray in the container. RouterOS
	// gives the files it places no execute bit, so xray always runs from a
	// copy made here.
	StageDir string
	// GoMemLimit is xray's GOMEMLIMIT. Empty leaves it unset, even when the
	// runner's own environment sets it.
	GoMemLimit string
	// StopGrace is how long a SIGTERM may take before SIGKILL; zero means 5 s.
	StopGrace time.Duration
	// Log receives xray's stdout and stderr. Nil discards them.
	Log io.Writer
}

// Exit is the end of an xray process that nobody asked to stop.
type Exit struct {
	// Selection is what the process ran.
	Selection runnerapi.Selection
	// Err is what cmd.Wait reported: nil for a clean exit, an *exec.ExitError
	// for a failure or a signal.
	Err error
	// Ran is how long the process lived.
	Ran time.Duration
}

// Supervisor runs at most one xray process. It manages the process and nothing
// more: what to do when xray dies is up to whoever reads Exits. It is safe for
// concurrent use.
type Supervisor struct {
	cfg   SupervisorConfig
	exits chan Exit

	// mu serializes Start and Stop, which hold it until the old process is
	// gone, so two xrays never overlap. PID does not take it.
	mu  sync.Mutex
	cur atomic.Pointer[process]

	// signal sends a stop signal; a test replaces it to make a stop fail.
	signal func(p *os.Process, sig os.Signal) error
}

// process is one xray run.
type process struct {
	cmd     *exec.Cmd
	sel     runnerapi.Selection
	started time.Time
	// expected is set before a deliberate stop signals the process, so that
	// its exit is not reported.
	expected atomic.Bool
	// done is closed when the process has been reaped.
	done chan struct{}
}

// NewSupervisor returns a supervisor with nothing running.
func NewSupervisor(c SupervisorConfig) *Supervisor {
	if c.StopGrace <= 0 {
		c.StopGrace = defaultStopGrace
	}
	return &Supervisor{cfg: c, exits: make(chan Exit, exitsBuffer), signal: (*os.Process).Signal}
}

// Stage copies the selection's core to <StageDir>/<core>/xray with mode 0755
// and returns that path. The copy gets the core's modification time, and a
// staged copy is reused only while it has the core's size and modification
// time, so staging a core again is cheap but a slot installed again with
// another binary, even of the same size, is staged again (an install writes
// a new file, which has a new time). The copy appears atomically, so a
// running xray is never disturbed and a failed copy leaves nothing behind.
func (s *Supervisor) Stage(sel runnerapi.Selection) (string, error) {
	dst := s.stagedPath(sel)
	if err := stageCopy(s.cfg.Dirs.CoreBinary(sel.Core), dst); err != nil {
		return "", fmt.Errorf("runner: stage core %s: %w", sel.Core, err)
	}
	return dst, nil
}

// stagedPath is where Stage puts the selection's core.
func (s *Supervisor) stagedPath(sel runnerapi.Selection) string {
	return filepath.Join(s.cfg.StageDir, sel.Core, "xray")
}

func stageCopy(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	si, err := in.Stat()
	if err != nil {
		return err
	}
	if !si.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	if di, err := os.Stat(dst); err == nil && di.Mode().IsRegular() && di.Mode().Perm() == 0o755 &&
		di.Size() == si.Size() && di.ModTime().Equal(si.ModTime()) {
		return nil
	}

	dir := filepath.Dir(dst)
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// A child forked while the copy is open for writing holds that descriptor
	// until it execs, and exec'ing the copy meanwhile fails with ETXTBSY. No
	// fork may happen until the copy is closed.
	syscall.ForkLock.Lock()
	defer syscall.ForkLock.Unlock()
	tmp, err := os.CreateTemp(dir, ".xray.tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if _, err = io.Copy(tmp, in); err != nil {
		return err
	}
	if err = tmp.Chmod(0o755); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chtimes(tmp.Name(), time.Time{}, si.ModTime()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// CleanStage removes from StageDir the staged copy of every core not in keep,
// and what an interrupted staging or test left: the .xray.tmp-* files of the
// kept cores and the .test-config-* files. Anything else in StageDir is left
// alone. Call it only while nothing stages or tests, with every core that
// may still run in keep.
func (s *Supervisor) CleanStage(keep ...string) error {
	ents, err := os.ReadDir(s.cfg.StageDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("runner: clean %s: %w", s.cfg.StageDir, err)
	}
	var errs []error
	for _, e := range ents {
		path := filepath.Join(s.cfg.StageDir, e.Name())
		switch {
		case e.IsDir() && slices.Contains(keep, e.Name()):
			tmps, _ := filepath.Glob(filepath.Join(path, ".xray.tmp-*"))
			for _, tmp := range tmps {
				errs = append(errs, os.Remove(tmp))
			}
		case e.IsDir():
			errs = append(errs, os.RemoveAll(path))
		case strings.HasPrefix(e.Name(), ".test-config-"):
			errs = append(errs, os.Remove(path))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("runner: clean %s: %w", s.cfg.StageDir, err)
	}
	return nil
}

// Test runs "xray run -test" on the selection's config with the staged core
// and returns what xray printed. A rejected config is an error wrapping the
// *exec.ExitError; the output says why. The config's TUN devices are renamed
// for the test (see testConfig), so that it can run beside the active xray.
func (s *Supervisor) Test(ctx context.Context, sel runnerapi.Selection) (string, error) {
	path, err := s.Stage(sel)
	if err != nil {
		return "", err
	}
	config, cleanup, err := s.testConfigFile(sel)
	if err != nil {
		return "", err
	}
	defer cleanup()
	cmd := exec.CommandContext(ctx, path, "run", "-test", "-c", config)
	cmd.Env = s.env(sel)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("runner: xray run -test: %w", err)
	}
	return string(out), nil
}

// testConfigFile returns the config file Test hands to xray: a copy of the
// selection's config made by testConfig, in StageDir, or the config itself
// when testConfig leaves it as it is or it cannot be read (xray then says
// why). cleanup removes the copy.
func (s *Supervisor) testConfigFile(sel runnerapi.Selection) (path string, cleanup func(), err error) {
	orig := s.cfg.Dirs.ConfigPath(sel.Config)
	data, err := os.ReadFile(orig)
	if err != nil {
		return orig, func() {}, nil
	}
	renamed, changed := testConfig(data)
	if !changed {
		return orig, func() {}, nil
	}
	if err := os.MkdirAll(s.cfg.StageDir, 0o755); err != nil {
		return "", nil, fmt.Errorf("runner: test config: %w", err)
	}
	f, err := os.CreateTemp(s.cfg.StageDir, ".test-config-*.json")
	if err != nil {
		return "", nil, fmt.Errorf("runner: test config: %w", err)
	}
	cleanup = func() { os.Remove(f.Name()) }
	_, err = f.Write(renamed)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("runner: test config: %w", err)
	}
	return f.Name(), cleanup, nil
}

// Version returns the first line of "xray version" for the selection's core.
func (s *Supervisor) Version(sel runnerapi.Selection) (string, error) {
	path, err := s.Stage(sel)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), versionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "version")
	cmd.Env = s.env(sel)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("runner: xray version: %w", err)
	}
	line, _, _ := strings.Cut(string(out), "\n")
	if line = strings.TrimSpace(line); line == "" {
		return "", errors.New("runner: xray version printed nothing")
	}
	return line, nil
}

// Start stages the selection's core, stops the running xray if there is one,
// then starts "xray run -c <config>". A selection that cannot be staged leaves
// the running process alone. The old process's exit is not reported.
func (s *Supervisor) Start(sel runnerapi.Selection) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, err := s.Stage(sel)
	if err != nil {
		return err
	}
	if err := s.stopLocked(); err != nil {
		return err
	}
	cmd := exec.Command(path, "run", "-c", s.cfg.Dirs.ConfigPath(sel.Config))
	cmd.Env = s.env(sel)
	cmd.Stdout = s.cfg.Log
	cmd.Stderr = s.cfg.Log
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("runner: start xray %s: %w", sel.Core, err)
	}
	p := &process{cmd: cmd, sel: sel, started: time.Now(), done: make(chan struct{})}
	s.cur.Store(p)
	go s.watch(p)
	return nil
}

// watch reaps the process and reports its exit unless a deliberate stop asked
// for it. The report is made after done is closed, so whoever receives it sees
// PID 0 and can Start again at once. Exits never blocks the supervisor: a
// consumer that falls 16 exits behind loses the newest.
func (s *Supervisor) watch(p *process) {
	err := p.cmd.Wait()
	ran := time.Since(p.started)
	expected := p.expected.Load()
	close(p.done)
	if expected {
		return
	}
	select {
	case s.exits <- Exit{Selection: p.sel, Err: err, Ran: ran}:
	default:
	}
}

// Stop sends SIGTERM and waits for xray to exit, up to StopGrace, then sends
// SIGKILL. It returns once the process is gone, and that exit is not reported.
// Stop with nothing running does nothing.
func (s *Supervisor) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopLocked()
}

func (s *Supervisor) stopLocked() error {
	p := s.cur.Load()
	if p == nil {
		return nil
	}
	p.expected.Store(true)
	select {
	case <-p.done: // it died on its own; nothing to stop
	default:
		if err := s.signal(p.cmd.Process, syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("runner: stop xray: %w", err)
		}
		timer := time.NewTimer(s.cfg.StopGrace)
		defer timer.Stop()
		select {
		case <-p.done:
		case <-timer.C:
			if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return fmt.Errorf("runner: kill xray: %w", err)
			}
			<-p.done
		}
	}
	s.cur.Store(nil)
	return nil
}

// Exits delivers every exit that Stop and Start did not ask for.
func (s *Supervisor) Exits() <-chan Exit { return s.exits }

// PID is the running xray's process ID, or 0 when none runs.
func (s *Supervisor) PID() int {
	p := s.cur.Load()
	if p == nil {
		return 0
	}
	select {
	case <-p.done:
		return 0
	default:
		return p.cmd.Process.Pid
	}
}

// env is the environment of an xray process: the runner's own, with GOMEMLIMIT
// and XRAY_LOCATION_ASSET taken from the config and the selection, and absent
// when they have no value.
func (s *Supervisor) env(sel runnerapi.Selection) []string {
	inherited := os.Environ()
	env := make([]string, 0, len(inherited)+2)
	for _, kv := range inherited {
		if !strings.HasPrefix(kv, "GOMEMLIMIT=") && !strings.HasPrefix(kv, "XRAY_LOCATION_ASSET=") {
			env = append(env, kv)
		}
	}
	if s.cfg.GoMemLimit != "" {
		env = append(env, "GOMEMLIMIT="+s.cfg.GoMemLimit)
	}
	if sel.Geo != "" {
		env = append(env, "XRAY_LOCATION_ASSET="+s.cfg.Dirs.GeoDir(sel.Geo))
	}
	return env
}
