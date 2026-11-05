package runner

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

const (
	// defaultTestTimeout bounds one TestConfig.
	defaultTestTimeout = 20 * time.Second
	// testDirPrefix names TestConfig's directories in the run directory.
	testDirPrefix = ".test-"
)

// TestConfig runs "xray run -test" on config with the core of the xray that
// runs now, the candidate during a trial and otherwise the active one, the
// way a trial tests its candidate: with the TUN devices renamed (see
// testConfig) and XRAY_LOCATION_ASSET set from that selection. It never waits
// for the runner's goroutine and changes no state, so it answers during a
// trial, even while the trial's own test runs, and leaves the running xray
// alone. The config is written 0600 to a fresh 0700 directory in the run
// directory, never to run/config, whose files an apply may prune at any time,
// and that directory is gone when TestConfig returns.
//
// A completed test returns xray's verdict (see runTest). A test that gives no
// verdict on the config, because xray could not start, a signal killed it,
// it exited with a status other than runnerapi.ExitConfigRefused, or it
// took longer than 20 s, is a *testError, so that the caller can retry the
// same config. With no xray running the error is runnerapi.ErrNoCore.
func (r *Runner) TestConfig(ctx context.Context, config []byte) (runnerapi.TestResult, error) {
	sel, ok := r.runningSelection()
	if !ok {
		return runnerapi.TestResult{}, runnerapi.ErrNoCore
	}
	dir, err := os.MkdirTemp(r.dirs().Run(), testDirPrefix+"*")
	if err != nil {
		return runnerapi.TestResult{}, prepareError(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "config.json")
	renamed, _ := testConfig(config)
	if err := os.WriteFile(path, renamed, 0o600); err != nil {
		return runnerapi.TestResult{}, prepareError(err)
	}

	tctx, cancel := context.WithTimeout(ctx, r.testTimeout)
	defer cancel()
	res, err := runTest(tctx, r.sup.stagedPath(sel), r.sup.env(sel), path)
	switch {
	case ctx.Err() != nil:
		return runnerapi.TestResult{}, fmt.Errorf("runner: test config: %w", ctx.Err())
	case err == nil:
		return res, nil
	case tctx.Err() != nil:
		return runnerapi.TestResult{}, unfinishedError(r.testTimeout.String(), tctx.Err())
	default:
		return runnerapi.TestResult{}, err
	}
}

// cleanTestDirs removes the directories of TestConfig calls that a stopped
// runner left in the run directory; their configs may hold credentials. Boot
// runs it before anything runs, when no TestConfig can be under way.
func cleanTestDirs(d Dirs) {
	dirs, _ := filepath.Glob(filepath.Join(d.Run(), testDirPrefix+"*")) // only a bad pattern fails
	for _, dir := range dirs {
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("runner: %v", err)
		}
	}
}
