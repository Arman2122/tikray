package runner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

const (
	// defaultTestTimeout bounds one TestConfig.
	defaultTestTimeout = 20 * time.Second
	// maxTestOutput caps the output TestConfig returns. xray says why it
	// rejects a config first, so the start is what is kept.
	maxTestOutput = 8 << 10
	// truncatedMark ends an output that was cut to maxTestOutput.
	truncatedMark = "\n[output truncated]"
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
// A config xray rejects, or a test that takes more than 20 s, is a result with
// OK false. The output is what xray printed, cut to its first 8 KiB. With no
// xray running TestConfig returns runnerapi.ErrNoCore, and when ctx ends
// first, its error.
func (r *Runner) TestConfig(ctx context.Context, config []byte) (runnerapi.TestResult, error) {
	sel, ok := r.runningSelection()
	if !ok {
		return runnerapi.TestResult{}, runnerapi.ErrNoCore
	}
	dir, err := os.MkdirTemp(r.dirs().Run(), testDirPrefix+"*")
	if err != nil {
		return runnerapi.TestResult{}, fmt.Errorf("runner: test config: %w", err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "config.json")
	renamed, _ := testConfig(config)
	if err := os.WriteFile(path, renamed, 0o600); err != nil {
		return runnerapi.TestResult{}, fmt.Errorf("runner: test config: %w", err)
	}

	tctx, cancel := context.WithTimeout(ctx, r.testTimeout)
	defer cancel()
	out := &headBuffer{max: maxTestOutput + 1} // a byte more tells a cut
	err = runTest(tctx, r.sup.stagedPath(sel), r.sup.env(sel), path, out)
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return runnerapi.TestResult{}, fmt.Errorf("runner: test config: %w", ctx.Err())
	case err == nil:
		return runnerapi.TestResult{OK: true, Output: capOutput(string(out.buf))}, nil
	case tctx.Err() != nil:
		msg := fmt.Sprintf("xray run -test did not finish within %s\n", r.testTimeout)
		return runnerapi.TestResult{Output: capOutput(msg + string(out.buf))}, nil
	case errors.As(err, &exit):
		return runnerapi.TestResult{Output: capOutput(string(out.buf))}, nil
	default: // xray did not run at all
		return runnerapi.TestResult{}, err
	}
}

// headBuffer keeps the first max bytes written to it and drops the rest, so
// that an xray that prints without end costs no more memory than that.
type headBuffer struct {
	buf []byte
	max int
}

func (b *headBuffer) Write(p []byte) (int, error) {
	if room := b.max - len(b.buf); room > 0 {
		b.buf = append(b.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// capOutput returns out when it has at most maxTestOutput bytes, and
// otherwise its start, cut at a character boundary, and truncatedMark, in
// maxTestOutput bytes.
func capOutput(out string) string {
	if len(out) <= maxTestOutput {
		return out
	}
	cut := maxTestOutput - len(truncatedMark)
	for cut > 0 && !utf8.RuneStart(out[cut]) {
		cut--
	}
	return out[:cut] + truncatedMark
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
