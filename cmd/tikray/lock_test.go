package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

// While tikray serve holds serve.lock, the direct paths do not run, whatever
// the probe of its address found: two processes would write the state.
func TestDirectPathsRefuseWhileServeOwnsTheState(t *testing.T) {
	cfgFile, _ := configFile(t, `{"inbounds":[]}`+"\n")
	for _, args := range [][]string{
		{"apply"},
		{"core", "update", "26.10.21"},
		{"core", "update", "26.10.21", "--config", cfgFile},
		{"core", "rollback"},
	} {
		t.Run(strings.Join(args[:min(2, len(args))], " "), func(t *testing.T) {
			// TIKRAY_API names a port that nothing listens on, as when the
			// daemon listens somewhere else: the probe finds no daemon.
			vars, data, runner := trialEnv(t, &runnerapi.Selection{Core: "26.3.27", Config: testConfigRel})
			installSlot(t, data, "26.10.21")
			writeState(t, data, withServer)
			stateFile := filepath.Join(data, "state", "state.v1.json")
			before, err := os.ReadFile(stateFile)
			if err != nil {
				t.Fatal(err)
			}
			unlock, err := lockServe(data)
			if err != nil {
				t.Fatal(err)
			}
			defer unlock()

			code, stdout, stderr := runFast(t, vars, args...)
			want := "tikray: tikray serve is running (it holds " + filepath.Join(data, "state", "serve.lock") + ")\n"
			if code != 1 || !strings.Contains(stderr, want) {
				t.Errorf("exit %d, stderr %q; want 1 and %q", code, stderr, want)
			}
			if res := decodeResult(t, stdout); res.Outcome != artifacts.OutcomeRefused {
				t.Errorf("result %+v, want a refusal", res)
			}
			if n := len(runner.candidates()); n != 0 {
				t.Errorf("%d trials beside a serve", n)
			}
			if after, err := os.ReadFile(stateFile); err != nil || !bytes.Equal(after, before) {
				t.Errorf("the state file changed (%v)", err)
			}
			if _, err := os.Stat(filepath.Join(data, "state", "core-history.jsonl")); err == nil {
				t.Error("a history was written beside a serve")
			}
			if _, err := os.Stat(filepath.Join(data, "run", "candidate.json")); err == nil {
				t.Error("a candidate config was put down beside a serve")
			}
		})
	}

	// The commands that only read do not need the lock.
	vars, data, _ := trialEnv(t, &runnerapi.Selection{Core: "26.10.21", Config: testConfigRel})
	unlock, err := lockServe(data)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if code, _, stderr := runFast(t, vars, "config", "render", "--core", "26.10.21"); code != 0 {
		t.Errorf("config render: exit %d, stderr %q", code, stderr)
	}
	if code, _, stderr := runFast(t, vars, "core", "status"); code != 0 {
		t.Errorf("core status: exit %d, stderr %q", code, stderr)
	}
}

// A direct run holds the lock for as long as it runs, and lets go of it after.
func TestDirectPathsHoldTheLockWhileTheyRun(t *testing.T) {
	vars, data, runner := trialEnv(t, &runnerapi.Selection{Core: "26.10.21", Config: testConfigRel})
	writeState(t, data, func(*store.State) {})

	var during error
	var out, errb bytes.Buffer
	c := &cli{getenv: envOf(vars), stdout: &out, stderr: &errb, tune: func(u *artifacts.CoreUpdater) {
		u.EarlyExit = time.Millisecond
		u.HealthWindow = 300 * time.Millisecond
		// The updater is about to run: serve could not start now.
		var unlock func()
		if unlock, during = lockServe(data); unlock != nil {
			unlock()
		}
	}}
	if code := c.run(context.Background(), []string{"apply"}); code != 0 {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
	if !errors.Is(during, errServeHeld) {
		t.Errorf("a second owner while apply ran: %v, want errServeHeld", during)
	}
	if n := len(runner.candidates()); n != 1 {
		t.Errorf("%d trials, want 1", n)
	}
	unlock, err := lockServe(data)
	if err != nil {
		t.Fatalf("the lock was not let go: %v", err)
	}
	unlock()
}
