package runner

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestXrayAPI(t *testing.T) {
	g := runningRig(t)
	got := g.r.XrayAPI(t.Context(), []string{"echo", "a b", "c"})
	if got.ExitCode != 0 || got.Stdout != "api: echo|a b|c\n" || got.Stderr != "" {
		t.Errorf("XrayAPI = %+v, want exit 0, stdout %q and no stderr", got, "api: echo|a b|c\n")
	}
}

func TestXrayAPINoShell(t *testing.T) {
	g := runningRig(t)
	args := []string{"echo", "; touch pwned", "$(id)", "`id`", "*"}
	got := g.r.XrayAPI(t.Context(), args)
	want := "api: " + strings.Join(args, "|") + "\n"
	if got.ExitCode != 0 || got.Stdout != want {
		t.Errorf("XrayAPI = %+v, want exit 0 and stdout %q (arguments passed through untouched)", got, want)
	}
}

func TestXrayAPIFailure(t *testing.T) {
	g := runningRig(t)
	got := g.r.XrayAPI(t.Context(), []string{"fail"})
	if got.ExitCode != 3 || got.Stdout != "partial\n" || got.Stderr != "fakexray: api failed\n" {
		t.Errorf("XrayAPI = %+v, want the exit code, stdout and stderr of the failed call", got)
	}
}

func TestXrayAPINoXray(t *testing.T) {
	g := newRig(t, nil) // not booted: nothing runs
	got := g.r.XrayAPI(t.Context(), []string{"echo"})
	if got.ExitCode != -1 || got.Stderr != "no xray is running" || got.Stdout != "" {
		t.Errorf("XrayAPI = %+v, want exit -1 and stderr %q", got, "no xray is running")
	}
}

func TestRunXrayAPIStartFailure(t *testing.T) {
	got := runXrayAPI(t.Context(), "/nonexistent/xray", []string{"echo"})
	if got.ExitCode != -1 || !strings.Contains(got.Stderr, "/nonexistent/xray") {
		t.Errorf("runXrayAPI = %+v, want exit -1 and the start error in stderr", got)
	}
}

func TestXrayAPIContext(t *testing.T) {
	g := runningRig(t)
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	got := g.r.XrayAPI(ctx, []string{"hang"})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("XrayAPI took %v after its context ended", elapsed)
	}
	if got.ExitCode != -1 || !strings.Contains(got.Stderr, context.DeadlineExceeded.Error()) {
		t.Errorf("XrayAPI = %+v, want exit -1 and %q in stderr", got, context.DeadlineExceeded)
	}
}
