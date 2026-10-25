package runner

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

// xrayAPIWaitDelay bounds how long a call may linger after its context ends or
// its process is gone, in case something that inherited the output pipes lives
// on.
const xrayAPIWaitDelay = time.Second

// XrayAPI runs "xray api <args>" with the xray that runs now; it is what
// NewServer takes for its xrayAPI. It looks the binary up itself, since xray
// may have stopped after the server's own check. No shell is involved: args go
// to the process as they are. A call that cannot run at all (no xray, the
// process does not start, the context ends first) has exit code -1 and says
// why in Stderr.
func (r *Runner) XrayAPI(ctx context.Context, args []string) runnerapi.XrayAPIResponse {
	bin, ok := r.RunningBinary()
	if !ok {
		return runnerapi.XrayAPIResponse{ExitCode: -1, Stderr: "no xray is running"}
	}
	return runXrayAPI(ctx, bin, args)
}

// runXrayAPI runs "<bin> api <args>" and returns what it printed and how it
// ended.
func runXrayAPI(ctx context.Context, bin string, args []string) runnerapi.XrayAPIResponse {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, append([]string{"api"}, args...)...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = xrayAPIWaitDelay
	err := cmd.Run()
	res := runnerapi.XrayAPIResponse{Stdout: stdout.String(), Stderr: stderr.String()}
	if err == nil {
		return res
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() >= 0 {
		res.ExitCode = exit.ExitCode()
		return res
	}
	// The process did not start, was killed with the context (an exit code of
	// -1 means a signal), or left its output pipes open.
	res.ExitCode = -1
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if res.Stderr != "" && !strings.HasSuffix(res.Stderr, "\n") {
		res.Stderr += "\n"
	}
	res.Stderr += err.Error()
	return res
}
