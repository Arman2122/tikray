// Command tikray is the control plane's command line. In M1 it drives xray-core
// updates; the daemon, REST API and UI come with M2.
//
//	tikray core update <version|latest> [--config FILE] [--allow-unverified]
//	tikray core rollback
//	tikray core list [--json]
//	tikray core status
//
// update and rollback print their result as JSON on stdout, save it to
// <data>/state/last-result.json, and exit 0 if the core was committed or
// already active and 1 otherwise. Progress and errors go to stderr. Usage
// errors exit 2.
//
// They remove the previous last-result.json as soon as the data root is ready,
// so the file is always this run's result or absent. A failure before the
// updater runs, such as an unreadable runner token, is saved as a refused
// result. A run that is killed leaves no file.
//
// Environment (see Config): TIKRAY_DATA, TIKRAY_ARCH, TIKRAY_RUNNER_URL,
// TIKRAY_SOCKS, TIKRAY_UPSTREAM, TIKRAY_MIRRORS, TIKRAY_INDEX_URLS,
// TIKRAY_INDEX_PUBKEY_FILE, TIKRAY_PROBE_URL.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
)

const (
	lastResultName = "last-result.json"
	// probeTimeout bounds one SOCKS health probe.
	probeTimeout = 10 * time.Second
)

const usageText = `usage: tikray core <command> [flags]

commands:
  update <version|latest> [--config FILE] [--allow-unverified]
                 switch the runner to another xray-core, on a trial
  rollback       switch back to the previously committed core
  list [--json]  list the installed cores
  status         print the runner's status as JSON

Configuration comes from the environment: TIKRAY_DATA, TIKRAY_ARCH,
TIKRAY_RUNNER_URL, TIKRAY_SOCKS, TIKRAY_UPSTREAM, TIKRAY_MIRRORS,
TIKRAY_INDEX_URLS, TIKRAY_INDEX_PUBKEY_FILE and TIKRAY_PROBE_URL.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// cli is one invocation: its environment and output.
type cli struct {
	getenv         func(string) string
	stdout, stderr io.Writer
}

// run executes the command line args (without the program name) and returns
// the exit code: 0 for success, 1 for a failure, 2 for a usage error.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	c := &cli{getenv: getenv, stdout: stdout, stderr: stderr}
	if len(args) == 0 {
		return c.usageError("")
	}
	switch args[0] {
	case "help", "-h", "--help":
		io.WriteString(stdout, usageText)
		return 0
	case "core":
		return c.core(ctx, args[1:])
	}
	return c.usageError(fmt.Sprintf("unknown command %q", args[0]))
}

func (c *cli) core(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return c.usageError("")
	}
	switch args[0] {
	case "update":
		return c.update(ctx, args[1:])
	case "rollback":
		return c.rollback(ctx, args[1:])
	case "list":
		return c.list(args[1:])
	case "status":
		return c.status(ctx, args[1:])
	case "help", "-h", "--help":
		io.WriteString(c.stdout, usageText)
		return 0
	}
	return c.usageError(fmt.Sprintf("unknown core command %q", args[0]))
}

// usageError prints msg, if any, and the usage to stderr and returns 2.
func (c *cli) usageError(msg string) int {
	if msg != "" {
		fmt.Fprintf(c.stderr, "tikray: %s\n", msg)
	}
	io.WriteString(c.stderr, usageText)
	return 2
}

// fail prints err to stderr and returns 1.
func (c *cli) fail(err error) int {
	fmt.Fprintf(c.stderr, "tikray: %v\n", err)
	return 1
}

// parse parses the flags and positional arguments of one subcommand, which
// may come in either order. want is the number of positional arguments. The
// ok result is false when the command is not to run, and code is its exit code.
func (c *cli) parse(fs *flag.FlagSet, args []string, want int) (pos []string, code int, ok bool) {
	pos, err := parseInterleaved(fs, args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		return nil, 0, false // the FlagSet has printed the usage
	case err != nil:
		return nil, 2, false // so has it the error
	case len(pos) != want:
		fmt.Fprintf(c.stderr, "%s: want %d argument(s), got %d\n", fs.Name(), want, len(pos))
		fs.Usage()
		return nil, 2, false
	}
	return pos, 0, true
}

// newFlagSet is the FlagSet of one subcommand; usage is the synopsis after
// "tikray core ".
func (c *cli) newFlagSet(name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet("tikray core "+name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: tikray core %s\n", usage)
		fs.PrintDefaults()
	}
	return fs
}

// parseInterleaved is fs.Parse for a command line whose flags may follow its
// positional arguments, such as "update 26.10.21 --config FILE". It returns
// the positional arguments.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func (c *cli) update(ctx context.Context, args []string) int {
	fs := c.newFlagSet("update", "update <version|latest> [--config FILE] [--allow-unverified]")
	configFile := fs.String("config", "", "run the core with the xray config in `FILE` (default: keep the active config)")
	allow := fs.Bool("allow-unverified", false, "install a core whose SHA-256 nobody knows, if it is in the inbox")
	pos, code, ok := c.parse(fs, args, 1)
	if !ok {
		return code
	}
	return c.updateOrRollback(ctx, pos[0], func(ctx context.Context, u *artifacts.CoreUpdater) (artifacts.Result, error) {
		return u.Update(ctx, pos[0], artifacts.UpdateOptions{ConfigFile: *configFile, AllowUnverified: *allow})
	})
}

func (c *cli) rollback(ctx context.Context, args []string) int {
	fs := c.newFlagSet("rollback", "rollback")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	return c.updateOrRollback(ctx, "", func(ctx context.Context, u *artifacts.CoreUpdater) (artifacts.Result, error) {
		return u.Rollback(ctx)
	})
}

// updateOrRollback builds the updater, runs do and reports its result. to is
// the version asked for, empty for a rollback.
//
// Once the data root is known to be usable, the previous last-result.json is
// removed, before anything else can fail. From then on the file is either
// this run's result or absent, so that a reader never mistakes an older run
// for this one: a failure in setup leaves a refused result, and a run that is
// killed leaves none. Only a bad environment or an unusable data root leave
// the file as it was; there is no place to write one.
func (c *cli) updateOrRollback(ctx context.Context, to string, do func(context.Context, *artifacts.CoreUpdater) (artifacts.Result, error)) int {
	cfg, err := configFromEnv(c.getenv)
	if err != nil {
		return c.fail(err)
	}
	if err := prepareDirs(cfg.Data); err != nil {
		return c.fail(err)
	}
	if err := removeFileDurably(filepath.Join(cfg.Data, "state", lastResultName)); err != nil {
		return c.refused(cfg, to, fmt.Errorf("removing the previous result: %w", err))
	}
	runner, err := newRunner(cfg)
	if err != nil {
		return c.refused(cfg, to, err)
	}
	u, err := newUpdater(cfg, runner, c.stderr)
	if err != nil {
		return c.refused(cfg, to, err)
	}
	res, err := do(ctx, u)
	return c.report(cfg, res, err)
}

// refused reports a refusal that no CoreUpdater made, because the command
// failed before it could run: the result is not in the history, which is the
// updater's.
func (c *cli) refused(cfg Config, to string, err error) int {
	res := artifacts.Result{To: to, Outcome: artifacts.OutcomeRefused, Detail: err.Error(), At: time.Now()}
	return c.report(cfg, res, err)
}

// report prints res, saves it as the last result and returns the exit code.
// The code follows the outcome, not err: a committed core whose history line
// could not be written still ends in a non-nil err.
func (c *cli) report(cfg Config, res artifacts.Result, err error) int {
	b, merr := json.MarshalIndent(res, "", "  ")
	if merr != nil {
		return c.fail(fmt.Errorf("encoding the result: %w", merr))
	}
	b = append(b, '\n')
	c.stdout.Write(b)
	if err != nil {
		fmt.Fprintf(c.stderr, "tikray: %v\n", err)
	}
	code := exitCode(res)
	path := filepath.Join(cfg.Data, "state", lastResultName)
	if werr := writeFileAtomic(path, b, 0o600); werr != nil {
		// Whoever reads last-result.json would find the previous run's result.
		fmt.Fprintf(c.stderr, "tikray: saving the result (outcome %q): %v\n", res.Outcome, werr)
		code = 1
	}
	return code
}

// exitCode is 0 for an update or rollback that committed or found its target
// already active, and 1 for every other outcome.
func exitCode(res artifacts.Result) int {
	switch res.Outcome {
	case runnerapi.OutcomeCommitted, artifacts.OutcomeNoop:
		return 0
	}
	return 1
}

func (c *cli) list(args []string) int {
	fs := c.newFlagSet("list", "list [--json]")
	asJSON := fs.Bool("json", false, "print JSON instead of a table")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	cfg, err := configFromEnv(c.getenv)
	if err != nil {
		return c.fail(err)
	}
	slots, err := artifacts.ListCores(filepath.Join(cfg.Data, "cores"))
	if err != nil {
		return c.fail(err)
	}
	if *asJSON {
		type core struct {
			Version     string    `json:"version"`
			Verified    string    `json:"verified"`
			Source      string    `json:"source"`
			InstalledAt time.Time `json:"installed_at"`
		}
		cores := make([]core, 0, len(slots))
		for _, s := range slots {
			cores = append(cores, core{s.Version.String(), s.Meta.Verified, s.Meta.Source, s.Meta.InstalledAt})
		}
		return c.printJSON(cores)
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "VERSION\tVERIFIED\tSOURCE\tINSTALLED")
	for _, s := range slots {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.Version, orDash(s.Meta.Verified), orDash(s.Meta.Source), s.Meta.InstalledAt.UTC().Format(time.RFC3339))
	}
	if err := tw.Flush(); err != nil {
		return c.fail(err)
	}
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (c *cli) status(ctx context.Context, args []string) int {
	fs := c.newFlagSet("status", "status")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	cfg, err := configFromEnv(c.getenv)
	if err != nil {
		return c.fail(err)
	}
	runner, err := newRunner(cfg)
	if err != nil {
		return c.fail(err)
	}
	st, err := runner.Status(ctx)
	if err != nil {
		return c.fail(err)
	}
	return c.printJSON(st)
}

// printJSON writes v as indented JSON to stdout.
func (c *cli) printJSON(v any) int {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.stdout, "%s\n", b)
	return 0
}

// prepareDirs creates the directories tikray works in under data: state/
// (0700, it holds secrets), state/tmp and inbox/. It points TMPDIR at
// state/tmp, because the image is FROM scratch and has no /tmp, and the
// verification of a download makes temporary files. Call it before any
// artifacts work.
func prepareDirs(data string) error {
	tmp := filepath.Join(data, "state", "tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil { // and state/
		return err
	}
	if err := os.MkdirAll(filepath.Join(data, "inbox"), 0o755); err != nil {
		return err
	}
	return os.Setenv("TMPDIR", tmp)
}

// newRunner is the client of the runner at cfg.RunnerURL, with the token from
// <data>/run/runner.token.
func newRunner(cfg Config) (*runnerapi.Client, error) {
	tok, err := os.ReadFile(filepath.Join(cfg.Data, "run", "runner.token"))
	if err != nil {
		return nil, fmt.Errorf("reading the runner token: %w", err)
	}
	return &runnerapi.Client{BaseURL: cfg.RunnerURL, Token: strings.TrimSpace(string(tok))}, nil
}

// proxyHealthy reports whether the fetch chain may use the proxy: the runner
// has xray running, or on trial, with its gateway up.
func proxyHealthy(runner *runnerapi.Client) func(context.Context) bool {
	return func(ctx context.Context) bool {
		st, err := runner.Status(ctx)
		if err != nil {
			return false
		}
		return (st.State == runnerapi.StateRunning || st.State == runnerapi.StateTrial) && st.GatewayUp
	}
}

// newUpdater wires the CoreUpdater of §4: the fetch chain in the order of
// §4.2 (direct, the proxy, the mirrors, the inbox), a verifier whose .dgst
// only ever comes from upstream (§4.3), and a health check that needs the
// proxy to carry traffic and xray's API to answer.
func newUpdater(cfg Config, runner *runnerapi.Client, log io.Writer) (*artifacts.CoreUpdater, error) {
	var pub []byte
	if cfg.IndexPubKeyFile != "" {
		var err error
		if pub, err = os.ReadFile(cfg.IndexPubKeyFile); err != nil {
			return nil, fmt.Errorf("reading the hash index key: %w", err)
		}
	}
	upstream := []artifacts.Source{
		artifacts.Direct(cfg.Upstream, nil),
		artifacts.Proxy(cfg.Socks, cfg.Upstream, proxyHealthy(runner)),
	}
	fetch := append([]artifacts.Source(nil), upstream...)
	for _, m := range cfg.Mirrors {
		fetch = append(fetch, artifacts.Mirror(m, nil))
	}
	fetch = append(fetch, artifacts.Inbox(filepath.Join(cfg.Data, "inbox")))
	return &artifacts.CoreUpdater{
		Data:   cfg.Data,
		Arch:   cfg.Arch,
		Fetch:  artifacts.Chain{Sources: fetch},
		Verify: artifacts.Verifier{Upstream: artifacts.Chain{Sources: upstream}, IndexURLs: cfg.IndexURLs, IndexPub: pub},
		Runner: runner,
		Health: artifacts.AllOf(
			artifacts.SOCKSProbe{Addr: cfg.Socks, URL: cfg.ProbeURL, Timeout: probeTimeout},
			artifacts.XrayAPIProbe{Runner: runner},
		),
		Log: log,
	}, nil
}

// writeFileAtomic replaces path with data so that a crash leaves either the
// old file or the new one: it writes a temporary file in the same directory,
// sets its mode, fsyncs it, renames it over path and fsyncs the directory.
func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(perm); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

// removeFileDurably removes path, then fsyncs its directory so that the
// removal survives a crash. A missing file is not an error.
func removeFileDurably(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// syncDir fsyncs a directory so that the entries made or removed in it survive
// a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
