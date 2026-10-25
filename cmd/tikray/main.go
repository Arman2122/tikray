// Command tikray is the control plane's command line. It renders the xray
// config from the state and drives xray-core updates; the daemon, REST API and
// UI come with M2b.
//
//	tikray config render [--core VER]
//	tikray apply
//	tikray core update <version|latest> [--config FILE] [--allow-unverified]
//	tikray core rollback
//	tikray core list [--json]
//	tikray core status
//
// config render prints the config the state renders to, for xray-core VER
// (default: the runner's active core). It only reads: the one thing it may
// write to the data root is the empty state directory a fresh install lacks.
//
// apply, update and rollback print their result as JSON on stdout, save it to
// <data>/state/last-result.json, and exit 0 if the config or core was
// committed or already active and 1 otherwise. Progress and errors go to
// stderr. Usage errors exit 2.
//
// They remove the previous last-result.json as soon as the data root is ready,
// so the file is always this run's result or absent. A failure before the
// updater runs, such as an unreadable runner token, is saved as a refused
// result. A run that is killed leaves no file.
//
// apply puts the config rendered from the state on trial with the active
// core. update and rollback run the core they switch to with the config
// rendered from the state, unless update is given a --config file; updating to
// the core that is active therefore trials the new render if the state has
// changed. Until a state file is saved the state is the default one, whose
// render sends all traffic direct: they then refuse to put that render in
// place of another config the runner runs, such as one an update ran with
// --config. A runner with no core yet starts from it.
//
// The state is <data>/state. A command reads it once and never writes it; the
// daemon owns it. A state that cannot be read fails the command, except
// update --config and core status, which only take the runner's addresses
// from it: they go on with a warning, using the addresses of a fresh install
// where no variable names them. config render, which has nothing to render
// then, says that the state can't be read before it asks the runner anything.
//
// Environment (see Config): TIKRAY_DATA, TIKRAY_ARCH, TIKRAY_RUNNER_URL,
// TIKRAY_SOCKS, TIKRAY_XRAY_API, TIKRAY_UPSTREAM, TIKRAY_MIRRORS,
// TIKRAY_INDEX_URLS, TIKRAY_INDEX_PUBKEY_FILE, TIKRAY_PROBE_URL. The runner's
// three addresses default to its address on the state's private subnet, and
// the probe URL to the state's health.probe_url.
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
	"github.com/Arman2122/tikray/internal/atomicfile"
	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xrayver"
)

const (
	lastResultName = "last-result.json"
	// probeTimeout bounds one SOCKS health probe.
	probeTimeout = 10 * time.Second
)

const usageText = `usage: tikray <command> [flags]

commands:
  config render [--core VER]
                 print the xray config rendered from the state, for xray-core
                 VER (default: the runner's active core)
  apply          render the config from the state for the active core and put
                 it on trial
  core update <version|latest> [--config FILE] [--allow-unverified]
                 switch the runner to another xray-core, on a trial. Without
                 --config the config is rendered from the state for the target
                 core, so updating to the version already active re-renders
                 and trials the config when the state changed.
  core rollback  switch back to the previously committed core, with a config
                 rendered from the state
  core list [--json]
                 list the installed cores
  core status    print the runner's status as JSON

Configuration comes from the environment: TIKRAY_DATA, TIKRAY_ARCH,
TIKRAY_RUNNER_URL, TIKRAY_SOCKS, TIKRAY_XRAY_API, TIKRAY_UPSTREAM,
TIKRAY_MIRRORS, TIKRAY_INDEX_URLS, TIKRAY_INDEX_PUBKEY_FILE and
TIKRAY_PROBE_URL. The runner's addresses default to the one the state's
private subnet gives it, and the probe URL to the state's.
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
	// tune, if set, adjusts the CoreUpdater before it runs. Only tests set it,
	// to shorten the waits of a trial.
	tune func(*artifacts.CoreUpdater)
}

// run executes the command line args (without the program name) and returns
// the exit code: 0 for success, 1 for a failure, 2 for a usage error.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	c := &cli{getenv: getenv, stdout: stdout, stderr: stderr}
	return c.run(ctx, args)
}

func (c *cli) run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return c.usageError("")
	}
	switch args[0] {
	case "help", "-h", "--help":
		io.WriteString(c.stdout, usageText)
		return 0
	case "config":
		return c.config(ctx, args[1:])
	case "apply":
		return c.apply(ctx, args[1:])
	case "core":
		return c.core(ctx, args[1:])
	}
	return c.usageError(fmt.Sprintf("unknown command %q", args[0]))
}

func (c *cli) config(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return c.usageError("")
	}
	switch args[0] {
	case "render":
		return c.configRender(ctx, args[1:])
	case "help", "-h", "--help":
		io.WriteString(c.stdout, usageText)
		return 0
	}
	return c.usageError(fmt.Sprintf("unknown config command %q", args[0]))
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

// newFlagSet is the FlagSet of one subcommand, such as "core update"; usage is
// the synopsis after "tikray ".
func (c *cli) newFlagSet(name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet("tikray "+name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: tikray %s\n", usage)
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
	fs := c.newFlagSet("core update", "core update <version|latest> [--config FILE] [--allow-unverified]")
	configFile := fs.String("config", "", "run the core with the xray config in `FILE`. Without --config the config is rendered from the state for the target core, so updating to the version already active re-renders and trials the config when the state changed.")
	allow := fs.Bool("allow-unverified", false, "install a core whose SHA-256 nobody knows, if it is in the inbox")
	pos, code, ok := c.parse(fs, args, 1)
	if !ok {
		return code
	}
	return c.runUpdater(ctx, artifacts.Result{To: pos[0]}, *configFile == "", func(ctx context.Context, u *artifacts.CoreUpdater) (artifacts.Result, error) {
		return u.Update(ctx, pos[0], artifacts.UpdateOptions{ConfigFile: *configFile, AllowUnverified: *allow})
	})
}

func (c *cli) rollback(ctx context.Context, args []string) int {
	fs := c.newFlagSet("core rollback", "core rollback")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	return c.runUpdater(ctx, artifacts.Result{}, true, func(ctx context.Context, u *artifacts.CoreUpdater) (artifacts.Result, error) {
		return u.Rollback(ctx)
	})
}

func (c *cli) apply(ctx context.Context, args []string) int {
	fs := c.newFlagSet("apply", "apply")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	return c.runUpdater(ctx, artifacts.Result{Kind: artifacts.KindConfig}, true, func(ctx context.Context, u *artifacts.CoreUpdater) (artifacts.Result, error) {
		return u.Apply(ctx)
	})
}

// runUpdater builds the updater, runs do and reports its result. base is what
// a refusal before the updater runs keeps of the result: the version asked
// for, or the Kind of an apply. fromState is whether the config is rendered
// from the state, as opposed to named by the user (update --config).
//
// Once the data root is known to be usable, the previous last-result.json is
// removed, before anything else can fail. From then on the file is either
// this run's result or absent, so that a reader never mistakes an older run
// for this one: a failure in setup, such as a state that cannot be read, leaves
// a refused result, and a run that is killed leaves none. Only a bad
// environment or an unusable data root leave the file as it was; there is no
// place to write one.
//
// The state is read once, and the render, the health checks and the runner's
// addresses all follow that one snapshot. With a config file (not fromState)
// the state supplies the addresses alone, and one that cannot be read is
// replaced, with a warning, by the default state.
func (c *cli) runUpdater(ctx context.Context, base artifacts.Result, fromState bool, do func(context.Context, *artifacts.CoreUpdater) (artifacts.Result, error)) int {
	cfg, err := configFromEnv(c.getenv)
	if err != nil {
		return c.fail(err)
	}
	if err := prepareDirs(cfg.Data); err != nil {
		return c.fail(err)
	}
	if err := removeFileDurably(filepath.Join(stateDir(cfg.Data), lastResultName)); err != nil {
		return c.refused(cfg, base, fmt.Errorf("removing the previous result: %w", err))
	}
	var st store.State
	var rev uint64
	if fromState {
		if st, rev, err = readState(cfg.Data); err != nil {
			return c.refused(cfg, base, err)
		}
	} else {
		// With a config file of its own the update needs the state for
		// nothing but the runner's default addresses. A state that cannot be
		// read must not stand in the way of M1's recovery path.
		st = c.addressState(cfg.Data)
	}
	cfg = cfg.withState(st)
	runner, err := newRunner(cfg)
	if err != nil {
		return c.refused(cfg, base, err)
	}
	// All the probes run for a config file, as in M1. The config rendered from
	// the state sends socks-in to block while no server is there, so its SOCKS
	// probe could only fail.
	var rend artifacts.Renderer
	socks := true
	if fromState {
		rend, socks = stateRenderer(st), render.ProxyAvailable(st)
	}
	u, err := newUpdater(cfg, runner, c.stderr, rend, socks)
	if err != nil {
		return c.refused(cfg, base, err)
	}
	// Revision 0 is no state file: the render is the default state's, which
	// must not replace a config the runner already runs.
	u.NoState = fromState && rev == 0
	if c.tune != nil {
		c.tune(u)
	}
	res, err := do(ctx, u)
	return c.report(cfg, res, err)
}

// addressState is the state of a command that needs it for nothing but the
// runner's addresses: the state in data, or, when that cannot be read, the
// default state, after one warning on stderr that names the problem. The
// command then goes on with the addresses of a fresh install where no
// variable names them.
func (c *cli) addressState(data string) store.State {
	st, _, err := readState(data)
	if err != nil {
		fmt.Fprintf(c.stderr, "tikray: warning: %s; taking the runner's default addresses from the default state\n",
			strings.ReplaceAll(err.Error(), "\n", "; "))
		return store.Default()
	}
	return st
}

// refused reports a refusal that no CoreUpdater made, because the command
// failed before it could run: the result is not in the history, which is the
// updater's. base is the result as far as the command knows it.
func (c *cli) refused(cfg Config, base artifacts.Result, err error) int {
	res := base
	res.Outcome, res.Detail, res.At = artifacts.OutcomeRefused, err.Error(), time.Now()
	return c.report(cfg, res, err)
}

// configRender prints the config the state renders to. It is a read: it
// neither writes the state nor touches the rest of the data root.
func (c *cli) configRender(ctx context.Context, args []string) int {
	fs := c.newFlagSet("config render", "config render [--core VER]")
	var core *xrayver.Version
	fs.Func("core", "render for xray-core `VER` (default: the runner's active core)", func(s string) error {
		v, err := xrayver.Parse(s)
		if err != nil {
			return err
		}
		core = &v
		return nil
	})
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	cfg, st, err := loadConfig(c.getenv)
	if err != nil {
		return c.fail(err)
	}
	if core == nil {
		v, err := activeCore(ctx, cfg)
		if err != nil {
			return c.fail(fmt.Errorf("no --core given, and the runner's active core is unknown: %w", err))
		}
		core = &v
	}
	out, err := renderConfig(st, *core, "")
	if err != nil {
		return c.fail(err)
	}
	if _, err := c.stdout.Write(out); err != nil {
		return c.fail(err)
	}
	return 0
}

// activeCore is the xray-core the runner has active.
func activeCore(ctx context.Context, cfg Config) (xrayver.Version, error) {
	runner, err := newRunner(cfg)
	if err != nil {
		return xrayver.Version{}, err
	}
	st, err := runner.Status(ctx)
	if err != nil {
		return xrayver.Version{}, err
	}
	if st.Active == nil {
		return xrayver.Version{}, errors.New("the runner has no active core")
	}
	return xrayver.Parse(st.Active.Core)
}

// renderConfig is the xray config st renders to for core and the geo bundle
// geo. Nothing installs geo bundles before M3, so any name is refused and the
// empty one, none, is rendered with no geo data.
func renderConfig(st store.State, core xrayver.Version, geo string) ([]byte, error) {
	if geo != "" {
		return nil, fmt.Errorf("geo bundles are not supported yet (the selection names %q)", geo)
	}
	return render.Render(render.Input{State: st, Core: core})
}

// stateRenderer is the Renderer of the state as it was read.
func stateRenderer(st store.State) artifacts.Renderer {
	return func(core xrayver.Version, geo string) ([]byte, error) {
		return renderConfig(st, core, geo)
	}
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
	path := filepath.Join(stateDir(cfg.Data), lastResultName)
	if werr := atomicfile.WriteFile(path, b, 0o600); werr != nil {
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
	fs := c.newFlagSet("core list", "core list [--json]")
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
	fs := c.newFlagSet("core status", "core status")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	cfg, err := configFromEnv(c.getenv)
	if err != nil {
		return c.fail(err)
	}
	runner, err := newRunner(cfg.withState(c.addressState(cfg.Data)))
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
// artifacts work. What a killed run leaves in state/tmp is removed by the
// next update or rollback, once it holds the artifacts lock (never before, so
// a concurrent update's files are not touched).
func prepareDirs(data string) error {
	tmp := filepath.Join(stateDir(data), "tmp")
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

// healthChecks are the probes an update must pass: the proxy carries traffic
// (when socks is set) and xray's API answers. The SOCKS probe is left out
// while the config sends socks-in to block, which it does when it has no
// server to proxy through.
func healthChecks(cfg Config, runner *runnerapi.Client, socks bool) []artifacts.HealthChecker {
	var checks []artifacts.HealthChecker
	if socks {
		checks = append(checks, artifacts.SOCKSProbe{Addr: cfg.Socks, URL: cfg.ProbeURL, Timeout: probeTimeout})
	}
	return append(checks, artifacts.XrayAPIProbe{Runner: runner, Server: cfg.XrayAPI})
}

// newUpdater wires the CoreUpdater of §4: the fetch chain in the order of
// §4.2 (direct, the proxy, the mirrors, the inbox), a verifier whose .dgst
// only ever comes from upstream (§4.3), and a health check that needs the
// proxy to carry traffic (if socks) and xray's API to answer. rend renders the
// config of an update, rollback or apply; nil leaves an update to its --config
// file.
func newUpdater(cfg Config, runner *runnerapi.Client, log io.Writer, rend artifacts.Renderer, socks bool) (*artifacts.CoreUpdater, error) {
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
		Render: rend,
		Health: artifacts.AllOf(healthChecks(cfg, runner, socks)...),
		Log:    log,
	}, nil
}

// removeFileDurably removes path, then fsyncs its directory so that the
// removal survives a crash. A missing file is not an error.
func removeFileDurably(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicfile.SyncDir(filepath.Dir(path))
}
