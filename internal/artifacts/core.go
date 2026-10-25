package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/xrayver"
)

// Outcomes of an update besides the runner's trial outcomes.
const (
	OutcomeUnhealthy = "unhealthy" // the health check failed and the trial was aborted
	OutcomeNoop      = "noop"      // the core and config were already active
	OutcomeRefused   = "refused"   // no trial ran; Detail says why
)

const (
	defaultKeep          = 2
	defaultTrialDeadline = 120 * time.Second
	defaultEarlyExit     = 10 * time.Second
	defaultHealthWindow  = 30 * time.Second
	// trialMargin is how much longer than TrialDeadline the trial call may
	// take; the runner bounds xray run -test by the deadline.
	trialMargin = 30 * time.Second
	// cleanupTimeout bounds the calls that clean up after a failure, which
	// run even once the caller's context has ended.
	cleanupTimeout = 10 * time.Second
)

// ErrLocked means another update or rollback holds the artifacts lock.
var ErrLocked = errors.New("artifacts: another core update or rollback is running")

// CoreUpdater switches the runner to another xray-core: fetch, verify,
// install into a slot, runner trial, health check, then commit or let the
// trial revert (§4.5). Zero durations and Keep take the defaults.
type CoreUpdater struct {
	Data string // the data root: cores/, run/ and state/ are in it
	Arch string // GOARCH of the cores to fetch; empty means runtime.GOARCH
	// Fetch is where release zips come from.
	Fetch Chain
	// Verify finds the SHA-256 a zip must have. Its Upstream must hold only
	// Direct and Proxy sources, never a mirror or the inbox, so that the
	// .dgst always comes from upstream (§4.3).
	Verify Verifier
	// Runner is the runner's control API. Trial is called through a copy
	// whose HTTP timeout covers TrialDeadline plus a margin, since the
	// runner answers it only after xray run -test.
	Runner *runnerapi.Client
	// Health must pass, through the candidate, before a commit. So must the
	// runner's data path: its status must show the candidate's routes in
	// place and its gateway up.
	Health        HealthChecker
	Keep          int           // committed versions whose slots a commit keeps (2)
	TrialDeadline time.Duration // how long the runner waits for the commit (120 s)
	EarlyExit     time.Duration // wait after the candidate starts, before checking on it (10 s)
	HealthWindow  time.Duration // how long the health check may keep failing (30 s)
	Now           func() time.Time
	Log           io.Writer // progress lines; nil drops them
}

// UpdateOptions are the choices of one Update.
type UpdateOptions struct {
	// ConfigFile is an xray config to run the core with; empty keeps the
	// active one.
	ConfigFile string
	// AllowUnverified lets a zip whose SHA-256 nobody knows be installed. Such
	// a zip is taken only from Fetch's Inbox sources: the consent is for a
	// manual upload, never for an unverified download.
	AllowUnverified bool
}

// Result is what an update or rollback did; it is also the line it adds to
// state/core-history.jsonl.
type Result struct {
	From     string    `json:"from,omitempty"`
	To       string    `json:"to"`
	Outcome  string    `json:"outcome"`
	Source   string    `json:"source,omitempty"`
	Verified string    `json:"verified,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	At       time.Time `json:"at"`
}

// Update switches the runner to xray-core version, "latest" or a release
// such as 26.10.21. It holds the artifacts lock throughout, records the
// Result in the history, and returns an error with every outcome but
// committed and noop.
func (u *CoreUpdater) Update(ctx context.Context, version string, o UpdateOptions) (Result, error) {
	res := Result{To: version}
	return u.locked(&res, func() error { return u.update(ctx, version, o, &res) })
}

// Rollback switches the runner, through the same trial, to the most recently
// committed core in the history that differs from the active one and is
// still installed, with the active config. With none it refuses.
func (u *CoreUpdater) Rollback(ctx context.Context) (Result, error) {
	var res Result
	return u.locked(&res, func() error { return u.rollback(ctx, &res) })
}

// locked runs fn, which fills in res, under the artifacts lock, then records res.
func (u *CoreUpdater) locked(res *Result, fn func() error) (Result, error) {
	if u.Data == "" { // there is nowhere to record anything
		err := errors.New("artifacts: CoreUpdater.Data is not set")
		res.Outcome, res.Detail, res.At = OutcomeRefused, err.Error(), u.now()
		return *res, err
	}
	// fn must run before *res is read: the order of the two in one call's
	// arguments is unspecified.
	unlock, err := lockState(u.stateDir())
	if err != nil {
		err = refuse(res, err)
	} else {
		defer unlock() // after record, so the history line is written under the lock
		err = fn()
	}
	return u.record(*res, err)
}

func (u *CoreUpdater) update(ctx context.Context, version string, o UpdateOptions, res *Result) error {
	if err := u.ready(); err != nil {
		return refuse(res, err)
	}
	var v xrayver.Version
	var err error
	if version == "latest" {
		v, err = Latest(ctx, u.Verify.Upstream.Sources...)
	} else {
		v, err = xrayver.Parse(version)
	}
	if err != nil {
		return refuse(res, err)
	}
	res.To = v.String()
	if v.Less(xrayver.MinTUN) {
		return refuse(res, fmt.Errorf("xray-core %s is older than %s, the first release with the TUN inbound", v, xrayver.MinTUN))
	}
	active, err := u.active(ctx)
	if err != nil {
		return refuse(res, err)
	}
	cfg, err := readConfig(o.ConfigFile)
	if err != nil {
		return refuse(res, err)
	}
	sel := runnerapi.Selection{Core: v.String()}
	if active != nil {
		res.From = active.Core
		sel.Geo, sel.Config = active.Geo, active.Config
	}
	if cfg != nil {
		sel.Config = cfg.rel
	}
	switch {
	case sel.Config == "":
		return refuse(res, errors.New("no config: the runner has no active selection to take it from, and no config file was given"))
	case active != nil && sel == *active:
		res.Outcome, res.Detail = OutcomeNoop, "already active"
		return nil
	}
	slot, err := u.slotFor(ctx, v, o.AllowUnverified)
	if err != nil {
		return refuse(res, err)
	}
	res.Source, res.Verified = slot.Meta.Source, slot.Meta.Verified
	if cfg != nil {
		if err := cfg.write(u.runDir()); err != nil {
			return refuse(res, err)
		}
	}
	return u.trial(ctx, sel, res)
}

func (u *CoreUpdater) rollback(ctx context.Context, res *Result) error {
	if err := u.ready(); err != nil {
		return refuse(res, err)
	}
	active, err := u.active(ctx)
	if err != nil {
		return refuse(res, err)
	}
	if active == nil {
		return refuse(res, errors.New("nothing to roll back: the runner has no active core"))
	}
	res.From = active.Core
	h, err := readHistory(u.historyPath())
	if err != nil {
		return refuse(res, err)
	}
	slots, err := ListCores(u.coresDir())
	if err != nil {
		return refuse(res, err)
	}
	installed := map[string]Slot{}
	for _, s := range slots {
		installed[s.Version.String()] = s
	}
	for _, v := range committedVersions(h) {
		s, ok := installed[v]
		if v == active.Core || !ok {
			continue
		}
		res.To, res.Source, res.Verified = v, s.Meta.Source, s.Meta.Verified
		return u.trial(ctx, runnerapi.Selection{Core: v, Geo: active.Geo, Config: active.Config}, res)
	}
	return refuse(res, fmt.Errorf("nothing to roll back to: the history has no committed core other than %s that is still installed", active.Core))
}

// ready refuses an updater that lacks what every update needs.
func (u *CoreUpdater) ready() error {
	switch {
	case u.Runner == nil:
		return errors.New("artifacts: CoreUpdater.Runner is not set")
	case u.Health == nil:
		return errors.New("artifacts: CoreUpdater.Health is not set")
	}
	return nil
}

// active returns the runner's active selection, nil when it has none. An open
// trial is refused: under the lock it is none of ours, and candidate.json is
// its file until it ends, by its deadline at the latest.
func (u *CoreUpdater) active(ctx context.Context) (*runnerapi.Selection, error) {
	st, err := u.Runner.Status(ctx)
	if err != nil {
		return nil, err
	}
	if st.State == runnerapi.StateTrial {
		core := "?"
		if st.Candidate != nil {
			core = st.Candidate.Core
		}
		return nil, fmt.Errorf("%w: a trial of core %s is open", runnerapi.ErrBusy, core)
	}
	return st.Active, nil
}

// slotFor returns the installed slot of v. Without one it finds the zip's
// SHA-256, fetches a zip that has it into a temporary directory, and installs
// it. When nobody knows the hash, consent admits only a manual upload (§4.3):
// the zip comes from the chain's inbox sources alone and must be a core zip.
func (u *CoreUpdater) slotFor(ctx context.Context, v xrayver.Version, allowUnverified bool) (Slot, error) {
	slots, err := ListCores(u.coresDir())
	if err != nil {
		return Slot{}, err
	}
	for _, s := range slots {
		if s.Version == v {
			return s, nil
		}
	}
	file, err := xrayver.AssetName(u.arch())
	if err != nil {
		return Slot{}, err
	}
	r := Request{Version: v, File: file, Arch: u.arch()}
	chain := u.Fetch
	want, err := u.Verify.Expected(ctx, r)
	if errors.Is(err, ErrNoHash) {
		if !allowUnverified {
			return Slot{}, fmt.Errorf("%w; installing it unverified needs explicit consent", err)
		}
		chain = inboxOnly(u.Fetch)
		if len(chain.Sources) == 0 {
			return Slot{}, fmt.Errorf("%w; an unverified core is only installed from the inbox (a manual upload), and no inbox source is configured", err)
		}
		want, err = Verified{Method: "unverified"}, nil
	}
	if err != nil {
		return Slot{}, err
	}
	dir, err := os.MkdirTemp("", "tikray-core-")
	if err != nil {
		return Slot{}, err
	}
	defer os.RemoveAll(dir)
	zipPath := filepath.Join(dir, file)
	var sum string
	src, err := chain.Fetch(ctx, r, zipPath, func(path string) error {
		got, err := FileSHA256(path)
		if err != nil {
			return err
		}
		switch {
		case want.SHA256 == "":
			// Unverified: a file that cannot be installed must not end the chain.
			if err := checkCoreZip(path); err != nil {
				return err
			}
		case got != want.SHA256:
			return fmt.Errorf("SHA-256 is %s, the %s says %s", got, want.Method, want.SHA256)
		}
		sum = got
		return nil
	})
	if err != nil {
		return Slot{}, err
	}
	u.logf("xray-core %s: fetched %s from %s (%s)", v, file, src, want.Method)
	return InstallCore(u.coresDir(), v, zipPath, Meta{Source: src, ZipSHA256: sum, Verified: want.Method, InstalledAt: u.now()})
}

// inboxOnly returns c with only its Inbox sources.
func inboxOnly(c Chain) Chain {
	var keep []Source
	for _, s := range c.Sources {
		if _, ok := s.(inbox); ok {
			keep = append(keep, s)
		}
	}
	c.Sources = keep
	return c
}

// trial puts sel on trial and drives it to its end. A commit prunes the slots.
func (u *CoreUpdater) trial(ctx context.Context, sel runnerapi.Selection, res *Result) error {
	if err := sel.Validate(); err != nil {
		return refuse(res, err)
	}
	cand := runnerapi.Candidate{Selection: sel, Deadline: u.now().Add(u.trialDeadline())}
	if err := os.MkdirAll(u.runDir(), 0o755); err != nil {
		return refuse(res, err)
	}
	if err := writeJSONAtomic(u.candidatePath(), cand); err != nil {
		return refuse(res, err)
	}
	u.logf("xray-core %s: trial until %s", sel.Core, cand.Deadline.Format(time.RFC3339))
	var err error
	res.Outcome, res.Detail, err = u.drive(ctx, cand)
	if res.Outcome == runnerapi.OutcomeCommitted {
		u.prune(res)
	}
	return err
}

// drive runs the trial of cand, already in candidate.json, and returns its
// outcome, the detail and the error behind it, if any.
func (u *CoreUpdater) drive(ctx context.Context, cand runnerapi.Candidate) (string, string, error) {
	limit := u.trialDeadline() + trialMargin
	tctx, cancel := context.WithTimeout(ctx, limit)
	err := withTimeout(u.Runner, limit).Trial(tctx)
	cancel()
	var tf *runnerapi.TestFailedError
	switch {
	case errors.As(err, &tf):
		return runnerapi.OutcomeRejected, tf.Output, err
	case errors.Is(err, runnerapi.ErrBusy):
		return OutcomeRefused, "another trial is open", err
	case err != nil:
		return u.unstarted(ctx, cand, err)
	}

	if err := sleep(ctx, u.earlyExit()); err != nil {
		return u.abort(ctx, cand, runnerapi.OutcomeAborted, err)
	}
	st, err := u.Runner.Status(ctx)
	if err != nil {
		return u.abort(ctx, cand, runnerapi.OutcomeAborted, err)
	}
	if !onTrial(st, cand) {
		if o, d, ok := recorded(st, cand); ok {
			return o, d, nil
		}
		return runnerapi.OutcomeExited, "the candidate is no longer on trial, and the runner recorded no outcome for it", nil
	}

	if err := u.healthy(ctx, cand); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return u.abort(ctx, cand, runnerapi.OutcomeAborted, fmt.Errorf("%w during the health check", cerr))
		}
		return u.abort(ctx, cand, OutcomeUnhealthy, err)
	}
	err = u.Runner.Commit(ctx)
	if err == nil {
		return runnerapi.OutcomeCommitted, "", nil
	}
	// The trial may have ended before the commit arrived (no_trial), or the
	// commit may have happened and only its answer been lost.
	cctx, cancel := cleanupContext(ctx)
	defer cancel()
	if st, serr := u.Runner.Status(cctx); serr == nil {
		if o, d, ok := recorded(st, cand); ok {
			return o, d, nil
		}
	}
	return u.abort(ctx, cand, runnerapi.OutcomeAborted, fmt.Errorf("commit: %w", err))
}

// unstarted handles a trial call that failed for a reason the runner did not
// name. The outcome is the runner's record of cand when it has one, and a
// trial of cand that is open after all is aborted. Otherwise the trial never
// started, and candidate.json is removed so that the runner's next boot does
// not count it as a trial the reboot ended.
func (u *CoreUpdater) unstarted(ctx context.Context, cand runnerapi.Candidate, err error) (string, string, error) {
	cctx, cancel := cleanupContext(ctx)
	defer cancel()
	st, serr := u.Runner.Status(cctx)
	if serr != nil {
		return OutcomeRefused, err.Error(), err
	}
	if onTrial(st, cand) {
		return u.abort(ctx, cand, runnerapi.OutcomeAborted, err)
	}
	if o, d, ok := recorded(st, cand); ok {
		return o, d, err
	}
	if st.State != runnerapi.StateTrial {
		if rerr := removeSynced(u.candidatePath()); rerr != nil {
			u.logf("artifacts: %v", rerr)
		}
	}
	return OutcomeRefused, err.Error(), err
}

// abort ends the open trial of cand and reports outcome, because of why. When
// no trial is left to abort, the runner's record of how cand's ended is the
// outcome instead.
func (u *CoreUpdater) abort(ctx context.Context, cand runnerapi.Candidate, outcome string, why error) (string, string, error) {
	cctx, cancel := cleanupContext(ctx)
	defer cancel()
	err := u.Runner.Abort(cctx)
	switch {
	case err == nil:
		return outcome, why.Error(), why
	case errors.Is(err, runnerapi.ErrNoTrial):
		if st, serr := u.Runner.Status(cctx); serr == nil {
			if o, d, ok := recorded(st, cand); ok {
				return o, d, nil
			}
		}
		return outcome, why.Error(), why
	}
	return outcome, fmt.Sprintf("%v; the abort failed, so the runner reverts at the deadline: %v", why, err), why
}

// healthy retries the health check of cand until it passes or HealthWindow
// ends, and returns the last failure. The check is the runner's data path
// (see dataPath), then Health.
func (u *CoreUpdater) healthy(ctx context.Context, cand runnerapi.Candidate) error {
	window := u.healthWindow()
	hctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	retry := min(time.Second, window/10)
	for {
		err := u.dataPath(hctx, cand)
		if err == nil {
			err = u.Health.Check(hctx)
		}
		if err == nil {
			return nil
		}
		if sleep(hctx, retry) != nil {
			return fmt.Errorf("health check failing for %s: %w", window, err)
		}
	}
}

// dataPath checks, from the runner's status, that cand is on trial with its
// routes into xray0 in place and its gateway up (it answers ping). Health's
// probes pass without xray0, but a runner whose gateway is down sends
// fail-open devices direct and blackholes the kill-switch ones.
func (u *CoreUpdater) dataPath(ctx context.Context, cand runnerapi.Candidate) error {
	st, err := u.Runner.Status(ctx)
	switch {
	case err != nil:
		return err
	case !onTrial(st, cand):
		return errors.New("the candidate is no longer on trial")
	case !st.RoutesOK:
		return errors.New("the runner's routes into xray0 are not in place")
	case !st.GatewayUp:
		return errors.New("the runner's gateway is down: it does not answer ping")
	}
	return nil
}

// prune removes the slots of all but the Keep most recently committed cores.
// res, just committed, is not in the history yet. A failure is noted in res
// without undoing the commit.
func (u *CoreUpdater) prune(res *Result) {
	h, err := readHistory(u.historyPath())
	if err != nil {
		res.Detail = "old cores were not pruned: " + err.Error()
		return
	}
	keep := committedVersions(append(h, *res))
	keep = keep[:min(len(keep), u.keep())]
	removed, err := Prune(u.coresDir(), keep)
	if len(removed) > 0 {
		u.logf("xray-core %s: removed the cores %s", res.To, strings.Join(removed, ", "))
	}
	if err != nil {
		res.Detail = "pruning old cores: " + err.Error()
	}
}

// record stamps res, appends it to the history and gives a failed outcome
// its error, which wraps cause when there is one.
func (u *CoreUpdater) record(res Result, cause error) (Result, error) {
	res.At = u.now()
	var err error
	switch {
	case res.Outcome == runnerapi.OutcomeCommitted || res.Outcome == OutcomeNoop:
	case cause != nil:
		err = fmt.Errorf("%s: %w", res.Outcome, cause)
	case res.Detail != "":
		err = fmt.Errorf("%s: %s", res.Outcome, res.Detail)
	default:
		err = errors.New(res.Outcome)
	}
	if res.Detail != "" {
		u.logf("xray-core %s: %s: %s", res.To, res.Outcome, res.Detail)
	} else {
		u.logf("xray-core %s: %s", res.To, res.Outcome)
	}
	if herr := appendHistory(u.historyPath(), res); herr != nil {
		err = errors.Join(err, fmt.Errorf("artifacts: recording the result: %w", herr))
	}
	return res, err
}

// refuse makes res a refusal because of err, and returns err.
func refuse(res *Result, err error) error {
	res.Outcome, res.Detail = OutcomeRefused, err.Error()
	return err
}

// onTrial reports whether the runner has cand on trial.
func onTrial(st runnerapi.Status, cand runnerapi.Candidate) bool {
	return st.State == runnerapi.StateTrial && st.Candidate != nil && sameCandidate(*st.Candidate, cand)
}

// recorded returns how the trial of cand ended, from the runner's status: the
// outcome it recorded, or committed when cand's selection is active (a core
// that died in the commit's fsyncs can show as restarting). ok is false while
// cand is on trial and when the runner knows nothing of it.
func recorded(st runnerapi.Status, cand runnerapi.Candidate) (outcome, detail string, ok bool) {
	switch {
	case onTrial(st, cand):
		return "", "", false
	case st.LastTrial != nil && sameCandidate(st.LastTrial.Candidate, cand):
		return st.LastTrial.Outcome, st.LastTrial.Detail, true
	case st.Active != nil && *st.Active == cand.Selection:
		return runnerapi.OutcomeCommitted, "", true
	}
	return "", "", false
}

func sameCandidate(a, b runnerapi.Candidate) bool {
	return a.Selection == b.Selection && a.Deadline.Equal(b.Deadline)
}

// config is a config file to put on trial and its name under run/.
type config struct {
	data []byte
	rel  string // config/<sha256>.json
}

// readConfig reads the config file at path; an empty path gives nil.
func readConfig(path string) (*config, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return &config{data: data, rel: "config/" + hex.EncodeToString(sum[:]) + ".json"}, nil
}

func (c *config) write(runDir string) error {
	if err := os.MkdirAll(filepath.Join(runDir, "config"), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(runDir, c.rel), c.data, 0o644)
}

// writeJSONAtomic writes v as indented JSON, mode 0644, with writeFileAtomic.
func writeJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'), 0o644)
}

// writeFileAtomic replaces path with data so that a crash leaves either the
// old file or the new one: it writes a temporary file in the same directory,
// fsyncs it, renames it over path and fsyncs the directory.
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

// removeSynced removes path durably; a missing file is not an error.
func removeSynced(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// cleanupContext is for the calls that clean up after a failure: they run
// even when ctx has ended, for at most cleanupTimeout.
func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
}

// sleep waits d, or until ctx ends.
func sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (u *CoreUpdater) logf(format string, args ...any) {
	if u.Log != nil {
		fmt.Fprintf(u.Log, format+"\n", args...)
	}
}

func (u *CoreUpdater) coresDir() string      { return filepath.Join(u.Data, "cores") }
func (u *CoreUpdater) runDir() string        { return filepath.Join(u.Data, "run") }
func (u *CoreUpdater) stateDir() string      { return filepath.Join(u.Data, "state") }
func (u *CoreUpdater) candidatePath() string { return filepath.Join(u.runDir(), "candidate.json") }
func (u *CoreUpdater) historyPath() string   { return filepath.Join(u.stateDir(), historyName) }

func (u *CoreUpdater) arch() string {
	if u.Arch != "" {
		return u.Arch
	}
	return runtime.GOARCH
}

func (u *CoreUpdater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *CoreUpdater) keep() int { return orDefault(u.Keep, defaultKeep) }

func (u *CoreUpdater) trialDeadline() time.Duration {
	return orDefault(u.TrialDeadline, defaultTrialDeadline)
}

func (u *CoreUpdater) earlyExit() time.Duration { return orDefault(u.EarlyExit, defaultEarlyExit) }

func (u *CoreUpdater) healthWindow() time.Duration {
	return orDefault(u.HealthWindow, defaultHealthWindow)
}

// orDefault is v, or def when v is not positive.
func orDefault[T int | time.Duration](v, def T) T {
	if v > 0 {
		return v
	}
	return def
}
