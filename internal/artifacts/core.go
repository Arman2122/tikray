package artifacts

import (
	"cmp"
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
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/atomicfile"
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

// KindConfig is the Kind of the Result of Apply.
const KindConfig = "config"

// keepConfigs is how many configs, besides the committed one, a commit keeps
// in run/config/.
const keepConfigs = 4

// configFileRE matches the name of a config file in run/config/, the one
// runnerapi.Selection.Validate asks of a Config.
var configFileRE = regexp.MustCompile(`^[0-9a-f]{64}\.json$`)

// Renderer renders the xray config for core and the geo slot geo (empty for
// none) from the desired state.
type Renderer func(core xrayver.Version, geo string) ([]byte, error)

// CoreUpdater switches the runner to another xray-core: fetch, verify,
// install into a slot, render its config, runner trial, health check, then
// commit or let the trial revert (§4.5). Zero durations and Keep take the
// defaults.
type CoreUpdater struct {
	// Data is the data root: cores/, run/ and state/ are in it. state/tmp is
	// for the temporary files of updates alone, and an update empties it
	// once it holds the artifacts lock.
	Data string
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
	// Render makes the config an update or rollback runs the core with, and the
	// one Apply puts on trial. Nil keeps the active config for a core change,
	// unless the update names a config file, and refuses Apply.
	Render Renderer
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
	// ConfigFile is an xray config to run the core with; empty takes the
	// render for the core if there is a Renderer, and keeps the active config
	// if not.
	ConfigFile string
	// AllowUnverified lets a zip whose SHA-256 nobody knows be installed. Such
	// a zip is taken only from Fetch's Inbox sources: the consent is for a
	// manual upload, never for an unverified download. A core installed that
	// way needs it again on every later update to it, while its hash is
	// still unknown.
	AllowUnverified bool
}

// Result is what an update, rollback or Apply did; it is also the line it
// adds to state/core-history.jsonl.
type Result struct {
	From     string    `json:"from,omitempty"`
	To       string    `json:"to"`
	Outcome  string    `json:"outcome"`
	Kind     string    `json:"kind,omitempty"` // KindConfig for an Apply, empty for an update or rollback
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

// Apply renders the config for the active core and geo and puts it on trial
// through the same trial as an update. It does not fetch or verify the core,
// since that is the one running. It holds the artifacts lock throughout,
// records the Result (of Kind KindConfig) in the history, and returns an error
// with every outcome but committed and noop. With no Render, or no active
// core, it refuses.
func (u *CoreUpdater) Apply(ctx context.Context) (Result, error) {
	res := Result{Kind: KindConfig}
	return u.locked(&res, func() error { return u.apply(ctx, &res) })
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
		u.sweepTemp()
		err = fn()
	}
	return u.record(*res, err)
}

// sweepTemp empties state/tmp, where updates make their temporary files (the
// tikray CLI points TMPDIR at it). It runs under the lock, when no other
// update can be using it, so whatever is there was left by a run that was
// killed.
func (u *CoreUpdater) sweepTemp() {
	dir := filepath.Join(u.stateDir(), "tmp")
	ents, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		u.logf("artifacts: %v", err)
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			u.logf("artifacts: %v", err)
		}
	}
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
	sel := runnerapi.Selection{Core: v.String()}
	if active != nil {
		res.From = active.Core
		sel.Geo, sel.Config = active.Geo, active.Config
	}
	cfg, err := u.configFor(o.ConfigFile, v, sel.Geo)
	if err != nil {
		return refuse(res, err)
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
		sel := runnerapi.Selection{Core: v, Geo: active.Geo, Config: active.Config}
		if u.Render != nil {
			cfg, err := u.render(s.Version, active.Geo)
			if err == nil {
				err = cfg.write(u.runDir())
			}
			if err != nil {
				return refuse(res, err)
			}
			sel.Config = cfg.rel
		}
		return u.trial(ctx, sel, res)
	}
	return refuse(res, fmt.Errorf("nothing to roll back to: the history has no committed core other than %s that is still installed", active.Core))
}

func (u *CoreUpdater) apply(ctx context.Context, res *Result) error {
	if err := u.ready(); err != nil {
		return refuse(res, err)
	}
	if u.Render == nil {
		return refuse(res, errors.New("artifacts: CoreUpdater.Render is not set"))
	}
	active, err := u.active(ctx)
	if err != nil {
		return refuse(res, err)
	}
	if active == nil {
		return refuse(res, errors.New("no active core: install one with tikray core update"))
	}
	res.From, res.To = active.Core, active.Core
	v, err := xrayver.Parse(active.Core)
	if err != nil {
		return refuse(res, err)
	}
	cfg, err := u.render(v, active.Geo)
	if err != nil {
		return refuse(res, err)
	}
	if cfg.rel == active.Config {
		res.Outcome, res.Detail = OutcomeNoop, "already active"
		return nil
	}
	if err := cfg.write(u.runDir()); err != nil {
		return refuse(res, err)
	}
	return u.trial(ctx, runnerapi.Selection{Core: active.Core, Geo: active.Geo, Config: cfg.rel}, res)
}

// configFor returns the config an update to v puts on trial, nil for the
// active one: the file the caller named, else the render for v and geo if
// there is a Renderer.
func (u *CoreUpdater) configFor(file string, v xrayver.Version, geo string) (*config, error) {
	switch {
	case file != "":
		return readConfig(file)
	case u.Render != nil:
		return u.render(v, geo)
	}
	return nil, nil
}

// render renders the config for core v and geo, named by its content like a
// config file with the same bytes.
func (u *CoreUpdater) render(v xrayver.Version, geo string) (*config, error) {
	data, err := u.Render(v, geo)
	if err != nil {
		return nil, fmt.Errorf("artifacts: rendering the config for xray-core %s: %w", v, err)
	}
	return newConfig(data), nil
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

// slotFor returns the installed slot of v (see installed). Without one it
// finds the zip's SHA-256, fetches a zip that has it into a temporary
// directory, and installs it. When nobody knows the hash, consent admits only
// a manual upload (§4.3): the zip comes from the chain's inbox sources alone
// and must be a core zip.
func (u *CoreUpdater) slotFor(ctx context.Context, v xrayver.Version, allowUnverified bool) (Slot, error) {
	slots, err := ListCores(u.coresDir())
	if err != nil {
		return Slot{}, err
	}
	for _, s := range slots {
		if s.Version == v {
			return u.installed(ctx, s, allowUnverified)
		}
	}
	r, err := u.request(v)
	if err != nil {
		return Slot{}, err
	}
	file := r.File
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

// installed returns s, the slot already installed for its version. A slot
// that was installed unverified is used again only with consent, unless its
// zip's SHA-256 has become known since: it must then match, and the slot
// counts as verified for this update.
func (u *CoreUpdater) installed(ctx context.Context, s Slot, allowUnverified bool) (Slot, error) {
	if s.Meta.Verified != "unverified" {
		return s, nil
	}
	r, err := u.request(s.Version)
	if err != nil {
		return Slot{}, err
	}
	want, err := u.Verify.Expected(ctx, r)
	switch {
	case err == nil && want.SHA256 == s.Meta.ZipSHA256:
		s.Meta.Verified = want.Method
		return s, nil
	case err == nil:
		return Slot{}, fmt.Errorf("the installed core %s does not match the published hash: it was installed unverified from a zip with SHA-256 %s, and the %s says %s", s.Version, s.Meta.ZipSHA256, want.Method, want.SHA256)
	case errors.Is(err, ErrNoHash) && allowUnverified:
		return s, nil
	case errors.Is(err, ErrNoHash):
		return Slot{}, fmt.Errorf("%w; the installed core %s was installed unverified, and running it needs explicit consent", err, s.Version)
	}
	return Slot{}, err
}

// request names the release zip of v for the updater's architecture.
func (u *CoreUpdater) request(v xrayver.Version) (Request, error) {
	file, err := xrayver.AssetName(u.arch())
	if err != nil {
		return Request{}, err
	}
	return Request{Version: v, File: file, Arch: u.arch()}, nil
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

// trial puts sel on trial and drives it to its end. A commit prunes the slots
// and the configs.
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
		u.pruneConfigs(ctx, sel, res)
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
	if err := runsCore(st, cand.Core); err != nil {
		return u.abort(ctx, cand, OutcomeUnhealthy, err)
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
		note(res, "old cores were not pruned: "+err.Error())
		return
	}
	keep := committedVersions(append(h, *res))
	keep = keep[:min(len(keep), u.keep())]
	removed, err := Prune(u.coresDir(), keep)
	if len(removed) > 0 {
		u.logf("xray-core %s: removed the cores %s", res.To, strings.Join(removed, ", "))
	}
	if err != nil {
		note(res, "pruning old cores: "+err.Error())
	}
}

// pruneConfigs removes from run/config/ all but the committed config, sel's,
// and the keepConfigs most recently modified others. Never one the runner's
// active selection or an open candidate names, as its status shows. Only files
// named like a config count: anything else is left alone. A failure is noted
// in res without undoing the commit.
func (u *CoreUpdater) pruneConfigs(ctx context.Context, sel runnerapi.Selection, res *Result) {
	st, err := u.Runner.Status(ctx)
	if err != nil {
		note(res, "old configs were not pruned: "+err.Error())
		return
	}
	inUse := map[string]bool{sel.Config: true}
	if st.Active != nil {
		inUse[st.Active.Config] = true
	}
	if st.Candidate != nil {
		inUse[st.Candidate.Config] = true
	}
	dir := filepath.Join(u.runDir(), "config")
	ents, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		note(res, "old configs were not pruned: "+err.Error())
		return
	}
	type file struct {
		name string
		mod  time.Time
	}
	var others []file
	var errs []error
	for _, e := range ents {
		if !e.Type().IsRegular() || !configFileRE.MatchString(e.Name()) || "config/"+e.Name() == sel.Config {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		others = append(others, file{e.Name(), fi.ModTime()})
	}
	slices.SortFunc(others, func(a, b file) int {
		return cmp.Or(b.mod.Compare(a.mod), cmp.Compare(a.name, b.name))
	})
	removed := 0
	for _, f := range others[min(len(others), keepConfigs):] {
		if inUse["config/"+f.name] {
			continue
		}
		if err := os.Remove(filepath.Join(dir, f.name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
			continue
		}
		removed++
	}
	if removed > 0 {
		u.logf("xray-core %s: removed %d old configs", res.To, removed)
	}
	if err := errors.Join(errs...); err != nil {
		note(res, "pruning old configs: "+err.Error())
	}
}

// note adds msg to res.Detail, after what it holds.
func note(res *Result, msg string) {
	if res.Detail != "" {
		res.Detail += "; "
	}
	res.Detail += msg
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

// runsCore checks that the xray the runner runs reports version core, as
// "Xray <core> (...)" on the first line of xray version. A slot whose binary
// is another release than its name, such as an inbox zip of another version,
// must never be committed under that name.
func runsCore(st runnerapi.Status, core string) error {
	switch {
	case strings.HasPrefix(st.XrayVersion, "Xray "+core+" "):
		return nil
	case st.XrayVersion == "":
		return fmt.Errorf("the runner reports no xray version for the candidate, want xray-core %s", core)
	}
	return fmt.Errorf("the candidate reports %q, not xray-core %s", st.XrayVersion, core)
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

// newConfig names data by its SHA-256, so that a file and a render with the
// same bytes are the same config.
func newConfig(data []byte) *config {
	sum := sha256.Sum256(data)
	return &config{data: data, rel: "config/" + hex.EncodeToString(sum[:]) + ".json"}
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
	return newConfig(data), nil
}

func (c *config) write(runDir string) error {
	if err := os.MkdirAll(filepath.Join(runDir, "config"), 0o755); err != nil {
		return err
	}
	return atomicfile.WriteFile(filepath.Join(runDir, c.rel), c.data, 0o644)
}

// writeJSONAtomic writes v as indented JSON, mode 0644, with
// atomicfile.WriteFile.
func writeJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(path, append(b, '\n'), 0o644)
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
