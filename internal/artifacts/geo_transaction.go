package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/Arman2122/tikray/internal/atomicfile"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/xrayver"
	"golang.org/x/sys/unix"
)

const (
	KindGeo         = "geo"
	geoPendingFile  = "geo-pending.json"
	geoVersionsFile = "geo-versions.json"
)

// ErrGeoPending prevents other mutations from overwriting evidence from a
// geo trial whose runner and router selections have not yet been verified.
var ErrGeoPending = errors.New("artifacts: geo reconciliation pending")

// ErrGeoPolicyRefused marks a definite policy/ownership conflict. Only this
// verdict can authorize a compensating trial after the new runner committed.
var ErrGeoPolicyRefused = errors.New("artifacts: geo policy refused")

// GeoUpdater changes just the geo slot and rendered config of a running core.
// On managed routers the service holds its policy writer across these calls.
// Prepare must withdraw obsolete direct exemptions without admitting new
// ones. Finish must diff and verify the ranges for the committed selection.
// Standalone installations leave both callbacks nil.
type GeoUpdater struct {
	Core    *CoreUpdater
	Stage   func(context.Context, string, string) (string, error)
	Prepare func(context.Context, runnerapi.Selection, runnerapi.Selection, []netip.Prefix, []netip.Prefix) error
	Finish  func(context.Context, runnerapi.Selection, []netip.Prefix) error
}

type geoTransition struct {
	Version   int                 `json:"version"`
	From      runnerapi.Selection `json:"from"`
	To        runnerapi.Selection `json:"to"`
	Restoring bool                `json:"restoring,omitempty"`
	Deadline  time.Time           `json:"trial_deadline,omitzero"`
}

// GeoPending includes unreadable evidence so ordinary core/config updates
// cannot make an unresolved runner selection impossible to identify.
func GeoPending(data string) bool {
	_, err := os.Lstat(filepath.Join(data, "state", geoPendingFile))
	return !errors.Is(err, fs.ErrNotExist)
}

func writeGeoState(data, name string, pair geoTransition) error {
	body, err := json.Marshal(pair)
	if err != nil || atomicfile.WriteFile(filepath.Join(data, "state", name), body, 0600) != nil {
		return errors.New("artifacts: cannot persist geo transaction")
	}
	return nil
}

func readGeoState(data, name string) (*geoTransition, error) {
	b, err := atomicfile.ReadRegular(filepath.Join(data, "state", name), 4096, 0600)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	var p geoTransition
	if err != nil || json.Unmarshal(b, &p) != nil || p.Version != 1 || p.From.Validate() != nil || p.To.Validate() != nil || p.From.Core != p.To.Core || p.From.Geo == p.To.Geo {
		return nil, errors.New("artifacts: invalid geo transaction")
	}
	return &p, nil
}

func (g *GeoUpdater) valid() bool {
	return g.Core != nil && g.Core.Data != "" && g.Core.Runner != nil && (g.Prepare == nil) == (g.Finish == nil)
}

func (g *GeoUpdater) Update(ctx context.Context, profile, version string) (Result, error) {
	return g.change(ctx, profile, version, false)
}

func (g *GeoUpdater) Rollback(ctx context.Context) (Result, error) {
	return g.change(ctx, "", "", true)
}

func (g *GeoUpdater) change(ctx context.Context, profile, version string, rollback bool) (Result, error) {
	res := Result{Kind: KindGeo}
	if !g.valid() {
		err := refuse(&res, errors.New("artifacts: geo updater unavailable"))
		return res, err
	}
	return g.Core.locked(&res, func() error {
		if GeoPending(g.Core.Data) {
			return refuse(&res, ErrGeoPending)
		}
		if HotPending(g.Core.Data) {
			return refuse(&res, errors.New("artifacts: unfinished config change"))
		}
		if err := g.Core.ready(); err != nil {
			return refuse(&res, err)
		}
		if g.Core.Render == nil {
			return refuse(&res, errors.New("artifacts: geo update needs a state renderer"))
		}

		old, err := g.live(ctx)
		if err != nil {
			return refuse(&res, err)
		}
		prior, err := readGeoState(g.Core.Data, geoVersionsFile)
		if err != nil {
			return refuse(&res, err)
		}
		if prior != nil && prior.To.Geo != old.Geo {
			return refuse(&res, errors.New("artifacts: geo rollback record differs from active selection"))
		}
		next := old
		if rollback {
			if prior == nil {
				return refuse(&res, errors.New("artifacts: no previous geo bundle"))
			}
			next.Geo = prior.From.Geo
		} else {
			stage := g.Stage
			if stage == nil {
				stage = g.Core.StageGeo
			}
			name, err := stage(ctx, profile, version)
			if err != nil {
				return refuse(&res, &redactedError{err: err, text: "artifacts: cannot stage verified geo bundle"})
			}
			if !runnerapi.ValidGeoName(name) {
				return refuse(&res, errors.New("artifacts: invalid staged geo name"))
			}
			next.Geo = name
		}
		equal, err := SameGeo(g.Core.Data, old.Geo, next.Geo)
		if err != nil {
			return refuse(&res, err)
		}
		res.From = old.Geo
		if equal {
			res.To, res.Outcome = old.Geo, OutcomeNoop
			if err := g.prune(old.Geo, prior); err != nil {
				return refuse(&res, err)
			}
			return nil
		}
		res.To = next.Geo
		if _, err := os.Lstat(g.Core.candidatePath()); !errors.Is(err, fs.ErrNotExist) {
			return refuse(&res, errors.New("artifacts: unresolved runner candidate file"))
		}
		if err := g.verifyConfig(ctx, old.Config); err != nil {
			return refuse(&res, err)
		}
		core, _ := xrayver.Parse(old.Core) // live validated the canonical core.
		// A release can legitimately change the default render's bytes. Check
		// the previous render before replacing a selection made via --config.
		if g.Core.NoState {
			cfg, err := g.Core.render(core, old.Geo)
			if err != nil {
				return refuse(&res, errors.New("artifacts: cannot verify active config"))
			}
			if err := g.Core.unsaved(&old, cfg, "save the desired state before changing geo"); err != nil {
				return refuse(&res, err)
			}
		}
		cfg, err := g.Core.render(core, next.Geo)
		if err != nil || cfg.write(g.Core.runDir()) != nil {
			return refuse(&res, errors.New("artifacts: cannot prepare geo config"))
		}
		next.Config = cfg.rel
		before, err := geoRanges(g.Core.Data, old.Geo)
		if err != nil {
			return refuse(&res, err)
		}
		after, err := geoRanges(g.Core.Data, next.Geo)
		if err != nil {
			return refuse(&res, err)
		}
		p := geoTransition{Version: 1, From: old, To: next}
		if err := writeGeoState(g.Core.Data, geoPendingFile, p); err != nil {
			return refuse(&res, err)
		}
		if g.Prepare != nil {
			if err := g.Prepare(ctx, old, next, before, after); err != nil {
				// No runner write has been attempted. Even a partial native
				// prepare must restore the old verified view if still live.
				restore, cancel := cleanupContext(ctx)
				defer cancel()
				if _, undo := g.settle(restore, p); undo != nil {
					return refuse(&res, &redactedError{err: errors.Join(ErrGeoPending, err), text: "artifacts: router geo preparation pending"})
				}
				return refuse(&res, &redactedError{err: err, text: "artifacts: router geo preparation refused"})
			}
		}
		if active, e := g.live(ctx); e != nil || active != old {
			return refuse(&res, ErrGeoPending)
		}
		trialErr := g.trySelection(ctx, &p, next, &res)
		resolve := ctx
		if ctx.Err() != nil {
			var cancel context.CancelFunc
			resolve, cancel = cleanupContext(ctx)
			defer cancel()
		}
		confirmed, err := g.settle(resolve, p)
		if err != nil {
			return refuse(&res, &redactedError{err: errors.Join(ErrGeoPending, err), text: "artifacts: geo completion pending"})
		}
		if confirmed == next {
			res.Outcome, res.Detail = runnerapi.OutcomeCommitted, ""
			return nil
		}
		if res.Outcome == runnerapi.OutcomeCommitted {
			res.Outcome, res.Detail = OutcomeRefused, "router refused geo; previous selection restored"
			return ErrGeoPolicyRefused
		}
		switch res.Outcome {
		case runnerapi.OutcomeAborted, runnerapi.OutcomeDeadline, runnerapi.OutcomeReboot, runnerapi.OutcomeExited, runnerapi.OutcomeRejected, OutcomeUnhealthy:
		default:
			res.Outcome = OutcomeRefused
		}
		res.Detail = "geo trial did not commit"
		return &redactedError{err: trialErr, text: "artifacts: geo trial did not commit"}
	})
}

// Bind the runner request to this journal, including its exact deadline,
// before writing candidate.json. Other artifact mutations stay fenced if this
// process dies or loses the acknowledgement at any later point.
func (g *GeoUpdater) trySelection(ctx context.Context, p *geoTransition, target runnerapi.Selection, res *Result) error {
	p.Deadline = g.Core.now().Add(g.Core.trialDeadline())
	if err := writeGeoState(g.Core.Data, geoPendingFile, *p); err != nil {
		return refuse(res, err)
	}
	trial := *g.Core
	trial.Log = nil // peer diagnostics can include material taken from a bundle
	candidate := runnerapi.Candidate{Selection: target, Deadline: p.Deadline}
	return trial.trialCandidate(ctx, candidate, res, trial.ProxyHealth)
}

// live never treats the last stored selection or a provisional candidate
// as the operating, committed data path.
func (g *GeoUpdater) live(ctx context.Context) (runnerapi.Selection, error) {
	s, err := g.Core.Runner.Status(ctx)
	if err != nil || s.State != runnerapi.StateRunning || s.Active == nil || s.Candidate != nil || s.Active.Validate() != nil || !s.RoutesOK || !s.GatewayUp || runsCore(s, s.Active.Core) != nil {
		return runnerapi.Selection{}, ErrGeoPending
	}
	return *s.Active, nil
}

func geoRanges(data, slot string) ([]netip.Prefix, error) {
	if slot == "" {
		return nil, nil
	}
	_, ps, err := LoadGeo(data, slot)
	return ps, err
}

func (g *GeoUpdater) prune(active string, prior *geoTransition) error {
	keep := []string{active}
	if prior != nil {
		keep = append(keep, prior.From.Geo)
	}
	return PruneGeo(g.Core.Data, keep)
}

// Recover replays only a verified router diff. An in-flight or unrelated
// runner selection leaves the journal in place for the next pass.
func (g *GeoUpdater) Recover(ctx context.Context) error {
	if !g.valid() {
		return errors.New("artifacts: geo updater unavailable")
	}
	if !GeoPending(g.Core.Data) {
		return nil
	}
	unlock, err := lockState(g.Core.stateDir())
	if err != nil {
		return err
	}
	defer unlock()
	p, err := readGeoState(g.Core.Data, geoPendingFile)
	if err != nil || p == nil {
		return err
	}
	_, err = g.settle(ctx, *p)
	return err
}

func (g *GeoUpdater) settle(ctx context.Context, p geoTransition) (runnerapi.Selection, error) {
	var none runnerapi.Selection
	active, err := g.live(ctx)
	if err != nil || (active != p.From && active != p.To) {
		return none, ErrGeoPending
	}
	// A matching name alone is not proof our trial was ever authorized.
	if active == p.To && !p.Restoring && p.Deadline.IsZero() {
		return none, ErrGeoPending
	}
	if e := g.checkCandidateFile(p, active); e != nil {
		return none, e
	}
	if p.Restoring && active == p.To {
		if err := g.restore(ctx, &p); err != nil {
			return none, err
		}
		active, err = g.live(ctx)
		if err != nil || active != p.From {
			return none, ErrGeoPending
		}
	}
	if g.Finish != nil {
		ranges, err := geoRanges(g.Core.Data, active.Geo)
		if err != nil {
			return none, err
		}
		if err = g.Finish(ctx, active, ranges); err != nil {
			if active == p.To && !p.Restoring && errors.Is(err, ErrGeoPolicyRefused) {
				// Persist the decision before any compensating native or
				// runner write. A reboot must resume the old target.
				p.Restoring = true
				p.Deadline = time.Time{}
				if err = writeGeoState(g.Core.Data, geoPendingFile, p); err != nil {
					return none, err
				}
				return g.settle(ctx, p)
			}
			return none, &redactedError{err: err, text: "artifacts: cannot confirm router geo policy"}
		}
	} else if _, err = geoRanges(g.Core.Data, active.Geo); err != nil {
		return none, err
	}
	if live, err := g.live(ctx); err != nil || live != active {
		return none, ErrGeoPending
	}
	prior, err := readGeoState(g.Core.Data, geoVersionsFile)
	if err != nil {
		return none, err
	}
	if active == p.To {
		if err := writeGeoState(g.Core.Data, geoVersionsFile, p); err != nil {
			return none, err
		}
		prior = &p
	} else if prior != nil && prior.From == p.From && prior.To == p.To {
		// An earlier completion persisted both sides but died before the
		// journal was retired. The candidate was a verified version. If the
		// runner returned to the old selection, retain that proven pair in
		// the order we just confirmed instead of pinning the wrong version.
		restored := geoTransition{Version: 1, From: p.To, To: p.From}
		if err := writeGeoState(g.Core.Data, geoVersionsFile, restored); err != nil {
			return none, err
		}
		prior = &restored
	}
	if prior != nil && prior.To.Geo != active.Geo {
		return none, ErrGeoPending
	}
	if err := g.prune(active.Geo, prior); err != nil {
		return none, err
	}
	if removeSynced(filepath.Join(g.Core.stateDir(), geoPendingFile)) != nil {
		return none, errors.New("artifacts: cannot retire geo transaction")
	}
	return active, nil
}

// restore drives a real, verified trial of the exact previous bytes. It is
// never authorized by a timeout or an unknown response from the router.
func (g *GeoUpdater) restore(ctx context.Context, p *geoTransition) error {
	if err := g.Core.ready(); err != nil {
		return err
	}
	oldRanges, err := geoRanges(g.Core.Data, p.From.Geo)
	if err != nil {
		return err
	}
	newRanges, err := geoRanges(g.Core.Data, p.To.Geo)
	if err != nil {
		return err
	}
	if err := g.verifyConfig(ctx, p.From.Config); err != nil {
		return err
	}
	if g.Prepare != nil {
		if err = g.Prepare(ctx, p.To, p.From, newRanges, oldRanges); err != nil {
			return &redactedError{err: err, text: "artifacts: cannot protect geo rollback"}
		}
	}
	if active, err := g.live(ctx); err != nil || active != p.To {
		return ErrGeoPending
	}
	res := Result{Kind: KindGeo}
	_ = g.trySelection(ctx, p, p.From, &res)
	// Even when commit or abort timed out, only the live selection can
	// establish what happened. Never relabel the acknowledged candidate.
	if active, err := g.live(ctx); err != nil || active != p.From {
		return ErrGeoPending
	}
	return nil
}

// Verify the previous content-addressed file without loading an arbitrary
// saved configuration into memory or following links in the shared run tree.
func (g *GeoUpdater) verifyConfig(ctx context.Context, name string) error {
	bad := errors.New("artifacts: previous geo config unavailable")
	dir, err := openGeoDir(g.Core.Data, false, "run", "config")
	if err != nil {
		return bad
	}
	defer unix.Close(dir)
	h := sha256.New()
	if readGeoFile(dir, filepath.Base(name), math.MaxInt64-1, contextWriter{ctx, h}) != nil || "config/"+hex.EncodeToString(h.Sum(nil))+".json" != name {
		return bad
	}
	return nil
}

type contextWriter struct {
	ctx context.Context
	w   io.Writer
}

func (w contextWriter) Write(b []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.w.Write(b)
}

// If the process died after writing candidate.json, a timed-out request may
// still be in flight. Keep the guards until the runner settles the trial or
// the recorded deadline passes. Never remove another operation's candidate.
func (g *GeoUpdater) checkCandidateFile(p geoTransition, active runnerapi.Selection) error {
	b, err := atomicfile.ReadRegular(g.Core.candidatePath(), 4096, 0644)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	var c runnerapi.Candidate
	target := p.To
	if p.Restoring {
		target = p.From
	}
	if err != nil || json.Unmarshal(b, &c) != nil || c.Selection != target || c.Deadline.IsZero() || !c.Deadline.Equal(p.Deadline) || (active != target && g.Core.now().Before(c.Deadline)) {
		return ErrGeoPending
	}
	if removeSynced(g.Core.candidatePath()) != nil {
		return ErrGeoPending
	}
	return nil
}
