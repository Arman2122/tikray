package service

import (
	"context"
	"errors"
	"net/netip"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

func (s *Service) geoUpdater(st store.State, rev uint64) *artifacts.GeoUpdater {
	g := &artifacts.GeoUpdater{Core: s.updater(st, rev)}
	if s.router == nil {
		return g
	}
	g.Prepare = func(ctx context.Context, old, candidate runnerapi.Selection, before, after []netip.Prefix) error {
		if err := s.store.EnsureDurable(); err != nil {
			return ErrRouterUnavailable
		}
		p, err := routeros.Project(st)
		if err != nil {
			return ErrRouterConflict
		}
		s.routerPending("geo")
		if err := s.router.Prepare(ctx, routeros.Target{Revision: rev, Policy: p, Geo: after, WithdrawGeo: true}); err != nil {
			return s.routerFailure(err)
		}
		return nil
	}
	g.Finish = func(ctx context.Context, active runnerapi.Selection, ranges []netip.Prefix) error {
		err := s.finishRouterFor(ctx, st, rev, active, ranges)
		if errors.Is(err, ErrRouterConflict) {
			return errors.Join(artifacts.ErrGeoPolicyRefused, err)
		}
		return err
	}
	return g
}

// recoverGeo runs under the policy writer before another operation can change
// the runner or the desired state used to verify the crash journal.
func (s *Service) recoverGeo(ctx context.Context) error {
	if !artifacts.GeoPending(s.data) {
		return nil
	}
	if s.repairBridge {
		return ErrRouterUnavailable
	}
	st, rev := s.store.State()
	if err := s.geoUpdater(st, rev).Recover(ctx); err != nil {
		s.geoDegraded.Store(true)
		s.routerPending("geo")
		return artifacts.ErrGeoPending
	}
	s.geoDegraded.Store(false)
	return nil
}

func (s *Service) GeoUpdate(ctx context.Context, profile, version string) (artifacts.Result, error) {
	return s.geoOperation(ctx, profile, version, false)
}
func (s *Service) GeoRollback(ctx context.Context) (artifacts.Result, error) {
	return s.geoOperation(ctx, "", "", true)
}
func (s *Service) geoOperation(ctx context.Context, profile, version string, rollback bool) (artifacts.Result, error) {
	if s.bootPending.Load() {
		return artifacts.Result{}, ErrBootstrapPending
	}
	if s.repairBridge {
		return artifacts.Result{}, ErrRouterUnavailable
	}
	if err := s.acquire(ctx); err != nil {
		return artifacts.Result{}, err
	}
	defer s.pokeMonitor()
	defer s.release()
	if err := s.recoverGeo(ctx); err != nil {
		s.Kick()
		return artifacts.Result{}, err
	}
	if !rollback {
		if profile == "" {
			var err error
			profile, err = s.selectedGeoProfile(ctx)
			if err != nil {
				return artifacts.Result{}, err
			}
		}
		if !artifacts.ValidGeoTarget(profile, version) || !artifacts.ValidGeoProfile(profile) {
			return artifacts.Result{}, &Refused{Reason: "invalid geo profile or release"}
		}
	}
	st, rev := s.store.State()
	g := s.geoUpdater(st, rev)
	if s.router != nil {
		// A just-saved policy might not be active yet. Let its ordinary pass
		// converge first, so recovery can always identify the exact old config.
		rs, err := s.runner.Status(ctx)
		if err != nil || rs.Active == nil || rs.State != runnerapi.StateRunning || rs.Candidate != nil {
			return artifacts.Result{}, ErrRouterUnavailable
		}
		name, err := configName(g.Core, rs.Active)
		if err != nil {
			s.geoDegraded.Store(true)
			s.routerPending("geo")
			return artifacts.Result{}, ErrRouterUnavailable
		}
		if name != rs.Active.Config {
			s.Kick()
			return artifacts.Result{}, ErrRouterUnavailable
		}
	}
	var res artifacts.Result
	var err error
	if rollback {
		res, err = g.Rollback(ctx)
	} else {
		res, err = g.Update(ctx, profile, version)
	}
	s.geoDegraded.Store(err != nil)
	if err != nil {
		if artifacts.GeoPending(s.data) {
			s.routerPending("geo")
			s.Kick()
		}
		s.record(KindGeo, "geo update failed")
		if errors.Is(err, artifacts.ErrGeoPending) {
			return res, artifacts.ErrGeoPending
		}
		return res, s.redactError(err)
	}
	if res.Outcome != artifacts.OutcomeNoop {
		s.record(KindGeo, "geo bundle committed")
	}
	return res, nil
}
