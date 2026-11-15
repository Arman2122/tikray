package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/atomicfile"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

const (
	// scheduleFirst is how long after the start the scheduler first looks
	// for subscriptions that are due: long enough for the runner and the
	// proxy to come up, so that the first fetch need not fail.
	scheduleFirst = 30 * time.Second
	// scheduleEvery is the time between two looks.
	scheduleEvery = time.Minute
)

// schedule refreshes the subscriptions that are due until ctx ends: 30 s
// after the start, and then every minute (see due). Run starts it. It
// refreshes one subscription at a time, in the state's order, and does not
// look again until it has done with those that were due. A failed refresh
// has been recorded by RefreshSubscription already, and the subscription
// waits (see refreshFailed).
func (s *Service) schedule(ctx context.Context) {
	wait := scheduleFirst
	for {
		fire, stop := s.schedAfter(wait)
		if s.schedIdle != nil {
			s.schedIdle()
		}
		select {
		case <-ctx.Done():
			stop()
			return
		case <-fire:
		}
		s.refreshDue(ctx)
		s.checkGeoDue(ctx, s.GeoUpdate)
		wait = scheduleEvery
	}
}

// refreshDue refreshes each enabled subscription that is due now. A
// subscription is read again just before its turn: an earlier refresh can take
// long enough for it to have been refreshed, changed or removed.
func (s *Service) refreshDue(ctx context.Context) {
	listed, _ := s.store.State()
	for _, first := range listed.Subscriptions {
		if ctx.Err() != nil {
			return
		}
		st, _ := s.store.State()
		i := subscriptionIndex(st.Subscriptions, first.ID)
		if i < 0 || !s.due(st.Subscriptions[i], s.now()) {
			continue
		}
		// The error is the caller's to read; here it is in the events.
		_, _ = s.RefreshSubscription(ctx, first.ID)
	}
}

// due reports whether sub is to be refreshed at now: it is enabled and was
// never fetched or was fetched Interval ago or more, and it is not waiting to
// try again after a failure. A failure puts off the next try by min(1 h,
// Interval), held in memory, so that a restart tries at once.
func (s *Service) due(sub store.Subscription, now time.Time) bool {
	if sub.Disabled {
		return false
	}
	s.mu.Lock()
	until, held := s.holds[sub.ID]
	s.mu.Unlock()
	if held && now.Before(until) {
		return false
	}
	return sub.LastFetch.IsZero() || !sub.LastFetch.Add(time.Duration(sub.Interval)).After(now)
}

// selectedGeoProfile takes the current owner configuration or the profile of
// the verified active slot. An unusable slot cannot select a different source.
func (s *Service) selectedGeoProfile(ctx context.Context) (string, error) {
	active, err := s.geoScheduleSelection(ctx)
	if err != nil {
		return "", err
	}
	return s.profileForSlot(active.Geo)
}

func (s *Service) geoScheduleSelection(ctx context.Context) (runnerapi.Selection, error) {
	if s.repairBridge || s.bootPending.Load() {
		return runnerapi.Selection{}, ErrBootstrapPending
	}
	query, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	status, err := s.runner.Status(query)
	if err != nil {
		return runnerapi.Selection{}, ErrRunnerUnavailable
	}
	if status.Active == nil || status.State != runnerapi.StateRunning || status.Candidate != nil {
		return runnerapi.Selection{}, ErrBootstrapPending
	}
	return *status.Active, nil
}

func (s *Service) profileForSlot(slot string) (string, error) {
	installed, err := artifacts.GeoSlotProfile(s.data, slot)
	if err != nil {
		return "", &Refused{Reason: "could not verify active geo profile"}
	}
	if s.geoProfile != "" {
		return s.geoProfile, nil
	}
	return installed, nil
}

// Reserve the day before fetching so a process killed mid-update cannot
// duplicate the automatic work after restart. Manual requests stay available.
func (s *Service) checkGeoDue(ctx context.Context, update func(context.Context, string, string) (artifacts.Result, error)) {
	if ctx.Err() != nil || s.bootPending.Load() || s.repairBridge {
		return
	}
	due, err := s.reserveGeoCheck(ctx)
	if err != nil {
		if !errors.Is(err, ErrBootstrapPending) && !errors.Is(err, ErrRunnerUnavailable) && ctx.Err() == nil {
			s.record(KindError, "could not verify the daily geo check")
		}
		return
	}
	if due {
		if s.geoSchedule.mode == "notify" {
			if err := s.notifyGeo(ctx); err != nil && ctx.Err() == nil {
				s.record(KindError, "could not check for a geo release")
			}
			return
		}
		// Resolve the profile again under the service's writer lock. The
		// manual update or rollback that acquired it first may have changed it.
		_, _ = update(ctx, "", "latest")
	}
}

func (s *Service) reserveGeoCheck(ctx context.Context) (bool, error) {
	s.geoScheduleMu.Lock()
	defer s.geoScheduleMu.Unlock()
	now := s.now().UTC()
	if !s.geoSchedule.due(now, time.Time{}) {
		return false, nil
	}
	path := filepath.Join(s.data, "state", "geo-check.json")
	raw, err := atomicfile.ReadRegular(path, 256, 0600)
	switch {
	case err == nil:
		var last time.Time
		if json.Unmarshal(raw, &last) != nil || last.IsZero() {
			return false, errors.New("service: invalid geo check receipt")
		}
		if !s.geoSchedule.due(now, last) {
			return false, nil
		}
	case !errors.Is(err, os.ErrNotExist):
		return false, errors.New("service: cannot read geo check receipt")
	}
	// A never-configured installation keeps its old, quiet scheduling path.
	// The shared runner file is only a hint; an update still authenticates
	// the live runner and verifies the slot before choosing the publisher.
	if s.geoProfile == "" {
		raw, err := atomicfile.ReadRegular(filepath.Join(s.data, "run", "active.json"), 4096, 0)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		var active runnerapi.Selection
		if err != nil || json.Unmarshal(raw, &active) != nil || active.Validate() != nil {
			return false, errors.New("service: cannot read geo scheduling selection")
		}
		if active.Geo == "" {
			return false, nil
		}
	}
	profile, err := s.selectedGeoProfile(ctx)
	if err != nil || profile == "" {
		return false, err
	}
	data, err := json.Marshal(now)
	if err != nil || atomicfile.WriteFile(path, append(data, '\n'), 0600) != nil {
		return false, errors.New("service: could not reserve the daily geo check")
	}
	return true, nil
}
