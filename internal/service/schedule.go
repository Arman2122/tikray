package service

import (
	"context"
	"time"

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
