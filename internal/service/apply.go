package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xrayver"
)

// Kick asks the loop for an apply of the state as it is once Debounce has
// passed without another kick. A kick while the loop applies leads to another
// apply after that one, of the state as it is then. A change of the state
// calls Kick after it is written.
func (s *Service) Kick() {
	s.mu.Lock()
	s.kicked++
	s.mu.Unlock()
	// A token already waiting stands for this kick too: the loop has not
	// taken it, so the pass it leads to reads the state after this change.
	select {
	case s.kicks <- struct{}{}:
	default:
	}
}

// loop is the apply loop. A kick (re)starts the debounce timer; when it
// fires, a pass applies the newest state. A pass that fails for a reason that
// may pass by itself runs again after Retry, the wait doubling with each such
// failure in a row, up to maxRetry; a kick meanwhile starts the debounce
// instead. A pass never misses a kick: the token of a kick that lands during
// a pass waits in kicks, and leads to another pass after it.
func (s *Service) loop(ctx context.Context) {
	s.catchUp(ctx)
	var (
		fire <-chan time.Time
		stop = func() bool { return false }
		wait = s.retry // before the next retry, if the next pass fails
	)
	defer func() { stop() }()
	arm := func(d time.Duration) {
		stop()
		fire, stop = s.after(d)
	}
	for {
		if s.idle != nil {
			s.idle()
		}
		select {
		case <-ctx.Done():
			return
		case <-s.kicks:
			arm(s.debounce)
		case <-fire:
			fire, stop = nil, func() bool { return false }
			again := s.pass(ctx, wait)
			if ctx.Err() != nil {
				return
			}
			if !again {
				wait = s.retry
				continue
			}
			arm(wait)
			wait = min(2*wait, max(maxRetry, s.retry))
		}
	}
}

// catchUp kicks once at the start when the state was saved (its revision is
// above 0) and is not the runner's config, or the runner can't tell.
func (s *Service) catchUp(ctx context.Context) {
	st, rev := s.store.State()
	if rev == 0 {
		return
	}
	rs, err := s.runner.Status(ctx)
	if err == nil && rs.Active != nil {
		name, err := configName(s.updater(st, rev), rs.Active)
		if err == nil && name == rs.Active.Config {
			return
		}
	}
	s.Kick()
}

// pass applies the newest state once, unless the runner runs it already, and
// records how that went. It reports whether to try again later: when the
// runner can't be reached, or another update or trial is in the way. retry is
// how long the loop waits then, for the event to say.
func (s *Service) pass(ctx context.Context, retry time.Duration) (again bool) {
	if s.acquire(ctx) != nil {
		return false
	}
	defer s.release()
	// The kicks counted now are served by this pass, which reads the state
	// after them.
	s.mu.Lock()
	gen := s.kicked
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.retrying = again
		if !again {
			s.served = max(s.served, gen)
		}
	}()

	st, rev := s.store.State()
	rs, err := s.runner.Status(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return false
		}
		s.record(KindApply, fmt.Sprintf("revision %d not applied: %v; trying again in %s", rev, s.runnerError(ctx, err), retry))
		return true
	}
	u := s.updater(st, rev)
	if rs.Active != nil {
		name, err := configName(u, rs.Active)
		switch {
		case err != nil:
			// Apply would refuse with the same error.
			s.noteRender(rev, err, true)
			return false
		case name == rs.Active.Config:
			s.record(KindApply, fmt.Sprintf("revision %d is applied already", rev))
			return false
		}
	}
	res, err := u.Apply(ctx)
	again = retryable(res, err) && ctx.Err() == nil
	if !again {
		retry = 0
	}
	s.noteApply(rev, res, err, retry)
	return again
}

// retryable reports whether an apply that ended with res and err may work if
// tried again later without a change: the runner could not be reached, or
// another update holds the artifacts lock, or a trial is open that will end
// by its deadline. A config that xray rejected, or that failed the health
// check, waits for a change.
func retryable(res artifacts.Result, err error) bool {
	switch {
	case err == nil, res.Outcome == runnerapi.OutcomeRejected, res.Outcome == artifacts.OutcomeUnhealthy:
		return false
	}
	return errors.Is(err, artifacts.ErrLocked) || errors.Is(err, runnerapi.ErrBusy) || unreachable(err)
}

// ApplyNow applies the state as it is now, as the loop would, but at once and
// even when the runner runs it already: the result is then noop. It fails
// with ErrRunnerUnavailable when the runner can't be reached; artifacts.ErrLocked
// comes back as it is. A rejected or unhealthy apply is not retried.
func (s *Service) ApplyNow(ctx context.Context) (artifacts.Result, error) {
	if err := s.acquire(ctx); err != nil {
		return artifacts.Result{}, err
	}
	defer s.release()
	st, rev := s.store.State()
	if _, err := s.runner.Status(ctx); err != nil {
		err = s.runnerError(ctx, err)
		s.record(KindApply, fmt.Sprintf("revision %d not applied: %v", rev, err))
		return artifacts.Result{}, err
	}
	res, err := s.updater(st, rev).Apply(ctx)
	s.noteApply(rev, res, err, 0)
	return res, s.runnerError(ctx, err)
}

// CoreUpdate switches the runner to xray-core version ("latest" or a release)
// with the config rendered from the state as it is now (see
// artifacts.CoreUpdater.Update). It fails with ErrRunnerUnavailable when the
// runner can't be reached.
func (s *Service) CoreUpdate(ctx context.Context, version string, o artifacts.UpdateOptions) (artifacts.Result, error) {
	return s.coreOp(ctx, "xray-core update to "+version, func(u *artifacts.CoreUpdater) (artifacts.Result, error) {
		return u.Update(ctx, version, o)
	})
}

// CoreRollback switches the runner back to the core committed before the
// active one, with the config rendered from the state as it is now (see
// artifacts.CoreUpdater.Rollback). It fails with ErrRunnerUnavailable when the
// runner can't be reached.
func (s *Service) CoreRollback(ctx context.Context) (artifacts.Result, error) {
	return s.coreOp(ctx, "rollback", func(u *artifacts.CoreUpdater) (artifacts.Result, error) {
		return u.Rollback(ctx)
	})
}

// coreOp runs op, a core update or rollback named what, with an updater for
// the state as it is now, under the lock, and records how it ended.
func (s *Service) coreOp(ctx context.Context, what string, op func(*artifacts.CoreUpdater) (artifacts.Result, error)) (artifacts.Result, error) {
	if err := s.acquire(ctx); err != nil {
		return artifacts.Result{}, err
	}
	defer s.release()
	st, rev := s.store.State()
	if _, err := s.runner.Status(ctx); err != nil {
		err = s.runnerError(ctx, err)
		s.record(KindCore, fmt.Sprintf("%s failed: %v", what, err))
		return artifacts.Result{}, err
	}
	res, err := op(s.updater(st, rev))
	switch {
	case err != nil:
		s.record(KindCore, fmt.Sprintf("%s failed: %v", what, err))
	case res.Outcome == artifacts.OutcomeNoop:
		s.record(KindCore, fmt.Sprintf("%s: xray-core %s is active already", what, res.To))
	default:
		msg := fmt.Sprintf("%s: xray-core %s is active, with revision %d", what, res.To, rev)
		if res.From != "" {
			msg += ", in place of " + res.From
		}
		if res.Detail != "" {
			msg += "; " + res.Detail
		}
		s.record(KindCore, msg)
	}
	return res, s.runnerError(ctx, err)
}

// noteApply keeps res as the last apply's and records how the apply of
// revision rev ended. retry, when not 0, is when the loop tries again.
func (s *Service) noteApply(rev uint64, res artifacts.Result, err error, retry time.Duration) {
	res.Detail = s.redact(res.Detail)
	s.mu.Lock()
	s.lastApply = &res
	s.mu.Unlock()
	var msg string
	switch {
	case err != nil:
		msg = fmt.Sprintf("revision %d not applied: %v", rev, err)
		if retry > 0 {
			msg += fmt.Sprintf("; trying again in %s", retry)
		}
	case res.Outcome == artifacts.OutcomeNoop:
		msg = fmt.Sprintf("revision %d is applied already", rev)
	default:
		msg = fmt.Sprintf("revision %d applied with xray-core %s", rev, res.To)
		if res.Detail != "" {
			msg += "; " + res.Detail
		}
	}
	s.record(KindApply, msg)
}

// noteRender records that revision rev does not render, with err; a nil err
// says it renders. Status records a failure once until it changes; a pass
// (always) records its own, as the reason it applied nothing.
func (s *Service) noteRender(rev uint64, err error, always bool) {
	s.mu.Lock()
	if err == nil {
		s.renderErr = ""
		s.mu.Unlock()
		return
	}
	text := err.Error()
	again := text == s.renderErr
	s.renderErr = text
	s.mu.Unlock()
	switch {
	case always:
		s.record(KindApply, fmt.Sprintf("revision %d not applied: %s", rev, text))
	case !again:
		s.record(KindError, fmt.Sprintf("revision %d does not render: %s", rev, text))
	}
}

// updater is the CoreUpdater for st at rev, which redacts with the service's
// redactor: the secrets of the state now and those of st, which its render
// holds.
func (s *Service) updater(st store.State, rev uint64) *artifacts.CoreUpdater {
	u := s.updaters(st, rev)
	own := RedactorFor(st)
	u.Redact = func(text string) string { return s.redact(own(text)) }
	return u
}

// configName is the name under run/ of the config that u renders for the
// active selection's core and geo.
func configName(u *artifacts.CoreUpdater, active *runnerapi.Selection) (string, error) {
	if u.Render == nil {
		return "", errors.New("service: the updater has no Render")
	}
	v, err := xrayver.Parse(active.Core)
	if err != nil {
		return "", fmt.Errorf("service: the runner's active core: %w", err)
	}
	cfg, err := u.Render(v, active.Geo)
	if err != nil {
		return "", fmt.Errorf("service: rendering the config for xray-core %s: %w", v, err)
	}
	return artifacts.ConfigName(cfg), nil
}

// acquire takes the lock that the loop's pass and the operations share,
// waiting until it is free or ctx ends.
func (s *Service) acquire(ctx context.Context) error {
	select {
	case s.lock <- struct{}{}:
		return nil
	default:
	}
	if s.onWait != nil {
		s.onWait()
	}
	select {
	case s.lock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) release() { <-s.lock }
