package service

import (
	"context"
	"errors"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

// RouterController prepares scoped protection before either policy changes.
// Reconcile releases it only after verifying the effective router policy.
type RouterController interface {
	Prepare(context.Context, routeros.Target) error
	Reconcile(context.Context, routeros.Target) (routeros.Report, error)
	Watch(context.Context, func()) error
	Leases(context.Context) ([]routeros.LeaseInfo, error)
}

type RouterStatus struct {
	Revision     uint64    `json:"revision"`
	Pending      bool      `json:"pending"`
	Degraded     string    `json:"degraded,omitempty"`
	LastVerified time.Time `json:"last_verified,omitzero"`
}

var (
	ErrRouterUnavailable = errors.New("service: router protection could not be verified")
	ErrRouterConflict    = errors.New("service: router policy conflicts with the observed configuration")
)

// Waiting for another edit is bounded separately from doing the work. Every
// native call has a deadline. A larger policy may need many successful calls
// to release its guards, and restarting that release can prevent convergence.
const routerWriterWait = 2 * time.Minute

func publicRouterError(err error) error {
	if errors.Is(err, routeros.ErrIPv6FlowScope) {
		return errors.Join(ErrRouterConflict, routeros.ErrIPv6FlowScope)
	}
	if errors.Is(err, routeros.ErrPolicyConflict) {
		return ErrRouterConflict
	}
	return ErrRouterUnavailable
}

func (s *Service) routerPending(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routerStatus.Pending = true
	s.routerStatus.Degraded = reason
}

func (s *Service) routerFailure(err error) error {
	public := publicRouterError(err)
	reason := "unavailable"
	if errors.Is(err, routeros.ErrIPv6FlowScope) {
		reason = "ipv6_fasttrack_scope"
	} else if public == ErrRouterConflict {
		reason = "conflict"
	}
	s.routerPending(reason)
	return public
}

// prepareRouter also re-observes a transition interrupted before a store
// write. A failed read or write leaves the journal for the next pass.
func (s *Service) prepareRouter(ctx context.Context, st store.State, rev uint64) error {
	if s.router == nil || s.repairBridge {
		return nil
	}
	if err := s.store.EnsureDurable(); err != nil {
		s.routerPending("state")
		return ErrRouterUnavailable
	}
	policy, err := routeros.Project(st)
	if err != nil {
		s.routerPending("policy")
		return ErrRouterConflict
	}
	s.routerPending("")
	if err := s.router.Prepare(ctx, routeros.Target{Policy: policy, Revision: rev}); err != nil {
		return s.routerFailure(err)
	}
	return nil
}

func (s *Service) afterRunner(ctx context.Context, st store.State, rev uint64, err error) error {
	if s.router == nil {
		return err
	}
	if err != nil {
		s.routerPending("runner")
		return err
	}
	return s.finishRouter(ctx, st, rev)
}

// finishRouter holds the apply lock across the runner observation and router
// diff. All managed state writes take this lock. Re-read the revision as
// well, so a stale caller cannot label its result as the current policy.
func (s *Service) finishRouter(ctx context.Context, st store.State, rev uint64) error {
	if s.router == nil {
		return nil
	}
	rs, err := s.runner.Status(ctx)
	if err != nil || rs.State != runnerapi.StateRunning || rs.Active == nil || rs.Candidate != nil || artifacts.HotPending(s.data) {
		s.routerPending("runner")
		return ErrRouterUnavailable
	}
	name, err := configName(s.updater(st, rev), rs.Active)
	if err != nil || name != rs.Active.Config {
		s.routerPending("runner")
		return ErrRouterUnavailable
	}
	// A named geo slot needs a verified matching CIDR list before direct
	// exemptions can be finalized. An unreadable list must never mean empty.
	if rs.Active.Geo != "" {
		s.routerPending("geo")
		return ErrRouterUnavailable
	}
	if _, cur := s.store.State(); cur != rev {
		s.routerPending("revision")
		return store.ErrConflict
	}
	policy, err := routeros.Project(st)
	if err != nil {
		s.routerPending("policy")
		return ErrRouterConflict
	}
	selection := *rs.Active
	verify := func(ctx context.Context) error {
		if _, current := s.store.State(); current != rev {
			return store.ErrConflict
		}
		now, err := s.runner.Status(ctx)
		if err != nil || now.State != runnerapi.StateRunning || now.Candidate != nil || now.Active == nil || *now.Active != selection || artifacts.HotPending(s.data) {
			return ErrRouterUnavailable
		}
		return nil
	}
	report, err := s.router.Reconcile(ctx, routeros.Target{Policy: policy, Revision: rev, Selection: selection, Verify: verify})
	if err != nil {
		return s.routerFailure(err)
	}
	if report.Revision != rev {
		s.routerPending("revision")
		return store.ErrConflict
	}
	if err := verify(ctx); err != nil {
		s.routerPending("runner")
		return err
	}
	s.mu.Lock()
	wasVerified := !s.routerStatus.LastVerified.IsZero() && s.routerStatus.Revision == rev && s.routerSelection == *rs.Active
	s.routerStatus = RouterStatus{Revision: rev, LastVerified: s.now().UTC()}
	s.routerSelection = *rs.Active
	s.mu.Unlock()
	if wasVerified && report.Added+report.Set+report.Moved+report.Removed+report.Invalidated > 0 {
		s.record(KindRouter, "drift corrected")
	}
	return nil
}

func (s *Service) watchRouter(ctx context.Context) {
	hint := func() {
		select {
		case s.routerHints <- struct{}{}:
		default:
		}
	}
	for ctx.Err() == nil {
		_ = s.router.Watch(ctx, hint)
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.retry):
			// A reconnect can miss a removal while the socket is down.
			hint()
		}
	}
}

// Leases is discovery only. Router diagnostics can contain peer-supplied
// values, so callers receive a fixed category instead.
func (s *Service) Leases(ctx context.Context) ([]routeros.LeaseInfo, error) {
	if s.router == nil || s.repairBridge {
		return nil, ErrRouterUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	leases, err := s.router.Leases(ctx)
	if err != nil {
		return nil, publicRouterError(err)
	}
	return leases, nil
}
