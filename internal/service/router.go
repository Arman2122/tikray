package service

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/routeros/adapters"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

type routerProfiler interface {
	Profile() adapters.Profile
}

type routerInterfaceReader interface {
	Interfaces(context.Context) (routeros.NetworkInventory, error)
}

// RouterController prepares scoped protection before either policy changes.
// Reconcile releases it only after verifying the effective router policy.
type RouterController interface {
	VerifyInstallation(context.Context, routeros.Target) error
	Prepare(context.Context, routeros.Target) error
	Reconcile(context.Context, routeros.Target) (routeros.Report, error)
	Watch(context.Context, func()) error
	Leases(context.Context) ([]routeros.LeaseInfo, error)
	MakeStaticLease(context.Context, netip.Addr) (routeros.LeaseInfo, error)
}

type RouterStatus struct {
	Version      string    `json:"version,omitempty"`
	Untested     bool      `json:"untested,omitempty"`
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
	return s.prepareRouterMode(ctx, st, rev, false)
}

func (s *Service) prepareRouterMode(ctx context.Context, st store.State, rev uint64, legacyOpenUDP bool) error {
	if err := s.recoverGeo(ctx); err != nil {
		return err
	}
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
	if err := s.router.Prepare(ctx, routeros.Target{Policy: policy, Revision: rev, KeepGeo: true, LegacyOpenUDP: legacyOpenUDP}); err != nil {
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
	return s.finishRouterMode(ctx, st, rev, false)
}

func (s *Service) finishRouterMode(ctx context.Context, st store.State, rev uint64, legacyOpenUDP bool) error {
	if s.router == nil {
		return nil
	}
	rs, err := s.runner.Status(ctx)
	if err != nil || rs.State != runnerapi.StateRunning || rs.Active == nil || rs.Candidate != nil || artifacts.HotPending(s.data) {
		s.routerPending("runner")
		return ErrRouterUnavailable
	}
	ranges, err := s.activeGeoRanges(rs.Active.Geo, false)
	if err != nil {
		return err
	}
	return s.finishRouterFor(ctx, st, rev, *rs.Active, ranges, legacyOpenUDP)
}

func renderFailureReason(err error) string {
	if errors.Is(err, artifacts.ErrGeoSlot) {
		return "geo"
	}
	return "runner"
}

func (s *Service) activeGeoRanges(slot string, fresh bool) ([]netip.Prefix, error) {
	if slot == "" {
		return nil, nil
	}
	load := s.geoReader.Load
	if fresh {
		load = artifacts.LoadGeo
	}
	_, prefixes, err := load(s.data, slot)
	if err != nil {
		s.routerPending("geo")
		return nil, ErrRouterUnavailable
	}
	return prefixes, nil
}

// The geo journal supplies a specific committed selection. Never substitute
// another observation between choosing its ranges and releasing its guards.
func (s *Service) finishRouterFor(ctx context.Context, st store.State, rev uint64, selection runnerapi.Selection, ranges []netip.Prefix, legacyOpenUDP bool) error {
	name, err := configName(s.updater(st, rev), &selection)
	if err != nil || name != selection.Config {
		s.routerPending(renderFailureReason(err))
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
	if err := verify(ctx); err != nil {
		s.routerPending("runner")
		return err
	}
	report, err := s.router.Reconcile(ctx, routeros.Target{Policy: policy, Revision: rev, Selection: selection, Geo: ranges, LegacyOpenUDP: legacyOpenUDP, Verify: verify})
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
	wasVerified := !s.routerStatus.LastVerified.IsZero() && s.routerStatus.Revision == rev && s.routerSelection == selection
	s.routerStatus = RouterStatus{Revision: rev, LastVerified: s.now().UTC()}
	s.routerSelection = selection
	select {
	case <-s.routerReady:
	default:
		close(s.routerReady)
	}
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

// MakeStaticLease converts a single bound dynamic DHCP lease on the router to
// a static reservation so the device keeps a stable IP for routing rules.
func (s *Service) MakeStaticLease(ctx context.Context, addr netip.Addr) (routeros.LeaseInfo, error) {
	if s.bootPending.Load() {
		return routeros.LeaseInfo{}, ErrBootstrapPending
	}
	if s.router == nil || s.repairBridge {
		return routeros.LeaseInfo{}, ErrRouterUnavailable
	}
	if !addr.IsValid() || !addr.Is4() {
		return routeros.LeaseInfo{}, &Refused{Reason: "address must be a valid IPv4 address"}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	lease, err := s.router.MakeStaticLease(ctx, addr)
	if err != nil {
		if errors.Is(err, routeros.ErrLeaseNotFound) {
			return routeros.LeaseInfo{}, ErrNotFound
		}
		return routeros.LeaseInfo{}, publicRouterError(err)
	}
	s.record(KindRouter, "made DHCP lease static")
	return lease, nil
}

// RouterInterfaces reads live MikroTik physical ports, Wi-Fi radios/SSIDs,
// bridges, VLANs, subnets, and WAN Internet-in uplinks on demand. In standalone
// mode it returns Managed: false cleanly without failing.
func (s *Service) RouterInterfaces(ctx context.Context) (routeros.NetworkInventory, error) {
	empty := routeros.NetworkInventory{
		Managed:    false,
		Uplinks:    []routeros.WANUplink{},
		Interfaces: []routeros.RouterInterface{},
	}
	if s.router == nil || s.repairBridge {
		return empty, nil
	}
	reader, ok := s.router.(routerInterfaceReader)
	if !ok {
		return empty, nil
	}
	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	inv, err := reader.Interfaces(ctx)
	if err != nil {
		return routeros.NetworkInventory{}, publicRouterError(err)
	}
	st, _ := s.store.State()
	redact := RedactorFor(st)
	for i := range inv.Interfaces {
		if inv.Interfaces[i].SSID != "" && redact(inv.Interfaces[i].SSID) != inv.Interfaces[i].SSID {
			inv.Interfaces[i].SSID = ""
		}
	}
	return inv, nil
}
