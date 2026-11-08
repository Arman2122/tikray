package service

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

var ErrBootstrapPending = errors.New("service: retry bootstrap; a committed xray core and router connection must be verified")

// Bootstrap is present until the installer's private completion record has been synced.
type Bootstrap struct {
	Version      string
	Ready        func() error
	Offline      bool
	IndexKeyFile string
}

// BootstrapCore owns the same operation lock as core update, apply and managed
// state writes. A restart after the trial committed can finish from readback.
func (s *Service) BootstrapCore(ctx context.Context, version string) error {
	_, err := s.bootstrapCore(ctx, version)
	return err
}

func (s *Service) bootstrapCore(ctx context.Context, version string) (artifacts.Result, error) {
	var res artifacts.Result
	if s.bootstrap == nil || version != s.bootstrap.Version || s.repairBridge {
		return artifacts.Result{}, ErrBootstrapPending
	}
	if err := s.acquire(ctx); err != nil {
		return artifacts.Result{}, err
	}
	defer s.release()
	if !s.bootPending.Load() {
		return artifacts.Result{Outcome: artifacts.OutcomeNoop, Detail: "bootstrap complete"}, nil
	}
	st, rev := s.store.State()
	u := s.updater(st, rev)
	rs, err := s.runner.Status(ctx)
	if err != nil || rs.Candidate != nil || artifacts.HotPending(s.data) {
		return artifacts.Result{}, ErrBootstrapPending
	}
	if rs.Active == nil {
		// An interrupted or retained installation may contain a working state.
		// Only an unconfigured, all-direct state can receive a first core here.
		initial := store.Default()
		initial.Network = st.Network
		if !reflect.DeepEqual(st, initial) || rs.State != runnerapi.StateEmpty {
			return artifacts.Result{}, ErrBootstrapPending
		}
		if s.bootstrap.Offline {
			inbox := filepath.Join(s.data, "inbox")
			key, e := artifacts.InboxVerifier(inbox, s.bootstrap.IndexKeyFile)
			if e != nil {
				return artifacts.Result{}, ErrBootstrapPending
			}
			u.Fetch = artifacts.Chain{Sources: []artifacts.Source{artifacts.Inbox(inbox)}}
			u.Verify = key
		}
		if version == "latest" {
			v, err := artifacts.Latest(ctx, u.Verify.Upstream.Sources...)
			if err != nil {
				return artifacts.Result{}, ErrBootstrapPending
			}
			version = v.String()
		}
		// The updater can reuse an extracted slot without downloading its zip.
		// Check those bytes before the runner is asked to execute them.
		if _, err := inspectBootstrapSlot(s.data, version); err != nil {
			return artifacts.Result{}, ErrBootstrapPending
		}
		// Raw download and runner diagnostics are not installer output. The
		// usual update/trial history still records its public outcome.
		u.Redact = func(string) string { return "bootstrap" }
		if res, err = u.Update(ctx, version, artifacts.UpdateOptions{}); err != nil {
			return artifacts.Result{}, ErrBootstrapPending
		}
		rs, err = s.runner.Status(ctx)
	}
	if err != nil || rs.State != runnerapi.StateRunning || rs.Candidate != nil || rs.Active == nil || rs.Active.Validate() != nil || !rs.RoutesOK || !rs.GatewayUp {
		return artifacts.Result{}, ErrBootstrapPending
	}
	active := *rs.Active
	cfg, err := configName(u, &active)
	installed, slotErr := inspectBootstrapSlot(s.data, active.Core)
	if err != nil || cfg != active.Config || !installed || slotErr != nil || u.Health == nil || u.Health.Check(ctx) != nil {
		return artifacts.Result{}, ErrBootstrapPending
	}
	if err = s.prepareRouter(ctx, st, rev); err != nil {
		return artifacts.Result{}, ErrBootstrapPending
	}
	if err = s.finishRouter(ctx, st, rev); err != nil {
		return artifacts.Result{}, ErrBootstrapPending
	}
	now, err := s.runner.Status(ctx)
	if err != nil || now.State != runnerapi.StateRunning || now.Candidate != nil || now.Active == nil || *now.Active != active || !now.RoutesOK || !now.GatewayUp {
		return artifacts.Result{}, ErrBootstrapPending
	}
	if err = s.bootstrap.Ready(); err != nil {
		return artifacts.Result{}, ErrBootstrapPending
	}
	s.bootPending.Store(false)
	s.Kick()
	if res.Outcome == "" {
		res = artifacts.Result{Outcome: artifacts.OutcomeNoop, To: active.Core, Detail: "active core verified"}
	}
	return res, nil
}

func inspectBootstrapSlot(data, version string) (bool, error) {
	slots, err := artifacts.ListCores(filepath.Join(data, "cores"))
	if err != nil {
		return false, err
	}
	for _, slot := range slots {
		if slot.Version.String() != version {
			continue
		}
		if slot.Meta.Verified != "dgst" && slot.Meta.Verified != "index" {
			return true, ErrBootstrapPending
		}
		sum, err := artifacts.FileSHA256(filepath.Join(slot.Dir, "xray"))
		if err != nil || sum != slot.Meta.BinarySHA256 {
			return true, ErrBootstrapPending
		}
		return true, nil
	}
	return false, nil
}
