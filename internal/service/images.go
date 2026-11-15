package service

import (
	"context"
	"errors"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

func (s *Service) ImageStatus(_ context.Context, component string) (artifacts.ImageStatus, error) {
	if s.router == nil || !artifacts.ValidImageComponent(component) {
		return artifacts.ImageStatus{}, artifacts.ErrImageState
	}
	status, err := artifacts.ReadImageStatus(s.data, component)
	if err != nil {
		return artifacts.ImageStatus{}, artifacts.ErrImageState
	}
	return status, nil
}

func (s *Service) ImageUpdate(ctx context.Context, component, version string) (artifacts.ImageOperation, error) {
	if !artifacts.ValidImageComponent(component) || !artifacts.ValidImageVersion(version) {
		return artifacts.ImageOperation{}, &Refused{Reason: "invalid image component or release"}
	}
	return s.imageChange(ctx, component, version)
}
func (s *Service) ImageRollback(ctx context.Context, component string) (artifacts.ImageOperation, error) {
	if !artifacts.ValidImageComponent(component) {
		return artifacts.ImageOperation{}, &Refused{Reason: "invalid image component"}
	}
	return s.imageChange(ctx, component, "")
}
func (s *Service) imageChange(ctx context.Context, component, version string) (artifacts.ImageOperation, error) {
	var none artifacts.ImageOperation
	if s.router == nil || s.repairBridge || (version != "" && s.imagesDisabled) {
		return none, artifacts.ErrImageState
	}
	if s.bootPending.Load() {
		return none, ErrBootstrapPending
	}
	if err := s.acquire(ctx); err != nil {
		return none, err
	}
	defer s.release()
	if artifacts.ImagePending(s.data) {
		return none, artifacts.ErrImageBusy
	}
	if artifacts.HotPending(s.data) || artifacts.GeoPending(s.data) {
		return none, artifacts.ErrLocked
	}
	if _, err := artifacts.ReadImageStatus(s.data, component); err != nil {
		return none, artifacts.ErrImageState
	}
	st, rev := s.store.State()
	if version == "" && component == "runner" {
		// Preparation retains native protections while the unavailable
		// runner is verified from its durable selection by BeginImageRollback.
		if err := s.prepareRouter(ctx, st, rev); err != nil {
			return none, err
		}
	} else if err := s.finishRouter(ctx, st, rev); err != nil {
		return none, err
	}
	u := s.updater(st, rev)
	var op artifacts.ImageOperation
	var err error
	if version == "" {
		op, err = u.BeginImageRollback(ctx, component)
	} else {
		var img artifacts.VerifiedImage
		img, err = u.StageImage(ctx, component, version)
		if err != nil {
			if errors.Is(err, artifacts.ErrLocked) || ctx.Err() != nil {
				return none, err
			}
			return none, &Refused{Reason: "signed release image could not be verified"}
		}
		op, err = u.BeginImageUpdate(ctx, img)
	}
	if err != nil {
		if errors.Is(err, artifacts.ErrImageBusy) || errors.Is(err, artifacts.ErrImagePrevious) || errors.Is(err, artifacts.ErrLocked) {
			return none, err
		}
		return none, artifacts.ErrImageState
	}
	s.record(KindImage, "watchdog replacement requested for "+component)
	return op, nil
}

// A ping can succeed with xray absent. Verify authenticated runner status,
// the saved selection, TUN and gateway, the live xray API and, when the
// config has a proxy, a request through it. Sample process identity again.
func (s *Service) verifyImageDataPath(ctx context.Context, expected string) error {
	st, rev := s.store.State()
	u := s.updater(st, rev)
	before, err := s.runner.Status(ctx)
	if err != nil || before.Active == nil || before.XrayPID <= 0 || artifacts.ImageSelectionDigest(*before.Active) != expected || !s.verifiedInstallSelection(ctx, u, before) {
		return artifacts.ErrImageState
	}
	if u.ProxyHealth != nil && u.ProxyHealth.Check(ctx) != nil {
		return artifacts.ErrImageState
	}
	after, err := s.runner.Status(ctx)
	if err != nil || after.Active == nil || after.State != runnerapi.StateRunning || after.Candidate != nil || *after.Active != *before.Active || after.XrayPID != before.XrayPID || after.XrayInstance != before.XrayInstance || !after.RoutesOK || !after.GatewayUp {
		return artifacts.ErrImageState
	}
	if _, current := s.store.State(); current != rev {
		return artifacts.ErrImageState
	}
	return nil
}

// The watchdog stays authoritative while either container is unavailable.
// Only publish a fresh health answer to its challenge. After it retires a
// request, a restarted service can also reclaim superseded verified archives.
func (s *Service) watchImages(ctx context.Context) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	wasPending, prune := false, true
	var nextClean time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if artifacts.ImagePending(s.data) {
			wasPending = true
			check, cancel := context.WithTimeout(ctx, 20*time.Second)
			_ = artifacts.ProveRunnerImage(check, s.data, s.verifyImageDataPath)
			cancel()
			continue
		}
		if wasPending {
			wasPending, prune = false, true
			nextClean = time.Time{}
			s.Kick()
		}
		if !prune || time.Now().Before(nextClean) {
			continue
		}
		if s.acquire(ctx) != nil {
			return
		}
		if !artifacts.ImagePending(s.data) {
			prune = artifacts.PruneInstalledImages(ctx, s.data) != nil
			if !prune && store.Current > 1 {
				a, p, e := artifacts.RetainedStateSchemas(ctx, s.data)
				prune = e != nil || s.store.PruneImageState(a, p) != nil
			}
			nextClean = time.Now().Add(time.Minute)
		}
		s.release()
	}
}
