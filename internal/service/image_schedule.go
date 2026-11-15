package service

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/atomicfile"
)

// ImageSchedule uses the same UTC window as geo. Unlike geo, an unset
// image policy is notify-only; activation requires an explicit opt-in.
type ImageSchedule struct {
	window GeoSchedule
	auto   bool
}
type ImageSchedules struct{ Control, Runner ImageSchedule }

func ParseImageSchedule(mode, window string) (ImageSchedule, error) {
	p, err := ParseGeoSchedule(mode, window)
	if err != nil {
		return ImageSchedule{}, errors.New("service: invalid image update policy or UTC window")
	}
	return ImageSchedule{window: p, auto: mode == "auto"}, nil
}

func (s *Service) checkImagesDue(ctx context.Context) {
	if s.imageSchedules == nil || s.router == nil || s.repairBridge || s.bootPending.Load() {
		return
	}
	st, rev := s.store.State()
	latest := s.updater(st, rev).NextInstalledImageRelease
	s.scheduleImage(ctx, "tikray", s.imageSchedules.Control, latest, s.ImageUpdate)
	s.scheduleImage(ctx, "runner", s.imageSchedules.Runner, latest, s.ImageUpdate)
}

// Only the scheduler writes these two private attempt receipts. Reserve each
// window before contacting the publisher so a reboot cannot repeat an update.
func (s *Service) scheduleImage(ctx context.Context, component string, policy ImageSchedule, latest func(context.Context, string) (string, error), swap func(context.Context, string, string) (artifacts.ImageOperation, error)) {
	now := s.now().UTC()
	if ctx.Err() != nil || !policy.window.due(now, time.Time{}) || artifacts.ImagePending(s.data) {
		return
	}
	path := filepath.Join(s.data, "state", "image-check-"+component+".json")
	b, err := atomicfile.ReadRegular(path, 256, 0600)
	var last time.Time
	if err == nil {
		if json.Unmarshal(b, &last) != nil || last.IsZero() || !policy.window.due(now, last) {
			return
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return
	}
	b, err = json.Marshal(now)
	if err != nil || atomicfile.WriteFile(path, b, 0600) != nil {
		return
	}
	version, err := latest(ctx, component)
	if err != nil {
		if ctx.Err() == nil {
			s.record(KindImage, "could not verify the release for "+component)
		}
		return
	}
	if version == "" || artifacts.ImagePending(s.data) {
		return
	}
	if !policy.auto {
		s.record(KindImage, "image release available for "+component)
		return
	}
	if _, err := swap(ctx, component, version); err != nil && ctx.Err() == nil {
		s.record(KindImage, "scheduled image change was not queued for "+component)
	}
}
