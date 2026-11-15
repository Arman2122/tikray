package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
)

// GeoSchedule controls the automatic geo check. Its zero value runs daily
// without a time restriction. It never controls an explicit owner request.
type GeoSchedule struct {
	mode       string
	start, end int // minutes after midnight UTC; zero pair means all day
}

// ParseGeoSchedule validates the optional mode and daily UTC window.
func ParseGeoSchedule(mode, window string) (GeoSchedule, error) {
	var p GeoSchedule
	switch mode {
	case "", "auto":
	case "notify", "manual":
		p.mode = mode
	default:
		return GeoSchedule{}, errors.New("service: invalid geo update mode")
	}
	if window == "" {
		return p, nil
	}
	left, right, ok := strings.Cut(window, "-")
	a, errA := time.Parse("15:04", left)
	b, errB := time.Parse("15:04", right)
	if !ok || len(left) != 5 || len(right) != 5 || errA != nil || errB != nil || a.Equal(b) {
		return GeoSchedule{}, errors.New("service: invalid UTC geo update window")
	}
	p.start, p.end = a.Hour()*60+a.Minute(), b.Hour()*60+b.Minute()
	return p, nil
}

// due returns true once per explicit window, counting both sides of a
// midnight-crossing window together. Without a window wait a full 24h.
func (p GeoSchedule) due(now, last time.Time) bool {
	if p.mode == "manual" || now.Before(last) {
		return false
	}
	if p.start == p.end {
		return last.IsZero() || !now.Before(last.Add(24*time.Hour))
	}
	now = now.UTC()
	open := time.Date(now.Year(), now.Month(), now.Day(), p.start/60, p.start%60, 0, 0, time.UTC)
	minute := now.Hour()*60 + now.Minute()
	if p.end < p.start && minute < p.end {
		open = open.AddDate(0, 0, -1)
	}
	duration := (p.end - p.start + 24*60) % (24 * 60)
	return !now.Before(open) && now.Before(open.Add(time.Duration(duration)*time.Minute)) && last.Before(open)
}

func (s *Service) notifyGeo(ctx context.Context) error {
	if artifacts.GeoPending(s.data) {
		return artifacts.ErrGeoPending
	}
	active, err := s.geoScheduleSelection(ctx)
	if err != nil {
		return err
	}
	profile, err := s.profileForSlot(active.Geo)
	if err != nil || profile == "" {
		return err
	}
	st, rev := s.store.State()
	available, err := s.updater(st, rev).GeoReleaseAvailable(ctx, profile, active.Geo)
	if err != nil || !available {
		return err
	}
	// An external publisher can be slow. Take the service writer only for
	// the final local observation and event; policy recovery can proceed
	// throughout the network read.
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	if artifacts.GeoPending(s.data) {
		return artifacts.ErrGeoPending
	}
	live, err := s.geoScheduleSelection(ctx)
	if err != nil || active != live {
		return ErrRunnerUnavailable
	}
	s.record(KindGeo, "a new geo release is available")
	return nil
}
