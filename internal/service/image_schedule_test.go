package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
)

func TestImageSchedulesDefaultToNotify(t *testing.T) {
	e := newEnv(t)
	cfg, err := ParseImageSchedule("", "")
	if err != nil || cfg.auto {
		t.Fatal("images did not default to notification")
	}
	manual, _ := ParseImageSchedule("manual", "")
	auto, err := ParseImageSchedule("auto", "23:00-01:00")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 16, 23, 30, 0, 0, time.UTC)
	e.s.now = func() time.Time { return now }
	var checks, swaps int
	check := func(context.Context, string) (string, error) { checks++; return "v2", nil }
	swap := func(context.Context, string, string) (artifacts.ImageOperation, error) {
		swaps++
		return artifacts.ImageOperation{}, nil
	}
	e.s.scheduleImage(t.Context(), "tikray", manual, check, swap)
	e.s.scheduleImage(t.Context(), "tikray", cfg, check, swap)
	e.s.scheduleImage(t.Context(), "tikray", cfg, check, swap)
	if checks != 1 || swaps != 0 {
		t.Fatal("manual/notify policy staged an image or repeated a check")
	}
	if list := e.s.Events(0); len(list) != 1 || list[0].Message != "image release available for tikray" {
		t.Fatal("missing fixed availability event")
	}
	e.s.scheduleImage(t.Context(), "runner", auto, check, swap)
	now = now.Add(time.Hour)
	e.s.scheduleImage(t.Context(), "runner", auto, check, swap)
	if checks != 2 || swaps != 1 {
		t.Fatal("auto window was skipped or repeated across midnight")
	}
	e.s = e.newService(Config{})
	e.s.now = func() time.Time { return now }
	e.s.scheduleImage(t.Context(), "runner", auto, check, swap)
	if swaps != 1 {
		t.Fatal("restart repeated a scheduled replacement")
	}
	if os.WriteFile(filepath.Join(e.data, "state", "image-update.json"), []byte("undecided"), 0600) != nil {
		t.Fatal("fixture")
	}
	now = now.AddDate(0, 0, 1)
	e.s.scheduleImage(t.Context(), "runner", auto, check, swap)
	if checks != 2 || swaps != 1 {
		t.Fatal("scheduled check raced an unresolved replacement")
	}
}
