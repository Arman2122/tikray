package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
)

// The automatic check uses the same verified updater as a manual request.
// Even when that updater reports a content no-op, a minute tick, concurrent
// call or restarted process must not fetch the release again before a day.
func TestGeoDailyChecksCoalesceAcrossRestart(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	var calls atomic.Int32
	update := func(ctx context.Context, profile, version string) (artifacts.Result, error) {
		if profile != "" || version != "latest" {
			t.Fatal("daily check did not resolve the current configured profile under the writer")
		}
		calls.Add(1)
		return artifacts.Result{Outcome: artifacts.OutcomeNoop}, nil
	}
	before := len(e.runner.gotCalls())
	e.s.checkGeoDue(t.Context(), update)
	if calls.Load() != 0 || len(e.runner.gotCalls()) != before {
		t.Fatal("empty installation fetched a geo bundle")
	}
	e.s = e.newService(Config{GeoProfile: "iran"})
	if s, err := e.s.selectedGeoProfile(t.Context()); err != nil || s != "iran" {
		t.Fatal("configured profile not selected")
	}
	var group sync.WaitGroup
	for range 4 {
		group.Add(1)
		go func() { defer group.Done(); e.s.checkGeoDue(t.Context(), update) }()
	}
	group.Wait()
	e.s = e.newService(Config{GeoProfile: "iran"})
	e.s.checkGeoDue(t.Context(), update)
	if calls.Load() != 1 {
		t.Fatal("duplicate geo check on repeated tick or restart")
	}
	e.clock.advance(-time.Hour)
	e.s.checkGeoDue(t.Context(), update)
	e.clock.advance(25*time.Hour - time.Second)
	e.s.checkGeoDue(t.Context(), update)
	if calls.Load() != 1 {
		t.Fatal("daily check ran early")
	}
	e.clock.advance(time.Second)
	e.s.checkGeoDue(t.Context(), update)
	if calls.Load() != 2 {
		t.Fatal("daily check never became due")
	}
}

func TestGeoDailyRefusesUnreadableClaim(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	e.s = e.newService(Config{GeoProfile: "iran"})
	const private = "private-schedule-fixture"
	if os.WriteFile(filepath.Join(e.data, "state", "geo-check.json"), []byte(private), 0600) != nil {
		t.Fatal("cannot prepare malformed receipt")
	}
	e.s.checkGeoDue(t.Context(), func(context.Context, string, string) (artifacts.Result, error) {
		t.Fatal("malformed receipt authorized daily activity")
		return artifacts.Result{}, nil
	})
	for _, ev := range e.s.Events(0) {
		if strings.Contains(ev.Message, private) {
			t.Fatal("scheduling diagnostics disclosed invalid receipt")
		}
	}
}

func TestDailyGeoProfileFollowsCommittedSlot(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	release := strings.Repeat("a", 64)
	slot := "g-" + release[:62]
	dir := filepath.Join(e.data, "geo", slot)
	if os.MkdirAll(dir, 0755) != nil {
		t.Fatal("cannot create test slot")
	}
	hashes := map[string]string{"geoip.dat": release, "geosite.dat": release, "domestic-v4.txt": release}
	m, err := json.Marshal(map[string]any{"version": slot, "profile": "iran", "release_id": release, "sha256": hashes})
	if err != nil || os.WriteFile(filepath.Join(dir, "meta.json"), m, 0644) != nil {
		t.Fatal("cannot create test slot metadata")
	}
	e.runner.mu.Lock()
	e.runner.st.Active.Geo = slot
	e.runner.mu.Unlock()
	profile, err := e.s.selectedGeoProfile(t.Context())
	if err != nil || profile != "iran" {
		t.Fatal("did not derive publisher from active slot")
	}
	e.s = e.newService(Config{GeoProfile: "custom"})
	profile, err = e.s.selectedGeoProfile(t.Context())
	if err != nil || profile != "custom" {
		t.Fatal("owner default did not override installed publisher")
	}
	if os.Remove(filepath.Join(dir, "meta.json")) != nil {
		t.Fatal("cannot damage test metadata")
	}
	if _, err = e.s.selectedGeoProfile(t.Context()); err == nil {
		t.Fatal("unreadable active slot authorized a fallback")
	}
	e.runner.mu.Lock()
	e.runner.st.Active.Geo = ""
	e.runner.mu.Unlock()
	e.s = e.newService(Config{})
	profile, err = e.s.selectedGeoProfile(t.Context())
	if err != nil || profile != "" {
		t.Fatal("returned to a retired publisher after rollback to no geo")
	}
}

func TestGeoDailyFailureDoesNotLoop(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	e.s = e.newService(Config{GeoProfile: "custom"})
	checks := 0
	update := func(context.Context, string, string) (artifacts.Result, error) {
		checks++
		return artifacts.Result{}, errors.New("fixture cannot fetch a release")
	}
	e.s.checkGeoDue(t.Context(), update)
	e.clock.advance(time.Hour)
	e.s = e.newService(Config{GeoProfile: "custom"})
	e.s.checkGeoDue(t.Context(), update)
	if checks != 1 {
		t.Fatal("restarted scheduler retried failed fetch within one day")
	}
	e.clock.advance(23 * time.Hour)
	e.s.checkGeoDue(t.Context(), update)
	if checks != 2 {
		t.Fatal("failed publisher check was not retried next day")
	}
}
