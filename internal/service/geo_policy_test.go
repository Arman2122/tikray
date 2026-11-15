package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/store"
)

func TestGeoSchedulerRespectsOwnerWindowAndMode(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	// Use a non-UTC location so accepting local hours by mistake fails.
	loc := time.FixedZone("fixture", -4*3600)
	now := time.Date(2026, 11, 15, 17, 59, 0, 0, loc) // 21:59 UTC
	set := func(mode, window string) {
		policy, err := ParseGeoSchedule(mode, window)
		if err != nil {
			t.Fatal("unexpected invalid schedule")
		}
		e.s = e.newService(Config{GeoProfile: "custom", GeoSchedule: policy, Now: func() time.Time { return now }})
	}
	var calls int
	update := func(context.Context, string, string) (artifacts.Result, error) {
		calls++
		return artifacts.Result{}, nil
	}
	check := func(want int) {
		t.Helper()
		e.s.checkGeoDue(t.Context(), update)
		if calls != want {
			t.Fatalf("unexpected daily update count %d, want %d", calls, want)
		}
	}
	receipt := filepath.Join(e.data, "state", "geo-check.json")
	set("manual", "")
	check(0)
	if _, err := os.Stat(receipt); !os.IsNotExist(err) {
		t.Fatal("manual scheduling reserved a day")
	}
	set("auto", "22:00-02:00")
	check(0)
	if _, err := os.Stat(receipt); !os.IsNotExist(err) {
		t.Fatal("check outside window reserved a day")
	}
	now = now.Add(time.Minute)
	check(1)
	now = now.Add(3 * time.Hour)
	set("auto", "22:00-02:00")
	check(1)
	now = now.Add(time.Hour)
	check(1) // end excluded
	// Wait until late in a later window to exercise restart close to midnight.
	now = now.Add(23 * time.Hour)
	check(2)
	now = now.Add(21 * time.Hour)
	set("auto", "22:00-02:00")
	check(3)
	now = now.Add(-24 * time.Hour)
	check(3)
	// A narrow window's check can occur at different seconds on adjacent days.
	set("auto", "08:30-08:31")
	now = time.Date(2026, 11, 20, 8, 30, 58, 0, time.UTC)
	check(4)
	now = time.Date(2026, 11, 21, 8, 30, 8, 0, time.UTC)
	check(5)
}

func TestGeoNotifyOnlyChecksTrustedRelease(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	var lookups, other atomic.Int32
	const private = "private-publisher-label"
	publisher := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest" {
			lookups.Add(1)
			io.WriteString(w, private)
			return
		}
		other.Add(1)
		http.NotFound(w, r)
	}))
	defer publisher.Close()
	r := &testRouter{}
	policy, err := ParseGeoSchedule("notify", "")
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Router: r, GeoProfile: "custom", GeoSchedule: policy, Updaters: func(st store.State, rev uint64) *artifacts.CoreUpdater {
		u := e.updaters(st, rev)
		u.GeoSource = artifacts.GeoSourceConfig{CustomURL: publisher.URL, Direct: publisher.Client()}
		return u
	}}
	e.s = e.newService(config)
	update := func(context.Context, string, string) (artifacts.Result, error) {
		t.Fatal("notify mode ran the updater")
		return artifacts.Result{}, nil
	}
	e.s.checkGeoDue(t.Context(), update)
	got := e.s.Events(0)
	if len(got) != 1 || got[0].Kind != KindGeo || got[0].Message != "a new geo release is available" || strings.Contains(got[0].Message, private) {
		t.Fatal("missing or unsafe update notification")
	}
	e.s = e.newService(config)
	e.s.checkGeoDue(t.Context(), update)
	if lookups.Load() != 1 || other.Load() != 0 || len(e.runner.gotTrials()) != 0 || len(r.prepared)+r.count() != 0 || artifacts.GeoPending(e.data) {
		t.Fatal("notify exceeded a single trusted release check")
	}
	if _, err := os.Stat(filepath.Join(e.data, "geo")); !os.IsNotExist(err) {
		t.Fatal("notify created a slot")
	}
}

func TestGeoNotificationDoesNotHoldPolicyWriterDuringPublisherRead(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	lookup, release := make(chan struct{}), make(chan struct{})
	pub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(lookup)
		<-release
		io.WriteString(w, "r2")
	}))
	defer pub.Close()
	e.s = e.newService(Config{GeoProfile: "custom", Updaters: func(st store.State, rev uint64) *artifacts.CoreUpdater {
		u := e.updaters(st, rev)
		u.GeoSource = artifacts.GeoSourceConfig{CustomURL: pub.URL, Direct: pub.Client()}
		return u
	}})
	done := make(chan error, 1)
	go func() { done <- e.s.notifyGeo(t.Context()) }()
	select {
	case <-lookup:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("no publisher observation")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	err := e.s.acquire(ctx)
	if err == nil {
		e.s.release()
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal("notify failed")
	}
	if err != nil {
		t.Fatal("a read-only publisher notification blocked the policy writer")
	}
}
