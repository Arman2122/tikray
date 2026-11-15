package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xrayver"
)

// A regular sweep, owner reimport, and a state-only edit must all preserve
// the same active domestic policy; a damaged slot cannot stand for no geo.
func TestActiveGeoSurvivesSweepsAndAttestation(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	installCore(t, e.data, testCore)
	r := &attestationRouter{}
	e.s = e.newService(Config{Router: r, Updaters: func(st store.State, rev uint64) *artifacts.CoreUpdater {
		u := e.updaters(st, rev)
		render := u.Render
		u.Render = func(v xrayver.Version, slot string) ([]byte, error) {
			if slot != "" {
				if _, _, err := artifacts.LoadGeo(e.data, slot); err != nil {
					return nil, artifacts.ErrGeoSlot
				}
			}
			return render(v, slot)
		}
		return u
	}})
	st, rev := e.s.State()
	const name = "fixture-release"
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	dir := filepath.Join(e.data, "geo", name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	hashes := map[string]string{}
	for name, v := range map[string]string{"geoip.dat": "fixture-IP", "geosite.dat": "fixture-domains", "domestic-v4.txt": prefix.String() + "\n"} {
		sum := sha256.Sum256([]byte(v))
		hashes[name] = hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0644); err != nil {
			t.Fatal(err)
		}
	}
	meta, _ := json.Marshal(map[string]any{"version": name, "sha256": hashes, "site": []string{"geosite:ir"}, "ip": []string{"geoip:ir"}})
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0644); err != nil {
		t.Fatal(err)
	}
	v, _ := xrayver.Parse(testCore)
	b, _ := renderFor(st, v, name)
	e.runner.setActive(artifacts.ConfigName(b))
	e.runner.mu.Lock()
	e.runner.st.Active.Geo = name
	e.runner.mu.Unlock()
	r.probe = func(_ context.Context, target routeros.Target) error {
		if !slices.Equal(target.Geo, []netip.Prefix{prefix}) || target.Selection.Geo != name {
			t.Fatal("attestation lost the active geo ranges")
		}
		return nil
	}
	if err := e.s.finishRouter(t.Context(), st, rev); err != nil {
		t.Fatal("verified geo could not be applied", err)
	}
	if len(r.verified) != 1 || !slices.Equal(r.verified[0].Geo, []netip.Prefix{prefix}) {
		t.Fatal("sweep changed active geo ranges")
	}
	if err := e.s.VerifyInstallation(t.Context()); err != nil {
		t.Fatal("installed geo did not survive owner attestation", err)
	}
	if err := os.Remove(filepath.Join(dir, "domestic-v4.txt")); err != nil {
		t.Fatal(err)
	}
	// Both the public status path and the regular sweep try to render before
	// normal router verification. They must identify this as geo degradation.
	status := e.s.Status(t.Context())
	if !status.GeoDegraded || status.Applied || status.Router.Degraded != "geo" {
		t.Fatal("status hid active geo corruption")
	}
	if !e.s.pass(t.Context(), time.Second) || len(r.verified) != 1 || e.s.routerStatus.Degraded != "geo" {
		t.Fatal("sweep changed native geo or misclassified the failure")
	}
	if err := e.s.finishRouter(t.Context(), st, rev); err == nil || len(r.verified) != 1 || e.s.routerStatus.Degraded != "geo" {
		t.Fatal("unreadable bundle was not reported, or overwrote the verified list")
	}
	if err := os.WriteFile(filepath.Join(dir, "domestic-v4.txt"), []byte(prefix.String()+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if e.s.pass(t.Context(), time.Second) {
		t.Fatal("valid repaired slot did not converge")
	}
	status = e.s.Status(t.Context())
	if !status.Applied || status.GeoDegraded || status.Router.Pending {
		t.Fatal("verified geo repair did not clear degraded status")
	}
	e.failRender(errors.New("unrelated config failure"))
	if e.s.Status(t.Context()).GeoDegraded {
		t.Fatal("unrelated renderer error marked the geo slot degraded")
	}
}

func TestRejectedGeoExposesDegradationAndPreservesVerifiedList(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	r := &testRouter{}
	e.s = e.newService(Config{Router: r})
	st, rev := e.s.State()
	if err := e.s.finishRouter(t.Context(), st, rev); err != nil {
		t.Fatal("router baseline failed")
	}
	writes := len(r.verified)
	if _, err := e.s.GeoUpdate(t.Context(), "custom", "missing-fixture"); err == nil {
		t.Fatal("missing offline bundle accepted")
	}
	got := e.s.Status(t.Context())
	if !got.GeoDegraded || !got.Applied || got.Router.Pending || len(r.verified) != writes || len(e.runner.gotTrials()) != 0 {
		t.Fatal("bad bundle hid degraded status or disturbed the previously effective selection")
	}
}

// A restarted daemon must finish the durable transaction before a saved
// state edit, even when editing a field that does not change router rules.
func TestManagedEditWaitsForGeoRecovery(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	r := &testRouter{}
	e.s = e.newService(Config{Router: r})
	st, rev := e.s.State()
	v, _ := xrayver.Parse(testCore)
	cfg, _ := renderFor(st, v, "")
	old := runnerapi.Selection{Core: testCore, Config: artifacts.ConfigName(cfg)}
	next := old
	next.Geo = "release-b"
	raw, _ := json.Marshal(map[string]any{"version": 1, "from": old, "to": next})
	if os.MkdirAll(filepath.Join(e.data, "geo"), 0755) != nil || os.WriteFile(filepath.Join(e.data, "state", "geo-pending.json"), raw, 0600) != nil {
		t.Fatal("geo recovery fixture unavailable")
	}
	e.runner.setDown(true)
	if _, err := e.s.SetDefaultPolicy(t.Context(), rev, st.DefaultPolicy); err == nil {
		t.Fatal("edit raced a still-undecided geo selection")
	}
	if _, saved := e.s.State(); saved != rev || !artifacts.GeoPending(e.data) || r.count() != 0 {
		t.Fatal("unconfirmed runner changed revision, router policy or pending evidence")
	}
	e.runner.setDown(false)
	if err := e.s.recoverGeo(t.Context()); err != nil || artifacts.GeoPending(e.data) || r.count() != 1 {
		t.Fatal("could not restore the previously committed no-geo policy on startup", err)
	}
	if _, err := e.s.SetDefaultPolicy(t.Context(), rev, st.DefaultPolicy); err != nil {
		t.Fatal("verified recovery did not unblock later edits")
	}
}

func TestGeoRequestDoesNotReplayAnUndecidedRollback(t *testing.T) {
	e := newEnv(t)
	e.inSync()
	r := &testRouter{}
	e.s = e.newService(Config{Router: r})
	st, _ := e.s.State()
	v, _ := xrayver.Parse(testCore)
	config, _ := renderFor(st, v, "")
	now := runnerapi.Selection{Core: testCore, Config: artifacts.ConfigName(config)}
	previous := now
	previous.Geo = "candidate-slot"
	journal, _ := json.Marshal(map[string]any{"version": 1, "from": now, "to": previous})
	if os.MkdirAll(filepath.Join(e.data, "geo"), 0755) != nil || os.WriteFile(filepath.Join(e.data, "state", "geo-pending.json"), journal, 0600) != nil {
		t.Fatal("could not set the interrupted operation")
	}
	_, err := e.s.GeoRollback(t.Context())
	if !errors.Is(err, artifacts.ErrGeoPending) || !artifacts.GeoPending(e.data) || r.count() != 0 || len(e.runner.gotTrials()) != 0 {
		t.Fatal("a new rollback processed the previous journal and attempted a second operation")
	}
}
