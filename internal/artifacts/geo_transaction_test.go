package artifacts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/xrayver"
)

type geoTrialEnv struct {
	*coreEnv
	geo      GeoUpdater
	ranges   []netip.Prefix
	finishes []string
	prepares int
}

func seededGeo(t *testing.T, data, version, prefix string) {
	t.Helper()
	d := filepath.Join(data, "geo", version)
	if os.MkdirAll(d, 0755) != nil {
		t.Fatal("cannot seed geo slot")
	}
	files := map[string]string{"domestic-v4.txt": prefix, "geoip.dat": "ip data " + version, "geosite.dat": "site data " + version}
	hashes := map[string]string{}
	for name, b := range files {
		hashes[name] = shaOf(b)
		writeTestFile(t, filepath.Join(d, name), b)
	}
	b, err := json.Marshal(geoMeta{Version: version, SHA256: hashes})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(d, "meta.json"), string(b))
}

func newGeoTrialEnv(t *testing.T) *geoTrialEnv {
	t.Helper()
	e := &geoTrialEnv{coreEnv: newCoreEnv(t, "26.10.21")}
	seededGeo(t, e.data, "g1", "192.0.2.0/24\n198.51.100.0/24")
	seededGeo(t, e.data, "g2", "198.51.100.0/24\n203.0.113.0/24")
	_, e.ranges, _ = LoadGeo(e.data, "g1")
	e.u.Render = func(core xrayver.Version, geo string) ([]byte, error) {
		if geo == "g1" || geo == "" {
			return []byte(activeConfigBody), nil
		}
		return []byte(renderedBody), nil
	}
	e.geo = GeoUpdater{Core: e.u, Stage: func(context.Context, string, string) (string, error) { return "g2", nil }}
	e.geo.Prepare = func(ctx context.Context, old, next runnerapi.Selection, before, after []netip.Prefix) error {
		if !GeoPending(e.data) {
			t.Fatal("router write before durable journal")
		}
		if e.runner.activeSelection() != old {
			t.Fatal("router prepared after changing runner")
		}
		e.prepares++
		var restricted []netip.Prefix
		for _, prefix := range before {
			if slices.Contains(after, prefix) {
				restricted = append(restricted, prefix)
			}
		}
		e.ranges = restricted
		return nil
	}
	e.geo.Finish = func(ctx context.Context, active runnerapi.Selection, ranges []netip.Prefix) error {
		if !GeoPending(e.data) || e.runner.activeSelection() != active {
			t.Fatal("router admitted ranges without a matching committed selection")
		}
		e.finishes = append(e.finishes, active.Geo)
		e.ranges = slices.Clone(ranges)
		return nil
	}
	return e
}

func TestGeoTrialFailureRestoresPreviousList(t *testing.T) {
	e := newGeoTrialEnv(t)
	before := slices.Clone(e.ranges)
	e.runner.script(func(f *fakeRunner) {
		f.onTrial = func(w http.ResponseWriter, c runnerapi.Candidate) bool {
			if !GeoPending(e.data) || !slices.Equal(e.ranges, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}) {
				t.Error("obsolete exemption remained during candidate test")
			}
			// The runner discards candidate.json on a definite xray -test rejection.
			if err := os.Remove(filepath.Join(e.data, "run", "candidate.json")); err != nil {
				t.Error("runner did not receive candidate")
			}
			fakeError(w, http.StatusUnprocessableEntity, "test_failed", "private-geo-input")
			return true
		}
	})
	res, err := e.geo.Update(t.Context(), "custom", "g2")
	if err == nil || res.Outcome != runnerapi.OutcomeRejected || e.prepares != 1 || !slices.Equal(e.finishes, []string{"g1"}) || !slices.Equal(e.ranges, before) || GeoPending(e.data) {
		t.Fatal("rejected candidate damaged the previous verified state")
	}
	if slices.ContainsFunc(e.history(t), func(r Result) bool { return r.Detail == "private-geo-input" }) {
		t.Fatal("private trial output entered history")
	}
}

func TestGeoCrashAtEachBoundary(t *testing.T) {
	for _, phase := range []string{"journal", "router-prepared", "trial-open", "runner-committed", "router-finished", "rollback-saved"} {
		t.Run(phase, func(t *testing.T) {
			e := newGeoTrialEnv(t)
			before := e.runner.activeSelection()
			after := runnerapi.Selection{Core: before.Core, Geo: "g2", Config: configRel(renderedBody)}
			p := geoTransition{Version: 1, From: before, To: after}
			if phase != "journal" && phase != "router-prepared" {
				p.Deadline = t0.Add(e.u.trialDeadline())
			}
			if err := newConfig([]byte(renderedBody)).write(e.u.runDir()); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(e.data, "state"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := writeGeoState(e.data, geoPendingFile, p); err != nil {
				t.Fatal(err)
			}
			if phase != "journal" {
				e.ranges = nil
			}
			if phase == "trial-open" {
				e.runner.script(func(f *fakeRunner) {
					f.st.State = runnerapi.StateTrial
					f.st.Candidate = &runnerapi.Candidate{Selection: after}
				})
				if e.geo.Recover(t.Context()) == nil || !GeoPending(e.data) || len(e.finishes) > 0 {
					t.Fatal("a live trial was treated as committed")
				}
				e.runner.script(func(f *fakeRunner) { f.st.State = runnerapi.StateRunning; f.st.Candidate = nil })
			}
			want := before
			if phase == "runner-committed" || phase == "router-finished" || phase == "rollback-saved" {
				want = after
				e.runner.script(func(f *fakeRunner) { f.st.Active = &after })
			}
			if phase == "router-finished" || phase == "rollback-saved" {
				_, e.ranges, _ = LoadGeo(e.data, after.Geo)
			}
			if phase == "rollback-saved" {
				if err := writeGeoState(e.data, geoVersionsFile, p); err != nil {
					t.Fatal(err)
				}
			}
			if err := e.geo.Recover(t.Context()); err != nil {
				t.Fatal(err)
			}
			_, ranges, _ := LoadGeo(e.data, want.Geo)
			if GeoPending(e.data) || !slices.Equal(e.ranges, ranges) || !slices.Equal(e.finishes, []string{want.Geo}) || len(e.runner.candidates()) != 0 {
				t.Fatal("recovery picked the wrong side or replayed a trial")
			}
			if err := e.geo.Recover(t.Context()); err != nil || len(e.finishes) != 1 {
				t.Fatal("completed recovery was repeated")
			}
			if want == after {
				res, err := e.geo.Rollback(t.Context())
				if err != nil || res.Outcome != runnerapi.OutcomeCommitted || e.runner.activeSelection() != before {
					t.Fatal("previous geo unavailable after recovery", err)
				}
			}
		})
	}
}

func TestGeoRollbackToNoGeo(t *testing.T) {
	e := newGeoTrialEnv(t)
	sel := e.runner.activeSelection()
	sel.Geo = ""
	e.runner.script(func(f *fakeRunner) { f.st.Active = &sel })
	if _, err := e.geo.Update(t.Context(), "custom", "g2"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.geo.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if e.runner.activeSelection() != sel || len(e.ranges) != 0 || GeoPending(e.data) {
		t.Fatal("rollback lost no-geo selection")
	}
	if h := committedVersions(e.history(t)); len(h) != 0 {
		t.Fatal("geo commits counted as core rollback targets")
	}
}

func TestGeoRecoveryKeepsMarkerWhenUncertain(t *testing.T) {
	e := newGeoTrialEnv(t)
	before := e.runner.activeSelection()
	p := geoTransition{Version: 1, From: before, To: runnerapi.Selection{Core: before.Core, Geo: "g2", Config: configRel(renderedBody)}}
	if err := os.MkdirAll(filepath.Join(e.data, "state"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeGeoState(e.data, geoPendingFile, p); err != nil {
		t.Fatal(err)
	}
	e.geo.Finish = func(context.Context, runnerapi.Selection, []netip.Prefix) error {
		return errors.New("native_unavailable")
	}
	if e.geo.Recover(t.Context()) == nil || !GeoPending(e.data) {
		t.Fatal("lost journal despite incomplete readback")
	}
	if _, err := e.u.Apply(t.Context()); err == nil || len(e.runner.candidates()) != 0 {
		t.Fatal("ordinary apply raced pending geo recovery")
	}
	bad := before
	bad.Config = configRel("another config")
	e.runner.script(func(f *fakeRunner) { f.st.Active = &bad })
	e.geo.Finish = func(context.Context, runnerapi.Selection, []netip.Prefix) error {
		t.Fatal("guessed an unrelated runner selection")
		return nil
	}
	if e.geo.Recover(t.Context()) == nil || !GeoPending(e.data) {
		t.Fatal("cleared unknown selection")
	}
}

func TestGeoDailyNoWritesOnSameBundle(t *testing.T) {
	e := newGeoTrialEnv(t)
	d := filepath.Join(e.data, "geo", "g3")
	if err := os.Mkdir(d, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"geoip.dat", "geosite.dat", "domestic-v4.txt", metaFile} {
		b, err := os.ReadFile(filepath.Join(e.data, "geo", "g1", name))
		if err != nil {
			t.Fatal(err)
		}
		if name == metaFile {
			var m geoMeta
			if json.Unmarshal(b, &m) != nil {
				t.Fatal("unreadable fixture")
			}
			m.Version = "g3"
			b, err = json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
		}
		if os.WriteFile(filepath.Join(d, name), b, 0644) != nil {
			t.Fatal("cannot seed identical geo input")
		}
	}
	e.geo.Stage = func(context.Context, string, string) (string, error) { return "g3", nil }
	for range 2 {
		res, err := e.geo.Update(t.Context(), "custom", "latest")
		if err != nil || res.Outcome != OutcomeNoop || GeoPending(e.data) || e.prepares != 0 || len(e.finishes) != 0 || len(e.runner.candidates()) != 0 {
			t.Fatal("identical verified bundle caused side effects", err)
		}
	}
	if e.runner.activeSelection() != e.activeSel {
		t.Fatal("identical content switched runner")
	}
}

func TestGeoRefusesBeforeTrial(t *testing.T) {
	for _, reason := range []string{"unsaved replacement", "damaged current list", "bad new checksum", "write lock", "hot repair", "slot history corrupt"} {
		t.Run(reason, func(t *testing.T) {
			e := newGeoTrialEnv(t)
			switch reason {
			case "unsaved replacement":
				e.u.NoState = true
				e.u.Render = func(xrayver.Version, string) ([]byte, error) { return []byte(renderedBody), nil }
			case "damaged current list":
				if os.Remove(filepath.Join(e.data, "geo", "g1", "domestic-v4.txt")) != nil {
					t.Fatal("could not damage fixture")
				}
			case "bad new checksum":
				writeTestFile(t, filepath.Join(e.data, "geo", "g2", "geoip.dat"), "private-tampered-input")
			case "write lock":
				unlock, err := lockState(e.u.stateDir())
				if err != nil {
					t.Fatal(err)
				}
				defer unlock()
			case "hot repair":
				if err := os.MkdirAll(e.u.hotDir(), 0700); err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, pendingPath(e.data), "private-input")
			case "slot history corrupt":
				if err := os.MkdirAll(e.u.stateDir(), 0700); err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, filepath.Join(e.u.stateDir(), geoVersionsFile), "private-input")
			}
			old := slices.Clone(e.ranges)
			if _, err := e.geo.Update(t.Context(), "custom", "g2"); err == nil || !slices.Equal(old, e.ranges) || e.prepares != 0 || len(e.runner.candidates()) != 0 || GeoPending(e.data) {
				t.Fatal("refusal damaged previous allow-list or opened trial")
			}
		})
	}
}

func TestGeoPreservesForeignAndUndecidedCandidateFile(t *testing.T) {
	e := newGeoTrialEnv(t)
	before := e.runner.activeSelection()
	after := runnerapi.Selection{Core: before.Core, Geo: "g2", Config: configRel(renderedBody)}
	p := geoTransition{Version: 1, From: before, To: after, Deadline: t0.Add(e.u.trialDeadline())}
	if err := os.MkdirAll(e.u.stateDir(), 0700); err != nil {
		t.Fatal(err)
	}
	if writeGeoState(e.data, geoPendingFile, p) != nil {
		t.Fatal("could not seed pending state")
	}
	for _, candidate := range []runnerapi.Candidate{{Selection: before, Deadline: t0}, {Selection: after, Deadline: t0.Add(e.u.trialDeadline())}} {
		if err := writeJSONAtomic(e.u.candidatePath(), candidate); err != nil {
			t.Fatal(err)
		}
		if err := e.geo.Recover(t.Context()); err == nil || !GeoPending(e.data) || len(e.finishes) != 0 {
			t.Fatal("ambiguous candidate permitted native changes")
		}
		if _, err := os.Stat(e.u.candidatePath()); err != nil {
			t.Fatal("ambiguous candidate was discarded")
		}
	}
	e.u.Now = func() time.Time { return t0.Add(2 * e.u.trialDeadline()) }
	if err := e.geo.Recover(t.Context()); err != nil || GeoPending(e.data) || len(e.finishes) != 1 {
		t.Fatal("expired orphan did not recover previous selection", err)
	}
	wantNoCandidateFile(t, e.coreEnv)
}

func TestGeoDefiniteNativeRefusalCompensates(t *testing.T) {
	e := newGeoTrialEnv(t)
	before := e.runner.activeSelection()
	base := e.geo.Finish
	e.geo.Finish = func(ctx context.Context, active runnerapi.Selection, ps []netip.Prefix) error {
		if active.Geo == "g2" {
			return ErrGeoPolicyRefused
		}
		return base(ctx, active, ps)
	}
	res, err := e.geo.Update(t.Context(), "custom", "g2")
	if err == nil || res.Outcome == runnerapi.OutcomeCommitted || GeoPending(e.data) || e.runner.activeSelection() != before || e.prepares != 2 || !slices.Equal(e.finishes, []string{"g1"}) {
		t.Fatal("definitive refusal did not restore both sides", err)
	}
	trials := e.runner.candidates()
	if len(trials) != 2 || trials[1].Selection != before {
		t.Fatal("compensation did not run the previously committed selection")
	}
	// No owner-approved slot changed; this attempted update must not become
	// a rollback target merely because the temporary trial was committed.
	if _, err := e.geo.Rollback(t.Context()); err == nil {
		t.Fatal("refused geo created a rollback target")
	}
}

func TestGeoCompensationRestart(t *testing.T) {
	for _, phase := range []string{"intent", "runner-returned", "second-trial-open", "missing-previous-config"} {
		t.Run(phase, func(t *testing.T) {
			e := newGeoTrialEnv(t)
			before := e.runner.activeSelection()
			after := runnerapi.Selection{Core: before.Core, Geo: "g2", Config: configRel(renderedBody)}
			p := geoTransition{Version: 1, From: before, To: after, Restoring: true}
			if os.MkdirAll(e.u.stateDir(), 0700) != nil || writeGeoState(e.data, geoPendingFile, p) != nil {
				t.Fatal("cannot seed interrupted compensation")
			}
			if phase != "runner-returned" {
				e.runner.script(func(f *fakeRunner) { f.st.Active = &after })
			}
			switch phase {
			case "second-trial-open":
				e.runner.script(func(f *fakeRunner) {
					f.st.State = runnerapi.StateTrial
					f.st.Candidate = &runnerapi.Candidate{Selection: before}
				})
				if err := e.geo.Recover(t.Context()); err == nil || !GeoPending(e.data) || len(e.finishes) != 0 || len(e.runner.candidates()) != 0 {
					t.Fatal("compensation replayed an open trial")
				}
				e.runner.script(func(f *fakeRunner) { f.st.State = runnerapi.StateRunning; f.st.Candidate = nil; f.st.Active = &before })
			case "missing-previous-config":
				if os.Remove(filepath.Join(e.u.runDir(), before.Config)) != nil {
					t.Fatal("cannot remove previous config")
				}
				if err := e.geo.Recover(t.Context()); err == nil || !GeoPending(e.data) || len(e.finishes) != 0 || len(e.runner.candidates()) != 0 {
					t.Fatal("missing previous proof allowed rollback")
				}
				return
			}
			if err := e.geo.Recover(t.Context()); err != nil || e.runner.activeSelection() != before || GeoPending(e.data) || !slices.Equal(e.finishes, []string{"g1"}) {
				t.Fatal("pending compensation did not converge", err)
			}
		})
	}
}

func TestGeoPreparationRefusalRestoresOldView(t *testing.T) {
	e := newGeoTrialEnv(t)
	before := slices.Clone(e.ranges)
	e.geo.Prepare = func(context.Context, runnerapi.Selection, runnerapi.Selection, []netip.Prefix, []netip.Prefix) error {
		e.ranges = nil
		return errors.New("preparation interrupted")
	}
	res, err := e.geo.Update(t.Context(), "custom", "g2")
	if err == nil || res.Outcome == runnerapi.OutcomeCommitted || GeoPending(e.data) || !slices.Equal(e.ranges, before) || len(e.runner.candidates()) != 0 {
		t.Fatal("known old runner did not recover from interrupted prepare", err)
	}
}

func TestGeoNeverOverwritesUnrelatedRunnerIntent(t *testing.T) {
	e := newGeoTrialEnv(t)
	c := runnerapi.Candidate{Selection: e.runner.activeSelection(), Deadline: t0.Add(e.u.trialDeadline())}
	if err := writeJSONAtomic(e.u.candidatePath(), c); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(e.u.candidatePath())
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.geo.Update(t.Context(), "custom", "g2")
	after, readErr := os.ReadFile(e.u.candidatePath())
	if err == nil || readErr != nil || string(b) != string(after) || e.prepares != 0 || GeoPending(e.data) {
		t.Fatal("foreign runner intent was overwritten")
	}
}

func TestGeoUnsubmittedSelectionCannotReleaseGuard(t *testing.T) {
	e := newGeoTrialEnv(t)
	old := e.runner.activeSelection()
	p := geoTransition{Version: 1, From: old, To: runnerapi.Selection{Core: old.Core, Geo: "g2", Config: configRel(renderedBody)}}
	if os.MkdirAll(e.u.stateDir(), 0700) != nil || writeGeoState(e.data, geoPendingFile, p) != nil {
		t.Fatal("cannot seed intent")
	}
	e.runner.script(func(f *fakeRunner) { f.st.Active = &p.To })
	if err := e.geo.Recover(t.Context()); err == nil || !GeoPending(e.data) || len(e.finishes) != 0 {
		t.Fatal("unsubmitted candidate allowed relaxation")
	}
}

func TestGeoRecoveryAfterVersionReceiptDurable(t *testing.T) {
	for _, phase := range []string{"committed-then-refused", "runner-restored"} {
		t.Run(phase, func(t *testing.T) {
			e := newGeoTrialEnv(t)
			before := e.runner.activeSelection()
			after := runnerapi.Selection{Core: before.Core, Geo: "g2", Config: configRel(renderedBody)}
			p := geoTransition{Version: 1, From: before, To: after, Deadline: t0}
			if os.MkdirAll(e.u.stateDir(), 0700) != nil || writeGeoState(e.data, geoPendingFile, p) != nil || writeGeoState(e.data, geoVersionsFile, p) != nil || newConfig([]byte(renderedBody)).write(e.u.runDir()) != nil {
				t.Fatal("cannot seed confirmed transaction")
			}
			if phase == "committed-then-refused" {
				e.runner.script(func(f *fakeRunner) { f.st.Active = &after })
				finish := e.geo.Finish
				e.geo.Finish = func(ctx context.Context, sel runnerapi.Selection, ps []netip.Prefix) error {
					if sel == after {
						return ErrGeoPolicyRefused
					}
					return finish(ctx, sel, ps)
				}
			}
			if err := e.geo.Recover(t.Context()); err != nil || GeoPending(e.data) || e.runner.activeSelection() != before {
				t.Fatal("receipt recovery failed", err)
			}
			record, err := readGeoState(e.data, geoVersionsFile)
			if err != nil || record == nil || record.To != before || record.From != after {
				t.Fatal("recovery stranded previous rollback lineage")
			}
		})
	}
}
