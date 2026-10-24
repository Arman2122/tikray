package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

var testSel = runnerapi.Selection{
	Core:   "26.10.21",
	Geo:    "2026.10.20",
	Config: "config/" + strings.Repeat("ab", 32) + ".json",
}

func newDirs(t *testing.T) Dirs {
	t.Helper()
	d := Dirs{Data: t.TempDir()}
	if err := os.MkdirAll(d.Run(), 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

// writeCandidate plays the control plane, which is what writes candidate.json.
func writeCandidate(t *testing.T, d Dirs, c runnerapi.Candidate) {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.CandidateFile(), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDirsPaths(t *testing.T) {
	d := Dirs{Data: "/data"}
	got := map[string]string{
		"Run":           d.Run(),
		"Cores":         d.Cores(),
		"Geo":           d.Geo(),
		"Active":        d.Active(),
		"CandidateFile": d.CandidateFile(),
		"LastTrial":     d.LastTrial(),
		"Token":         d.Token(),
		"CoreBinary":    d.CoreBinary("26.10.21"),
		"GeoDir":        d.GeoDir("v1"),
		"ConfigPath":    d.ConfigPath("config/x.json"),
	}
	want := map[string]string{
		"Run":           "/data/run",
		"Cores":         "/data/cores",
		"Geo":           "/data/geo",
		"Active":        "/data/run/active.json",
		"CandidateFile": "/data/run/candidate.json",
		"LastTrial":     "/data/run/last-trial.json",
		"Token":         "/data/run/runner.token",
		"CoreBinary":    "/data/cores/26.10.21/xray",
		"GeoDir":        "/data/geo/v1",
		"ConfigPath":    "/data/run/config/x.json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %v, want %v", got, want)
	}
}

func TestActiveRoundTrip(t *testing.T) {
	d := newDirs(t)
	got, err := ReadActive(d)
	if got != nil || err != nil {
		t.Fatalf("missing active = %v, %v; want nil, nil", got, err)
	}
	if err := WriteActive(d, testSel); err != nil {
		t.Fatal(err)
	}
	got, err = ReadActive(d)
	if err != nil || got == nil || *got != testSel {
		t.Fatalf("ReadActive = %v, %v; want %v", got, err, testSel)
	}
	fi, err := os.Stat(d.Active())
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("active mode = %v, err %v; want 0644", fi.Mode(), err)
	}
}

func TestWriteActiveRejectsInvalid(t *testing.T) {
	d := newDirs(t)
	if err := WriteActive(d, runnerapi.Selection{Core: "../x"}); err == nil {
		t.Fatal("WriteActive accepted an invalid selection")
	}
	if _, err := os.Stat(d.Active()); !os.IsNotExist(err) {
		t.Errorf("active.json exists after a refused write: %v", err)
	}
}

func TestReadActiveRejectsInvalid(t *testing.T) {
	d := newDirs(t)
	bad := `{"core":"../x","config":"config/` + strings.Repeat("ab", 32) + `.json"}`
	if err := os.WriteFile(d.Active(), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadActive(d)
	if err == nil || got != nil {
		t.Fatalf("ReadActive = %v, %v; want an error", got, err)
	}
}

func TestReadActiveRejectsGarbage(t *testing.T) {
	d := newDirs(t)
	if err := os.WriteFile(d.Active(), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadActive(d); err == nil || got != nil {
		t.Fatalf("ReadActive = %v, %v; want an error", got, err)
	}
}

func TestCandidateReadAndRemove(t *testing.T) {
	d := newDirs(t)
	if got, err := ReadCandidate(d); got != nil || err != nil {
		t.Fatalf("missing candidate = %v, %v; want nil, nil", got, err)
	}
	if err := RemoveCandidate(d); err != nil {
		t.Fatalf("RemoveCandidate on a missing file: %v", err)
	}

	want := runnerapi.Candidate{Selection: testSel, Deadline: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)}
	writeCandidate(t, d, want)
	got, err := ReadCandidate(d)
	if err != nil || got == nil || got.Selection != want.Selection || !got.Deadline.Equal(want.Deadline) {
		t.Fatalf("ReadCandidate = %+v, %v; want %+v", got, err, want)
	}

	if err := RemoveCandidate(d); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d.CandidateFile()); !os.IsNotExist(err) {
		t.Errorf("candidate.json still there: %v", err)
	}
	if got, err := ReadCandidate(d); got != nil || err != nil {
		t.Errorf("candidate after remove = %v, %v; want nil, nil", got, err)
	}
}

func TestReadCandidateRejectsInvalidSelection(t *testing.T) {
	d := newDirs(t)
	bad := `{"core":"26.10.21","config":"config/../../etc/passwd","deadline":"2026-10-25T12:00:00Z"}`
	if err := os.WriteFile(d.CandidateFile(), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadCandidate(d); err == nil || got != nil {
		t.Fatalf("ReadCandidate = %v, %v; want an error", got, err)
	}
}

func TestLastTrialRoundTrip(t *testing.T) {
	d := newDirs(t)
	if got, err := ReadLastTrial(d); got != nil || err != nil {
		t.Fatalf("missing last trial = %v, %v; want nil, nil", got, err)
	}
	at := time.Date(2026, 10, 25, 12, 2, 0, 0, time.UTC)
	want := runnerapi.TrialResult{
		Candidate: runnerapi.Candidate{Selection: testSel, Deadline: at},
		Outcome:   runnerapi.OutcomeDeadline,
		Detail:    "no commit",
		At:        at,
	}
	if err := WriteLastTrial(d, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadLastTrial(d)
	if err != nil || got == nil || got.Outcome != want.Outcome || got.Detail != want.Detail ||
		!got.At.Equal(at) || got.Candidate.Selection != testSel {
		t.Fatalf("ReadLastTrial = %+v, %v; want %+v", got, err, want)
	}
}

func TestReadLastTrialRejectsInvalidSelection(t *testing.T) {
	d := newDirs(t)
	bad := `{"candidate":{"core":"../x","config":"c","deadline":"2026-10-25T12:00:00Z"},"outcome":"exited","at":"2026-10-25T12:00:00Z"}`
	if err := os.WriteFile(d.LastTrial(), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadLastTrial(d); err == nil || got != nil {
		t.Fatalf("ReadLastTrial = %v, %v; want an error", got, err)
	}
}

func TestWriteAtomicLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	for i := 0; i < 20; i++ {
		data := []byte(strings.Repeat("x", i+1))
		if err := writeAtomic(target, data, 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(target)
		if err != nil || string(got) != string(data) {
			t.Fatalf("write %d: read %q, %v", i, got, err)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "state.json" {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only state.json", names)
	}
}

func TestWriteAtomicFailureLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	// The target is a non-empty directory, so the final rename fails.
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(target, []byte("x"), 0o644); err == nil {
		t.Fatal("writeAtomic over a directory succeeded")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != "target" {
		t.Errorf("failed write left %v behind", ents)
	}
}

func TestWriteAtomicSetsModeOnReplace(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(target, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(target)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, err %v; want 0600", fi.Mode(), err)
	}
}

func TestTokenStable(t *testing.T) {
	d := Dirs{Data: t.TempDir()}
	os.MkdirAll(d.Run(), 0o755)
	a, err := LoadOrCreateToken(d)
	b, _ := LoadOrCreateToken(d)
	fi, _ := os.Stat(d.Token())
	if err != nil || len(a) != 64 || a != b || fi.Mode().Perm() != 0o600 {
		t.Errorf("token %q %q mode %v err %v", a, b, fi.Mode(), err)
	}
}

func TestTokenReusesExistingTrimmed(t *testing.T) {
	d := newDirs(t)
	if err := os.WriteFile(d.Token(), []byte("  abc123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOrCreateToken(d)
	if err != nil || got != "abc123" {
		t.Errorf("token = %q, err %v; want abc123", got, err)
	}
}

func TestTokenReplacesEmptyFile(t *testing.T) {
	d := newDirs(t)
	if err := os.WriteFile(d.Token(), []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOrCreateToken(d)
	if err != nil || len(got) != 64 {
		t.Fatalf("token = %q, err %v; want 64 hex chars", got, err)
	}
	again, _ := LoadOrCreateToken(d)
	if again != got {
		t.Errorf("token changed on reload: %q then %q", got, again)
	}
}
