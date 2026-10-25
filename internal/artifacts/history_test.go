package artifacts

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

func TestHistoryAppendAndRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core-history.jsonl")
	if h, err := readHistory(path); err != nil || h != nil {
		t.Fatalf("missing history = %v, %v; want none", h, err)
	}
	a := Result{To: "26.3.27", Outcome: runnerapi.OutcomeCommitted, At: t0}
	b := Result{From: "26.3.27", To: "26.10.21", Outcome: runnerapi.OutcomeRejected, Detail: "line one\nline two", At: t0}
	for _, r := range []Result{a, b} {
		if err := appendHistory(path, r); err != nil {
			t.Fatal(err)
		}
	}
	h, err := readHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 2 {
		t.Fatalf("history = %+v, want 2 results", h)
	}
	wantResult(t, h[0], a)
	wantResult(t, h[1], b)
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("history file: %v, %v; want mode 0600", fi, err)
	}
}

// A crash can cut the last line short; it must not take the next one with it.
func TestHistoryTornLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core-history.jsonl")
	torn := `{"to":"26.1.18","outcome":"committed"}` + "\n" + `{"to":"26.3.27","outc`
	if err := os.WriteFile(path, []byte(torn), 0o600); err != nil {
		t.Fatal(err)
	}
	r := Result{To: "26.10.21", Outcome: runnerapi.OutcomeCommitted, At: t0}
	if err := appendHistory(path, r); err != nil {
		t.Fatal(err)
	}
	h, err := readHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 2 || h[0].To != "26.1.18" {
		t.Fatalf("history = %+v, want 26.1.18 and 26.10.21", h)
	}
	wantResult(t, h[1], r)
}

func TestCommittedVersions(t *testing.T) {
	c := committedResult
	for _, tc := range []struct {
		name string
		h    []Result
		want []string
	}{
		{"empty", nil, nil},
		{"newest first", []Result{c("26.1.18", ""), c("26.3.27", ""), c("26.10.21", "")}, []string{"26.10.21", "26.3.27", "26.1.18"}},
		{"each once", []Result{c("26.3.27", ""), c("26.10.21", "26.3.27"), c("26.3.27", "26.10.21")}, []string{"26.3.27", "26.10.21"}},
		{"only commits", []Result{
			c("26.3.27", ""),
			{From: "26.3.27", To: "99.0.1", Outcome: runnerapi.OutcomeExited},
			{From: "26.3.27", To: "26.10.21", Outcome: OutcomeUnhealthy},
			{From: "26.3.27", To: "26.3.27", Outcome: OutcomeNoop},
			{To: "26.1.0", Outcome: OutcomeRefused},
		}, []string{"26.3.27"}},
		{"the replaced core counts", []Result{c("26.10.21", "26.3.27")}, []string{"26.10.21", "26.3.27"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := committedVersions(tc.h); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("committedVersions = %v, want %v", got, tc.want)
			}
		})
	}
}
