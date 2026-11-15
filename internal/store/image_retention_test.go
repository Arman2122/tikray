package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Both retained signed control images must have usable state. Current or
// future copies and unrelated owner files survive collection.
func TestImageStateRetentionKeepsRollback(t *testing.T) {
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private directory required")
	}
	steps := map[int]migration{1: addHealth, 2: addHealth}
	one := fileJSON(1, 3, stateWithProbe(probeAfterMigration))
	two := fileJSON(2, 4, stateWithProbe(probeAfterMigration))
	put(t, dir, stateName(1), one)
	put(t, dir, stateName(2), two)
	s := &Store{dir: dir, current: 3}
	put(t, dir, "owner.json", []byte("owner"))
	if err := s.pruneImageState(3, 2, steps); err != nil {
		t.Fatal(err)
	}
	if _, e := os.Stat(filepath.Join(dir, stateName(1))); e != nil {
		t.Fatal("retired old state with an unproven active copy")
	}
	three := fileJSON(3, 5, stateWithProbe(probeAfterMigration))
	put(t, dir, stateName(3), three)
	if err := s.pruneImageState(3, 0, steps); err != nil {
		t.Fatal(err)
	}
	if _, e := os.Stat(filepath.Join(dir, stateName(1))); e != nil {
		t.Fatal("retired state without previous-image evidence")
	}
	if err := s.pruneImageState(3, 2, steps); err != nil {
		t.Fatal(err)
	}
	if _, e := os.Stat(filepath.Join(dir, stateName(1))); !os.IsNotExist(e) {
		t.Fatal("obsolete positively identified store retained")
	}
	if !bytes.Equal(get(t, dir, stateName(2)), two) || !bytes.Equal(get(t, dir, stateName(3)), three) || !bytes.Equal(get(t, dir, "owner.json"), []byte("owner")) {
		t.Fatal("retained rollback or owner data changed")
	}
	if err := s.pruneImageState(3, 2, steps); err != nil {
		t.Fatal(err)
	}
}

func TestImageStateRetentionRefusesUnusableRollbackState(t *testing.T) {
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private directory required")
	}
	steps := map[int]migration{1: addHealth, 2: addHealth}
	for _, v := range []int{1, 3} {
		put(t, dir, stateName(v), fileJSON(v, 2, stateWithProbe(probeAfterMigration)))
	}
	put(t, dir, stateName(2), fileJSON(2, 2, `{"network":"private-fixture"}`))
	s := &Store{dir: dir, current: 3}
	if err := s.pruneImageState(3, 2, steps); err != nil {
		t.Fatal("unsafe input produced a diagnostic")
	}
	if _, e := os.Stat(filepath.Join(dir, stateName(1))); e != nil {
		t.Fatal("unusable rollback copy authorized pruning")
	}
}
