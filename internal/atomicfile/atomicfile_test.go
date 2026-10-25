package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	// The second write replaces the first, and a looser mode becomes a tighter
	// one: the file gets the mode asked for, whatever it had.
	for _, c := range []struct {
		data string
		perm os.FileMode
	}{
		{"first\n", 0o644},
		{"second, and longer\n", 0o600},
		{"", 0o600},
	} {
		if err := WriteFile(path, []byte(c.data), c.perm); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != c.data {
			t.Fatalf("read %q, %v; want %q", got, err, c.data)
		}
		if fi, err := os.Stat(path); err != nil || fi.Mode() != c.perm {
			t.Fatalf("mode %v, %v; want %v", fi.Mode(), err, c.perm)
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(ents) != 1 || ents[0].Name() != "state.json" {
			t.Fatalf("the directory holds %v, want only state.json", ents)
		}
	}
}

func TestWriteFileMissingDir(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFile(filepath.Join(dir, "missing", "f"), []byte("x"), 0o600); err == nil {
		t.Error("writing into a missing directory gave no error")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Errorf("a failed write left %v", ents)
	}
}

// TestWriteFileFailedRename makes the rename fail, by putting a directory
// where the file should go, and checks the temporary file goes.
func TestWriteFileFailedRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("x"), 0o600); err == nil {
		t.Fatal("replacing a directory gave no error")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "state.json" || !ents[0].IsDir() {
		t.Errorf("the directory holds %v, want only the state.json directory", ents)
	}
}

func TestSyncDir(t *testing.T) {
	dir := t.TempDir()
	if err := SyncDir(dir); err != nil {
		t.Errorf("SyncDir(%q) = %v", dir, err)
	}
	if err := SyncDir(filepath.Join(dir, "missing")); err == nil {
		t.Error("SyncDir of a missing directory gave no error")
	}
}
