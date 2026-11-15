package store

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Arman2122/tikray/internal/atomicfile"
)

// PruneImageState retires old versions only after both signed control images
// have a materialized compatible state in this private store. Preserve unknown,
// unreadable, newer and unversioned files, including a failed migration.
func (s *Store) PruneImageState(active, previous int) error {
	return s.pruneImageState(active, previous, migrations)
}

func (s *Store) pruneImageState(active, previous int, steps map[int]migration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	floor := min(active, previous)
	if floor <= 1 || active != s.current || s.writeUncertain {
		return nil
	}
	info, err := os.Lstat(s.dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("store: image state directory unavailable")
	}
	verified := func(version int) os.FileInfo {
		path := filepath.Join(s.dir, stateName(version))
		before, err := os.Lstat(path)
		if err != nil || !before.Mode().IsRegular() {
			return nil
		}
		b, err := atomicfile.ReadRegular(path, 16<<20, fileMode)
		if err != nil {
			return nil
		}
		st, _, err := decodeStateFile(b, version, s.current, steps)
		if err != nil {
			return nil
		}
		if _, _, err = admit(st); err != nil {
			return nil
		}

		after, err := os.Lstat(path)
		if err != nil || !os.SameFile(before, after) {
			return nil
		}
		return after
	}
	if verified(active) == nil || verified(previous) == nil {
		return nil
	}
	files, err := os.ReadDir(s.dir)
	if err != nil {
		return errors.New("store: image state inventory unavailable")
	}
	for _, item := range files {
		m := stateFileRE.FindStringSubmatch(item.Name())
		if m == nil || item.IsDir() {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil || n >= floor {
			continue
		}
		if verified(n) == nil {
			continue
		}
		if os.Remove(filepath.Join(s.dir, item.Name())) != nil {
			return errors.New("store: cannot retire obsolete state version")
		}
	}
	if atomicfile.SyncDir(s.dir) != nil {
		return errors.New("store: cannot sync state retirement")
	}
	return nil
}
