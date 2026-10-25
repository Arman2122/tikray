// Package runner is the data-plane runner: it supervises xray and keeps its
// state as small JSON files on the router's disk.
package runner

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

// Dirs locates the runner's files. Data is the data root, /data in the
// container; the runner gets cores and geo read-only and run read-write.
type Dirs struct{ Data string }

// Run is the runner's state directory.
func (d Dirs) Run() string { return filepath.Join(d.Data, "run") }

// Cores holds one directory per xray version.
func (d Dirs) Cores() string { return filepath.Join(d.Data, "cores") }

// Geo holds one directory per geo bundle.
func (d Dirs) Geo() string { return filepath.Join(d.Data, "geo") }

// Active is the selection the runner boots from.
func (d Dirs) Active() string { return filepath.Join(d.Run(), "active.json") }

// CandidateFile is the selection on trial, if any.
func (d Dirs) CandidateFile() string { return filepath.Join(d.Run(), "candidate.json") }

// LastTrial records how the last trial ended.
func (d Dirs) LastTrial() string { return filepath.Join(d.Run(), "last-trial.json") }

// Token is the bearer token of the control API.
func (d Dirs) Token() string { return filepath.Join(d.Run(), "runner.token") }

// CoreBinary is the xray binary of a core slot.
func (d Dirs) CoreBinary(ver string) string { return filepath.Join(d.Cores(), ver, "xray") }

// GeoDir is the directory of a geo slot.
func (d Dirs) GeoDir(ver string) string { return filepath.Join(d.Geo(), ver) }

// ConfigPath resolves a Selection.Config, which is relative to Run and has
// already been validated.
func (d Dirs) ConfigPath(rel string) string { return filepath.Join(d.Run(), rel) }

// ReadActive returns the active selection, or nil, nil when there is none. A
// file that does not hold a valid selection is an error.
func ReadActive(d Dirs) (*runnerapi.Selection, error) {
	var s runnerapi.Selection
	if ok, err := readJSON(d.Active(), &s); !ok || err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("runner: %s: %w", d.Active(), err)
	}
	return &s, nil
}

// WriteActive replaces active.json atomically. It refuses an invalid selection
// so that it never writes a file the next boot would reject.
func WriteActive(d Dirs, s runnerapi.Selection) error {
	if err := s.Validate(); err != nil {
		return err
	}
	return writeJSON(d.Active(), s)
}

// ReadCandidate returns the candidate on trial, or nil, nil when there is none.
// A file that does not hold a valid selection is an error.
func ReadCandidate(d Dirs) (*runnerapi.Candidate, error) {
	var c runnerapi.Candidate
	if ok, err := readJSON(d.CandidateFile(), &c); !ok || err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("runner: %s: %w", d.CandidateFile(), err)
	}
	return &c, nil
}

// RemoveCandidate deletes candidate.json durably. A file that is already gone
// is not an error.
func RemoveCandidate(d Dirs) error {
	if err := os.Remove(d.CandidateFile()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDir(d.Run())
}

// WriteLastTrial replaces last-trial.json atomically.
func WriteLastTrial(d Dirs, r runnerapi.TrialResult) error {
	return writeJSON(d.LastTrial(), r)
}

// ReadLastTrial returns how the last trial ended, or nil, nil when none has.
// A file that does not hold a valid selection is an error.
func ReadLastTrial(d Dirs) (*runnerapi.TrialResult, error) {
	var r runnerapi.TrialResult
	if ok, err := readJSON(d.LastTrial(), &r); !ok || err != nil {
		return nil, err
	}
	if err := r.Candidate.Validate(); err != nil {
		return nil, fmt.Errorf("runner: %s: %w", d.LastTrial(), err)
	}
	return &r, nil
}

// LoadOrCreateToken returns the control API token. It reuses a non-empty
// runner.token and otherwise writes 32 random bytes as hex, mode 0600.
func LoadOrCreateToken(d Dirs) (string, error) {
	b, err := os.ReadFile(d.Token())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if tok := strings.TrimSpace(string(b)); tok != "" {
		return tok, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw)
	if err := writeAtomic(d.Token(), []byte(tok), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

// readJSON decodes the file at path into v. It reports false, with no error,
// when the file does not exist.
func readJSON(path string, v any) (bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("runner: %s: %w", path, err)
	}
	return true, nil
}

// writeJSON atomically writes v as indented JSON, mode 0644.
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'), 0o644)
}

// writeAtomic replaces path with data so that a power cut leaves either the old
// file or the new one, never a mix: it writes a temp file in the same
// directory, fsyncs it, renames it over path and fsyncs the directory.
func writeAtomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir fsyncs a directory so a rename or removal in it survives power loss.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
