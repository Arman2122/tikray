package artifacts

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

const (
	historyName = "core-history.jsonl"
	lockName    = "artifacts.lock"
)

// lockState takes the artifacts lock, <dir>/artifacts.lock, without waiting,
// and creates dir (mode 0700) if it is missing. It gives ErrLocked when
// another holder has it. The lock is the flock of an open file, so it goes
// when unlock closes the file or the process dies.
func lockState(dir string) (unlock func(), err error) {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	path := filepath.Join(dir, lockName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("artifacts: lock %s: %w", path, err)
	}
	return func() { f.Close() }, nil
}

// appendHistory adds r to the history file as one JSON line and fsyncs it.
// When a crash has left the last line without its newline, the line is ended
// first, so that it spoils only itself.
func appendHistory(path string, r Result) error {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	err = func() error {
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		if n := fi.Size(); n > 0 {
			last := make([]byte, 1)
			if _, err := f.ReadAt(last, n-1); err != nil {
				return err
			}
			if last[0] != '\n' {
				line = append([]byte{'\n'}, line...)
			}
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return err
		}
		return f.Sync()
	}()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// ReadHistory returns the results that updates, rollbacks and applies have
// recorded in <data>/state/core-history.jsonl, oldest first. A data root
// without the file has an empty history, and a line that does not parse,
// such as one a crash cut short, is skipped.
func ReadHistory(data string) ([]Result, error) {
	h, err := readHistory(filepath.Join(data, "state", historyName))
	if err == nil && h == nil {
		h = []Result{}
	}
	return h, err
}

// readHistory returns the results in the history file, oldest first. A
// missing file is an empty history, and a line that does not parse, such as
// one a crash cut short, is skipped.
func readHistory(path string) ([]Result, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Result
	br := bufio.NewReader(f)
	for {
		line, err := br.ReadBytes('\n')
		var r Result
		if len(bytes.TrimSpace(line)) > 0 && json.Unmarshal(line, &r) == nil {
			out = append(out, r)
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// committedVersions returns the cores the history shows committed, newest
// first and each once. A committed result's From counts as well, just after
// its To: it was the active core, so it had been committed, perhaps before
// the history began (the core the installer put in place). The committed
// result of an Apply counts like any other, with the active core as both To
// and From.
func committedVersions(h []Result) []string {
	var out []string
	seen := map[string]bool{}
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for i := len(h) - 1; i >= 0; i-- {
		if h[i].Outcome == runnerapi.OutcomeCommitted {
			add(h[i].To)
			add(h[i].From)
		}
	}
	return out
}
