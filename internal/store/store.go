package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"

	"github.com/Arman2122/tikray/internal/atomicfile"
)

// Current is the version of the state file this program writes, and the
// newest one it reads. The file is state.v<Current>.json. A change to the
// state's layout that older files cannot express raises Current and adds a
// migration (see migrations).
const Current = 1

// ErrConflict is what Update returns when the revision it was given is not
// the current one: someone else changed the state first.
var ErrConflict = errors.New("store: the state changed since it was read")

// AnyRevision is the revision to give Update to skip the check on the
// revision. It is never the revision of a state: Open refuses a file that
// has it.
const AnyRevision uint64 = math.MaxUint64

// stateFileRE matches the name of a state file, state.v<N>.json with N a
// positive decimal number. Anything else in the directory is not ours.
var stateFileRE = regexp.MustCompile(`^state\.v([1-9][0-9]*)\.json$`)

// stateName is the name of the state file of a version.
func stateName(version int) string { return "state.v" + strconv.Itoa(version) + ".json" }

// fileMode is the mode of a state file. The state holds subscription URLs and
// server credentials.
const fileMode = 0o600

// file is a state file as Open reads it. The state stays JSON until the
// migrations have run.
type file struct {
	Version  int             `json:"version"`
	Revision uint64          `json:"revision"`
	State    json.RawMessage `json:"state"`
}

// Store keeps the desired state in memory and in a directory of versioned
// files. It is safe for use by many goroutines, but not by many processes:
// one process owns the directory and writes the state. A second one that
// opened the same directory would not see the first one's changes and would
// overwrite them.
//
// Each Update writes the whole state to state.v<Current>.json, as a new
// revision, through a temporary file and a rename, so that a crash leaves
// the old file or the new one. When Current goes up, Open migrates the older
// file to the new version and writes it as a new file, leaving the older one
// as it was: the older program can still read it.
type Store struct {
	dir     string
	current int

	mu    sync.Mutex // held across the write in Update
	state State
	rev   uint64

	degraded []string // what Open disabled; never changed after it
}

// Open opens the state in dir, creating dir (mode 0700) if it is missing. It
// loads the newest state file this program can read, migrates it to Current
// if it is older, and checks it with Validate. A directory without a state
// file gives Default() at revision 0, and nothing is written until the first
// Update.
//
// A server that fails the checks on its own (its name, the shape and protocol
// of its outbound, and what xraypolicy refuses) does not make Open fail, as it
// does not make the rest of the state wrong: a newer tikray, or a newer
// xray-core policy, may refuse what an older one saved. Open disables such a
// server in memory and gives the reason in Invalid, and Degraded lists it. The
// file is not written: the next Update writes the server as it is held. When
// the state passes Validate only after that, Open succeeds.
//
// A file that cannot be read, parsed or validated otherwise makes Open fail,
// with an error that starts with "store: " and the file's name; the error holds
// the problems that remain once those servers are disabled. The file is never
// repaired or replaced. Files of a newer version are left alone and ignored;
// if they are all there is, Open fails, so that a program that is too old
// does not start from an empty state.
func Open(dir string) (*Store, error) {
	return openWith(dir, Current, migrations)
}

// openWith is Open for a given current version and set of migrations.
func openWith(dir string, current int, steps map[int]migration) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	version, newer, err := scan(dir, current)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	s := &Store{dir: dir, current: current, state: Default()}
	if version == 0 {
		if newer != 0 {
			return nil, fmt.Errorf("store: %s: is newer than this program reads (version %d) and there is no older state file", stateName(newer), current)
		}
		return s, nil
	}
	name := stateName(version)
	st, rev, err := read(filepath.Join(dir, name), version, current, steps)
	if err != nil {
		return nil, fmt.Errorf("store: %s: %w", name, err)
	}
	held, degraded, err := admit(st)
	if err != nil {
		return nil, fmt.Errorf("store: %s: %w", name, err)
	}
	if version != current {
		// The file of the new version is the older one as it was migrated:
		// what Open disabled stays in memory, as it does without a migration.
		if err := s.write(st, rev); err != nil {
			return nil, fmt.Errorf("store: %s: %w", stateName(current), err)
		}
	}
	s.state, s.rev, s.degraded = held, rev, degraded
	return s, nil
}

// admit checks a loaded state with Validate. A state that fails it only for
// servers that fail the checks on their own (see State.degrade) is returned
// with those servers disabled, and their IDs. Any other failure is an error:
// the one Validate gives for the state with those servers disabled.
func admit(st State) (State, []string, error) {
	err := st.Validate()
	if err == nil {
		return st, []string{}, nil
	}
	held, ids := st.degrade()
	if len(ids) == 0 {
		return State{}, nil, err
	}
	if err := held.Validate(); err != nil {
		return State{}, nil, err
	}
	return held, ids, nil
}

// scan returns the highest version up to current that dir has a state file
// for, and the highest above current; 0 stands for none.
func scan(dir string, current int) (found, newer int, err error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, err
	}
	for _, e := range ents {
		m := stateFileRE.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue // too large to be a version
		}
		if n <= current {
			found = max(found, n)
		} else {
			newer = max(newer, n)
		}
	}
	return found, newer, nil
}

// read loads the state file at path, which is of the given version, and
// migrates its state up to current. It writes nothing, and does not validate
// the state: that is admit's.
func read(path string, version, current int, steps map[int]migration) (State, uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, 0, err
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return State{}, 0, err
	}
	if f.Version != version {
		return State{}, 0, fmt.Errorf("version is %d, want %d", f.Version, version)
	}
	if len(f.State) == 0 || string(f.State) == "null" {
		return State{}, 0, errors.New("state is missing")
	}
	raw, err := migrate(f.State, version, current, steps)
	if err != nil {
		return State{}, 0, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return State{}, 0, err
	}
	st.normalize()
	if f.Revision == AnyRevision {
		return State{}, 0, fmt.Errorf("revision is %d, which Update takes for any revision", f.Revision)
	}
	return st, f.Revision, nil
}

// normalize turns the nil lists of the state's top level into empty ones, so
// that they marshal as [] and not null. JSON that omits a list, or says null,
// decodes to a nil one.
func (s *State) normalize() {
	if s.Servers == nil {
		s.Servers = []Server{}
	}
	if s.Subscriptions == nil {
		s.Subscriptions = []Subscription{}
	}
	if s.Devices == nil {
		s.Devices = []Device{}
	}
}

// encode returns the content of a state file: indented with two spaces, and
// ending in a newline. URLs and share links keep their & and < as they are.
func encode(version int, rev uint64, st State) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(struct {
		Version  int    `json:"version"`
		Revision uint64 `json:"revision"`
		State    State  `json:"state"`
	}{version, rev, st})
	return buf.Bytes(), err
}

// write replaces the state file of the current version.
func (s *Store) write(st State, rev uint64) error {
	data, err := encode(s.current, rev, st)
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(filepath.Join(s.dir, stateName(s.current)), data, fileMode)
}

// State returns a copy of the state and its revision. The revision counts the
// Updates: it is 0 until the first one, and a state loaded from a file has the
// file's.
func (s *Store) State() (State, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Clone(), s.rev
}

// Degraded returns the IDs of the servers that Open disabled because they fail
// this tikray's checks, in state order, or an empty list if there are none. It
// is what Open found and does not change: a server that the file already held
// disabled with a reason (Server.Invalid) is not Open's doing, and neither is
// one that an Update disabled later.
func (s *Store) Degraded() []string { return append([]string{}, s.degraded...) }

// Update changes the state. It calls fn with a copy of the state, checks that
// the result passes Validate, writes it as the next revision and makes it the
// state, and returns it with its revision.
//
// A rev of AnyRevision skips the check on the revision. Any other value, 0
// included, must be the current revision, as State returned it, or Update
// fails with ErrConflict without calling fn: a store that nothing has been
// written to is at revision 0, and a caller that read it passes 0 back. When
// fn or Validate fails, nothing is written or changed, and Update returns
// their error as it is. When the write fails the error starts with "store: "
// and the file's name; the state is as it was, though if the failure was the
// final sync of the directory, the new file may already be in place. On any
// error the state and revision returned are zero.
//
// Update holds the store's lock while fn runs and while the file is written,
// so fn must not call the store.
func (s *Store) Update(rev uint64, fn func(*State) error) (State, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rev != AnyRevision && rev != s.rev {
		return State{}, 0, ErrConflict
	}
	next := s.state.Clone()
	if err := fn(&next); err != nil {
		return State{}, 0, err
	}
	next.normalize()
	if err := next.Validate(); err != nil {
		return State{}, 0, err
	}
	if err := s.write(next, s.rev+1); err != nil {
		return State{}, 0, fmt.Errorf("store: %s: %w", stateName(s.current), err)
	}
	s.rev++
	// The store keeps a copy of its own, out of reach of whatever fn kept a
	// hold of and of whatever the caller does with the result.
	s.state = next.Clone()
	return next, s.rev, nil
}
