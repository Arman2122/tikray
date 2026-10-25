package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

const (
	// stateTail is the part of a state that every test file shares.
	stateTail = `"default_policy":{"mode":"direct"},"routing":{"domestic":{}},"dns":{"remote":"https://1.1.1.1/dns-query"},"network":{"subnet":"172.31.255.0/29"}`
	// stateBeforeHealth is a version 1 state in the tests that migrate: it has
	// no health section, which version 2 requires. Only addHealth makes it
	// valid.
	stateBeforeHealth = `{"servers":[],"subscriptions":[],"devices":[],` + stateTail + `}`
	// probeAfterMigration is the probe URL addHealth gives.
	probeAfterMigration = "https://probe.example/204"
)

// stateWithProbe is a valid state, compact, whose probe URL is probeURL.
func stateWithProbe(probeURL string) string {
	return `{"servers":[],"subscriptions":[],"devices":[],` + stateTail + `,"health":{"probe_url":"` + probeURL + `"}}`
}

// fileJSON is a state file's content as a hand-written file would have it.
func fileJSON(version int, revision uint64, state string) []byte {
	return fmt.Appendf(nil, `{"version":%d,"revision":%d,"state":%s}`, version, revision, state)
}

// addHealth is the migration of the tests: version 2 has the health section
// that version 1 did not.
func addHealth(raw json.RawMessage) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	obj["health"] = json.RawMessage(`{"probe_url":"` + probeAfterMigration + `"}`)
	return json.Marshal(obj)
}

// setSmart is a second migration: version 3 sends unlisted devices through the
// proxy by default.
func setSmart(raw json.RawMessage) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	obj["default_policy"] = json.RawMessage(`{"mode":"smart"}`)
	return json.Marshal(obj)
}

// mustFail is a migration that must not run.
func mustFail(t *testing.T) migration {
	return func(json.RawMessage) (json.RawMessage, error) {
		t.Error("a migration ran that should not have")
		return nil, errors.New("must not run")
	}
}

func put(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// names lists what dir holds, sorted.
func names(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func mustOpen(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

// compact is the state as compact JSON. The tests compare states with it, not
// with reflect.DeepEqual, because a state that went through a file comes back
// with its outbounds indented.
func compact(t *testing.T, st State) string {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func sameState(t *testing.T, got, want State) {
	t.Helper()
	if g, w := compact(t, got), compact(t, want); g != w {
		t.Errorf("state is\n%s\nwant\n%s", g, w)
	}
}

// server is a valid server.
func server(name string) Server {
	return Server{ID: NewID(), Name: name, Outbound: json.RawMessage(`{"protocol":"vless"}`)}
}

// add returns an Update function that adds a server.
func add(name string) func(*State) error {
	return func(st *State) error {
		st.Servers = append(st.Servers, server(name))
		return nil
	}
}

// fileFields are the fields of a state file that the tests read.
type fileFields struct {
	Version  int             `json:"version"`
	Revision uint64          `json:"revision"`
	State    json.RawMessage `json:"state"`
}

func readFields(t *testing.T, dir, name string) fileFields {
	t.Helper()
	var f fileFields
	if err := json.Unmarshal(get(t, dir, name), &f); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return f
}

func TestOpenEmptyDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "state")
	s := mustOpen(t, dir)
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("dir: %v, %v; want a directory with mode 0700", fi, err)
	}
	st, rev := s.State()
	if rev != 0 {
		t.Errorf("revision %d, want 0", rev)
	}
	if want := Default(); !reflect.DeepEqual(st, want) {
		t.Errorf("state is %+v, want Default() %+v", st, want)
	}
	if got := names(t, dir); len(got) != 0 {
		t.Errorf("Open wrote %v, want nothing until the first Update", got)
	}
	// An existing, empty directory is no different.
	if _, err := Open(dir); err != nil {
		t.Errorf("Open of the existing directory: %v", err)
	}
}

func TestUpdateWritesAtomically(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)
	srv := server("alpha")
	got, rev, err := s.Update(0, func(st *State) error {
		st.Servers = append(st.Servers, srv)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if rev != 1 || len(got.Servers) != 1 || got.Servers[0].ID != srv.ID {
		t.Fatalf("Update = %+v, %d; want one server at revision 1", got, rev)
	}

	fi, err := os.Stat(filepath.Join(dir, "state.v1.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state.v1.json: %v, %v; want mode 0600", fi, err)
	}
	f := readFields(t, dir, "state.v1.json")
	if f.Version != 1 || f.Revision != 1 {
		t.Errorf("version %d, revision %d; want 1 and 1", f.Version, f.Revision)
	}

	// Two spaces, no tabs, and a newline at the end.
	data := get(t, dir, "state.v1.json")
	var flat, indented bytes.Buffer
	if err := json.Compact(&flat, data); err != nil {
		t.Fatal(err)
	}
	if err := json.Indent(&indented, flat.Bytes(), "", "  "); err != nil {
		t.Fatal(err)
	}
	indented.WriteByte('\n')
	if !bytes.Equal(data, indented.Bytes()) {
		t.Errorf("state.v1.json is\n%s\nwant it indented with two spaces and ending in a newline:\n%s", data, indented.Bytes())
	}
	if !strings.HasPrefix(string(data), "{\n  \"version\": 1,\n  \"revision\": 1,\n  \"state\": {\n") {
		t.Errorf("state.v1.json starts %q", data[:min(len(data), 60)])
	}

	again := mustOpen(t, dir)
	st, rev2 := again.State()
	sameState(t, st, got)
	if rev2 != 1 {
		t.Errorf("the second Open has revision %d, want 1", rev2)
	}
	if n := names(t, dir); !slices.Equal(n, []string{"state.v1.json"}) {
		t.Errorf("the directory holds %v, want only state.v1.json", n)
	}
}

// TestUpdateKeepsURLsReadable: the file is meant to be read and edited, so a
// URL with a query keeps its & instead of \u0026.
func TestUpdateKeepsURLsReadable(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)
	const probe = "https://probe.example/204?a=1&b=2"
	got, _, err := s.Update(0, func(st *State) error {
		st.Health.ProbeURL = probe
		st.Servers = append(st.Servers, Server{ID: NewID(), Name: "a<b", Outbound: json.RawMessage(`{"protocol":"vless","note":"x&y<z>"}`)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	data := string(get(t, dir, "state.v1.json"))
	for _, want := range []string{probe, `"a<b"`, `x&y<z>`} {
		if !strings.Contains(data, want) {
			t.Errorf("state.v1.json lacks %s:\n%s", want, data)
		}
	}
	st, _ := mustOpen(t, dir).State()
	sameState(t, st, got)
}

func TestUpdateConflict(t *testing.T) {
	if ErrConflict.Error() != "store: the state changed since it was read" {
		t.Errorf("ErrConflict says %q", ErrConflict)
	}
	dir := t.TempDir()
	s := mustOpen(t, dir)
	for _, name := range []string{"one", "two"} {
		if _, _, err := s.Update(0, add(name)); err != nil {
			t.Fatal(err)
		}
	}
	before := get(t, dir, "state.v1.json")
	stBefore, _ := s.State()
	for _, stale := range []uint64{1, 3, 1 << 63} {
		called := false
		st, rev, err := s.Update(stale, func(st *State) error {
			called = true
			return add("three")(st)
		})
		if !errors.Is(err, ErrConflict) {
			t.Errorf("Update(%d) = %v, want ErrConflict", stale, err)
		}
		if called {
			t.Errorf("Update(%d) ran fn although the revision is stale", stale)
		}
		if rev != 0 || len(st.Servers) != 0 {
			t.Errorf("Update(%d) returned %+v, %d with its error", stale, st, rev)
		}
		if after := get(t, dir, "state.v1.json"); !bytes.Equal(after, before) {
			t.Errorf("Update(%d) changed the file:\n%s\nwas\n%s", stale, after, before)
		}
		now, rev := s.State()
		sameState(t, now, stBefore)
		if rev != 2 {
			t.Errorf("revision %d after Update(%d), want 2", rev, stale)
		}
	}
}

func TestUpdateRevisions(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)
	// A revision of 0 skips the check; the current revision passes it.
	var rev uint64
	for i, check := range []uint64{0, 1, 0, 3} {
		var err error
		_, rev, err = s.Update(check, add(fmt.Sprint("server", i)))
		if err != nil {
			t.Fatalf("Update(%d): %v", check, err)
		}
		if want := uint64(i + 1); rev != want {
			t.Fatalf("Update(%d) gave revision %d, want %d", check, rev, want)
		}
		if f := readFields(t, dir, "state.v1.json"); f.Revision != rev {
			t.Fatalf("the file has revision %d, want %d", f.Revision, rev)
		}
	}
	st, got := s.State()
	if got != 4 || len(st.Servers) != 4 {
		t.Errorf("State() = %d servers at revision %d, want 4 at 4", len(st.Servers), got)
	}
}

func TestUpdateInvalidWritesNothing(t *testing.T) {
	t.Run("no file yet", func(t *testing.T) {
		dir := t.TempDir()
		s := mustOpen(t, dir)
		bad := Default()
		bad.DefaultPolicy.Mode = "bogus"
		want := bad.Validate()
		if want == nil {
			t.Fatal("the test state is valid")
		}
		_, _, err := s.Update(0, func(st *State) error {
			st.DefaultPolicy.Mode = "bogus"
			return nil
		})
		if err == nil || err.Error() != want.Error() {
			t.Errorf("Update = %v, want Validate's error unchanged: %v", err, want)
		}
		if got := names(t, dir); len(got) != 0 {
			t.Errorf("Update wrote %v", got)
		}
		st, rev := s.State()
		if rev != 0 || !reflect.DeepEqual(st, Default()) {
			t.Errorf("State() = %+v, %d; want Default() at 0", st, rev)
		}
	})
	t.Run("with a file", func(t *testing.T) {
		dir := t.TempDir()
		s := mustOpen(t, dir)
		if _, _, err := s.Update(0, add("alpha")); err != nil {
			t.Fatal(err)
		}
		before := get(t, dir, "state.v1.json")
		stBefore, revBefore := s.State()

		// The edit reaches into the state's lists, so that it also shows
		// whether fn works on a copy.
		edit := func(st *State) error {
			st.Servers[0].Name = " "
			st.Servers[0].Outbound[2] = 'X'
			st.Servers = append(st.Servers, server("beta"))
			return nil
		}
		bad := stBefore.Clone()
		edit(&bad)
		want := bad.Validate()
		if want == nil {
			t.Fatal("the test state is valid")
		}
		_, rev, err := s.Update(revBefore, edit)
		if err == nil || err.Error() != want.Error() {
			t.Errorf("Update = %v, want Validate's error unchanged: %v", err, want)
		}
		if rev != 0 {
			t.Errorf("Update returned revision %d with its error", rev)
		}
		if after := get(t, dir, "state.v1.json"); !bytes.Equal(after, before) {
			t.Errorf("Update changed the file:\n%s\nwas\n%s", after, before)
		}
		st, rev := s.State()
		sameState(t, st, stBefore)
		if rev != revBefore {
			t.Errorf("revision %d, want %d", rev, revBefore)
		}
		if n := names(t, dir); !slices.Equal(n, []string{"state.v1.json"}) {
			t.Errorf("the directory holds %v", n)
		}
	})
}

func TestUpdateFnError(t *testing.T) {
	boom := errors.New("boom")
	dir := t.TempDir()
	s := mustOpen(t, dir)
	fail := func(st *State) error {
		add("lost")(st)
		st.DefaultPolicy.Mode = ModeFull
		return boom
	}

	// With no file yet.
	if _, _, err := s.Update(0, fail); err != boom {
		t.Errorf("Update = %v, want the error fn returned, unchanged", err)
	}
	if got := names(t, dir); len(got) != 0 {
		t.Errorf("Update wrote %v", got)
	}

	// With a file.
	if _, _, err := s.Update(0, add("alpha")); err != nil {
		t.Fatal(err)
	}
	before := get(t, dir, "state.v1.json")
	stBefore, revBefore := s.State()
	if _, rev, err := s.Update(revBefore, fail); err != boom || rev != 0 {
		t.Errorf("Update = revision %d, %v; want 0 and the error fn returned, unchanged", rev, err)
	}
	if after := get(t, dir, "state.v1.json"); !bytes.Equal(after, before) {
		t.Errorf("Update changed the file:\n%s\nwas\n%s", after, before)
	}
	st, rev := s.State()
	sameState(t, st, stBefore)
	if rev != revBefore {
		t.Errorf("revision %d, want %d", rev, revBefore)
	}
}

func TestUpdateWriteFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s := mustOpen(t, dir)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.Update(0, add("alpha"))
	if err == nil || !strings.HasPrefix(err.Error(), "store: state.v1.json: ") {
		t.Fatalf("Update = %v, want a store: state.v1.json: error", err)
	}
	st, rev := s.State()
	if rev != 0 || !reflect.DeepEqual(st, Default()) {
		t.Errorf("State() = %+v, %d after a failed write; want Default() at 0", st, rev)
	}
	// The failed write did not use up the revision.
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, rev, err := s.Update(0, add("alpha")); err != nil || rev != 1 {
		t.Errorf("Update after the directory came back = revision %d, %v; want 1", rev, err)
	}
}

func TestStateIsACopy(t *testing.T) {
	s := mustOpen(t, t.TempDir())
	var kept *State
	got, _, err := s.Update(0, func(st *State) error {
		kept = st
		return add("alpha")(st)
	})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := s.State()
	wantJSON := compact(t, want)

	scribble := func(st *State) {
		st.Servers[0].Name = "changed"
		st.Servers[0].Outbound[2] = 'X'
		st.Servers = append(st.Servers, server("extra"))
		st.Devices = append(st.Devices, Device{})
	}
	scribble(&got)
	snapshot, _ := s.State()
	scribble(&snapshot)
	// fn's pointer outlives the Update; using it must not reach the store.
	kept.Servers[0].Name = "changed"
	kept.Servers[0].Outbound[2] = 'X'

	now, _ := s.State()
	if g := compact(t, now); g != wantJSON {
		t.Errorf("the store's state changed through a copy:\n%s\nwant\n%s", g, wantJSON)
	}
}

func TestConcurrentUpdates(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)
	const writers, each = 8, 5
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := range each {
				if _, _, err := s.Update(0, add(fmt.Sprintf("w%d-%d", w, i))); err != nil {
					t.Error(err)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range each {
				st, rev := s.State()
				if uint64(len(st.Servers)) != rev {
					t.Errorf("State() has %d servers at revision %d", len(st.Servers), rev)
				}
			}
		}()
	}
	wg.Wait()
	st, rev := s.State()
	if rev != writers*each || len(st.Servers) != writers*each {
		t.Errorf("State() = %d servers at revision %d, want %d", len(st.Servers), rev, writers*each)
	}
	again := mustOpen(t, dir)
	st2, rev2 := again.State()
	sameState(t, st2, st)
	if rev2 != rev {
		t.Errorf("reopened at revision %d, want %d", rev2, rev)
	}
}

func TestCorruptFileIsAnError(t *testing.T) {
	good := stateWithProbe("https://www.gstatic.com/generate_204")
	for _, c := range []struct {
		name string
		data []byte
		want string // part of the error
	}{
		{"truncated", []byte("{"), "unexpected end of JSON input"},
		{"empty file", nil, "unexpected end of JSON input"},
		{"trailing bytes", append(fileJSON(1, 0, good), 'x'), "invalid character"},
		{"not an object", []byte("[]"), "cannot unmarshal"},
		{"version of another file", fileJSON(2, 0, good), "version is 2, want 1"},
		{"no version", []byte(`{"revision":0,"state":` + good + `}`), "version is 0, want 1"},
		{"no state", []byte(`{"version":1,"revision":0}`), "state is missing"},
		{"null state", []byte(`{"version":1,"revision":0,"state":null}`), "state is missing"},
		{"negative revision", []byte(`{"version":1,"revision":-1,"state":` + good + `}`), "cannot unmarshal"},
		{"state of the wrong shape", fileJSON(1, 0, `"text"`), "cannot unmarshal"},
		{"fails Validate", fileJSON(1, 0, stateWithProbe("ftp://x.example")), "health.probe_url: must be an absolute http or https URL"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			put(t, dir, "state.v1.json", c.data)
			_, err := Open(dir)
			if err == nil {
				t.Fatal("Open succeeded")
			}
			if msg := err.Error(); !strings.HasPrefix(msg, "store: state.v1.json: ") || !strings.Contains(msg, c.want) {
				t.Errorf("Open = %q, want store: state.v1.json: … %s", msg, c.want)
			}
			if after := get(t, dir, "state.v1.json"); !bytes.Equal(after, c.data) {
				t.Errorf("Open changed the file to %q, was %q", after, c.data)
			}
			if n := names(t, dir); !slices.Equal(n, []string{"state.v1.json"}) {
				t.Errorf("the directory holds %v", n)
			}
		})
	}
}

func TestOpenNormalisesNilLists(t *testing.T) {
	for _, c := range []struct{ name, lists string }{
		{"null", `"servers":null,"subscriptions":null,"devices":null,`},
		{"omitted", ``},
		{"some of each", `"servers":null,"devices":[],`},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			put(t, dir, "state.v1.json", fileJSON(1, 4, `{`+c.lists+stateTail+`,"health":{"probe_url":"https://www.gstatic.com/generate_204"}}`))
			s := mustOpen(t, dir)
			st, _ := s.State()
			if want := Default(); !reflect.DeepEqual(st, want) {
				t.Errorf("state is %+v, want Default() %+v", st, want)
			}

			// What goes back to the file is [], also when fn makes a list nil.
			for i, edit := range []func(*State) error{
				func(st *State) error { st.DefaultPolicy.Mode = ModeSmart; return nil },
				func(st *State) error { st.Servers, st.Subscriptions, st.Devices = nil, nil, nil; return nil },
			} {
				st, _, err := s.Update(0, edit)
				if err != nil {
					t.Fatal(err)
				}
				if st.Servers == nil || st.Subscriptions == nil || st.Devices == nil {
					t.Errorf("edit %d: Update returned a nil list: %+v", i, st)
				}
				var raw map[string]json.RawMessage
				if err := json.Unmarshal(get(t, dir, "state.v1.json"), &raw); err != nil {
					t.Fatal(err)
				}
				var onDisk map[string]any
				if err := json.Unmarshal(raw["state"], &onDisk); err != nil {
					t.Fatal(err)
				}
				for _, key := range []string{"servers", "subscriptions", "devices"} {
					if list, ok := onDisk[key].([]any); !ok || list == nil || len(list) != 0 {
						t.Errorf("edit %d: the file has %s = %v, want []", i, key, onDisk[key])
					}
				}
			}
			again := mustOpen(t, dir)
			st, _ = again.State()
			if st.Servers == nil || st.Subscriptions == nil || st.Devices == nil {
				t.Errorf("a reopened state has a nil list: %+v", st)
			}
		})
	}
}

func TestMigrates(t *testing.T) {
	dir := t.TempDir()
	v1 := fileJSON(1, 7, stateBeforeHealth)
	put(t, dir, "state.v1.json", v1)

	s, err := openWith(dir, 2, map[int]migration{1: addHealth})
	if err != nil {
		t.Fatal(err)
	}
	st, rev := s.State()
	if rev != 7 || st.Health.ProbeURL != probeAfterMigration {
		t.Errorf("State() = probe %q at revision %d, want the migrated %q at 7", st.Health.ProbeURL, rev, probeAfterMigration)
	}
	if n := names(t, dir); !slices.Equal(n, []string{"state.v1.json", "state.v2.json"}) {
		t.Errorf("the directory holds %v", n)
	}
	if fi, err := os.Stat(filepath.Join(dir, "state.v2.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("state.v2.json: %v, %v; want mode 0600", fi, err)
	}
	f := readFields(t, dir, "state.v2.json")
	if f.Version != 2 || f.Revision != 7 {
		t.Errorf("state.v2.json has version %d, revision %d; want 2 and 7", f.Version, f.Revision)
	}
	if !bytes.Equal(get(t, dir, "state.v1.json"), v1) {
		t.Error("the version 1 file changed")
	}

	// From here on the store writes version 2 and leaves version 1 alone.
	if _, rev, err := s.Update(7, add("alpha")); err != nil || rev != 8 {
		t.Fatalf("Update = revision %d, %v; want 8", rev, err)
	}
	if f := readFields(t, dir, "state.v2.json"); f.Revision != 8 {
		t.Errorf("state.v2.json has revision %d, want 8", f.Revision)
	}
	if !bytes.Equal(get(t, dir, "state.v1.json"), v1) {
		t.Error("the version 1 file changed after an Update")
	}
	// And the next Open reads version 2, with nothing to migrate.
	again, err := openWith(dir, 2, map[int]migration{1: mustFail(t)})
	if err != nil {
		t.Fatal(err)
	}
	st2, rev2 := again.State()
	if rev2 != 8 || len(st2.Servers) != 1 {
		t.Errorf("reopened: %d servers at revision %d, want 1 at 8", len(st2.Servers), rev2)
	}
}

func TestMigratesInSteps(t *testing.T) {
	t.Run("from 1 to 3", func(t *testing.T) {
		dir := t.TempDir()
		v1 := fileJSON(1, 2, stateBeforeHealth)
		put(t, dir, "state.v1.json", v1)
		var order []int
		step := func(n int, m migration) migration {
			return func(raw json.RawMessage) (json.RawMessage, error) {
				order = append(order, n)
				return m(raw)
			}
		}
		s, err := openWith(dir, 3, map[int]migration{1: step(1, addHealth), 2: step(2, setSmart)})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(order, []int{1, 2}) {
			t.Errorf("migrations ran as %v, want [1 2]", order)
		}
		st, rev := s.State()
		if rev != 2 || st.Health.ProbeURL != probeAfterMigration || st.DefaultPolicy.Mode != ModeSmart {
			t.Errorf("State() = %+v at revision %d, want both migrations applied at 2", st, rev)
		}
		// Only the result is written, not the version in between.
		if n := names(t, dir); !slices.Equal(n, []string{"state.v1.json", "state.v3.json"}) {
			t.Errorf("the directory holds %v", n)
		}
		if !bytes.Equal(get(t, dir, "state.v1.json"), v1) {
			t.Error("the version 1 file changed")
		}
	})
	t.Run("from 2 to 3", func(t *testing.T) {
		dir := t.TempDir()
		v1 := fileJSON(1, 1, stateBeforeHealth)
		v2 := fileJSON(2, 5, stateWithProbe("https://www.gstatic.com/generate_204"))
		put(t, dir, "state.v1.json", v1)
		put(t, dir, "state.v2.json", v2)
		s, err := openWith(dir, 3, map[int]migration{1: mustFail(t), 2: setSmart})
		if err != nil {
			t.Fatal(err)
		}
		st, rev := s.State()
		if rev != 5 || st.DefaultPolicy.Mode != ModeSmart {
			t.Errorf("State() = %+v at revision %d, want version 2 migrated at 5", st, rev)
		}
		if n := names(t, dir); !slices.Equal(n, []string{"state.v1.json", "state.v2.json", "state.v3.json"}) {
			t.Errorf("the directory holds %v", n)
		}
		if !bytes.Equal(get(t, dir, "state.v1.json"), v1) || !bytes.Equal(get(t, dir, "state.v2.json"), v2) {
			t.Error("an older file changed")
		}
	})
}

func TestMigrationFails(t *testing.T) {
	boom := errors.New("boom")
	for _, c := range []struct {
		name string
		m    migration
		want string
	}{
		{"returns an error", func(json.RawMessage) (json.RawMessage, error) { return nil, boom }, "migration from version 1 to 2 failed: boom"},
		{"returns no JSON", func(json.RawMessage) (json.RawMessage, error) { return json.RawMessage("not json"), nil }, "migration from version 1 to 2 returned invalid JSON"},
		{"returns an invalid state", func(raw json.RawMessage) (json.RawMessage, error) { return raw, nil }, "health.probe_url"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			v1 := fileJSON(1, 3, stateBeforeHealth)
			put(t, dir, "state.v1.json", v1)
			_, err := openWith(dir, 2, map[int]migration{1: c.m})
			if err == nil {
				t.Fatal("Open succeeded")
			}
			if msg := err.Error(); !strings.HasPrefix(msg, "store: state.v1.json: ") || !strings.Contains(msg, c.want) {
				t.Errorf("Open = %q, want store: state.v1.json: … %s", msg, c.want)
			}
			if c.name == "returns an error" && !errors.Is(err, boom) {
				t.Errorf("Open = %v, want it to wrap the migration's error", err)
			}
			if n := names(t, dir); !slices.Equal(n, []string{"state.v1.json"}) {
				t.Errorf("the directory holds %v, want nothing written", n)
			}
			if !bytes.Equal(get(t, dir, "state.v1.json"), v1) {
				t.Error("the version 1 file changed")
			}
		})
	}
}

func TestIgnoresNewer(t *testing.T) {
	future := []byte("a file from the future, not JSON")
	t.Run("migrates from the highest it can read", func(t *testing.T) {
		dir := t.TempDir()
		v1 := fileJSON(1, 6, stateBeforeHealth)
		put(t, dir, "state.v1.json", v1)
		put(t, dir, "state.v3.json", future)
		s, err := openWith(dir, 2, map[int]migration{1: addHealth})
		if err != nil {
			t.Fatal(err)
		}
		st, rev := s.State()
		if rev != 6 || st.Health.ProbeURL != probeAfterMigration {
			t.Errorf("State() = probe %q at revision %d, want the migrated %q at 6", st.Health.ProbeURL, rev, probeAfterMigration)
		}
		if n := names(t, dir); !slices.Equal(n, []string{"state.v1.json", "state.v2.json", "state.v3.json"}) {
			t.Errorf("the directory holds %v", n)
		}
		if !bytes.Equal(get(t, dir, "state.v3.json"), future) {
			t.Error("the version 3 file changed")
		}
		if !bytes.Equal(get(t, dir, "state.v1.json"), v1) {
			t.Error("the version 1 file changed")
		}
		// Updates go to the version this program writes.
		if _, _, err := s.Update(0, add("alpha")); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(get(t, dir, "state.v3.json"), future) {
			t.Error("the version 3 file changed after an Update")
		}
	})
	t.Run("loads version 2 when it is there", func(t *testing.T) {
		dir := t.TempDir()
		v1 := fileJSON(1, 6, stateBeforeHealth)
		v2 := fileJSON(2, 9, stateWithProbe("https://v2.example/204"))
		put(t, dir, "state.v1.json", v1)
		put(t, dir, "state.v2.json", v2)
		put(t, dir, "state.v3.json", future)
		s, err := openWith(dir, 2, map[int]migration{1: mustFail(t)})
		if err != nil {
			t.Fatal(err)
		}
		st, rev := s.State()
		if rev != 9 || st.Health.ProbeURL != "https://v2.example/204" {
			t.Errorf("State() = probe %q at revision %d, want version 2's %q at 9", st.Health.ProbeURL, rev, "https://v2.example/204")
		}
		if n := names(t, dir); !slices.Equal(n, []string{"state.v1.json", "state.v2.json", "state.v3.json"}) {
			t.Errorf("the directory holds %v", n)
		}
		for name, want := range map[string][]byte{"state.v1.json": v1, "state.v2.json": v2, "state.v3.json": future} {
			if !bytes.Equal(get(t, dir, name), want) {
				t.Errorf("%s changed", name)
			}
		}
	})
}

// TestLoadsTheHighestVersion: versions are numbers, not names, so 10 is
// higher than 9 and 2 although "state.v10.json" sorts before both.
func TestLoadsTheHighestVersion(t *testing.T) {
	dir := t.TempDir()
	for i, version := range []int{2, 9, 10, 11} {
		put(t, dir, stateName(version), fileJSON(version, uint64(i+1), stateWithProbe(fmt.Sprintf("https://v%d.example/204", version))))
	}
	s, err := openWith(dir, 10, map[int]migration{9: mustFail(t)})
	if err != nil {
		t.Fatal(err)
	}
	st, rev := s.State()
	if rev != 3 || st.Health.ProbeURL != "https://v10.example/204" {
		t.Errorf("State() = probe %q at revision %d, want version 10's at 3", st.Health.ProbeURL, rev)
	}
	if len(names(t, dir)) != 4 {
		t.Errorf("the directory holds %v, want the four files it had", names(t, dir))
	}
}

// TestOnlyNewerIsAnError: a program that finds only state from a newer one
// must not start from an empty state as if nothing were configured.
func TestOnlyNewerIsAnError(t *testing.T) {
	dir := t.TempDir()
	future := []byte("a file from the future, not JSON")
	put(t, dir, "state.v3.json", future)
	_, err := openWith(dir, 2, map[int]migration{1: mustFail(t)})
	if err == nil {
		t.Fatal("Open succeeded")
	}
	if msg := err.Error(); !strings.HasPrefix(msg, "store: state.v3.json: ") || !strings.Contains(msg, "newer") {
		t.Errorf("Open = %q, want store: state.v3.json: … newer …", msg)
	}
	if n := names(t, dir); !slices.Equal(n, []string{"state.v3.json"}) {
		t.Errorf("the directory holds %v", n)
	}
	if !bytes.Equal(get(t, dir, "state.v3.json"), future) {
		t.Error("the version 3 file changed")
	}
}

func TestMissingMigration(t *testing.T) {
	dir := t.TempDir()
	v1 := fileJSON(1, 3, stateBeforeHealth)
	put(t, dir, "state.v1.json", v1)
	_, err := openWith(dir, 3, map[int]migration{1: addHealth})
	if err == nil {
		t.Fatal("Open succeeded")
	}
	if msg := err.Error(); !strings.HasPrefix(msg, "store: state.v1.json: ") || !strings.Contains(msg, "no migration from version 2 to 3") {
		t.Errorf("Open = %q, want store: state.v1.json: … no migration from version 2 to 3", msg)
	}
	if n := names(t, dir); !slices.Equal(n, []string{"state.v1.json"}) {
		t.Errorf("the directory holds %v, want nothing written", n)
	}
	if !bytes.Equal(get(t, dir, "state.v1.json"), v1) {
		t.Error("the version 1 file changed")
	}
}

func TestIgnoresOtherFiles(t *testing.T) {
	dir := t.TempDir()
	junk := map[string][]byte{
		"state.v1.json.tmp-123":  []byte("{"),
		".state.v1.json.tmp-456": []byte("{"),
		"state.vX.json":          []byte("{"),
		"state.v.json":           []byte("{"),
		"state.v0.json":          []byte("{"),
		"state.v01.json":         []byte("{"),
		"state.v+1.json":         []byte("{"),
		"state.v1.json.bak":      []byte("{"),
		"state.json":             []byte("{"),
		"notes.txt":              []byte("remember the milk"),
	}
	for name, data := range junk {
		put(t, dir, name, data)
	}
	s := mustOpen(t, dir)
	st, rev := s.State()
	if rev != 0 || !reflect.DeepEqual(st, Default()) {
		t.Errorf("State() = %+v, %d; want Default() at 0", st, rev)
	}
	// None of it is touched, nor does the first Update care about it.
	if _, _, err := s.Update(0, add("alpha")); err != nil {
		t.Fatal(err)
	}
	for name, data := range junk {
		if !bytes.Equal(get(t, dir, name), data) {
			t.Errorf("%s changed", name)
		}
	}
	if len(names(t, dir)) != len(junk)+1 {
		t.Errorf("the directory holds %v, want the junk and state.v1.json", names(t, dir))
	}
}
