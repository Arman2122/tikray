package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
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
	got, rev, err := s.Update(AnyRevision, func(st *State) error {
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
	got, _, err := s.Update(AnyRevision, func(st *State) error {
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
		if _, _, err := s.Update(AnyRevision, add(name)); err != nil {
			t.Fatal(err)
		}
	}
	before := get(t, dir, "state.v1.json")
	stBefore, _ := s.State()
	// Revision 0 is no different from any other: it is stale at revision 2.
	for _, stale := range []uint64{0, 1, 3, 1 << 63} {
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
	// The current revision passes the check, and so does AnyRevision. The first
	// Update of a new store is at revision 0, which is an exact check too.
	var rev uint64
	for i, check := range []uint64{0, 1, AnyRevision, 3} {
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
		_, _, err := s.Update(AnyRevision, func(st *State) error {
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
		if _, _, err := s.Update(AnyRevision, add("alpha")); err != nil {
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
	if _, _, err := s.Update(AnyRevision, fail); err != boom {
		t.Errorf("Update = %v, want the error fn returned, unchanged", err)
	}
	if got := names(t, dir); len(got) != 0 {
		t.Errorf("Update wrote %v", got)
	}

	// With a file.
	if _, _, err := s.Update(AnyRevision, add("alpha")); err != nil {
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
	_, _, err := s.Update(AnyRevision, add("alpha"))
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
	if _, rev, err := s.Update(AnyRevision, add("alpha")); err != nil || rev != 1 {
		t.Errorf("Update after the directory came back = revision %d, %v; want 1", rev, err)
	}
}

func TestStateIsACopy(t *testing.T) {
	s := mustOpen(t, t.TempDir())
	var kept *State
	got, _, err := s.Update(AnyRevision, func(st *State) error {
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
				if _, _, err := s.Update(AnyRevision, add(fmt.Sprintf("w%d-%d", w, i))); err != nil {
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
				st, _, err := s.Update(AnyRevision, edit)
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
		if _, _, err := s.Update(AnyRevision, add("alpha")); err != nil {
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
	if _, _, err := s.Update(AnyRevision, add("alpha")); err != nil {
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

func TestUpdateAnyRevision(t *testing.T) {
	if AnyRevision != math.MaxUint64 {
		t.Errorf("AnyRevision is %d, want the largest uint64", uint64(AnyRevision))
	}
	dir := t.TempDir()
	put(t, dir, "state.v1.json", fileJSON(1, 5, stateWithProbe("https://www.gstatic.com/generate_204")))
	s := mustOpen(t, dir)
	st, rev, err := s.Update(AnyRevision, add("alpha"))
	if err != nil || rev != 6 || len(st.Servers) != 1 {
		t.Fatalf("Update(AnyRevision) = %d servers at revision %d, %v; want 1 at 6", len(st.Servers), rev, err)
	}
	if f := readFields(t, dir, "state.v1.json"); f.Revision != 6 {
		t.Errorf("the file has revision %d, want 6", f.Revision)
	}
}

// TestUpdateRevisionZeroIsChecked: 0 is a revision like the others, the one of
// a store nothing has been written to. It does not skip the check.
func TestUpdateRevisionZeroIsChecked(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)
	if _, rev, err := s.Update(0, add("alpha")); err != nil || rev != 1 {
		t.Fatalf("Update(0) on a new store = revision %d, %v; want 1", rev, err)
	}
	before := get(t, dir, "state.v1.json")
	called := false
	_, rev, err := s.Update(0, func(st *State) error {
		called = true
		return add("beta")(st)
	})
	if !errors.Is(err, ErrConflict) || rev != 0 {
		t.Errorf("Update(0) at revision 1 = revision %d, %v; want ErrConflict", rev, err)
	}
	if called {
		t.Error("Update(0) ran fn at revision 1")
	}
	if after := get(t, dir, "state.v1.json"); !bytes.Equal(after, before) {
		t.Errorf("Update(0) changed the file:\n%s\nwas\n%s", after, before)
	}
	if st, rev := s.State(); rev != 1 || len(st.Servers) != 1 {
		t.Errorf("State() = %d servers at revision %d, want 1 at 1", len(st.Servers), rev)
	}
}

// TestOpenRefusesTheRevisionOfAnyRevision: a state at AnyRevision would hand
// its callers a revision that checks nothing.
func TestOpenRefusesTheRevisionOfAnyRevision(t *testing.T) {
	dir := t.TempDir()
	data := fileJSON(1, AnyRevision, stateWithProbe("https://www.gstatic.com/generate_204"))
	put(t, dir, "state.v1.json", data)
	_, err := Open(dir)
	if err == nil || !strings.HasPrefix(err.Error(), "store: state.v1.json: ") || !strings.Contains(err.Error(), "revision") {
		t.Errorf("Open = %v, want a store: state.v1.json: error about the revision", err)
	}
	if !bytes.Equal(get(t, dir, "state.v1.json"), data) {
		t.Error("Open changed the file")
	}
}

// refused is a server whose outbound is not a proxy's, which this tikray
// refuses.
func refused(name string) Server {
	return Server{ID: NewID(), Name: name, Outbound: json.RawMessage(`{"protocol":"direct"}`)}
}

// stateWith is the default state holding servers, as the compact JSON of a
// state file's "state".
func stateWith(t *testing.T, servers ...Server) string {
	t.Helper()
	st := Default()
	st.Servers = servers
	return compact(t, st)
}

func TestOpenDegradesRefusedServer(t *testing.T) {
	dir := t.TempDir()
	good, bad := server("good"), refused("bad")
	data := fileJSON(1, 3, stateWith(t, good, bad))
	put(t, dir, "state.v1.json", data)

	s := mustOpen(t, dir)
	st, rev := s.State()
	if rev != 3 || len(st.Servers) != 2 {
		t.Fatalf("State() = %d servers at revision %d, want 2 at 3", len(st.Servers), rev)
	}
	if g := st.Servers[0]; g.Disabled || g.Invalid != "" {
		t.Errorf("the valid server is disabled=%t invalid=%q, want it left alone", g.Disabled, g.Invalid)
	}
	b := st.Servers[1]
	if !b.Disabled || !strings.Contains(b.Invalid, "direct") {
		t.Errorf("the refused server is disabled=%t invalid=%q, want it disabled for direct", b.Disabled, b.Invalid)
	}
	if strings.Contains(b.Invalid, "servers[") || strings.Contains(b.Invalid, "outbound") {
		t.Errorf("the reason %q holds the problem's path", b.Invalid)
	}
	if got := s.Degraded(); !slices.Equal(got, []string{bad.ID}) {
		t.Errorf("Degraded() = %v, want [%s]", got, bad.ID)
	}
	if err := st.Validate(); err != nil {
		t.Errorf("the degraded state does not validate: %v", err)
	}

	// Open writes nothing.
	if after := get(t, dir, "state.v1.json"); !bytes.Equal(after, data) {
		t.Errorf("Open changed the file:\n%s\nwas\n%s", after, data)
	}
	if n := names(t, dir); !slices.Equal(n, []string{"state.v1.json"}) {
		t.Errorf("the directory holds %v", n)
	}

	// The next Update does, with the server disabled and the reason in it.
	if _, rev, err := s.Update(3, func(st *State) error { st.DefaultPolicy.Mode = ModeSmart; return nil }); err != nil || rev != 4 {
		t.Fatalf("Update = revision %d, %v; want 4", rev, err)
	}
	var onDisk struct {
		Servers []struct {
			ID       string `json:"id"`
			Disabled bool   `json:"disabled"`
			Invalid  string `json:"invalid"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(readFields(t, dir, "state.v1.json").State, &onDisk); err != nil {
		t.Fatal(err)
	}
	if len(onDisk.Servers) != 2 || onDisk.Servers[0].Disabled || onDisk.Servers[0].Invalid != "" ||
		onDisk.Servers[1].ID != bad.ID || !onDisk.Servers[1].Disabled || onDisk.Servers[1].Invalid != b.Invalid {
		t.Errorf("the file's servers are %+v, want the valid one as it was and the refused one disabled with invalid %q", onDisk.Servers, b.Invalid)
	}

	// The reopened store has it already: Open disables nothing this time, and
	// the reason is kept.
	again := mustOpen(t, dir)
	st2, rev2 := again.State()
	if rev2 != 4 || !st2.Servers[1].Disabled || st2.Servers[1].Invalid != b.Invalid {
		t.Errorf("reopened: revision %d, server %+v; want 4 and the reason kept", rev2, st2.Servers[1])
	}
	if got := again.Degraded(); len(got) != 0 {
		t.Errorf("Degraded() = %v after the file was written with the server disabled, want none", got)
	}
}

// TestOpenDegradesEachCheckOfAServer: each check a server has on its own
// disables it, with that check's text as the reason, and none of the reasons
// repeats a credential, a name or a path.
func TestOpenDegradesEachCheckOfAServer(t *testing.T) {
	srv := func(name, outbound string) Server {
		return Server{ID: NewID(), Name: name, Outbound: json.RawMessage(outbound)}
	}
	for _, c := range []struct {
		name string
		srv  Server
		want string
	}{
		{"protocol that is not a proxy", srv("n", `{"protocol":"direct"}`), `"direct" is not a proxy protocol`},
		{"no protocol", srv("n", `{"settings":{}}`), "is required"},
		{"a tag", srv("n", `{"protocol":"vless","tag":"x"}`), "must not be set: tikray tags the outbound itself"},
		{"not an object", srv("n", `"vless"`), "must be a JSON object"},
		{"refused by xray-core", srv("n", fmt.Sprintf(vlessPlainTo, "1.2.3.4")), "xray-core refuses VLESS without TLS or encryption to a public address"},
		{"empty name", srv("", `{"protocol":"vless"}`), "must not be empty"},
		{"name with an escape", srv("Frank\x1b[2Jfurt", `{"protocol":"vless"}`), "must not hold control characters or bidi overrides"},
		{"name too long", srv(strings.Repeat("a", MaxNameRunes+1), `{"protocol":"vless"}`), fmt.Sprintf("must be at most %d characters", MaxNameRunes)},
		{"name and outbound", srv("", `{"protocol":"direct"}`), `must not be empty; "direct" is not a proxy protocol`},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			put(t, dir, "state.v1.json", fileJSON(1, 0, stateWith(t, server("good"), c.srv)))
			s := mustOpen(t, dir)
			st, _ := s.State()
			if got := st.Servers[1]; !got.Disabled || got.Invalid != c.want {
				t.Errorf("the server is disabled=%t invalid=%q, want it disabled for %q", got.Disabled, got.Invalid, c.want)
			}
			if st.Servers[0].Disabled || st.Servers[0].Invalid != "" {
				t.Errorf("the valid server was changed: %+v", st.Servers[0])
			}
			if got := s.Degraded(); !slices.Equal(got, []string{c.srv.ID}) {
				t.Errorf("Degraded() = %v, want [%s]", got, c.srv.ID)
			}
			if strings.Contains(st.Servers[1].Invalid, "s3cret") {
				t.Errorf("the reason repeats a secret: %q", st.Servers[1].Invalid)
			}
		})
	}
}

// TestOpenDegradesInOrderAndKeepsMarkedServers: Degraded lists the servers
// Open disabled in state order, a server the operator had disabled is marked
// invalid as well, and one that is marked already keeps its reason and is not
// listed.
func TestOpenDegradesInOrderAndKeepsMarkedServers(t *testing.T) {
	marked := refused("marked")
	marked.Disabled, marked.Invalid = true, "an older reason"
	off := refused("off")
	off.Disabled = true
	first, second := refused("first"), refused("second")
	dir := t.TempDir()
	put(t, dir, "state.v1.json", fileJSON(1, 0, stateWith(t, first, marked, server("good"), off, second)))
	s := mustOpen(t, dir)
	st, _ := s.State()
	if got, want := s.Degraded(), []string{first.ID, off.ID, second.ID}; !slices.Equal(got, want) {
		t.Errorf("Degraded() = %v, want %v", got, want)
	}
	if st.Servers[1].Invalid != "an older reason" {
		t.Errorf("a marked server's reason is %q, want it kept", st.Servers[1].Invalid)
	}
	for i, want := range []bool{true, true, false, true, true} {
		if st.Servers[i].Disabled != want {
			t.Errorf("servers[%d] disabled = %t, want %t", i, st.Servers[i].Disabled, want)
		}
	}
	if !strings.Contains(st.Servers[3].Invalid, "direct") {
		t.Errorf("the server the operator disabled has reason %q, want it marked too", st.Servers[3].Invalid)
	}
}

// TestOpenDegradesNothingWhenItIsValid: Degraded is empty, not nil, when
// there is nothing to degrade.
func TestOpenDegradesNothingWhenItIsValid(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, "state.v1.json", fileJSON(1, 1, stateWith(t, server("good"))))
	if got := mustOpen(t, dir).Degraded(); got == nil || len(got) != 0 {
		t.Errorf("Degraded() = %#v, want an empty list", got)
	}
	if got := mustOpen(t, t.TempDir()).Degraded(); got == nil || len(got) != 0 {
		t.Errorf("Degraded() of a new store = %#v, want an empty list", got)
	}
}

func TestOpenStillFailsOnStructure(t *testing.T) {
	overlap := func(st *State) {
		st.Devices = []Device{
			{Address: netip.MustParsePrefix("192.168.1.0/24"), Policy: Policy{Mode: ModeSmart}},
			{Address: netip.MustParsePrefix("192.168.1.5/32"), Policy: Policy{Mode: ModeSmart}},
		}
	}
	for _, c := range []struct {
		name string
		edit func(*State)
		want string // part of the error
	}{
		{"overlapping devices", overlap, "devices[1].address: overlaps devices[0]"},
		{"overlapping devices beside a refused server", func(st *State) {
			overlap(st)
			st.Servers = []Server{refused("bad")}
		}, "devices[1].address: overlaps devices[0]"},
		{"a refused server with a bad ID", func(st *State) {
			st.Servers = []Server{refused("bad")}
			st.Servers[0].ID = "NOT-HEX"
		}, "servers[0].id: must be 8 lowercase hex digits"},
		{"two refused servers with one ID", func(st *State) {
			a := refused("a")
			st.Servers = []Server{a, a}
		}, "servers[1].id: duplicates servers[0]"},
		{"a refused server of no subscription", func(st *State) {
			st.Servers = []Server{refused("bad")}
			st.Servers[0].Subscription = "00ff00ff"
		}, `servers[0].subscription: names no subscription: "00ff00ff"`},
		{"a server that is invalid but enabled", func(st *State) {
			st.Servers = []Server{refused("bad")}
			st.Servers[0].Invalid = "an older reason"
		}, "servers[0]: a server that failed this tikray's checks stays disabled"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			st := Default()
			c.edit(&st)
			data := fileJSON(1, 2, compact(t, st))
			put(t, dir, "state.v1.json", data)
			_, err := Open(dir)
			if err == nil {
				t.Fatal("Open succeeded")
			}
			if msg := err.Error(); !strings.HasPrefix(msg, "store: state.v1.json: ") || !strings.Contains(msg, c.want) {
				t.Errorf("Open = %q, want store: state.v1.json: … %s", msg, c.want)
			}
			if after := get(t, dir, "state.v1.json"); !bytes.Equal(after, data) {
				t.Errorf("Open changed the file to %q, was %q", after, data)
			}
		})
	}
}

// TestOpenWritesAMigrationAsItIs: the older file migrated to the new version
// is written as the migration made it. What Open disabled stays in memory, as
// it does when nothing is migrated.
func TestOpenWritesAMigrationAsItIs(t *testing.T) {
	dir := t.TempDir()
	// The older state has no health section, which version 2 requires.
	v1 := fileJSON(1, 7, `{"servers":[{"id":"a1b2c3d4","name":"bad","outbound":{"protocol":"direct"}}],"subscriptions":[],"devices":[],`+stateTail+`}`)
	put(t, dir, "state.v1.json", v1)

	s, err := openWith(dir, 2, map[int]migration{1: addHealth})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Degraded(); !slices.Equal(got, []string{"a1b2c3d4"}) {
		t.Errorf("Degraded() = %v, want [a1b2c3d4]", got)
	}
	if held, rev := s.State(); rev != 7 || !held.Servers[0].Disabled || held.Servers[0].Invalid == "" {
		t.Errorf("State() = %+v at revision %d, want the server disabled and invalid at 7", held.Servers, rev)
	}
	var onDisk struct {
		Servers []Server `json:"servers"`
	}
	if err := json.Unmarshal(readFields(t, dir, "state.v2.json").State, &onDisk); err != nil {
		t.Fatal(err)
	}
	if len(onDisk.Servers) != 1 || onDisk.Servers[0].Disabled || onDisk.Servers[0].Invalid != "" {
		t.Errorf("state.v2.json holds %+v, want the server as the migration left it", onDisk.Servers)
	}
	if !bytes.Equal(get(t, dir, "state.v1.json"), v1) {
		t.Error("the version 1 file changed")
	}
}
