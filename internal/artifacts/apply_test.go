package artifacts

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/xrayver"
)

// renderedBody is what the fake renderer renders unless a test says otherwise;
// it differs from activeConfigBody, the config the runner starts with.
const renderedBody = `{"inbounds":[{"protocol":"tun"}]}` + "\n"

// fakeRender is a Renderer that records its calls and renders body, or fails
// with err.
type fakeRender struct {
	mu    sync.Mutex
	body  string
	err   error
	calls []renderCall
}

type renderCall struct {
	core xrayver.Version
	geo  string
}

func (r *fakeRender) render(core xrayver.Version, geo string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, renderCall{core, geo})
	if r.err != nil {
		return nil, r.err
	}
	return []byte(r.body), nil
}

func (r *fakeRender) got() []renderCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]renderCall(nil), r.calls...)
}

// wantRenders fails unless the renderer was called exactly with want, in order.
func wantRenders(t *testing.T, r *fakeRender, want ...renderCall) {
	t.Helper()
	got := r.got()
	if len(want) == 0 && len(got) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("renderer calls = %v, want %v", got, want)
	}
}

// newRenderEnv is newCoreEnv with an updater whose renderer renders renderedBody.
func newRenderEnv(t *testing.T, active string) (*coreEnv, *fakeRender) {
	t.Helper()
	e := newCoreEnv(t, active)
	r := &fakeRender{body: renderedBody}
	e.u.Render = r.render
	return e, r
}

// configRel is the name under run/ of the config with body.
func configRel(body string) string { return "config/" + shaOf(body) + ".json" }

// configFiles lists run/config/, sorted.
func configFiles(t *testing.T, e *coreEnv) []string {
	t.Helper()
	names := dirNames(t, filepath.Join(e.data, "run", "config"))
	slices.Sort(names)
	return names
}

// historyLines returns the lines of the history file as written.
func historyLines(t *testing.T, e *coreEnv) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(e.data, "state", "core-history.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

func wantNoCandidateFile(t *testing.T, e *coreEnv) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(e.data, "run", "candidate.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("candidate.json was written: %v", err)
	}
}

func TestApplyCommits(t *testing.T) {
	e, r := newRenderEnv(t, "26.10.21")

	res, err := e.u.Apply(bg)
	wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
	want := Result{From: "26.10.21", To: "26.10.21", Outcome: "committed", Kind: "config", At: t0}
	wantResult(t, res, want)
	wantRenders(t, r, renderCall{mustVer(t, "26.10.21"), "g1"})

	rel := configRel(renderedBody)
	wantActions(t, e.runner, "trial", "commit")
	wantCandidate(t, e.runner, runnerapi.Candidate{
		Selection: runnerapi.Selection{Core: "26.10.21", Geo: "g1", Config: rel},
		Deadline:  t0.Add(120 * time.Second),
	})
	p := filepath.Join(e.data, "run", rel)
	if b, err := os.ReadFile(p); err != nil || string(b) != renderedBody {
		t.Errorf("%s = %q, %v; want the render", rel, b, err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("%s: %v, %v; want mode 0600", rel, fi, err)
	}
	if e.health.n.Load() == 0 {
		t.Error("the health check never ran")
	}
	if hits := e.rel.hitList(); len(hits) != 0 {
		t.Errorf("upstream was asked for %v; the active core is installed and verified", hits)
	}

	lines := historyLines(t, e)
	if len(lines) != 1 || !strings.Contains(lines[0], `"kind":"config"`) {
		t.Fatalf("history = %q, want one line with \"kind\":\"config\"", lines)
	}
	h := e.history(t)
	wantResult(t, h[0], want)
	if got := e.slots(t); !reflect.DeepEqual(got, []string{"26.10.21"}) {
		t.Errorf("slots = %v", got)
	}
	e.wantClean(t)
}

// A config holds every server's credentials, so run/config/ and the configs
// in it are root's alone; both images run as root. A run/config/ that an
// older tikray made open to all is closed.
func TestConfigsAreRootsAlone(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{"run/config made", func(t *testing.T, dir string) {
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
		}},
		{"run/config open to all", func(t *testing.T, dir string) {
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newRenderEnv(t, "")
			e.rel.add(t, "26.10.21")
			dir := filepath.Join(e.data, "run", "config")
			tc.setup(t, dir)

			res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
			wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
			for rel, want := range map[string]os.FileMode{
				"config":                0o700,
				configRel(renderedBody): 0o600,
				// The runner's own directory stays as it was.
				".": 0o755,
			} {
				fi, err := os.Stat(filepath.Join(e.data, "run", rel))
				if err != nil {
					t.Errorf("run/%s: %v", rel, err)
				} else if got := fi.Mode().Perm(); got != want {
					t.Errorf("run/%s has mode %v, want %v", rel, got, want)
				}
			}
		})
	}
}

// An Apply is a committed trial of the active core, so a rollback after it
// still goes to the core before.
func TestApplyKeepsRollbackWorking(t *testing.T) {
	e, _ := newRenderEnv(t, "26.10.21")
	install(t, e.cores(), "26.3.27")
	e.writeHistory(t, committedResult("26.3.27", ""), committedResult("26.10.21", "26.3.27"))

	res, err := e.u.Apply(bg)
	wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
	if got := committedVersions(e.history(t)); !reflect.DeepEqual(got, []string{"26.10.21", "26.3.27"}) {
		t.Errorf("committed versions = %v", got)
	}
	if got := e.slots(t); !reflect.DeepEqual(got, []string{"26.10.21", "26.3.27"}) {
		t.Errorf("slots = %v, want the previous core kept", got)
	}

	res, err = e.u.Rollback(bg)
	wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
	if res.To != "26.3.27" || res.Kind != "" {
		t.Errorf("Rollback = %+v, want to 26.3.27, of no kind", res)
	}
}

func TestApplyNoop(t *testing.T) {
	e, r := newRenderEnv(t, "26.10.21")
	r.body = activeConfigBody

	res, err := e.u.Apply(bg)
	wantOutcome(t, res, err, OutcomeNoop)
	wantResult(t, res, Result{From: "26.10.21", To: "26.10.21", Outcome: OutcomeNoop, Kind: "config", Detail: "already active", At: t0})
	wantRenders(t, r, renderCall{mustVer(t, "26.10.21"), "g1"})
	if calls := e.runner.actions(); len(calls) != 0 {
		t.Errorf("the runner got %v, want no trial", calls)
	}
	wantNoCandidateFile(t, e)
	lines := historyLines(t, e)
	if len(lines) != 1 || !strings.Contains(lines[0], `"kind":"config"`) || !strings.Contains(lines[0], `"outcome":"noop"`) {
		t.Errorf("history = %q", lines)
	}
}

func TestApplyNoActive(t *testing.T) {
	e, r := newRenderEnv(t, "")

	res, err := e.u.Apply(bg)
	wantOutcome(t, res, err, OutcomeRefused)
	wantDetail(t, res, "no active core: install one with tikray core update")
	if res.Kind != "config" {
		t.Errorf("Kind = %q, want config", res.Kind)
	}
	wantRenders(t, r)
	wantActions(t, e.runner)
	wantNoCandidateFile(t, e)
	if h := e.history(t); len(h) != 1 || h[0].Outcome != OutcomeRefused || h[0].Kind != "config" {
		t.Errorf("history = %+v", h)
	}
}

func TestApplyNoRenderer(t *testing.T) {
	e := newCoreEnv(t, "26.10.21")

	res, err := e.u.Apply(bg)
	wantOutcome(t, res, err, OutcomeRefused)
	wantDetail(t, res, "Render is not set")
	if calls := e.runner.allCalls(); len(calls) != 0 {
		t.Errorf("the runner got %v", calls)
	}
	wantNoCandidateFile(t, e)
}

func TestApplyRenderError(t *testing.T) {
	e, r := newRenderEnv(t, "26.10.21")
	boom := errors.New("render: no server is enabled")
	r.err = boom

	res, err := e.u.Apply(bg)
	wantOutcome(t, res, err, OutcomeRefused)
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the render's error", err)
	}
	wantDetail(t, res, boom.Error())
	wantActions(t, e.runner)
	wantNoCandidateFile(t, e)
	if got := configFiles(t, e); len(got) != 1 {
		t.Errorf("run/config holds %v, want only the active config", got)
	}
	if h := e.history(t); len(h) != 1 || h[0].Outcome != OutcomeRefused {
		t.Errorf("history = %+v", h)
	}
}

func TestApplyLocked(t *testing.T) {
	e, r := newRenderEnv(t, "26.10.21")
	release, ok := tryLock(t, e.data)
	if !ok {
		t.Fatal("could not take the lock")
	}
	defer release()

	res, err := e.u.Apply(bg)
	wantOutcome(t, res, err, OutcomeRefused)
	if !errors.Is(err, ErrLocked) {
		t.Errorf("err = %v, want ErrLocked", err)
	}
	if res.Kind != "config" {
		t.Errorf("Kind = %q, want config", res.Kind)
	}
	wantRenders(t, r)
	if calls := e.runner.allCalls(); len(calls) != 0 {
		t.Errorf("the runner got %v", calls)
	}
	wantNoCandidateFile(t, e)
}

// A config the data path or health check fails on is not kept: the runner
// reverts, and nothing is pruned.
func TestApplyUnhealthy(t *testing.T) {
	e, _ := newRenderEnv(t, "26.10.21")
	e.health.fn = func(int) error { return errors.New("probe: connection refused") }
	old := seedConfigs(t, e, 8)

	res, err := e.u.Apply(bg)
	wantOutcome(t, res, err, OutcomeUnhealthy)
	wantDetail(t, res, "probe: connection refused")
	if res.Kind != "config" {
		t.Errorf("Kind = %q, want config", res.Kind)
	}
	wantActions(t, e.runner, "trial", "abort")
	if sel := e.runner.activeSelection(); sel != e.activeSel {
		t.Errorf("the runner's active selection = %+v, want %+v", sel, e.activeSel)
	}
	wantConfigs(t, e, append([]string{shaOf(renderedBody) + ".json"}, old...)...)
	if lines := historyLines(t, e); len(lines) != 1 || !strings.Contains(lines[0], `"kind":"config"`) {
		t.Errorf("history = %q", lines)
	}
}

func TestUpdateRendersForTarget(t *testing.T) {
	t.Run("without a config file", func(t *testing.T) {
		e, r := newRenderEnv(t, "26.10.21")
		e.rel.add(t, "26.3.27")

		res, err := e.u.Update(bg, "26.3.27", UpdateOptions{})
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantResult(t, res, Result{From: "26.10.21", To: "26.3.27", Outcome: "committed", Source: "direct", Verified: "dgst", At: t0})
		wantRenders(t, r, renderCall{mustVer(t, "26.3.27"), "g1"})
		rel := configRel(renderedBody)
		wantCandidate(t, e.runner, runnerapi.Candidate{
			Selection: runnerapi.Selection{Core: "26.3.27", Geo: "g1", Config: rel},
			Deadline:  t0.Add(120 * time.Second),
		})
		if b, err := os.ReadFile(filepath.Join(e.data, "run", rel)); err != nil || string(b) != renderedBody {
			t.Errorf("%s = %q, %v; want the render", rel, b, err)
		}
	})
	t.Run("with a config file", func(t *testing.T) {
		e, r := newRenderEnv(t, "26.10.21")
		e.rel.add(t, "26.3.27")
		body := `{"log":{}}`

		res, err := e.u.Update(bg, "26.3.27", UpdateOptions{ConfigFile: writeConfigFile(t, body)})
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantRenders(t, r)
		wantCandidate(t, e.runner, runnerapi.Candidate{
			Selection: runnerapi.Selection{Core: "26.3.27", Geo: "g1", Config: configRel(body)},
			Deadline:  t0.Add(120 * time.Second),
		})
	})
	t.Run("render error", func(t *testing.T) {
		e, r := newRenderEnv(t, "26.10.21")
		e.rel.add(t, "26.3.27")
		boom := errors.New("render: no server is enabled")
		r.err = boom

		res, err := e.u.Update(bg, "26.3.27", UpdateOptions{})
		wantOutcome(t, res, err, OutcomeRefused)
		if !errors.Is(err, boom) {
			t.Errorf("err = %v, want the render's error", err)
		}
		wantDetail(t, res, boom.Error())
		wantRenders(t, r, renderCall{mustVer(t, "26.3.27"), "g1"})
		wantActions(t, e.runner)
		wantNoCandidateFile(t, e)
		if hits := e.rel.hitList(); len(hits) != 0 {
			t.Errorf("upstream was asked for %v; a refused update fetches nothing", hits)
		}
		if got := e.slots(t); !reflect.DeepEqual(got, []string{"26.10.21"}) {
			t.Errorf("slots = %v", got)
		}
	})
	t.Run("no active core", func(t *testing.T) {
		e, r := newRenderEnv(t, "")
		e.rel.add(t, "26.10.21")

		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantRenders(t, r, renderCall{mustVer(t, "26.10.21"), ""})
		wantCandidate(t, e.runner, runnerapi.Candidate{
			Selection: runnerapi.Selection{Core: "26.10.21", Config: configRel(renderedBody)},
			Deadline:  t0.Add(120 * time.Second),
		})
	})
	t.Run("the active core with the active config", func(t *testing.T) {
		e, r := newRenderEnv(t, "26.10.21")
		r.body = activeConfigBody

		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
		wantOutcome(t, res, err, OutcomeNoop)
		wantRenders(t, r, renderCall{mustVer(t, "26.10.21"), "g1"})
		wantActions(t, e.runner)
	})
}

func TestRollbackRendersForTarget(t *testing.T) {
	setup := func(t *testing.T) (*coreEnv, *fakeRender) {
		e, r := newRenderEnv(t, "26.10.21")
		install(t, e.cores(), "26.3.27")
		e.writeHistory(t, committedResult("26.3.27", ""), committedResult("26.10.21", "26.3.27"))
		return e, r
	}
	t.Run("renders", func(t *testing.T) {
		e, r := setup(t)

		res, err := e.u.Rollback(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		if res.To != "26.3.27" {
			t.Errorf("To = %q, want 26.3.27", res.To)
		}
		wantRenders(t, r, renderCall{mustVer(t, "26.3.27"), "g1"})
		rel := configRel(renderedBody)
		wantCandidate(t, e.runner, runnerapi.Candidate{
			Selection: runnerapi.Selection{Core: "26.3.27", Geo: "g1", Config: rel},
			Deadline:  t0.Add(120 * time.Second),
		})
		if b, err := os.ReadFile(filepath.Join(e.data, "run", rel)); err != nil || string(b) != renderedBody {
			t.Errorf("%s = %q, %v; want the render", rel, b, err)
		}
	})
	t.Run("render error", func(t *testing.T) {
		e, r := setup(t)
		boom := errors.New("render: no server is enabled")
		r.err = boom

		res, err := e.u.Rollback(bg)
		wantOutcome(t, res, err, OutcomeRefused)
		if !errors.Is(err, boom) {
			t.Errorf("err = %v, want the render's error", err)
		}
		wantActions(t, e.runner)
		wantNoCandidateFile(t, e)
	})
	t.Run("no renderer keeps the active config", func(t *testing.T) {
		e, _ := setup(t)
		e.u.Render = nil

		res, err := e.u.Rollback(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantCandidate(t, e.runner, runnerapi.Candidate{
			Selection: runnerapi.Selection{Core: "26.3.27", Geo: "g1", Config: e.activeSel.Config},
			Deadline:  t0.Add(120 * time.Second),
		})
	})
}

// With NoState the render is that of a state nobody saved, which sends all
// traffic direct: it must not take the place of another config the runner
// runs, such as one an update ran with --config. A runner with no active
// selection takes it, as a fresh install does.
func TestNoStateKeepsTheActiveConfig(t *testing.T) {
	refused := func(t *testing.T, e *coreEnv, res Result, err error, hint string) {
		t.Helper()
		wantOutcome(t, res, err, OutcomeRefused)
		wantDetail(t, res, "no state has been saved, and the runner's active config is not the default state's render")
		wantDetail(t, res, hint)
		wantActions(t, e.runner)
		wantNoCandidateFile(t, e)
		if got := configFiles(t, e); !reflect.DeepEqual(got, []string{filepath.Base(e.activeSel.Config)}) {
			t.Errorf("run/config holds %v, want the active config alone", got)
		}
		if h := e.history(t); len(h) != 1 || h[0].Outcome != OutcomeRefused {
			t.Errorf("history = %+v, want the refusal", h)
		}
	}
	setup := func(t *testing.T) (*coreEnv, *fakeRender) {
		e, r := newRenderEnv(t, "26.10.21")
		e.u.NoState = true
		return e, r
	}

	t.Run("apply", func(t *testing.T) {
		e, _ := setup(t)
		res, err := e.u.Apply(bg)
		refused(t, e, res, err, "create a state")
		if res.Kind != KindConfig {
			t.Errorf("Kind = %q, want config", res.Kind)
		}
	})
	t.Run("update", func(t *testing.T) {
		e, _ := setup(t)
		e.rel.add(t, "26.3.27")
		res, err := e.u.Update(bg, "26.3.27", UpdateOptions{})
		refused(t, e, res, err, "--config FILE")
		if hits := e.rel.hitList(); len(hits) != 0 {
			t.Errorf("upstream was asked for %v; a refused update fetches nothing", hits)
		}
	})
	t.Run("update to the active core", func(t *testing.T) {
		e, _ := setup(t)
		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
		refused(t, e, res, err, "--config FILE")
	})
	t.Run("rollback", func(t *testing.T) {
		e, _ := setup(t)
		install(t, e.cores(), "26.3.27")
		e.writeHistory(t, committedResult("26.3.27", ""), committedResult("26.10.21", "26.3.27"))
		res, err := e.u.Rollback(bg)
		wantOutcome(t, res, err, OutcomeRefused)
		wantDetail(t, res, "no state has been saved")
		wantDetail(t, res, "create a state")
		wantActions(t, e.runner)
		wantNoCandidateFile(t, e)
	})

	t.Run("update with a config file", func(t *testing.T) {
		e, r := setup(t)
		body := `{"log":{}}`
		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{ConfigFile: writeConfigFile(t, body)})
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantRenders(t, r)
		if got := e.runner.activeSelection().Config; got != configRel(body) {
			t.Errorf("active config %s, want the file's %s", got, configRel(body))
		}
	})
	t.Run("the active config is the render", func(t *testing.T) {
		e, r := setup(t)
		r.body = activeConfigBody
		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, OutcomeNoop)
		e.rel.add(t, "26.3.27")
		res, err = e.u.Update(bg, "26.3.27", UpdateOptions{})
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		if got := e.runner.activeSelection(); got.Core != "26.3.27" || got.Config != e.activeSel.Config {
			t.Errorf("the runner is on %+v, want 26.3.27 with the config it had", got)
		}
	})
	t.Run("a fresh install", func(t *testing.T) {
		e, _ := newRenderEnv(t, "")
		e.u.NoState = true
		e.rel.add(t, "26.10.21")
		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		if got := e.runner.activeSelection().Config; got != configRel(renderedBody) {
			t.Errorf("active config %s, want the render %s", got, configRel(renderedBody))
		}
	})
}

// seedConfigs makes run/config hold n configs older than any a test commits:
// the runner's active one, an hour old, and others, each an hour older than
// the one before. It returns their names, newest first. Other files in
// run/config/ are left alone by pruning, so two of those are put there too,
// older than all.
func seedConfigs(t *testing.T, e *coreEnv, n int) []string {
	t.Helper()
	dir := filepath.Join(e.data, "run", "config")
	names := []string{filepath.Base(e.activeSel.Config)}
	for i := 2; i <= n; i++ {
		names = append(names, shaOf(fmt.Sprintf("old config %d", i))+".json")
		writeTestFile(t, filepath.Join(dir, names[i-1]), fmt.Sprintf("old config %d", i))
	}
	now := time.Now()
	for i, name := range names {
		age(t, filepath.Join(dir, name), now.Add(-time.Duration(i+1)*time.Hour))
	}
	for _, name := range []string{"notes.txt", "." + shaOf("x") + ".json.tmp-123"} {
		writeTestFile(t, filepath.Join(dir, name), "not a config")
		age(t, filepath.Join(dir, name), now.Add(-100*time.Hour))
	}
	return names
}

func age(t *testing.T, path string, mod time.Time) {
	t.Helper()
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
}

// wantConfigs fails unless run/config holds exactly the configs named, and the
// two files that are no config.
func wantConfigs(t *testing.T, e *coreEnv, names ...string) {
	t.Helper()
	want := append([]string{"notes.txt", "." + shaOf("x") + ".json.tmp-123"}, names...)
	slices.Sort(want)
	if got := configFiles(t, e); !reflect.DeepEqual(got, want) {
		t.Errorf("run/config holds\n%v\nwant\n%v", got, want)
	}
}

func TestPruneConfigs(t *testing.T) {
	t.Run("keeps the committed and the 4 newest others", func(t *testing.T) {
		e, _ := newRenderEnv(t, "26.10.21")
		old := seedConfigs(t, e, 7)

		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantConfigs(t, e, shaOf(renderedBody)+".json", old[0], old[1], old[2], old[3])
		if res.Detail != "" {
			t.Errorf("Detail = %q", res.Detail)
		}
	})
	t.Run("few enough are all kept", func(t *testing.T) {
		e, _ := newRenderEnv(t, "26.10.21")
		old := seedConfigs(t, e, 4)

		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantConfigs(t, e, append([]string{shaOf(renderedBody) + ".json"}, old...)...)
	})
	t.Run("an update prunes as well", func(t *testing.T) {
		e, _ := newRenderEnv(t, "26.10.21")
		e.rel.add(t, "26.12.1")
		old := seedConfigs(t, e, 7)

		res, err := e.u.Update(bg, "26.12.1", UpdateOptions{})
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantConfigs(t, e, shaOf(renderedBody)+".json", old[0], old[1], old[2], old[3])
	})
	t.Run("the committed config stays however old", func(t *testing.T) {
		// A rollback without a renderer commits the config that is active, which
		// is the oldest file here.
		e := newCoreEnv(t, "26.10.21")
		install(t, e.cores(), "26.3.27")
		e.writeHistory(t, committedResult("26.3.27", ""), committedResult("26.10.21", "26.3.27"))
		old := seedConfigs(t, e, 7)
		age(t, filepath.Join(e.data, "run", e.activeSel.Config), time.Now().Add(-1000*time.Hour))

		res, err := e.u.Rollback(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantConfigs(t, e, old[0], old[1], old[2], old[3], old[4])
	})
	t.Run("an open candidate's config stays", func(t *testing.T) {
		e, _ := newRenderEnv(t, "26.10.21")
		old := seedConfigs(t, e, 8)
		// Right after the commit another trial opens, on the oldest config.
		other := runnerapi.Candidate{
			Selection: runnerapi.Selection{Core: "26.10.21", Geo: "g1", Config: "config/" + old[7]},
			Deadline:  t0.Add(time.Minute),
		}
		e.runner.script(func(f *fakeRunner) {
			f.onCommit = func(w http.ResponseWriter) bool {
				f.end(runnerapi.OutcomeCommitted, "")
				f.st.State, f.st.Candidate = runnerapi.StateTrial, &other
				w.WriteHeader(http.StatusNoContent)
				return true
			}
		})

		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantConfigs(t, e, shaOf(renderedBody)+".json", old[0], old[1], old[2], old[3], old[7])
	})
	t.Run("a failure is noted and the commit stands", func(t *testing.T) {
		e, _ := newRenderEnv(t, "26.10.21")
		old := seedConfigs(t, e, 7)
		// Once the commit is through, the runner cannot be asked what it runs, so
		// nothing can be removed safely.
		e.u.Runner.HTTP = &http.Client{Transport: &statusDownAfterCommit{base: e.runner.srv.Client().Transport}}

		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantDetail(t, res, "old configs were not pruned")
		wantDetail(t, res, "connection refused")
		wantConfigs(t, e, append([]string{shaOf(renderedBody) + ".json"}, old...)...)
		if got := e.runner.activeCore(); got != "26.10.21" {
			t.Errorf("runner's active core = %q", got)
		}
		if h := e.history(t); len(h) != 1 || h[0].Outcome != runnerapi.OutcomeCommitted || !strings.Contains(h[0].Detail, "old configs were not pruned") {
			t.Errorf("history = %+v, want the committed result with the note", h)
		}
	})
	t.Run("notes join", func(t *testing.T) {
		res := Result{Detail: "pruning old cores: boom"}
		note(&res, "old configs were not pruned: bust")
		if want := "pruning old cores: boom; old configs were not pruned: bust"; res.Detail != want {
			t.Errorf("Detail = %q, want %q", res.Detail, want)
		}
		res = Result{}
		note(&res, "first")
		if res.Detail != "first" {
			t.Errorf("Detail = %q", res.Detail)
		}
	})
}

// statusDownAfterCommit fails the status calls that follow a commit.
type statusDownAfterCommit struct {
	base      http.RoundTripper
	committed atomic.Bool
}

func (s *statusDownAfterCommit) RoundTrip(r *http.Request) (*http.Response, error) {
	if s.committed.Load() && strings.HasSuffix(r.URL.Path, "/v1/status") {
		return nil, errors.New("connection refused")
	}
	resp, err := s.base.RoundTrip(r)
	if err == nil && strings.HasSuffix(r.URL.Path, "/v1/commit") {
		s.committed.Store(true)
	}
	return resp, err
}
