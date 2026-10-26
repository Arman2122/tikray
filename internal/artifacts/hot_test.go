package artifacts

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

// apiAddr is the address of xray's API that the hot tests' updater names.
const apiAddr = "127.0.0.1:10085"

// vlessTo is a VLESS Reality outbound to addr, as sharelink builds one.
func vlessTo(addr string) json.RawMessage {
	return json.RawMessage(`{"protocol":"vless","settings":{"vnext":[{"address":"` + addr + `","port":443,"users":[{"encryption":"none","flow":"xtls-rprx-vision","id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},"streamSettings":{"network":"tcp","realitySettings":{"fingerprint":"chrome","publicKey":"SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc","serverName":"www.example.com","shortId":"6ba85179e30d4fc2"},"security":"reality"}}`)
}

// The servers of the hot tests: a and b, and a2, which is a moved to another
// address.
var (
	srvA  = store.Server{ID: "aaaaaaaa", Name: "a", Outbound: vlessTo("203.0.113.10")}
	srvA2 = store.Server{ID: "aaaaaaaa", Name: "a", Outbound: vlessTo("203.0.113.20")}
	srvB  = store.Server{ID: "bbbbbbbb", Name: "b", Outbound: vlessTo("198.51.100.7")}
)

// Their outbounds' tags.
const (
	tagA = "srv-aaaaaaaa"
	tagB = "srv-bbbbbbbb"
)

// withServers is the default state with the default policy smart and servers.
func withServers(servers ...store.Server) store.State {
	st := store.Default()
	st.DefaultPolicy = store.Policy{Mode: store.ModeSmart}
	st.Servers = append([]store.Server{}, servers...)
	return st
}

// rendered is the config that render makes of st for 26.10.21, with no geo.
func rendered(t *testing.T, st store.State) string {
	t.Helper()
	b, err := render.Render(render.Input{State: st, Core: mustVer(t, "26.10.21")})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// newHotEnv is newRenderEnv where the runner runs the config active, its xray
// with active's outbounds, and the updater renders candidate and tries a hot
// change first.
func newHotEnv(t *testing.T, active, candidate string) (*coreEnv, *fakeRender) {
	t.Helper()
	e, r := newRenderEnv(t, "26.10.21")
	if err := os.Remove(filepath.Join(e.data, "run", e.activeSel.Config)); err != nil {
		t.Fatal(err)
	}
	e.activeSel.Config = configRel(active)
	writeTestFile(t, filepath.Join(e.data, "run", e.activeSel.Config), active)
	sel := e.activeSel
	e.runner.script(func(f *fakeRunner) {
		f.st.Active = &sel
		f.live = configTags(t, active)
	})
	r.body = candidate
	e.u.Hot, e.u.XrayAPIServer, e.u.RunnerRun = true, apiAddr, filepath.Join(e.data, "run")
	return e, r
}

// fakeState is what the tests read of the fake runner at once.
type fakeState struct {
	tested    [][]byte
	apiArgs   [][]string
	adoFiles  []adoFile
	adopted   []string
	live      []string
	pendingAt []string
}

func (f *fakeRunner) state() fakeState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeState{
		tested:    slices.Clone(f.tested),
		apiArgs:   slices.Clone(f.apiArgs),
		adoFiles:  slices.Clone(f.adoFiles),
		adopted:   slices.Clone(f.adopted),
		live:      slices.Clone(f.live),
		pendingAt: slices.Clone(f.pendingAt),
	}
}

// pendingFile is the marker of a hot change that did not end in a known
// state.
func pendingFile(e *coreEnv) string { return filepath.Join(e.data, "run", "hot", "pending") }

// leavePending puts the marker in place as a hot change towards the config
// named rel leaves it when tikray dies before the change ends.
func leavePending(t *testing.T, e *coreEnv, rel string) {
	t.Helper()
	writeTestFile(t, pendingFile(e), rel+"\n")
}

// wantPending fails unless the marker is there exactly when want is, as
// HotPending tells.
func wantPending(t *testing.T, e *coreEnv, want bool) {
	t.Helper()
	if got := HotPending(e.data); got != want {
		t.Errorf("HotPending = %v, want %v", got, want)
	}
}

// failingRoute is a transport that fails every request for a path ending in
// path, as a broken connection does, and passes the others to base.
type failingRoute struct {
	base http.RoundTripper
	path string
}

func (f failingRoute) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, f.path) {
		return nil, errors.New("connection reset by peer")
	}
	return f.base.RoundTrip(r)
}

// statusFailsAfterAdopt is a transport that fails the status call that
// follows an adopt, once.
type statusFailsAfterAdopt struct {
	base    http.RoundTripper
	mu      sync.Mutex
	adopted bool
}

func (s *statusFailsAfterAdopt) RoundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	fail := s.adopted && strings.HasSuffix(r.URL.Path, "/v1/status")
	if fail {
		s.adopted = false
	}
	s.mu.Unlock()
	if fail {
		return nil, errors.New("connection refused")
	}
	resp, err := s.base.RoundTrip(r)
	if err == nil && strings.HasSuffix(r.URL.Path, "/v1/adopt") {
		s.mu.Lock()
		s.adopted = true
		s.mu.Unlock()
	}
	return resp, err
}

// failAdo makes the fake's ado fail with xray's message boom, while the other
// xray api calls work.
func failAdo(f *fakeRunner) {
	f.onXrayAPI = func(w http.ResponseWriter, args []string) {
		if args[0] == "ado" {
			writeJSONReply(w, http.StatusOK, runnerapi.XrayAPIResponse{ExitCode: 1, Stderr: "boom\n"})
			return
		}
		writeJSONReply(w, http.StatusOK, f.liveAPI(args))
	}
}

// wantLive fails unless the fake's xray runs the outbounds of config, in any
// order: a hot change adds at the end.
func wantLive(t *testing.T, e *coreEnv, config string) {
	t.Helper()
	got, want := e.runner.state().live, configTags(t, config)
	slices.Sort(got)
	slices.Sort(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("xray runs the outbounds %v, want %v", got, want)
	}
}

// wantHotDirEmpty fails unless run/hot/ holds nothing, if it is there.
func wantHotDirEmpty(t *testing.T, e *coreEnv) {
	t.Helper()
	dir := filepath.Join(e.data, "run", "hot")
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return
	}
	if got := dirNames(t, dir); len(got) != 0 {
		t.Errorf("run/hot holds %v, want nothing", got)
	}
}

func TestHotPlan(t *testing.T) {
	one, two := withServers(srvA), withServers(srvA, srvB)
	disabled := withServers(srvA, srvB)
	disabled.Servers[1].Disabled = true
	rule := withServers(srvA)
	rule.Routing.Rules = []store.Rule{{Domains: []string{"domain:example.com"}, Action: store.ActionDirect}}
	dns := withServers(srvA)
	dns.DNS.Remote = "9.9.9.9"
	pin := withServers(srvA, srvB)
	pin.Routing.Pinned = srvB.ID
	device := withServers(srvA)
	device.Devices = []store.Device{{Address: netip.MustParsePrefix("192.168.88.10/32"), Policy: store.Policy{Mode: store.ModeFull}}}

	// Hand-written configs, for what render never makes.
	cfg := func(outbounds ...string) string {
		return `{"log":{"loglevel":"warning"},"outbounds":[` + strings.Join(outbounds, ",") + `],"routing":{"rules":[]}}`
	}
	const (
		block   = `{"tag":"block","protocol":"blackhole"}`
		direct  = `{"tag":"direct","protocol":"freedom"}`
		direct2 = `{"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"UseIP"}}`
		sa      = `{"tag":"srv-a","protocol":"vless","settings":{"address":"a"}}`
		sa2     = `{"tag":"srv-a","protocol":"vless","settings":{"address":"a2"}}`
		sb      = `{"tag":"srv-b","protocol":"vless","settings":{"address":"b"}}`
	)

	for _, tc := range []struct {
		name              string
		active, candidate string
		hot               bool
		remove, add       []string // the tags of the outbounds removed and added
		added, removed    int
		changed           int
	}{
		{name: "add", active: rendered(t, one), candidate: rendered(t, two), hot: true, add: []string{tagB}, added: 1},
		{name: "remove", active: rendered(t, two), candidate: rendered(t, one), hot: true, remove: []string{tagB}, removed: 1},
		{name: "disable", active: rendered(t, two), candidate: rendered(t, disabled), hot: true, remove: []string{tagB}, removed: 1},
		{name: "change", active: rendered(t, one), candidate: rendered(t, withServers(srvA2)), hot: true, remove: []string{tagA}, add: []string{tagA}, changed: 1},
		{name: "change one, add one", active: rendered(t, one), candidate: rendered(t, withServers(srvA2, srvB)), hot: true,
			remove: []string{tagA}, add: []string{tagA, tagB}, added: 1, changed: 1},
		{name: "a rules change", active: rendered(t, one), candidate: rendered(t, rule)},
		{name: "a DNS change", active: rendered(t, one), candidate: rendered(t, dns)},
		{name: "a device's policy", active: rendered(t, one), candidate: rendered(t, device)},
		{name: "a pin", active: rendered(t, two), candidate: rendered(t, pin)},
		// The balancers, the observatory and the rules that use them are there
		// only while some server is.
		{name: "zero servers to one", active: rendered(t, withServers()), candidate: rendered(t, one)},
		{name: "one server to zero", active: rendered(t, one), candidate: rendered(t, withServers())},

		{name: "a reordered outbound that is not a server's", active: cfg(block, direct, sa), candidate: cfg(direct, block, sa)},
		{name: "a changed outbound that is not a server's", active: cfg(block, direct, sa), candidate: cfg(block, direct2, sa)},
		{name: "an added outbound that is not a server's", active: cfg(block, sa), candidate: cfg(block, direct, sa)},
		{name: "a removed outbound that is not a server's", active: cfg(block, direct, sa), candidate: cfg(block, sa)},
		{name: "an outbound without a tag", active: cfg(block, sa), candidate: cfg(block, sa, `{"protocol":"freedom"}`)},
		{name: "an outbound with an empty tag", active: cfg(block, sa), candidate: cfg(block, sa, `{"tag":"","protocol":"freedom"}`)},
		{name: "a tag twice", active: cfg(block, sa), candidate: cfg(block, sa, sa2)},
		// xray's first outbound is its default, which xray api does not move.
		{name: "a server's outbound first", active: cfg(sa, block), candidate: cfg(sa, block, sb)},
		{name: "a top-level key added", active: cfg(block, sa), candidate: strings.TrimSuffix(cfg(block, sa), "}") + `,"stats":{}}`},
		{name: "no outbounds", active: `{"log":{"loglevel":"warning"},"routing":{"rules":[]}}`, candidate: cfg(block)},
		{name: "not JSON", active: cfg(block, sa), candidate: `{"outbounds":[`},
		{name: "not an object", active: cfg(block, sa), candidate: `[]`},

		{name: "the same config written another way", hot: true, active: cfg(block, sa),
			candidate: "{\n  \"routing\": {\"rules\": []},\n  \"outbounds\": [{\"protocol\": \"blackhole\", \"tag\": \"block\"}, {\"settings\": {\"address\": \"a\"}, \"tag\": \"srv-a\", \"protocol\": \"vless\"}],\n  \"log\": {\"loglevel\": \"warning\"}\n}\n"},
		{name: "servers reordered", active: cfg(block, sa, sb), candidate: cfg(block, sb, sa), hot: true},
		{name: "a server added before another", active: cfg(block, sb), candidate: cfg(block, sa, sb), hot: true, add: []string{"srv-a"}, added: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := hotPlan([]byte(tc.active), []byte(tc.candidate))
			if ok != tc.hot {
				t.Fatalf("hotPlan qualifies: %v, want %v (plan %+v)", ok, tc.hot, p)
			}
			if !ok {
				return
			}
			if !reflect.DeepEqual(p.remove, tc.remove) {
				t.Errorf("remove = %q, want %q", p.remove, tc.remove)
			}
			var added []string
			for _, raw := range p.add {
				var o struct {
					Tag string `json:"tag"`
				}
				if err := json.Unmarshal(raw, &o); err != nil {
					t.Fatalf("an added outbound is not an object: %v", err)
				}
				added = append(added, o.Tag)
			}
			if !reflect.DeepEqual(added, tc.add) {
				t.Errorf("add = %q, want %q", added, tc.add)
			}
			if p.added != tc.added || p.removed != tc.removed || p.changed != tc.changed {
				t.Errorf("added %d, removed %d, changed %d; want %d, %d, %d", p.added, p.removed, p.changed, tc.added, tc.removed, tc.changed)
			}
		})
	}

	// What is added is the candidate's outbound itself.
	p, ok := hotPlan([]byte(rendered(t, one)), []byte(rendered(t, withServers(srvA2))))
	if !ok || len(p.add) != 1 || !bytes.Contains(p.add[0], []byte("203.0.113.20")) {
		t.Errorf("plan %+v (%v), want server a's new outbound added", p, ok)
	}
}

// A change to the servers alone goes live through xray api, in order, with no
// trial: test, baseline, rmo, ado, probe, adopt. The config is then the active
// one, and pruned around as after a committed trial.
func TestHotApply(t *testing.T) {
	active, candidate := rendered(t, withServers(srvA)), rendered(t, withServers(srvA2, srvB))
	e, _ := newHotEnv(t, active, candidate)
	p := newProxyProbe(e, func(int) error { return nil })
	old := seedConfigs(t, e, 7)
	hot := filepath.Join(e.data, "run", "hot")
	// What a run killed in the middle of a hot change left behind.
	writeTestFile(t, filepath.Join(hot, shaOf("left")+".json"), `{"outbounds":[]}`)
	writeTestFile(t, filepath.Join(hot, "."+shaOf("left")+".json.tmp-1"), `{"outbounds":[]}`)

	res, err := e.u.Apply(bg)
	wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
	want := Result{From: "26.10.21", To: "26.10.21", Outcome: "committed", Kind: "config", Hot: true,
		Detail: "applied without restarting xray: added 1, removed 0, changed 1", At: t0}
	wantResult(t, res, want)

	wantActions(t, e.runner, "test", "xray-api", "xray-api", "adopt")
	if at := p.calls(); !reflect.DeepEqual(at, []int{1, 3}) {
		t.Errorf("the probe saw %v runner actions before each call, want [1 3]: the baseline after the test, the probe after the rmo and the ado", at)
	}
	fs := e.runner.state()
	if len(fs.tested) != 1 || string(fs.tested[0]) != candidate {
		t.Errorf("the runner tested %d configs, want the candidate alone", len(fs.tested))
	}
	if len(fs.adoFiles) != 1 {
		t.Fatalf("ado read %d files, want 1", len(fs.adoFiles))
	}
	file := fs.adoFiles[0]
	name := filepath.Base(file.path)
	wantArgs := [][]string{
		{"rmo", "--server=" + apiAddr, tagA},
		{"ado", "--server=" + apiAddr, filepath.Join(e.data, "run", "hot", name)},
	}
	if !reflect.DeepEqual(fs.apiArgs, wantArgs) {
		t.Errorf("xray api calls = %q, want %q", fs.apiArgs, wantArgs)
	}
	if name != shaOf(file.body)+".json" {
		t.Errorf("the file ado read is %s, want it named by its SHA-256", name)
	}
	if file.mode != 0o600 || file.dirMode != 0o700 {
		t.Errorf("the file ado read had mode %v in a directory of mode %v, want 0600 in 0700", file.mode, file.dirMode)
	}
	if got := configTags(t, file.body); !reflect.DeepEqual(got, []string{tagA, tagB}) || !strings.Contains(file.body, "203.0.113.20") {
		t.Errorf("the file ado read adds %v, want the new a and b", got)
	}
	rel := configRel(candidate)
	// While xray api changes xray, the marker names the candidate, so that a
	// tikray that dies meanwhile heals at the next apply; the end leaves none.
	if want := []string{rel + "\n", rel + "\n"}; !reflect.DeepEqual(fs.pendingAt, want) {
		t.Errorf("run/hot/pending held %q at the xray api calls, want %q", fs.pendingAt, want)
	}
	wantPending(t, e, false)
	if !reflect.DeepEqual(fs.adopted, []string{rel}) {
		t.Errorf("adopted %q, want %q", fs.adopted, rel)
	}
	if sel := e.runner.activeSelection(); sel != (runnerapi.Selection{Core: "26.10.21", Geo: "g1", Config: rel}) {
		t.Errorf("the runner's active selection = %+v, want the candidate", sel)
	}
	wantLive(t, e, candidate)
	wantNoCandidateFile(t, e)

	// The file ado read is gone, and so is what was left behind.
	wantHotDirEmpty(t, e)
	if fi, err := os.Stat(hot); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("run/hot: %v, %v; want mode 0700", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(e.data, "run", rel)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("%s: %v, %v; want mode 0600", rel, fi, err)
	}

	lines := historyLines(t, e)
	if len(lines) != 1 || !strings.Contains(lines[0], `"hot":true`) || !strings.Contains(lines[0], `"kind":"config"`) {
		t.Fatalf("history = %q, want one line of a config, hot", lines)
	}
	wantResult(t, e.history(t)[0], want)
	wantConfigs(t, e, shaOf(candidate)+".json", old[0], old[1], old[2], old[3])
}

// A hot change takes the baseline as a trial does: without the proxy on the
// active config, or without a probe, the change is not asked to carry
// traffic. A change that only removes writes no file.
func TestHotApplyProbes(t *testing.T) {
	t.Run("the baseline fails", func(t *testing.T) {
		e, _ := newHotEnv(t, rendered(t, withServers(srvA)), rendered(t, withServers(srvA, srvB)))
		p := newProxyProbe(e, failingProxy)

		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		if want := "applied without restarting xray: added 1, removed 0, changed 0; " + baselineNote; res.Detail != want || !res.Hot {
			t.Errorf("Result = %+v, want hot with Detail %q", res, want)
		}
		if at := p.calls(); !reflect.DeepEqual(at, []int{1}) {
			t.Errorf("the probe saw %v runner actions before each call, want the baseline alone", at)
		}
		wantActions(t, e.runner, "test", "xray-api", "adopt")
	})
	t.Run("no proxy probe", func(t *testing.T) {
		two := rendered(t, withServers(srvA, srvB))
		e, _ := newHotEnv(t, two, rendered(t, withServers(srvB)))

		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		if want := "applied without restarting xray: added 0, removed 1, changed 0"; res.Detail != want || !res.Hot {
			t.Errorf("Result = %+v, want hot with Detail %q", res, want)
		}
		wantActions(t, e.runner, "test", "xray-api", "adopt")
		if fs := e.runner.state(); !reflect.DeepEqual(fs.apiArgs, [][]string{{"rmo", "--server=" + apiAddr, tagA}}) || len(fs.adoFiles) != 0 {
			t.Errorf("xray api calls = %q, files %d; want the rmo alone", fs.apiArgs, len(fs.adoFiles))
		}
		wantLive(t, e, rendered(t, withServers(srvB)))
	})
}

// failsUntilTrial is a proxy probe that passes its first call, the baseline,
// then fails until a trial has opened.
func failsUntilTrial(e *coreEnv) func(call int) error {
	return func(call int) error {
		if call == 1 || slices.Contains(e.runner.actions(), "trial") {
			return nil
		}
		return errors.New("socks probe: connection refused")
	}
}

// A hot change that fails half way falls back to a trial of the same
// candidate, which restarts xray from it: the partial change is gone.
func TestHotFallsBackToTrial(t *testing.T) {
	active, candidate := rendered(t, withServers(srvA)), rendered(t, withServers(srvA2, srvB))
	for _, tc := range []struct {
		name    string
		script  func(e *coreEnv)
		why     string
		actions []string // before the trial
	}{
		{
			name: "ado fails after an rmo",
			script: func(e *coreEnv) {
				e.runner.script(func(f *fakeRunner) {
					f.onXrayAPI = func(w http.ResponseWriter, args []string) {
						if args[0] == "ado" {
							writeJSONReply(w, http.StatusOK, runnerapi.XrayAPIResponse{ExitCode: 1, Stderr: "failed to build outbound: boom\n"})
							return
						}
						writeJSONReply(w, http.StatusOK, f.liveAPI(args))
					}
				})
			},
			why:     "exit status 1: failed to build outbound: boom",
			actions: []string{"test", "xray-api", "xray-api"},
		},
		{
			name:    "the probe fails after the change",
			script:  func(e *coreEnv) { newProxyProbe(e, failsUntilTrial(e)) },
			why:     "socks probe: connection refused",
			actions: []string{"test", "xray-api", "xray-api"},
		},
		{
			name: "adopt is busy",
			script: func(e *coreEnv) {
				e.runner.script(func(f *fakeRunner) {
					f.onAdopt = func(w http.ResponseWriter, config string) bool {
						fakeError(w, http.StatusConflict, "busy", "xray is restarting")
						return true
					}
				})
			},
			why:     "runner is busy: xray is restarting",
			actions: []string{"test", "xray-api", "xray-api", "adopt"},
		},
		{
			// xray died and the runner started it again from the active config,
			// so it lacks the change that went before.
			name: "xray restarted during the change",
			script: func(e *coreEnv) {
				e.runner.script(func(f *fakeRunner) {
					f.onAdopt = func(w http.ResponseWriter, config string) bool {
						f.st.XrayPID = 99
						f.restartLive(f.st.Active.Config)
						return false
					}
				})
			},
			why:     "xray restarted",
			actions: []string{"test", "xray-api", "xray-api", "adopt"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newHotEnv(t, active, candidate)
			tc.script(e)

			res, err := e.u.Apply(bg)
			wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
			if res.Hot {
				t.Error("Result.Hot is set for a trial")
			}
			if !strings.HasPrefix(res.Detail, "the hot change failed (") || !strings.HasSuffix(res.Detail, "), so a trial was tried") {
				t.Errorf("Detail = %q, want the note that the hot change failed", res.Detail)
			}
			wantDetail(t, res, tc.why)
			wantActions(t, e.runner, append(tc.actions, "trial", "commit")...)
			wantCandidate(t, e.runner, runnerapi.Candidate{
				Selection: runnerapi.Selection{Core: "26.10.21", Geo: "g1", Config: configRel(candidate)},
				Deadline:  t0.Add(120 * time.Second),
			})
			if sel := e.runner.activeSelection(); sel.Config != configRel(candidate) {
				t.Errorf("the runner's active config = %s, want the candidate", sel.Config)
			}
			wantLive(t, e, candidate)
			wantHotDirEmpty(t, e)
			if h := e.history(t); len(h) != 1 || h[0].Hot || !strings.HasPrefix(h[0].Detail, "the hot change failed (") {
				t.Errorf("history = %+v, want the trial's line with the note", h)
			}
		})
	}
}

// When the trial that a failed hot change falls back to never restarted xray
// (its PID is the last one the hot change saw), whatever outcome the trial
// reports, xray is restarted from the active config: it must not keep half of
// the change. The marker goes once xray is known to run the active config.
func TestHotFallbackRestoresXray(t *testing.T) {
	active, candidate := rendered(t, withServers(srvA)), rendered(t, withServers(srvA2, srvB))
	refuseTrials := func(f *fakeRunner) {
		f.onTrial = func(w http.ResponseWriter, c runnerapi.Candidate) bool {
			fakeError(w, http.StatusInternalServerError, "internal", "disk full")
			return true
		}
	}
	t.Run("a changed xray is restarted", func(t *testing.T) {
		e, _ := newHotEnv(t, active, candidate)
		e.runner.script(func(f *fakeRunner) {
			refuseTrials(f)
			failAdo(f)
		})

		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, OutcomeRefused)
		wantDetail(t, res, "the hot change failed (")
		wantDetail(t, res, "), so a trial was tried: ")
		wantDetail(t, res, "disk full")
		wantDetail(t, res, "xray was restarted from the active config")
		wantActions(t, e.runner, "test", "xray-api", "xray-api", "trial", "restart")
		wantLive(t, e, active)
		if sel := e.runner.activeSelection(); sel != e.activeSel {
			t.Errorf("the runner's active selection = %+v, want %+v", sel, e.activeSel)
		}
		wantPending(t, e, false)
	})
	t.Run("a trial rejected by xray run -test", func(t *testing.T) {
		e, _ := newHotEnv(t, active, candidate)
		e.runner.script(func(f *fakeRunner) {
			failAdo(f)
			f.onTrial = func(w http.ResponseWriter, c runnerapi.Candidate) bool {
				fakeError(w, http.StatusUnprocessableEntity, "test_failed", "Failed to start: out of memory")
				return true
			}
		})

		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeRejected)
		wantDetail(t, res, "), so a trial was tried: Failed to start: out of memory")
		wantDetail(t, res, "xray was restarted from the active config")
		wantActions(t, e.runner, "test", "xray-api", "xray-api", "trial", "restart")
		wantLive(t, e, active)
		wantPending(t, e, false)
	})
	t.Run("the status after the adopt fails", func(t *testing.T) {
		// The adopt took, but no xray was seen after it: whatever the trial
		// did, xray is restarted from the active config, now the candidate.
		e, _ := newHotEnv(t, active, candidate)
		e.u.Runner.HTTP = &http.Client{Transport: &statusFailsAfterAdopt{base: e.runner.srv.Client().Transport}}

		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantDetail(t, res, "the hot change failed (checking on xray after the adopt: ")
		wantDetail(t, res, "xray was restarted from the active config")
		wantActions(t, e.runner, "test", "xray-api", "xray-api", "adopt", "trial", "commit", "restart")
		wantCandidate(t, e.runner, runnerapi.Candidate{
			Selection: runnerapi.Selection{Core: "26.10.21", Geo: "g1", Config: configRel(candidate)},
			Deadline:  t0.Add(120 * time.Second),
		})
		wantLive(t, e, candidate)
		wantPending(t, e, false)
	})
	t.Run("xray restarted before the adopt, and the trial never reached the runner", func(t *testing.T) {
		// The double fault: the runner started xray again from the old config
		// between the ado and the adopt, so the PID check fails; the adopt
		// made the candidate the active config, and the trial is lost on the
		// way. The runner's record says committed, as the candidate is
		// active, but nothing restarted xray since the hot change last saw
		// it: it runs the old outbounds, and is restarted.
		e, _ := newHotEnv(t, active, candidate)
		e.runner.script(func(f *fakeRunner) {
			f.onAdopt = func(w http.ResponseWriter, config string) bool {
				f.st.XrayPID = 99
				f.restartLive(f.st.Active.Config)
				return false
			}
		})
		e.u.Runner.HTTP = &http.Client{Transport: failingRoute{base: e.runner.srv.Client().Transport, path: "/v1/trial"}}

		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantDetail(t, res, "the hot change failed (xray restarted during the change")
		wantDetail(t, res, "xray was restarted from the active config")
		wantActions(t, e.runner, "test", "xray-api", "xray-api", "adopt", "restart")
		if sel := e.runner.activeSelection(); sel.Config != configRel(candidate) {
			t.Errorf("the runner's active config = %s, want the candidate", sel.Config)
		}
		wantLive(t, e, candidate)
		wantPending(t, e, false)
	})
	t.Run("the restart fails", func(t *testing.T) {
		e, _ := newHotEnv(t, active, candidate)
		newProxyProbe(e, failsUntilTrial(e))
		e.runner.script(func(f *fakeRunner) {
			refuseTrials(f)
			f.onRestart = func(w http.ResponseWriter) bool {
				fakeError(w, http.StatusInternalServerError, "internal", "no xray binary")
				return true
			}
		})

		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, OutcomeRefused)
		wantDetail(t, res, "restarting xray from the active config failed")
		wantDetail(t, res, "no xray binary")
		// xray may still run the change: the next apply must heal it.
		wantPending(t, e, true)
		if b, err := os.ReadFile(pendingFile(e)); err != nil || string(b) != configRel(candidate)+"\n" {
			t.Errorf("run/hot/pending = %q, %v; want the candidate's name", b, err)
		}
		if fi, err := os.Stat(pendingFile(e)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("run/hot/pending: %v, %v; want mode 0600", fi, err)
		}
	})
	t.Run("an xray that was not changed is not restarted", func(t *testing.T) {
		e, _ := newHotEnv(t, active, candidate)
		e.runner.script(func(f *fakeRunner) {
			refuseTrials(f)
			f.onTest = func(w http.ResponseWriter, config []byte) bool {
				fakeError(w, http.StatusInternalServerError, "internal", "test broke")
				return true
			}
		})

		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, OutcomeRefused)
		wantDetail(t, res, "the hot change failed (")
		wantDetail(t, res, "test broke")
		wantActions(t, e.runner, "test", "trial")
		wantLive(t, e, active)
	})
}

// A candidate that xray run -test rejects is rejected as a trial would reject
// it, and nothing reaches xray: no baseline, no xray api, no adopt.
func TestHotRejectedTouchesNothing(t *testing.T) {
	active := rendered(t, withServers(srvA))
	e, _ := newHotEnv(t, active, rendered(t, withServers(srvA2, srvB)))
	p := newProxyProbe(e, func(int) error { return nil })
	e.runner.script(func(f *fakeRunner) {
		f.onTest = func(w http.ResponseWriter, config []byte) bool {
			writeJSONReply(w, http.StatusOK, runnerapi.TestResult{OK: false, Output: "Failed to start: unknown user"})
			return true
		}
	})

	res, err := e.u.Apply(bg)
	wantOutcome(t, res, err, runnerapi.OutcomeRejected)
	wantResult(t, res, Result{From: "26.10.21", To: "26.10.21", Outcome: "rejected", Kind: "config", Detail: "Failed to start: unknown user", At: t0})
	var tf *runnerapi.TestFailedError
	if !errors.As(err, &tf) {
		t.Errorf("err = %v, want a *TestFailedError, as a trial's rejection has", err)
	}
	wantActions(t, e.runner, "test")
	if at := p.calls(); len(at) != 0 {
		t.Errorf("the probe ran %d times", len(at))
	}
	if fs := e.runner.state(); len(fs.apiArgs) != 0 || len(fs.adopted) != 0 || !reflect.DeepEqual(fs.live, configTags(t, active)) {
		t.Errorf("xray api calls %q, adopted %q, xray runs %v; want nothing touched", fs.apiArgs, fs.adopted, fs.live)
	}
	if sel := e.runner.activeSelection(); sel != e.activeSel {
		t.Errorf("the runner's active selection = %+v, want %+v", sel, e.activeSel)
	}
	wantNoCandidateFile(t, e)
	wantHotDirEmpty(t, e)
	if h := e.history(t); len(h) != 1 || h[0].Outcome != runnerapi.OutcomeRejected || h[0].Kind != KindConfig {
		t.Errorf("history = %+v", h)
	}
}

// A tikray that died between the hot calls and the adopt left xray with the
// change while the active config is the old one. The next apply's hot change
// fails on what xray has already, and the trial heals it.
func TestHotInterruptedHeals(t *testing.T) {
	for _, tc := range []struct {
		name              string
		active, candidate store.State
		live              store.State // what xray runs: the change, or part of it
		why               string
	}{
		{"the ado went through", withServers(srvA), withServers(srvA, srvB), withServers(srvA, srvB), "existing tag found: " + tagB},
		{"the rmo went through", withServers(srvA), withServers(srvA2), withServers(), "failed to remove outbound " + tagA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := rendered(t, tc.candidate)
			e, _ := newHotEnv(t, rendered(t, tc.active), candidate)
			live := configTags(t, rendered(t, tc.live))
			e.runner.script(func(f *fakeRunner) { f.live = live })

			res, err := e.u.Apply(bg)
			wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
			wantDetail(t, res, "the hot change failed (")
			wantDetail(t, res, tc.why)
			if res.Hot {
				t.Error("Result.Hot is set for a trial")
			}
			wantCandidate(t, e.runner, runnerapi.Candidate{
				Selection: runnerapi.Selection{Core: "26.10.21", Geo: "g1", Config: configRel(candidate)},
				Deadline:  t0.Add(120 * time.Second),
			})
			wantLive(t, e, candidate)
		})
	}
}

// Anything but a change to the servers' outbounds goes to the trial, without
// a word about hot changes; so does any apply while the runner is not plainly
// running the active core, or its config can't be read.
func TestHotOnlyForServerOutbounds(t *testing.T) {
	one := withServers(srvA)
	device := withServers(srvA)
	device.Devices = []store.Device{{Address: netip.MustParsePrefix("192.168.88.10/32"), Policy: store.Policy{Mode: store.ModeFull}}}
	rule := withServers(srvA)
	rule.Routing.Rules = []store.Rule{{Domains: []string{"domain:example.com"}, Action: store.ActionServer, Server: srvA.ID}}
	dns := withServers(srvA)
	dns.DNS.Remote = "9.9.9.9"
	pin := withServers(srvA, srvB)
	pin.Routing.Pinned = srvB.ID

	for _, tc := range []struct {
		name              string
		active, candidate store.State
		script            func(t *testing.T, e *coreEnv)
	}{
		{name: "a device's policy", active: one, candidate: device},
		{name: "a rule", active: one, candidate: rule},
		{name: "DNS", active: one, candidate: dns},
		{name: "a pin", active: withServers(srvA, srvB), candidate: pin},
		{name: "the first server", active: withServers(), candidate: one},
		{name: "the last server", active: one, candidate: withServers()},
		{name: "the runner is restarting", active: one, candidate: withServers(srvA, srvB), script: func(t *testing.T, e *coreEnv) {
			e.runner.script(func(f *fakeRunner) { f.st.State = runnerapi.StateRestarting })
		}},
		{name: "xray runs another core", active: one, candidate: withServers(srvA, srvB), script: func(t *testing.T, e *coreEnv) {
			e.runner.script(func(f *fakeRunner) { f.st.XrayVersion = fakeXrayVersion("26.3.27") })
		}},
		{name: "the active config can't be read", active: one, candidate: withServers(srvA, srvB), script: func(t *testing.T, e *coreEnv) {
			if err := os.Remove(filepath.Join(e.data, "run", e.activeSel.Config)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "the active config's name is no config's", active: one, candidate: withServers(srvA, srvB), script: func(t *testing.T, e *coreEnv) {
			// A file that is there, but outside run/config/.
			writeTestFile(t, filepath.Join(e.data, "run", "odd.json"), rendered(t, one))
			e.runner.script(func(f *fakeRunner) { f.st.Active.Config = "config/../odd.json" })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newHotEnv(t, rendered(t, tc.active), rendered(t, tc.candidate))
			if tc.script != nil {
				tc.script(t, e)
			}

			res, err := e.u.Apply(bg)
			wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
			if res.Hot || res.Detail != "" {
				t.Errorf("Result = %+v, want a trial's, with no note", res)
			}
			wantActions(t, e.runner, "trial", "commit")
			if fs := e.runner.state(); len(fs.tested) != 0 || len(fs.apiArgs) != 0 {
				t.Errorf("the runner tested %d configs and got the xray api calls %q, want none", len(fs.tested), fs.apiArgs)
			}
		})
	}
}

// With Hot off, a change to the servers alone goes through a trial too.
func TestHotOff(t *testing.T) {
	e, _ := newHotEnv(t, rendered(t, withServers(srvA)), rendered(t, withServers(srvA, srvB)))
	e.u.Hot = false

	res, err := e.u.Apply(bg)
	wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
	if res.Hot || res.Detail != "" {
		t.Errorf("Result = %+v, want a trial's", res)
	}
	wantActions(t, e.runner, "trial", "commit")
	if fs := e.runner.state(); len(fs.tested) != 0 || len(fs.apiArgs) != 0 || len(fs.adopted) != 0 {
		t.Errorf("tested %d, xray api %q, adopted %q; want none", len(fs.tested), fs.apiArgs, fs.adopted)
	}
}

// The hot path is part of Apply alone, behind all that Apply checks first: the
// artifacts lock, no open trial, NoState, and the noop. A core update, even to
// the active core, never takes it.
func TestHotKeepsApplysChecks(t *testing.T) {
	active, candidate := rendered(t, withServers(srvA)), rendered(t, withServers(srvA, srvB))
	t.Run("the lock", func(t *testing.T) {
		e, _ := newHotEnv(t, active, candidate)
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
		if calls := e.runner.allCalls(); len(calls) != 0 {
			t.Errorf("the runner got %v", calls)
		}
	})
	t.Run("an open trial", func(t *testing.T) {
		e, _ := newHotEnv(t, active, candidate)
		other := runnerapi.Candidate{Selection: e.activeSel, Deadline: t0.Add(time.Minute)}
		e.runner.script(func(f *fakeRunner) { f.st.State, f.st.Candidate = runnerapi.StateTrial, &other })
		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, OutcomeRefused)
		if !errors.Is(err, runnerapi.ErrBusy) {
			t.Errorf("err = %v, want ErrBusy", err)
		}
		wantActions(t, e.runner)
	})
	t.Run("no state", func(t *testing.T) {
		e, _ := newHotEnv(t, active, candidate)
		e.u.NoState = true
		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, OutcomeRefused)
		wantDetail(t, res, "no state has been saved")
		wantActions(t, e.runner)
	})
	t.Run("noop", func(t *testing.T) {
		e, _ := newHotEnv(t, active, active)
		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, OutcomeNoop)
		wantActions(t, e.runner)
	})
	t.Run("a core update", func(t *testing.T) {
		e, _ := newHotEnv(t, active, candidate)
		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		if res.Hot {
			t.Error("Result.Hot is set for an update")
		}
		wantActions(t, e.runner, "trial", "commit")
	})
}

// The reason a hot change failed is xray's output, which can name a server's
// credentials: it is redacted in the Result, the history and the log.
func TestHotRedactsTheReason(t *testing.T) {
	const secret = "b831381d-6324-4d53-ad4f-8cda48b30811"
	e, _ := newHotEnv(t, rendered(t, withServers(srvA)), rendered(t, withServers(srvA, srvB)))
	var log bytes.Buffer
	e.u.Log = &log
	e.u.Redact = func(s string) string { return strings.ReplaceAll(s, secret, "‹redacted›") }
	e.runner.script(func(f *fakeRunner) {
		f.onXrayAPI = func(w http.ResponseWriter, args []string) {
			writeJSONReply(w, http.StatusOK, runnerapi.XrayAPIResponse{ExitCode: 1, Stderr: "invalid user " + secret + "\n"})
		}
	})

	res, err := e.u.Apply(bg)
	wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
	wantDetail(t, res, "invalid user ‹redacted›")
	for what, s := range map[string]string{"Detail": res.Detail, "the history": strings.Join(historyLines(t, e), "\n"), "the log": log.String()} {
		if strings.Contains(s, secret) {
			t.Errorf("%s holds the secret", what)
		}
	}
}

// A tikray that died during a hot change left the marker, and xray with
// outbounds the active config lacks. Whatever Hot is, the next Apply heals
// it: with no noop and no hot change, a render that is the active config has
// xray restarted from it, and any other goes on trial, which restarts xray;
// a trial that never starts is followed by a restart.
func TestHotPendingHeals(t *testing.T) {
	one, two := rendered(t, withServers(srvA)), rendered(t, withServers(srvA, srvB))
	for _, tc := range []struct {
		name      string
		candidate string
		hotOff    bool
		script    func(f *fakeRunner)
		outcome   string
		detail    string
		actions   []string
		live      string // the config whose outbounds xray runs after
	}{
		{
			// The ado went through, tikray died, and then the added server
			// was removed again: the render is the active config.
			name: "the render is the active config", candidate: one,
			outcome: runnerapi.OutcomeCommitted,
			detail:  "a hot change had not finished, so xray was restarted from the active config",
			actions: []string{"restart"}, live: one,
		},
		{
			name: "the same with hot changes off", candidate: one, hotOff: true,
			outcome: runnerapi.OutcomeCommitted,
			detail:  "a hot change had not finished, so xray was restarted from the active config",
			actions: []string{"restart"}, live: one,
		},
		{
			name: "the render is another config", candidate: two,
			outcome: runnerapi.OutcomeCommitted,
			detail:  "a hot change had not finished, so a trial was tried",
			actions: []string{"trial", "commit"}, live: two,
		},
		{
			name: "the trial is refused", candidate: two,
			script: func(f *fakeRunner) {
				f.onTrial = func(w http.ResponseWriter, c runnerapi.Candidate) bool {
					fakeError(w, http.StatusInternalServerError, "internal", "disk full")
					return true
				}
			},
			outcome: OutcomeRefused,
			detail:  "a hot change had not finished, so a trial was tried: ",
			actions: []string{"trial", "restart"}, live: one,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newHotEnv(t, one, tc.candidate)
			e.u.Hot = !tc.hotOff
			leavePending(t, e, configRel(two))
			stray := withServers(srvA, srvB)
			stray.Servers[1].ID = "cccccccc"
			e.runner.script(func(f *fakeRunner) {
				f.live = configTags(t, rendered(t, stray))
				if tc.script != nil {
					tc.script(f)
				}
			})

			res, err := e.u.Apply(bg)
			wantOutcome(t, res, err, tc.outcome)
			wantDetail(t, res, tc.detail)
			if res.Hot {
				t.Error("Result.Hot is set")
			}
			wantActions(t, e.runner, tc.actions...)
			if fs := e.runner.state(); len(fs.tested) != 0 || len(fs.apiArgs) != 0 {
				t.Errorf("tested %d, xray api %q; want no hot change", len(fs.tested), fs.apiArgs)
			}
			if got, want := e.runner.state().live, configTags(t, tc.live); !reflect.DeepEqual(got, want) {
				t.Errorf("xray runs the outbounds %v, want those of the active config, %v", got, want)
			}
			wantPending(t, e, false)
			wantHotDirEmpty(t, e)
		})
	}
}

// A restart that fails keeps the marker, and so does the next apply's, until
// one works: the change that tikray could not finish is healed even though
// the state went back to the active config meanwhile.
func TestHotPendingSurvivesUntilHealed(t *testing.T) {
	one, two := rendered(t, withServers(srvA)), rendered(t, withServers(srvA, srvB))
	e, r := newHotEnv(t, one, two)
	newProxyProbe(e, failsUntilTrial(e))
	restarts := errors.New("no xray binary")
	e.runner.script(func(f *fakeRunner) {
		// The ado works and the probe fails after it; the trial is refused,
		// and so is the restart: xray keeps server b.
		f.onTrial = func(w http.ResponseWriter, c runnerapi.Candidate) bool {
			fakeError(w, http.StatusInternalServerError, "internal", "disk full")
			return true
		}
		f.onRestart = func(w http.ResponseWriter) bool {
			if restarts != nil {
				fakeError(w, http.StatusInternalServerError, "internal", restarts.Error())
				return true
			}
			return false
		}
	})
	res, err := e.u.Apply(bg)
	wantOutcome(t, res, err, OutcomeRefused)
	wantPending(t, e, true)
	wantLive(t, e, two)

	// Server b is removed: the render is the active config again. The restart
	// still fails, and the marker stays.
	r.body = one
	res, err = e.u.Apply(bg)
	wantOutcome(t, res, err, OutcomeRefused)
	wantDetail(t, res, "a hot change had not finished, and restarting xray from the active config failed: ")
	wantDetail(t, res, "no xray binary")
	wantPending(t, e, true)

	e.runner.script(func(*fakeRunner) { restarts = nil })
	res, err = e.u.Apply(bg)
	wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
	wantPending(t, e, false)
	if got, want := e.runner.state().live, configTags(t, one); !reflect.DeepEqual(got, want) {
		t.Errorf("xray runs the outbounds %v, want the active config's, %v", got, want)
	}
	if res, err := e.u.Apply(bg); err != nil || res.Outcome != OutcomeNoop {
		t.Errorf("the apply after = %+v, %v; want noop", res, err)
	}
}

// What a killed hot change left in run/hot/ holds credentials: every update,
// rollback or apply removes it under the lock, hot or not, but never the
// marker, which only an apply ends.
func TestHotSweepsLeftovers(t *testing.T) {
	one, two := rendered(t, withServers(srvA)), rendered(t, withServers(srvA, srvB))
	left := func(t *testing.T, e *coreEnv) {
		t.Helper()
		writeTestFile(t, filepath.Join(e.data, "run", "hot", shaOf("left")+".json"), `{"outbounds":[]}`)
		writeTestFile(t, filepath.Join(e.data, "run", "hot", "."+shaOf("left")+".json.tmp-1"), `{"outbounds":[]}`)
	}
	t.Run("an apply that is a trial", func(t *testing.T) {
		e, _ := newHotEnv(t, one, two)
		e.u.Hot = false
		left(t, e)
		res, err := e.u.Apply(bg)
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		wantHotDirEmpty(t, e)
	})
	t.Run("an update keeps the marker", func(t *testing.T) {
		e, _ := newHotEnv(t, one, two)
		left(t, e)
		leavePending(t, e, configRel(two))
		res, err := e.u.Update(bg, "26.10.21", UpdateOptions{})
		wantOutcome(t, res, err, runnerapi.OutcomeCommitted)
		if got := dirNames(t, filepath.Join(e.data, "run", "hot")); !reflect.DeepEqual(got, []string{"pending"}) {
			t.Errorf("run/hot holds %v, want the marker alone", got)
		}
	})
}
