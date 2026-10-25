package health

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xray"
)

const (
	idA = "aaaaaaa1"
	idB = "bbbbbbb2"
	idC = "ccccccc3"
	idD = "ddddddd4"
)

var bg = context.Background()

// running is a runner that carries traffic.
var running = runnerapi.Status{
	State: runnerapi.StateRunning, XrayVersion: "26.10.21", RoutesOK: true, GatewayUp: true,
}

func srv(id string) store.Server { return store.Server{ID: id, Name: "server " + id} }

func off(s store.Server) store.Server { s.Disabled = true; return s }

func stateOf(servers ...store.Server) store.State {
	st := store.Default()
	st.Servers = servers
	return st
}

func tag(id string) string { return store.ServerTagPrefix + id }

func up(id string, delay time.Duration) xray.OutboundStatus {
	return xray.OutboundStatus{Tag: tag(id), Alive: true, Delay: delay}
}

func down(id, why string) xray.OutboundStatus {
	return xray.OutboundStatus{Tag: tag(id), LastError: why}
}

// deadlineIn is how long ctx has left, or -1 for a context without deadline.
func deadlineIn(ctx context.Context) time.Duration {
	d, ok := ctx.Deadline()
	if !ok {
		return -1
	}
	return time.Until(d)
}

type fakeRunner struct {
	mu       sync.Mutex
	st       runnerapi.Status
	err      error
	calls    int
	deadline time.Duration
	called   chan struct{} // when set, each call sends on it
}

func (f *fakeRunner) Status(ctx context.Context) (runnerapi.Status, error) {
	f.mu.Lock()
	f.calls++
	f.deadline = deadlineIn(ctx)
	st, err, called := f.st, f.err, f.called
	f.mu.Unlock()
	if called != nil {
		select {
		case called <- struct{}{}:
		default:
		}
	}
	if err := ctx.Err(); err != nil {
		return runnerapi.Status{}, err
	}
	return st, err
}

type fakeXray struct {
	status      []xray.OutboundStatus
	statusErr   error
	targets     []string
	targetsErr  error
	statusCalls int
	balCalls    int
	balTags     []string
	deadlines   []time.Duration
	onStatus    func() // when set, runs inside each OutboundStatus call
}

func (f *fakeXray) OutboundStatus(ctx context.Context) ([]xray.OutboundStatus, error) {
	f.statusCalls++
	f.deadlines = append(f.deadlines, deadlineIn(ctx))
	if f.onStatus != nil {
		f.onStatus()
	}
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return f.status, nil
}

func (f *fakeXray) BalancerTargets(ctx context.Context, tag string) (string, []string, error) {
	f.balCalls++
	f.balTags = append(f.balTags, tag)
	f.deadlines = append(f.deadlines, deadlineIn(ctx))
	if f.targetsErr != nil {
		return "", nil, f.targetsErr
	}
	return "", f.targets, nil
}

type fakeProbe struct {
	err      error
	calls    int
	deadline time.Duration
}

func (p *fakeProbe) Check(ctx context.Context) error {
	p.calls++
	p.deadline = deadlineIn(ctx)
	return p.err
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// rig is a Monitor over fakes, with a clock that only moves when a test says.
type rig struct {
	t      *testing.T
	m      *Monitor
	runner *fakeRunner
	xray   *fakeXray
	probe  *fakeProbe
	clock  *fakeClock
	state  store.State
}

// newRig has a running runner and an observatory that sees nothing yet. Like
// the real probe factory, Probe gives nil when no server is available.
func newRig(t *testing.T, st store.State) *rig {
	t.Helper()
	r := &rig{
		t:      t,
		runner: &fakeRunner{st: running},
		xray:   &fakeXray{},
		probe:  &fakeProbe{},
		clock:  &fakeClock{t: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)},
		state:  st,
	}
	r.m = &Monitor{
		Runner: r.runner,
		Xray:   r.xray,
		Probe: func(st store.State) artifacts.HealthChecker {
			if !render.ProxyAvailable(st) {
				return nil
			}
			return r.probe
		},
		State: func() store.State { return r.state },
		Now:   r.clock.Now,
	}
	return r
}

// tick runs one check and returns the snapshot it published.
func (r *rig) tick() Snapshot {
	r.t.Helper()
	r.m.tick(bg)
	return r.m.Snapshot()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLevels(t *testing.T) {
	trial := running
	trial.State = runnerapi.StateTrial
	restarting := running
	restarting.State = runnerapi.StateRestarting
	empty := runnerapi.Status{State: runnerapi.StateEmpty}

	two := stateOf(srv(idA), srv(idB))
	bothUp := []xray.OutboundStatus{up(idA, 40*time.Millisecond), up(idB, 90*time.Millisecond)}
	oneUp := []xray.OutboundStatus{up(idA, 40*time.Millisecond), down(idB, "timeout")}
	noneUp := []xray.OutboundStatus{down(idA, "timeout"), down(idB, "refused")}
	probeFailed := errors.New("socks probe: HTTP 503")
	pinnedAway := stateOf(srv(idA), off(srv(idB)))
	pinnedAway.Routing.Pinned = idB

	rows := []struct {
		name      string
		runner    runnerapi.Status
		runnerErr error
		state     store.State
		obs       []xray.OutboundStatus
		probeErr  error
		want      string
	}{
		{"runner unreachable", running, errors.New("connection refused"), two, bothUp, nil, LevelDown},
		{"runner has no core", empty, nil, two, bothUp, nil, LevelDown},
		{"runner restarting", restarting, nil, two, bothUp, nil, LevelDown},
		{"down before idle", empty, nil, stateOf(), nil, nil, LevelDown},
		{"down before outage", restarting, nil, two, noneUp, nil, LevelDown},
		{"no servers", running, nil, stateOf(), nil, nil, LevelIdle},
		{"every server disabled", running, nil, stateOf(off(srv(idA))), nil, nil, LevelIdle},
		{"pinned server disabled", running, nil, pinnedAway, []xray.OutboundStatus{up(idA, time.Millisecond)}, nil, LevelIdle},
		{"idle before outage", running, nil, stateOf(off(srv(idA))), noneUp, nil, LevelIdle},
		{"no server alive", running, nil, two, noneUp, nil, LevelOutage},
		{"nothing observed yet", running, nil, two, nil, nil, LevelOutage},
		{"outage before a failed probe", running, nil, two, noneUp, probeFailed, LevelOutage},
		{"one server dead", running, nil, two, oneUp, nil, LevelDegraded},
		{"probe failed", running, nil, two, bothUp, probeFailed, LevelDegraded},
		{"all alive, probe fine", running, nil, two, bothUp, nil, LevelOK},
		{"trial counts as running", trial, nil, two, bothUp, nil, LevelOK},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			r := newRig(t, row.state)
			r.runner.st, r.runner.err = row.runner, row.runnerErr
			r.xray.status = row.obs
			r.probe.err = row.probeErr
			if got := r.tick().Level; got != row.want {
				t.Errorf("Level = %q, want %q", got, row.want)
			}
		})
	}
}

func TestRunnerHealth(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond)}
	want := RunnerHealth{Reachable: true, State: "running", XrayVersion: "26.10.21", RoutesOK: true, GatewayUp: true}
	if got := r.tick().Runner; got != want {
		t.Errorf("Runner = %+v, want %+v", got, want)
	}

	r.runner.err = errors.New("runnerapi: GET /v1/status: connection refused")
	snap := r.tick()
	if snap.Runner.Reachable || snap.Runner.State != "" || snap.Runner.GatewayUp {
		t.Errorf("an unreachable runner reports %+v", snap.Runner)
	}
	if want := "health: runner: runnerapi: GET /v1/status: connection refused"; snap.Runner.Err != want {
		t.Errorf("Runner.Err = %q, want %q", snap.Runner.Err, want)
	}
	// An unreachable runner is not asked about xray, which may not exist.
	if r.xray.statusCalls != 1 || r.xray.balCalls != 1 {
		t.Errorf("xray calls = %d, %d, want only the first check's", r.xray.statusCalls, r.xray.balCalls)
	}
}

func TestSnapshotServers(t *testing.T) {
	// State order is C, A, (disabled B), D; xray lists them in another order,
	// with an outbound the state doesn't have and without D.
	st := stateOf(srv(idC), srv(idA), off(srv(idB)), srv(idD))
	r := newRig(t, st)
	local := time.FixedZone("UTC+3:30", 3*3600+1800)
	tried := time.Date(2026, 10, 25, 15, 30, 5, 0, local)
	r.xray.status = []xray.OutboundStatus{
		{Tag: tag(idA), Alive: false, Delay: 99999999 * time.Millisecond, LastError: "dial tcp: i/o timeout", LastTry: tried},
		{Tag: "direct", Alive: true, Delay: time.Millisecond},
		{Tag: tag(idB), Alive: true, Delay: time.Millisecond},
		{Tag: tag(idC), Alive: true, Delay: 35 * time.Millisecond, LastTry: tried},
	}
	got := r.tick().Servers
	utc := tried.UTC()
	want := []ServerHealth{
		{ID: idC, Alive: true, Delay: 35 * time.Millisecond, LastTry: utc},
		// xray reports a dead server's delay as 99999999 ms: that isn't one.
		{ID: idA, Alive: false, LastError: "dial tcp: i/o timeout", LastTry: utc},
		{ID: idD, Alive: false, LastError: "not observed yet"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Servers =\n %+v\nwant\n %+v", got, want)
	}
	for _, s := range got {
		if s.LastTry.Location() != time.UTC {
			t.Errorf("server %s: LastTry is in %v, want UTC", s.ID, s.LastTry.Location())
		}
	}
}

// With a pin the balancers' only member is the pinned server, and the
// observatory probes only it: the other enabled servers are not "not
// observed", they're out of play.
func TestPinnedServerIsTheOnlyMember(t *testing.T) {
	st := stateOf(srv(idA), srv(idB), srv(idC))
	st.Routing.Pinned = idB
	r := newRig(t, st)
	r.xray.status = []xray.OutboundStatus{up(idB, 20*time.Millisecond)}
	r.xray.targets = []string{tag(idA), tag(idB)} // a stale pick from before the pin
	snap := r.tick()
	if len(snap.Servers) != 1 || snap.Servers[0].ID != idB || !snap.Servers[0].Alive {
		t.Errorf("Servers = %+v, want only %s", snap.Servers, idB)
	}
	if snap.Level != LevelOK {
		t.Errorf("Level = %q, want ok", snap.Level)
	}
	if snap.Selected != idB {
		t.Errorf("Selected = %q, want %q", snap.Selected, idB)
	}
}

func TestSnapshotListsNoServersWhenIdle(t *testing.T) {
	r := newRig(t, stateOf(off(srv(idA))))
	snap := r.tick()
	if snap.Servers == nil || len(snap.Servers) != 0 {
		t.Errorf("Servers = %#v, want an empty list", snap.Servers)
	}
	if r.xray.statusCalls != 0 || r.xray.balCalls != 0 {
		t.Errorf("an idle proxy was asked about xray (%d, %d calls): its observatory doesn't exist", r.xray.statusCalls, r.xray.balCalls)
	}
	if r.probe.calls != 0 {
		t.Errorf("an idle proxy was probed %d times", r.probe.calls)
	}
}

func TestSelected(t *testing.T) {
	st := stateOf(srv(idA), srv(idB), off(srv(idC)))
	rows := []struct {
		name    string
		targets []string
		want    string
	}{
		{"the pick", []string{tag(idB)}, idB},
		{"the first member", []string{tag(idA), tag(idB)}, idA},
		{"skips what is no member", []string{"direct", tag(idC), tag(idD), tag(idB)}, idB},
		{"only non-members", []string{"direct", tag(idC)}, ""},
		{"no pick while nothing is alive", nil, ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			r := newRig(t, st)
			r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond), up(idB, time.Millisecond)}
			r.xray.targets = row.targets
			if got := r.tick().Selected; got != row.want {
				t.Errorf("Selected = %q, want %q", got, row.want)
			}
			if want := []string{render.BalancerOpen}; !reflect.DeepEqual(r.xray.balTags, want) {
				t.Errorf("asked balancers %q, want %q", r.xray.balTags, want)
			}
		})
	}
}

func TestProbeCadence(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	r.m.Interval, r.m.ProbeEvery = 10*time.Second, 60*time.Second
	r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond)}

	first := r.tick()
	if r.probe.calls != 1 {
		t.Fatalf("probe ran %d times at the start, want 1", r.probe.calls)
	}
	if !first.Probe.Ran || !first.Probe.OK || !first.Probe.At.Equal(r.clock.Now()) {
		t.Errorf("Probe = %+v, want it to have run OK at %v", first.Probe, r.clock.Now())
	}

	// Five more checks, 10 s apart, are all within ProbeEvery of the probe.
	for i := 1; i <= 5; i++ {
		r.clock.advance(10 * time.Second)
		snap := r.tick()
		if r.probe.calls != 1 {
			t.Fatalf("after %d s the probe has run %d times, want 1", i*10, r.probe.calls)
		}
		if snap.Probe != first.Probe {
			t.Errorf("after %d s Probe = %+v, want the first result %+v", i*10, snap.Probe, first.Probe)
		}
		if !snap.At.Equal(r.clock.Now()) {
			t.Errorf("After %d s At = %v, want the check's time %v", i*10, snap.At, r.clock.Now())
		}
	}
	if r.runner.calls != 6 || r.xray.statusCalls != 6 {
		t.Errorf("runner and observatory were asked %d and %d times, want a check each time", r.runner.calls, r.xray.statusCalls)
	}

	// 60 s after the first: the probe runs again, and now it fails.
	r.probe.err = errors.New("socks probe: HTTP 503")
	r.clock.advance(10 * time.Second)
	snap := r.tick()
	if r.probe.calls != 2 {
		t.Fatalf("after 60 s the probe has run %d times, want 2", r.probe.calls)
	}
	if snap.Probe.OK || !snap.Probe.Ran || snap.Probe.Err == "" || !snap.Probe.At.Equal(r.clock.Now()) {
		t.Errorf("Probe = %+v, want a failure at %v", snap.Probe, r.clock.Now())
	}
	if snap.Level != LevelDegraded {
		t.Errorf("Level = %q after a failed probe, want degraded", snap.Level)
	}

	// The failure is kept until the next probe, which passes.
	r.probe.err = nil
	r.clock.advance(10 * time.Second)
	if snap = r.tick(); r.probe.calls != 2 || snap.Probe.OK {
		t.Errorf("10 s after the probe: %d runs, Probe %+v; want the failure kept", r.probe.calls, snap.Probe)
	}
	r.clock.advance(50 * time.Second)
	if snap = r.tick(); r.probe.calls != 3 || !snap.Probe.OK || snap.Level != LevelOK {
		t.Errorf("60 s after the failure: %d runs, Probe %+v, Level %q; want a pass", r.probe.calls, snap.Probe, snap.Level)
	}
}

// A check that runs a few milliseconds early, as a ticker's can, still
// probes on schedule instead of waiting a whole Interval more.
func TestProbeCadenceToleratesJitter(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	r.m.Interval, r.m.ProbeEvery = 10*time.Second, 60*time.Second
	r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond)}
	r.tick()
	r.clock.advance(60*time.Second - 20*time.Millisecond)
	r.tick()
	if r.probe.calls != 2 {
		t.Errorf("probe ran %d times, want 2: a check 20 ms early should probe", r.probe.calls)
	}
}

func TestProbeWaitsForARunningProxy(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	r.m.Interval, r.m.ProbeEvery = 10*time.Second, 60*time.Second
	r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond)}
	r.runner.st = runnerapi.Status{State: runnerapi.StateRestarting}
	if snap := r.tick(); r.probe.calls != 0 || snap.Probe.Ran {
		t.Fatalf("probed a runner that isn't running: %d runs, Probe %+v", r.probe.calls, snap.Probe)
	}

	// Back up, 10 s later: the probe doesn't wait for ProbeEvery, which
	// nothing has started.
	r.runner.st = running
	r.clock.advance(10 * time.Second)
	if snap := r.tick(); r.probe.calls != 1 || !snap.Probe.Ran {
		t.Fatalf("after the runner came back: %d runs, Probe %+v; want one right away", r.probe.calls, snap.Probe)
	}

	// A runner that drops out forgets the probe: its result described a
	// different xray.
	r.probe.err = errors.New("socks probe: refused")
	r.clock.advance(60 * time.Second)
	r.tick() // fails
	r.runner.st = runnerapi.Status{State: runnerapi.StateRestarting}
	r.clock.advance(10 * time.Second)
	if snap := r.tick(); snap.Probe.Ran {
		t.Errorf("Probe = %+v while the runner is down, want none", snap.Probe)
	}
	r.runner.st = running
	r.probe.err = nil
	r.clock.advance(10 * time.Second)
	if snap := r.tick(); !snap.Probe.OK || snap.Level != LevelOK {
		t.Errorf("Probe = %+v, Level %q after the runner returned, want a fresh pass", snap.Probe, snap.Level)
	}
}

func TestNoProbeFactory(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	r.m.Probe = nil
	r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond)}
	snap := r.tick()
	if snap.Probe.Ran || snap.Level != LevelOK {
		t.Errorf("Probe = %+v, Level %q, want no probe and ok", snap.Probe, snap.Level)
	}
}

// The probe's URL is the state's, and a URL can carry credentials. The
// errors the probe's HTTP client and SOCKSProbe make repeat it.
func TestProbeErrorHidesCredentials(t *testing.T) {
	st := stateOf(srv(idA))
	st.Health.ProbeURL = "https://tok3nuser:s3cretpass@probe.example/generate_204"
	r := newRig(t, st)
	r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond)}
	r.probe.err = fmt.Errorf("socks probe through 192.168.88.3:1080: GET %s: HTTP 503 Service Unavailable", st.Health.ProbeURL)
	snap := r.tick()
	for _, secret := range []string{"s3cretpass", "tok3nuser"} {
		if strings.Contains(snap.Probe.Err, secret) {
			t.Errorf("Probe.Err repeats the URL's credentials (%q found)", secret)
		}
	}
	for _, want := range []string{"health: probe: ", "probe.example", "HTTP 503"} {
		if !strings.Contains(snap.Probe.Err, want) {
			t.Errorf("Probe.Err = %q, want it to keep %q", snap.Probe.Err, want)
		}
	}
}

func TestProxyHealthy(t *testing.T) {
	notRunning := func(state string) runnerapi.Status { s := running; s.State = state; return s }
	noGateway := running
	noGateway.GatewayUp = false
	two := stateOf(srv(idA), srv(idB))

	rows := []struct {
		name   string
		runner runnerapi.Status
		err    error
		state  store.State
		obs    []xray.OutboundStatus
		want   bool
	}{
		{"running, gateway up, one server alive", running, nil, two, []xray.OutboundStatus{down(idA, "x"), up(idB, time.Millisecond)}, true},
		{"every server alive", running, nil, two, []xray.OutboundStatus{up(idA, time.Millisecond), up(idB, time.Millisecond)}, true},
		{"no server alive", running, nil, two, []xray.OutboundStatus{down(idA, "x"), down(idB, "y")}, false},
		{"nothing observed", running, nil, two, nil, false},
		{"gateway down", noGateway, nil, two, []xray.OutboundStatus{up(idA, time.Millisecond)}, false},
		{"runner in a trial", notRunning(runnerapi.StateTrial), nil, two, []xray.OutboundStatus{up(idA, time.Millisecond)}, false},
		{"runner restarting", notRunning(runnerapi.StateRestarting), nil, two, []xray.OutboundStatus{up(idA, time.Millisecond)}, false},
		{"runner unreachable", running, errors.New("refused"), two, []xray.OutboundStatus{up(idA, time.Millisecond)}, false},
		{"no server enabled", running, nil, stateOf(off(srv(idA))), []xray.OutboundStatus{up(idA, time.Millisecond)}, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			r := newRig(t, row.state)
			r.runner.st, r.runner.err = row.runner, row.err
			r.xray.status = row.obs
			if got := r.m.ProxyHealthy(bg); got {
				t.Errorf("ProxyHealthy before the first check = true, want false")
			}
			r.tick()
			if got := r.m.ProxyHealthy(bg); got != row.want {
				t.Errorf("ProxyHealthy = %v, want %v", got, row.want)
			}
		})
	}
}

func TestProxyHealthyDoesNoIO(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond)}
	r.tick()
	calls := r.runner.calls
	for i := 0; i < 3; i++ {
		r.m.ProxyHealthy(bg)
		r.m.Snapshot()
	}
	if r.runner.calls != calls || r.xray.statusCalls != 1 || r.probe.calls != 1 {
		t.Errorf("readers did I/O: runner %d→%d calls, observatory %d, probe %d", calls, r.runner.calls, r.xray.statusCalls, r.probe.calls)
	}
}

// After a restart xray's API connection is stale for one call. One failed
// poll must not turn every server dead and then alive again.
func TestOneFailedPollKeepsServers(t *testing.T) {
	r := newRig(t, stateOf(srv(idA), srv(idB)))
	r.xray.status = []xray.OutboundStatus{up(idA, 40*time.Millisecond), down(idB, "timeout")}
	r.xray.targets = []string{tag(idA)}
	before := r.tick()
	if before.Level != LevelDegraded || !before.Servers[0].Alive || before.Selected != idA {
		t.Fatalf("setup: %+v", before)
	}

	failure := &xray.StatusError{Code: 14, Message: "connection error: broken pipe"}
	r.xray.statusErr = failure
	r.clock.advance(10 * time.Second)
	kept := r.tick()
	if !reflect.DeepEqual(kept.Servers, before.Servers) {
		t.Errorf("after one failed poll Servers = %+v, want the previous %+v", kept.Servers, before.Servers)
	}
	if kept.Level != before.Level || kept.Selected != idA || kept.Runner.Err != "" {
		t.Errorf("after one failed poll: Level %q, Selected %q, Runner.Err %q; want them as before", kept.Level, kept.Selected, kept.Runner.Err)
	}
	if !kept.At.Equal(r.clock.Now()) {
		t.Errorf("At = %v, want the failed check's time %v: the snapshot is recent, not frozen", kept.At, r.clock.Now())
	}

	// The second failure in a row is reported: every server dead, with why.
	r.clock.advance(10 * time.Second)
	lost := r.tick()
	wantErr := "health: observatory: " + failure.Error()
	for _, s := range lost.Servers {
		if s.Alive || s.LastError != wantErr {
			t.Errorf("after two failed polls server %s = %+v, want dead with %q", s.ID, s, wantErr)
		}
	}
	if lost.Level != LevelOutage || lost.Selected != "" {
		t.Errorf("after two failed polls: Level %q, Selected %q; want outage and none", lost.Level, lost.Selected)
	}
	// xray isn't asked about the balancer when it can't answer the poll.
	if r.xray.balCalls != 2 {
		t.Errorf("balancer asked %d times, want 2: not after the reported failure", r.xray.balCalls)
	}

	// A good poll puts things right and gives the tolerance back.
	r.xray.statusErr = nil
	r.clock.advance(10 * time.Second)
	if back := r.tick(); !reflect.DeepEqual(back.Servers, before.Servers) || back.Level != before.Level {
		t.Errorf("after a good poll: %+v, want %+v", back, before)
	}
	r.xray.statusErr = failure
	r.clock.advance(10 * time.Second)
	if again := r.tick(); !reflect.DeepEqual(again.Servers, before.Servers) {
		t.Errorf("one failure after a good poll: Servers = %+v, want the previous %+v", again.Servers, before.Servers)
	}
}

func TestFailedPollWithNothingToKeepIsReported(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	r.xray.statusErr = &xray.StatusError{Code: 12, Message: "unknown service ObservatoryService"}
	snap := r.tick()
	if len(snap.Servers) != 1 || snap.Servers[0].Alive || !strings.HasPrefix(snap.Servers[0].LastError, "health: observatory: ") {
		t.Errorf("Servers = %+v, want the failure at once: there is no earlier poll", snap.Servers)
	}
	if snap.Level != LevelOutage {
		t.Errorf("Level = %q, want outage", snap.Level)
	}
}

// A runner that went down in between has no observation worth keeping.
func TestFailedPollAfterTheRunnerWasDownIsReported(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond)}
	if r.tick().Level != LevelOK {
		t.Fatal("setup")
	}
	r.runner.st = runnerapi.Status{State: runnerapi.StateRestarting}
	if r.tick().Level != LevelDown {
		t.Fatal("setup: not down")
	}
	r.runner.st = running
	r.xray.statusErr = &xray.StatusError{Code: 14, Message: "unavailable"}
	snap := r.tick()
	if snap.Servers[0].Alive || snap.Level != LevelOutage {
		t.Errorf("Servers = %+v, Level %q; want the failure, not the observation from before the restart", snap.Servers, snap.Level)
	}
}

func TestXrayErrorsNameTheirCall(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond)}
	balErr := &xray.StatusError{Code: 5, Message: "balancer proxy-open not found"}
	r.xray.targetsErr = balErr
	snap := r.tick()
	if want := "health: balancer: " + balErr.Error(); snap.Runner.Err != want {
		t.Errorf("Runner.Err = %q, want %q", snap.Runner.Err, want)
	}
	if !snap.Runner.Reachable || snap.Selected != "" || snap.Level != LevelOK {
		t.Errorf("a failed balancer query leaves Reachable %v, Selected %q, Level %q; want true, none, ok", snap.Runner.Reachable, snap.Selected, snap.Level)
	}

	// The observatory's error, once reported, is on every server.
	r.xray.targetsErr = nil
	obsErr := &xray.StatusError{Code: 14, Message: "unavailable"}
	r.xray.statusErr = obsErr
	r.tick()
	snap = r.tick()
	if want := "health: observatory: " + obsErr.Error(); snap.Servers[0].LastError != want {
		t.Errorf("LastError = %q, want %q", snap.Servers[0].LastError, want)
	}
	if snap.Runner.Err != "" {
		t.Errorf("Runner.Err = %q, want the runner's own error only", snap.Runner.Err)
	}
}

func TestTimesAreUTC(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	local := time.FixedZone("UTC-8", -8*3600)
	r.clock.t = time.Date(2026, 10, 25, 4, 0, 0, 0, local)
	r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond)}
	snap := r.tick()
	if snap.At.Location() != time.UTC || !snap.At.Equal(r.clock.Now()) {
		t.Errorf("At = %v, want %v in UTC", snap.At, r.clock.Now().UTC())
	}
	if snap.Probe.At.Location() != time.UTC || !snap.Probe.At.Equal(r.clock.Now()) {
		t.Errorf("Probe.At = %v, want %v in UTC", snap.Probe.At, r.clock.Now().UTC())
	}
}

func TestCallsAreBounded(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond)}
	r.tick()
	check := func(what string, d time.Duration) {
		t.Helper()
		if d <= 0 || d > 5*time.Second {
			t.Errorf("%s ran with %v left, want a deadline within 5 s", what, d)
		}
	}
	check("the runner call", r.runner.deadline)
	for _, d := range r.xray.deadlines {
		check("an xray call", d)
	}
	if r.probe.deadline <= 0 || r.probe.deadline > 10*time.Second {
		t.Errorf("the probe ran with %v left, want a deadline within 10 s", r.probe.deadline)
	}
}

func TestCancelledCheckPublishesNothing(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond)}
	good := r.tick()

	// Shutdown arrives while xray is being asked, and the call fails with it.
	ctx, cancel := context.WithCancel(bg)
	r.xray.onStatus = cancel
	r.xray.statusErr = context.Canceled
	r.clock.advance(time.Minute)
	r.m.tick(ctx)
	r.xray.onStatus = nil
	if got := r.m.Snapshot(); !reflect.DeepEqual(got, good) {
		t.Errorf("a check cancelled by shutdown replaced the snapshot:\n got %+v\nwant %+v", got, good)
	}
	// Nor did it use up the poll that is tolerated: one failure is still kept.
	if kept := r.tick(); !kept.Servers[0].Alive {
		t.Errorf("the cancelled check counted as a failed poll: %+v", kept.Servers)
	}
}

func TestSnapshotIsACopy(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond)}
	r.tick()
	s := r.m.Snapshot()
	s.Servers[0].Alive = false
	s.Servers = append(s.Servers, ServerHealth{ID: "x"})
	if got := r.m.Snapshot().Servers; len(got) != 1 || !got[0].Alive {
		t.Errorf("a caller changed the monitor's snapshot: %+v", got)
	}
}

func TestZeroSnapshot(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	s := r.m.Snapshot()
	if !s.At.IsZero() || s.Level != "" || s.Servers == nil || len(s.Servers) != 0 {
		t.Errorf("before the first check Snapshot = %#v, want only an empty list of servers", s)
	}
}

func TestDefaults(t *testing.T) {
	var m Monitor
	if m.interval() != 10*time.Second || m.probeEvery() != 60*time.Second {
		t.Errorf("defaults = %v, %v, want 10s, 60s", m.interval(), m.probeEvery())
	}
	if d := time.Since(m.now()); d < 0 || d > time.Minute {
		t.Errorf("default clock is %v off", d)
	}
	m.Interval, m.ProbeEvery = time.Second, time.Hour
	if m.interval() != time.Second || m.probeEvery() != time.Hour {
		t.Errorf("set values not used: %v, %v", m.interval(), m.probeEvery())
	}
}

func TestRunChecksAtStart(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	r.m.Interval = time.Hour // the first check can't be a tick's
	r.runner.called = make(chan struct{}, 8)
	r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond)}

	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() { r.m.Run(ctx); close(done) }()
	waitFor(t, "the first snapshot", func() bool { return r.m.Snapshot().Level == LevelOK })
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
	if n := len(r.runner.called); n != 1 {
		t.Errorf("the runner was asked %d times, want once", n)
	}
}

func TestRunChecksEveryInterval(t *testing.T) {
	r := newRig(t, stateOf(srv(idA)))
	r.m.Interval = 2 * time.Millisecond
	r.runner.called = make(chan struct{}, 1000)
	r.xray.status = []xray.OutboundStatus{up(idA, time.Millisecond)}

	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() { r.m.Run(ctx); close(done) }()
	for i := 0; i < 3; i++ {
		select {
		case <-r.runner.called:
		case <-time.After(5 * time.Second):
			t.Fatalf("check %d never happened", i+1)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}
