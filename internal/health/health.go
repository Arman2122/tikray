// Package health watches whether the router's proxy works: whether the runner
// is up, which servers xray's observatory sees alive, which one the balancer
// picked, and whether an end-to-end probe through the SOCKS port passes.
//
// Run does the I/O, on a timer. Everything else reads the last snapshot under
// a mutex, so a caller of Snapshot or ProxyHealthy never waits for a network.
package health

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xray"
)

// Levels of Snapshot.Level, from the worst to the best.
const (
	// LevelDown: the runner is unreachable, or has no xray running.
	LevelDown = "down"
	// LevelIdle: no server is enabled, so there is no proxy to judge.
	LevelIdle = "idle"
	// LevelOutage: no server is alive.
	LevelOutage = "outage"
	// LevelDegraded: some server is dead, or the last probe failed.
	LevelDegraded = "degraded"
	// LevelOK: every server is alive and the last probe passed.
	LevelOK = "ok"
)

const (
	defaultInterval   = 10 * time.Second
	defaultProbeEvery = 60 * time.Second
	// callTimeout bounds each call to the runner or to xray.
	callTimeout = 5 * time.Second
	// probeTimeout bounds one probe, which fetches a page through a server
	// and so is slower than a call to a local service. It is SOCKSProbe's own
	// default.
	probeTimeout = 10 * time.Second
	// notObserved is the LastError of a server that xray has not reported.
	notObserved = "not observed yet"
)

// RunnerStatus is the part of the runner's client that the monitor uses.
type RunnerStatus interface {
	Status(ctx context.Context) (runnerapi.Status, error)
}

// XrayStatus is the part of xray.Client that the monitor uses.
type XrayStatus interface {
	OutboundStatus(ctx context.Context) ([]xray.OutboundStatus, error)
	BalancerTargets(ctx context.Context, tag string) (string, []string, error)
}

// Snapshot is what the last check saw. Its times are UTC. Before the first
// check it is the zero value, with no servers listed.
type Snapshot struct {
	At    time.Time `json:"at"`
	Level string    `json:"level"`
	// Runner is the runner's own state. Err says what failed in reading it:
	// the runner's status call, or xray's balancer query.
	Runner RunnerHealth `json:"runner"`
	// Servers lists the servers the balancers can pick, in the state's order.
	Servers []ServerHealth `json:"servers"`
	// Selected is the ID of the server that proxy-open picks now, or "".
	Selected string      `json:"selected,omitempty"`
	Probe    ProbeHealth `json:"probe"`
}

// RunnerHealth is the runner's answer to a status call.
type RunnerHealth struct {
	Reachable   bool   `json:"reachable"`
	State       string `json:"state,omitempty"`
	XrayVersion string `json:"xray_version,omitempty"`
	RoutesOK    bool   `json:"routes_ok"`
	GatewayUp   bool   `json:"gateway_up"`
	Err         string `json:"error,omitempty"`
}

// ServerHealth is what xray's observatory knows of one server. Delay is
// marshalled as nanoseconds and is zero for a dead server.
type ServerHealth struct {
	ID        string        `json:"id"`
	Alive     bool          `json:"alive"`
	Delay     time.Duration `json:"delay"`
	LastError string        `json:"last_error,omitempty"`
	LastTry   time.Time     `json:"last_try,omitzero"`
}

// ProbeHealth is the last end-to-end probe. Ran is false while none has run
// since the proxy became available.
type ProbeHealth struct {
	Ran bool      `json:"ran"`
	OK  bool      `json:"ok"`
	At  time.Time `json:"at,omitzero"`
	Err string    `json:"error,omitempty"`
}

// Monitor checks the proxy every Interval. Runner, Xray and State are
// required; Probe may be nil.
type Monitor struct {
	Runner RunnerStatus
	Xray   XrayStatus
	// Probe returns the end-to-end probe for a state, or nil when the state
	// has no proxy to probe (render.ProxyAvailable is false).
	Probe func(store.State) artifacts.HealthChecker
	// State returns the state to judge the runner against.
	State func() store.State
	// Interval is the time between checks; zero means 10 s.
	Interval time.Duration
	// ProbeEvery is the time between probes; zero means 60 s. A probe runs
	// with the first check, and with the first check after ProbeEvery.
	ProbeEvery time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu   sync.Mutex
	snap Snapshot // the last check's, under mu

	// The rest belongs to the goroutine that runs checks (see tick).
	// pollFails counts the observatory polls that failed in a row. lastObs
	// is the last poll that worked, valid when haveObs.
	pollFails int
	lastObs   []xray.OutboundStatus
	haveObs   bool
	// probeRes is the last probe's result, run at probeAt.
	probeRes ProbeHealth
	probeAt  time.Time
}

func (m *Monitor) interval() time.Duration {
	if m.Interval > 0 {
		return m.Interval
	}
	return defaultInterval
}

func (m *Monitor) probeEvery() time.Duration {
	if m.ProbeEvery > 0 {
		return m.ProbeEvery
	}
	return defaultProbeEvery
}

func (m *Monitor) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Run checks once, then every Interval, until ctx is done. One check takes
// at most a few call timeouts (5 s each) plus a probe (10 s).
func (m *Monitor) Run(ctx context.Context) {
	m.tick(ctx)
	t := time.NewTicker(m.interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.tick(ctx)
		}
	}
}

// Snapshot returns the last check's result, without any I/O.
func (m *Monitor) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.snap
	s.Servers = append([]ServerHealth{}, s.Servers...)
	return s
}

// ProxyHealthy reports whether traffic through the proxy can be expected to
// work: the runner is running, its gateway is up, and some server was alive
// at the last check. It reads that check and does no I/O, so ctx is unused.
func (m *Monitor) ProxyHealthy(_ context.Context) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.snap.Runner
	if !r.Reachable || r.State != runnerapi.StateRunning || !r.GatewayUp {
		return false
	}
	return slices.ContainsFunc(m.snap.Servers, func(s ServerHealth) bool { return s.Alive })
}

// tick makes one check and publishes it. A check that shutdown cut short
// publishes nothing: what it saw is the cancellation. tick is not safe for
// concurrent use: Run calls it, one check after the other.
func (m *Monitor) tick(ctx context.Context) {
	now := m.now()
	st := m.State()
	members := membersOf(st)
	snap := Snapshot{At: now.UTC()}

	rs, err := m.runnerStatus(ctx)
	if err != nil {
		snap.Runner.Err = fmt.Sprintf("health: runner: %v", err)
	} else {
		snap.Runner = RunnerHealth{
			Reachable: true, State: rs.State, XrayVersion: rs.XrayVersion,
			RoutesOK: rs.RoutesOK, GatewayUp: rs.GatewayUp,
		}
	}
	live := err == nil && (rs.State == runnerapi.StateRunning || rs.State == runnerapi.StateTrial)
	proxy := render.ProxyAvailable(st)

	// Without a running xray, or with no server for the render to give
	// xray an observatory for, there is nothing to ask it.
	watch := live && proxy
	var obs []xray.OutboundStatus
	var obsErr error
	if watch {
		obs, obsErr = m.observe(ctx)
	} else {
		m.pollFails, m.lastObs, m.haveObs = 0, nil, false
	}
	snap.Servers = serverHealth(members, obs, obsErr)
	if watch && obsErr == nil {
		snap.Selected = m.selected(ctx, members, &snap.Runner)
	}
	if ctx.Err() != nil {
		return
	}
	snap.Probe = m.probe(ctx, st, now, watch)
	if ctx.Err() != nil {
		return
	}
	snap.Level = level(live, proxy, snap.Servers, snap.Probe)
	m.mu.Lock()
	m.snap = snap
	m.mu.Unlock()
}

func (m *Monitor) runnerStatus(ctx context.Context) (runnerapi.Status, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return m.Runner.Status(ctx)
}

// observe polls the observatory. xray restarts under the runner now and then,
// and the first call on the connection that outlived the old xray fails. So
// one failed poll after a good one gives the good one's answer again, which
// is recent enough; a second failure in a row is the result, wrapped with the
// call's name.
func (m *Monitor) observe(ctx context.Context) ([]xray.OutboundStatus, error) {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	obs, err := m.Xray.OutboundStatus(cctx)
	if ctx.Err() != nil {
		return nil, ctx.Err() // shutdown, not a failed poll
	}
	if err == nil {
		m.pollFails, m.lastObs, m.haveObs = 0, obs, true
		return obs, nil
	}
	m.pollFails++
	if m.pollFails == 1 && m.haveObs {
		return m.lastObs, nil
	}
	return nil, fmt.Errorf("health: observatory: %w", err)
}

// selected returns the ID of the member that proxy-open picks, or "". A
// failed query is recorded in r.Err.
func (m *Monitor) selected(ctx context.Context, members []store.Server, r *RunnerHealth) string {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	_, targets, err := m.Xray.BalancerTargets(cctx, render.BalancerOpen)
	if err != nil {
		if ctx.Err() == nil {
			r.Err = fmt.Sprintf("health: balancer: %v", err)
		}
		return ""
	}
	for _, t := range targets {
		for _, s := range members {
			if s.Tag() == t {
				return s.ID
			}
		}
	}
	return ""
}

// probe returns the end-to-end probe's result, running the probe when it is
// due: at the first check, and ProbeEvery after the last probe, give or take
// half an Interval. A ticker's checks come a few milliseconds early or late,
// and a probe that was 10 ms too early would wait a whole Interval more.
// While there is nothing to probe (watch is false: the runner is down or no
// server is enabled) there is no result, and the probe runs at the first
// check that has something to probe.
func (m *Monitor) probe(ctx context.Context, st store.State, now time.Time, watch bool) ProbeHealth {
	var check artifacts.HealthChecker
	if watch && m.Probe != nil {
		check = m.Probe(st)
	}
	if check == nil {
		m.probeRes, m.probeAt = ProbeHealth{}, time.Time{}
		return m.probeRes
	}
	if !m.probeAt.IsZero() && now.Sub(m.probeAt)+m.interval()/2 < m.probeEvery() {
		return m.probeRes
	}
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	err := check.Check(pctx)
	cancel()
	if ctx.Err() != nil {
		return m.probeRes // shutdown, not a failed probe
	}
	res := ProbeHealth{Ran: true, OK: err == nil, At: now.UTC()}
	if err != nil {
		res.Err = scrub(fmt.Sprintf("health: probe: %v", err), st.Health.ProbeURL)
	}
	m.probeRes, m.probeAt = res, now
	return res
}

// membersOf returns the servers that the balancers can pick, in the state's
// order: the enabled ones, or only the pinned one while a server is pinned.
// They are the servers the observatory probes.
func membersOf(st store.State) []store.Server {
	var out []store.Server
	for _, s := range st.Servers {
		// A state holding s alone has a proxy exactly when s is a member.
		if render.ProxyAvailable(store.State{Servers: []store.Server{s}, Routing: st.Routing}) {
			out = append(out, s)
		}
	}
	return out
}

// serverHealth returns the members' health from the observatory's answer, or,
// when polling it failed (obsErr), a dead server with that error each. A
// member that obs lacks has not been probed yet.
func serverHealth(members []store.Server, obs []xray.OutboundStatus, obsErr error) []ServerHealth {
	byTag := make(map[string]xray.OutboundStatus, len(obs))
	for _, o := range obs {
		byTag[o.Tag] = o
	}
	out := make([]ServerHealth, 0, len(members))
	for _, s := range members {
		h := ServerHealth{ID: s.ID}
		switch o, seen := byTag[s.Tag()]; {
		case obsErr != nil:
			h.LastError = obsErr.Error()
		case !seen:
			h.LastError = notObserved
		default:
			h.Alive, h.LastError, h.LastTry = o.Alive, o.LastError, o.LastTry.UTC()
			// xray gives a dead server a delay of 99999999 ms.
			if o.Alive {
				h.Delay = o.Delay
			}
		}
		out = append(out, h)
	}
	return out
}

// level decides the snapshot's level, in the order of the Level constants.
func level(live, proxy bool, servers []ServerHealth, probe ProbeHealth) string {
	switch {
	case !live:
		return LevelDown
	case !proxy:
		return LevelIdle
	case !slices.ContainsFunc(servers, func(s ServerHealth) bool { return s.Alive }):
		return LevelOutage
	case slices.ContainsFunc(servers, func(s ServerHealth) bool { return !s.Alive }), probe.Ran && !probe.OK:
		return LevelDegraded
	}
	return LevelOK
}

// scrub removes from msg the credentials in rawURL's userinfo, which the
// errors of a probe of rawURL may repeat. Strings shorter than 4 bytes are
// left alone, as the service's redactor does.
func scrub(msg, rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.User == nil {
		return msg
	}
	pw, _ := u.User.Password()
	for _, secret := range []string{u.User.String(), pw, u.User.Username()} {
		if len(secret) >= 4 {
			msg = strings.ReplaceAll(msg, secret, "‹redacted›")
		}
	}
	return msg
}
