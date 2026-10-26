// Package service is tikray serve's core: it owns the desired state, keeps
// xray applied to the newest state through the runner's trial, records what
// it does as events, with every secret redacted, and reports its status.
//
// One goroutine, the apply loop, applies the state after each change (see
// Kick). It and the operations a caller starts (ApplyNow, CoreUpdate,
// CoreRollback) take one lock, so that only one of them runs at a time; a
// change made while one runs leads to another apply after it.
//
// A second goroutine, the scheduler, refreshes the subscriptions that are due
// (see RefreshSubscription and schedule). Run starts both.
package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/health"
	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/subscription"
	"github.com/Arman2122/tikray/internal/xrayver"
)

const (
	defaultDebounce = 2 * time.Second
	defaultRetry    = 10 * time.Second
	// maxRetry bounds the wait between retries, which doubles from Retry.
	maxRetry = 5 * time.Minute
	// statusTimeout bounds Status's call to the runner, so that a runner
	// that does not answer leaves the status unapplied soon.
	statusTimeout = 5 * time.Second
)

// LevelUnknown is Status.Health.Level until the monitor has checked once, or
// when the service has no monitor.
const LevelUnknown = "unknown"

// ErrRunnerUnavailable means the runner can't be reached: a call to it
// failed before it answered.
var ErrRunnerUnavailable = errors.New("service: the runner can't be reached")

// Runner is the part of the runner's control API the service uses itself.
// *runnerapi.Client implements it.
type Runner interface {
	Status(ctx context.Context) (runnerapi.Status, error)
	Test(ctx context.Context, config []byte) (runnerapi.TestResult, error)
}

// Updaters builds the CoreUpdater for a state and its revision: Render renders
// st, NoState is rev == 0 (a state never saved), and Health and ProxyHealth
// check the trial. The service sets Redact on what it returns, so the factory
// needn't. The service calls it from several goroutines at once (Status, the
// loop's pass, the operations), so it must be safe for that, and return a
// new CoreUpdater each time.
type Updaters func(st store.State, rev uint64) *artifacts.CoreUpdater

// Config is what New makes a service from. Store, Updaters, Runner and Data
// are required.
type Config struct {
	Store    *store.Store
	Updaters Updaters
	Runner   Runner
	// Monitor, if set, runs with Run, and gives Status its health. When its
	// State is nil, New sets it to read the service's state.
	Monitor *health.Monitor
	// Data is the data root: cores/ and state/ are in it.
	Data string
	// Debounce is how long the loop waits after a kick, for more of them,
	// before it applies; zero means 2 s.
	Debounce time.Duration
	// Retry is the first wait before the loop tries again after a failure
	// that may pass (the runner can't be reached, or another update holds
	// the artifacts lock). It doubles with each failure in a row, up to 5
	// minutes. Zero means 10 s.
	Retry time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Log gets a line for each event; nil drops them.
	Log io.Writer
	// Fetcher makes the fetcher that a subscription refresh downloads with,
	// for the state it refreshes in. A refresh sets its Accept itself. Nil
	// means a fetcher that goes direct, and through the runner's SOCKS
	// inbound at Socks when the monitor says the proxy works.
	Fetcher func(st store.State) subscription.Fetcher
	// Socks is the address (host:port) of the runner's SOCKS inbound, which
	// the default Fetcher takes its second attempt through. Empty means the
	// default Fetcher goes direct only.
	Socks string
}

// Service owns the desired state and keeps xray applied to it.
type Service struct {
	store    *store.Store
	updaters Updaters
	runner   Runner
	monitor  *health.Monitor
	data     string
	debounce time.Duration
	retry    time.Duration
	now      func() time.Time
	log      io.Writer

	// lock is held by the loop's pass, ApplyNow, CoreUpdate and CoreRollback
	// while each runs: a channel, so that a caller's context can end the
	// wait.
	lock chan struct{}
	// kicks holds a token while a kick is waiting for the loop.
	kicks   chan struct{}
	running atomic.Bool

	fetcher func(st store.State) subscription.Fetcher
	// refreshing holds a token while a subscription refresh runs: a channel,
	// so that a caller's context can end the wait.
	refreshing chan struct{}

	mu sync.Mutex // guards the fields below
	// kicked counts the kicks, and served is the count a pass that ended
	// had read when it started: the kicks up to it are served. retrying is
	// set while the loop waits to retry a pass.
	kicked, served uint64
	retrying       bool
	lastApply      *artifacts.Result
	// renderErr is the render error last recorded, so that Status records
	// each one once.
	renderErr string
	// holds is, by subscription ID, the time before which the scheduler
	// leaves a subscription whose refresh failed alone. It is in memory only.
	holds map[string]time.Time

	emu    sync.Mutex // guards events and seq, and orders the log's lines
	events []Event
	seq    uint64

	rmu    sync.Mutex // guards red and redRev
	red    func(string) string
	redRev uint64

	// after makes the loop's timers: a time.Timer's channel and Stop, or a
	// fake clock's in tests. Tests also set idle, called each time the loop
	// is about to wait, and onWait, called when an operation has to wait
	// for the lock. The scheduler has the same, schedAfter and schedIdle,
	// apart from the loop's, so that its timers are no part of the loop's.
	after      func(time.Duration) (<-chan time.Time, func() bool)
	idle       func()
	onWait     func()
	schedAfter func(time.Duration) (<-chan time.Time, func() bool)
	schedIdle  func()
}

// New makes a service from c. Every server that c.Store's Open disabled
// becomes a degraded event.
func New(c Config) (*Service, error) {
	switch {
	case c.Store == nil:
		return nil, errors.New("service: Config.Store is not set")
	case c.Updaters == nil:
		return nil, errors.New("service: Config.Updaters is not set")
	case c.Runner == nil:
		return nil, errors.New("service: Config.Runner is not set")
	case c.Data == "":
		return nil, errors.New("service: Config.Data is not set")
	}
	s := &Service{
		store:    c.Store,
		updaters: c.Updaters,
		runner:   c.Runner,
		monitor:  c.Monitor,
		data:     c.Data,
		debounce: orDefault(c.Debounce, defaultDebounce),
		retry:    orDefault(c.Retry, defaultRetry),
		now:      c.Now,
		log:      c.Log,
		lock:     make(chan struct{}, 1),
		kicks:    make(chan struct{}, 1),

		fetcher:    c.Fetcher,
		refreshing: make(chan struct{}, 1),
		holds:      map[string]time.Time{},
		after:      realTimer,
		schedAfter: realTimer,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.fetcher == nil {
		s.fetcher = defaultFetcher(c.Socks, c.Monitor)
	}
	if m := c.Monitor; m != nil && m.State == nil {
		m.State = func() store.State {
			st, _ := c.Store.State()
			return st
		}
	}
	st, _ := c.Store.State()
	for _, id := range c.Store.Degraded() {
		i := slices.IndexFunc(st.Servers, func(srv store.Server) bool { return srv.ID == id })
		if i < 0 {
			continue
		}
		srv := st.Servers[i]
		s.record(KindDegraded, fmt.Sprintf("server %s (%s) disabled: %s", srv.ID, srv.Name, srv.Invalid))
	}
	return s, nil
}

// Run runs the apply loop, the subscription scheduler and the monitor if
// there is one, until ctx ends, and returns nil once all have stopped. At the
// start, a state that was saved (its revision is above 0) and that the runner
// does not run, or that the runner can't be asked about, is applied as if
// kicked. Run refuses to run twice at once.
func (s *Service) Run(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("service: Run is already running")
	}
	defer s.running.Store(false)
	var wg sync.WaitGroup
	if s.monitor != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.monitor.Run(ctx)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.schedule(ctx)
	}()
	s.loop(ctx)
	wg.Wait()
	return nil
}

// State returns a copy of the state and its revision.
func (s *Service) State() (store.State, uint64) { return s.store.State() }

// Status is what the service reports of itself.
type Status struct {
	Revision uint64 `json:"revision"`
	// Applied: the render of the current state, for the runner's active core
	// and geo, is the runner's active config.
	Applied bool `json:"applied"`
	// Pending: the loop has an apply to make, waiting for the debounce or
	// for a retry, or making it now.
	Pending bool `json:"pending"`
	// LastApply is how the last apply ended, by the loop or by ApplyNow; nil
	// before the first.
	LastApply *artifacts.Result `json:"last_apply,omitempty"`
	// Core is the runner's active core, empty when it has none or can't be
	// reached, and CoreTested says whether the render is tested against it
	// (render.IsTested).
	Core       string `json:"core,omitempty"`
	CoreTested bool   `json:"core_tested"`
	// Health is the monitor's last check, its errors redacted. Its Level is
	// LevelUnknown before the first.
	Health health.Snapshot `json:"health"`
	// Degraded lists the IDs of the servers that are disabled because this
	// tikray refuses them (store.Server.Invalid), in state order.
	Degraded []string `json:"degraded"`
}

// Status reports the service's state. It asks the runner for its active
// selection, waiting 5 s at most, and renders the state to tell whether it
// is applied; a render that fails is recorded as an error event, once until
// it changes.
func (s *Service) Status(ctx context.Context) Status {
	st, rev := s.store.State()
	out := Status{Revision: rev, Health: s.health(), Degraded: []string{}}
	for _, srv := range st.Servers {
		if srv.Invalid != "" {
			out.Degraded = append(out.Degraded, srv.ID)
		}
	}
	s.mu.Lock()
	out.Pending = s.kicked != s.served || s.retrying
	if s.lastApply != nil {
		r := *s.lastApply
		out.LastApply = &r
	}
	s.mu.Unlock()

	rctx, cancel := context.WithTimeout(ctx, statusTimeout)
	rs, err := s.runner.Status(rctx)
	cancel()
	if err != nil || rs.Active == nil {
		return out
	}
	out.Core = rs.Active.Core
	if v, err := xrayver.Parse(out.Core); err == nil {
		out.CoreTested = render.IsTested(v)
	}
	name, err := configName(s.updater(st, rev), rs.Active)
	s.noteRender(rev, err, false)
	out.Applied = err == nil && name == rs.Active.Config
	return out
}

// health is the monitor's snapshot with its errors redacted: xray's
// observatory reports its own text, which can name a server's address or
// user.
func (s *Service) health() health.Snapshot {
	if s.monitor == nil {
		return health.Snapshot{Level: LevelUnknown, Servers: []health.ServerHealth{}}
	}
	snap := s.monitor.Snapshot()
	if snap.Level == "" {
		snap.Level = LevelUnknown
	}
	red := s.redactorNow()
	snap.Runner.Err = red(snap.Runner.Err)
	snap.Probe.Err = red(snap.Probe.Err)
	for i := range snap.Servers { // Snapshot's list is a copy
		snap.Servers[i].LastError = red(snap.Servers[i].LastError)
	}
	return snap
}

// CoreInfo is the runner's active core, the installed cores and the history
// of updates, rollbacks and applies.
type CoreInfo struct {
	// Active is the version of the runner's active core, empty when it has
	// none.
	Active string `json:"active"`
	// Slots are the installed cores, newest first (artifacts.ListCores).
	Slots []artifacts.Slot `json:"slots"`
	// History is state/core-history.jsonl, oldest first.
	History []artifacts.Result `json:"history"`
}

// Core reports the active core, the installed ones and the history. It fails
// with ErrRunnerUnavailable when the runner can't be reached.
func (s *Service) Core(ctx context.Context) (CoreInfo, error) {
	rs, err := s.runner.Status(ctx)
	if err != nil {
		return CoreInfo{}, s.runnerError(ctx, err)
	}
	info := CoreInfo{Slots: []artifacts.Slot{}}
	if rs.Active != nil {
		info.Active = rs.Active.Core
	}
	slots, err := artifacts.ListCores(filepath.Join(s.data, "cores"))
	if err != nil {
		return CoreInfo{}, s.redactError(fmt.Errorf("service: listing the cores: %w", err))
	}
	if slots != nil {
		info.Slots = slots
	}
	if info.History, err = artifacts.ReadHistory(s.data); err != nil {
		return CoreInfo{}, s.redactError(fmt.Errorf("service: reading the core history: %w", err))
	}
	return info, nil
}

// runnerError is err, from a call to the runner, redacted, and wrapped with
// ErrRunnerUnavailable when the call failed before the runner answered
// (net/http's *url.Error, or no token to send it with) and not because ctx
// ended.
func (s *Service) runnerError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	err = s.redactError(err)
	if unreachable(err) && ctx.Err() == nil {
		return fmt.Errorf("%w: %w", ErrRunnerUnavailable, err)
	}
	return err
}

// unreachable reports whether err is a call that failed before the server
// answered: net/http's call failed, or the runner's client had no token to
// send yet (runnerapi.ErrNoToken), which the runner makes when it starts.
func unreachable(err error) bool {
	var ue *url.Error
	return errors.As(err, &ue) || errors.Is(err, runnerapi.ErrNoToken)
}

// redactError returns err with its text redacted. The result unwraps to err,
// so that errors.Is and As still find what err wraps.
func (s *Service) redactError(err error) error {
	if err == nil {
		return nil
	}
	return &redactedError{err: err, text: s.redact(err.Error())}
}

type redactedError struct {
	err  error
	text string
}

func (e *redactedError) Error() string { return e.text }
func (e *redactedError) Unwrap() error { return e.err }

// realTimer is a time.Timer's channel and Stop.
func realTimer(d time.Duration) (<-chan time.Time, func() bool) {
	t := time.NewTimer(d)
	return t.C, t.Stop
}

// orDefault is v, or def when v is not positive.
func orDefault(v, def time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return def
}
