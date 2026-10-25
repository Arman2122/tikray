package runner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

const (
	defaultEarlyExit  = 10 * time.Second
	defaultMaxTrial   = time.Hour
	defaultBackoffMin = time.Second
	defaultBackoffMax = 30 * time.Second
	// backoffReset is how long xray must have run for its crash to restart
	// the backoff from BackoffMin.
	backoffReset = time.Minute
)

// ErrInvalidCandidate is wrapped around every reason Trial refuses
// candidate.json before testing it.
var ErrInvalidCandidate = errors.New("runner: invalid candidate")

var errClosed = errors.New("runner: closed")

// Config configures a Runner. Zero values take the defaults.
type Config struct {
	Supervisor SupervisorConfig
	// EarlyExit (10 s) is how long the control plane waits before it
	// health-checks a candidate. Any exit during a trial reverts; the runner
	// only notes in the result whether the exit came this early.
	EarlyExit time.Duration
	// MaxTrial (1 h) caps how long a trial may last, whatever its deadline.
	MaxTrial time.Duration
	// BackoffMin and BackoffMax (1 s, 30 s) bound the wait before a crashed
	// xray is restarted. It doubles with each crash and starts again from
	// BackoffMin after a run of a minute.
	BackoffMin, BackoffMax time.Duration
	// Now (time.Now) is the wall clock, read only to turn a deadline into a
	// duration and to stamp trial results.
	Now func() time.Time
}

// Runner keeps xray running from active.json and runs the trial protocol. One
// goroutine owns its state: the methods hand it requests and wait for the
// answer, so trials, commits, exits, the deadline and restarts never overlap.
type Runner struct {
	cfg  Config
	sup  *Supervisor
	reqs chan request
	quit chan struct{}
	done chan struct{}
	once sync.Once

	// Owned by the loop goroutine.
	v        view
	booted   bool
	deadline *time.Timer // of the open trial
	restart  *time.Timer // the backoff before a restart
	backoff  time.Duration
	versions map[string]string // xray version by core
	closeErr error

	mu                  sync.Mutex // guards what Status reads
	pub                 view
	routesOK, gatewayUp bool
}

// view is the part of the loop's state that Status shows.
type view struct {
	state   string
	active  *runnerapi.Selection // mirrors active.json
	cand    *runnerapi.Candidate // the open trial
	running *runnerapi.Selection // what the current xray runs; nil when none should
	version string               // xray version of running
	last    *runnerapi.TrialResult
}

type request struct {
	fn    func() error
	reply chan error
}

// New returns a runner with nothing running. Call Boot to start xray.
func New(c Config) *Runner {
	if c.EarlyExit <= 0 {
		c.EarlyExit = defaultEarlyExit
	}
	if c.MaxTrial <= 0 {
		c.MaxTrial = defaultMaxTrial
	}
	if c.BackoffMin <= 0 {
		c.BackoffMin = defaultBackoffMin
	}
	if c.BackoffMax <= 0 {
		c.BackoffMax = defaultBackoffMax
	}
	c.BackoffMax = max(c.BackoffMax, c.BackoffMin)
	if c.Now == nil {
		c.Now = time.Now
	}
	r := &Runner{
		cfg:      c,
		sup:      NewSupervisor(c.Supervisor),
		reqs:     make(chan request),
		quit:     make(chan struct{}),
		done:     make(chan struct{}),
		v:        view{state: runnerapi.StateEmpty},
		versions: map[string]string{},
	}
	r.publish()
	go r.loop()
	return r
}

// Boot ends a trial that was open when the runner stopped, then starts
// active.json, or stays empty without one. An unreadable active.json is
// returned as an error and leaves the runner empty but usable.
func (r *Runner) Boot() error { return r.do(context.Background(), r.boot) }

// Trial tests candidate.json with xray run -test and switches to it. It
// returns once the candidate runs; the trial then lasts until Commit, Abort,
// the deadline or the candidate's exit. A second trial gets ErrBusy, a bad
// candidate.json ErrInvalidCandidate, and a config xray rejects, or a test
// that outlasts the trial's deadline, a *runnerapi.TestFailedError, with the
// active xray left running.
func (r *Runner) Trial(ctx context.Context) error {
	return r.do(ctx, func() error { return r.trial(ctx) })
}

// Commit makes the running candidate the active selection without restarting
// it. Outside a trial it returns ErrNoTrial.
func (r *Runner) Commit() error { return r.do(context.Background(), r.commit) }

// Abort ends the trial and reverts. Outside a trial it returns ErrNoTrial.
func (r *Runner) Abort() error {
	return r.do(context.Background(), func() error {
		if r.v.state != runnerapi.StateTrial {
			return runnerapi.ErrNoTrial
		}
		r.revert(runnerapi.OutcomeAborted, "")
		return nil
	})
}

// Restart restarts xray from the active selection. During a trial it
// returns ErrBusy.
func (r *Runner) Restart(ctx context.Context) error {
	return r.do(ctx, func() error {
		if r.v.state == runnerapi.StateTrial {
			return runnerapi.ErrBusy
		}
		if r.v.active == nil {
			return errors.New("runner: restart: no active selection")
		}
		r.backoff = 0
		return r.startActive()
	})
}

// Reload re-reads active.json and starts it; without one xray is stopped.
// During a trial it returns ErrBusy.
func (r *Runner) Reload(ctx context.Context) error {
	return r.do(ctx, func() error {
		if r.v.state == runnerapi.StateTrial {
			return runnerapi.ErrBusy
		}
		a, err := ReadActive(r.dirs())
		if err != nil {
			return err
		}
		r.v.active = a
		r.backoff = 0
		return r.startActive()
	})
}

// Status reports the runner's state. It never waits for the runner's
// goroutine, so a slow xray run -test does not hold it up.
func (r *Runner) Status() runnerapi.Status {
	r.mu.Lock()
	v, routesOK, gatewayUp := r.pub, r.routesOK, r.gatewayUp
	r.mu.Unlock()
	st := runnerapi.Status{
		State:     v.state,
		Active:    clone(v.active),
		Candidate: clone(v.cand),
		XrayPID:   r.sup.PID(),
		RoutesOK:  routesOK,
		GatewayUp: gatewayUp,
		LastTrial: clone(v.last),
	}
	if st.XrayPID > 0 {
		st.XrayVersion = v.version
	}
	return st
}

// SetNet records the network state that Status reports.
func (r *Runner) SetNet(routesOK, gatewayUp bool) {
	r.mu.Lock()
	r.routesOK, r.gatewayUp = routesOK, gatewayUp
	r.mu.Unlock()
}

// Healthy reports whether xray runs in state running or trial.
func (r *Runner) Healthy() bool {
	r.mu.Lock()
	state := r.pub.state
	r.mu.Unlock()
	return (state == runnerapi.StateRunning || state == runnerapi.StateTrial) && r.sup.PID() > 0
}

// RunningBinary is the staged core of the xray running now: the candidate
// during a trial, otherwise the active one. ok is false when none runs.
func (r *Runner) RunningBinary() (path string, ok bool) {
	r.mu.Lock()
	sel := r.pub.running
	r.mu.Unlock()
	if sel == nil || r.sup.PID() == 0 {
		return "", false
	}
	return r.sup.stagedPath(*sel), true
}

// Close stops xray and the runner's goroutine. An open trial stays in
// candidate.json for the next Boot.
func (r *Runner) Close() error {
	r.once.Do(func() { close(r.quit) })
	<-r.done
	return r.closeErr
}

// do runs fn on the loop goroutine and returns its result. A request that has
// not reached the loop when ctx ends is dropped.
func (r *Runner) do(ctx context.Context, fn func() error) error {
	reply := make(chan error, 1)
	select {
	case r.reqs <- request{fn: fn, reply: reply}:
		return <-reply
	case <-ctx.Done():
		return ctx.Err()
	case <-r.done:
		return errClosed
	}
}

func (r *Runner) loop() {
	defer close(r.done)
	for {
		select {
		case req := <-r.reqs:
			r.settle()
			err := req.fn()
			r.publish()
			req.reply <- err
			continue
		case e := <-r.sup.Exits():
			r.onExit(e)
		case <-timerC(r.deadline):
			r.deadline = nil
			r.revert(runnerapi.OutcomeDeadline, "no commit before the deadline")
		case <-timerC(r.restart):
			r.restart = nil
			if err := r.startActive(); err != nil {
				log.Printf("runner: %v", err)
			}
		case <-r.quit:
			stopTimer(&r.deadline)
			stopTimer(&r.restart)
			r.closeErr = r.sup.Stop()
			return
		}
		r.publish()
	}
}

func (r *Runner) publish() {
	r.mu.Lock()
	r.pub = r.v
	r.mu.Unlock()
}

func (r *Runner) dirs() Dirs { return r.cfg.Supervisor.Dirs }

func (r *Runner) boot() error {
	if r.booted {
		return errors.New("runner: Boot called twice")
	}
	r.booted = true
	d := r.dirs()
	active, aerr := ReadActive(d)
	r.v.active = active
	last, err := ReadLastTrial(d)
	if err != nil {
		log.Printf("runner: ignoring last-trial.json: %v", err)
	}
	r.v.last = last
	cerr := r.resolveCandidate()
	if err := r.startActive(); err != nil {
		log.Printf("runner: %v", err)
	}
	r.cleanStage()
	return errors.Join(aerr, cerr)
}

// resolveCandidate ends a trial that was open when the runner stopped. A
// candidate equal to active.json is what a commit interrupted after its
// rename leaves behind, so it goes silently; any other is a reboot.
func (r *Runner) resolveCandidate() error {
	d := r.dirs()
	cand, err := ReadCandidate(d)
	switch {
	case err != nil:
		log.Printf("runner: removing an invalid candidate.json: %v", err)
	case cand == nil:
		return nil
	case r.v.active != nil && cand.Selection == *r.v.active:
	default:
		r.record(*cand, runnerapi.OutcomeReboot, "the runner restarted during the trial")
	}
	return RemoveCandidate(d)
}

func (r *Runner) trial(ctx context.Context) error {
	if r.v.state == runnerapi.StateTrial {
		return runnerapi.ErrBusy
	}
	cand, err := ReadCandidate(r.dirs())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCandidate, err)
	}
	if cand == nil {
		return fmt.Errorf("%w: no %s", ErrInvalidCandidate, r.dirs().CandidateFile())
	}
	window := min(cand.Deadline.Sub(r.cfg.Now()), r.cfg.MaxTrial)
	if window <= 0 {
		return fmt.Errorf("%w: deadline %s is not in the future", ErrInvalidCandidate, cand.Deadline.Format(time.RFC3339))
	}
	// The deadline becomes a monotonic timer here and is never compared with
	// the wall clock again, so a clock jump neither ends the trial early nor
	// keeps it open.
	deadline := time.NewTimer(window)
	// The loop supervises the active xray, so -test may not hold it for
	// longer than the trial could last: a test that outlasts the window is
	// a rejection.
	tctx, cancel := context.WithTimeout(ctx, window)
	out, err := r.sup.Test(tctx, cand.Selection)
	timedOut := tctx.Err() != nil
	cancel()
	if cerr := ctx.Err(); cerr != nil {
		deadline.Stop()
		return fmt.Errorf("runner: trial: %w", cerr)
	}
	if err != nil {
		deadline.Stop()
		switch {
		case timedOut:
			out = fmt.Sprintf("xray run -test did not finish within the trial's %s\n%s", window, out)
		case out == "":
			out = err.Error()
		}
		if err := RemoveCandidate(r.dirs()); err != nil {
			log.Printf("runner: %v", err)
		}
		r.record(*cand, runnerapi.OutcomeRejected, out)
		r.cleanStage()
		return &runnerapi.TestFailedError{Output: out}
	}

	stopTimer(&r.restart)
	drainExits(r.sup) // older processes' exits must not end the trial
	r.v.state, r.v.cand, r.deadline = runnerapi.StateTrial, cand, deadline
	if err := r.start(cand.Selection); err != nil {
		r.revert(runnerapi.OutcomeExited, "could not start: "+err.Error())
		return fmt.Errorf("runner: start candidate: %w", err)
	}
	log.Printf("runner: trial of core %s for %s", cand.Core, window)
	return nil
}

func (r *Runner) commit() error {
	if r.v.state != runnerapi.StateTrial {
		return runnerapi.ErrNoTrial
	}
	cand := *r.v.cand
	if err := WriteActive(r.dirs(), cand.Selection); err != nil {
		return fmt.Errorf("runner: commit: %w", err)
	}
	// active.json now names the candidate: the commit has happened, and a
	// candidate.json left behind is removed silently at the next boot.
	stopTimer(&r.deadline)
	sel := cand.Selection
	r.v.state, r.v.active, r.v.cand = runnerapi.StateRunning, &sel, nil
	r.backoff = 0
	if err := RemoveCandidate(r.dirs()); err != nil {
		log.Printf("runner: %v", err)
	}
	r.record(cand, runnerapi.OutcomeCommitted, "")
	r.cleanStage()
	return nil
}

// revert ends the open trial: it stops the candidate, removes candidate.json,
// starts active.json (or goes empty without one) and records the outcome.
func (r *Runner) revert(outcome, detail string) {
	cand := *r.v.cand
	stopTimer(&r.deadline)
	r.v.cand, r.v.running = nil, nil
	if err := r.sup.Stop(); err != nil {
		log.Printf("runner: %v", err)
	}
	if err := RemoveCandidate(r.dirs()); err != nil {
		log.Printf("runner: %v", err)
	}
	if err := r.startActive(); err != nil {
		log.Printf("runner: %v", err)
	}
	r.record(cand, outcome, detail)
	r.cleanStage()
}

// cleanStage removes the staged cores that neither run nor are active, and
// the leftovers of interrupted staging (see Supervisor.CleanStage). Every
// core takes about 30 MB of the container's disk, and nothing else removes
// them. It runs on the loop between trials, when nothing stages or tests.
func (r *Runner) cleanStage() {
	var keep []string
	for _, sel := range []*runnerapi.Selection{r.v.active, r.v.running} {
		if sel != nil {
			keep = append(keep, sel.Core)
		}
	}
	if err := r.sup.CleanStage(keep...); err != nil {
		log.Printf("%v", err)
	}
}

// startActive starts the active selection, or stops xray when there is none.
// When the start fails with nothing left running, it retries after a backoff.
func (r *Runner) startActive() error {
	stopTimer(&r.restart)
	if r.v.active == nil {
		r.v.state, r.v.running = runnerapi.StateEmpty, nil
		return r.sup.Stop()
	}
	if err := r.start(*r.v.active); err != nil {
		if r.sup.PID() == 0 {
			r.v.running = nil
			r.scheduleRestart(0)
		}
		return err
	}
	r.v.state = runnerapi.StateRunning
	return nil
}

func (r *Runner) start(sel runnerapi.Selection) error {
	if err := r.sup.Start(sel); err != nil {
		return err
	}
	r.v.running = &sel
	r.v.version = r.versionOf(sel)
	return nil
}

func (r *Runner) versionOf(sel runnerapi.Selection) string {
	if v, ok := r.versions[sel.Core]; ok {
		return v
	}
	v, err := r.sup.Version(sel)
	if err != nil {
		log.Printf("runner: %v", err)
		return ""
	}
	r.versions[sel.Core] = v
	return v
}

// onExit handles an exit of the xray process the runner believes runs. Exits
// carry no process identity, so one is believed only when its selection is
// the running one and no xray runs now: a process that is still up cannot be
// the one that exited.
func (r *Runner) onExit(e Exit) {
	if r.v.running == nil || e.Selection != *r.v.running || r.sup.PID() != 0 {
		return
	}
	detail := exitDetail(e, r.cfg.EarlyExit)
	if r.v.state == runnerapi.StateTrial {
		r.revert(runnerapi.OutcomeExited, detail)
		return
	}
	log.Printf("runner: xray core %s %s", e.Selection.Core, detail)
	r.v.running = nil
	r.scheduleRestart(e.Ran)
}

// settle handles exits that are already pending, and a candidate that died
// before its exit arrived, so that no request acts on a dead candidate.
func (r *Runner) settle() {
	for drained := false; !drained; {
		select {
		case e := <-r.sup.Exits():
			r.onExit(e)
		default:
			drained = true
		}
	}
	if r.v.state == runnerapi.StateTrial && r.sup.PID() == 0 {
		r.revert(runnerapi.OutcomeExited, "the candidate exited")
	}
}

func (r *Runner) scheduleRestart(ran time.Duration) {
	var delay time.Duration
	delay, r.backoff = nextBackoff(r.backoff, ran, r.cfg)
	r.v.state = runnerapi.StateRestarting
	stopTimer(&r.restart)
	r.restart = time.NewTimer(delay)
	log.Printf("runner: restarting xray in %s", delay)
}

// nextBackoff returns the wait before a restart and the wait to use after the
// next crash. ran is how long the crashed xray ran.
func nextBackoff(cur, ran time.Duration, c Config) (delay, next time.Duration) {
	delay = cur
	if delay < c.BackoffMin || ran >= backoffReset {
		delay = c.BackoffMin
	}
	return delay, min(2*delay, c.BackoffMax)
}

func (r *Runner) record(cand runnerapi.Candidate, outcome, detail string) {
	res := runnerapi.TrialResult{Candidate: cand, Outcome: outcome, Detail: detail, At: r.cfg.Now()}
	r.v.last = &res
	if err := WriteLastTrial(r.dirs(), res); err != nil {
		log.Printf("runner: %v", err)
	}
	if detail != "" {
		outcome += ": " + detail
	}
	log.Printf("runner: trial of core %s: %s", cand.Core, outcome)
}

// clone copies *p, so that a caller cannot change the runner's state.
func clone[T any](p *T) *T {
	if p == nil {
		return nil
	}
	c := *p
	return &c
}

func exitDetail(e Exit, early time.Duration) string {
	how := "exit status 0"
	if e.Err != nil {
		how = e.Err.Error()
	}
	d := "ran " + e.Ran.Round(time.Millisecond).String()
	if e.Ran < early {
		d += ", within the " + early.String() + " early-exit window"
	}
	return d + ": " + how
}

func drainExits(s *Supervisor) {
	for {
		select {
		case <-s.Exits():
		default:
			return
		}
	}
}

func timerC(t *time.Timer) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}

func stopTimer(t **time.Timer) {
	if *t != nil {
		(*t).Stop()
		*t = nil
	}
}
