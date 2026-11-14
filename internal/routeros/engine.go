package routeros

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/Arman2122/tikray/internal/atomicfile"
)

type Engine struct {
	// Pure policy-engine callers can supply a topology without an installed
	// container bridge. The production Managed session must prove that bridge.
	managedBindings bool
	finalPurge      func(context.Context, Native, Actual, []policyView) (int, error)
	check           func(context.Context, Native, Actual, []policyView) error
	c               Native
	scope           InstallScope
	file            string
	gate            chan struct{}
	observe         func(context.Context, Native, InstallScope) (Actual, error)
	purge           func(context.Context, Native, Actual, []policyView) (int, error)
	mu              sync.RWMutex
	seen            map[string]bool
	seenGeneration  uint64
}

func NewEngine(c Native, scope InstallScope, stateDir string) *Engine {
	return &Engine{c: c, scope: scope, file: filepath.Join(stateDir, "router-policy.json"), gate: make(chan struct{}, 1), observe: Observe, purge: purgeFlows, finalPurge: purgeAfterSwitch, check: checkFlowScope}
}

type checkpoint struct {
	Version    int            `json:"version"`
	Verified   *policyView    `json:"verified,omitempty"`
	Policy     *PolicyInput   `json:"policy,omitempty"`
	Geo        []netip.Prefix `json:"geo,omitempty"`
	Revision   uint64         `json:"revision"`
	Pending    []policyView   `json:"pending,omitempty"`
	Protected  bool           `json:"protected,omitempty"`
	FinalPurge bool           `json:"final_purge,omitempty"`
	Emergency  bool           `json:"emergency,omitempty"`
}

func publicEngineError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrIPv6FlowScope):
		return ErrIPv6FlowScope
	case errors.Is(err, ErrPolicyConflict), errors.Is(err, errConflict), errors.Is(err, errPolicy), errors.Is(err, errTopology), errors.Is(err, errFastTrack), errors.Is(err, errIPv6Guard):
		return ErrPolicyConflict
	default:
		return ErrUnavailable
	}
}

func (e *Engine) lock(ctx context.Context) error {
	select {
	case e.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ErrUnavailable
	}
}
func (e *Engine) Snapshot(ctx context.Context) (Actual, error) {
	a, err := e.observe(ctx, e.c, e.scope)
	if err != nil {
		return Actual{}, publicEngineError(err)
	}
	ids := map[string]bool{}
	for _, r := range a.Rows {
		if ownedRole(r.Menu, r.Comment) {
			ids[r.Menu+r.ID] = true
		}
	}
	e.mu.Lock()
	e.seen = ids
	e.seenGeneration = a.Generation
	e.mu.Unlock()
	return a, nil
}

type emergencyFence struct {
	Native
	marker string
	verify func(context.Context) error
}

func (f emergencyFence) CommandAt(ctx context.Context, g uint64, w []string) ([]Row, error) {
	if !isRead(w) {
		if f.verify != nil && f.verify(ctx) != nil {
			return nil, ErrUnavailable
		}
		id, busy, err := EmergencyState(ctx, f.Native, g)
		if err != nil {
			return nil, err
		}
		if busy || id != f.marker {
			return nil, ErrPolicyConflict
		}
	}
	return f.Native.CommandAt(ctx, g, w)
}

func (e *Engine) readJournal() (checkpoint, error) {
	dir, err := os.Lstat(filepath.Dir(e.file))
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		return checkpoint{}, errPrivate
	}
	var j checkpoint
	ok, err := readPrivate(e.file, &j, 16<<20)
	if err != nil {
		return j, ErrPolicyConflict
	}
	if !ok {
		return checkpoint{Version: 1}, nil
	}
	if j.Version != 1 || len(j.Pending) == 1 || len(j.Pending) > 64 || j.Verified == nil && len(j.Pending) == 0 {
		return j, ErrPolicyConflict
	}
	if n := len(j.Pending); n > 0 && (j.Pending[0].RepairOnly || j.Pending[n-1].RepairOnly) {
		return j, ErrPolicyConflict
	}
	if (j.Verified == nil) != (j.Policy == nil) || j.Verified != nil && j.Verified.RepairOnly {
		return j, ErrPolicyConflict
	}
	if j.Policy != nil {
		if _, err := normalizePolicy(*j.Policy); err != nil {
			return j, ErrPolicyConflict
		}
		for _, prefix := range j.Geo {
			if !validPrefix(prefix) {
				return j, ErrPolicyConflict
			}
		}
	}
	views := append([]policyView(nil), j.Pending...)
	if j.Verified != nil {
		views = append(views, *j.Verified)
	}
	for _, v := range views {
		if !validView(v) || !e.scope.containsView(v) {
			return j, ErrPolicyConflict
		}
	}
	if len(j.Pending) > 0 && atomicfile.SyncDir(filepath.Dir(e.file)) != nil {
		return j, ErrUnavailable
	}
	return j, nil
}
func (e *Engine) save(j checkpoint) error {
	body, err := encodePrivate(j, 16<<20)
	if err != nil || atomicfile.WriteFile(e.file, body, 0600) != nil {
		return ErrUnavailable
	}
	return nil
}

type pass struct {
	a      Actual
	target Target
	rows   []Object
	view   policyView
	j      checkpoint
	holds  []Object
	fence  emergencyFence
	report Report
}

// A candidate can have a journal and guards even though its state write
// failed. Restoring the original, still-acknowledged revision does not
// require admitting that abandoned tightening.
func (p *pass) purgeViews() []policyView {
	vs := p.j.Pending
	if len(vs) > 2 && p.target.Revision == p.j.Revision && reflect.DeepEqual(vs[0], p.view) {
		for i := len(vs) - 2; i > 0; i-- {
			if !vs[i].RepairOnly && !reflect.DeepEqual(vs[i], p.view) {
				return vs[i:]
			}
		}
	}
	return vs
}
func (p *pass) account(ops []Op) {
	for _, op := range ops {
		switch op.Kind {
		case "add":
			p.report.Added++
		case "set":
			p.report.Set++
		case "move":
			p.report.Moved++
		case "remove":
			p.report.Removed++
		}
	}
}

// Each pass reads the observed generation again after mutation. A different
// generation invalidates the entire plan, including its native row IDs.
func (e *Engine) verify(ctx context.Context, p *pass) error {
	a, err := e.Snapshot(ctx)
	if err != nil {
		return err
	}
	if a.Generation != p.a.Generation {
		return ErrStaleGeneration
	}
	rows, err := Desired(p.target.Policy, a.Topology, p.target.Geo)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(rows, p.rows) {
		return errDrift
	}
	p.a = a
	return nil
}
func (e *Engine) sync(ctx context.Context, p *pass, holds bool, wanted []Object) (bool, error) {
	plan := Plan
	if holds {
		plan = PlanHolds
	}
	ops, err := plan(p.a, wanted)
	if err != nil {
		return false, err
	}
	if len(ops) == 0 {
		return false, nil
	}
	// Invalidate the persisted purge proof before the first repair write:
	// the router may execute that write and lose its acknowledgement.
	if len(p.j.Pending) > 0 && (holds && len(wanted) > 0 && p.j.Protected || !holds && p.j.FinalPurge) {
		if holds {
			p.j.Protected = false
		}
		p.j.FinalPurge = false
		if err = e.save(p.j); err != nil {
			return false, err
		}
	}
	if err = Execute(ctx, p.fence, p.a, ops); err != nil {
		return false, err
	}
	p.account(ops)
	if err = e.verify(ctx, p); err != nil {
		return true, err
	}
	remaining, err := plan(p.a, wanted)
	if err != nil {
		return true, err
	}
	if len(remaining) != 0 {
		return true, errDrift
	}
	return true, nil
}

// An old handle becoming unobservable is not proof that an accelerated
// binding went away. Keep the guards, verify them on a fresh topology, and
// classify the affected sources again. Only the fresh classification can
// select a new handle. Connections already on their target path survive.
func (e *Engine) cleanBindings(ctx context.Context, p *pass, final bool) (int, error) {
	clean := e.purge
	if final {
		clean = e.finalPurge
	}
	views := p.purgeViews()
	n, err := clean(ctx, p.fence, p.a, views)
	if !errors.Is(err, errBindingChanged) {
		return n, err
	}
	if err = e.verify(ctx, p); err != nil {
		return n, err
	}
	ops, err := PlanHolds(p.a, p.holds)
	if err != nil || len(ops) != 0 {
		return n, ErrUnavailable
	}
	if final {
		ops, err = Plan(p.a, p.rows)
		if err != nil || len(ops) != 0 {
			return n, ErrUnavailable
		}
	}
	// This second pass uses the stricter target-path check even during
	// preparation. A second ambiguous handle leaves the journal pending.
	m, err := e.finalPurge(ctx, p.fence, p.a, views)
	return n + m, err
}

func (e *Engine) prepare(ctx context.Context, t Target) (*pass, error) {
	p := &pass{target: t, report: Report{Revision: t.Revision}}
	var err error
	p.j, err = e.readJournal()
	if err != nil {
		return nil, err
	}
	if e.managedBindings {
		if err = ReconcileBindings(ctx, e.c, e.scope.Subnet, true); err != nil {
			return nil, err
		}
	}
	p.a, err = e.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	marker, busy, err := EmergencyState(ctx, e.c, p.a.Generation)
	if err != nil {
		return nil, err
	}
	if busy {
		return nil, ErrPolicyConflict
	}
	p.fence = emergencyFence{Native: e.c, marker: marker}
	p.rows, err = Desired(t.Policy, p.a.Topology, t.Geo)
	if err != nil {
		return nil, err
	}
	p.view = viewOf(p.rows, p.a.Topology)
	if p.j.Verified == nil && len(p.j.Pending) == 0 {
		for _, r := range p.a.Rows {
			if ownedRole(r.Menu, r.Comment) {
				return nil, ErrPolicyConflict
			}
		}
	}
	before := policyView{}
	if p.j.Verified != nil {
		before = *p.j.Verified
	}
	current := before
	if n := len(p.j.Pending); n > 0 {
		current = p.j.Pending[n-1]
	}
	// Stage newly requested tightening only after admission. Previously
	// accepted guards need restoration even when earlier traffic cannot
	// yet be proven safe to release.
	changed := false
	emergency := marker != "" && !p.j.Emergency
	if !reflect.DeepEqual(current, p.view) || emergency {
		if len(p.j.Pending) == 0 {
			p.j.Pending = []policyView{before}
		}
		admission := []policyView{current, p.view}
		if emergency {
			p.j.Pending = append(p.j.Pending, policyView{})
			admission = []policyView{{}, p.view}
			p.j.Emergency = true
		}
		if p.j.Verified == nil || p.target.Revision != p.j.Revision {
			if err = e.check(ctx, p.fence, p.a, admission); err != nil {
				// A rejected addition cannot leave damage to a previously
				// acknowledged client uncovered. Stage only the saved policy;
				// its purge may itself need evidence before it can finish.
				if p.j.Policy != nil && marker == "" && t.Revision != p.j.Revision {
					_, recovery := e.prepare(ctx, Target{Revision: p.j.Revision, Policy: *p.j.Policy, Geo: p.j.Geo})
					if recovery != nil {
						return nil, recovery
					}
				}
				return nil, err
			}
		}
		p.j.Pending = append(p.j.Pending, p.view)
		changed = true
	}
	if p.j.Verified != nil && marker == "" {
		ops, err := Plan(p.a, p.rows)
		if err != nil {
			return nil, err
		}
		if repair, needed := repairWindow(before, p.view, ops, p.a, p.j.Pending); needed {
			if len(p.j.Pending) == 0 {
				p.j.Pending = []policyView{before}
			}
			p.j.Pending = append(p.j.Pending, repair, p.view)
			changed = true
		}
	}
	if changed {
		if len(p.j.Pending) > 64 {
			return nil, ErrPolicyConflict
		}
		p.j.Protected = false
		p.j.FinalPurge = false
		if err = e.save(p.j); err != nil {
			return nil, err
		}
	}
	if len(p.j.Pending) == 0 {
		// A missing/corrupt transition record cannot authorize tearing down
		// existing protection.
		for _, r := range p.a.Rows {
			if isHold(r.Comment) {
				return nil, ErrPolicyConflict
			}
		}
		return p, nil
	}
	p.holds = holdsFor(p.j.Pending)
	wrote, err := e.sync(ctx, p, true, p.holds)
	if err != nil {
		return nil, err
	}
	if wrote || !p.j.Protected {
		p.j.Protected = false
		p.j.FinalPurge = false
		if err = e.save(p.j); err != nil {
			return nil, err
		}
		n, err := e.cleanBindings(ctx, p, false)
		if err != nil {
			return nil, err
		}
		if err = e.verify(ctx, p); err != nil {
			return nil, err
		}
		remaining, err := PlanHolds(p.a, p.holds)
		if err != nil || len(remaining) != 0 {
			return nil, ErrUnavailable
		}
		p.report.Invalidated += n
		p.j.Protected = true
		if err = e.save(p.j); err != nil {
			return nil, err
		}
	}
	return p, nil
}
func (e *Engine) Prepare(ctx context.Context, t Target) error {
	if err := e.lock(ctx); err != nil {
		return err
	}
	defer func() { <-e.gate }()
	_, err := e.prepare(ctx, t)
	return publicEngineError(err)
}
func (e *Engine) Reconcile(ctx context.Context, t Target) (Report, error) {
	if err := e.lock(ctx); err != nil {
		return Report{}, err
	}
	defer func() { <-e.gate }()
	p, err := e.prepare(ctx, t)
	if err != nil {
		return Report{}, publicEngineError(err)
	}
	verify := func() error {
		if t.Verify == nil || t.Verify(ctx) != nil {
			return ErrUnavailable
		}
		return nil
	}
	if len(p.view.Sources) > 0 && t.Selection.Validate() != nil {
		return p.report, ErrUnavailable
	}
	if err = verify(); err != nil {
		return p.report, err
	}
	changed, err := e.sync(ctx, p, false, p.rows)
	if err != nil {
		return p.report, publicEngineError(err)
	}
	if len(p.j.Pending) > 0 {
		if changed || !p.j.FinalPurge {
			n, err := e.cleanBindings(ctx, p, true)
			if err != nil {
				return p.report, publicEngineError(err)
			}
			p.report.Invalidated += n
			p.j.FinalPurge = true
			if err = e.save(p.j); err != nil {
				return p.report, err
			}
		}
		if err = e.verify(ctx, p); err != nil {
			return p.report, publicEngineError(err)
		}
		normal, err := Plan(p.a, p.rows)
		if err != nil || len(normal) > 0 {
			return p.report, ErrUnavailable
		}
		protected, err := PlanHolds(p.a, p.holds)
		if err != nil || len(protected) > 0 {
			return p.report, ErrUnavailable
		}
		if err = verify(); err != nil {
			return p.report, err
		}
		p.fence.verify = t.Verify
		_, err = e.sync(ctx, p, true, nil)
		p.fence.verify = nil
		if err != nil {
			e.restore(ctx, p)
			return p.report, publicEngineError(err)
		}
	}
	still, err := Plan(p.a, p.rows)
	if err != nil || len(still) != 0 {
		if len(p.j.Pending) > 0 {
			e.restore(ctx, p)
		}
		return p.report, ErrUnavailable
	}
	if err = verify(); err != nil {
		if len(p.j.Pending) > 0 {
			e.restore(ctx, p)
		}
		return p.report, err
	}
	if id := p.fence.marker; id != "" {
		if err = ClearEmergency(ctx, e.c, p.a.Generation, id); err != nil {
			return p.report, publicEngineError(err)
		}
	}
	if p.j.Verified == nil || len(p.j.Pending) > 0 || p.j.Revision != t.Revision {
		if err = e.save(checkpoint{Version: 1, Verified: &p.view, Policy: &t.Policy, Geo: t.Geo, Revision: t.Revision}); err != nil {
			return p.report, err
		}
	}
	return p.report, nil
}

func (e *Engine) Leases(ctx context.Context) ([]LeaseInfo, error) {
	a, err := e.Snapshot(ctx)
	return a.Leases, err
}
func (e *Engine) Watch(ctx context.Context, notify func()) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for _, menu := range managedMenus {
		if menu == routeMenu {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			words := append([]string{menu + "/listen", "=.proplist=.id,.dead,comment"}, prefixQuery("comment", "tikray:")...)
			_ = e.c.Listen(ctx, words, func(ch Change) {
				e.mu.RLock()
				seen := e.seenGeneration == ch.Generation && e.seen[menu+ch.Row[".id"]]
				e.mu.RUnlock()
				if ch.Kind != ChangeRow || ownedRole(menu, ch.Row["comment"]) || seen {
					notify()
				}
			})
		}()
	}
	wg.Wait()
	return ErrUnavailable
}

// If the runner changes during release, re-arm using fresh IDs and the
// durable intent. The emergency job/marker takes precedence over recovery.
func (e *Engine) restore(parent context.Context, p *pass) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 15*time.Second)
	defer cancel()
	a, err := e.Snapshot(ctx)
	if err != nil {
		return
	}
	marker, busy, err := EmergencyState(ctx, e.c, a.Generation)
	if err != nil || busy || marker != p.fence.marker {
		return
	}
	p.a = a
	_, _ = e.sync(ctx, p, true, p.holds)
}
