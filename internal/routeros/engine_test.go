package routeros

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

func TestAdmissionVerifiesHoldAfterPurge(t *testing.T) {
	f := newDiffRouter()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	e := NewEngine(f, InstallScope{}, dir)
	e.observe = func(context.Context, Native, InstallScope) (Actual, error) { return f.actual(), nil }
	e.check = func(context.Context, Native, Actual, []policyView) error { return nil }
	e.purge = func(context.Context, Native, Actual, []policyView) (int, error) {
		for i := range f.rows {
			if isHold(f.rows[i].Comment) && f.rows[i].Props["action"] == "drop" {
				f.rows[i].Props["disabled"] = "yes"
				break
			}
		}
		return 1, nil
	}
	target := Target{Revision: 1, Policy: PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeFull, KillSwitch: true}}}
	if err := e.Prepare(t.Context(), target); err == nil {
		t.Fatal("accepted missing protection after conntrack cleanup")
	}
}

func TestRejectedAdmissionRestoresPreviouslyVerifiedGuard(t *testing.T) {
	f := newDiffRouter()
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private fixture")
	}
	newSession := func() *Engine {
		e := NewEngine(f, InstallScope{}, dir)
		e.observe = func(context.Context, Native, InstallScope) (Actual, error) { return f.actual(), nil }
		e.check = func(context.Context, Native, Actual, []policyView) error { return nil }
		e.purge = func(context.Context, Native, Actual, []policyView) (int, error) { return 0, nil }
		e.finalPurge = e.purge
		return e
	}
	a := PolicyDevice{Address: netip.MustParsePrefix("10.20.0.6/32"), MAC: "02:00:00:00:00:06", Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}}
	b := a
	b.Address, b.MAC = netip.MustParsePrefix("10.20.0.7/32"), "02:00:00:00:00:07"
	target := Target{Revision: 1, Policy: PolicyInput{Network: store.Default().Network, Default: directPolicy, Devices: []PolicyDevice{a}}, Selection: runnerapi.Selection{Core: "26.10.31", Config: "config/" + strings.Repeat("a", 64) + ".json"}, Verify: func(context.Context) error { return nil }}
	if _, err := newSession().Reconcile(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	for i, r := range f.rows {
		if r.Menu == ipv6Filter && r.Props["action"] == "reject" {
			f.rows = append(f.rows[:i], f.rows[i+1:]...)
			break
		}
	}
	e := newSession()
	e.check = func(context.Context, Native, Actual, []policyView) error { return ErrIPv6FlowScope }
	e.purge = func(context.Context, Native, Actual, []policyView) (int, error) { return 0, ErrIPv6FlowScope }
	target.Revision++
	target.Policy.Devices = append(target.Policy.Devices, b)
	if err := e.Prepare(t.Context(), target); !errors.Is(err, ErrIPv6FlowScope) {
		t.Fatal("unprovable addition was accepted", err)
	}
	protected := false
	for _, r := range f.rows {
		if !isHold(r.Comment) || r.Props["action"] != "reject" {
			continue
		}
		if strings.EqualFold(r.Props["src-mac-address"], b.MAC) {
			t.Fatal("staged unapproved IPv6 restriction")
		}
		protected = protected || strings.EqualFold(r.Props["src-mac-address"], a.MAC)
	}
	if !protected {
		t.Fatal("verified client was exposed by an unrelated rejected edit")
	}
}

func TestRollbackPurgeIncludesConcurrentRepair(t *testing.T) {
	a := policyView{LANList: "verified"}
	b := policyView{LANList: "abandoned"}
	r := a
	r.RepairOnly = true
	p := pass{j: checkpoint{Revision: 1, Pending: []policyView{a, b, a, r, a}}, view: a, target: Target{Revision: 1}}
	vs := p.purgeViews()
	if len(vs) != 4 || vs[0].LANList != b.LANList || !vs[2].RepairOnly {
		t.Fatal("abandoned candidate or concurrent repair escaped cleanup")
	}
}

func TestSourceDriftInvalidatesOnlyThatPrefix(t *testing.T) {
	f := newDiffRouter()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	e := NewEngine(f, InstallScope{}, dir)
	e.observe = func(context.Context, Native, InstallScope) (Actual, error) { return f.actual(), nil }
	e.check = func(context.Context, Native, Actual, []policyView) error { return nil }
	var scopes []flowChange
	e.purge = func(_ context.Context, _ Native, _ Actual, vs []policyView) (int, error) {
		scopes = nil
		for i := 1; i < len(vs); i++ {
			scopes = append(scopes, flowChanges(vs[i-1], vs[i])...)
		}
		return 0, nil
	}
	e.finalPurge = e.purge
	target := Target{Revision: 1, Policy: PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeFull, KillSwitch: true}}, Selection: runnerapi.Selection{Core: "26.10.31", Config: "config/" + strings.Repeat("a", 64) + ".json"}, Verify: func(context.Context) error { return nil }}
	if _, err := e.Reconcile(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	var affected netip.Prefix
	for i, r := range f.rows {
		if r.Menu == addressListMenu && r.Props["list"] == "tikray-src-full-closed" {
			affected = netip.MustParsePrefix(r.Props["address"])
			f.rows = append(f.rows[:i], f.rows[i+1:]...)
			break
		}
	}
	scopes = nil
	if _, err := e.Reconcile(t.Context(), target); err != nil || len(scopes) != 1 || scopes[0].Source != affected {
		t.Fatal("closed-source drift left cached bypasses or reset unrelated prefixes", err)
	}
}

func TestReconcileRecoversJournalBeforeGuardRelease(t *testing.T) {
	f := newDiffRouter()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal("private fixture directory unavailable")
	}
	engine := NewEngine(f, InstallScope{}, dir)
	engine.check = func(context.Context, Native, Actual, []policyView) error { return nil }
	engine.observe = func(context.Context, Native, InstallScope) (Actual, error) { return f.actual(), nil }
	var purges int
	engine.purge = func(context.Context, Native, Actual, []policyView) (int, error) { purges++; return 0, nil }
	engine.finalPurge = engine.purge
	target := Target{Revision: 1, Policy: PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeFull, KillSwitch: true}}, Selection: runnerapi.Selection{Core: "26.10.31", Config: "config/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json"}, Verify: func(context.Context) error { return nil }}
	if e := engine.Prepare(t.Context(), target); e != nil {
		t.Fatal(e)
	}
	held := func() bool {
		for _, r := range f.rows {
			if isHold(r.Comment) {
				return true
			}
		}
		return false
	}
	if !held() || purges != 1 {
		t.Fatal("missing protection or initial invalidation")
	}
	// The control process dies before or during the xray trial.
	restarted := NewEngine(f, InstallScope{}, dir)
	restarted.observe = engine.observe
	restarted.purge = engine.purge
	restarted.finalPurge = engine.purge
	restarted.check = engine.check
	target.Verify = func(context.Context) error { return errors.New("selection changed") }
	if _, e := restarted.Reconcile(t.Context(), target); e == nil || !held() {
		t.Fatal("unverified selection released guard")
	}
	target.Verify = func(context.Context) error { return nil }
	if _, e := restarted.Reconcile(t.Context(), target); e != nil || held() {
		t.Fatal("verified transition did not finish", e)
	}
	writes, clears := len(f.writes), purges
	if _, e := restarted.Reconcile(t.Context(), target); e != nil || len(f.writes) != writes || purges != clears {
		t.Fatal("converged pass wrote or invalidated")
	}
}

func TestSelectionChangeDuringReleaseRestagesHolds(t *testing.T) {
	f := newDiffRouter()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	e := NewEngine(f, InstallScope{}, dir)
	e.check = func(context.Context, Native, Actual, []policyView) error { return nil }
	e.observe = func(context.Context, Native, InstallScope) (Actual, error) { return f.actual(), nil }
	e.purge = func(context.Context, Native, Actual, []policyView) (int, error) { return 0, nil }
	e.finalPurge = e.purge
	target := Target{Revision: 1, Policy: PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeFull, KillSwitch: true}}, Selection: runnerapi.Selection{Core: "26.10.31", Config: "config/" + strings.Repeat("a", 64) + ".json"}}
	if err := e.Prepare(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	var invalid bool
	f.afterWrite = func() {
		if strings.HasSuffix(f.writes[len(f.writes)-1][0], "/remove") {
			invalid = true
		}
	}
	target.Verify = func(context.Context) error {
		if invalid {
			return ErrUnavailable
		}
		return nil
	}
	if _, err := e.Reconcile(t.Context(), target); err == nil {
		t.Fatal("unverified selection was committed")
	}
	j, err := e.readJournal()
	if err != nil {
		t.Fatal(err)
	}
	outstanding, err := PlanHolds(f.actual(), holdsFor(j.Pending))
	if err != nil || len(outstanding) != 0 {
		t.Fatal("lost guard after a concurrent runner change")
	}
}

func TestFailedHoldRepairRepeatsProtectionProof(t *testing.T) {
	f := newDiffRouter()
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private directory")
	}
	e := NewEngine(f, InstallScope{}, dir)
	e.check = func(context.Context, Native, Actual, []policyView) error { return nil }
	e.observe = func(context.Context, Native, InstallScope) (Actual, error) { return f.actual(), nil }
	n := 0
	e.purge = func(context.Context, Native, Actual, []policyView) (int, error) { n++; return 0, nil }
	e.finalPurge = e.purge
	target := Target{Revision: 1, Policy: PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeFull, KillSwitch: true}}}
	if err := e.Prepare(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	for i := range f.rows {
		if isHold(f.rows[i].Comment) && f.rows[i].Props["action"] == "drop" {
			f.rows[i].Props["disabled"] = "yes"
			break
		}
	}
	f.lose = true
	if err := e.Prepare(t.Context(), target); err == nil {
		t.Fatal("lost acknowledgement was accepted")
	}
	f.lose = false
	if err := e.Prepare(t.Context(), target); err != nil || n != 2 {
		t.Fatal("a repaired guard reused the previous purge proof", err)
	}
}

func TestChangedConnectionKeepsGuardsAcrossFreshClassification(t *testing.T) {
	for _, mode := range []string{"verified", "damaged guard", "still changing"} {
		t.Run(mode, func(t *testing.T) {
			f := newDiffRouter()
			dir := t.TempDir()
			if os.Chmod(dir, 0700) != nil {
				t.Fatal("private state unavailable")
			}
			e := NewEngine(f, InstallScope{}, dir)
			snapshots, before, fresh := 0, 0, 0
			e.observe = func(context.Context, Native, InstallScope) (Actual, error) { snapshots++; return f.actual(), nil }
			e.check = func(context.Context, Native, Actual, []policyView) error { return nil }
			e.purge = func(context.Context, Native, Actual, []policyView) (int, error) {
				before = snapshots
				if mode == "damaged guard" {
					for i := range f.rows {
						if isHold(f.rows[i].Comment) && f.rows[i].Props["action"] == "drop" {
							f.rows[i].Props["disabled"] = "yes"
							break
						}
					}
				}
				return 0, errBindingChanged
			}
			e.finalPurge = func(context.Context, Native, Actual, []policyView) (int, error) {
				fresh++
				if snapshots <= before {
					t.Fatal("reclassified on a stale snapshot")
				}
				if mode == "still changing" {
					return 0, errBindingChanged
				}
				return 0, nil
			}
			target := Target{Revision: 1, Policy: PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeFull, KillSwitch: true}}}
			err := e.Prepare(t.Context(), target)
			if (err == nil) != (mode == "verified") || fresh > 1 || (fresh == 0) != (mode == "damaged guard") {
				t.Fatal("invalid admission, guard check, or retry bound")
			}
			j, e2 := e.readJournal()
			if e2 != nil || len(j.Pending) == 0 || j.Protected != (err == nil) {
				t.Fatal("unfinished guards were declared verified")
			}
		})
	}
}
