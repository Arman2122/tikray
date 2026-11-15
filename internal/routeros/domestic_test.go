package routeros

import (
	"context"
	"errors"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"maps"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

func TestDomesticDiffOnlyChangedRanges(t *testing.T) {
	f := newDiffRouter()
	manual := netip.MustParsePrefix("198.51.100.0/24")
	shared := netip.MustParsePrefix("203.0.113.0/25")
	oldOnly := netip.MustParsePrefix("192.0.2.0/26")
	newOnly := netip.MustParsePrefix("192.0.2.64/26")
	policy := PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeSmart, KillSwitch: true}, Domestic: []netip.Prefix{manual}}
	previous := []netip.Prefix{shared, oldOnly, manual}
	candidate := []netip.Prefix{newOnly, shared}

	// Drive the same compiler, planner, and native executor used by Reconcile.
	sync := func(prefixes []netip.Prefix) error {
		t.Helper()
		a := f.actual()
		want, err := Desired(policy, a.Topology, prefixes)
		if err != nil {
			t.Fatal(err)
		}
		ops, err := Plan(a, want)
		if err != nil {
			return err
		}
		return Execute(t.Context(), f, a, ops)
	}
	members := func() map[netip.Prefix]string {
		t.Helper()
		ids := make(map[netip.Prefix]string)
		for _, r := range f.rows {
			if r.Menu != addressListMenu || r.Props["list"] != "tikray-domestic" {
				continue
			}
			p := netip.MustParsePrefix(r.Props["address"])
			if r.Comment != "tikray:domestic:"+p.String() || r.ID == "" || ids[p] != "" {
				t.Fatal("duplicate or unowned domestic member")
			}
			ids[p] = r.ID
		}
		return ids
	}
	if err := sync(previous); err != nil {
		t.Fatal(err)
	}
	initial := members()
	if len(initial) != 3 || initial[manual] == "" || initial[shared] == "" || initial[oldOnly] == "" {
		t.Fatal("previous geo and manual ranges were not installed")
	}

	// Preserve both sources of existing exemptions, even when the next
	// bundle stops listing the prefix still configured by the owner.
	for _, tc := range []struct {
		prefixes    []netip.Prefix
		add, remove netip.Prefix
	}{
		{candidate, newOnly, oldOnly},
		{previous, oldOnly, newOnly},
	} {
		before := members()
		f.writes = nil
		if err := sync(tc.prefixes); err != nil {
			t.Fatal(err)
		}
		after := members()
		counts := make(map[string]int)
		for _, words := range f.writes {
			counts[words[0]]++
			if words[0] == addressListMenu+"/remove" && !slices.Contains(words, "=.id="+before[tc.remove]) {
				t.Fatal("removed an unchanged row")
			}
		}
		if !maps.Equal(counts, map[string]int{addressListMenu + "/add": 1, addressListMenu + "/remove": 1}) {
			t.Fatalf("expected one add and one remove, got %v", counts)
		}
		if len(after) != 3 || after[manual] != initial[manual] || after[shared] != initial[shared] || after[tc.add] == "" || after[tc.remove] != "" {
			t.Fatal("geo diff did not preserve the exact retained rows")
		}
		f.writes = nil
		if err := sync(tc.prefixes); err != nil || len(f.writes) != 0 {
			t.Fatal("repeating the same bundle wrote to the router", err)
		}
	}

	f.insert(addressListMenu, "owner:exception", map[string]string{"list": "tikray-domestic", "address": newOnly.String()})
	before := f.actual()
	if err := sync(candidate); !errors.Is(err, errConflict) || len(f.writes) != 0 {
		t.Fatal("shared domestic list did not refuse before mutation", err)
	}
	if !reflect.DeepEqual(f.rows, before.Rows) {
		t.Fatal("foreign member or installation changed on refusal")
	}
}

// The runner still uses A until its trial commits. Preparation can withdraw
// an exemption, but neither a new exemption nor a released hold is safe yet.
func TestGeoPrepareWithdrawsBeforeTrial(t *testing.T) {
	f := newDiffRouter()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(f, InstallScope{}, dir)
	e.observe = func(context.Context, Native, InstallScope) (Actual, error) { return f.actual(), nil }
	e.purge = func(context.Context, Native, Actual, []policyView) (int, error) { return 0, nil }
	e.finalPurge = e.purge
	e.check = func(context.Context, Native, Actual, []policyView) error { return nil }
	a, b, c := netip.MustParsePrefix("93.184.216.0/27"), netip.MustParsePrefix("93.184.216.64/27"), netip.MustParsePrefix("93.184.216.128/27")
	target := Target{Revision: 1, Selection: runnerapi.Selection{Core: "26.10.31", Geo: "a", Config: "config/" + strings.Repeat("a", 64) + ".json"}, Geo: []netip.Prefix{a, b}, Policy: PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeSmart, KillSwitch: true}}, Verify: func(context.Context) error { return nil }}
	if _, err := e.Reconcile(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	id := func(p netip.Prefix) string {
		for _, r := range f.rows {
			if r.Comment == "tikray:domestic:"+p.String() {
				return r.ID
			}
		}
		return ""
	}
	held := func() bool {
		for _, r := range f.rows {
			if isHold(r.Comment) {
				return true
			}
		}
		return false
	}
	shared := id(b)
	if id(a) == "" || shared == "" || id(c) != "" {
		t.Fatal("initial ranges missing")
	}
	target.Selection.Geo = "b"
	target.Geo = []netip.Prefix{b, c}
	target.WithdrawGeo = true
	if err := e.Prepare(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	if id(a) != "" || id(b) != shared || id(c) != "" || !held() {
		t.Fatal("pre-trial diff did not withdraw only the obsolete exemption under guard")
	}
	if err := e.Prepare(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	target.WithdrawGeo = false
	if _, err := e.Reconcile(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	if id(a) != "" || id(b) != shared || id(c) == "" || held() {
		t.Fatal("committed diff did not preserve the shared row and finish the switch")
	}
	// Normal state edits can prepare during a runner outage. The verified
	// set is available in the native journal even after a process restart.
	writes := len(f.writes)
	target.Geo = nil
	target.KeepGeo = true
	if err := e.Prepare(t.Context(), target); err != nil || len(f.writes) != writes {
		t.Fatal("ordinary prepare interpreted unknown geo as an empty set", err)
	}
}
