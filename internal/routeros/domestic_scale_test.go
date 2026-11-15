package routeros

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

// A modest sparse geo list can have many more CIDRs in its complement than
// the entire native reply budget, even though very few rows are actually needed.
func TestGeoSparseTransitionRemainsObservable(t *testing.T) {
	const n = 4096
	pol := store.Policy{Mode: store.ModeSmart, KillSwitch: true}
	previous := policyView{LANList: "LAN", Sources: []sourceClass{{netip.MustParsePrefix("192.168.88.10/32"), pol}}}
	candidate := previous
	for i := 0; i < n; i++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], 0x44000001+uint32(i)<<12)
		candidate.Domestic = append(candidate.Domestic, netip.PrefixFrom(netip.AddrFrom4(b), 32))
	}
	holds := holdsFor([]policyView{previous, candidate})
	if len(holds) > n+2 {
		t.Fatalf("sparse change needs %d temporary rows for %d changed IPs", len(holds), n)
	}
	var protected []addrRange
	for _, o := range holds {
		if o.Menu == firewallFilter {
			if !strings.HasPrefix(o.Props["dst-address-list"], "!tikray-h") {
				t.Fatal("M3a emergency-off cannot recognize a temporary hold")
			}
			continue
		}
		if o.Menu != addressListMenu {
			t.Fatal("unexpected temporary menu")
		}
		addr := o.Props["address"]
		if p, e := netip.ParsePrefix(addr); e == nil {
			lo, hi := span(p)
			protected = append(protected, addrRange{lo, hi})
			continue
		}
		l, r, ok := strings.Cut(addr, "-")
		if !ok {
			t.Fatal("invalid interval")
		}
		protected = append(protected, addrRange{number(netip.MustParseAddr(l)), 1 + number(netip.MustParseAddr(r))})
	}
	// Verify the *exact* old/new exemption set, including the adjacent
	// unchanged IPs; a larger blanket hold would break other traffic.
	for _, p := range candidate.Domestic {
		n := number(p.Addr())
		for _, delta := range []int{-1, 0, 1} {
			probe := uint64(int64(n) + int64(delta))
			hit := false
			for _, r := range protected {
				if r.lo <= probe && probe < r.hi {
					hit = true
					break
				}
			}
			if hit != (delta != 0) {
				t.Fatal("hold covered a different destination set")
			}
		}
	}
}

// Require proof that the future native reads still fit before persisting
// or staging a candidate that cannot subsequently be observed.
func TestGeoCapacityRefusesBeforeJournalOrWrites(t *testing.T) {
	f := newDiffRouter()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(f, InstallScope{}, dir)
	e.observe = func(context.Context, Native, InstallScope) (Actual, error) { return f.actual(), nil }
	e.check = func(context.Context, Native, Actual, []policyView) error { return nil }
	e.purge = func(context.Context, Native, Actual, []policyView) (int, error) { return 0, nil }
	e.finalPurge = e.purge
	target := Target{Revision: 1, Policy: PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeSmart, KillSwitch: true}}, Verify: func(context.Context) error { return nil }, Selection: runnerapi.Selection{Core: "26.10.31", Config: "config/" + strings.Repeat("a", 64) + ".json"}}
	if _, err := e.Reconcile(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	baseline, err := os.ReadFile(e.file)
	if err != nil {
		t.Fatal(err)
	}
	before := len(f.writes)
	e.c = &fullAddressMenu{Native: f}
	target.WithdrawGeo = true
	target.Geo = []netip.Prefix{netip.MustParsePrefix("93.184.216.0/28")}
	if err := e.Prepare(t.Context(), target); err == nil {
		t.Fatal("accepted unobservable future address-list inventory")
	}
	now, err := os.ReadFile(e.file)
	if err != nil || !bytes.Equal(now, baseline) || len(f.writes) != before {
		t.Fatal("insufficient native capacity mutated the router or its journal")
	}
}

type fullAddressMenu struct{ Native }

func (p *fullAddressMenu) CommandAt(ctx context.Context, gen uint64, words []string) ([]Row, error) {
	if words[0] == addressListMenu+"/print" && slices.Contains(words, "=count-only=") {
		return []Row{{"ret": "24576"}}, nil
	}
	return p.Native.CommandAt(ctx, gen, words)
}

func TestLargeGeoObservationKeepsNativeQueriesBounded(t *testing.T) {
	p := &observationPeer{generation: 1, rows: map[string][]Row{}}
	const size = 4400
	for i := 0; i < size; i++ {
		ip := ipv4Number(0x44000001 + uint64(i)).String()
		p.rows[addressListMenu] = append(p.rows[addressListMenu], Row{".id": fmt.Sprintf("*%X", i+1), "address": ip, "comment": "tikray:domestic:" + ip + "/32", "list": "tikray-domestic"})
	}
	p.rows[addressListMenu] = append(p.rows[addressListMenu], Row{".id": "*ABCDEF", "comment": "owner:foreign", "list": "owner", "address": "192.0.2.1"})
	o := observation{ctx: t.Context(), c: p, gen: p.Generation()}
	rows, err := o.ownedRows(addressListMenu)
	if err != nil || len(rows) != size {
		t.Fatal("large native snapshot lost rows", err)
	}
	pages := 0
	for _, words := range p.queries {
		if words[0] != addressListMenu+"/print" {
			continue
		}
		if !slices.Contains(words, "?>comment=tikray:") || !slices.Contains(words, "?<comment=tikray;") {
			t.Fatal("unspecified native scope")
		}
		if slices.Contains(words, "=.proplist=.id") {
			continue
		}
		if !slices.ContainsFunc(words, func(w string) bool { return strings.HasPrefix(w, "?.id=") }) {
			t.Fatal("large native rows requested in a single unbounded print")
		}
		pages++
	}
	if pages < 2 {
		t.Fatal("positive native page witness missing")
	}
}

type replacedAddressPage struct {
	*observationPeer
	indexes int
}

func (p *replacedAddressPage) CommandAt(ctx context.Context, g uint64, words []string) ([]Row, error) {
	rows, err := p.observationPeer.CommandAt(ctx, g, words)
	if slices.Contains(words, "=.proplist=.id") && !slices.Contains(words, "=count-only=") {
		p.indexes++
		if p.indexes == 2 && len(rows) > 0 {
			// One new owner/tagged row replaced one earlier in the snapshot.
			// A repeated count alone cannot establish the observed set.
			rows[0][".id"] = "*DD0001"
		}
	}
	return rows, err
}
func TestGeoAddressPageRejectsChangedFinalIndex(t *testing.T) {
	p := &replacedAddressPage{observationPeer: &observationPeer{generation: 1, rows: map[string][]Row{}}}
	for i := 0; i < smallAddressReply+1; i++ {
		id := fmt.Sprintf("*%X", i+1)
		a := ipv4Number(0x46000001 + uint64(i)).String()
		p.rows[addressListMenu] = append(p.rows[addressListMenu], Row{".id": id, "list": "tikray-domestic", "comment": "tikray:domestic:" + a + "/32", "address": a})
	}
	o := observation{ctx: t.Context(), c: p, gen: 1}
	if _, err := o.ownedRows(addressListMenu); err == nil {
		t.Fatal("accepted same-size changed snapshot")
	}
}
