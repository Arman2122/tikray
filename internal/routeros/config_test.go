package routeros

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

func TestManagedInstallMissingAndMalformed(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, "state")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("fixture")
	}
	if m, e := OpenManaged(data); e != nil || m != nil {
		t.Fatal("standalone mode unavailable")
	}
	if os.WriteFile(filepath.Join(dir, "router-policy.json"), []byte("{}"), 0600) != nil {
		t.Fatal("fixture")
	}
	if m, e := OpenManaged(data); e == nil || m != nil {
		t.Fatal("missing config silently bypassed managed policy")
	}
	o := compilerTopology()
	in := Installation{Version: 1, Address: o.Subnet.Addr().Next().String() + ":8729", Username: "tikray", Password: "private fixture", Fingerprint: strings.Repeat("00", 32), Scope: InstallScope{Subnet: o.Subnet, LANList: o.LANList, LANs: o.LANs, WAN: o.WAN[0]}}
	file := filepath.Join(dir, "routeros.json")
	body, _ := json.Marshal(in)
	os.WriteFile(file, body, 0600)
	if m, e := OpenManaged(data); e != nil || m == nil {
		t.Fatal("valid installation refused")
	}
	in.Scope.LANs[0].Prefix = in.Scope.Subnet
	body, _ = json.Marshal(in)
	os.WriteFile(file, body, 0600)
	if m, e := OpenManaged(data); e == nil || m != nil || strings.Contains(e.Error(), in.Password) {
		t.Fatal("invalid scope accepted or exposed")
	}
}

func TestJournalRequiresInstalledScopeAndCompleteEdges(t *testing.T) {
	top := compilerTopology()
	e := NewEngine(newDiffRouter(), InstallScope{Subnet: top.Subnet, LANs: top.LANs, LANList: top.LANList}, t.TempDir())
	if os.Chmod(filepath.Dir(e.file), 0700) != nil {
		t.Fatal("fixture")
	}
	pol := store.Policy{Mode: store.ModeFull, KillSwitch: true}
	v := policyView{LANList: top.LANList, Sources: []sourceClass{{netip.MustParsePrefix("10.20.0.6/32"), pol}}}
	for _, tc := range []string{"unterminated repair", "foreign scope", "foreign LAN list"} {
		t.Run(tc, func(t *testing.T) {
			next := v
			switch tc {
			case "unterminated repair":
				next.RepairOnly = true
			case "foreign scope":
				next.Sources = []sourceClass{{netip.MustParsePrefix("0.0.0.0/0"), pol}}
			case "foreign LAN list":
				next.LANList = "guests"
			}
			if err := e.save(checkpoint{Version: 1, Pending: []policyView{v, next}}); err != nil {
				t.Fatal(err)
			}
			if _, err := e.readJournal(); err == nil {
				t.Fatal("unsafe checkpoint accepted")
			}
		})
	}
}
