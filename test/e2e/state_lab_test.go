//go:build lab

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xrayver"
)

// The state TestCoreLifecycle pushes has to be one the store accepts and the
// renderer can use, and to reproduce what the M1 fixture config does. These
// tests need no lab: run them with
//
//	go test -tags lab -run 'TestLifecycleState|TestWriteStateFile' ./test/e2e/
func TestLifecycleState(t *testing.T) {
	st, err := lifecycleState()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(st.Servers) != 1 || st.Servers[0].Name != "lab-a" || st.Servers[0].Disabled {
		t.Fatalf("servers %+v, want lab-a alone, enabled", st.Servers)
	}
	var ob struct {
		Protocol string `json:"protocol"`
		Settings struct {
			Vnext []struct {
				Address string `json:"address"`
				Port    int    `json:"port"`
			} `json:"vnext"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(st.Servers[0].Outbound, &ob); err != nil {
		t.Fatal(err)
	}
	if ob.Protocol != "vless" || len(ob.Settings.Vnext) != 1 || ob.Settings.Vnext[0].Address != "203.0.113.10" || ob.Settings.Vnext[0].Port != 443 {
		t.Errorf("outbound %s, want VLESS to 203.0.113.10:443", st.Servers[0].Outbound)
	}
	if id := st.Servers[0].ID; len(id) != 8 {
		t.Errorf("server ID %q, want one from store.NewID", id)
	}
	if st.DefaultPolicy != (store.Policy{Mode: store.ModeSmart}) {
		t.Errorf("default policy %+v, want smart without the kill switch", st.DefaultPolicy)
	}
	if want := (store.Domestic{Domains: []string{"domain:domestic.test"}, IPs: []string{"203.0.113.20/32"}}); !reflect.DeepEqual(st.Routing.Domestic, want) {
		t.Errorf("domestic %+v, want %+v", st.Routing.Domestic, want)
	}
	if st.DNS.Remote != "203.0.113.53" || st.DNS.Domestic != netip.MustParseAddr("203.0.113.54") {
		t.Errorf("DNS %+v, want remote 203.0.113.53 and domestic 203.0.113.54", st.DNS)
	}
	if st.Network != store.Default().Network {
		t.Errorf("network %+v, want the default subnet", st.Network)
	}
	// The lab has no internet: with the default probe URL the observatory
	// would find lab-a down, and the balancers would fall back.
	if st.Health.ProbeURL != labProbeURL {
		t.Errorf("probe URL %q, want the lab's %q", st.Health.ProbeURL, labProbeURL)
	}

	// The newest core renders it, with the server in.
	out, err := render.Render(render.Input{State: st, Core: xrayver.Version{Major: 26, Minor: 10, Patch: 21}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "srv-"+st.Servers[0].ID) {
		t.Errorf("the render lacks the server:\n%s", out)
	}
}

// TestWriteStateFile checks that writeStateFile makes the file the store
// itself writes, so that what the lab pushes is what store.Open reads back.
func TestWriteStateFile(t *testing.T) {
	st, err := lifecycleState()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path, err := writeStateFile(dir, st)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "state.v1.json") || filepath.Base(path) != filepath.Base(statePath) {
		t.Errorf("file %s, want state.v1.json in %s, named as the router's %s", path, dir, statePath)
	}
	var f struct {
		Version  int             `json:"version"`
		Revision uint64          `json:"revision"`
		State    json.RawMessage `json:"state"`
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if f.Version != 1 || f.Revision != 1 || len(f.State) == 0 {
		t.Errorf("file holds version %d, revision %d, state %q; want version 1, revision 1 and a state", f.Version, f.Revision, f.State)
	}

	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, rev := s.State()
	// The file holds the outbound indented; Marshal compacts it again.
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(st)
	if rev != 1 || string(gotJSON) != string(wantJSON) {
		t.Errorf("store.Open reads revision %d and\n%s\nwant revision 1 and\n%s", rev, gotJSON, wantJSON)
	}

	// A state the store refuses is not written.
	bad := st.Clone()
	bad.DefaultPolicy.Mode = "bogus"
	if _, err := writeStateFile(t.TempDir(), bad); err == nil {
		t.Error("an invalid state was written")
	}
}

// TestConfigStates checks the states TestConfigApply pushes, without a lab:
// each is valid and renders for every core the test runs, the LAN client is
// the one smart device, and the raw server that its bad_raw_server check
// adds passes the store's checks and the render, so that only xray run -test
// can refuse it. Run it with
//
//	go test -tags lab -run TestConfigStates ./test/e2e/
func TestConfigStates(t *testing.T) {
	a, err := serverFromLink(linkA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := serverFromLink(linkB)
	if err != nil {
		t.Fatal(err)
	}
	if a.Link != linkA || b.Name != "lab-b" || a.ID == b.ID {
		t.Fatalf("servers %+v and %+v, want lab-a and lab-b with their links and IDs of their own", a, b)
	}
	bad := configState(true, a, b)
	bad.Servers = append(bad.Servers, badServer())
	cores := []string{"26.10.21", previousXray, oldestXray}
	for name, st := range map[string]store.State{
		"default":          store.Default(),
		"lab-a":            configState(false, a),
		"lab-a and lab-b":  configState(false, a, b),
		"kill switch":      configState(true, a, b),
		"with the bad one": bad,
	} {
		if err := st.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, core := range cores {
			if _, err := renderedName(st, core); err != nil {
				t.Errorf("%s for %s: %v", name, core, err)
			}
		}
		if name == "default" {
			continue
		}
		if st.DefaultPolicy.Mode != store.ModeDirect || len(st.Devices) != 1 || st.Devices[0].Address != lanClient || st.Devices[0].Policy.Mode != store.ModeSmart {
			t.Errorf("%s: default policy %+v and devices %+v, want direct and the LAN client smart", name, st.DefaultPolicy, st.Devices)
		}
		if st.Health.ProbeURL != labProbeURL || st.DNS.Remote != "203.0.113.53" {
			t.Errorf("%s: probe URL %q and DNS %+v, want the lab's", name, st.Health.ProbeURL, st.DNS)
		}
	}

	// renderedName names the render as artifacts does: by the SHA-256 of the
	// bytes.
	out, err := render.Render(render.Input{State: store.Default(), Core: xrayver.Version{Major: 26, Minor: 10, Patch: 21}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := renderedName(store.Default(), "26.10.21")
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(out); got != "config/"+hex.EncodeToString(sum[:])+".json" {
		t.Errorf("renderedName = %s, want the SHA-256 of the render", got)
	}
}
