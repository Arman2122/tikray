package render

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/sharelink"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xrayver"
)

// update makes TestGolden write the golden configs instead of comparing
// them: go test ./internal/render/ -run TestGolden -update. A golden config
// encodes the spec, so read every one it changes before committing it.
var update = flag.Bool("update", false, "write testdata/<scenario>.xray.json instead of comparing with it")

// goldenScenarios are the golden scenarios, in testdata: each has its input
// in <name>.state.json and its rendered config in <name>.xray.json. The
// compatibility test (test/compat) runs every <name>.xray.json on xray-core
// releases.
var goldenScenarios = []string{
	"empty",
	"smart-one-server",
	"pinned-two-servers",
	"kill-switch-default",
	"full-default",
	"full-devices",
	"custom-rules",
	"geo-domestic",
	"plain-dns",
	"all-protocols",
}

// scenario is the content of a <name>.state.json: the Input of Render, with
// the core and the geo data in a header beside the state.
type scenario struct {
	// Core is the xray-core release the config is rendered for.
	Core string `json:"core"`
	// Geo is the geo data, or null for none.
	Geo *struct {
		Version string   `json:"version"`
		Site    []string `json:"site"`
		IP      []string `json:"ip"`
	} `json:"geo"`
	State store.State `json:"state"`
}

// loadScenario reads testdata/<name>.state.json. A key that the header or
// the state does not have fails the test, so that a typo in a scenario
// cannot quietly leave a setting out.
func loadScenario(t *testing.T, name string) Input {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".state.json"))
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var sc scenario
	if err := d.Decode(&sc); err != nil {
		t.Fatalf("%s.state.json: %v", name, err)
	}
	core, err := xrayver.Parse(sc.Core)
	if err != nil {
		t.Fatalf("%s.state.json: core: %v", name, err)
	}
	in := Input{State: sc.State, Core: core}
	if sc.Geo != nil {
		in.Geo = &Geo{Version: sc.Geo.Version, Site: sc.Geo.Site, IP: sc.Geo.IP}
	}
	return in
}

// TestGolden renders each golden scenario and compares the config, byte for
// byte, with its <name>.xray.json.
func TestGolden(t *testing.T) {
	for _, name := range goldenScenarios {
		t.Run(name, func(t *testing.T) {
			got, err := Render(loadScenario(t, name))
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			path := filepath.Join("testdata", name+".xray.json")
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (go test ./internal/render/ -run TestGolden -update writes it)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("Render differs from %s (go test ./internal/render/ -run TestGolden -update rewrites it):\n%s", path, firstDiff(got, want))
			}
		})
	}
}

// TestGoldenScenarioFiles fails on a scenario file in testdata that
// goldenScenarios does not list, which TestGolden would never render.
func TestGoldenScenarioFiles(t *testing.T) {
	for _, pattern := range []string{"*.state.json", "*.xray.json"} {
		files, err := filepath.Glob(filepath.Join("testdata", pattern))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			name, _, _ := strings.Cut(filepath.Base(f), ".")
			if !slices.Contains(goldenScenarios, name) {
				t.Errorf("%s is not a golden scenario: add %q to goldenScenarios or remove the file", f, name)
			}
		}
	}
}

// TestGoldenLinks checks that each scenario server that has a share link
// holds the outbound sharelink parses from that link, so that the golden
// configs, and the compatibility test that runs them, test what sharelink
// produces now.
func TestGoldenLinks(t *testing.T) {
	for _, name := range goldenScenarios {
		in := loadScenario(t, name)
		for i, s := range in.State.Servers {
			if s.Link == "" {
				continue
			}
			parsed, err := sharelink.Parse(s.Link)
			if err != nil {
				t.Errorf("%s: servers[%d] (%s): %v", name, i, s.Name, err)
				continue
			}
			if got, want := compact(t, s.Outbound), compact(t, parsed.Outbound); got != want {
				t.Errorf("%s: servers[%d] (%s): outbound is not what sharelink parses from its link\n got %s\nwant %s", name, i, s.Name, got, want)
			}
		}
	}
}

// compact returns raw as compact JSON.
func compact(t *testing.T, raw []byte) string {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		t.Fatalf("invalid JSON %s: %v", raw, err)
	}
	return b.String()
}

// firstDiff describes the first line where got and want differ.
func firstDiff(got, want []byte) string {
	g := strings.Split(string(got), "\n")
	w := strings.Split(string(want), "\n")
	for i := range max(len(g), len(w)) {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl || i >= len(g) || i >= len(w) {
			return fmt.Sprintf("line %d:\n got %q\nwant %q", i+1, gl, wl)
		}
	}
	return "no line differs"
}
