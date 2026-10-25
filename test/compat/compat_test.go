//go:build compat

package compat

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/test/lab"
)

// goldenDir holds render's golden configs, <scenario>.xray.json.
var goldenDir = filepath.Join("..", "..", "internal", "render", "testdata")

// testTimeout bounds one xray run -test, which takes well under a second.
const testTimeout = 2 * time.Minute

// TestXrayAcceptsGolden runs xray run -test on every golden config, one at a
// time (they all name the TUN device xray0), on each release compatVersions
// gives. It fails with xray's output when xray refuses a config, and logs
// what xray prints when it accepts one, warnings among it.
func TestXrayAcceptsGolden(t *testing.T) {
	if os.Geteuid() != 0 {
		const why = "xray releases before 26.10 open the config's TUN device during run -test, which needs root"
		if os.Getenv("TIKRAY_COMPAT_REQUIRED") == "1" {
			t.Fatal(why + " (TIKRAY_COMPAT_REQUIRED=1)")
		}
		t.Skip(why)
	}
	ctx := t.Context()
	configs, err := filepath.Glob(filepath.Join(goldenDir, "*.xray.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) == 0 {
		t.Fatalf("no golden configs in %s", goldenDir)
	}
	versions, err := compatVersions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range versions {
		core, err := lab.XrayCoreVersion(v)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(core, func(t *testing.T) {
			bin, err := lab.XrayBinaryVersion(ctx, lab.CacheDir(), v, runtime.GOARCH)
			if err != nil {
				t.Fatalf("build xray-core %s: %v", v, err)
			}
			for _, config := range configs {
				name := strings.TrimSuffix(filepath.Base(config), ".xray.json")
				t.Run(name, func(t *testing.T) {
					out, err := xrayTest(ctx, t.TempDir(), bin, config)
					if err != nil {
						t.Fatalf("xray-core %s refuses %s: %v\n%s", core, name, err, out)
					}
					if banner := "Xray " + core + " "; !strings.HasPrefix(string(out), banner) {
						t.Errorf("xray-core %s is not the release it was built as: its output does not start with %q\n%s", v, banner, out)
					}
					t.Logf("xray-core %s accepts %s:\n%s", core, name, out)
				})
			}
		})
	}
}

// compatVersions returns the xray-core releases to test, as lab versions
// (see lab.XrayBinaryVersion): TIKRAY_COMPAT_VERSIONS when it is set, or else
// the oldest release tikray supports (render.Tested[0]) and the newest two
// release tags.
func compatVersions(ctx context.Context) ([]string, error) {
	if env := os.Getenv("TIKRAY_COMPAT_VERSIONS"); env != "" {
		var versions []string
		for _, v := range strings.Split(env, ",") {
			if v = strings.TrimSpace(v); v == "" {
				continue
			}
			if _, err := lab.XrayCoreVersion(v); err != nil {
				return nil, fmt.Errorf("TIKRAY_COMPAT_VERSIONS: %w", err)
			}
			versions = append(versions, v)
		}
		if len(versions) == 0 {
			return nil, fmt.Errorf("TIKRAY_COMPAT_VERSIONS %q names no version", env)
		}
		return versions, nil
	}
	tags, err := lab.ReleaseTags(ctx)
	if err != nil {
		return nil, err
	}
	if len(tags) < 2 {
		return nil, fmt.Errorf("xray-core has %d release tags, want at least 2", len(tags))
	}
	return []string{"v" + render.Tested[0].String(), tags[1], tags[0]}, nil
}

// xrayTest runs bin run -test on the config at path from dir, with the geo
// files for the codes it names (geoCodes) in dir, and returns what xray
// prints.
func xrayTest(ctx context.Context, dir, bin, path string) ([]byte, error) {
	config, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sites, ips, err := geoCodes(config)
	if err != nil {
		return nil, err
	}
	if err := writeGeoDat(dir, sites, ips); err != nil {
		return nil, err
	}
	file := filepath.Join(dir, "config.json")
	if err := os.WriteFile(file, config, 0o600); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "-test", "-c", file)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+dir)
	return cmd.CombinedOutput()
}

// geoCodes returns the geosite and geoip codes that the config names, each
// with one made-up entry for writeGeoDat. A geosite:<code> or geoip:<code>
// string anywhere in the config counts.
func geoCodes(config []byte) (sites, ips map[string][]string, err error) {
	var v any
	if err := json.Unmarshal(config, &v); err != nil {
		return nil, nil, err
	}
	sites, ips = map[string][]string{}, map[string][]string{}
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for _, e := range v {
				walk(e)
			}
		case []any:
			for _, e := range v {
				walk(e)
			}
		case string:
			if code, ok := strings.CutPrefix(v, "geosite:"); ok {
				sites[code] = []string{code + ".test"}
			} else if code, ok := strings.CutPrefix(v, "geoip:"); ok {
				ips[code] = []string{"192.0.2.0/24"}
			}
		}
	}
	walk(v)
	return sites, ips, nil
}

// TestCompatVersions checks that TIKRAY_COMPAT_VERSIONS replaces the
// releases, and that it must name lab versions.
func TestCompatVersions(t *testing.T) {
	t.Setenv("TIKRAY_COMPAT_VERSIONS", " v26.3.27 , v1.260118.0,")
	got, err := compatVersions(t.Context())
	if err != nil || strings.Join(got, ",") != "v26.3.27,v1.260118.0" {
		t.Errorf("compatVersions = %q, %v; want [v26.3.27 v1.260118.0]", got, err)
	}
	for _, bad := range []string{"26.3.27", ",", "latest"} {
		t.Setenv("TIKRAY_COMPAT_VERSIONS", bad)
		if got, err := compatVersions(t.Context()); err == nil {
			t.Errorf("TIKRAY_COMPAT_VERSIONS=%q gives %q, want an error", bad, got)
		}
	}
}

func TestGeoCodes(t *testing.T) {
	sites, ips, err := geoCodes([]byte(`{"routing":{"rules":[{"domain":["geosite:category-ir","domain:ir"]},{"ip":["geoip:ir","10.0.0.0/8"]}]},"dns":{"servers":[{"domains":["geosite:category-ir","geosite:ads"]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(sites); got != "map[ads:[ads.test] category-ir:[category-ir.test]]" {
		t.Errorf("sites = %s", got)
	}
	if got := fmt.Sprint(ips); got != "map[ir:[192.0.2.0/24]]" {
		t.Errorf("ips = %s", got)
	}
}

// TestWriteGeoDat checks the bytes writeGeoDat writes against protobuf
// encoded by hand from xray-core's geodata messages.
func TestWriteGeoDat(t *testing.T) {
	dir := t.TempDir()
	err := writeGeoDat(dir,
		map[string][]string{"ir": {"a.ir"}, "ads": nil},
		map[string][]string{"ir": {"192.0.2.0/24", "2001:db8::/32"}})
	if err != nil {
		t.Fatal(err)
	}
	for file, want := range map[string]string{
		// GeoSiteList{entry: [{code "ADS"}, {code "IR", domain: [{type Domain, value "a.ir"}]}]}
		"geosite.dat": "0a05" + "0a03414453" +
			"0a0e" + "0a024952" + "1208" + "0802" + "1204612e6972",
		// GeoIPList{entry: [{code "IR", cidr: [{ip 192.0.2.0, prefix 24}, {ip 2001:db8::, prefix 32}]}]}
		"geoip.dat": "0a24" + "0a024952" +
			"1208" + "0a04c0000200" + "1018" +
			"1214" + "0a1020010db8000000000000000000000000" + "1020",
	} {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(b); got != want {
			t.Errorf("%s:\n got %s\nwant %s", file, got, want)
		}
	}
	if err := writeGeoDat(t.TempDir(), nil, map[string][]string{"ir": {"192.0.2.0"}}); err == nil {
		t.Error("writeGeoDat takes an address without a prefix length")
	}
	if err := writeGeoDat(t.TempDir(), map[string][]string{"": nil}, nil); err == nil {
		t.Error("writeGeoDat takes an empty code")
	}
}
