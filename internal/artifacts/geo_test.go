package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestGeoChecksumsAndUnsafeSlots(t *testing.T) {
	const version = "ir-2026.11.14"
	const private = "private-fixture-value"
	payloads := map[string]string{
		"geosite.dat":     "fixture site bytes\x00",
		"geoip.dat":       "fixture IP bytes\xff",
		"domestic-v4.txt": "# publisher ranges\r\n198.51.100.0/24\n192.0.2.0/24\n198.51.100.0/24\n",
	}
	type fixture struct {
		data, slot string
		hashes     map[string]string
		meta       map[string]any
	}
	put := func(t *testing.T, path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal("cannot prepare geo fixture")
		}
	}
	hash := func(body string) string { sum := sha256.Sum256([]byte(body)); return hex.EncodeToString(sum[:]) }
	newFixture := func(t *testing.T) fixture {
		t.Helper()
		data := t.TempDir()
		slot := filepath.Join(data, "geo", version)
		if err := os.MkdirAll(slot, 0700); err != nil {
			t.Fatal("cannot create geo slot")
		}
		hashes := map[string]string{}
		for name, content := range payloads {
			put(t, filepath.Join(slot, name), content)
			hashes[name] = hash(content)
		}
		return fixture{data, slot, hashes, map[string]any{"version": version, "site": []string{"geosite:category-ir"}, "ip": []string{"geoip:ir"}, "sha256": hashes}}
	}
	saveMeta := func(t *testing.T, f fixture) {
		t.Helper()
		b, err := json.Marshal(f.meta)
		if err != nil {
			t.Fatal("invalid test metadata")
		}
		put(t, filepath.Join(f.slot, "meta.json"), string(b))
	}
	checkFailure := func(t *testing.T, data, selected string) {
		t.Helper()
		g, ranges, err := LoadGeo(data, selected)
		if err == nil || g.Version != "" || len(g.IP)+len(g.Site) != 0 || ranges != nil {
			t.Fatal("invalid slot yielded usable geo data or no error")
		}
		if !strings.HasPrefix(err.Error(), "artifacts:") || strings.Contains(err.Error(), private) || strings.Contains(err.Error(), data) {
			t.Fatal("slot error exposed supplied input or lacked a package prefix")
		}
	}
	t.Run("complete", func(t *testing.T) {
		f := newFixture(t)
		saveMeta(t, f)
		g, ranges, err := LoadGeo(f.data, version)
		want := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24")}
		if err != nil || g.Version != version || !slices.Equal(g.Site, []string{"geosite:category-ir"}) || !slices.Equal(g.IP, []string{"geoip:ir"}) || !slices.Equal(ranges, want) {
			t.Fatal("verified slot did not yield its matchers and canonical prefixes")
		}
	})
	t.Run("empty verified range list", func(t *testing.T) {
		f := newFixture(t)
		put(t, filepath.Join(f.slot, "domestic-v4.txt"), "")
		f.hashes["domestic-v4.txt"] = hash("")
		saveMeta(t, f)
		g, ranges, err := LoadGeo(f.data, version)
		if err != nil || g.Version != version || len(ranges) != 0 {
			t.Fatal("valid empty range set rejected")
		}
	})
	for name := range payloads {
		t.Run("mismatch "+name, func(t *testing.T) {
			f := newFixture(t)
			saveMeta(t, f)
			put(t, filepath.Join(f.slot, name), private)
			checkFailure(t, f.data, version)
		})
		t.Run("missing digest "+name, func(t *testing.T) {
			f := newFixture(t)
			delete(f.hashes, name)
			saveMeta(t, f)
			checkFailure(t, f.data, version)
		})
	}
	for _, tc := range []struct {
		key   string
		value any
	}{
		{"version", "another-slot"}, {"site", []string{""}}, {"ip", []string{"geoip:"}}, {"site", []string{"domain:" + private}}, {"ip", []string{"geoip:ir\n" + private}},
	} {
		t.Run("invalid "+tc.key, func(t *testing.T) {
			f := newFixture(t)
			f.meta[tc.key] = tc.value
			saveMeta(t, f)
			checkFailure(t, f.data, version)
		})
	}
	for _, text := range []string{"192.0.2.0/24\n" + private, "2001:db8::/32", "192.0.2.1/24", strings.Repeat("192.0.2.0/24\n", 32769)} {
		t.Run("invalid ranges", func(t *testing.T) {
			f := newFixture(t)
			put(t, filepath.Join(f.slot, "domestic-v4.txt"), text)
			f.hashes["domestic-v4.txt"] = hash(text)
			saveMeta(t, f)
			checkFailure(t, f.data, version)
		})
	}
	t.Run("incomplete or oversized asset", func(t *testing.T) {
		f := newFixture(t)
		saveMeta(t, f)
		asset := filepath.Join(f.slot, "geoip.dat")
		for _, size := range []int64{0, 1 << 30} {
			if err := os.Truncate(asset, size); err != nil {
				t.Fatal("cannot resize fixture")
			}
			if size == 0 {
				f.hashes["geoip.dat"] = hash("")
				saveMeta(t, f)
			}
			checkFailure(t, f.data, version)
		}
		if err := os.Remove(asset); err != nil {
			t.Fatal("cannot remove fixture")
		}
		checkFailure(t, f.data, version)
	})
	t.Run("untrusted names", func(t *testing.T) {
		f := newFixture(t)
		saveMeta(t, f)
		for _, name := range []string{"", "../" + private, "x..y", ".hidden", strings.Repeat("a", 65), f.slot} {
			checkFailure(t, f.data, name)
		}
	})
	for _, part := range []string{"geo", "slot", "meta.json", "geosite.dat", "geoip.dat", "domestic-v4.txt"} {
		t.Run("symlink "+part, func(t *testing.T) {
			f := newFixture(t)
			saveMeta(t, f)
			name := filepath.Join(f.slot, part)
			switch part {
			case "geo":
				name = filepath.Join(f.data, "geo")
			case "slot":
				name = f.slot
			}
			moved := filepath.Join(f.data, private)
			if os.Rename(name, moved) != nil || os.Symlink(moved, name) != nil {
				t.Fatal("cannot prepare linked fixture")
			}
			checkFailure(t, f.data, version)
		})
	}
	t.Run("nonregular", func(t *testing.T) {
		f := newFixture(t)
		saveMeta(t, f)
		p := filepath.Join(f.slot, "geoip.dat")
		if os.Remove(p) != nil || syscall.Mkfifo(p, 0600) != nil {
			t.Fatal("cannot prepare fifo")
		}
		checkFailure(t, f.data, version)
	})
}
