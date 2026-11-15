package artifacts

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGeoReaderRevalidatesChangedBytesAndCopiesResults(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, "geo", "r1")
	if e := os.MkdirAll(dir, 0755); e != nil {
		t.Fatal(e)
	}
	files := geoTestFiles("r1")
	for k, v := range files {
		if e := os.WriteFile(filepath.Join(dir, k), []byte(v), 0644); e != nil {
			t.Fatal(e)
		}
	}
	// Let the initial filesystem timestamp tick end so this exercises a cache hit.
	time.Sleep(3 * time.Second)
	var reader GeoReader
	geo, ps, e := reader.Load(data, "r1")
	if e != nil || len(ps) != 1 {
		t.Fatal("initial read refused")
	}
	geo.Site[0] = "invalid"
	ps[0] = netip.PrefixFrom(ps[0].Addr(), 1) // mutating returned values must not alter the cache
	geo, ps, e = reader.Load(data, "r1")
	if e != nil || geo.Site[0] != "geosite:ir" || ps[0].Bits() != 24 {
		t.Fatal("caller modified cached data")
	}
	path := filepath.Join(dir, "geoip.dat")
	st, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	b := []byte(files["geoip.dat"])
	b[len(b)-1] ^= 1
	if os.WriteFile(path, b, 0644) != nil || os.Chtimes(path, st.ModTime(), st.ModTime()) != nil {
		t.Fatal("could not change data bytes preserving length/mtime")
	}
	if g, p, e := reader.Load(data, "r1"); e == nil || g.Version != "" || p != nil {
		t.Fatal("inode change time ignored or stale data returned after corruption")
	}
	if os.WriteFile(path, []byte(files["geoip.dat"]), 0644) != nil {
		t.Fatal("could not repair fixture")
	}
	if _, _, e := reader.Load(data, "r1"); e != nil {
		t.Fatal("repaired data not observed")
	}
	old := path + "-old"
	if os.Rename(path, old) != nil || os.Symlink(old, path) != nil {
		t.Fatal("could not substitute fixture")
	}
	if _, _, e := reader.Load(data, "r1"); e == nil {
		t.Fatal("accepted a link replacing an observed file")
	}
}
