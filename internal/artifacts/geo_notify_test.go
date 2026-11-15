package artifacts

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestGeoReleaseCheckComparesVerifiedActiveSlot(t *testing.T) {
	const tag = "r1"
	files := geoTestFiles(tag)
	var current atomic.Value
	current.Store(tag)
	var payloads atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest" {
			fmt.Fprint(w, current.Load().(string))
			return
		}
		payloads.Add(1)
		if data, ok := files[filepath.Base(r.URL.Path)]; ok {
			fmt.Fprint(w, data)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	data := t.TempDir()
	u := CoreUpdater{Data: data, GeoSource: GeoSourceConfig{CustomURL: server.URL, Direct: server.Client()}}
	active, err := u.StageGeo(t.Context(), "custom", tag)
	if err != nil {
		t.Fatal(err)
	}
	base := payloads.Load()
	if yes, err := u.GeoReleaseAvailable(t.Context(), "custom", active); yes || err != nil {
		t.Fatal("unchanged release reported as available")
	}
	current.Store("r2")
	if yes, err := u.GeoReleaseAvailable(t.Context(), "custom", active); !yes || err != nil {
		t.Fatal("missing new release notification")
	}
	if err = os.WriteFile(filepath.Join(data, "geo", active, "geoip.dat"), []byte("damaged"), 0644); err != nil {
		t.Fatal(err)
	}
	if yes, err := u.GeoReleaseAvailable(t.Context(), "custom", active); yes || err == nil {
		t.Fatal("unverified active bundle accepted for comparison")
	}
	list, err := os.ReadDir(filepath.Join(data, "geo"))
	if err != nil || len(list) != 1 || payloads.Load() != base {
		t.Fatal("notification downloaded or installed a release")
	}
}
