package lab

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func zipWith(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestResolveChannel(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/NEWESTa7.stable":
			w.Write([]byte("7.25 1792678320\n"))
		case "/NEWESTa7.long-term":
			w.Write([]byte("7.23.8 1791452776"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx := context.Background()

	for channel, want := range map[string]string{"stable": "7.25", "long-term": "7.23.8"} {
		got, err := ResolveChannel(ctx, srv.URL, channel)
		if err != nil {
			t.Fatalf("%s: %v", channel, err)
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", channel, got, want)
		}
	}

	before := hits.Load()
	if _, err := ResolveChannel(ctx, srv.URL, "testing"); err == nil {
		t.Error("unknown channel: expected error")
	}
	if hits.Load() != before {
		t.Error("unknown channel made an HTTP request")
	}
}

func fetchServer(t *testing.T, files map[string][]byte, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
}

func checkUnder(t *testing.T, path, dir, base string) {
	t.Helper()
	if filepath.Dir(path) != dir || filepath.Base(path) != base {
		t.Errorf("path %q, want %s/%s", path, dir, base)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("stat %s: %v", path, err)
	}
}

func TestFetchCHRx86(t *testing.T) {
	var hits atomic.Int32
	srv := fetchServer(t, map[string][]byte{
		"/7.25/chr-7.25.img.zip":          zipWith(t, "chr-7.25.img", []byte("disk")),
		"/7.25/all_packages-x86-7.25.zip": zipWith(t, "container-7.25.npk", []byte("npk")),
	}, &hits)
	defer srv.Close()
	cache := t.TempDir()

	a, err := FetchCHR(context.Background(), srv.URL, cache, "7.25", ArchX86)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(cache, "7.25", "x86_64")
	checkUnder(t, a.DiskImage, dir, "chr-7.25.img")
	checkUnder(t, a.ContainerNPK, dir, "container-7.25.npk")

	before := hits.Load()
	if _, err := FetchCHR(context.Background(), srv.URL, cache, "7.25", ArchX86); err != nil {
		t.Fatal(err)
	}
	if n := hits.Load() - before; n != 0 {
		t.Errorf("second call made %d HTTP requests, want 0", n)
	}
}

func TestFetchCHRarm64(t *testing.T) {
	var hits atomic.Int32
	srv := fetchServer(t, map[string][]byte{
		"/7.25/chr-7.25-arm64.img.zip":      zipWith(t, "chr-7.25-arm64.img", []byte("disk")),
		"/7.25/all_packages-arm64-7.25.zip": zipWith(t, "container-7.25-arm64.npk", []byte("npk")),
	}, &hits)
	defer srv.Close()
	cache := t.TempDir()

	a, err := FetchCHR(context.Background(), srv.URL, cache, "7.25", ArchARM64)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(cache, "7.25", "arm64")
	checkUnder(t, a.DiskImage, dir, "chr-7.25-arm64.img")
	checkUnder(t, a.ContainerNPK, dir, "container-7.25-arm64.npk")
}

func TestFetchCHRPartialDownload(t *testing.T) {
	full := zipWith(t, "chr-7.25.img", bytes.Repeat([]byte("x"), 1<<20))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/7.25/chr-7.25.img.zip" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", "999999999")
		w.Write(full[:len(full)/2])
		// Returning early with a short body makes the server close the connection.
	}))
	defer srv.Close()
	cache := t.TempDir()

	if _, err := FetchCHR(context.Background(), srv.URL, cache, "7.25", ArchX86); err == nil {
		t.Fatal("expected error on truncated download")
	}
	var leftovers []string
	filepath.Walk(cache, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && !strings.HasSuffix(p, ".part") {
			leftovers = append(leftovers, p)
		}
		return nil
	})
	if len(leftovers) != 0 {
		t.Errorf("non-.part files left in cache after failed download: %v", leftovers)
	}
}

func TestArchGOARCH(t *testing.T) {
	if got := ArchX86.GOARCH(); got != "amd64" {
		t.Errorf("x86_64 → %q, want amd64", got)
	}
	if got := ArchARM64.GOARCH(); got != "arm64" {
		t.Errorf("arm64 → %q, want arm64", got)
	}
}

func TestCacheDir(t *testing.T) {
	t.Setenv("TIKRAY_LAB_CACHE", "/x/y")
	if got := CacheDir(); got != "/x/y" {
		t.Errorf("got %q, want /x/y", got)
	}
	t.Setenv("TIKRAY_LAB_CACHE", "")
	t.Setenv("HOME", "/home/u")
	if got := CacheDir(); got != "/home/u/.cache/tikray-lab" {
		t.Errorf("got %q, want /home/u/.cache/tikray-lab", got)
	}
}
