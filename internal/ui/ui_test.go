package ui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesIndexAssetsAndSPAFallback(t *testing.T) {
	h := Handler()

	// Root serves index.html with strict CSP and no-store caching.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("GET / Content-Type = %q", w.Header().Get("Content-Type"))
	}
	if w.Header().Get("Content-Security-Policy") != ContentSecurityPolicy {
		t.Fatalf("CSP = %q", w.Header().Get("Content-Security-Policy"))
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("index Cache-Control = %q, want no-store", w.Header().Get("Cache-Control"))
	}
	if !strings.Contains(w.Body.String(), `<div id="app"></div>`) {
		t.Fatalf("GET / body missing app root")
	}

	// SPA client route falls back to index.html.
	for _, route := range []string{"/servers", "/devices", "/routing", "/updates", "/settings", "/events"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, route, nil))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `<div id="app"></div>`) {
			t.Fatalf("GET %s status=%d", route, w.Code)
		}
	}

	// Embedded hashed assets serve with immutable cache header.
	sub, err := fs.Sub(distFS, "dist/assets")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(sub, ".")
	if err != nil || len(entries) == 0 {
		t.Fatalf("expected built assets under dist/assets: %v", err)
	}
	assetPath := "/assets/" + entries[0].Name()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, assetPath, nil))
	if w.Code != http.StatusOK || w.Body.Len() == 0 {
		t.Fatalf("GET %s status=%d len=%d", assetPath, w.Code, w.Body.Len())
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset Cache-Control = %q, want immutable", w.Header().Get("Cache-Control"))
	}

	// Missing asset returns 404, not index.html.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/assets/nonexistent.js", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing asset status = %d, want 404", w.Code)
	}

	// Non-GET/HEAD returns 405.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST / status = %d, want 405", w.Code)
	}
}
