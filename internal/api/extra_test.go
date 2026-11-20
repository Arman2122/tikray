package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/auth"
	"github.com/Arman2122/tikray/internal/backup"
)

func TestEventsHeaderStatsGeoAndStaticLease(t *testing.T) {
	fb := newFake()
	store, err := auth.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(fb, testToken, store, auth.NewLimiter(nil), "")

	req := func(method, target, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+testToken)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	// GET /v1/events includes X-Tikray-Boot-ID header without breaking array body.
	w := req(http.MethodGet, "/v1/events", "")
	if w.Code != http.StatusOK || w.Header().Get("X-Tikray-Boot-ID") != "0123456789abcdef" {
		t.Fatalf("events status=%d boot_id=%q", w.Code, w.Header().Get("X-Tikray-Boot-ID"))
	}

	// GET /v1/stats returns live telemetry.
	w = req(http.MethodGet, "/v1/stats", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"available":true`) {
		t.Fatalf("stats status=%d body=%s", w.Code, w.Body.String())
	}

	// GET /v1/geo returns active slot and verified slot inventory.
	w = req(http.MethodGet, "/v1/geo", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ir-20261119"`) {
		t.Fatalf("geo status=%d body=%s", w.Code, w.Body.String())
	}

	// POST /v1/routeros/leases/static validates IPv4 and returns static lease view.
	w = req(http.MethodPost, "/v1/routeros/leases/static", `{"address":"not-an-ip"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad lease address status=%d, want 400", w.Code)
	}
	w = req(http.MethodPost, "/v1/routeros/leases/static", `{"address":"192.168.1.17"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"static":true`) {
		t.Fatalf("make static status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestBackupAndInboxRoutes(t *testing.T) {
	fb := newFake()
	fb.state.Servers[0].Outbound = json.RawMessage(`{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443,"users":[{"id":"` + secretID + `","encryption":"none"}]}]},"streamSettings":{"security":"tls"}}`)
	store, err := auth.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.SetupCode()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(t.Context(), code, "admin", "super-strong-password-1"); err != nil {
		t.Fatal(err)
	}
	_, tok, err := store.CreateToken("monitor", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(fb, testToken, store, auth.NewLimiter(nil), "")

	// Named API token is forbidden from backup export, restore, inbox upload, and server config inspection.
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/backup/export", `{"passphrase":"export-passphrase-123"}`},
		{http.MethodPost, "/v1/backup/restore", `{"passphrase":"export-passphrase-123","bundle":{}}`},
		{http.MethodPost, "/v1/inbox/core/Xray-linux-arm64-v8a.zip", "zipbytes"},
		{http.MethodGet, "/v1/servers/5ab3c4d5/config", ""},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("named token on %s %s got %d, want 403", tc.method, tc.path, w.Code)
		}
	}

	// Root token can export and restore encrypted backups.
	pass := "backup-roundtrip-passphrase-99"
	r := httptest.NewRequest(http.MethodPost, "/v1/backup/export", strings.NewReader(`{"passphrase":"`+pass+`"}`))
	r.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), secretID) || strings.Contains(w.Body.String(), pass) {
		t.Fatal("export response leaked plaintext secret or passphrase")
	}
	var bundle backup.Bundle
	if err := json.Unmarshal(w.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}

	// Wrong passphrase returns 422 bad_passphrase (not 401).
	badRestore, _ := json.Marshal(map[string]any{"passphrase": "wrong-passphrase-999", "bundle": bundle})
	r = httptest.NewRequest(http.MethodPost, "/v1/backup/restore", bytes.NewReader(badRestore))
	r.Header.Set("Authorization", "Bearer "+testToken)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), `"bad_passphrase"`) {
		t.Fatalf("wrong passphrase status=%d body=%s", w.Code, w.Body.String())
	}

	// Valid restore returns 200 and new ETag.
	goodRestore, _ := json.Marshal(map[string]any{"passphrase": pass, "bundle": bundle})
	r = httptest.NewRequest(http.MethodPost, "/v1/backup/restore", bytes.NewReader(goodRestore))
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("If-Match", `"7"`)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("ETag") != `"8"` {
		t.Fatalf("restore status=%d etag=%q body=%s", w.Code, w.Header().Get("ETag"), w.Body.String())
	}

	// Inbox upload routes stream bytes cleanly.
	r = httptest.NewRequest(http.MethodPost, "/v1/inbox/core/Xray-linux-arm64-v8a.zip", strings.NewReader("payload123"))
	r.Header.Set("Authorization", "Bearer "+testToken)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"bytes":10`) {
		t.Fatalf("core inbox status=%d body=%s", w.Code, w.Body.String())
	}

	r = httptest.NewRequest(http.MethodPost, "/v1/inbox/geo/iran/v2026.11.20/geoip.dat", strings.NewReader("geobytes"))
	r.Header.Set("Authorization", "Bearer "+testToken)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"bytes":8`) {
		t.Fatalf("geo inbox status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestNewHandlerWithUIRoutingAndBypassDefense(t *testing.T) {
	fb := newFake()
	store, err := auth.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ui := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("UI:" + r.URL.Path))
	})
	h := NewHandlerWithUI(fb, testToken, store, auth.NewLimiter(nil), "inst-1", ui)

	// Browser routes go to UI.
	for _, p := range []string{"/", "/servers", "/assets/app.js"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusOK || w.Body.String() != "UI:"+p {
			t.Fatalf("GET %s -> %d %q, want UI", p, w.Code, w.Body.String())
		}
	}

	// API paths and traversal attempts MUST never reach the UI handler.
	for _, p := range []string{"/v1/status", "/v1", "/foo/../v1/status", "//v1/status", "/v1/..//v1/status"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusUnauthorized || strings.HasPrefix(w.Body.String(), "UI:") {
			t.Fatalf("GET %s -> %d %q, want 401 API rejection", p, w.Code, w.Body.String())
		}
	}

	// Public /healthz goes to API, not UI.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"inst-1"`) {
		t.Fatalf("GET /healthz -> %d %q", w.Code, w.Body.String())
	}

	// Non-GET/HEAD on UI paths hit API guard (401 unauthenticated).
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/servers", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("POST /servers -> %d, want 401", w.Code)
	}
}
