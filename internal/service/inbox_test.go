package service

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUploadInboxCoreAndGeo(t *testing.T) {
	e := newEnv(t)
	e.s = e.newService(Config{})

	// Upload core archive.
	payload := []byte("PK\x03\x04fake-zip-bytes")
	n, err := e.s.UploadInbox(t.Context(), "core", "", "", "Xray-linux-arm64-v8a.zip", bytes.NewReader(payload))
	if err != nil || n != int64(len(payload)) {
		t.Fatalf("UploadInbox core = %d, %v", n, err)
	}
	got, err := os.ReadFile(filepath.Join(e.data, "inbox", "Xray-linux-arm64-v8a.zip"))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("core inbox content mismatch: %q, %v", got, err)
	}

	// Upload geo assets for iran, v2fly, and custom.
	geoBytes := []byte("geo-data-bytes")
	if n, err := e.s.UploadInbox(t.Context(), "geo", "iran", "20261119", "geoip.dat", bytes.NewReader(geoBytes)); err != nil || n != int64(len(geoBytes)) {
		t.Fatalf("UploadInbox geo iran = %d, %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(e.data, "inbox", "geo", "iran", "20261119", "geoip.dat")); err != nil {
		t.Fatalf("iran geoip.dat missing: %v", err)
	}
	if _, err := e.s.UploadInbox(t.Context(), "geo", "v2fly", "20261119+20261118", "dlc.dat", bytes.NewReader(geoBytes)); err != nil {
		t.Fatalf("UploadInbox geo v2fly dlc.dat: %v", err)
	}
	if _, err := e.s.UploadInbox(t.Context(), "geo", "custom", "my-release-1", "domestic-v4.txt", bytes.NewReader(nil)); err != nil {
		t.Fatalf("UploadInbox empty custom domestic-v4.txt should be allowed: %v", err)
	}

	// Reject bad names, traversal, wrong files, and empty payloads.
	badCases := []struct {
		name                             string
		kind, profile, version, filename string
		body                             string
	}{
		{"bad kind", "other", "", "", "Xray-linux-64.zip", "abc"},
		{"bad core filename", "core", "", "", "../evil.zip", "abc"},
		{"empty core", "core", "", "", "Xray-linux-64.zip", ""},
		{"geo latest", "geo", "iran", "latest", "geoip.dat", "abc"},
		{"geo bad profile", "geo", "evil", "20261119", "geoip.dat", "abc"},
		{"geo traversal", "geo", "custom", "../escape", "geoip.dat", "abc"},
		{"v2fly geosite rejected", "geo", "v2fly", "20261119+20261119", "geosite.dat", "abc"},
		{"iran dlc rejected", "geo", "iran", "20261119", "dlc.dat", "abc"},
		{"iran domestic rejected", "geo", "iran", "20261119", "domestic-v4.txt", "1.2.3.0/24"},
		{"oversized domestic", "geo", "custom", "rel-1", "domestic-v4.txt", strings.Repeat("a", maxInboxText+1)},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			var refused *Refused
			_, err := e.s.UploadInbox(t.Context(), tc.kind, tc.profile, tc.version, tc.filename, strings.NewReader(tc.body))
			if !errors.As(err, &refused) {
				t.Fatalf("err = %v, want *Refused", err)
			}
		})
	}

	// Symlink inbox dir must be rejected.
	outside := t.TempDir()
	symData := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(symData, "inbox")); err != nil {
		t.Fatal(err)
	}
	e.s.data = symData
	if _, err := e.s.UploadInbox(t.Context(), "core", "", "", "Xray-linux-64.zip", bytes.NewReader(payload)); err == nil {
		t.Fatal("symlink inbox was accepted")
	}
}
