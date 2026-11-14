package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallCheckNeedsFreshPinnedProof(t *testing.T) {
	data := t.TempDir()
	if err := os.Mkdir(stateDir(data), 0700); err != nil {
		t.Fatal(err)
	}
	var reads int
	https := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.URL.Path != "/healthz" {
			t.Error("unexpected credential or request")
		}
		w.WriteHeader(200)
	}))
	defer https.Close()
	sum := sha256.Sum256(https.Certificate().Raw)
	pin := hex.EncodeToString(sum[:])
	challenge := func(n string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(data, "install.check"), []byte(n), 0600); err != nil {
			t.Fatal(err)
		}
	}
	proof := filepath.Join(stateDir(data), "install.checked")
	first, second := strings.Repeat("ab", 16), strings.Repeat("cd", 16)
	challenge(strings.Repeat("ef", 16))
	probe := func(ctx context.Context) error { reads++; return nil }
	if _, err := checkInstallation(t.Context(), data, https.URL, strings.Repeat("00", 32), "", probe); err == nil || reads != 0 {
		t.Fatal("untrusted TLS reached router verification")
	}
	if _, err := os.Stat(proof); !os.IsNotExist(err) {
		t.Fatal("issued untrusted proof")
	}
	challenge(first)
	done, err := checkInstallation(t.Context(), data, https.URL, pin, "", probe)
	if err != nil || done != first || reads != 1 {
		t.Fatal("first challenge failed")
	}
	info, _ := os.Stat(proof)
	b, _ := os.ReadFile(proof)
	if string(b) != first+" "+pin || info.Mode().Perm() != 0600 {
		t.Fatal("invalid challenge proof")
	}
	if _, err := checkInstallation(t.Context(), data, https.URL, pin, done, probe); err != nil || reads != 1 {
		t.Fatal("repeated idle check")
	}
	// Recognize acknowledgements from an image which predates durable claims.
	if err := os.Remove(filepath.Join(stateDir(data), "install.attempt")); err != nil {
		t.Fatal(err)
	}
	if _, err := checkInstallation(t.Context(), data, https.URL, pin, "", probe); err != nil || reads != 1 {
		t.Fatal("daemon restart repeated a successful live challenge")
	}
	challenge(second)
	if _, err := checkInstallation(t.Context(), data, https.URL, pin, done, func(context.Context) error { reads++; return context.DeadlineExceeded }); err == nil {
		t.Fatal("reused stale router status")
	}
	b, _ = os.ReadFile(proof)
	if string(b) != first+" "+pin {
		t.Fatal("acknowledged failed check")
	}
	if _, err := checkInstallation(t.Context(), data, https.URL, pin, "", probe); err != nil || reads != 2 {
		t.Fatal("daemon restart retried an expired challenge")
	}
	challenge(strings.Repeat("ed", 16))
	if _, err := checkInstallation(t.Context(), data, https.URL, pin, done, func(context.Context) error { challenge(first); return nil }); err == nil {
		t.Fatal("superseded challenge accepted")
	}
}
