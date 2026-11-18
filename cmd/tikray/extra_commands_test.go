package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/backup"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
)

func TestVersionStatsGeoStaticLeaseAndBackupCLI(t *testing.T) {
	// Version works without a running daemon.
	var out, errBuf bytes.Buffer
	code := run(t.Context(), []string{"version"}, func(string) string { return "" }, &out, &errBuf)
	if code != 0 || strings.TrimSpace(out.String()) != buildVersion {
		t.Fatalf("version code=%d out=%q err=%q", code, out.String(), errBuf.String())
	}

	// Start a mock HTTPS daemon speaking the new endpoints.
	const token = "cli-test-root-token"
	var lastStaticIP string
	var restoredRev uint64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"5"`)
		switch r.URL.Path {
		case "/v1/stats":
			_ = json.NewEncoder(w).Encode(service.Stats{
				Available: true,
				Sys:       &service.SysMetrics{Uptime: 3600, NumGoroutine: 32, Alloc: 4 << 20},
				Outbounds: []service.TrafficCounter{{Tag: "direct", Uplink: 1024, Downlink: 2048}},
				Inbounds:  []service.TrafficCounter{{Tag: "tun-in", Uplink: 4096, Downlink: 8192}},
			})
		case "/v1/geo":
			_ = json.NewEncoder(w).Encode(service.GeoInfo{
				Active:  "ir-20261119",
				Profile: "iran",
				Slots:   []artifacts.GeoSlotInfo{{Slot: "ir-20261119", Profile: "iran", PrefixCount: 120}},
			})
		case "/v1/routeros/leases/static":
			var in struct{ Address string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			lastStaticIP = in.Address
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address": in.Address, "mac": "02:00:00:00:00:10", "static": true,
			})
		case "/v1/backup/export":
			var in struct{ Passphrase string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			b, err := backup.Seal(r.Context(), store.Default(), in.Passphrase)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(b)
		case "/v1/backup/restore":
			var in struct {
				Passphrase string
				Bundle     backup.Bundle
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			if _, err := backup.Open(r.Context(), in.Bundle, in.Passphrase); err != nil {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"error":"bad_passphrase","detail":"wrong passphrase"}`))
				return
			}
			restoredRev = 6
			_ = json.NewEncoder(w).Encode(map[string]uint64{"revision": restoredRev})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	fp, err := apiclient.FingerprintOfPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	envMap := map[string]string{
		"TIKRAY_DATA":              dataDir,
		"TIKRAY_API":               srv.URL,
		"TIKRAY_API_TOKEN":         token,
		"TIKRAY_API_FINGERPRINT":   fp,
		"TIKRAY_BACKUP_PASSPHRASE": "cli-backup-passphrase-2026",
	}
	getenv := func(k string) string { return envMap[k] }

	execCLI := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		c := &cli{getenv: getenv, stdout: &stdout, stderr: &stderr}
		return c.run(context.Background(), args), stdout.String(), stderr.String()
	}

	if code, stdout, stderr := execCLI("stats"); code != 0 || !strings.Contains(stdout, "1h0m0s") || !strings.Contains(stdout, "tun-in") {
		t.Fatalf("stats code=%d out=%q err=%q", code, stdout, stderr)
	}
	if code, stdout, stderr := execCLI("geo", "status"); code != 0 || !strings.Contains(stdout, "ir-20261119") || !strings.Contains(stdout, "prefixes=120") {
		t.Fatalf("geo status code=%d out=%q err=%q", code, stdout, stderr)
	}
	if code, stdout, stderr := execCLI("device", "make-static", "192.168.88.42"); code != 0 || lastStaticIP != "192.168.88.42" || !strings.Contains(stdout, "192.168.88.42") {
		t.Fatalf("device make-static code=%d ip=%q out=%q err=%q", code, lastStaticIP, stdout, stderr)
	}

	backupFile := filepath.Join(t.TempDir(), "state.backup.json")
	if code, stdout, stderr := execCLI("backup", "export", "--out", backupFile); code != 0 || !strings.Contains(stdout, backupFile) {
		t.Fatalf("backup export code=%d out=%q err=%q", code, stdout, stderr)
	}
	info, err := os.Stat(backupFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup file mode = %v, %v; want 0600", info, err)
	}
	if code, stdout, stderr := execCLI("backup", "restore", "--in", backupFile); code != 0 || restoredRev != 6 || !strings.Contains(stdout, "revision 6") {
		t.Fatalf("backup restore code=%d rev=%d out=%q err=%q", code, restoredRev, stdout, stderr)
	}
}
