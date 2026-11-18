package service

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/backup"
	"github.com/Arman2122/tikray/internal/store"
)

const sampleVLESSLink = "vless://11111111-2222-3333-4444-555555555555@edge.example.com:443?security=tls&type=tcp#edge"

func TestExportAndRestoreBackup(t *testing.T) {
	e := newEnv(t)
	e.s = e.newService(Config{})

	srv, rev, err := e.s.AddServer(t.Context(), 0, NewServer{Link: sampleVLESSLink})
	if err != nil {
		t.Fatalf("AddServer: %v", err)
	}
	rev, err = e.s.SetDefaultPolicy(t.Context(), rev, store.Policy{Mode: store.ModeSmart, KillSwitch: true})
	if err != nil {
		t.Fatalf("SetDefaultPolicy: %v", err)
	}

	const pass = "restore-secret-passphrase-2026"
	bundle, err := e.s.ExportBackup(t.Context(), pass)
	if err != nil {
		t.Fatalf("ExportBackup: %v", err)
	}

	// Mutate live state before restoring.
	rev, err = e.s.RemoveServer(t.Context(), rev, srv.ID)
	if err != nil {
		t.Fatalf("RemoveServer: %v", err)
	}
	rev, err = e.s.SetDefaultPolicy(t.Context(), rev, store.Policy{Mode: store.ModeDirect})
	if err != nil {
		t.Fatalf("SetDefaultPolicy direct: %v", err)
	}

	// Wrong passphrase fails cleanly without mutating state.
	if _, err := e.s.RestoreBackup(t.Context(), rev, bundle, "wrong-passphrase-12345"); !errors.Is(err, backup.ErrDecrypt) {
		t.Fatalf("wrong passphrase err = %v, want backup.ErrDecrypt", err)
	}
	// Stale revision fails with store.ErrConflict.
	if _, err := e.s.RestoreBackup(t.Context(), rev-1, bundle, pass); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale rev err = %v, want store.ErrConflict", err)
	}

	// Valid restore brings back server and policy.
	nextRev, err := e.s.RestoreBackup(t.Context(), rev, bundle, pass)
	if err != nil {
		t.Fatalf("RestoreBackup: %v", err)
	}
	if nextRev <= rev {
		t.Fatalf("nextRev = %d, want > %d", nextRev, rev)
	}
	st, _ := e.s.State()
	if len(st.Servers) != 1 || st.Servers[0].ID != srv.ID || st.DefaultPolicy.Mode != store.ModeSmart || !st.DefaultPolicy.KillSwitch {
		t.Fatalf("restored state mismatch: %+v", st)
	}

	// Passphrase must never appear in events.
	for _, ev := range e.s.Events(0) {
		if strings.Contains(ev.Message, pass) {
			t.Fatalf("passphrase leaked into event: %q", ev.Message)
		}
	}
}

func TestRestoreBackupPreservesManagedBridgeSubnet(t *testing.T) {
	// Export from a standalone state using 172.31.10.0/29.
	custom := store.Default()
	custom.Network.Subnet = netip.MustParsePrefix("172.31.10.0/29")
	custom.DefaultPolicy = store.Policy{Mode: store.ModeFull}
	bundle, err := backup.Seal(t.Context(), custom, "managed-bridge-passphrase-1")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Restore onto a managed router whose bridge subnet is 172.30.0.0/29.
	dst := newEnv(t)
	r := &testRouter{}
	dst.s = dst.newService(Config{Router: r})
	orig, rev := dst.s.State()
	wantSubnet := orig.Network.Subnet

	if _, err := dst.s.RestoreBackup(t.Context(), rev, bundle, "managed-bridge-passphrase-1"); err != nil {
		t.Fatalf("RestoreBackup on managed router: %v", err)
	}
	got, _ := dst.s.State()
	if got.Network.Subnet != wantSubnet {
		t.Fatalf("subnet changed from %s to %s on managed router", wantSubnet, got.Network.Subnet)
	}
	if got.DefaultPolicy.Mode != store.ModeFull {
		t.Fatalf("policy = %+v, want full", got.DefaultPolicy)
	}
	if len(r.prepared) == 0 {
		t.Fatal("RestoreBackup did not prepare router protection before writing state")
	}
}
