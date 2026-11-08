package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/store"
)

func TestBootstrapHandoffSetsSubnetAndRetainsCredential(t *testing.T) {
	data := t.TempDir()
	db, e := store.Open(stateDir(data))
	if e != nil {
		t.Fatal(e)
	}
	req := map[string]any{"version": 1, "core": "26.10.31", "offline": true, "address": "172.30.9.1:8729", "fingerprint": strings.Repeat("af", 32), "scope": map[string]any{"subnet": "172.30.9.0/29", "lan_list": "LAN", "lans": []map[string]any{{"interface": "ether2", "prefix": "10.99.13.0/24", "dedicated": true}}, "wan": map[string]string{"interface": "ether1"}}}
	body, _ := json.Marshal(req)
	p := filepath.Join(data, "install.json")
	if e = os.WriteFile(p, body, 0644); e != nil {
		t.Fatal(e)
	}
	ready := filepath.Join(stateDir(data), "install.ready")
	if os.WriteFile(ready, []byte(strings.Repeat("ad", 32)), 0600) != nil {
		t.Fatal("fixture")
	}
	if _, err := openInstallation(data, db); err == nil {
		t.Fatal("orphan completion record accepted")
	}
	if os.Remove(ready) != nil {
		t.Fatal("fixture cleanup")
	}
	open := func() {
		t.Helper()
		r, e := openInstallation(data, db)
		if e != nil || r == nil {
			t.Fatal("private installation missing", e)
		}
	}
	open()
	st, rev := db.State()
	if st.Network.Subnet != netip.MustParsePrefix("172.30.9.0/29") || !st.Network.RequireLocalBridge || st.DefaultPolicy.Mode != store.ModeDirect {
		t.Fatal("network not initialized")
	}
	path := filepath.Join(stateDir(data), "routeros.json")
	read := func() routeros.Installation {
		t.Helper()
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		var in routeros.Installation
		if json.Unmarshal(b, &in) != nil || len(in.Password) < 32 {
			t.Fatal("missing durable credential")
		}
		return in
	}
	first := read()
	if os.Remove(p) != nil {
		t.Fatal("fixture")
	}
	open()
	if _, r := db.State(); rev != r || read().Password != first.Password {
		t.Fatal("retry replaced private state")
	}
	req["fingerprint"] = strings.Repeat("bd", 32)
	body, _ = json.Marshal(req)
	os.WriteFile(p, body, 0644)
	if _, e = openInstallation(data, db); e == nil || strings.Contains(e.Error(), first.Password) {
		t.Fatal("mismatched pin accepted or credential exposed")
	}
	if info, e := os.Stat(path); e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credential mode")
	}
}

func TestInstallerBeforeServeBlocksDirectUpdater(t *testing.T) {
	vars, data, _ := trialEnv(t, nil)
	if os.WriteFile(filepath.Join(data, "install.json"), []byte("{}"), 0600) != nil {
		t.Fatal("fixture")
	}
	if code, out, msg := runFast(t, vars, "core", "update", "26.10.31"); code != 1 || !strings.Contains(out+msg, "tikray serve") {
		t.Fatal("updater bypassed initial installer handoff")
	}
}
