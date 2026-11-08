package main

import (
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
)

func TestBootstrapHandoffSetsSubnetAndRetainsCredential(t *testing.T) {
	data := t.TempDir()
	db, e := store.Open(stateDir(data))
	if e != nil {
		t.Fatal(e)
	}
	req := testInstallRequest()
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
	idPath := filepath.Join(stateDir(data), "install.id")
	idBytes, err := os.ReadFile(idPath)
	if err != nil || len(idBytes) != 32 || strings.Trim(string(idBytes), "0123456789abcdef") != "" {
		t.Fatal("managed installation lacks public identifier")
	}
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
	again, err := os.ReadFile(idPath)
	if err != nil || string(again) != string(idBytes) {
		t.Fatal("startup replaced the public identity")
	}
	if err := os.WriteFile(idPath, []byte(strings.Repeat("0", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openInstallation(data, db); err == nil {
		t.Fatal("conflicting published identity accepted")
	}
	if err := os.Remove(idPath); err != nil {
		t.Fatal(err)
	}
	open()
	again, err = os.ReadFile(idPath)
	if err != nil || string(again) != string(idBytes) {
		t.Fatal("identity lost during repair of public handoff")
	}
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

func testInstallRequest() map[string]any {
	return map[string]any{"version": 1, "core": "26.10.31", "offline": true, "address": "172.30.9.1:8729", "fingerprint": strings.Repeat("af", 32), "scope": map[string]any{"subnet": "172.30.9.0/29", "lan_list": "LAN", "lans": []map[string]any{{"interface": "ether2", "prefix": "10.99.13.0/24", "dedicated": true}}, "wan": map[string]string{"interface": "ether1"}}}
}

func TestManagedNetworkRepairPreservesInstallerScope(t *testing.T) {
	data := t.TempDir()
	db, err := store.Open(stateDir(data))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(testInstallRequest())
	if err != nil || os.WriteFile(filepath.Join(data, "install.json"), body, 0644) != nil {
		t.Fatal("create public install request")
	}
	installation, err := openInstallation(data, db)
	if err != nil || installation == nil {
		t.Fatal("create installation handoff")
	}
	st, rev := db.State()
	router, err := routeros.OpenManaged(data)
	if err != nil || router == nil {
		t.Fatal("open installed scope")
	}
	w := wireService(Config{Data: data}, st, nil, io.Discard)
	replacement := netip.MustParsePrefix("172.30.10.0/29")
	cfg := service.Config{Store: db, Data: data, Runner: w.runner, Updaters: w.updaters, Router: router, VerifyBridge: true,
		LocalBridge: func(n store.Network) bool { return n.Subnet == replacement }}
	svc, err := service.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.RepairNetwork(t.Context(), rev, service.NetworkRepair{Subnet: replacement}); err == nil {
		t.Error("accepted a new subnet outside the installer scope")
	}
	// The owner restores the original veth and restarts. Startup must still
	// recognize the same installation even if the native API was offline.
	reopened, err := store.Open(stateDir(data))
	if err != nil {
		t.Fatal(err)
	}
	after, gotRev := reopened.State()
	again, err := openInstallation(data, reopened)
	if err != nil || again == nil || again.ID != installation.ID || gotRev != rev || st.Network != after.Network {
		t.Fatal("repair invalidated the persisted installation or its network")
	}
}

func TestPrivateCoreTargetNeverReachesCLIResult(t *testing.T) {
	vars, data, _ := trialEnv(t, nil)
	if err := os.WriteFile(filepath.Join(data, "install.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	raw := "provider-" + strings.Repeat("x", 31)
	code, out, diag := runFast(t, vars, "core", "update", raw)
	b, err := os.ReadFile(filepath.Join(stateDir(data), lastResultName))
	if code == 0 || err != nil || strings.Contains(out+diag+string(b), raw) || !strings.Contains(string(b), "refused") {
		t.Fatal("invalid core target was accepted, exposed or left stale evidence")
	}
}
