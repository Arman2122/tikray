package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

func TestServerConfigSanitizesSecretsAndUpdatePreservesThem(t *testing.T) {
	e := newEnv(t)
	e.s = e.newService(Config{})

	const (
		uuidSecret = "11111111-2222-3333-4444-555555555555"
		pbkSecret  = "TestPublicKeyValue1234567890abcdef"
		sidSecret  = "a1b2c3d4e5f6"
		spxSecret  = "/secret-spider-path"
	)

	origOutbound, _ := json.Marshal(map[string]any{
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": "203.0.113.10",
				"port":    443,
				"users": []any{map[string]any{
					"id":         uuidSecret,
					"encryption": "none",
					"flow":       "xtls-rprx-vision",
				}},
			}},
		},
		"streamSettings": map[string]any{
			"network":  "raw",
			"security": "reality",
			"realitySettings": map[string]any{
				"serverName":  "www.example.com",
				"fingerprint": "chrome",
				"publicKey":   pbkSecret,
				"shortId":     sidSecret,
				"spiderX":     spxSecret,
			},
		},
	})

	srv, _, err := e.s.AddServer(t.Context(), 0, NewServer{Name: "test-reality", Outbound: origOutbound})
	if err != nil {
		t.Fatalf("AddServer: %v", err)
	}

	cfg, err := e.s.ServerConfig(srv.ID)
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
	rawCfg := string(cfg.Outbound)
	for _, secret := range []string{uuidSecret, pbkSecret, sidSecret, spxSecret} {
		if strings.Contains(rawCfg, secret) {
			t.Fatalf("ServerConfig leaked secret %q in %s", secret, rawCfg)
		}
	}
	if !strings.Contains(rawCfg, "www.example.com") || !strings.Contains(rawCfg, "chrome") || !strings.Contains(rawCfg, "xtls-rprx-vision") {
		t.Fatalf("ServerConfig missing expected non-secret fields: %s", rawCfg)
	}
	if !strings.Contains(rawCfg, KeepSecretSentinel) {
		t.Fatalf("ServerConfig missing sentinel placeholder: %s", rawCfg)
	}

	// Edit SNI, port, and enable mux while leaving all saved credential sentinels untouched.
	edited := strings.Replace(rawCfg, "www.example.com", "cdn.example.net", 1)
	edited = strings.Replace(edited, `"port":443`, `"port":8443`, 1)
	var editedMap map[string]any
	if err := json.Unmarshal([]byte(edited), &editedMap); err != nil {
		t.Fatal(err)
	}
	editedMap["mux"] = map[string]any{"enabled": true, "concurrency": 8}
	editedBytes, _ := json.Marshal(editedMap)

	if _, _, err := e.s.UpdateServer(t.Context(), 1, srv.ID, ServerPatch{Outbound: editedBytes}); err != nil {
		t.Fatalf("UpdateServer with preserved sentinels: %v", err)
	}

	// Verify stored outbound kept original secrets while applying SNI, port, and mux edits.
	st, _ := e.s.State()
	stored := string(st.Servers[0].Outbound)
	if strings.Contains(stored, KeepSecretSentinel) {
		t.Fatalf("stored outbound still contains sentinel: %s", stored)
	}
	for _, want := range []string{uuidSecret, pbkSecret, sidSecret, spxSecret, "cdn.example.net", "8443", `"concurrency":8`} {
		if !strings.Contains(stored, want) {
			t.Fatalf("stored outbound missing %q: %s", want, stored)
		}
	}

	// Brand-new server with sentinel must be refused.
	if _, _, err := e.s.AddServer(t.Context(), 2, NewServer{Name: "bad-sentinel", Outbound: cfg.Outbound}); err == nil {
		t.Fatal("AddServer accepted KeepSecretSentinel without prior secret")
	}
}

func TestInterfacePoliciesAndWANUplinkMutations(t *testing.T) {
	e := newEnv(t)
	e.s = e.newService(Config{})

	// Set Wi-Fi VPN interface policy.
	rev, err := e.s.SetInterfacePolicy(t.Context(), 0, store.InterfacePolicy{
		Interface: "wifi-vpn",
		Name:      "VPN Wi-Fi",
		Policy:    store.Policy{Mode: store.ModeFull, KillSwitch: true},
	})
	if err != nil {
		t.Fatalf("SetInterfacePolicy: %v", err)
	}
	// Pin Xray WAN uplink.
	rev, err = e.s.SetWANInterface(t.Context(), rev, "pppoe-out1")
	if err != nil {
		t.Fatalf("SetWANInterface: %v", err)
	}
	st, _ := e.s.State()
	if len(st.Interfaces) != 1 || st.Interfaces[0].Interface != "wifi-vpn" || !st.Interfaces[0].Policy.KillSwitch {
		t.Fatalf("unexpected Interfaces state: %+v", st.Interfaces)
	}
	if st.Network.WANInterface != "pppoe-out1" {
		t.Fatalf("WANInterface = %q, want pppoe-out1", st.Network.WANInterface)
	}

	// Reject reserved or invalid interface names.
	if _, err := e.s.SetWANInterface(t.Context(), rev, "tikray"); err == nil {
		t.Fatal("expected refusal for reserved interface name tikray")
	}
	if _, err := e.s.SetInterfacePolicy(t.Context(), rev, store.InterfacePolicy{
		Interface: "!ether1",
		Policy:    store.Policy{Mode: store.ModeSmart},
	}); err == nil {
		t.Fatal("expected refusal for negated interface name")
	}

	// Standalone RouterInterfaces returns Managed: false without error.
	inv, err := e.s.RouterInterfaces(t.Context())
	if err != nil || inv.Managed {
		t.Fatalf("standalone RouterInterfaces = (%+v, %v), want managed=false, nil", inv, err)
	}

	// Remove interface override cleanly.
	if _, err := e.s.RemoveInterfacePolicy(t.Context(), rev, "wifi-vpn"); err != nil {
		t.Fatalf("RemoveInterfacePolicy: %v", err)
	}
	st, _ = e.s.State()
	if len(st.Interfaces) != 0 {
		t.Fatalf("expected empty Interfaces after remove, got %+v", st.Interfaces)
	}
}
