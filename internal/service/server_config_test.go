package service

import (
	"encoding/json"
	"strings"
	"testing"
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
