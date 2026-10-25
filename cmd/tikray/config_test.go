package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

// envOf is a getenv over a fixed set of variables.
func envOf(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestConfigFromEnv(t *testing.T) {
	// The runner's three addresses and the probe URL default to the state's
	// (TestDefaultsFromState), so the environment leaves them empty.
	defaults := Config{
		Data:     "/data",
		Arch:     runtime.GOARCH,
		Upstream: "https://github.com/XTLS/Xray-core",
		Listen:   ":443",
		API:      "https://127.0.0.1:443",
	}

	t.Run("defaults", func(t *testing.T) {
		got, err := configFromEnv(envOf(nil))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, defaults) {
			t.Errorf("got %+v, want %+v", got, defaults)
		}
	})

	t.Run("every variable overridden", func(t *testing.T) {
		got, err := configFromEnv(envOf(map[string]string{
			"TIKRAY_DATA":              "/srv/tikray",
			"TIKRAY_ARCH":              "amd64",
			"TIKRAY_RUNNER_URL":        "http://10.0.0.2:9090",
			"TIKRAY_SOCKS":             "10.0.0.2:1081",
			"TIKRAY_XRAY_API":          "10.0.0.2:10086",
			"TIKRAY_UPSTREAM":          "https://git.example/Xray-core",
			"TIKRAY_MIRRORS":           "https://m1.example/{version}/{file}, https://m2.example/{arch}/{file},",
			"TIKRAY_INDEX_URLS":        "https://idx1.example/hashes.json, https://idx2.example/hashes.json",
			"TIKRAY_INDEX_PUBKEY_FILE": "/data/inbox/index.pub",
			"TIKRAY_PROBE_URL":         "https://probe.example/204",
			"TIKRAY_LISTEN":            "10.0.0.2:8443",
			"TIKRAY_API":               "https://10.0.0.2:8443",
			"TIKRAY_API_TOKEN":         "a-token",
			"TIKRAY_API_FINGERPRINT":   strings.Repeat("ab", 32),
		}))
		if err != nil {
			t.Fatal(err)
		}
		want := Config{
			Listen:          "10.0.0.2:8443",
			API:             "https://10.0.0.2:8443",
			APIToken:        "a-token",
			APIFingerprint:  strings.Repeat("ab", 32),
			Data:            "/srv/tikray",
			Arch:            "amd64",
			RunnerURL:       "http://10.0.0.2:9090",
			Socks:           "10.0.0.2:1081",
			XrayAPI:         "10.0.0.2:10086",
			Upstream:        "https://git.example/Xray-core",
			Mirrors:         []string{"https://m1.example/{version}/{file}", "https://m2.example/{arch}/{file}"},
			IndexURLs:       []string{"https://idx1.example/hashes.json", "https://idx2.example/hashes.json"},
			IndexPubKeyFile: "/data/inbox/index.pub",
			ProbeURL:        "https://probe.example/204",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v\nwant %+v", got, want)
		}
	})

	t.Run("empty lists mean none", func(t *testing.T) {
		got, err := configFromEnv(envOf(map[string]string{
			"TIKRAY_MIRRORS":    "",
			"TIKRAY_INDEX_URLS": " , ",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Mirrors) != 0 || len(got.IndexURLs) != 0 {
			t.Errorf("mirrors %q, index URLs %q; want none", got.Mirrors, got.IndexURLs)
		}
	})

	bad := []struct {
		name string
		vars map[string]string
		want string // a substring of the error
	}{
		{"mirror without {file}", map[string]string{"TIKRAY_MIRRORS": "https://ok.example/{file},https://m.example/{version}/xray.zip"}, "https://m.example/{version}/xray.zip"},
		{"mirror that is not an http(s) URL", map[string]string{"TIKRAY_MIRRORS": "ftp://m.example/{file}"}, "ftp://m.example/{file}"},
		{"index URLs without a key", map[string]string{"TIKRAY_INDEX_URLS": "https://idx.example/hashes.json"}, "TIKRAY_INDEX_PUBKEY_FILE"},
		{"API over plain http", map[string]string{"TIKRAY_API": "http://127.0.0.1:443"}, "TIKRAY_API"},
		{"API without a scheme", map[string]string{"TIKRAY_API": "127.0.0.1:443"}, "TIKRAY_API"},
		{"API without a host", map[string]string{"TIKRAY_API": "https://"}, "TIKRAY_API"},
		{"API with a password", map[string]string{"TIKRAY_API": "https://admin:hunter2@127.0.0.1"}, "TIKRAY_API"},
		{"fingerprint that is not hex", map[string]string{"TIKRAY_API_FINGERPRINT": "tikray"}, "TIKRAY_API_FINGERPRINT"},
		{"fingerprint too short", map[string]string{"TIKRAY_API_FINGERPRINT": "abcd"}, "TIKRAY_API_FINGERPRINT"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := configFromEnv(envOf(tc.vars))
			if err == nil {
				t.Fatal("no error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "hunter2") {
				t.Errorf("error %q repeats the password in the URL", err)
			}
		})
	}

	// Where the commands look for the daemon follows where it listens, so that
	// a daemon on another port or address is not taken for no daemon.
	t.Run("API follows TIKRAY_LISTEN", func(t *testing.T) {
		for listen, want := range map[string]string{
			"":                    "https://127.0.0.1:443",
			":443":                "https://127.0.0.1:443",
			":8443":               "https://127.0.0.1:8443",
			"0.0.0.0:8443":        "https://127.0.0.1:8443",
			"[::]:9000":           "https://127.0.0.1:9000",
			"192.168.88.2:443":    "https://192.168.88.2:443",
			"192.168.88.2:8443":   "https://192.168.88.2:8443",
			"127.0.0.1:0":         "https://127.0.0.1:0",
			"[fd00::2]:443":       "https://[fd00::2]:443",
			"router.lan:8443":     "https://127.0.0.1:8443",
			"192.168.88.2":        "https://127.0.0.1:443", // no port: serve will refuse it
			"192.168.88.2:":       "https://192.168.88.2:443",
			"not an address:port": "https://127.0.0.1:443",
		} {
			got, err := configFromEnv(envOf(map[string]string{"TIKRAY_LISTEN": listen}))
			if err != nil {
				t.Errorf("TIKRAY_LISTEN=%q: %v", listen, err)
				continue
			}
			if got.API != want {
				t.Errorf("TIKRAY_LISTEN=%q: API %q, want %q", listen, got.API, want)
			}
		}
		// An address of its own wins.
		got, err := configFromEnv(envOf(map[string]string{"TIKRAY_LISTEN": "192.168.88.2:8443", "TIKRAY_API": "https://router.lan:9443"}))
		if err != nil || got.API != "https://router.lan:9443" {
			t.Errorf("with TIKRAY_API set: %q, %v", got.API, err)
		}
	})

	t.Run("fingerprint forms", func(t *testing.T) {
		// The fingerprint a person copies: either case, colons between bytes.
		for _, in := range []string{strings.Repeat("AB", 32), strings.Repeat("ab:", 31) + "ab", " " + strings.Repeat("ab", 32) + "\n"} {
			if _, err := configFromEnv(envOf(map[string]string{"TIKRAY_API_FINGERPRINT": in})); err != nil {
				t.Errorf("fingerprint %q: %v", in, err)
			}
		}
	})
}

func TestDefaultsFromState(t *testing.T) {
	data := t.TempDir()
	writeState(t, data, func(st *store.State) {
		st.Network.Subnet = netip.MustParsePrefix("10.9.8.0/29")
		st.Health.ProbeURL = "https://probe.state.example/204"
	})

	t.Run("no variables", func(t *testing.T) {
		cfg, st, err := loadConfig(envOf(map[string]string{"TIKRAY_DATA": data}), nil)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RunnerURL != "http://10.9.8.3:8080" || cfg.Socks != "10.9.8.3:1080" || cfg.XrayAPI != "10.9.8.3:10085" {
			t.Errorf("runner URL %q, SOCKS %q, xray API %q; want the runner's .3 on 10.9.8.0/29", cfg.RunnerURL, cfg.Socks, cfg.XrayAPI)
		}
		// One probe URL for tikray's SOCKS probe and xray's observatory.
		if cfg.ProbeURL != "https://probe.state.example/204" || cfg.ProbeURL != st.Health.ProbeURL {
			t.Errorf("probe URL %q, want the state's %q", cfg.ProbeURL, st.Health.ProbeURL)
		}
		if st.Network.Subnet != netip.MustParsePrefix("10.9.8.0/29") {
			t.Errorf("the state it was derived from has subnet %v", st.Network.Subnet)
		}
	})

	t.Run("variables win", func(t *testing.T) {
		all := map[string]string{
			"TIKRAY_DATA":       data,
			"TIKRAY_RUNNER_URL": "http://10.0.0.2:9090",
			"TIKRAY_SOCKS":      "10.0.0.2:1081",
			"TIKRAY_XRAY_API":   "10.0.0.2:10086",
			"TIKRAY_PROBE_URL":  "https://probe.env.example/204",
		}
		cfg, _, err := loadConfig(envOf(all), nil)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RunnerURL != all["TIKRAY_RUNNER_URL"] || cfg.Socks != all["TIKRAY_SOCKS"] || cfg.XrayAPI != all["TIKRAY_XRAY_API"] || cfg.ProbeURL != all["TIKRAY_PROBE_URL"] {
			t.Errorf("runner URL %q, SOCKS %q, xray API %q, probe URL %q; want the variables", cfg.RunnerURL, cfg.Socks, cfg.XrayAPI, cfg.ProbeURL)
		}
		// Each one on its own leaves the others to the state.
		for _, key := range []string{"TIKRAY_RUNNER_URL", "TIKRAY_SOCKS", "TIKRAY_XRAY_API", "TIKRAY_PROBE_URL"} {
			cfg, _, err := loadConfig(envOf(map[string]string{"TIKRAY_DATA": data, key: all[key]}), nil)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]string{"TIKRAY_RUNNER_URL": cfg.RunnerURL, "TIKRAY_SOCKS": cfg.Socks, "TIKRAY_XRAY_API": cfg.XrayAPI, "TIKRAY_PROBE_URL": cfg.ProbeURL}
			want := map[string]string{"TIKRAY_RUNNER_URL": "http://10.9.8.3:8080", "TIKRAY_SOCKS": "10.9.8.3:1080", "TIKRAY_XRAY_API": "10.9.8.3:10085", "TIKRAY_PROBE_URL": "https://probe.state.example/204"}
			want[key] = all[key]
			if !reflect.DeepEqual(got, want) {
				t.Errorf("only %s set: got %v, want %v", key, got, want)
			}
		}
	})

	t.Run("no state file", func(t *testing.T) {
		// A fresh install: the default subnet, which is where M1 pointed.
		cfg, _, err := loadConfig(envOf(map[string]string{"TIKRAY_DATA": t.TempDir()}), nil)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RunnerURL != "http://172.31.255.3:8080" || cfg.Socks != "172.31.255.3:1080" || cfg.XrayAPI != "172.31.255.3:10085" {
			t.Errorf("runner URL %q, SOCKS %q, xray API %q", cfg.RunnerURL, cfg.Socks, cfg.XrayAPI)
		}
		// The default state's probe URL, which is what M1 probed.
		if cfg.ProbeURL != "https://www.gstatic.com/generate_204" {
			t.Errorf("probe URL %q, want the default state's", cfg.ProbeURL)
		}
	})

	t.Run("bad environment comes first", func(t *testing.T) {
		// The state is not even opened: the data root is left as it was.
		fresh := t.TempDir()
		_, _, err := loadConfig(envOf(map[string]string{"TIKRAY_DATA": fresh, "TIKRAY_MIRRORS": "https://m.example/nofile"}), nil)
		if err == nil || !strings.Contains(err.Error(), "TIKRAY_MIRRORS") {
			t.Fatalf("error %v, want one naming TIKRAY_MIRRORS", err)
		}
		if ents, _ := os.ReadDir(fresh); len(ents) != 0 {
			t.Errorf("a bad environment created %v", ents)
		}
	})

	t.Run("unreadable state", func(t *testing.T) {
		bad := t.TempDir()
		if err := os.MkdirAll(filepath.Join(bad, "state"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bad, "state", "state.v1.json"), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := loadConfig(envOf(map[string]string{"TIKRAY_DATA": bad}), nil)
		if err == nil || !strings.Contains(err.Error(), "state.v1.json") {
			t.Errorf("error %v, want one naming the state file", err)
		}
	})
}
