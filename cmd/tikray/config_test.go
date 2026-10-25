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
		}))
		if err != nil {
			t.Fatal(err)
		}
		want := Config{
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
		})
	}
}

func TestDefaultsFromState(t *testing.T) {
	data := t.TempDir()
	writeState(t, data, func(st *store.State) {
		st.Network.Subnet = netip.MustParsePrefix("10.9.8.0/29")
		st.Health.ProbeURL = "https://probe.state.example/204"
	})

	t.Run("no variables", func(t *testing.T) {
		cfg, st, err := loadConfig(envOf(map[string]string{"TIKRAY_DATA": data}))
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
		cfg, _, err := loadConfig(envOf(all))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RunnerURL != all["TIKRAY_RUNNER_URL"] || cfg.Socks != all["TIKRAY_SOCKS"] || cfg.XrayAPI != all["TIKRAY_XRAY_API"] || cfg.ProbeURL != all["TIKRAY_PROBE_URL"] {
			t.Errorf("runner URL %q, SOCKS %q, xray API %q, probe URL %q; want the variables", cfg.RunnerURL, cfg.Socks, cfg.XrayAPI, cfg.ProbeURL)
		}
		// Each one on its own leaves the others to the state.
		for _, key := range []string{"TIKRAY_RUNNER_URL", "TIKRAY_SOCKS", "TIKRAY_XRAY_API", "TIKRAY_PROBE_URL"} {
			cfg, _, err := loadConfig(envOf(map[string]string{"TIKRAY_DATA": data, key: all[key]}))
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
		cfg, _, err := loadConfig(envOf(map[string]string{"TIKRAY_DATA": t.TempDir()}))
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
		_, _, err := loadConfig(envOf(map[string]string{"TIKRAY_DATA": fresh, "TIKRAY_MIRRORS": "https://m.example/nofile"}))
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
		_, _, err := loadConfig(envOf(map[string]string{"TIKRAY_DATA": bad}))
		if err == nil || !strings.Contains(err.Error(), "state.v1.json") {
			t.Errorf("error %v, want one naming the state file", err)
		}
	})
}
