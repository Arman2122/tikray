package main

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// envOf is a getenv over a fixed set of variables.
func envOf(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestConfigFromEnv(t *testing.T) {
	defaults := Config{
		Data:      "/data",
		Arch:      runtime.GOARCH,
		RunnerURL: "http://172.31.255.3:8080",
		Socks:     "172.31.255.3:1080",
		Upstream:  "https://github.com/XTLS/Xray-core",
		ProbeURL:  "https://www.gstatic.com/generate_204",
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
