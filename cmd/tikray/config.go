package main

import (
	"fmt"
	"net/url"
	"runtime"
	"strings"
)

// Config is what the CLI runs with. M1 reads it from the environment; M2
// replaces that with the state store.
type Config struct {
	Data      string // the data root (TIKRAY_DATA)
	Arch      string // GOARCH of the cores to fetch (TIKRAY_ARCH)
	RunnerURL string // the runner's control API (TIKRAY_RUNNER_URL)
	Socks     string // the runner's SOCKS5 listener, host:port (TIKRAY_SOCKS)
	Upstream  string // the XTLS release server (TIKRAY_UPSTREAM)
	// Mirrors are download URL templates with {version}, {arch} and {file}
	// (TIKRAY_MIRRORS, comma-separated).
	Mirrors []string
	// IndexURLs locate the signed hash index (TIKRAY_INDEX_URLS,
	// comma-separated); IndexPubKeyFile is the PEM key it is signed with
	// (TIKRAY_INDEX_PUBKEY_FILE).
	IndexURLs       []string
	IndexPubKeyFile string
	ProbeURL        string // fetched through the proxy as the health check (TIKRAY_PROBE_URL)
}

const (
	defaultData      = "/data"
	defaultRunnerURL = "http://172.31.255.3:8080"
	defaultSocks     = "172.31.255.3:1080"
	defaultUpstream  = "https://github.com/XTLS/Xray-core"
	defaultProbeURL  = "https://www.gstatic.com/generate_204"
)

// configFromEnv reads the configuration from getenv. An unset or empty
// variable takes its default; the two lists are empty by default.
func configFromEnv(getenv func(string) string) (Config, error) {
	str := func(key, def string) string {
		if v := getenv(key); v != "" {
			return v
		}
		return def
	}
	cfg := Config{
		Data:            str("TIKRAY_DATA", defaultData),
		Arch:            str("TIKRAY_ARCH", runtime.GOARCH),
		RunnerURL:       str("TIKRAY_RUNNER_URL", defaultRunnerURL),
		Socks:           str("TIKRAY_SOCKS", defaultSocks),
		Upstream:        str("TIKRAY_UPSTREAM", defaultUpstream),
		Mirrors:         splitList(getenv("TIKRAY_MIRRORS")),
		IndexURLs:       splitList(getenv("TIKRAY_INDEX_URLS")),
		IndexPubKeyFile: getenv("TIKRAY_INDEX_PUBKEY_FILE"),
		ProbeURL:        str("TIKRAY_PROBE_URL", defaultProbeURL),
	}
	for _, m := range cfg.Mirrors {
		if err := checkMirror(m); err != nil {
			return Config{}, fmt.Errorf("TIKRAY_MIRRORS: %w", err)
		}
	}
	// The index is only consulted with its key. Say so rather than skip it
	// silently.
	if len(cfg.IndexURLs) > 0 && cfg.IndexPubKeyFile == "" {
		return Config{}, fmt.Errorf("TIKRAY_INDEX_URLS is set but TIKRAY_INDEX_PUBKEY_FILE is not: the hash index cannot be checked without its key")
	}
	return cfg, nil
}

// splitList splits a comma-separated list, trimming each item and dropping
// the empty ones.
func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// checkMirror applies the rules artifacts.Mirror holds a template to, so that
// a bad one is an error up front rather than a source that always fails.
func checkMirror(template string) error {
	u, err := url.Parse(template)
	switch {
	case err != nil:
		return fmt.Errorf("template %q: %w", template, err)
	case u.Scheme != "http" && u.Scheme != "https", u.Host == "":
		return fmt.Errorf("template %q: want an http(s) URL with a host", template)
	case !strings.Contains(template, "{file}"):
		return fmt.Errorf("template %q: lacks {file}", template)
	}
	return nil
}
