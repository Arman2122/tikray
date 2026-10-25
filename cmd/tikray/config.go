package main

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/internal/store"
)

// Config is what the CLI runs with: the environment, and the state for the
// runner's address (see withState).
type Config struct {
	Data string // the data root (TIKRAY_DATA)
	Arch string // GOARCH of the cores to fetch (TIKRAY_ARCH)
	// RunnerURL, Socks and XrayAPI default to the runner's address on the
	// private subnet, which the state holds. configFromEnv leaves them empty
	// where their variable is unset, and withState fills them in.
	RunnerURL string // the runner's control API (TIKRAY_RUNNER_URL)
	Socks     string // the runner's SOCKS5 listener, host:port (TIKRAY_SOCKS)
	// XrayAPI is where xray's gRPC API listens, host:port (TIKRAY_XRAY_API).
	// The health check runs "xray api statssys --server=<XrayAPI>" in the
	// runner, so it must be an address the runner can reach and the config's
	// api rule lets the runner use.
	XrayAPI  string
	Upstream string // the XTLS release server (TIKRAY_UPSTREAM)
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
	defaultData     = "/data"
	defaultUpstream = "https://github.com/XTLS/Xray-core"
	defaultProbeURL = "https://www.gstatic.com/generate_204"
	// runnerPort is the port of the runner's control API, which
	// cmd/tikray-runner serves on its address of the private subnet.
	runnerPort = 8080
)

// stateDir is where the CLI keeps the state, under the data root.
func stateDir(data string) string { return filepath.Join(data, "state") }

// readState reads the state in <data>/state and its revision. It never writes
// the state: a directory without one gives the default state at revision 0,
// and the store is not changed. Opening the store makes the directory (0700)
// if it is missing.
func readState(data string) (store.State, uint64, error) {
	s, err := store.Open(stateDir(data))
	if err != nil {
		return store.State{}, 0, err
	}
	st, rev := s.State()
	return st, rev, nil
}

// withState returns c with the runner's address, RunnerURL, Socks and XrayAPI,
// taken from st's private subnet where the environment left them unset.
func (c Config) withState(st store.State) Config {
	runner := st.Network.Runner().String()
	if c.RunnerURL == "" {
		c.RunnerURL = "http://" + net.JoinHostPort(runner, strconv.Itoa(runnerPort))
	}
	if c.Socks == "" {
		c.Socks = net.JoinHostPort(runner, strconv.Itoa(render.SOCKSPort))
	}
	if c.XrayAPI == "" {
		c.XrayAPI = net.JoinHostPort(runner, strconv.Itoa(render.APIPort))
	}
	return c
}

// loadConfig reads the environment and the state, once, and returns the
// configuration they give together with the state it was derived from. The
// environment is checked first: a bad one never opens the state. A state
// that cannot be read gives an error that starts "the state can't be read: ".
func loadConfig(getenv func(string) string) (Config, store.State, error) {
	cfg, err := configFromEnv(getenv)
	if err != nil {
		return Config{}, store.State{}, err
	}
	st, _, err := readState(cfg.Data)
	if err != nil {
		return Config{}, store.State{}, fmt.Errorf("the state can't be read: %w", err)
	}
	return cfg.withState(st), st, nil
}

// configFromEnv reads the configuration from getenv. An unset or empty
// variable takes its default; the two lists are empty by default. The
// addresses of the runner (TIKRAY_RUNNER_URL, TIKRAY_SOCKS, TIKRAY_XRAY_API)
// stay empty when unset: their default is the state's (withState).
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
		RunnerURL:       getenv("TIKRAY_RUNNER_URL"),
		Socks:           getenv("TIKRAY_SOCKS"),
		XrayAPI:         getenv("TIKRAY_XRAY_API"),
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
