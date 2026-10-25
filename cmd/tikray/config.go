package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/internal/store"
)

// Config is what the CLI runs with: the environment, and the state for the
// runner's address (see withState).
type Config struct {
	Data string // the data root (TIKRAY_DATA)
	Arch string // GOARCH of the cores to fetch (TIKRAY_ARCH)
	// Listen is where tikray serve listens (TIKRAY_LISTEN).
	Listen string
	// API is the address of tikray serve's API, for the commands that talk to
	// it (TIKRAY_API); unset, it follows Listen (see apiForListen). APIToken
	// and APIFingerprint (TIKRAY_API_TOKEN and
	// TIKRAY_API_FINGERPRINT, the latter in the normal form of
	// apiclient.NormalizeFingerprint) are empty where their variable is unset:
	// apiClient and apiToken then take them from the files tikray serve
	// makes.
	API            string
	APIToken       string
	APIFingerprint string
	// RunnerURL, Socks and XrayAPI default to the runner's address on the
	// private subnet, which the state holds, and ProbeURL to the state's
	// Health.ProbeURL. configFromEnv leaves them empty where their variable is
	// unset, and withState fills them in.
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
	// ProbeURL is fetched through the proxy as the health check
	// (TIKRAY_PROBE_URL). It is the URL xray's observatory probes, so the two
	// agree on whether the proxy works.
	ProbeURL string
}

const (
	defaultData     = "/data"
	defaultUpstream = "https://github.com/XTLS/Xray-core"
	// defaultListen is where tikray serve listens: every interface of the
	// container, which has the bridge veth alone.
	defaultListen = ":443"
	// defaultAPIPort is the API's port where TIKRAY_LISTEN names none.
	defaultAPIPort = "443"
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
//
// A server that this tikray refuses is disabled when the state is opened
// (store.Open). If warn is not nil it gets one line for each, as the daemon
// records them: "server <id> (<name>) disabled: <reason>".
func readState(data string, warn io.Writer) (store.State, uint64, error) {
	s, err := store.Open(stateDir(data))
	if err != nil {
		return store.State{}, 0, err
	}
	st, rev := s.State()
	if warn != nil {
		for _, id := range s.Degraded() {
			if i := slices.IndexFunc(st.Servers, func(srv store.Server) bool { return srv.ID == id }); i >= 0 {
				fmt.Fprintf(warn, "server %s (%s) disabled: %s\n", id, oneLine(st.Servers[i].Name), oneLine(st.Servers[i].Invalid))
			}
		}
	}
	return st, rev, nil
}

// withState returns c with the runner's address, RunnerURL, Socks and XrayAPI,
// taken from st's private subnet where the environment left them unset, and
// with ProbeURL taken from st's Health.ProbeURL likewise: tikray's SOCKS probe
// and xray's observatory then fetch the same URL.
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
	if c.ProbeURL == "" {
		c.ProbeURL = st.Health.ProbeURL
	}
	return c
}

// loadConfig reads the environment and the state, once, and returns the
// configuration they give together with the state it was derived from. The
// environment is checked first: a bad one never opens the state. A state
// that cannot be read gives an error that starts "the state can't be read: ".
// warn is readState's.
func loadConfig(getenv func(string) string, warn io.Writer) (Config, store.State, error) {
	cfg, err := configFromEnv(getenv)
	if err != nil {
		return Config{}, store.State{}, err
	}
	st, _, err := readState(cfg.Data, warn)
	if err != nil {
		return Config{}, store.State{}, fmt.Errorf("the state can't be read: %w", err)
	}
	return cfg.withState(st), st, nil
}

// configFromEnv reads the configuration from getenv. An unset or empty
// variable takes its default; the two lists are empty by default. The
// addresses of the runner (TIKRAY_RUNNER_URL, TIKRAY_SOCKS, TIKRAY_XRAY_API)
// and the probe URL (TIKRAY_PROBE_URL) stay empty when unset: their default is
// the state's (withState).
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
		ProbeURL:        getenv("TIKRAY_PROBE_URL"),
		Listen:          str("TIKRAY_LISTEN", defaultListen),
		API:             getenv("TIKRAY_API"),
		APIToken:        strings.TrimSpace(getenv("TIKRAY_API_TOKEN")),
	}
	if cfg.API == "" {
		cfg.API = apiForListen(cfg.Listen)
	}
	// The messages below never repeat the value: a URL can hold a password.
	if err := checkAPI(cfg.API); err != nil {
		return Config{}, fmt.Errorf("TIKRAY_API: %w", err)
	}
	if v := getenv("TIKRAY_API_FINGERPRINT"); strings.TrimSpace(v) != "" {
		fp, err := apiclient.NormalizeFingerprint(v)
		if err != nil {
			return Config{}, errors.New("TIKRAY_API_FINGERPRINT: want the SHA-256 of the certificate, as 64 hex digits (colons between the bytes are fine)")
		}
		cfg.APIFingerprint = fp
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

// apiForListen is where the commands look for the daemon that listens at
// listen (TIKRAY_LISTEN), when TIKRAY_API does not say: the address it names,
// when that is a specific IP address, else this machine's loopback address,
// which every address of an interface answers; and its port, 443 if there is
// none. A listen address that is no host:port, or whose port is no number,
// gives the default (serve itself refuses such an address).
func apiForListen(listen string) string {
	host, port := "127.0.0.1", defaultAPIPort
	if h, p, err := net.SplitHostPort(listen); err == nil {
		if ip := net.ParseIP(h); ip != nil && !ip.IsUnspecified() {
			host = ip.String()
		}
		if n, err := strconv.ParseUint(p, 10, 16); err == nil {
			port = strconv.FormatUint(n, 10)
		}
	}
	return "https://" + net.JoinHostPort(host, port)
}

// checkAPI checks the address of the API: an https URL with a host, and no user
// info, which a person would put a password in. The error does not repeat it.
func checkAPI(s string) error {
	u, err := url.Parse(s)
	switch {
	case err != nil, u.Scheme != "https", u.Host == "":
		return errors.New("want an https URL with a host, such as https://127.0.0.1:443")
	case u.User != nil:
		return errors.New("the URL must not hold a user name or a password; the token is TIKRAY_API_TOKEN")
	}
	return nil
}

// apiClient returns the client of the daemon at c.API, without its token (see
// apiToken). It trusts the certificate with the fingerprint of
// TIKRAY_API_FINGERPRINT, or else the one in <data>/state/tls.crt, which tikray
// serve made. Where neither exists the client has no fingerprint and trusts
// nothing: a connection refused still shows that no daemon is there, and one
// that is made is refused in the handshake.
func (c Config) apiClient() (*apiclient.Client, error) {
	fp := c.APIFingerprint
	if fp == "" {
		path := filepath.Join(stateDir(c.Data), "tls.crt")
		b, err := os.ReadFile(path)
		switch {
		case err == nil:
			if fp, err = apiclient.FingerprintOfPEM(b); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
		case !errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("reading the API certificate: %w", err)
		}
	}
	return &apiclient.Client{BaseURL: c.API, Fingerprint: fp}, nil
}

// apiToken is the token for the API: TIKRAY_API_TOKEN, or else the contents of
// <data>/state/api.token, which tikray serve made. It is only read once a
// daemon has answered, and no error repeats it.
func (c Config) apiToken() (string, error) {
	if c.APIToken != "" {
		return c.APIToken, nil
	}
	path := filepath.Join(stateDir(c.Data), "api.token")
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("no API token: TIKRAY_API_TOKEN is not set, and %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("no API token: TIKRAY_API_TOKEN is not set, and %s is empty", path)
	}
	return tok, nil
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
