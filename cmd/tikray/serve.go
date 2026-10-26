package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"

	"github.com/Arman2122/tikray/internal/api"
	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/health"
	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xray"
)

// serve runs the service until ctx ends, which main ties to SIGINT and
// SIGTERM, and then stops gracefully: the API stops accepting, ends the
// operations it runs, whose trials are then aborted, and waits up to 10 s for
// the requests it serves (api.Serve), and the service's loops stop.
// It returns 0 for that, and 1 for a failure to start or to go on.
//
// The service owns the state from here on: it holds serve.lock for as long as
// it runs (a second serve on the data root exits at once), the store is
// opened once, here, and every change goes through the API. What it needs is
// checked before the port is opened, so that a bad setup is an error and not a
// service that is half there; the runner's token is not among it, since the
// runner may start after it (see runnerToken): the API comes up, and the
// status says what it waits for. It prints one line on stderr, with the
// address and the fingerprint of its certificate, which is what a client pins;
// the token is in no output, only in <data>/state/api.token.
func (c *cli) serve(ctx context.Context, args []string) int {
	fs := c.newFlagSet("serve", "serve")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	env, err := configFromEnv(c.getenv)
	if err != nil {
		return c.fail(err)
	}
	if err := prepareDirs(env.Data); err != nil {
		return c.fail(err)
	}
	// One process owns the state: this one, for as long as it runs. A command
	// that runs the updater itself takes the same lock (runUpdater).
	unlock, err := lockServe(env.Data)
	switch {
	case errors.Is(err, errServeHeld):
		return c.fail(fmt.Errorf("another tikray serve owns %s", env.Data))
	case err != nil:
		return c.fail(err)
	}
	defer unlock()
	s, err := store.Open(stateDir(env.Data))
	if err != nil {
		return c.fail(err)
	}
	st, _ := s.State()
	pub, err := indexKey(env)
	if err != nil {
		return c.fail(err)
	}
	token, err := api.LoadOrCreateToken(stateDir(env.Data))
	if err != nil {
		return c.fail(err)
	}
	cert, fingerprint, err := api.LoadOrCreateCert(stateDir(env.Data), certIPs(env.Listen, net.InterfaceAddrs))
	if err != nil {
		return c.fail(err)
	}
	w := wireService(env, st, pub, c.stderr)
	svc, err := service.New(service.Config{
		Store:    s,
		Updaters: w.updaters,
		Runner:   w.runner,
		Monitor:  w.monitor,
		Data:     env.Data,
		Socks:    w.cfg.Socks,
		Log:      c.stderr,
	})
	if err != nil {
		return c.fail(err)
	}
	ln, err := net.Listen("tcp", env.Listen)
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.stderr, "tikray: serving on %s, certificate sha256 %s\n", ln.Addr(), fingerprint)

	// Either one ending is the end of both. Each returns nil once ctx is done.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var watcher sync.WaitGroup
	if !w.token.ready() {
		// The runner has not made its token yet. The service is up all the same;
		// when the token is there, a state that was saved is applied at once,
		// not at the loop's next try.
		watcher.Add(1)
		go func() {
			defer watcher.Done()
			w.token.watch(ctx, func() {
				if _, rev := svc.State(); rev > 0 {
					svc.Kick()
				}
			})
		}()
	}
	ended := make(chan error, 2)
	go func() { ended <- svc.Run(ctx) }()
	go func() { ended <- api.ServeListener(ctx, ln, api.NewHandler(svc, token), cert) }()
	var first error
	for range 2 {
		if err := <-ended; err != nil && first == nil {
			first = err
		}
		cancel()
	}
	watcher.Wait()
	if first != nil {
		return c.fail(first)
	}
	return 0
}

// serveWiring is what the service is made of, for a configuration and the state
// at start.
type serveWiring struct {
	// cfg is the environment's configuration with the runner's addresses of
	// the state at start. Its ProbeURL is the environment's: empty unless
	// TIKRAY_PROBE_URL is set.
	cfg      Config
	token    *runnerToken
	runner   *runnerapi.Client
	updaters service.Updaters
	monitor  *health.Monitor
}

// wireService makes the service's runner client, its Updaters factory and its
// monitor from env, the configuration of the environment (configFromEnv), and
// st, the state at start. Neither pub (see indexKey) nor log is changed.
//
// The runner's addresses follow the state's private subnet, which only a
// restart changes: they are those of st. The probe URL does not stay as it is
// at start. Where the environment leaves it unset, it is the state's own at the
// time of each updater and each check (serveUpdaters, serveMonitor), so that
// a PUT /v1/health takes effect without a restart. cfg.ProbeURL is therefore
// the environment's alone, never filled in from st.
//
// The runner client has the package's timeouts (HTTP nil), waits for the
// runner's token, and reads it again once the runner refuses it (runnerToken).
func wireService(env Config, st store.State, pub []byte, log io.Writer) serveWiring {
	cfg := env.withState(st)
	cfg.ProbeURL = env.ProbeURL // withState filled it from st, which would freeze it
	tok := newRunnerToken(filepath.Join(env.Data, "run", "runner.token"))
	runner := &runnerapi.Client{BaseURL: cfg.RunnerURL, TokenFunc: tok.get, Unauthorized: tok.drop}
	return serveWiring{
		cfg:      cfg,
		token:    tok,
		runner:   runner,
		updaters: serveUpdaters(cfg, runner, pub, log),
		monitor:  serveMonitor(cfg, runner),
	}
}

// serveUpdaters is the service's factory of CoreUpdaters. The service calls it
// for the state it is about to apply, to report on, or to run an operation
// with, from several goroutines at once, so it makes a new updater each time
// and shares nothing mutable with the last (buildUpdater). It leaves Redact
// unset: the service sets it.
//
// The probe URL of the end-to-end health check is the one in the state it is
// given, unless TIKRAY_PROBE_URL is set (cfg.withState), so that a change of
// the setting (PUT /v1/health) takes effect on the next updater and needs no
// restart. The updater has a proxy health check only for a state that has a
// server to proxy through, and NoState says that the state was never saved:
// its revision is 0.
func serveUpdaters(cfg Config, runner *runnerapi.Client, pub []byte, log io.Writer) service.Updaters {
	return func(st store.State, rev uint64) *artifacts.CoreUpdater {
		u := buildUpdater(cfg.withState(st), pub, runner, log, stateRenderer(st), render.ProxyAvailable(st))
		u.NoState = rev == 0
		return u
	}
}

// serveMonitor is the monitor of the service: it asks the runner and xray's
// API, and probes through the SOCKS port with the probe URL of the state it
// judges (as serveUpdaters does), when that state has a proxy to probe. The
// service fills in State.
func serveMonitor(cfg Config, runner *runnerapi.Client) *health.Monitor {
	return &health.Monitor{
		Runner: runner,
		Xray:   &xray.Client{Addr: cfg.XrayAPI},
		Probe: func(st store.State) artifacts.HealthChecker {
			if !render.ProxyAvailable(st) {
				return nil
			}
			_, proxy := healthChecks(cfg.withState(st), runner)
			return proxy
		},
	}
}

// certIPs are the addresses the API's certificate is made for: the one the
// listen address names, or, when it names none (":443", "0.0.0.0:443" and the
// like, or a host name) every address of this machine that is not a loopback,
// unspecified or multicast address, since a client may reach any of them.
// addrs lists the interface addresses (net.InterfaceAddrs). The certificate is
// made once, at the first start (api.LoadOrCreateCert), and the loopback
// address is always in it.
func certIPs(listen string, addrs func() ([]net.Addr, error)) []net.IP {
	if host, _, err := net.SplitHostPort(listen); err == nil {
		if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
			return []net.IP{ip}
		}
	}
	list, err := addrs()
	if err != nil {
		return nil
	}
	var ips []net.IP
	for _, a := range list {
		var ip net.IP
		switch a := a.(type) {
		case *net.IPNet:
			ip = a.IP
		case *net.IPAddr:
			ip = a.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		ips = append(ips, ip)
	}
	return ips
}
