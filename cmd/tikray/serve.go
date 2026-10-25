package main

import (
	"context"
	"fmt"
	"io"
	"net"

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
// SIGTERM, and then stops gracefully: the API stops accepting and waits up to
// 10 s for the requests it serves (api.Serve), and the service's loops stop.
// It returns 0 for that, and 1 for a failure to start or to go on.
//
// The service owns the state from here on: the store is opened once, here,
// and every change goes through the API. Everything it needs is checked
// before the port is opened, so that a bad setup is an error and not a
// service that is half there. It prints one line on stderr, with the address
// and the fingerprint of its certificate, which is what a client pins; the
// token is in no output, only in <data>/state/api.token.
func (c *cli) serve(ctx context.Context, args []string) int {
	fs := c.newFlagSet("serve", "serve")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	cfg, err := configFromEnv(c.getenv)
	if err != nil {
		return c.fail(err)
	}
	if err := prepareDirs(cfg.Data); err != nil {
		return c.fail(err)
	}
	s, err := store.Open(stateDir(cfg.Data))
	if err != nil {
		return c.fail(err)
	}
	st, _ := s.State()
	// The runner's addresses follow the state's private subnet, which only a
	// restart changes. The probe URL does not: serveUpdaters and serveMonitor
	// take it from the state they are given.
	cfg = cfg.withState(st)
	runner, err := newRunner(cfg)
	if err != nil {
		return c.fail(err)
	}
	pub, err := indexKey(cfg)
	if err != nil {
		return c.fail(err)
	}
	token, err := api.LoadOrCreateToken(stateDir(cfg.Data))
	if err != nil {
		return c.fail(err)
	}
	cert, fingerprint, err := api.LoadOrCreateCert(stateDir(cfg.Data), certIPs(cfg.Listen, net.InterfaceAddrs))
	if err != nil {
		return c.fail(err)
	}
	svc, err := service.New(service.Config{
		Store:    s,
		Updaters: serveUpdaters(cfg, runner, pub, c.stderr),
		Runner:   runner,
		Monitor:  serveMonitor(cfg, runner),
		Data:     cfg.Data,
		Socks:    cfg.Socks,
		Log:      c.stderr,
	})
	if err != nil {
		return c.fail(err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.stderr, "tikray: serving on %s, certificate sha256 %s\n", ln.Addr(), fingerprint)

	// Either one ending is the end of both. Each returns nil once ctx is done.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
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
	if first != nil {
		return c.fail(first)
	}
	return 0
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
