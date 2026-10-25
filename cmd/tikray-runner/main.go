//go:build linux

// Command tikray-runner is the data-plane runner: PID 1 of a RouterOS
// container. It sets up the container's networking, keeps xray running from
// /data/run/active.json and serves the control API that tikray drives.
//
// Environment:
//
//	TIKRAY_DATA       the data root (default /data)
//	XRAY_GOMEMLIMIT   xray's GOMEMLIMIT (default 128MiB; "off" leaves it unset)
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/Arman2122/tikray/internal/runner"
	"github.com/Arman2122/tikray/internal/runner/netsetup"
)

const (
	// listenPort is the control API's port, on the ingress link's address.
	listenPort = "8080"
	// stageDir is where the supervisor stages cores, which RouterOS places
	// without the execute bit.
	stageDir = "/run/xray"

	defaultData     = "/data"
	defaultMemLimit = "128MiB"

	readHeaderTimeout = 10 * time.Second
	idleTimeout       = time.Minute
	// shutdownGrace is how long in-flight requests get to finish after
	// SIGTERM; a trial can be waiting out its xray run -test.
	shutdownGrace = 10 * time.Second
)

func main() {
	log.SetFlags(log.Ltime | log.Lmsgprefix)
	log.SetPrefix("tikray-runner: ")
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	logSysctls(netsetup.Sysctls())
	ingress, addr, err := waitIngress(ctx)
	if err != nil {
		log.Print(err)
		return 1
	}
	log.Printf("ingress link %s, address %s", ingress.Attrs().Name, addr)

	dirs := runner.Dirs{Data: env("TIKRAY_DATA", defaultData)}
	token, err := runner.LoadOrCreateToken(dirs)
	if err != nil {
		log.Printf("token: %v", err)
		return 1
	}

	r := runner.New(runner.Config{Supervisor: runner.SupervisorConfig{
		Dirs:       dirs,
		StageDir:   stageDir,
		GoMemLimit: memLimit(os.Getenv("XRAY_GOMEMLIMIT")),
		Log:        os.Stdout, // an *os.File, so cmd.Wait never waits on a copy goroutine
	}})
	// A bad active.json leaves the runner empty but usable: keep serving, so
	// the control plane can repair the state.
	if err := r.Boot(); err != nil {
		log.Printf("boot: %v", err)
	}

	keepCtx, stopKeep := context.WithCancel(ctx)
	defer stopKeep()
	keepDone := make(chan struct{})
	go func() {
		defer close(keepDone)
		netsetup.Keep(keepCtx, ingress, r.Healthy, r.SetNet)
	}()

	// No WriteTimeout: a trial request lasts as long as the xray run -test
	// window.
	srv := &http.Server{
		Addr:              net.JoinHostPort(addr, listenPort),
		Handler:           runner.NewServer(r, token, r.XrayAPI),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
	served := make(chan error, 1)
	go func() { served <- srv.ListenAndServe() }()
	log.Printf("serving the control API on %s", srv.Addr)

	code := 0
	select {
	case <-ctx.Done():
		log.Print("stopping")
	case err := <-served:
		log.Printf("control API: %v", err)
		code = 1
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		srv.Close()
	}
	if err := r.Close(); err != nil {
		log.Printf("stopping xray: %v", err)
	}
	stopKeep() // Keep stops answering ping on its way out
	<-keepDone
	return code
}

// waitIngress waits for the IPv4 default route and an address on its link, and
// returns the link and its first IPv4 address. The container's network may not
// be configured yet when the runner starts.
func waitIngress(ctx context.Context) (netlink.Link, string, error) {
	for {
		link, err := netsetup.Ingress()
		if err == nil {
			var addr string
			if addr, err = firstIPv4(link); err == nil {
				return link, addr, nil
			}
		}
		log.Printf("waiting for the ingress link: %v", err)
		select {
		case <-ctx.Done():
			return nil, "", errors.New("stopped before the ingress link was ready")
		case <-time.After(time.Second):
		}
	}
}

func firstIPv4(link netlink.Link) (string, error) {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if a.IP.To4() != nil {
			return a.IP.String(), nil
		}
	}
	return "", fmt.Errorf("%s has no IPv4 address", link.Attrs().Name)
}

func logSysctls(res map[string]error) {
	keys := make([]string, 0, len(res))
	for k := range res {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if res[k] != nil {
			log.Printf("sysctl %s: %v", k, res[k])
		}
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// memLimit is xray's GOMEMLIMIT for the value of XRAY_GOMEMLIMIT: unset or
// empty takes the default and "off" leaves GOMEMLIMIT unset.
func memLimit(v string) string {
	switch v {
	case "":
		return defaultMemLimit
	case "off":
		return ""
	}
	return v
}
