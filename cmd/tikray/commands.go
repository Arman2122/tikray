package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/health"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
)

// The commands that talk to tikray serve, over its API. They never write the
// state, and what they print leaves out every credential: an outbound's, a
// subscription's URL, the API token. Only --json prints the API's answer as
// it is. The nouns are in commands_servers.go (server, sub, device and
// policy); here are the daemon, status and events.

// apiCall is a call of the API that a command makes, written as a method
// expression, such as (*apiclient.Client).Apply.
type apiCall func(*apiclient.Client, context.Context) (apiclient.Response, error)

// probeWait is how long the daemon has to answer GET /healthz before a command
// stops waiting for it. It is a variable for the tests.
var probeWait = 2 * time.Second

// daemon looks for tikray serve at cfg.API with GET /healthz, which needs no
// token. If it answers, daemon returns a client for it with the token (the
// token is not read before a daemon is found).
//
// Nothing listening (the connection is refused) is running false with no
// error: there is no daemon, and a command that has a direct path takes it.
// Every other way of not getting an answer is an error. A certificate that is
// not the pinned one, an answer that is not a 200, or none within probeWait
// each mean that something is there, or may be, that this process can't
// reach, and a direct path would write the state beside it.
func (c *cli) daemon(ctx context.Context, cfg Config) (cl *apiclient.Client, running bool, err error) {
	cl, err = cfg.apiClient()
	if err != nil {
		return nil, false, err
	}
	pctx, cancel := context.WithTimeout(ctx, probeWait)
	defer cancel()
	switch err := cl.Healthz(pctx); {
	case err == nil:
	case errors.Is(err, syscall.ECONNREFUSED):
		return nil, false, nil
	case ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded):
		return nil, false, fmt.Errorf("tikray serve at %s did not answer /healthz within %s", cfg.API, probeWait)
	case cl.Fingerprint == "":
		return nil, false, fmt.Errorf("something answers at %s, but there is no certificate fingerprint to trust it by: set TIKRAY_API_FINGERPRINT, or restore state/tls.crt in the data root (%v)", cfg.API, err)
	default:
		return nil, false, fmt.Errorf("tikray serve at %s can't be used: %w", cfg.API, err)
	}
	if cl.Token, err = cfg.apiToken(); err != nil {
		return nil, false, err
	}
	return cl, true, nil
}

// withDaemon runs do against the daemon. The commands that read or change the
// state through the API have no other path: without a daemon they fail.
func (c *cli) withDaemon(ctx context.Context, do func(cl *apiclient.Client) int) int {
	cfg, err := configFromEnv(c.getenv)
	if err != nil {
		return c.fail(err)
	}
	cl, running, err := c.daemon(ctx, cfg)
	switch {
	case err != nil:
		return c.fail(err)
	case !running:
		return c.fail(fmt.Errorf("tikray serve is not running (nothing listens at %s)", cfg.API))
	}
	return do(cl)
}

// viaDaemon has the daemon run an apply, an update or a rollback, and reports
// its result as the direct path does. The daemon's failure to do it is a
// refused result with its words (see runUpdater).
func (c *cli) viaDaemon(ctx context.Context, cfg Config, base artifacts.Result, cl *apiclient.Client, call apiCall) int {
	if call == nil {
		return c.refused(cfg, base, errors.New("--config can't go through tikray serve, which owns the state and applies it: stop the service to run a core with a config file"))
	}
	resp, err := call(cl, ctx)
	if err != nil {
		return c.refused(cfg, base, c.apiError(ctx, err))
	}
	var res artifacts.Result
	if err := resp.Decode(&res); err != nil {
		return c.refused(cfg, base, err)
	}
	return c.report(cfg, res, nil)
}

// apiError is err as a command reports it. The daemon's error is its code and
// its detail, which it has redacted. A command that was interrupted
// (SIGINT, SIGTERM) leaves the operation it asked for running in the daemon,
// which finishes it whether or not anyone waits: say so, rather than that it
// failed.
func (c *cli) apiError(ctx context.Context, err error) error {
	var e *apiclient.Error
	switch {
	case ctx.Err() != nil:
		return errors.New("interrupted; tikray serve goes on with it, and `tikray events` shows how it ends")
	case errors.As(err, &e):
		switch {
		case e.Code == "":
			return fmt.Errorf("tikray serve answered %d", e.Status)
		case e.Detail == "":
			return errors.New(e.Code)
		}
		return fmt.Errorf("%s: %s", e.Code, oneLine(e.Detail))
	}
	return err
}

// failAPI reports a failed call, and returns 1.
func (c *cli) failAPI(ctx context.Context, err error) int {
	return c.fail(c.apiError(ctx, err))
}

// passJSON prints the API's answer as it is, with a newline at the end if it
// has none.
func (c *cli) passJSON(resp apiclient.Response) int {
	b := resp.Body
	if len(b) == 0 || b[len(b)-1] != '\n' {
		b = append(append([]byte(nil), b...), '\n')
	}
	if _, err := c.stdout.Write(b); err != nil {
		return c.fail(err)
	}
	return 0
}

// say prints a line on stdout.
func (c *cli) say(format string, args ...any) int {
	fmt.Fprintf(c.stdout, format+"\n", args...)
	return 0
}

// table returns a writer of aligned columns on stdout; flush it when done.
func (c *cli) table() *tabwriter.Writer {
	return tabwriter.NewWriter(c.stdout, 0, 8, 2, ' ', 0)
}

// --- what is shown of the state

// oneLine is s as one line of text for a terminal: every control character,
// line break and bidirectional override (store.ForbiddenInName) is a space,
// and runs of white space are one space. An event or an error from the
// service can hold the output of a program, which could otherwise rewrite
// the screen.
func oneLine(s string) string {
	mapped := strings.Map(func(r rune) rune {
		if store.ForbiddenInName(r) {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(mapped), " ")
}

// oneWord is s for a cell of a table that is one word: oneLine's characters, and
// white space, are dropped.
func oneWord(s string) string {
	return strings.Map(func(r rune) rune {
		if store.ForbiddenInName(r) || unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// outboundEndpoint is the protocol and the host:port of an xray outbound, for
// a person to tell servers apart: the names that the share-link parser and
// xray's config write (settings.vnext[0] and servers[0] for the older shape,
// settings.address and port for the flat one, and a WireGuard peer's
// endpoint). "-" is what it can't find. Nothing else of the outbound is read,
// and so none of its credentials can be shown.
func outboundEndpoint(raw json.RawMessage) (protocol, endpoint string) {
	type target struct {
		Address json.RawMessage `json:"address"`
		Port    json.RawMessage `json:"port"`
	}
	var o struct {
		Protocol string `json:"protocol"`
		Settings struct {
			target
			Vnext   []target `json:"vnext"`
			Servers []target `json:"servers"`
			Peers   []struct {
				Endpoint string `json:"endpoint"`
			} `json:"peers"`
		} `json:"settings"`
	}
	// A field of the wrong type fails the decoding but leaves the others.
	_ = json.Unmarshal(raw, &o)

	protocol = oneWord(strings.ToLower(o.Protocol))
	if protocol == "" {
		protocol = "-"
	}
	t := o.Settings.target
	switch {
	case len(t.Address) > 0:
	case len(o.Settings.Vnext) > 0:
		t = o.Settings.Vnext[0]
	case len(o.Settings.Servers) > 0:
		t = o.Settings.Servers[0]
	case len(o.Settings.Peers) > 0 && o.Settings.Peers[0].Endpoint != "":
		if e := oneWord(o.Settings.Peers[0].Endpoint); e != "" {
			return protocol, e
		}
	}
	var host string
	if json.Unmarshal(t.Address, &host) != nil || oneWord(host) == "" {
		return protocol, "-"
	}
	host = oneWord(host)
	if port := oneWord(strings.Trim(string(t.Port), `"`)); port != "" && port != "null" {
		return protocol, net.JoinHostPort(host, port)
	}
	return protocol, host
}

// serverState is the STATE of a server in a table.
func serverState(s store.Server) string {
	switch {
	case s.Invalid != "":
		return "disabled (invalid: " + oneLine(s.Invalid) + ")"
	case s.Disabled:
		return "disabled"
	}
	return "enabled"
}

// printServers prints the table of servers: id, name, protocol, address and
// state. No credential is in it.
func (c *cli) printServers(servers []store.Server) int {
	tw := c.table()
	fmt.Fprintln(tw, "ID\tNAME\tPROTOCOL\tADDRESS\tSTATE")
	for _, s := range servers {
		protocol, endpoint := outboundEndpoint(s.Outbound)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", oneWord(s.ID), oneLine(s.Name), protocol, endpoint, serverState(s))
	}
	if err := tw.Flush(); err != nil {
		return c.fail(err)
	}
	return 0
}

// shortDuration is d as "24h" rather than "24h0m0s".
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// atTime is t as text, "-" for the zero time.
func atTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// --- status and events

func (c *cli) statusCommand(ctx context.Context, args []string) int {
	fs := c.newFlagSet("status", "status [--json]")
	asJSON := fs.Bool("json", false, "print the API's JSON instead of a summary")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		resp, err := cl.Status(ctx)
		if err != nil {
			return c.failAPI(ctx, err)
		}
		if *asJSON {
			return c.passJSON(resp)
		}
		var st service.Status
		if err := resp.Decode(&st); err != nil {
			return c.fail(err)
		}
		// The names, and the protocol and address, of the servers the status
		// names by id.
		resp, err = cl.Servers(ctx)
		if err != nil {
			return c.failAPI(ctx, err)
		}
		var servers []store.Server
		if err := resp.Decode(&servers); err != nil {
			return c.fail(err)
		}
		return c.printStatus(st, servers)
	})
}

func (c *cli) eventsCommand(ctx context.Context, args []string) int {
	fs := c.newFlagSet("events", "events [--after N]")
	after := fs.Uint64("after", 0, "print the events after sequence number `N` (the Seq of the last one seen)")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		resp, err := cl.Events(ctx, *after)
		if err != nil {
			return c.failAPI(ctx, err)
		}
		var events []service.Event
		if err := resp.Decode(&events); err != nil {
			return c.fail(err)
		}
		return c.printEvents(events)
	})
}

// printEvents prints one line for each event: its number, time, kind and
// text. The text is the service's, redacted, and made one line.
func (c *cli) printEvents(events []service.Event) int {
	for _, e := range events {
		fmt.Fprintf(c.stdout, "%d  %s  %s  %s\n", e.Seq, atTime(e.At), oneWord(e.Kind), oneLine(e.Message))
	}
	return 0
}

// printStatus prints what the daemon reports of itself, and one line for each
// server with how the monitor sees it.
func (c *cli) printStatus(st service.Status, servers []store.Server) int {
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	tw := c.table()
	fmt.Fprintf(tw, "revision\t%d\n", st.Revision)
	fmt.Fprintf(tw, "applied\t%s\n", yes(st.Applied))
	fmt.Fprintf(tw, "pending\t%s\n", yes(st.Pending))
	switch {
	case st.Core == "":
		fmt.Fprintf(tw, "core\tnone\n")
	case st.CoreTested:
		fmt.Fprintf(tw, "core\t%s (tested)\n", oneWord(st.Core))
	default:
		fmt.Fprintf(tw, "core\t%s (this tikray has not tested it)\n", oneWord(st.Core))
	}
	if r := st.LastApply; r != nil {
		line := fmt.Sprintf("%s %s", oneWord(r.Outcome), atTime(r.At))
		if r.Detail != "" {
			line += " (" + oneLine(r.Detail) + ")"
		}
		fmt.Fprintf(tw, "last apply\t%s\n", line)
	}
	h := st.Health
	fmt.Fprintf(tw, "health\t%s\n", oneWord(h.Level))
	switch {
	case h.Runner.Err != "":
		fmt.Fprintf(tw, "runner\t%s\n", oneLine(h.Runner.Err))
	case h.Runner.Reachable:
		fmt.Fprintf(tw, "runner\t%s, routes %s, gateway %s\n", oneWord(h.Runner.State), upDown(h.Runner.RoutesOK), upDown(h.Runner.GatewayUp))
	}
	switch {
	case h.Probe.Ran && h.Probe.OK:
		fmt.Fprintf(tw, "probe\tok %s\n", atTime(h.Probe.At))
	case h.Probe.Ran:
		fmt.Fprintf(tw, "probe\tfailed %s: %s\n", atTime(h.Probe.At), oneLine(h.Probe.Err))
	}
	if len(st.Degraded) > 0 {
		ids := make([]string, len(st.Degraded))
		for i, id := range st.Degraded {
			ids[i] = oneWord(id)
		}
		fmt.Fprintf(tw, "degraded\t%s (disabled: this tikray refuses them)\n", strings.Join(ids, ", "))
	}
	if err := tw.Flush(); err != nil {
		return c.fail(err)
	}
	if len(servers) == 0 {
		return 0
	}

	seen := map[string]health.ServerHealth{}
	for _, s := range h.Servers {
		seen[s.ID] = s
	}
	fmt.Fprintln(c.stdout)
	tw = c.table()
	fmt.Fprintln(tw, "ID\tNAME\tPROTOCOL\tADDRESS\tSTATE")
	for _, s := range servers {
		protocol, endpoint := outboundEndpoint(s.Outbound)
		state := serverState(s)
		if !s.Disabled {
			if sh, ok := seen[s.ID]; ok {
				if sh.Alive {
					state += ", alive " + sh.Delay.Round(time.Millisecond).String()
				} else {
					state += ", dead"
				}
			}
			if h.Selected == s.ID {
				state += ", selected"
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", oneWord(s.ID), oneLine(s.Name), protocol, endpoint, state)
	}
	if err := tw.Flush(); err != nil {
		return c.fail(err)
	}
	return 0
}

func upDown(ok bool) string {
	if ok {
		return "ok"
	}
	return "down"
}
