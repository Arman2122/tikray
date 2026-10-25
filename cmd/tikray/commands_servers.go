package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
)

// The commands on servers, subscriptions, devices and the default policy. Each
// makes one call of the API (see commands.go) and prints what it did in a
// line, or a table, with no credential in it.

// subcommands dispatches the first argument of a command with subcommands
// (server, sub, device, policy) to the one that handles it.
func (c *cli) subcommands(noun string, args []string, table map[string]func(args []string) int) int {
	if len(args) == 0 {
		return c.usageError("")
	}
	switch args[0] {
	case "help", "-h", "--help":
		io.WriteString(c.stdout, usageText)
		return 0
	}
	if f, ok := table[args[0]]; ok {
		return f(args[1:])
	}
	return c.usageError(fmt.Sprintf("unknown %s command %q", noun, args[0]))
}

// --- servers

func (c *cli) serverCommand(ctx context.Context, args []string) int {
	byID := func(verb string, do func(ctx context.Context, cl *apiclient.Client, id string) int) func([]string) int {
		return func(args []string) int {
			fs := c.newFlagSet("server "+verb, "server "+verb+" <id>")
			pos, code, ok := c.parse(fs, args, 1)
			if !ok {
				return code
			}
			return c.withDaemon(ctx, func(cl *apiclient.Client) int { return do(ctx, cl, pos[0]) })
		}
	}
	return c.subcommands("server", args, map[string]func([]string) int{
		"add":  func(args []string) int { return c.serverAdd(ctx, args) },
		"list": func(args []string) int { return c.serverList(ctx, args) },
		"rm":   byID("rm", c.serverRemove),
		"enable": byID("enable", func(ctx context.Context, cl *apiclient.Client, id string) int {
			return c.serverEnable(ctx, cl, id, true)
		}),
		"disable": byID("disable", func(ctx context.Context, cl *apiclient.Client, id string) int {
			return c.serverEnable(ctx, cl, id, false)
		}),
	})
}

func (c *cli) serverAdd(ctx context.Context, args []string) int {
	fs := c.newFlagSet("server add", "server add <link> | --json FILE [--name N]")
	file := fs.String("json", "", "read the xray outbound, a JSON object, from `FILE` instead of a share link; the server needs a --name then")
	name := fs.String("name", "", "the server's `NAME`; a share link has one of its own")
	pos, code, ok := c.parseRange(fs, args, 0, 1)
	if !ok {
		return code
	}
	switch {
	case len(pos) == 1 && *file != "":
		return c.flagError(fs, "give a share link or --json FILE, not both")
	case len(pos) == 0 && *file == "":
		return c.flagError(fs, "give a share link or --json FILE")
	case *file != "" && *name == "":
		return c.flagError(fs, "--json needs --name: an outbound has no name of its own")
	}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		n := apiclient.NewServer{Name: *name}
		if *file != "" {
			outbound, err := readOutbound(*file)
			if err != nil {
				return c.fail(err)
			}
			n.Outbound = outbound
		} else {
			n.Link = pos[0]
		}
		resp, err := cl.AddServer(ctx, n)
		if err != nil {
			return c.failAPI(ctx, err)
		}
		var srv store.Server
		if err := resp.Decode(&srv); err != nil {
			return c.fail(err)
		}
		protocol, endpoint := outboundEndpoint(srv.Outbound)
		return c.say("added server %s (%s): %s %s", oneWord(srv.ID), oneLine(srv.Name), protocol, endpoint)
	})
}

// readOutbound reads the xray outbound in the file: one JSON object. The errors
// name the file and never its content, which holds the credentials.
func readOutbound(file string) (json.RawMessage, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if !json.Valid(b) {
		return nil, fmt.Errorf("%s is not valid JSON", file)
	}
	if b = []byte(strings.TrimSpace(string(b))); b[0] != '{' {
		return nil, fmt.Errorf("%s is not a JSON object", file)
	}
	return b, nil
}

func (c *cli) serverList(ctx context.Context, args []string) int {
	fs := c.newFlagSet("server list", "server list [--json]")
	asJSON := fs.Bool("json", false, "print the API's JSON, with the servers' credentials, instead of a table")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		resp, err := cl.Servers(ctx)
		if err != nil {
			return c.failAPI(ctx, err)
		}
		if *asJSON {
			return c.passJSON(resp)
		}
		var servers []store.Server
		if err := resp.Decode(&servers); err != nil {
			return c.fail(err)
		}
		return c.printServers(servers)
	})
}

func (c *cli) serverRemove(ctx context.Context, cl *apiclient.Client, id string) int {
	if _, err := cl.RemoveServer(ctx, id); err != nil {
		return c.failAPI(ctx, err)
	}
	return c.say("removed server %s", oneWord(id))
}

func (c *cli) serverEnable(ctx context.Context, cl *apiclient.Client, id string, enabled bool) int {
	disabled := !enabled
	resp, err := cl.UpdateServer(ctx, id, apiclient.ServerPatch{Disabled: &disabled})
	if err != nil {
		return c.failAPI(ctx, err)
	}
	var srv store.Server
	if err := resp.Decode(&srv); err != nil {
		return c.fail(err)
	}
	state := "enabled"
	if srv.Disabled {
		state = "disabled"
	}
	return c.say("server %s (%s) %s", oneWord(srv.ID), oneLine(srv.Name), state)
}

// --- subscriptions

func (c *cli) subCommand(ctx context.Context, args []string) int {
	byID := func(verb string, do func(ctx context.Context, cl *apiclient.Client, id string) int) func([]string) int {
		return func(args []string) int {
			fs := c.newFlagSet("sub "+verb, "sub "+verb+" <id>")
			pos, code, ok := c.parse(fs, args, 1)
			if !ok {
				return code
			}
			return c.withDaemon(ctx, func(cl *apiclient.Client) int { return do(ctx, cl, pos[0]) })
		}
	}
	return c.subcommands("sub", args, map[string]func([]string) int{
		"add":     func(args []string) int { return c.subAdd(ctx, args) },
		"list":    func(args []string) int { return c.subList(ctx, args) },
		"rm":      byID("rm", c.subRemove),
		"refresh": byID("refresh", c.subRefresh),
	})
}

func (c *cli) subAdd(ctx context.Context, args []string) int {
	fs := c.newFlagSet("sub add", "sub add <url> [--name N] [--interval 24h]")
	name := fs.String("name", "", "the subscription's `NAME` (default: the host of the URL)")
	interval := fs.Duration("interval", 0, "how often to fetch it again, at least 1h (default 24h)")
	pos, code, ok := c.parse(fs, args, 1)
	if !ok {
		return code
	}
	// The URL is a credential: it is sent and never printed. A name is made
	// of its host, which names the provider and not the account.
	n := apiclient.NewSubscription{Name: *name, URL: pos[0], Interval: store.Duration(*interval)}
	if n.Name == "" {
		u, err := url.Parse(pos[0])
		if err != nil || u.Hostname() == "" {
			return c.flagError(fs, "give --name: the URL has no host to name the subscription by")
		}
		n.Name = u.Hostname()
	}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		resp, err := cl.AddSubscription(ctx, n)
		if err != nil {
			return c.failAPI(ctx, err)
		}
		var sub store.Subscription
		if err := resp.Decode(&sub); err != nil {
			return c.fail(err)
		}
		id := oneWord(sub.ID)
		return c.say("added subscription %s (%s), fetched every %s; `tikray sub refresh %s` fetches it now",
			id, oneLine(sub.Name), shortDuration(time.Duration(sub.Interval)), id)
	})
}

func (c *cli) subList(ctx context.Context, args []string) int {
	fs := c.newFlagSet("sub list", "sub list [--json]")
	asJSON := fs.Bool("json", false, "print the API's JSON, with the subscriptions' URLs, instead of a table")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		resp, err := cl.Subscriptions(ctx)
		if err != nil {
			return c.failAPI(ctx, err)
		}
		if *asJSON {
			return c.passJSON(resp)
		}
		var subs []store.Subscription
		if err := resp.Decode(&subs); err != nil {
			return c.fail(err)
		}
		// The service redacts the error it records, and an error of net/http
		// repeats the URL it was for: redact once more here, so that a URL
		// that got through is not the one thing a table shows.
		redact := service.RedactorFor(store.State{Subscriptions: subs})
		tw := c.table()
		fmt.Fprintln(tw, "ID\tNAME\tINTERVAL\tLAST FETCH\tSTATE\tLAST ERROR")
		for _, s := range subs {
			state := "enabled"
			if s.Disabled {
				state = "disabled"
			}
			lastErr := oneLine(redact(s.LastError))
			if lastErr == "" {
				lastErr = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", oneWord(s.ID), oneLine(s.Name), shortDuration(time.Duration(s.Interval)), atTime(s.LastFetch), state, lastErr)
		}
		if err := tw.Flush(); err != nil {
			return c.fail(err)
		}
		return 0
	})
}

func (c *cli) subRemove(ctx context.Context, cl *apiclient.Client, id string) int {
	if _, err := cl.RemoveSubscription(ctx, id); err != nil {
		return c.failAPI(ctx, err)
	}
	return c.say("removed subscription %s", oneWord(id))
}

func (c *cli) subRefresh(ctx context.Context, cl *apiclient.Client, id string) int {
	resp, err := cl.RefreshSubscription(ctx, id)
	if err != nil {
		return c.failAPI(ctx, err)
	}
	var res apiclient.RefreshResult
	if err := resp.Decode(&res); err != nil {
		return c.fail(err)
	}
	c.say("refreshed subscription %s via %s: %d added, %d updated, %d removed, %d kept",
		oneWord(id), oneWord(res.Via), res.Added, res.Updated, res.Removed, res.Kept)
	// The service words each skipped line as its scheme and name; it is
	// printed as it is, made one line.
	for _, s := range res.Skipped {
		c.say("skipped %s: %s", oneLine(s.Line), oneLine(s.Reason))
	}
	return 0
}

// --- devices and the default policy

func (c *cli) deviceCommand(ctx context.Context, args []string) int {
	return c.subcommands("device", args, map[string]func([]string) int{
		"set":  func(args []string) int { return c.deviceSet(ctx, args) },
		"rm":   func(args []string) int { return c.deviceRemove(ctx, args) },
		"list": func(args []string) int { return c.deviceList(ctx, args) },
	})
}

// parseDeviceAddress reads a device address: a CIDR prefix, or an IP address
// for that address alone.
func parseDeviceAddress(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return a.Prefix(a.BitLen())
}

// parseMode reads a policy mode.
func parseMode(s string) (store.Mode, bool) {
	switch m := store.Mode(s); m {
	case store.ModeDirect, store.ModeSmart, store.ModeFull:
		return m, true
	}
	return "", false
}

// describePolicy is "smart", or "smart (kill switch)".
func describePolicy(p store.Policy) string {
	if p.KillSwitch {
		return string(p.Mode) + " (kill switch)"
	}
	return string(p.Mode)
}

func (c *cli) deviceSet(ctx context.Context, args []string) int {
	fs := c.newFlagSet("device set", "device set <ip|cidr> <direct|smart|full> [--kill-switch] [--name N]")
	kill := fs.Bool("kill-switch", false, "block the device's proxied traffic while the proxy is unavailable, instead of letting it out direct")
	name := fs.String("name", "", "the device's `NAME`")
	pos, code, ok := c.parse(fs, args, 2)
	if !ok {
		return code
	}
	addr, err := parseDeviceAddress(pos[0])
	if err != nil {
		return c.flagError(fs, "the address must be an IP address or a CIDR prefix, such as 192.168.88.10 or 192.168.88.0/24")
	}
	mode, ok := parseMode(pos[1])
	if !ok {
		return c.flagError(fs, "the mode must be direct, smart or full")
	}
	dev := store.Device{Address: addr, Name: *name, Policy: store.Policy{Mode: mode, KillSwitch: *kill}}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		if _, err := cl.SetDevice(ctx, dev); err != nil {
			return c.failAPI(ctx, err)
		}
		return c.say("device %s set to %s", addr, describePolicy(dev.Policy))
	})
}

func (c *cli) deviceRemove(ctx context.Context, args []string) int {
	fs := c.newFlagSet("device rm", "device rm <ip|cidr>")
	pos, code, ok := c.parse(fs, args, 1)
	if !ok {
		return code
	}
	addr, err := parseDeviceAddress(pos[0])
	if err != nil {
		return c.flagError(fs, "the address must be an IP address or a CIDR prefix, such as 192.168.88.10 or 192.168.88.0/24")
	}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		if _, err := cl.RemoveDevice(ctx, addr); err != nil {
			return c.failAPI(ctx, err)
		}
		return c.say("removed device %s", addr)
	})
}

func (c *cli) deviceList(ctx context.Context, args []string) int {
	fs := c.newFlagSet("device list", "device list [--json]")
	asJSON := fs.Bool("json", false, "print the API's JSON instead of a table")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		resp, err := cl.Devices(ctx)
		if err != nil {
			return c.failAPI(ctx, err)
		}
		if *asJSON {
			return c.passJSON(resp)
		}
		var devices []store.Device
		if err := resp.Decode(&devices); err != nil {
			return c.fail(err)
		}
		tw := c.table()
		fmt.Fprintln(tw, "ADDRESS\tNAME\tMODE\tKILL-SWITCH")
		for _, d := range devices {
			kill, name := "no", oneLine(d.Name)
			if d.Policy.KillSwitch {
				kill = "yes"
			}
			if name == "" {
				name = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", d.Address, name, oneWord(string(d.Policy.Mode)), kill)
		}
		if err := tw.Flush(); err != nil {
			return c.fail(err)
		}
		return 0
	})
}

func (c *cli) policyCommand(ctx context.Context, args []string) int {
	return c.subcommands("policy", args, map[string]func([]string) int{
		"default": func(args []string) int { return c.policyDefault(ctx, args) },
	})
}

func (c *cli) policyDefault(ctx context.Context, args []string) int {
	fs := c.newFlagSet("policy default", "policy default <direct|smart|full> [--kill-switch]")
	kill := fs.Bool("kill-switch", false, "block proxied traffic while the proxy is unavailable, instead of letting it out direct")
	pos, code, ok := c.parse(fs, args, 1)
	if !ok {
		return code
	}
	mode, ok := parseMode(pos[0])
	if !ok {
		return c.flagError(fs, "the mode must be direct, smart or full")
	}
	p := store.Policy{Mode: mode, KillSwitch: *kill}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		if _, err := cl.SetPolicy(ctx, p); err != nil {
			return c.failAPI(ctx, err)
		}
		return c.say("default policy set to %s", describePolicy(p))
	})
}
