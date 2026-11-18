package main

import (
	"context"
	"fmt"
	"io"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/service"
)

// The daemon coordinates the runner and RouterOS; running a local updater
// when it is down could bypass the pending geo transaction.
func (c *cli) geoCommand(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return c.usageError("geo status, update or rollback is required")
	}
	var call apiCall
	switch args[0] {
	case "help", "--help", "-h":
		io.WriteString(c.stdout, usageText)
		return 0
	case "status":
		return c.geoStatusCommand(ctx, args[1:])
	case "update":
		fs := c.newFlagSet("geo update", "geo update <version|latest> [--profile NAME]")
		profile := fs.String("profile", "", "geo publisher profile: v2fly, loyalsoldier, iran or custom")
		// flag.FlagSet otherwise copies an unknown flag into stderr.
		fs.SetOutput(io.Discard)
		pos, code, ok := c.parse(fs, args[1:], 1)
		if !ok {
			return code
		}
		if !artifacts.ValidGeoTarget(*profile, pos[0]) {
			return c.flagError(fs, "invalid geo profile or release")
		}
		call = func(cl *apiclient.Client, ctx context.Context) (apiclient.Response, error) {
			return cl.GeoUpdate(ctx, *profile, pos[0])
		}
	case "rollback":
		fs := c.newFlagSet("geo rollback", "geo rollback")
		fs.SetOutput(io.Discard)
		if _, code, ok := c.parse(fs, args[1:], 0); !ok {
			return code
		}
		call = (*apiclient.Client).GeoRollback
	default:
		return c.usageError("unknown geo command")
	}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		resp, err := call(cl, ctx)
		if err != nil {
			return c.failAPI(ctx, err)
		}
		return c.passJSON(resp)
	})
}

func (c *cli) geoStatusCommand(ctx context.Context, args []string) int {
	fs := c.newFlagSet("geo status", "geo status [--json]")
	asJSON := fs.Bool("json", false, "print the API's JSON instead of a summary")
	if _, code, ok := c.parse(fs, args, 0); !ok {
		return code
	}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		resp, err := cl.Geo(ctx)
		if err != nil {
			return c.failAPI(ctx, err)
		}
		if *asJSON {
			return c.passJSON(resp)
		}
		var info service.GeoInfo
		if err := resp.Decode(&info); err != nil {
			return c.fail(err)
		}
		tw := c.table()
		active := info.Active
		if active == "" {
			active = "(none)"
		}
		profile := info.Profile
		if profile == "" {
			profile = "(unset)"
		}
		fmt.Fprintf(tw, "active\t%s\n", oneWord(active))
		fmt.Fprintf(tw, "profile\t%s\n", oneWord(profile))
		fmt.Fprintf(tw, "slots\t%d\n", len(info.Slots))
		if info.Degraded {
			fmt.Fprintln(tw, "degraded\tyes")
		}
		for _, sl := range info.Slots {
			mark := " "
			if sl.Slot == info.Active {
				mark = "*"
			}
			fmt.Fprintf(tw, "  %s %s\tprofile=%s\tprefixes=%d\n", mark, oneWord(sl.Slot), oneWord(sl.Profile), sl.PrefixCount)
		}
		if err := tw.Flush(); err != nil {
			return c.fail(err)
		}
		return 0
	})
}
