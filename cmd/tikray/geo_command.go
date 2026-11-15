package main

import (
	"context"
	"io"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/artifacts"
)

// The daemon coordinates the runner and RouterOS; running a local updater
// when it is down could bypass the pending geo transaction.
func (c *cli) geoCommand(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return c.usageError("geo update or rollback is required")
	}
	var call apiCall
	switch args[0] {
	case "help", "--help", "-h":
		io.WriteString(c.stdout, usageText)
		return 0
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
