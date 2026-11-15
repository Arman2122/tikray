package main

import (
	"context"
	"io"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/artifacts"
)

func (c *cli) imageCommand(ctx context.Context, args []string) int {
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		io.WriteString(c.stdout, usageText)
		return 0
	}
	if len(args) < 2 {
		return c.usageError("image status, update or rollback requires a component")
	}
	component := args[1]
	if component == "tikray-runner" {
		component = "runner"
	}
	if !artifacts.ValidImageComponent(component) {
		return c.usageError("image component must be tikray or runner")
	}
	var call apiCall
	switch args[0] {
	case "update":
		if len(args) != 3 || !artifacts.ValidImageVersion(args[2]) {
			return c.usageError("image update requires a release version")
		}
		call = func(cl *apiclient.Client, ctx context.Context) (apiclient.Response, error) {
			return cl.ImageUpdate(ctx, component, args[2])
		}
	case "status", "rollback":
		if len(args) != 2 {
			return c.usageError("image status and rollback take only a component")
		}
		call = func(cl *apiclient.Client, ctx context.Context) (apiclient.Response, error) {
			if args[0] == "status" {
				return cl.ImageStatus(ctx, component)
			}
			return cl.ImageRollback(ctx, component)
		}
	default:
		return c.usageError("unknown image command")
	}
	return c.withDaemon(ctx, func(cl *apiclient.Client) int {
		res, err := call(cl, ctx)
		if err != nil {
			return c.failAPI(ctx, err)
		}
		return c.passJSON(res)
	})
}
