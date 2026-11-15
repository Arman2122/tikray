package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/Arman2122/tikray/internal/atomicfile"
	"github.com/Arman2122/tikray/internal/service"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

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

func (cfg *Config) setImageSource(controlMode, controlWindow, runnerMode, runnerWindow string) error {
	cfg.imageEnv = cfg.ImageUpstream != "" || len(cfg.ImageMirrors) > 0 || controlMode != "" || controlWindow != "" || runnerMode != "" || runnerWindow != ""
	if cfg.ImageUpstream != "" && !geoHTTPS(cfg.ImageUpstream) {
		return errors.New("tikray: image publisher must be HTTPS")
	}
	for _, m := range cfg.ImageMirrors {
		if !geoHTTPS(m) || !strings.Contains(m, "{file}") {
			return errors.New("tikray: invalid HTTPS image mirror template")
		}
	}
	control, err := service.ParseImageSchedule(controlMode, controlWindow)
	if err != nil {
		return err
	}
	runner, err := service.ParseImageSchedule(runnerMode, runnerWindow)
	if err != nil {
		return err
	}
	if cfg.ImageUpstream != "" {
		cfg.ImageSchedules = &service.ImageSchedules{Control: control, Runner: runner}
	}
	return nil
}

// The installed RouterOS env list has an exact owner identity. Configure a
// publisher on the private control volume without altering that list.
func ownerImageSource(cfg Config) (Config, error) {
	if cfg.imageEnv || cfg.ImageUpstream != "" || len(cfg.ImageMirrors) != 0 {
		return cfg, nil
	}
	b, err := atomicfile.ReadRegular(filepath.Join(stateDir(cfg.Data), "image-source.json"), 16<<10, 0600)
	if errors.Is(err, fs.ErrNotExist) {
		return cfg, nil
	}
	bad := errors.New("tikray: invalid private image publisher configuration")
	if err != nil {
		return cfg, bad
	}
	var src struct {
		Version       int      `json:"version"`
		Upstream      string   `json:"upstream"`
		Mirrors       []string `json:"mirrors"`
		ControlMode   string   `json:"control_mode"`
		ControlWindow string   `json:"control_window"`
		RunnerMode    string   `json:"runner_mode"`
		RunnerWindow  string   `json:"runner_window"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&src) != nil || dec.Decode(new(any)) != io.EOF || src.Version != 1 {
		return cfg, bad
	}
	next := cfg
	next.ImageUpstream, next.ImageMirrors = src.Upstream, src.Mirrors
	if err := next.setImageSource(src.ControlMode, src.ControlWindow, src.RunnerMode, src.RunnerWindow); err != nil {
		return cfg, bad
	}
	return next, nil
}
