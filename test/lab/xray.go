package lab

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// xrayModVersion is the lab's xray-core: module v1.260327.0 is xray 26.3.27.
const xrayModVersion = "v1.260327.0"

// XrayBinary builds xray-core for goarch (once) and returns the cached path
// <cacheDir>/xray/<version>/<goarch>/xray. It builds from the Go module proxy,
// so it works where GitHub release downloads are blocked.
func XrayBinary(ctx context.Context, cacheDir, goarch string) (string, error) {
	out := filepath.Join(cacheDir, "xray", xrayModVersion, goarch, "xray")
	if _, err := os.Stat(out); err == nil {
		return out, nil
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return "", err
	}
	mod, err := os.MkdirTemp("", "labxray-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(mod)
	env := append(os.Environ(), "GOTOOLCHAIN=auto", "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0", "GOFLAGS=-mod=mod")
	steps := [][]string{
		{"go", "mod", "init", "labxray"},
		{"go", "get", "github.com/xtls/xray-core@" + xrayModVersion},
		{"go", "build", "-trimpath", "-ldflags", "-s -w", "-o", out + ".part", "github.com/xtls/xray-core/main"},
	}
	for _, s := range steps {
		cmd := exec.CommandContext(ctx, s[0], s[1:]...)
		cmd.Dir, cmd.Env = mod, env
		if b, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("%s: %v: %s", strings.Join(s, " "), err, b)
		}
	}
	return out, os.Rename(out+".part", out)
}
