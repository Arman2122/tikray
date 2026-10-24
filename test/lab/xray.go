package lab

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// defaultXray is the lab's default xray-core: module v1.260327.0 is xray
// 26.3.27, the newest release on the Go module proxy.
const defaultXray = "v1.260327.0"

var (
	moduleVersion = regexp.MustCompile(`^v1\.(\d{2})(\d{2})(\d{2})\.0$`)
	releaseTag    = regexp.MustCompile(`^v(\d{2})\.(\d{1,2})\.(\d{1,2})$`)
)

// LabXrayVersion is the xray-core the lab runs: $TIKRAY_LAB_XRAY, either a
// Go module version (v1.YYMMDD.0, built from the module proxy) or an XTLS
// release tag (vYY.M.D, built from a shallow git clone).
func LabXrayVersion() string {
	if v := os.Getenv("TIKRAY_LAB_XRAY"); v != "" {
		return v
	}
	return defaultXray
}

// XrayCoreVersion is the xray release number for a lab version, as used in
// core slot paths: v1.260327.0 → 26.3.27, v26.10.21 → 26.10.21.
func XrayCoreVersion(v string) (string, error) {
	var parts []string
	if m := moduleVersion.FindStringSubmatch(v); m != nil {
		parts = m[1:]
	} else if m := releaseTag.FindStringSubmatch(v); m != nil {
		parts = m[1:]
	} else {
		return "", fmt.Errorf("xray version %q is neither a module version (v1.YYMMDD.0) nor a release tag (vYY.M.D)", v)
	}
	nums := make([]string, len(parts))
	for i, p := range parts {
		n, _ := strconv.Atoi(p)
		nums[i] = strconv.Itoa(n)
	}
	return strings.Join(nums, "."), nil
}

// XrayBinary builds the lab's xray-core (LabXrayVersion) for goarch.
func XrayBinary(ctx context.Context, cacheDir, goarch string) (string, error) {
	return XrayBinaryVersion(ctx, cacheDir, LabXrayVersion(), goarch)
}

// XrayBinaryVersion builds xray-core version for goarch (once) and returns the
// cached path <cacheDir>/xray/<version>/<goarch>/xray. Module versions build
// from the Go module proxy and release tags from a shallow clone, so neither
// needs GitHub release downloads.
func XrayBinaryVersion(ctx context.Context, cacheDir, version, goarch string) (string, error) {
	if _, err := XrayCoreVersion(version); err != nil {
		return "", err
	}
	out := filepath.Join(cacheDir, "xray", version, goarch, "xray")
	if _, err := os.Stat(out); err == nil {
		return out, nil
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return "", err
	}
	env := append(os.Environ(), "GOTOOLCHAIN=auto", "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	build := []string{"go", "build", "-trimpath", "-ldflags", "-s -w", "-o", out + ".part"}
	var dir string
	var steps [][]string
	if moduleVersion.MatchString(version) {
		mod, err := os.MkdirTemp("", "labxray-")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(mod)
		dir, env = mod, append(env, "GOFLAGS=-mod=mod")
		steps = [][]string{
			{"go", "mod", "init", "labxray"},
			{"go", "get", "github.com/xtls/xray-core@" + version},
			append(build, "github.com/xtls/xray-core/main"),
		}
	} else {
		dir = filepath.Join(cacheDir, "xray-src", version)
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
			os.RemoveAll(dir)
			clone := exec.CommandContext(ctx, "git", "clone", "-q", "--depth", "1", "--branch", version, "https://github.com/XTLS/xray-core", dir)
			clone.Env = append(os.Environ(), "GIT_LFS_SKIP_SMUDGE=1")
			if b, err := clone.CombinedOutput(); err != nil {
				return "", fmt.Errorf("clone xray-core %s: %v: %s", version, err, b)
			}
		}
		steps = [][]string{append(build, "./main")}
	}
	for _, s := range steps {
		cmd := exec.CommandContext(ctx, s[0], s[1:]...)
		cmd.Dir, cmd.Env = dir, env
		if b, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("%s: %v: %s", strings.Join(s, " "), err, b)
		}
	}
	return out, os.Rename(out+".part", out)
}
