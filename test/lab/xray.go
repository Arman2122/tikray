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
	"sync"
)

// defaultXray is the lab's default xray-core: the newest XTLS release tag.
const defaultXray = "latest"

const xrayRepo = "https://github.com/XTLS/xray-core"

var (
	moduleVersion = regexp.MustCompile(`^v1\.(\d{2})(\d{2})(\d{2})\.0$`)
	releaseTag    = regexp.MustCompile(`^v(\d{2})\.(\d{1,2})\.(\d{1,2})$`)
)

// LabXrayVersion is the xray-core the lab runs: $TIKRAY_LAB_XRAY, which is
// "latest" (the default: the newest XTLS release tag), an XTLS release tag
// (vYY.M.D, built from a shallow git clone) or a Go module version
// (v1.YYMMDD.0, built from the module proxy).
func LabXrayVersion() string {
	if v := os.Getenv("TIKRAY_LAB_XRAY"); v != "" {
		return v
	}
	return defaultXray
}

// ResolveXrayVersion turns "latest" into the newest XTLS release tag; other
// versions are returned unchanged.
func ResolveXrayVersion(ctx context.Context, v string) (string, error) {
	if v != "latest" {
		return v, nil
	}
	latestOnce.Do(func() {
		out, err := exec.CommandContext(ctx, "git", "ls-remote", "--tags", "--refs", xrayRepo).Output()
		if err != nil {
			latestErr = fmt.Errorf("list xray-core tags: %w", err)
			return
		}
		if latest = latestReleaseTag(strings.Split(string(out), "\n")); latest == "" {
			latestErr = fmt.Errorf("no xray-core release tag found")
		}
	})
	return latest, latestErr
}

var (
	latestOnce sync.Once
	latest     string
	latestErr  error
)

// latestReleaseTag picks the highest vYY.M.D tag from `git ls-remote --tags`
// lines; pre-release and module (v1.*) tags are skipped.
func latestReleaseTag(refs []string) string {
	best, bestKey := "", [3]int{}
	for _, line := range refs {
		_, ref, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		tag := strings.TrimPrefix(ref, "refs/tags/")
		m := releaseTag.FindStringSubmatch(tag)
		if m == nil {
			continue
		}
		var key [3]int
		for i := range key {
			key[i], _ = strconv.Atoi(m[i+1])
		}
		if best == "" || key[0] > bestKey[0] || key[0] == bestKey[0] && (key[1] > bestKey[1] || key[1] == bestKey[1] && key[2] > bestKey[2]) {
			best, bestKey = tag, key
		}
	}
	return best
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

// XrayBinary builds the lab's xray-core (LabXrayVersion, resolved) for goarch.
func XrayBinary(ctx context.Context, cacheDir, goarch string) (string, error) {
	v, err := ResolveXrayVersion(ctx, LabXrayVersion())
	if err != nil {
		return "", err
	}
	return XrayBinaryVersion(ctx, cacheDir, v, goarch)
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
			clone := exec.CommandContext(ctx, "git", "clone", "-q", "--depth", "1", "--branch", version, xrayRepo, dir)
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
