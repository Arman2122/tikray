package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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
		var tags []string
		if tags, latestErr = ReleaseTags(ctx); latestErr == nil {
			latest = tags[0]
		}
	})
	return latest, latestErr
}

var (
	latestOnce sync.Once
	latest     string
	latestErr  error
)

// ReleaseTags returns the XTLS xray-core release tags (vYY.M.D), newest
// first, as `git ls-remote --tags` of the xray-core repository lists them.
// Pre-release and module (v1.*) tags are skipped. It is an error if no tag
// is left.
func ReleaseTags(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "git", "ls-remote", "--tags", "--refs", xrayRepo).Output()
	if err != nil {
		return nil, fmt.Errorf("list xray-core tags: %w", err)
	}
	tags := releaseTags(strings.Split(string(out), "\n"))
	if len(tags) == 0 {
		return nil, fmt.Errorf("no xray-core release tag found")
	}
	return tags, nil
}

// releaseTags returns the vYY.M.D tags from `git ls-remote --tags` lines,
// highest first, comparing each number in turn; pre-release and module
// (v1.*) tags are skipped.
func releaseTags(refs []string) []string {
	type release struct {
		tag string
		key [3]int
	}
	var rs []release
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
		r := release{tag: tag}
		for i := range r.key {
			r.key[i], _ = strconv.Atoi(m[i+1])
		}
		rs = append(rs, r)
	}
	slices.SortStableFunc(rs, func(a, b release) int { return slices.Compare(b.key[:], a.key[:]) })
	tags := make([]string, len(rs))
	for i, r := range rs {
		tags[i] = r.tag
	}
	return tags
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
	run := func(dir string, env []string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Dir, cmd.Env = dir, env
		var stderr strings.Builder
		cmd.Stderr = &stderr
		b, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("%s: %v: %s%s", strings.Join(args, " "), err, b, stderr.String())
		}
		return b, nil
	}
	var dir, gomod, pkg string
	if moduleVersion.MatchString(version) {
		mod, err := os.MkdirTemp("", "labxray-")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(mod)
		dir, env = mod, append(env, "GOFLAGS=-mod=mod")
		for _, s := range [][]string{
			{"go", "mod", "init", "labxray"},
			{"go", "get", "github.com/xtls/xray-core@" + version},
		} {
			if _, err := run(dir, env, s...); err != nil {
				return "", err
			}
		}
		b, err := run(dir, env, "go", "mod", "download", "-json", "github.com/xtls/xray-core@"+version)
		if err != nil {
			return "", err
		}
		var m struct{ GoMod string }
		if err := json.Unmarshal(b, &m); err != nil || m.GoMod == "" {
			return "", fmt.Errorf("xray-core %s: no go.mod from go mod download: %v", version, err)
		}
		gomod, pkg = m.GoMod, "github.com/xtls/xray-core/main"
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
		gomod, pkg = filepath.Join(dir, "go.mod"), "./main"
	}
	// A release builds with the Go it was released for. GOTOOLCHAIN=auto only
	// moves up, to the newest Go on PATH, and a newer Go can break a
	// release's dependencies: v26.1.18's gvisor redeclares names on Go 1.26.
	b, err := os.ReadFile(gomod)
	if err != nil {
		return "", err
	}
	tc, err := xrayToolchain(b)
	if err != nil {
		return "", fmt.Errorf("xray-core %s: %v", version, err)
	}
	if gomod != filepath.Join(dir, "go.mod") {
		// go mod init wrote the go version on PATH, which tc may predate.
		if _, err := run(dir, env, "go", "mod", "edit", "-go="+strings.TrimPrefix(tc, "go"), "-toolchain=none"); err != nil {
			return "", err
		}
	}
	if _, err := run(dir, append(env, "GOTOOLCHAIN="+tc), "go", "build", "-trimpath", "-ldflags", "-s -w", "-o", out+".part", pkg); err != nil {
		return "", err
	}
	return out, os.Rename(out+".part", out)
}

// xrayToolchain names the Go toolchain an xray-core go.mod asks for: its
// toolchain line, or else its go line, where 1.22 means go1.22.0.
func xrayToolchain(gomod []byte) (string, error) {
	var goVersion, toolchain string
	for _, line := range strings.Split(string(gomod), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "go":
			goVersion = f[1]
		case "toolchain":
			if f[1] != "default" {
				toolchain = f[1]
			}
		}
	}
	switch {
	case toolchain != "":
		return toolchain, nil
	case goVersion == "":
		return "", fmt.Errorf("go.mod has no go line")
	case strings.Count(goVersion, ".") == 1:
		goVersion += ".0"
	}
	return "go" + goVersion, nil
}
