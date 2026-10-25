// Package xrayver parses xray-core release versions and names XTLS release assets.
package xrayver

import (
	"fmt"
	"regexp"
	"strconv"
)

var versionRE = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// Version is an xray-core release number such as 26.10.21.
type Version struct{ Major, Minor, Patch int }

// MinTUN is the first xray-core release with the TUN inbound.
var MinTUN = Version{26, 1, 18}

// Parse accepts 26.10.21 and v26.10.21. It refuses anything else, including
// "latest", which callers resolve first.
func Parse(s string) (Version, error) {
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return Version{}, fmt.Errorf("xrayver: invalid version %q", s)
	}
	var n [3]int
	for i := range n {
		x, err := strconv.Atoi(m[i+1])
		if err != nil {
			return Version{}, fmt.Errorf("xrayver: invalid version %q: %w", s, err)
		}
		n[i] = x
	}
	return Version{n[0], n[1], n[2]}, nil
}

// String returns the release number, which is also the core slot directory name.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Tag returns the upstream git tag for the release, such as v26.10.21.
func (v Version) Tag() string {
	return "v" + v.String()
}

// Less reports whether v is an earlier release than o, comparing each field numerically.
func (v Version) Less(o Version) bool {
	if v.Major != o.Major {
		return v.Major < o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor < o.Minor
	}
	return v.Patch < o.Patch
}

// AssetName returns the XTLS release zip for a Go GOARCH value.
func AssetName(goarch string) (string, error) {
	switch goarch {
	case "arm64":
		return "Xray-linux-arm64-v8a.zip", nil
	case "amd64":
		return "Xray-linux-64.zip", nil
	}
	return "", fmt.Errorf("xrayver: no xray release asset for GOARCH %q", goarch)
}
