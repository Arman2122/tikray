package artifacts

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"golang.org/x/sys/unix"
)

const (
	maxGeoAsset  = 64 << 20
	maxGeoMeta   = 64 << 10
	maxGeoRanges = 1 << 20
	// Address-list rows share the native reply budget with non-geo policy.
	maxGeoPrefixes = 16384
)

type geoMeta struct {
	Version string            `json:"version"`
	Site    []string          `json:"site"`
	IP      []string          `json:"ip"`
	SHA256  map[string]string `json:"sha256"`
}

// LoadGeo verifies the three installed payloads against the slot metadata.
// Publisher authentication takes place when installing the immutable slot.
// No matcher or range is returned until all three digests have been checked.
func LoadGeo(data, version string) (render.Geo, []netip.Prefix, error) {
	if !runnerapi.ValidGeoName(version) {
		return render.Geo{}, nil, errors.New("artifacts: invalid geo slot name")
	}
	// Hold each directory open while resolving its child. Checking a path
	// and then reopening it would allow a replaced directory to redirect us.
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_DIRECTORY
	root, err := unix.Open(data, flags, 0)
	if err != nil {
		return render.Geo{}, nil, errors.New("artifacts: geo data directory unavailable")
	}
	defer unix.Close(root)
	geo, err := unix.Openat(root, "geo", flags, 0)
	if err != nil {
		return render.Geo{}, nil, errors.New("artifacts: geo directory unavailable")
	}
	defer unix.Close(geo)
	slot, err := unix.Openat(geo, version, flags, 0)
	if err != nil {
		return render.Geo{}, nil, errors.New("artifacts: geo slot unavailable")
	}
	defer unix.Close(slot)

	var metaBytes bytes.Buffer
	if err := readGeoFile(slot, metaFile, maxGeoMeta, &metaBytes); err != nil {
		return render.Geo{}, nil, err
	}
	var meta geoMeta
	if json.Unmarshal(metaBytes.Bytes(), &meta) != nil || meta.Version != version || len(meta.SHA256) != 3 {
		return render.Geo{}, nil, errors.New("artifacts: invalid geo metadata")
	}
	matchers := render.Geo{Version: version, Site: meta.Site, IP: meta.IP}
	if matchers.Validate() != nil {
		return render.Geo{}, nil, errors.New("artifacts: invalid domestic geo matcher")
	}
	var cidrs bytes.Buffer
	for _, name := range []string{"geoip.dat", "geosite.dat", "domestic-v4.txt"} {
		want := meta.SHA256[name]
		if !isSHA256Hex(want) {
			return render.Geo{}, nil, errors.New("artifacts: invalid geo checksum")
		}
		digest := sha256.New()
		var dst io.Writer = digest
		limit := int64(maxGeoAsset)
		if name == "domestic-v4.txt" {
			dst = io.MultiWriter(digest, &cidrs)
			limit = maxGeoRanges
		}
		if err := readGeoFile(slot, name, limit, dst); err != nil {
			return render.Geo{}, nil, err
		}
		if hex.EncodeToString(digest.Sum(nil)) != want {
			return render.Geo{}, nil, errors.New("artifacts: installed geo checksum mismatch")
		}
	}
	ranges, err := domesticIPv4(&cidrs)
	if err != nil {
		return render.Geo{}, nil, err
	}
	return matchers, ranges, nil
}

func readGeoFile(slot int, name string, limit int64, dst io.Writer) error {
	fd, err := unix.Openat(slot, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return errors.New("artifacts: geo file unavailable")
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit || st.Size() == 0 && name != "domestic-v4.txt" {
		return errors.New("artifacts: invalid geo file")
	}
	n, err := io.Copy(dst, io.LimitReader(f, limit+1))
	if err != nil || n != st.Size() {
		return errors.New("artifacts: could not verify entire geo file")
	}
	return nil
}

func domesticIPv4(r io.Reader) ([]netip.Prefix, error) {
	var ps []netip.Prefix
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil || !p.Addr().Is4() || p != p.Masked() {
			return nil, errors.New("artifacts: invalid domestic IPv4 range")
		}
		if len(ps) >= maxGeoPrefixes {
			return nil, errors.New("artifacts: too many domestic IPv4 ranges")
		}
		ps = append(ps, p)
	}
	if sc.Err() != nil {
		return nil, errors.New("artifacts: unreadable domestic IPv4 ranges")
	}
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if n := a.Addr().Compare(b.Addr()); n != 0 {
			return n
		}
		return cmp.Compare(a.Bits(), b.Bits())
	})
	return slices.Compact(ps), nil
}
