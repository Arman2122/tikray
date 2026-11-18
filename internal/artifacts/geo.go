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
	"path/filepath"
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

// ErrGeoSlot is the public renderer classification for an unreadable or
// unverified selected slot. It carries no path or publisher input.
var ErrGeoSlot = errors.New("artifacts: geo slot unavailable")

type geoMeta struct {
	Profile   string            `json:"profile,omitempty"`
	ReleaseID string            `json:"release_id,omitempty"`
	Version   string            `json:"version"`
	Site      []string          `json:"site"`
	IP        []string          `json:"ip"`
	SHA256    map[string]string `json:"sha256"`
}

// GeoSlotInfo summarizes one verified geo bundle slot under <data>/geo/.
type GeoSlotInfo struct {
	Slot        string   `json:"slot"`
	Profile     string   `json:"profile,omitempty"`
	ReleaseID   string   `json:"release_id,omitempty"`
	Site        []string `json:"site"`
	IP          []string `json:"ip"`
	PrefixCount int      `json:"prefix_count"`
}

// ListGeoSlots returns every verified geo slot under <data>/geo/, sorted by
// slot name descending. Missing geo directories return an empty slice;
// unverified, symlinked, or temporary directories are ignored.
func ListGeoSlots(data string) ([]GeoSlotInfo, error) {
	if _, err := os.Lstat(filepath.Join(data, "geo")); errors.Is(err, os.ErrNotExist) {
		return []GeoSlotInfo{}, nil
	}
	fd, err := openGeoDir(data, false, "geo")
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "geo")
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, errors.New("artifacts: geo directory unreadable")
	}
	out := make([]GeoSlotInfo, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !runnerapi.ValidGeoName(name) || !entry.IsDir() {
			continue
		}
		sub, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			continue
		}
		meta, ranges, verr := verifyGeoFD(sub, name)
		unix.Close(sub)
		if verr != nil {
			continue
		}
		out = append(out, GeoSlotInfo{
			Slot:        meta.Version,
			Profile:     meta.Profile,
			ReleaseID:   meta.ReleaseID,
			Site:        slices.Clone(meta.Site),
			IP:          slices.Clone(meta.IP),
			PrefixCount: len(ranges),
		})
	}
	slices.SortFunc(out, func(a, b GeoSlotInfo) int {
		return cmp.Compare(b.Slot, a.Slot)
	})
	return out, nil
}

// LoadGeo verifies the three installed payloads against the slot metadata.
// Publisher authentication takes place when installing the immutable slot.
// No matcher or range is returned until all three digests have been checked.
func LoadGeo(data, version string) (render.Geo, []netip.Prefix, error) {
	meta, ranges, err := verifiedGeo(data, version)
	if err != nil {
		return render.Geo{}, nil, err
	}
	return render.Geo{Version: meta.Version, Site: meta.Site, IP: meta.IP}, ranges, nil
}

func openGeoSlot(data, version string) (int, error) {
	if !runnerapi.ValidGeoName(version) {
		return -1, errors.New("artifacts: invalid geo slot name")
	}
	return openGeoDir(data, false, "geo", version)
}

// Hold each ancestor open while resolving its child. A renamed directory or
// a replaced symlink must never redirect a subsequent open to another volume.
func openGeoDir(data string, create bool, names ...string) (int, error) {
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	fd, err := unix.Open(data, flags, 0)
	if err != nil {
		return -1, errors.New("artifacts: geo data directory unavailable")
	}
	for _, name := range names {
		created := false
		if create {
			e := unix.Mkdirat(fd, name, 0755)
			if e != nil && e != unix.EEXIST {
				unix.Close(fd)
				return -1, errors.New("artifacts: cannot create geo directory")
			}
			created = e == nil
		}
		next, e := unix.Openat(fd, name, flags, 0)
		if e != nil {
			unix.Close(fd)
			return -1, errors.New("artifacts: geo slot unavailable")
		}
		if created && (unix.Fchmod(next, 0755) != nil || unix.Fsync(next) != nil || unix.Fsync(fd) != nil) {
			unix.Close(next)
			unix.Close(fd)
			return -1, errors.New("artifacts: cannot publish geo directory")
		}
		unix.Close(fd)
		fd = next
	}
	return fd, nil
}

func verifiedGeo(data, version string) (geoMeta, []netip.Prefix, error) {
	slot, err := openGeoSlot(data, version)
	if err != nil {
		return geoMeta{}, nil, err
	}
	defer unix.Close(slot)
	return verifyGeoFD(slot, version)
}

func readGeoMeta(slot int, version string) (geoMeta, error) {
	var metaBytes bytes.Buffer
	if err := readGeoFile(slot, metaFile, maxGeoMeta, &metaBytes); err != nil {
		return geoMeta{}, err
	}
	var meta geoMeta
	if json.Unmarshal(metaBytes.Bytes(), &meta) != nil || meta.Version != version || len(meta.SHA256) != 3 {
		return geoMeta{}, errors.New("artifacts: invalid geo metadata")
	}
	matchers := render.Geo{Version: version, Site: meta.Site, IP: meta.IP}
	if matchers.Validate() != nil {
		return geoMeta{}, errors.New("artifacts: invalid domestic geo matcher")
	}
	return meta, nil
}

func verifyGeoFD(slot int, version string) (geoMeta, []netip.Prefix, error) {
	meta, err := readGeoMeta(slot, version)
	if err != nil {
		return geoMeta{}, nil, err
	}
	var cidrs bytes.Buffer
	for _, name := range []string{"geoip.dat", "geosite.dat", "domestic-v4.txt"} {
		want := meta.SHA256[name]
		if !isSHA256Hex(want) {
			return geoMeta{}, nil, errors.New("artifacts: invalid geo checksum")
		}
		digest := sha256.New()
		var dst io.Writer = digest
		limit := int64(maxGeoAsset)
		if name == "domestic-v4.txt" {
			dst = io.MultiWriter(digest, &cidrs)
			limit = maxGeoRanges
		}
		if err := readGeoFile(slot, name, limit, dst); err != nil {
			return geoMeta{}, nil, err
		}
		if hex.EncodeToString(digest.Sum(nil)) != want {
			return geoMeta{}, nil, errors.New("artifacts: installed geo checksum mismatch")
		}
	}
	ranges, err := domesticIPv4(&cidrs)
	if err != nil {
		return geoMeta{}, nil, err
	}
	return meta, ranges, nil
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
