package artifacts

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/Arman2122/tikray/internal/render"
	"golang.org/x/sys/unix"
)

// GeoReader caches verified, immutable selections for ordinary service
// observations. An explicit transaction or attestation can call LoadGeo to
// hash the files unconditionally. The zero value is ready to use.
type GeoReader struct {
	mu      sync.Mutex
	entries [2]geoRead
}

type geoStamp struct {
	device, inode uint64
	mode          uint32
	size          int64
	ctime, mtime  unix.Timespec
}
type geoRead struct {
	geo    render.Geo
	ranges []netip.Prefix
	stamps [5]geoStamp // the pinned slot directory followed by its four files
}

func geoStamps(fd int) ([5]geoStamp, error) {
	var stamps [5]geoStamp
	for i, name := range [...]string{".", metaFile, "geoip.dat", "geosite.dat", "domestic-v4.txt"} {
		var st unix.Stat_t
		if unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || (i > 0 && st.Mode&unix.S_IFMT != unix.S_IFREG) {
			return stamps, errors.New("artifacts: invalid geo file identity")
		}
		stamps[i] = geoStamp{uint64(st.Dev), st.Ino, st.Mode, st.Size, st.Ctim, st.Mtim}
	}
	return stamps, nil
}

func (g *GeoReader) Load(data, version string) (render.Geo, []netip.Prefix, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	fd, e := openGeoSlot(data, version)
	if e != nil {
		return render.Geo{}, nil, e
	}
	defer unix.Close(fd)
	before, e := geoStamps(fd)
	if e != nil {
		return render.Geo{}, nil, e
	}
	// An in-place same-size rewrite must change ctime even if the owner
	// restores mtime. Files newly written in the same timestamp tick cannot
	// yet establish that; read those and unfamiliar filesystems in full.
	cutoff := time.Now().Add(-2 * time.Second).Unix()
	var fs unix.Statfs_t
	cacheable := unix.Fstatfs(fd, &fs) == nil && (fs.Type == unix.EXT4_SUPER_MAGIC || fs.Type == unix.BTRFS_SUPER_MAGIC || fs.Type == unix.XFS_SUPER_MAGIC || fs.Type == unix.TMPFS_MAGIC || fs.Type == unix.OVERLAYFS_SUPER_MAGIC)
	for _, stamp := range before {
		if stamp.ctime.Sec >= cutoff {
			cacheable = false
			break
		}
	}
	if cacheable {
		for i, c := range g.entries {
			if c.geo.Version == version && c.stamps == before {
				if i == 1 {
					g.entries[0], g.entries[1] = g.entries[1], g.entries[0]
				}
				return c.copy()
			}
		}
	}
	m, ps, e := verifyGeoFD(fd, version)
	if e != nil {
		return render.Geo{}, nil, e
	}
	after, e := geoStamps(fd)
	if e != nil || before != after {
		return render.Geo{}, nil, errors.New("artifacts: geo slot changed during verification")
	}
	fresh := geoRead{geo: render.Geo{Version: version, Site: m.Site, IP: m.IP}, ranges: ps, stamps: before}
	if cacheable {
		g.entries[1], g.entries[0] = g.entries[0], fresh
	}
	return fresh.copy()
}
func (c geoRead) copy() (render.Geo, []netip.Prefix, error) {
	c.geo.Site = slices.Clone(c.geo.Site)
	c.geo.IP = slices.Clone(c.geo.IP)
	return c.geo, slices.Clone(c.ranges), nil
}
