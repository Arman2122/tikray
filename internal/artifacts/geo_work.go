package artifacts

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Arman2122/tikray/internal/atomicfile"
	"golang.org/x/sys/unix"
)

const geoWorkFile = ".tikray-geo-work.json"

var errGeoWork = errors.New("artifacts: cannot verify geo working directory")

type geoWork struct {
	Name   string `json:"name"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func geoFDPath(fd int) string { return fmt.Sprintf("/proc/self/fd/%d", fd) }

// The artifacts lock serializes operations. Record the directory identity
// before writing a payload or renaming a retired slot. After a power failure
// an unrecorded lookalike directory can never authorize recursive deletion.
func recordGeoWork(parent, source int, name string) error {
	return recordSlotWork(parent, source, name, geoWorkFile)
}
func recordSlotWork(parent, source int, name, markerName string) error {
	var st unix.Stat_t
	if e := unix.Fstat(source, &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errGeoWork
	}
	work := geoWork{Name: name, Device: uint64(st.Dev), Inode: st.Ino}
	b, e := json.Marshal(work)
	if e != nil || atomicfile.WriteFile(filepath.Join(geoFDPath(parent), markerName), b, 0600) != nil {
		return errGeoWork
	}
	return nil
}

func cleanupGeoWork(parent int) error {
	return cleanupSlotWork(parent, geoWorkFile,
		func(s string) bool { return strings.HasPrefix(s, ".tmp-geo-") || strings.HasPrefix(s, ".old-geo-") },
		func(s string) bool {
			switch s {
			case "geoip.dat", "geosite.dat", "domestic-v4.txt", "meta.json", "geoip.dat.part", "geosite.dat.part", "domestic-v4.txt.part":
				return true
			}
			return false
		})
}
func cleanupSlotWork(parent int, markerName string, workingName, allowedFile func(string) bool) error {
	marker := filepath.Join(geoFDPath(parent), markerName)
	b, e := atomicfile.ReadRegular(marker, 2048, 0600)
	if errors.Is(e, fs.ErrNotExist) {
		return nil
	}
	var work geoWork
	if e != nil || json.Unmarshal(b, &work) != nil || work.Inode == 0 || len(work.Name) > 96 || work.Name != filepath.Base(work.Name) ||
		!workingName(work.Name) {
		return errGeoWork
	}
	fd, e := unix.Openat(parent, work.Name, unix.O_CLOEXEC|unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if e != nil && e != unix.ENOENT {
		return errGeoWork
	}
	if e == nil {
		f := os.NewFile(uintptr(fd), work.Name)
		defer f.Close()
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || uint64(st.Dev) != work.Device || st.Ino != work.Inode {
			return errGeoWork
		}
		entries, e := f.ReadDir(-1)
		if e != nil {
			return errGeoWork
		}
		for _, ent := range entries {
			if !allowedFile(ent.Name()) || !ent.Type().IsRegular() {
				return errGeoWork
			}
		}
		for _, ent := range entries {
			if unix.Unlinkat(fd, ent.Name(), 0) != nil {
				return errGeoWork
			}
		}
		if unix.Unlinkat(parent, work.Name, unix.AT_REMOVEDIR) != nil {
			return errGeoWork
		}
	}
	// Persist deletion/publication before retiring the marker. A replay
	// whose working name has disappeared just retires its marker.
	if unix.Fsync(parent) != nil || removeSynced(marker) != nil {
		return errGeoWork
	}
	return nil
}
