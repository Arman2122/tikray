package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Arman2122/tikray/internal/artifacts"
	"golang.org/x/sys/unix"
)

const (
	maxInboxAsset = 64 << 20
	maxInboxText  = 1 << 20
)

// UploadInbox writes a validated offline release artifact into <data>/inbox/
// atomically without following symlinks.
//
// Supported targets:
//   - kind="core": name in {"Xray-linux-arm64-v8a.zip", "Xray-linux-64.zip"}
//     stored at <data>/inbox/<name>.
//   - kind="geo": valid profile ("iran", "v2fly", "loyalsoldier", "custom"),
//     non-"latest" version tag, and profile-appropriate filename
//     ("geoip.dat", "geosite.dat", "dlc.dat" for v2fly, "domestic-v4.txt" for
//     custom) stored at <data>/inbox/geo/<profile>/<version>/<name>.
func (s *Service) UploadInbox(ctx context.Context, kind, profile, version, name string, r io.Reader) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if r == nil {
		return 0, &Refused{Reason: "empty upload body"}
	}
	var dirs []string
	var limit int64 = maxInboxAsset
	var allowEmpty bool
	var eventKind, eventMsg string

	switch kind {
	case "core":
		if profile != "" || version != "" {
			return 0, &Refused{Reason: "core inbox upload does not take profile or version"}
		}
		switch name {
		case "Xray-linux-arm64-v8a.zip", "Xray-linux-64.zip":
		default:
			return 0, &Refused{Reason: "unsupported xray-core release asset filename"}
		}
		dirs = []string{"inbox"}
		eventKind = KindCore
		eventMsg = "uploaded core archive to inbox: " + name
	case "geo":
		if !artifacts.ValidGeoProfile(profile) {
			return 0, &Refused{Reason: "invalid geo profile"}
		}
		if version == "" || version == "latest" || !artifacts.ValidGeoTarget(profile, version) ||
			strings.ContainsAny(version, `/\`) || strings.Contains(version, "..") || strings.HasPrefix(version, ".") {
			return 0, &Refused{Reason: "invalid geo release version"}
		}
		switch {
		case name == "geoip.dat":
		case name == "geosite.dat" && profile != "v2fly":
		case name == "dlc.dat" && profile == "v2fly":
		case name == "domestic-v4.txt" && profile == "custom":
			limit = maxInboxText
			allowEmpty = true
		default:
			return 0, &Refused{Reason: "unsupported geo asset filename for profile"}
		}
		dirs = []string{"inbox", "geo", profile, version}
		eventKind = KindGeo
		eventMsg = fmt.Sprintf("uploaded geo file to inbox (%s/%s)", profile, name)
	default:
		return 0, &Refused{Reason: "unsupported inbox kind"}
	}

	dirFD, err := openInboxDir(s.data, dirs...)
	if err != nil {
		return 0, err
	}
	defer unix.Close(dirFD)

	n, err := writeInboxFile(ctx, dirFD, name, r, limit, allowEmpty)
	if err != nil {
		return 0, err
	}
	s.record(eventKind, eventMsg)
	return n, nil
}

func openInboxDir(data string, parts ...string) (int, error) {
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	fd, err := unix.Open(data, flags, 0)
	if err != nil {
		return -1, errors.New("service: inbox data directory unavailable")
	}
	for _, p := range parts {
		created := false
		if err := unix.Mkdirat(fd, p, 0o755); err == nil {
			created = true
		} else if err != unix.EEXIST {
			unix.Close(fd)
			return -1, errors.New("service: cannot create inbox directory")
		}
		next, err := unix.Openat(fd, p, flags, 0)
		if err != nil {
			unix.Close(fd)
			return -1, errors.New("service: inbox directory unavailable")
		}
		if created {
			_ = unix.Fchmod(next, 0o755)
			_ = unix.Fsync(next)
			_ = unix.Fsync(fd)
		}
		unix.Close(fd)
		fd = next
	}
	return fd, nil
}

func writeInboxFile(ctx context.Context, dirFD int, name string, r io.Reader, limit int64, allowEmpty bool) (int64, error) {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return 0, errors.New("service: cannot allocate inbox temp file")
	}
	tmp := ".tmp-" + hex.EncodeToString(rnd[:])
	fd, err := unix.Openat(dirFD, tmp, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return 0, errors.New("service: cannot create inbox temp file")
	}
	f := os.NewFile(uintptr(fd), tmp)
	cleanup := func() {
		_ = f.Close()
		_ = unix.Unlinkat(dirFD, tmp, 0)
	}

	var total int64
	buf := make([]byte, 32<<10)
	lr := io.LimitReader(r, limit+1)
	for {
		if err := ctx.Err(); err != nil {
			cleanup()
			return 0, err
		}
		nr, rerr := lr.Read(buf)
		if nr > 0 {
			total += int64(nr)
			if total > limit {
				cleanup()
				return 0, &Refused{Reason: "uploaded file exceeds size limit"}
			}
			if _, werr := f.Write(buf[:nr]); werr != nil {
				cleanup()
				return 0, errors.New("service: cannot write inbox file")
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			cleanup()
			return 0, errors.New("service: failed reading upload stream")
		}
	}
	if total == 0 && !allowEmpty {
		cleanup()
		return 0, &Refused{Reason: "uploaded file must not be empty"}
	}
	if err := f.Chmod(0o644); err != nil {
		cleanup()
		return 0, errors.New("service: cannot set inbox file permissions")
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return 0, errors.New("service: cannot sync inbox file")
	}
	if err := f.Close(); err != nil {
		_ = unix.Unlinkat(dirFD, tmp, 0)
		return 0, errors.New("service: cannot close inbox file")
	}
	if err := unix.Renameat(dirFD, tmp, dirFD, name); err != nil {
		_ = unix.Unlinkat(dirFD, tmp, 0)
		return 0, errors.New("service: cannot publish inbox file")
	}
	_ = unix.Fsync(dirFD)
	return total, nil
}
