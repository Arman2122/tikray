package artifacts

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/Arman2122/tikray/internal/atomicfile"
	"github.com/Arman2122/tikray/internal/imagearchive"
	"golang.org/x/sys/unix"
)

type ImageRef = imagearchive.Ref

type ImageBootstrap struct {
	Version   int      `json:"version"`
	Arch      string   `json:"arch"`
	Publisher string   `json:"publisher"` // DER SPKI, base64, pinned by the owner installer
	Tikray    ImageRef `json:"tikray"`
	Runner    ImageRef `json:"runner"`
}

type ImageSourceConfig struct {
	Upstream      string
	Mirrors       []string
	Direct, Proxy *http.Client
	ProxyHealthy  func(context.Context) bool
}

type VerifiedImage struct{ ref ImageRef }

func (i VerifiedImage) Ref() ImageRef   { return i.ref }
func ValidImageVersion(s string) bool   { return imagearchive.Version(s) }
func ValidImageComponent(s string) bool { return imagearchive.Component(s) }

var (
	errImageTrust = errors.New("artifacts: image publisher trust unavailable")
	errImageRef   = errors.New("artifacts: invalid image identity")
	errImageStage = errors.New("artifacts: cannot stage verified image")
	errImageFetch = errors.New("artifacts: verified release image unavailable")
)

func imageKey(derBase64 string) (*ecdsa.PublicKey, error) {
	der, e := base64.StdEncoding.Strict().DecodeString(derBase64)
	if e != nil || len(der) > 512 {
		return nil, errImageTrust
	}
	k, e := x509.ParsePKIXPublicKey(der)
	p, ok := k.(*ecdsa.PublicKey)
	if e != nil || !ok || p.Curve != elliptic.P256() {
		return nil, errImageTrust
	}
	return p, nil
}

func ReadImageBootstrap(data string) (ImageBootstrap, error) {
	var b ImageBootstrap
	fd, e := openGeoDir(data, false, "state")
	if e != nil {
		return b, errImageTrust
	}
	defer unix.Close(fd)
	var raw bytes.Buffer
	if e := readGeoFile(fd, "image-bootstrap.json", 4096, &raw); e != nil {
		return b, errImageTrust
	}
	dec := json.NewDecoder(&raw)
	dec.DisallowUnknownFields()
	if dec.Decode(&b) != nil || dec.Decode(new(any)) != io.EOF || b.Version != 1 || (b.Arch != "amd64" && b.Arch != "arm64") ||
		!b.Tikray.Valid() || b.Tikray.Component != "tikray" || !b.Runner.Valid() || b.Runner.Component != "runner" {
		return ImageBootstrap{}, errImageTrust
	}
	if _, e = imageKey(b.Publisher); e != nil {
		return ImageBootstrap{}, e
	}
	return b, nil
}

func imageFileAt(dir int, name string) (*os.File, error) {
	fd, e := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, errImageStage
	}
	f := os.NewFile(uintptr(fd), name)
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > imagearchive.MaxSize {
		f.Close()
		return nil, errImageStage
	}
	return f, nil
}

func sigBytes(b []byte) ([]byte, error) {
	text := bytes.TrimSpace(b)
	if len(text) > 256 {
		return nil, errImageTrust
	}
	v, e := base64.StdEncoding.Strict().DecodeString(string(text))
	if e != nil || len(v) < 8 || len(v) > 80 {
		return nil, errImageTrust
	}
	return v, nil
}

func checkImageFile(ctx context.Context, f *os.File, component, arch, version string, key *ecdsa.PublicKey, sig []byte) (ImageRef, string, error) {
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		return ImageRef{}, "", errImageStage
	}
	ref, label, e := imagearchive.Inspect(ctx, f, st.Size(), component, arch, version)
	if e != nil {
		return ImageRef{}, "", e
	}
	digest, _ := hex.DecodeString(ref.Digest)
	if !ecdsa.VerifyASN1(key, digest, sig) {
		return ImageRef{}, "", errImageTrust
	}
	return ref, label, nil
}

func imageFilename(r ImageRef) string { return r.Component + "-" + r.Digest + ".tar" }

func verifySlot(ctx context.Context, dir int, key *ecdsa.PublicKey, arch string, ref ImageRef) (string, error) {
	if !ref.Valid() {
		return "", errImageRef
	}
	name := imageFilename(ref)
	var raw bytes.Buffer
	if readGeoFile(dir, name+".sig", 256, &raw) != nil {
		return "", errImageTrust
	}
	sig, e := sigBytes(raw.Bytes())
	if e != nil {
		return "", e
	}
	f, e := imageFileAt(dir, name)
	if e != nil {
		return "", e
	}
	defer f.Close()
	got, label, e := checkImageFile(ctx, f, ref.Component, arch, "", key, sig)
	if e != nil || got != ref {
		return "", errImageRef
	}
	return label, nil
}

// VerifyImageRef authenticates the retained tar and its detached cosign blob
// signature, including on re-use of a slot installed by an older process.
func VerifyImageRef(ctx context.Context, data string, ref ImageRef, arch string) error {
	boot, e := ReadImageBootstrap(data)
	if e != nil || boot.Arch != arch {
		return errImageTrust
	}
	key, e := imageKey(boot.Publisher)
	if e != nil {
		return e
	}
	dir, e := openGeoDir(data, false, "images")
	if e != nil {
		return errImageStage
	}
	defer unix.Close(dir)
	_, e = verifySlot(ctx, dir, key, arch, ref)
	return e
}

type imageSource struct {
	name string
	get  func(context.Context, string, io.Writer) error
}

func (s imageSource) Name() string { return s.name }
func (s imageSource) Fetch(ctx context.Context, r Request, d io.Writer) error {
	return s.get(ctx, r.File, d)
}

func (u *CoreUpdater) imageSources(version string) []Source {
	c := u.ImageSource
	direct := c.Direct
	if direct == nil {
		direct = HTTPClient("", defaultTimeout)
	}
	var sources []Source
	if c.Upstream != "" {
		sources = append(sources, imageSource{"direct", func(ctx context.Context, file string, w io.Writer) error {
			return get(ctx, geoClient(direct), geoURL(c.Upstream, version, file), w)
		}})
		if c.Proxy != nil && c.ProxyHealthy != nil {
			sources = append(sources, imageSource{"proxy", func(ctx context.Context, file string, w io.Writer) error {
				if !c.ProxyHealthy(ctx) {
					return errProxyUnavailable
				}
				return get(ctx, geoClient(c.Proxy), geoURL(c.Upstream, version, file), w)
			}})
		}
	}
	for _, t := range c.Mirrors {
		if !strings.Contains(t, "{file}") {
			continue
		}
		sources = append(sources, imageSource{"mirror", func(ctx context.Context, file string, w io.Writer) error {
			raw := strings.NewReplacer("{version}", version, "{arch}", u.Arch, "{file}", file).Replace(t)
			if geoURL(raw) == "" {
				return errImageFetch
			}
			return get(ctx, geoClient(direct), raw, w)
		}})
	}
	sources = append(sources, imageSource{"inbox", func(ctx context.Context, file string, w io.Writer) error {
		dir, e := openGeoDir(u.Data, false, "inbox", "images", version)
		if e != nil {
			return errImageFetch
		}
		defer unix.Close(dir)
		return readGeoFile(dir, file, imagearchive.MaxSize, w)
	}})
	return sources
}

// StageImage checks the publisher signature on exact archive bytes, then
// publishes a content-addressed tar while the shared artifacts lock is held.
func (u *CoreUpdater) StageImage(ctx context.Context, component, version string) (VerifiedImage, error) {
	if !ValidImageComponent(component) || !ValidImageVersion(version) {
		return VerifiedImage{}, errImageRef
	}
	if err := ctx.Err(); err != nil {
		return VerifiedImage{}, err
	}
	boot, e := ReadImageBootstrap(u.Data)
	if e != nil {
		return VerifiedImage{}, e
	}
	arch := u.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}
	if arch != boot.Arch {
		return VerifiedImage{}, errImageRef
	}
	if u.ImageSource.Upstream != "" && geoURL(u.ImageSource.Upstream) == "" {
		return VerifiedImage{}, errImageTrust
	}
	key, e := imageKey(boot.Publisher)
	if e != nil {
		return VerifiedImage{}, e
	}
	unlock, e := lockState(u.stateDir())
	if e != nil {
		return VerifiedImage{}, e
	}
	defer unlock()
	dir, e := openGeoDir(u.Data, true, "images")
	if e != nil {
		return VerifiedImage{}, errImageStage
	}
	defer unix.Close(dir)
	tmp, e := os.MkdirTemp(geoFDPath(dir), ".image-stage-")
	if e != nil {
		return VerifiedImage{}, errImageStage
	}
	defer os.RemoveAll(tmp)
	dst := filepath.Join(tmp, "archive")
	release := imagearchive.ReleaseName(component) + "-" + arch + ".tar"
	sources := u.imageSources(version)
	ch := Chain{Sources: sources, MaxBytes: imagearchive.MaxSize, Timeout: u.Fetch.Timeout, Stall: u.Fetch.Stall}
	seen := map[string]bool{}
	for _, s := range sources {
		if e := ctx.Err(); e != nil {
			return VerifiedImage{}, e
		}
		sigctx, stop := context.WithTimeout(ctx, latestTimeout)
		var text bytes.Buffer
		err := s.Fetch(sigctx, Request{File: release + ".sig"}, &capWriter{w: &text, left: 256})
		stop()
		sig, e := sigBytes(text.Bytes())
		if err != nil || e != nil || seen[string(sig)] {
			continue
		}
		seen[string(sig)] = true
		var ref ImageRef
		_, e = ch.Fetch(ctx, Request{File: release}, dst, func(path string) error {
			f, e := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
			if e != nil {
				return errImageStage
			}
			defer f.Close()
			ref, _, e = checkImageFile(ctx, f, component, arch, version, key, sig)
			return e
		})
		if e != nil {
			continue
		}
		if e = installImage(ctx, dir, dst, ref, key, arch, sig); e != nil {
			return VerifiedImage{}, e
		}
		return VerifiedImage{ref}, nil
	}
	if err := ctx.Err(); err != nil {
		return VerifiedImage{}, err
	}
	return VerifiedImage{}, errImageFetch
}

type imageOwner struct {
	Ref    ImageRef `json:"ref"`
	Device uint64   `json:"device"`
	Inode  uint64   `json:"inode"`
}

func installImage(ctx context.Context, dir int, src string, ref ImageRef, key *ecdsa.PublicKey, arch string, sig []byte) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	path := imageFilename(ref)
	var st unix.Stat_t
	e := unix.Fstatat(dir, path, &st, unix.AT_SYMLINK_NOFOLLOW)
	if e == nil {
		_, e = verifySlot(ctx, dir, key, arch, ref)
		return e
	}
	if e != unix.ENOENT {
		return errImageStage
	}
	sigPath := path + ".sig"
	publicSig := base64.StdEncoding.EncodeToString(sig)
	if e = writeSynced(src+".sig", 0644, func(w io.Writer) error { _, e := io.WriteString(w, publicSig); return e }); e != nil {
		return errImageStage
	}
	e = unix.Renameat2(unix.AT_FDCWD, src+".sig", dir, sigPath, unix.RENAME_NOREPLACE)
	if e == unix.EEXIST {
		var raw bytes.Buffer
		if readGeoFile(dir, sigPath, 256, &raw) != nil {
			return errImageStage
		}
		other, err := sigBytes(raw.Bytes())
		digest, _ := hex.DecodeString(ref.Digest)
		if err != nil || !ecdsa.VerifyASN1(key, digest, other) {
			return errImageTrust
		}
	} else if e != nil {
		return errImageStage
	}
	if e = unix.Renameat2(unix.AT_FDCWD, src, dir, path, unix.RENAME_NOREPLACE); e != nil {
		return errImageStage
	}
	if unix.Fsync(dir) != nil || unix.Fstatat(dir, path, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return errImageStage
	}
	if _, e = verifySlot(ctx, dir, key, arch, ref); e != nil {
		return e
	}
	owner := imageOwner{ref, uint64(st.Dev), st.Ino}
	b, _ := json.Marshal(owner)
	return writeImageOwner(dir, path+".owned", b)
}

func writeImageOwner(dir int, name string, data []byte) error {
	tmp, e := os.CreateTemp(geoFDPath(dir), ".image-owner-")
	if e != nil {
		return errImageStage
	}
	path := tmp.Name()
	defer os.Remove(path)
	_, e = tmp.Write(data)
	if e == nil {
		e = tmp.Sync()
	}
	if closeErr := tmp.Close(); e != nil || closeErr != nil {
		return errImageStage
	}
	if unix.Renameat2(unix.AT_FDCWD, path, dir, name, unix.RENAME_NOREPLACE) != nil || unix.Fsync(dir) != nil {
		return errImageStage
	}
	return nil
}

// PruneImages removes orphaned slots created by this installer/runtime only
// after the caller has verified the current/previous slots for both components.
// Keep the bootstrap originals for exact package reimport and reinstall.
func PruneImages(ctx context.Context, data, arch string, keep []ImageRef) error {
	boot, e := ReadImageBootstrap(data)
	if e != nil || boot.Arch != arch {
		return errImageTrust
	}
	for _, ref := range keep {
		if !ref.Valid() {
			return errImageRef
		}
	}
	keep = slices.Concat(keep, []ImageRef{boot.Tikray, boot.Runner})
	key, e := imageKey(boot.Publisher)
	if e != nil {
		return e
	}
	unlock, e := lockState(filepath.Join(data, "state"))
	if e != nil {
		return e
	}
	defer unlock()
	dir, e := openGeoDir(data, false, "images")
	if e != nil {
		return errImageStage
	}
	f := os.NewFile(uintptr(dir), "images")
	defer f.Close()
	for {
		names, err := f.Readdirnames(64)
		if err != nil && err != io.EOF {
			return errImageStage
		}
		for _, n := range names {
			if e := ctx.Err(); e != nil {
				return e
			}
			if !strings.HasSuffix(n, ".tar.owned") || len(n) > 96 {
				continue
			}
			ownerPath := filepath.Join(geoFDPath(dir), n)
			b, e := atomicfile.ReadRegular(ownerPath, 2048, 0600)
			if e != nil {
				continue
			}
			var own imageOwner
			if json.Unmarshal(b, &own) != nil || !own.Ref.Valid() || n != imageFilename(own.Ref)+".owned" || slices.Contains(keep, own.Ref) {
				continue
			}
			var st unix.Stat_t
			tar := imageFilename(own.Ref)
			if unix.Fstatat(dir, tar, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || uint64(st.Dev) != own.Device || st.Ino != own.Inode {
				continue
			}
			if _, e = verifySlot(ctx, dir, key, arch, own.Ref); e != nil {
				continue
			}
			if unix.Unlinkat(dir, tar, 0) != nil || unix.Unlinkat(dir, tar+".sig", 0) != nil || unix.Unlinkat(dir, n, 0) != nil || unix.Fsync(dir) != nil {
				return errImageStage
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

// ImageReleaseAvailable only compares a trusted public release tag; it never
// stages an image or writes the update marker.
func (u *CoreUpdater) ImageReleaseAvailable(ctx context.Context, component string, current ImageRef) (bool, error) {
	if component != current.Component || !current.Valid() {
		return false, errImageRef
	}
	c := u.ImageSource
	if c.Upstream == "" {
		return false, nil
	}
	raw := geoURL(c.Upstream, "latest")
	if raw == "" {
		return false, errImageTrust
	}
	src := GeoSourceConfig{Direct: c.Direct, Proxy: c.Proxy, ProxyHealthy: c.ProxyHealthy}
	b, e := src.small(ctx, raw)
	if e != nil {
		return false, errImageFetch
	}
	latest := strings.TrimSpace(string(b))
	if !ValidImageVersion(latest) {
		return false, errImageRef
	}
	boot, e := ReadImageBootstrap(u.Data)
	if e != nil {
		return false, e
	}
	key, e := imageKey(boot.Publisher)
	if e != nil {
		return false, e
	}
	dir, e := openGeoDir(u.Data, false, "images")
	if e != nil {
		return false, errImageStage
	}
	defer unix.Close(dir)
	version, e := verifySlot(ctx, dir, key, boot.Arch, current)
	if e != nil {
		return false, e
	}
	return latest != version && latest != "sha256-"+current.Digest, nil
}
