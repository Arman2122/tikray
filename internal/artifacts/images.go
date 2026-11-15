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
	var state unix.Stat_t
	if unix.Fstat(fd, &state) != nil || state.Mode&0077 != 0 {
		return b, errImageTrust
	}
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

func checkImageFile(ctx context.Context, f *os.File, component, arch, version string, key *ecdsa.PublicKey, sig []byte) (ImageRef, imagearchive.Metadata, error) {
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		return ImageRef{}, imagearchive.Metadata{}, errImageStage
	}
	ref, label, e := imagearchive.Inspect(ctx, f, st.Size(), component, arch, version)
	if e != nil {
		return ImageRef{}, imagearchive.Metadata{}, e
	}
	digest, _ := hex.DecodeString(ref.Digest)
	if !ecdsa.VerifyASN1(key, digest, sig) {
		return ImageRef{}, imagearchive.Metadata{}, errImageTrust
	}
	return ref, label, nil
}

func imageFilename(r ImageRef) string { return r.Component + "-" + r.Digest + ".tar" }

func verifySlot(ctx context.Context, dir int, key *ecdsa.PublicKey, arch string, ref ImageRef) (imagearchive.Metadata, error) {
	if !ref.Valid() {
		return imagearchive.Metadata{}, errImageRef
	}
	name := imageFilename(ref)
	var raw bytes.Buffer
	if readGeoFile(dir, name+".sig", 256, &raw) != nil {
		return imagearchive.Metadata{}, errImageTrust
	}
	sig, e := sigBytes(raw.Bytes())
	if e != nil {
		return imagearchive.Metadata{}, e
	}
	f, e := imageFileAt(dir, name)
	if e != nil {
		return imagearchive.Metadata{}, e
	}
	defer f.Close()
	got, label, e := checkImageFile(ctx, f, ref.Component, arch, "", key, sig)
	if e != nil || got != ref {
		return imagearchive.Metadata{}, errImageRef
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
func (u *CoreUpdater) StageImage(ctx context.Context, component, version string) (result VerifiedImage, err error) {
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
	if err := cleanupImageWork(dir, key); err != nil {
		return VerifiedImage{}, errImageStage
	}
	tmp, e := os.MkdirTemp(geoFDPath(dir), ".image-stage-")
	if e != nil {
		return VerifiedImage{}, errImageStage
	}
	working, e := unix.Openat(dir, filepath.Base(tmp), unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY, 0)
	if e != nil {
		return VerifiedImage{}, errImageStage
	}
	e = recordSlotWork(dir, working, filepath.Base(tmp), imageWorkFile)
	unix.Close(working)
	if e != nil {
		return VerifiedImage{}, errImageStage
	}
	defer func() {
		if cleanupImageWork(dir, key) != nil && err == nil {
			result = VerifiedImage{}
			err = errImageStage
		}
	}()
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

const imageWorkFile = ".tikray-image-work.json"

func cleanupImageWork(dir int, key *ecdsa.PublicKey) error {
	return cleanupSlotWork(dir, imageWorkFile,
		func(s string) bool { return strings.HasPrefix(s, ".image-stage-") },
		func(s string) bool {
			return s == "archive" || s == "archive.part" || s == "archive.sig" || s == "publication.json"
		},
		func(work int) error { return recoverImagePublication(dir, work, key) })
}

type imageOwner struct {
	Ref       ImageRef `json:"ref"`
	Device    uint64   `json:"device"`
	Inode     uint64   `json:"inode"`
	SigDevice uint64   `json:"sig_device,omitempty"`
	SigInode  uint64   `json:"sig_inode,omitempty"`
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
	owner := imageOwner{Ref: ref}
	var image, signature unix.Stat_t
	if unix.Lstat(src, &image) != nil || unix.Lstat(src+".sig", &signature) != nil {
		return errImageStage
	}
	owner.Device, owner.Inode = uint64(image.Dev), image.Ino
	switch e = unix.Fstatat(dir, sigPath, &st, unix.AT_SYMLINK_NOFOLLOW); e {
	case unix.ENOENT:
		owner.SigDevice, owner.SigInode = uint64(signature.Dev), signature.Ino
	case nil:
		var raw bytes.Buffer
		if readGeoFile(dir, sigPath, 256, &raw) != nil {
			return errImageStage
		}
		other, err := sigBytes(raw.Bytes())
		digest, _ := hex.DecodeString(ref.Digest)
		if err != nil || !ecdsa.VerifyASN1(key, digest, other) {
			return errImageTrust
		}
	default:
		return errImageStage
	}

	// Keep both staged inodes linked until the namespace is durable.
	// Linking the private receipt first makes ownership unambiguous at
	// every later power cut, even if a previous owner supplied the signature.
	work := filepath.Dir(src)
	publication := filepath.Join(work, "publication.json")
	b, _ := json.Marshal(owner)
	if writeSynced(publication, 0600, func(w io.Writer) error { _, e := w.Write(b); return e }) != nil || syncDir(work) != nil {
		return errImageStage
	}
	link := func(from, to string) error {
		if unix.Linkat(unix.AT_FDCWD, from, dir, to, 0) != nil || unix.Fsync(dir) != nil {
			return errImageStage
		}
		return nil
	}
	if err := link(publication, path+".owned"); err != nil {
		return err
	}
	if owner.SigInode != 0 {
		if err := link(src+".sig", sigPath); err != nil {
			return err
		}
	}
	if err := link(src, path); err != nil {
		return err
	}
	_, err := verifySlot(ctx, dir, key, arch, ref)
	return err
}

// A completed tar keeps its receipt. A cut before tar publication retires
// only links proved by the still-recorded staging directory and receipt.
func recoverImagePublication(dir, work int, key *ecdsa.PublicKey) error {
	tmp := filepath.Join(geoFDPath(work), "publication.json")
	b, err := atomicfile.ReadRegular(tmp, 2048, 0600)
	var own imageOwner
	if errors.Is(err, os.ErrNotExist) || (err == nil && (json.Unmarshal(b, &own) != nil || !own.Ref.Valid())) {
		// The working receipt may be incomplete before the first link.
		return nil
	}
	if err != nil {
		return errImageStage
	}
	tar := imageFilename(own.Ref)
	receipt := tar + ".owned"
	var staged, final unix.Stat_t
	if unix.Fstatat(work, "publication.json", &staged, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return errImageStage
	}
	err = unix.Fstatat(dir, receipt, &final, unix.AT_SYMLINK_NOFOLLOW)
	if err == unix.ENOENT || (err == nil && (final.Dev != staged.Dev || final.Ino != staged.Ino)) {
		return nil
	}
	if err != nil {
		return errImageStage
	}
	err = unix.Fstatat(dir, tar, &final, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil && uint64(final.Dev) == own.Device && final.Ino == own.Inode {
		return nil
	}
	if err != unix.ENOENT {
		return errImageStage
	}
	if err := removeImageSignature(dir, key, own); err != nil {
		return err
	}
	if unix.Unlinkat(dir, receipt, 0) != nil || unix.Fsync(dir) != nil {
		return errImageStage
	}
	return nil
}

// PruneImages removes orphaned slots created by this installer/runtime only
// after the caller has verified the current/previous slots for both components.
// Keep the bootstrap originals for exact package reimport and reinstall.
func PruneImages(ctx context.Context, data, arch string, keep []ImageRef) error {
	unlock, e := lockState(filepath.Join(data, "state"))
	if e != nil {
		return e
	}
	defer unlock()
	if ImagePending(data) {
		return ErrImageBusy
	}
	return pruneImagesLocked(ctx, data, arch, keep)
}

func pruneImagesLocked(ctx context.Context, data, arch string, keep []ImageRef) error {
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
	protected := make(map[string]bool, len(keep))
	for _, ref := range keep {
		protected[imageFilename(ref)+".owned"] = true
	}
	key, e := imageKey(boot.Publisher)
	if e != nil {
		return e
	}
	dir, e := openGeoDir(data, false, "images")
	if e != nil {
		return errImageStage
	}
	f := os.NewFile(uintptr(dir), "images")
	defer f.Close()
	if err := cleanupImageWork(dir, key); err != nil {
		return err
	}
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
			if !protected[n] {
				if err := retireImage(ctx, dir, key, arch, n, ImageRef{}); err != nil {
					return err
				}
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

// Retire only the signature and tar inodes named by the private receipt.
func retireImage(ctx context.Context, dir int, key *ecdsa.PublicKey, arch, n string, only ImageRef) error {
	ownerPath := filepath.Join(geoFDPath(dir), n)
	b, e := atomicfile.ReadRegular(ownerPath, 2048, 0600)
	if e != nil {
		return nil
	}
	var own imageOwner
	if json.Unmarshal(b, &own) != nil || !own.Ref.Valid() || n != imageFilename(own.Ref)+".owned" || (only.Valid() && own.Ref != only) {
		return nil
	}
	tar := imageFilename(own.Ref)
	var st unix.Stat_t
	statErr := unix.Fstatat(dir, tar, &st, unix.AT_SYMLINK_NOFOLLOW)
	if statErr != unix.ENOENT {
		if statErr != nil || uint64(st.Dev) != own.Device || st.Ino != own.Inode {
			return nil
		}
		if _, e := verifySlot(ctx, dir, key, arch, own.Ref); e != nil {
			return nil
		}
		if unix.Unlinkat(dir, tar, 0) != nil || unix.Fsync(dir) != nil {
			return errImageStage
		}
	}
	// Power loss after retiring the tar leaves its private receipt.
	// Delete only the exact signature we created.
	if err := removeImageSignature(dir, key, own); err != nil {
		return err
	}
	if unix.Fsync(dir) != nil || unix.Unlinkat(dir, n, 0) != nil || unix.Fsync(dir) != nil {
		return errImageStage
	}
	return nil
}

func removeImageSignature(dir int, key *ecdsa.PublicKey, own imageOwner) error {
	if own.SigInode == 0 {
		return nil
	}
	name := imageFilename(own.Ref) + ".sig"
	var st unix.Stat_t
	err := unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == unix.ENOENT {
		return nil
	}
	if err != nil {
		return errImageStage
	}
	if uint64(st.Dev) != own.SigDevice || st.Ino != own.SigInode {
		return nil
	}
	// The inode may have been edited in place after tar retirement.
	var buf bytes.Buffer
	if readGeoFile(dir, name, 256, &buf) != nil {
		return nil
	}
	sig, err := sigBytes(buf.Bytes())
	sum, _ := hex.DecodeString(own.Ref.Digest)
	if err != nil || !ecdsa.VerifyASN1(key, sum, sig) {
		return nil
	}
	if unix.Unlinkat(dir, name, 0) != nil || unix.Fsync(dir) != nil {
		return errImageStage
	}
	return nil
}

// A failed update may have already staged a signed release. The service
// still holds its writer while this lock excludes another artifact mutation.
func (u *CoreUpdater) retireRefusedImage(ctx context.Context, ref ImageRef) {
	if !ref.Valid() {
		return
	}
	unlock, err := lockState(u.stateDir())
	if err != nil {
		return
	}
	defer unlock()
	if ImagePending(u.Data) {
		return
	}
	boot, err := ReadImageBootstrap(u.Data)
	if err != nil || ref.Digest == boot.Runner.Digest || ref.Digest == boot.Tikray.Digest {
		return
	}
	id, err := readImageID(u.Data)
	if err != nil {
		return
	}
	receipt, err := imageVersions(u.Data, id, ref.Component, boot)
	if err != nil || receipt.Active.Digest == ref.Digest || receipt.Previous.Digest == ref.Digest {
		return
	}
	key, err := imageKey(boot.Publisher)
	if err != nil {
		return
	}
	dir, err := openGeoDir(u.Data, false, "images")
	if err != nil {
		return
	}
	defer unix.Close(dir)
	_ = retireImage(ctx, dir, key, boot.Arch, imageFilename(ref)+".owned", ref)
}

// NextInstalledImageRelease only inspects a trusted release pointer and the
// signed archive named by the active receipt. Network lookups don't authorize
// a write, and a selection changed during the observation invalidates it.
func (u *CoreUpdater) NextInstalledImageRelease(ctx context.Context, component string) (string, error) {
	id, err := readImageID(u.Data)
	if err != nil {
		return "", err
	}
	initial, err := ReadImageBootstrap(u.Data)
	if err != nil {
		return "", err
	}
	current, err := imageVersions(u.Data, id, component, initial)
	if err != nil {
		return "", err
	}
	target, err := u.availableImageVersion(ctx, component, current.Active)
	if err != nil || target == "" {
		return target, err
	}
	again, err := ReadImageStatus(u.Data, component)
	if err != nil || again.Pending != nil || again.Active != current.Active.Digest {
		return "", ErrImageState
	}
	return target, nil
}

// ImageReleaseAvailable checks the configured publisher without staging.
func (u *CoreUpdater) ImageReleaseAvailable(ctx context.Context, component string, current ImageRef) (bool, error) {
	v, err := u.availableImageVersion(ctx, component, current)
	return v != "", err
}
func (u *CoreUpdater) availableImageVersion(ctx context.Context, component string, current ImageRef) (string, error) {
	if component != current.Component || !current.Valid() {
		return "", errImageRef
	}
	c := u.ImageSource
	if c.Upstream == "" {
		return "", nil
	}
	raw := geoURL(c.Upstream, "latest")
	if raw == "" {
		return "", errImageTrust
	}
	src := GeoSourceConfig{Direct: c.Direct, Proxy: c.Proxy, ProxyHealthy: c.ProxyHealthy}
	b, e := src.small(ctx, raw)
	if e != nil {
		return "", errImageFetch
	}
	latest := strings.TrimSpace(string(b))
	if !ValidImageVersion(latest) {
		return "", errImageRef
	}
	boot, e := ReadImageBootstrap(u.Data)
	if e != nil {
		return "", e
	}
	key, e := imageKey(boot.Publisher)
	if e != nil {
		return "", e
	}
	dir, e := openGeoDir(u.Data, false, "images")
	if e != nil {
		return "", errImageStage
	}
	defer unix.Close(dir)
	version, e := verifySlot(ctx, dir, key, boot.Arch, current)
	if e != nil {
		return "", e
	}
	if latest == version.Version || latest == "sha256-"+current.Digest {
		return "", nil
	}
	return latest, nil
}
