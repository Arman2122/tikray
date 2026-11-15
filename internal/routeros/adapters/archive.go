package adapters

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"github.com/Arman2122/tikray/internal/atomicfile"
	"github.com/Arman2122/tikray/internal/imagearchive"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	installerChunkSize = 16 * 1024 // binary-safe on both measured CHRs
	maxArchive         = imagearchive.MaxSize
)

var (
	errArchive   = errors.New("installer: invalid release image")
	errSignature = errors.New("installer: release signature verification failed")
)

type VerifiedArchive struct {
	component, arch, releaseBase string
	publisher, signature         string
	ref                          imagearchive.Ref
	size                         int
	digests                      [][sha512.Size]byte
}

// VerifyArchive verifies exactly the bytes subsequently described by the chunk
// manifest. Both the publisher's key and the signatures are local build inputs.
func VerifyArchive(ctx context.Context, p Profile, component, dir, key, releaseBase string) (VerifiedArchive, error) {
	if p.GOARCH() == "" || component != "tikray" && component != "tikray-runner" {
		return VerifiedArchive{}, errArchive
	}
	file := filepath.Join(dir, component+"-"+p.GOARCH()+".tar")
	keyPath, err := filepath.Abs(key)
	if err != nil {
		return VerifiedArchive{}, errSignature
	}
	sig, err := filepath.Abs(file + ".sig")
	if err != nil {
		return VerifiedArchive{}, errSignature
	}
	keyPEM, err := atomicfile.ReadRegular(keyPath, 4096, 0)
	if err != nil {
		return VerifiedArchive{}, errSignature
	}
	block, tail := pem.Decode(keyPEM)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(tail)) != 0 {
		return VerifiedArchive{}, errSignature
	}
	sigText, err := atomicfile.ReadRegular(sig, 256, 0)
	if err != nil {
		return VerifiedArchive{}, errSignature
	}
	f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return VerifiedArchive{}, errArchive
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > maxArchive {
		return VerifiedArchive{}, errArchive
	}
	b, err := io.ReadAll(io.LimitReader(f, maxArchive+1))
	if err != nil || int64(len(b)) != st.Size() {
		return VerifiedArchive{}, errArchive
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cosign", "verify-blob", "--key", keyPath, "--signature", sig, "--insecure-ignore-tlog=true", "--offline=true", "-")
	cmd.Stdin = bytes.NewReader(b)
	if cmd.Run() != nil {
		return VerifiedArchive{}, errSignature
	}
	a, err := describeArchive(p, component, b, releaseBase)
	if err != nil {
		return VerifiedArchive{}, err
	}
	if err := a.bindSignature(block.Bytes, sigText); err != nil {
		return VerifiedArchive{}, err
	}
	return a, nil
}

var safeReleaseURL = regexp.MustCompile(`^https://[A-Za-z0-9.:-]+(/[A-Za-z0-9._/-]+)?$`)

func describeArchive(p Profile, component string, b []byte, releaseBase string) (VerifiedArchive, error) {
	// Restricted literal alphabet also excludes RouterOS variable/command syntax.
	if releaseBase != "" {
		u, e := url.Parse(releaseBase)
		if e != nil || !safeReleaseURL.MatchString(releaseBase) || u.Hostname() == "" || u.User != nil {
			return VerifiedArchive{}, errors.New("installer: release base must be a public HTTPS path")
		}
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		if host == "github.com" || host == "www.github.com" {
			// These routes deliberately redirect to signed query URLs. Native
			// fetch diagnostics can retain Location even when redirecting is off.
			route := path.Clean(strings.ToLower(u.Path)) + "/"
			if strings.Contains(route, "/releases/download/") || strings.Contains(route, "/releases/latest/download/") {
				return VerifiedArchive{}, errors.New("installer: use a direct public HTTPS release endpoint or upload the archives")
			}
		}
	}
	role := component
	if component == "tikray-runner" {
		role = "runner"
	}
	ref, _, err := imagearchive.Inspect(context.Background(), bytes.NewReader(b), int64(len(b)), role, p.GOARCH(), "")
	if err != nil || imagearchive.ReleaseName(role) != component {
		return VerifiedArchive{}, errArchive
	}
	a := VerifiedArchive{component: component, arch: p.GOARCH(), releaseBase: strings.TrimRight(releaseBase, "/"), size: len(b), ref: ref}
	for off := 0; off < len(b); off += installerChunkSize {
		a.digests = append(a.digests, sha512.Sum512(b[off:min(off+installerChunkSize, len(b))]))
	}
	return a, nil
}

// Preserve the exact trust input in the installer. In-process verification
// also prevents a replaced key or detached signature between two file reads
// from being provisioned by an otherwise successful cosign subprocess.
func (a *VerifiedArchive) bindSignature(der, sigText []byte) error {
	k, e := x509.ParsePKIXPublicKey(der)
	key, ok := k.(*ecdsa.PublicKey)
	if e != nil || !ok || key.Curve != elliptic.P256() {
		return errSignature
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(sigText)))
	digest, e2 := hex.DecodeString(a.ref.Digest)
	if e != nil || e2 != nil || len(digest) != sha256.Size || !ecdsa.VerifyASN1(key, digest, sig) {
		return errSignature
	}
	a.publisher = base64.StdEncoding.EncodeToString(der)
	a.signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}
