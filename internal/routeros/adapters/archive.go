package adapters

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	installerChunkSize = 16 * 1024 // binary-safe on both measured CHRs
	maxArchive         = 128 << 20
)

var (
	errArchive   = errors.New("installer: invalid release image")
	errSignature = errors.New("installer: release signature verification failed")
)

type VerifiedArchive struct {
	component, arch, releaseBase string
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
	for _, f := range []string{keyPath, sig} {
		st, e := os.Stat(f)
		if e != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 1<<20 {
			return VerifiedArchive{}, errSignature
		}
	}
	f, err := os.Open(file)
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
	return describeArchive(p, component, b, releaseBase)
}

var safeReleaseURL = regexp.MustCompile(`^https://[A-Za-z0-9.:-]+(/[A-Za-z0-9._/-]+)?$`)

func describeArchive(p Profile, component string, b []byte, releaseBase string) (VerifiedArchive, error) {
	// Restricted literal alphabet also excludes RouterOS variable/command syntax.
	if releaseBase != "" {
		u, e := url.Parse(releaseBase)
		if e != nil || !safeReleaseURL.MatchString(releaseBase) || u.Hostname() == "" || u.User != nil {
			return VerifiedArchive{}, errors.New("installer: release base must be a public HTTPS path")
		}
	}
	var manifest []struct {
		Config   string
		RepoTags []string
	}
	var config []byte
	reader := tar.NewReader(bytes.NewReader(b))
	for {
		h, e := reader.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return VerifiedArchive{}, errArchive
		}
		if h.Name != "manifest.json" {
			continue
		}
		if manifest != nil || h.Typeflag != tar.TypeReg || h.Size > 1<<20 {
			return VerifiedArchive{}, errArchive
		}
		data, e := io.ReadAll(reader)
		if e != nil || json.Unmarshal(data, &manifest) != nil || len(manifest) != 1 {
			return VerifiedArchive{}, errArchive
		}
	}
	if len(manifest) != 1 || len(manifest[0].RepoTags) != 1 || manifest[0].RepoTags[0] != "tikray/"+component+":"+p.GOARCH() {
		return VerifiedArchive{}, errArchive
	}
	reader = tar.NewReader(bytes.NewReader(b))
	for {
		h, e := reader.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return VerifiedArchive{}, errArchive
		}
		if h.Name != manifest[0].Config {
			continue
		}
		if config != nil || h.Typeflag != tar.TypeReg || h.Size > 1<<20 {
			return VerifiedArchive{}, errArchive
		}
		config, e = io.ReadAll(reader)
		if e != nil {
			return VerifiedArchive{}, errArchive
		}
	}
	var meta struct{ Architecture, OS string }
	sum := fmt.Sprintf("%x", sha256.Sum256(config))
	if json.Unmarshal(config, &meta) != nil || meta.OS != "linux" || meta.Architecture != p.GOARCH() || manifest[0].Config != "blobs/sha256/"+sum && manifest[0].Config != sum+".json" {
		return VerifiedArchive{}, errArchive
	}
	a := VerifiedArchive{component: component, arch: p.GOARCH(), releaseBase: strings.TrimRight(releaseBase, "/"), size: len(b)}
	for off := 0; off < len(b); off += installerChunkSize {
		a.digests = append(a.digests, sha512.Sum512(b[off:min(off+installerChunkSize, len(b))]))
	}
	return a, nil
}
