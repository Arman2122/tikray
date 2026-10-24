package lab

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Arch is a RouterOS CHR architecture name.
type Arch string

const (
	ArchX86   Arch = "x86_64"
	ArchARM64 Arch = "arm64"
)

// GOARCH returns the Go architecture name for binaries that run on a.
func (a Arch) GOARCH() string {
	if a == ArchX86 {
		return "amd64"
	}
	return string(a)
}

const (
	defaultUpgradeURL  = "https://upgrade.mikrotik.com/routeros"
	defaultDownloadURL = "https://download.mikrotik.com/routeros"
)

// Artifacts holds absolute paths to the extracted CHR files for one version
// and architecture.
type Artifacts struct {
	DiskImage    string
	ContainerNPK string
}

// CacheDir is where lab downloads and builds are cached.
func CacheDir() string {
	if d := os.Getenv("TIKRAY_LAB_CACHE"); d != "" {
		return d
	}
	return filepath.Join(os.Getenv("HOME"), ".cache", "tikray-lab")
}

// ResolveChannel returns the current RouterOS v7 version of a release channel
// ("stable" or "long-term").
func ResolveChannel(ctx context.Context, baseURL, channel string) (string, error) {
	if channel != "stable" && channel != "long-term" {
		return "", fmt.Errorf("unknown RouterOS channel %q", channel)
	}
	if baseURL == "" {
		baseURL = defaultUpgradeURL
	}
	body, err := get(ctx, baseURL+"/NEWESTa7."+channel)
	if err != nil {
		return "", err
	}
	defer body.Close()
	b, err := io.ReadAll(io.LimitReader(body, 1024))
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return "", fmt.Errorf("empty answer for channel %q", channel)
	}
	return fields[0], nil
}

// FetchCHR downloads (once) and extracts the CHR disk image and the container
// package for version and arch into cacheDir/<version>/<arch>/.
func FetchCHR(ctx context.Context, baseURL, cacheDir, version string, arch Arch) (Artifacts, error) {
	if baseURL == "" {
		baseURL = defaultDownloadURL
	}
	var imgZip, img, pkgZip, npk string
	switch arch {
	case ArchX86:
		imgZip, img = "chr-"+version+".img.zip", "chr-"+version+".img"
		pkgZip, npk = "all_packages-x86-"+version+".zip", "container-"+version+".npk"
	case ArchARM64:
		imgZip, img = "chr-"+version+"-arm64.img.zip", "chr-"+version+"-arm64.img"
		pkgZip, npk = "all_packages-arm64-"+version+".zip", "container-"+version+"-arm64.npk"
	default:
		return Artifacts{}, fmt.Errorf("unsupported arch %q", arch)
	}
	dir := filepath.Join(cacheDir, version, string(arch))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Artifacts{}, err
	}
	a := Artifacts{DiskImage: filepath.Join(dir, img), ContainerNPK: filepath.Join(dir, npk)}
	if err := fetchMember(ctx, baseURL+"/"+version+"/"+imgZip, img, a.DiskImage); err != nil {
		return Artifacts{}, err
	}
	if err := fetchMember(ctx, baseURL+"/"+version+"/"+pkgZip, npk, a.ContainerNPK); err != nil {
		return Artifacts{}, err
	}
	return a, nil
}

// fetchMember extracts one member of the zip at url to dst, unless dst
// already exists. Partial work only ever lives in *.part files.
func fetchMember(ctx context.Context, url, member, dst string) error {
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	zipPart := dst + ".zip.part"
	defer os.Remove(zipPart)
	if err := download(ctx, url, zipPart); err != nil {
		return err
	}
	zr, err := zip.OpenReader(zipPart)
	if err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != member {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		part := dst + ".part"
		if err := writeFile(part, rc); err != nil {
			os.Remove(part)
			return fmt.Errorf("extract %s from %s: %w", member, url, err)
		}
		return os.Rename(part, dst)
	}
	return fmt.Errorf("%s: no member %q", url, member)
}

func download(ctx context.Context, url, dst string) error {
	body, err := get(ctx, url)
	if err != nil {
		return err
	}
	defer body.Close()
	if err := writeFile(dst, body); err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	return nil
}

func writeFile(path string, r io.Reader) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func get(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}
