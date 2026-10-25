package labinet

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// The fake GitHub and its mirror share one directory, the releases root:
//
//	root/<tag>/<file>      release assets, e.g. v26.10.21/Xray-linux-64.zip
//	root/LATEST            the tag /releases/latest points at
//	root/index/index.json  the mirror's signed hash index, and its .sig
//
// A test switches their behaviour by creating and removing these empty files
// in root while labinet runs. They are looked at on every request.
const (
	// flagDown makes the fake GitHub answer 503 to everything.
	flagDown = ".down"
	// flagBlockDirect makes it answer 403 to the router's WAN address, so that
	// only requests that went through the proxy get through.
	flagBlockDirect = ".block-direct"
	// flagMirrorDown makes the mirror answer 503 to everything. The mirror is
	// not GitHub, so it ignores flagDown and flagBlockDirect.
	flagMirrorDown = ".mirror-down"

	latestFile = "LATEST"
	indexDir   = "index"
)

// routerWAN is where requests that left CHR's WAN directly come from: CHR
// masquerades its containers' traffic. Requests that went through the VLESS
// proxy come from proxyEgress instead.
const routerWAN = "198.51.100.2"

const githubPrefix = "/XTLS/Xray-core/releases/"

// nameRE is what a tag or a file name must look like to be served or
// redirected to: no separators, no leading dot (which also rules out "." and
// ".." and keeps the flag files out of reach), nothing a shell or a URL would
// treat specially. XTLS's names, such as Xray-linux-arm64-v8a.zip.dgst, fit.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._+-]{0,127}$`)

// ReleasesHandler is the lab's stand-in for XTLS/Xray-core on GitHub. It
// serves root/<tag>/<file> at /XTLS/Xray-core/releases/download/<tag>/<file>
// and answers /XTLS/Xray-core/releases/latest with a 302 to
// /XTLS/Xray-core/releases/tag/<tag> for the tag in root/LATEST. Flag files in
// root, flagDown and flagBlockDirect, change its behaviour.
func ReleasesHandler(root string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if flagSet(root, flagDown) {
			http.Error(w, "fake GitHub is down", http.StatusServiceUnavailable)
			return
		}
		if callerIP(r.RemoteAddr) == routerWAN && flagSet(root, flagBlockDirect) {
			http.Error(w, "fake GitHub refuses direct requests", http.StatusForbidden)
			return
		}
		if !readOnly(w, r) {
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, githubPrefix)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if rest == "latest" {
			redirectLatest(w, r, root)
			return
		}
		if rest, ok = strings.CutPrefix(rest, "download/"); ok {
			serveAsset(w, r, root, rest)
			return
		}
		http.NotFound(w, r)
	})
}

// MirrorHandler is the lab's mirror of the releases. It serves
// root/<tag>/<file> at /m/<tag>/<file>, and the signed hash index,
// root/index/index.json and root/index/index.json.sig, at /index.json and
// /index.json.sig. The flag file flagMirrorDown makes it answer 503 to
// everything.
func MirrorHandler(root string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if flagSet(root, flagMirrorDown) {
			http.Error(w, "mirror is down", http.StatusServiceUnavailable)
			return
		}
		if !readOnly(w, r) {
			return
		}
		switch p := r.URL.Path; p {
		case "/index.json", "/index.json.sig":
			serveFile(w, r, root, indexDir+p)
		default:
			if rest, ok := strings.CutPrefix(p, "/m/"); ok {
				serveAsset(w, r, root, rest)
				return
			}
			http.NotFound(w, r)
		}
	})
}

// readOnly reports whether r is a GET or HEAD. Otherwise it has answered 405,
// as an object store would.
func readOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

// flagSet reports whether the flag file exists in root now.
func flagSet(root, flag string) bool {
	_, err := os.Stat(filepath.Join(root, flag))
	return err == nil
}

// redirectLatest answers 302 to the release page of the tag in root/LATEST.
func redirectLatest(w http.ResponseWriter, r *http.Request, root string) {
	tag, err := readSmall(root, latestFile)
	tag = strings.TrimSpace(tag)
	if err != nil || !nameRE.MatchString(tag) {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, githubPrefix+"tag/"+tag, http.StatusFound)
}

// readSmall returns the start of the file rel in root.
func readSmall(root, rel string) (string, error) {
	rt, err := os.OpenRoot(root)
	if err != nil {
		return "", err
	}
	defer rt.Close()
	f, err := rt.Open(rel)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 256))
	return string(b), err
}

// serveAsset serves root/<tag>/<file> for tagFile, which must be exactly
// "<tag>/<file>".
func serveAsset(w http.ResponseWriter, r *http.Request, root, tagFile string) {
	tag, file, ok := strings.Cut(tagFile, "/")
	if !ok || !nameRE.MatchString(tag) || !nameRE.MatchString(file) {
		http.NotFound(w, r)
		return
	}
	serveFile(w, r, root, tag+"/"+file)
}

// serveFile serves the regular file rel of root. rel is relative and made of
// names that already passed nameRE. It is opened through os.Root, so even a
// symlink in root cannot lead out of it. root is opened anew on every
// request, so a test can remove and recreate it while labinet runs.
func serveFile(w http.ResponseWriter, r *http.Request, root, rel string) {
	rt, err := os.OpenRoot(root)
	if errors.Is(err, fs.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "releases root: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rt.Close()
	f, err := rt.Open(rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, filepath.Base(rel), fi.ModTime(), f)
}

// MakeReleaseZip writes at dst a zip laid out like XTLS's release archives:
// the binary at xrayPath as the root entry xray, mode 0755 whatever the mode
// of the source, beside a README.md. It returns the SHA-256 of the zip as
// lowercase hex. The same input gives the same zip, byte for byte. A failed
// call leaves no file at dst.
func MakeReleaseZip(dst, xrayPath string) (sum string, err error) {
	src, err := os.Open(xrayPath)
	if err != nil {
		return "", err
	}
	defer src.Close()
	fi, err := src.Stat()
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("release zip: %s is not a regular file", xrayPath)
	}

	out, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(dst)
		}
	}()
	h := sha256.New()
	zw := zip.NewWriter(io.MultiWriter(out, h))
	if err := addEntry(zw, "xray", 0o755, func(w io.Writer) error {
		_, err := io.Copy(w, src)
		return err
	}); err != nil {
		return "", err
	}
	if err := addEntry(zw, "README.md", 0o644, func(w io.Writer) error {
		_, err := io.WriteString(w, readme)
		return err
	}); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

const readme = "# Xray-core (tikray lab fixture)\n\nA stand-in for an XTLS release archive.\n"

// entryTime is every entry's modification time, which keeps zips reproducible.
var entryTime = time.Date(2026, 1, 18, 0, 0, 0, 0, time.UTC)

func addEntry(zw *zip.Writer, name string, mode fs.FileMode, fill func(io.Writer) error) error {
	hdr := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: entryTime}
	hdr.SetMode(mode)
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	return fill(w)
}

var sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// WriteDgst writes the .dgst file XTLS publishes next to each archive: four
// lines of "NAME= hex", what `openssl dgst` prints with the file name in
// parentheses cut out. Only the SHA2-256 line is meant to be read, so the
// other digests are placeholders of the right length.
func WriteDgst(path, sum string) error {
	if !sha256RE.MatchString(sum) {
		return errors.New("dgst: SHA-256 is not 64 lowercase hex characters")
	}
	body := "MD5= " + strings.Repeat("0f", 16) + "\n" +
		"SHA1= " + strings.Repeat("1e", 20) + "\n" +
		"SHA2-256= " + sum + "\n" +
		"SHA2-512= " + strings.Repeat("2d", 64) + "\n"
	return os.WriteFile(path, []byte(body), 0o644)
}
