package labinet

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/xrayver"
)

const (
	direct   = "198.51.100.2:1234" // a request that did not go through the proxy
	proxied  = "203.0.113.10:1234" // a request that left through the VLESS proxy
	proxiedB = "203.0.113.11:1234" // the same through the second VLESS server

	zipURL = "/XTLS/Xray-core/releases/download/v26.10.21/Xray-linux-64.zip"
)

// write creates root/rel, and any directory above it, with body.
func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// get serves GET target to h as a client at remote.
func get(h http.Handler, remote, target string) *httptest.ResponseRecorder {
	return do(h, "GET", remote, target)
}

func do(h http.Handler, method, remote, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestReleasesServe(t *testing.T) {
	root := t.TempDir()
	write(t, root, "v26.10.21/Xray-linux-64.zip", "zip bytes")
	h := ReleasesHandler(root)

	w := get(h, proxied, zipURL)
	if w.Code != 200 || w.Body.String() != "zip bytes" {
		t.Fatalf("GET %s = %d %q, want 200 \"zip bytes\"", zipURL, w.Code, w.Body)
	}
	if w := do(h, "HEAD", proxied, zipURL); w.Code != 200 || w.Body.Len() != 0 {
		t.Errorf("HEAD = %d with %d body bytes, want 200 and none", w.Code, w.Body.Len())
	}
	if w := get(h, proxied, zipURL+"?x=1"); w.Code != 200 {
		t.Errorf("GET with a query = %d, want 200", w.Code)
	}
	if w := get(h, proxied, "/XTLS/Xray-core/releases/download/v26.10.21/nope.zip"); w.Code != 404 {
		t.Errorf("missing file = %d, want 404", w.Code)
	}
	if w := get(h, proxied, "/XTLS/Xray-core/releases/download/v26.10.21/"); w.Code != 404 {
		t.Errorf("a tag directory = %d, want 404", w.Code)
	}
	if w := get(h, proxied, "/whoami"); w.Code != 404 {
		t.Errorf("a path GitHub does not have = %d, want 404", w.Code)
	}
	if w := do(h, "POST", proxied, zipURL); w.Code != 405 {
		t.Errorf("POST = %d, want 405", w.Code)
	}

	// The flag files are looked at on every request, so a test can flip
	// them while labinet runs.
	t.Run("down", func(t *testing.T) {
		down := filepath.Join(root, ".down")
		write(t, root, ".down", "")
		for _, remote := range []string{direct, proxied} {
			for _, target := range []string{zipURL, "/XTLS/Xray-core/releases/latest", "/nothing"} {
				if w := get(h, remote, target); w.Code != 503 {
					t.Errorf("%s GET %s with .down = %d, want 503", remote, target, w.Code)
				}
			}
		}
		os.Remove(down)
		if w := get(h, direct, zipURL); w.Code != 200 {
			t.Errorf("GET after .down is removed = %d, want 200", w.Code)
		}
	})

	t.Run("block-direct", func(t *testing.T) {
		write(t, root, ".block-direct", "")
		if w := get(h, direct, zipURL); w.Code != 403 {
			t.Errorf("router WAN with .block-direct = %d, want 403", w.Code)
		}
		for _, remote := range []string{proxied, proxiedB} {
			if w := get(h, remote, zipURL); w.Code != 200 || w.Body.String() != "zip bytes" {
				t.Errorf("%s with .block-direct = %d %q, want 200 \"zip bytes\"", remote, w.Code, w.Body)
			}
		}
		os.Remove(filepath.Join(root, ".block-direct"))
		if w := get(h, direct, zipURL); w.Code != 200 {
			t.Errorf("router WAN after .block-direct is removed = %d, want 200", w.Code)
		}
	})

	t.Run("down beats block-direct", func(t *testing.T) {
		write(t, root, ".down", "")
		write(t, root, ".block-direct", "")
		defer os.Remove(filepath.Join(root, ".down"))
		defer os.Remove(filepath.Join(root, ".block-direct"))
		if w := get(h, direct, zipURL); w.Code != 503 {
			t.Errorf("router WAN with both flags = %d, want 503", w.Code)
		}
	})

	// A mirror flag is not GitHub's business.
	write(t, root, ".mirror-down", "")
	if w := get(h, proxied, zipURL); w.Code != 200 {
		t.Errorf("GET with .mirror-down = %d, want 200", w.Code)
	}
}

func TestLatestRedirect(t *testing.T) {
	const latest = "/XTLS/Xray-core/releases/latest"
	root := t.TempDir()
	h := ReleasesHandler(root)

	if w := get(h, proxied, latest); w.Code != 404 {
		t.Errorf("latest with no LATEST file = %d, want 404", w.Code)
	}

	write(t, root, "LATEST", "v26.10.21\n")
	w := get(h, proxied, latest)
	if w.Code != 302 {
		t.Fatalf("latest = %d, want 302", w.Code)
	}
	if got, want := w.Header().Get("Location"), "/XTLS/Xray-core/releases/tag/v26.10.21"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}

	// The contents are read again each time.
	write(t, root, "LATEST", "  v26.11.2 \r\n\n")
	if got, want := get(h, proxied, latest).Header().Get("Location"), "/XTLS/Xray-core/releases/tag/v26.11.2"; got != want {
		t.Errorf("Location after LATEST changed = %q, want %q", got, want)
	}

	// Anything that is not a plain tag is no redirect target.
	for _, bad := range []string{"", "\n", "../../evil", "v1/../../x", "//evil.test/x", "a b"} {
		write(t, root, "LATEST", bad)
		if w := get(h, proxied, latest); w.Code == 302 {
			t.Errorf("LATEST %q redirected to %q", bad, w.Header().Get("Location"))
		}
	}
	write(t, root, "LATEST", "v26.10.21\n")

	// GitHub is the one being blocked, so the redirect obeys the flags too.
	write(t, root, ".block-direct", "")
	if w := get(h, direct, latest); w.Code != 403 {
		t.Errorf("latest from the router WAN with .block-direct = %d, want 403", w.Code)
	}
	if w := get(h, proxied, latest); w.Code != 302 {
		t.Errorf("latest proxied with .block-direct = %d, want 302", w.Code)
	}
	write(t, root, ".down", "")
	if w := get(h, proxied, latest); w.Code != 503 {
		t.Errorf("latest with .down = %d, want 503", w.Code)
	}
}

// secretTree makes root with a release and, beside it, a file that no handler
// may give out.
func secretTree(t *testing.T) (root string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "releases")
	write(t, root, "v1/ok.zip", "ok")
	write(t, base, "secret.txt", "SECRET")
	write(t, root, "v1/.hidden", "HIDDEN")
	write(t, root, "LATEST", "v1")
	if err := os.Symlink(filepath.Join(base, "secret.txt"), filepath.Join(root, "v1", "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, filepath.Join(root, "outside")); err != nil {
		t.Fatal(err)
	}
	return root
}

func assertNoLeak(t *testing.T, h http.Handler, targets []string) {
	t.Helper()
	for _, target := range targets {
		w := get(h, proxied, target)
		if w.Code == 200 || strings.Contains(w.Body.String(), "SECRET") || strings.Contains(w.Body.String(), "HIDDEN") {
			t.Errorf("GET %s = %d %q, want a refusal", target, w.Code, w.Body)
		}
	}
}

func TestReleasesRefuseEscapes(t *testing.T) {
	root := secretTree(t)
	h := ReleasesHandler(root)
	const dl = "/XTLS/Xray-core/releases/download/"
	if w := get(h, proxied, dl+"v1/ok.zip"); w.Code != 200 {
		t.Fatalf("control request = %d, want 200", w.Code)
	}
	assertNoLeak(t, h, []string{
		dl + "../secret.txt",
		dl + "v1/../../secret.txt",
		dl + "../releases/v1/ok.zip",
		dl + "v1/..",
		dl + "../v1/ok.zip",
		dl + "%2e%2e/secret.txt",
		dl + "v1/%2e%2e%2f%2e%2e%2fsecret.txt",
		dl + "v1%2f..%2f..%2fsecret.txt",
		dl + "..%2fsecret.txt",
		dl + "v1/..%5c..%5csecret.txt",
		dl + "v1//ok.zip",
		dl + "v1/ok.zip/",
		dl + "v1/ok.zip/extra",
		dl + "/etc/passwd",
		dl + "v1/%2fetc%2fpasswd",
		dl + "v1/ok.zip%00.txt",
		dl + "v1/link.txt",        // a symlink out of root
		dl + "outside/secret.txt", // a directory symlink out of root
		dl + "v1/.hidden",
		dl + "v1/.",
	})
}

func TestMirrorRefusesEscapes(t *testing.T) {
	root := secretTree(t)
	h := MirrorHandler(root)
	if w := get(h, proxied, "/m/v1/ok.zip"); w.Code != 200 {
		t.Fatalf("control request = %d, want 200", w.Code)
	}
	assertNoLeak(t, h, []string{
		"/m/../secret.txt",
		"/m/v1/../../secret.txt",
		"/m/%2e%2e/secret.txt",
		"/m/v1%2f..%2f..%2fsecret.txt",
		"/m/v1/..%5c..%5csecret.txt",
		"/m/v1//ok.zip",
		"/m//etc/passwd",
		"/m/v1/link.txt",
		"/m/outside/secret.txt",
		"/m/v1/.hidden",
		"/index/../../secret.txt",
		"/index.json/../../secret.txt",
	})
}

func TestReleasesDotFilesNotServed(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".block-direct", "block")
	write(t, root, ".mirror-down", "")
	write(t, root, "v1/ok.zip", "ok")
	write(t, root, "v1/.dgst-secret", "HIDDEN")
	write(t, root, ".hiddentag/ok.zip", "HIDDEN")
	for _, h := range []http.Handler{ReleasesHandler(root), MirrorHandler(root)} {
		for _, target := range []string{
			"/XTLS/Xray-core/releases/download/v1/.dgst-secret",
			"/XTLS/Xray-core/releases/download/.hiddentag/ok.zip",
			"/XTLS/Xray-core/releases/download/v1/../.block-direct",
			"/XTLS/Xray-core/releases/download/.block-direct/x",
			"/XTLS/Xray-core/releases/download/.mirror-down/x",
			"/XTLS/Xray-core/releases/.block-direct",
			"/m/v1/.dgst-secret",
			"/m/.hiddentag/ok.zip",
			"/m/.block-direct/x",
			"/.block-direct",
			"/.mirror-down",
			"/index/.mirror-down",
		} {
			if w := get(h, proxied, target); w.Code == 200 || strings.Contains(w.Body.String(), "HIDDEN") {
				t.Errorf("GET %s = %d %q, want a refusal", target, w.Code, w.Body)
			}
		}
	}
}

func TestMirrorServe(t *testing.T) {
	root := t.TempDir()
	write(t, root, "v26.10.21/Xray-linux-64.zip", "zip bytes")
	write(t, root, "index/index.json", `{"v":1}`)
	write(t, root, "index/index.json.sig", "c2ln")
	write(t, root, "index/other.json", "no")
	h := MirrorHandler(root)

	for _, c := range []struct{ target, want string }{
		{"/m/v26.10.21/Xray-linux-64.zip", "zip bytes"},
		{"/index.json", `{"v":1}`},
		{"/index.json.sig", "c2ln"},
	} {
		w := get(h, direct, c.target)
		if w.Code != 200 || w.Body.String() != c.want {
			t.Errorf("GET %s = %d %q, want 200 %q", c.target, w.Code, w.Body, c.want)
		}
	}
	for _, target := range []string{
		"/m/v26.10.21/missing.zip",
		"/m/v26.10.21",
		"/m/",
		"/index/other.json", // only the two index files are public
		"/other.json",
		"/XTLS/Xray-core/releases/download/v26.10.21/Xray-linux-64.zip", // GitHub's path is not the mirror's
	} {
		if w := get(h, direct, target); w.Code != 404 {
			t.Errorf("GET %s = %d, want 404", target, w.Code)
		}
	}
	if w := do(h, "POST", direct, "/index.json"); w.Code != 405 {
		t.Errorf("POST = %d, want 405", w.Code)
	}

	// A mirror is not GitHub: it ignores GitHub's flags...
	write(t, root, ".block-direct", "")
	write(t, root, ".down", "")
	for _, target := range []string{"/m/v26.10.21/Xray-linux-64.zip", "/index.json"} {
		if w := get(h, direct, target); w.Code != 200 {
			t.Errorf("GET %s with .block-direct and .down = %d, want 200", target, w.Code)
		}
	}
	// ...and has a flag of its own, which GitHub ignores.
	write(t, root, ".mirror-down", "")
	for _, target := range []string{"/m/v26.10.21/Xray-linux-64.zip", "/index.json", "/index.json.sig", "/nothing"} {
		for _, remote := range []string{direct, proxied} {
			if w := get(h, remote, target); w.Code != 503 {
				t.Errorf("%s GET %s with .mirror-down = %d, want 503", remote, target, w.Code)
			}
		}
	}
	os.Remove(filepath.Join(root, ".mirror-down"))
	if w := get(h, direct, "/index.json"); w.Code != 200 {
		t.Errorf("GET after .mirror-down is removed = %d, want 200", w.Code)
	}
}

// fakeXray is a stand-in binary for the zip fixtures.
func fakeXray(t *testing.T) (path string, body []byte) {
	t.Helper()
	body = append([]byte("\x7fELF fake xray "), bytes.Repeat([]byte{0xab, 0xcd}, 5000)...)
	path = filepath.Join(t.TempDir(), "xray-src")
	if err := os.WriteFile(path, body, 0o644); err != nil { // not executable: the zip says 0755
		t.Fatal(err)
	}
	return path, body
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestMakeReleaseZipInstalls(t *testing.T) {
	src, body := fakeXray(t)
	dst := filepath.Join(t.TempDir(), "Xray-linux-64.zip")
	zipSum, err := MakeReleaseZip(dst, src)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if zipSum != sha(raw) {
		t.Errorf("MakeReleaseZip returned %s, the file hashes to %s", zipSum, sha(raw))
	}

	v, err := xrayver.Parse("26.10.21")
	if err != nil {
		t.Fatal(err)
	}
	cores := t.TempDir()
	slot, err := artifacts.InstallCore(cores, v, dst, artifacts.Meta{Source: "direct", ZipSHA256: zipSum, Verified: "dgst"})
	if err != nil {
		t.Fatalf("InstallCore on the fixture zip: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(slot.Dir, "xray"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Error("the installed xray differs from the source binary")
	}
	if slot.Meta.BinarySHA256 != sha(body) {
		t.Errorf("BinarySHA256 = %s, want %s", slot.Meta.BinarySHA256, sha(body))
	}
	if fi, err := os.Stat(filepath.Join(slot.Dir, "xray")); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("installed xray mode = %v (%v), want 0755", fi.Mode().Perm(), err)
	}
}

func TestMakeReleaseZipLayout(t *testing.T) {
	src, body := fakeXray(t)
	dst := filepath.Join(t.TempDir(), "a.zip")
	if _, err := MakeReleaseZip(dst, src); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	byName := map[string]*zip.File{}
	for _, f := range zr.File {
		byName[f.Name] = f
	}
	if len(zr.File) != 2 || byName["xray"] == nil || byName["README.md"] == nil {
		t.Fatalf("entries = %v, want exactly xray and README.md at the root", names(zr.File))
	}
	if m := byName["xray"].Mode(); !m.IsRegular() || m.Perm() != 0o755 {
		t.Errorf("xray entry mode = %v, want a regular file with 0755", m)
	}
	rc, err := byName["xray"].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if b, _ := io.ReadAll(rc); !bytes.Equal(b, body) {
		t.Error("the xray entry differs from the source binary")
	}
	if byName["README.md"].UncompressedSize64 == 0 {
		t.Error("README.md is empty")
	}

	// The same input gives the same zip, so a hash can be pinned in a test.
	dst2 := filepath.Join(t.TempDir(), "b.zip")
	s1, _ := MakeReleaseZip(dst, src)
	s2, err := MakeReleaseZip(dst2, src)
	if err != nil || s1 != s2 {
		t.Errorf("second zip hash = %s (%v), want %s", s2, err, s1)
	}
}

func TestMakeReleaseZipErrors(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "x.zip")
	if _, err := MakeReleaseZip(dst, filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing xray binary gave no error")
	}
	if _, err := os.Stat(dst); err == nil {
		t.Error("a failed MakeReleaseZip left the zip behind")
	}
}

func names(files []*zip.File) []string {
	var n []string
	for _, f := range files {
		n = append(n, f.Name)
	}
	return n
}

func TestWriteDgst(t *testing.T) {
	sum := sha([]byte("anything"))
	path := filepath.Join(t.TempDir(), "Xray-linux-64.zip.dgst")
	if err := WriteDgst(path, sum); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 4 || !strings.HasSuffix(string(raw), "\n") {
		t.Fatalf("dgst = %q, want four newline-terminated lines", raw)
	}
	for i, c := range []struct {
		key  string
		hexN int
	}{{"MD5", 32}, {"SHA1", 40}, {"SHA2-256", 64}, {"SHA2-512", 128}} {
		key, val, ok := strings.Cut(lines[i], "= ")
		if !ok || key != c.key || len(val) != c.hexN || strings.Trim(val, "0123456789abcdef") != "" {
			t.Errorf("line %d = %q, want %q= and %d lowercase hex digits", i+1, lines[i], c.key, c.hexN)
		}
	}
	if got, want := lines[2], "SHA2-256= "+sum; got != want {
		t.Errorf("SHA-256 line = %q, want %q", got, want)
	}
	// What the installer's own parser reads out of it.
	got, err := artifacts.ParseDgst(bytes.NewReader(raw))
	if err != nil || got != sum {
		t.Errorf("ParseDgst = %q, %v; want %s", got, err, sum)
	}

	for _, bad := range []string{"", "abc", strings.ToUpper(sum), sum + "00", sum[:63] + "g"} {
		if err := WriteDgst(filepath.Join(t.TempDir(), "x.dgst"), bad); err == nil {
			t.Errorf("WriteDgst accepted SHA-256 %q", bad)
		}
	}
}
