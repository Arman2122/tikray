package labinet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSubServes(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "x", "vless://one\n")
	h := HTTPHandler(dir)

	w := get(h, direct, "/sub/x")
	if w.Code != 200 || w.Body.String() != "vless://one\n" {
		t.Fatalf("GET /sub/x = %d %q, want 200 \"vless://one\\n\"", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type %q, want text/plain", ct)
	}
	if w := do(h, "HEAD", direct, "/sub/x"); w.Code != 200 || w.Body.Len() != 0 {
		t.Errorf("HEAD = %d with %d body bytes, want 200 and none", w.Code, w.Body.Len())
	}
	if w := get(h, direct, "/sub/x?token=1"); w.Code != 200 {
		t.Errorf("GET with a query = %d, want 200", w.Code)
	}
	if w := do(h, "POST", direct, "/sub/x"); w.Code != 405 {
		t.Errorf("POST = %d, want 405", w.Code)
	}

	// The file is read on every request, so the test can switch what a
	// subscription answers while labinet runs.
	write(t, dir, "x", "vless://two\nvless://three\n")
	if w := get(h, direct, "/sub/x"); w.Code != 200 || w.Body.String() != "vless://two\nvless://three\n" {
		t.Errorf("GET /sub/x after a rewrite = %d %q, want the new contents", w.Code, w.Body)
	}
	write(t, dir, "x", "")
	if w := get(h, direct, "/sub/x"); w.Code != 200 || w.Body.Len() != 0 {
		t.Errorf("GET /sub/x after it was emptied = %d %q, want 200 and an empty body", w.Code, w.Body)
	}

	// Files that appear and go while it runs.
	if w := get(h, direct, "/sub/later.txt"); w.Code != 404 {
		t.Errorf("GET /sub/later.txt before it exists = %d, want 404", w.Code)
	}
	write(t, dir, "later.txt", "late")
	if w := get(h, direct, "/sub/later.txt"); w.Code != 200 || w.Body.String() != "late" {
		t.Errorf("GET /sub/later.txt once it exists = %d %q, want 200 \"late\"", w.Code, w.Body)
	}
	if err := os.Remove(filepath.Join(dir, "later.txt")); err != nil {
		t.Fatal(err)
	}
	if w := get(h, direct, "/sub/later.txt"); w.Code != 404 {
		t.Errorf("GET /sub/later.txt after it is removed = %d, want 404", w.Code)
	}

	// The other endpoints are still there.
	if w := get(h, "203.0.113.10:5555", "/whoami"); w.Body.String() != "203.0.113.10" {
		t.Errorf("/whoami with a subs dir = %q, want 203.0.113.10", w.Body)
	}
}

func TestSubMissing(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "x", "body")
	write(t, dir, "d/inner", "body")
	h := HTTPHandler(dir)
	for _, target := range []string{"/sub/nope", "/sub/", "/sub", "/sub/d", "/sub/d/inner"} {
		if w := get(h, direct, target); w.Code != 404 {
			t.Errorf("GET %s = %d, want 404", target, w.Code)
		}
	}
}

func TestSubWithoutDir(t *testing.T) {
	// No -subs: there is nothing to serve, even for a name the working
	// directory happens to have.
	for _, dir := range []string{"", filepath.Join(t.TempDir(), "gone")} {
		h := HTTPHandler(dir)
		for _, target := range []string{"/sub/x", "/sub/handlers.go", "/sub/"} {
			if w := get(h, direct, target); w.Code != 404 {
				t.Errorf("GET %s with subs dir %q = %d, want 404", target, dir, w.Code)
			}
		}
	}
	if w := get(HTTPHandler(""), "203.0.113.10:5555", "/whoami"); w.Body.String() != "203.0.113.10" {
		t.Errorf("/whoami without a subs dir = %q, want 203.0.113.10", w.Body)
	}
}

func TestSubRefusesEscapes(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "subs")
	write(t, dir, "x", "ok")
	write(t, dir, ".hidden", "HIDDEN")
	write(t, base, "secret.txt", "SECRET")
	if err := os.Symlink(filepath.Join(base, "secret.txt"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	h := HTTPHandler(dir)
	if w := get(h, direct, "/sub/x"); w.Code != 200 {
		t.Fatalf("control request = %d, want 200", w.Code)
	}
	for _, target := range []string{
		"/sub/../secret.txt",
		"/sub/x/../../secret.txt",
		"/sub/%2e%2e/secret.txt",
		"/sub/%2e%2e%2fsecret.txt",
		"/sub/..%2fsecret.txt",
		"/sub/..%5csecret.txt",
		"/sub/..",
		"/sub/.",
		"/sub/x/",
		"/sub/x/extra",
		"/sub//x",
		"/sub//etc/passwd",
		"/sub/%2fetc%2fpasswd",
		"/sub/x%00.txt",
		"/sub/.hidden", // a dot file is not a subscription
		"/sub/link",    // a symlink out of the dir
	} {
		w := get(h, direct, target)
		if w.Code != 404 || strings.Contains(w.Body.String(), "SECRET") || strings.Contains(w.Body.String(), "HIDDEN") {
			t.Errorf("GET %s = %d %q, want 404", target, w.Code, w.Body)
		}
	}
}
