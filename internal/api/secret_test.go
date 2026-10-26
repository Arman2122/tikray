package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// modeOf returns the permission bits of path.
func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTokenAndCertReused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state") // missing: created, 0700
	ips := []net.IP{net.ParseIP("172.31.255.2"), net.ParseIP("127.0.0.1"), net.ParseIP("172.31.255.2"), net.IPv4zero, nil}

	tok1, err := LoadOrCreateToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !hex64.MatchString(tok1) {
		t.Fatalf("the token is not 64 lowercase hex characters (length %d)", len(tok1))
	}
	cert1, fp1, err := LoadOrCreateCert(dir, ips)
	if err != nil {
		t.Fatal(err)
	}

	if got := modeOf(t, dir); got != 0o700 {
		t.Errorf("state dir mode = %o, want 700", got)
	}
	for name, want := range map[string]os.FileMode{"api.token": 0o600, "tls.key": 0o600, "tls.crt": 0o644} {
		if got := modeOf(t, filepath.Join(dir, name)); got != want {
			t.Errorf("%s mode = %o, want %o", name, got, want)
		}
	}
	tokBytes, crtBytes, keyBytes := readFile(t, filepath.Join(dir, "api.token")), readFile(t, filepath.Join(dir, "tls.crt")), readFile(t, filepath.Join(dir, "tls.key"))

	// A second call, with other addresses, changes nothing.
	tok2, err := LoadOrCreateToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	cert2, fp2, err := LoadOrCreateCert(dir, []net.IP{net.ParseIP("10.9.8.7")})
	if err != nil {
		t.Fatal(err)
	}
	if tok2 != tok1 {
		t.Error("a second call returned another token")
	}
	if fp2 != fp1 || !bytes.Equal(cert2.Certificate[0], cert1.Certificate[0]) {
		t.Error("a second call returned another certificate")
	}
	if !bytes.Equal(tokBytes, readFile(t, filepath.Join(dir, "api.token"))) ||
		!bytes.Equal(crtBytes, readFile(t, filepath.Join(dir, "tls.crt"))) ||
		!bytes.Equal(keyBytes, readFile(t, filepath.Join(dir, "tls.key"))) {
		t.Error("a second call rewrote a file")
	}

	// What the certificate says.
	sum := sha256.Sum256(cert1.Certificate[0])
	if fp1 != hex.EncodeToString(sum[:]) || fp1 != strings.ToLower(fp1) || len(fp1) != 64 {
		t.Errorf("fingerprint %q is not the lowercase hex SHA-256 of the DER", fp1)
	}
	leaf, err := x509.ParseCertificate(cert1.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "tikray" {
		t.Errorf("CN = %q, want tikray", leaf.Subject.CommonName)
	}
	if got, want := strings.Join(leaf.DNSNames, ","), "tikray,localhost"; got != want {
		t.Errorf("DNS names = %q, want %q", got, want)
	}
	var gotIPs []string
	for _, ip := range leaf.IPAddresses {
		gotIPs = append(gotIPs, ip.String())
	}
	// Each address once; 0.0.0.0 and nil are no address to name.
	if got, want := strings.Join(gotIPs, ","), "172.31.255.2,127.0.0.1"; got != want {
		t.Errorf("IPs = %q, want %q", got, want)
	}
	if life := leaf.NotAfter.Sub(time.Now()); life < 10*365*24*time.Hour-time.Hour || life > 10*366*24*time.Hour {
		t.Errorf("the certificate expires in %v, want about 10 years", life)
	}
	if !leaf.NotBefore.Before(time.Now()) {
		t.Error("the certificate is not valid yet")
	}
	if leaf.IsCA {
		t.Error("the certificate is a CA")
	}
	key, ok := cert1.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		t.Errorf("the key is %T, want an ECDSA P-256 key", cert1.PrivateKey)
	}

	// Both files are PEM.
	for name, typ := range map[string]string{"tls.crt": "CERTIFICATE", "tls.key": "PRIVATE KEY"} {
		blk, _ := pem.Decode(readFile(t, filepath.Join(dir, name)))
		if blk == nil || blk.Type != typ {
			t.Errorf("%s is not a PEM %s block", name, typ)
		}
	}
}

func TestLocalhostIsAlwaysNamed(t *testing.T) {
	cert, _, err := LoadOrCreateCert(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IPs = %v, want 127.0.0.1 alone", leaf.IPAddresses)
	}
}

func TestCertMismatchIsAnError(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	if _, _, err := LoadOrCreateCert(a, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateCert(b, nil); err != nil {
		t.Fatal(err)
	}
	crt := readFile(t, filepath.Join(a, "tls.crt"))
	otherKey := readFile(t, filepath.Join(b, "tls.key"))
	if err := os.WriteFile(filepath.Join(a, "tls.key"), otherKey, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := LoadOrCreateCert(a, nil); err == nil || !strings.HasPrefix(err.Error(), "api: ") {
		t.Fatalf("a key that does not match the certificate gave %v, want an api: error", err)
	}
	// Nothing was regenerated.
	if !bytes.Equal(crt, readFile(t, filepath.Join(a, "tls.crt"))) || !bytes.Equal(otherKey, readFile(t, filepath.Join(a, "tls.key"))) {
		t.Error("the mismatch rewrote a file")
	}
}

// A certificate without its key may be pinned by a client already, so that
// making another would lock it out without a word: that is an error.
func TestCertWithoutItsKeyIsAnError(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := LoadOrCreateCert(dir, nil); err != nil {
		t.Fatal(err)
	}
	crt := readFile(t, filepath.Join(dir, "tls.crt"))
	if err := os.Remove(filepath.Join(dir, "tls.key")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateCert(dir, nil); err == nil || !strings.HasPrefix(err.Error(), "api: ") {
		t.Fatalf("got %v, want an api: error", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tls.key")); !os.IsNotExist(err) {
		t.Error("a key was made")
	}
	if !bytes.Equal(crt, readFile(t, filepath.Join(dir, "tls.crt"))) {
		t.Error("the certificate was rewritten")
	}
}

// A crash between the two writes of the first start leaves a key and no
// certificate. Nothing was ever served with that key, so a new pair is made.
func TestKeyWithoutACertificateIsMadeAgain(t *testing.T) {
	for name, key := range map[string]func(t *testing.T, dir string) []byte{
		"a key from an earlier start": func(t *testing.T, dir string) []byte {
			if _, _, err := LoadOrCreateCert(dir, nil); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, "tls.crt")); err != nil {
				t.Fatal(err)
			}
			return readFile(t, filepath.Join(dir, "tls.key"))
		},
		"a key that is garbage": func(t *testing.T, dir string) []byte {
			if err := os.WriteFile(filepath.Join(dir, "tls.key"), []byte("not pem\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return []byte("not pem\n")
		},
		"a key with a wider mode": func(t *testing.T, dir string) []byte {
			if err := os.WriteFile(filepath.Join(dir, "tls.key"), []byte("old"), 0o666); err != nil {
				t.Fatal(err)
			}
			return []byte("old")
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			old := key(t, dir)

			cert, fp, err := LoadOrCreateCert(dir, []net.IP{net.ParseIP("172.31.255.2")})
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(old, readFile(t, filepath.Join(dir, "tls.key"))) {
				t.Error("the old key was kept")
			}
			for file, want := range map[string]os.FileMode{"tls.crt": 0o644, "tls.key": 0o600} {
				if got := modeOf(t, filepath.Join(dir, file)); got != want {
					t.Errorf("%s mode = %o, want %o", file, got, want)
				}
			}
			// The pair is a pair, and the next start reuses it.
			again, fp2, err := LoadOrCreateCert(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			if fp2 != fp || !bytes.Equal(again.Certificate[0], cert.Certificate[0]) {
				t.Error("the next start made another certificate")
			}
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if got := leaf.IPAddresses[0].String(); got != "172.31.255.2" {
				t.Errorf("first IP = %s, want the one given", got)
			}
		})
	}
}

func TestCertThatIsNotPEMIsAnError(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"tls.crt", "tls.key"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not pem\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := LoadOrCreateCert(dir, nil); err == nil {
		t.Fatal("no error")
	}
	if got := readFile(t, filepath.Join(dir, "tls.crt")); string(got) != "not pem\n" {
		t.Error("the file was rewritten")
	}
}

func TestMalformedTokenIsAnError(t *testing.T) {
	for name, content := range map[string]string{
		"short":     "abc123\n",
		"upper":     strings.Repeat("A", 64),
		"not hex":   strings.Repeat("g", 64),
		"too long":  strings.Repeat("a", 65),
		"empty":     "",
		"two lines": strings.Repeat("a", 64) + "\n" + strings.Repeat("b", 64),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "api.token")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadOrCreateToken(dir)
			if err == nil || !strings.HasPrefix(err.Error(), "api: ") {
				t.Fatalf("got %v, want an api: error", err)
			}
			if content != "" && strings.Contains(err.Error(), content) {
				t.Error("the error quotes the token file")
			}
			if string(readFile(t, path)) != content {
				t.Error("the file was rewritten")
			}
		})
	}
}

func TestTokenWithNewlineIsRead(t *testing.T) {
	dir := t.TempDir()
	want := strings.Repeat("ab12", 16)
	if err := os.WriteFile(filepath.Join(dir, "api.token"), []byte(want+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOrCreateToken(dir)
	if err != nil || got != want {
		t.Errorf("got %q, %v; want the token without its newline", got, err)
	}
}

func TestTokensDiffer(t *testing.T) {
	a, err := LoadOrCreateToken(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateToken(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two new tokens are equal")
	}
}
