package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/atomicfile"
)

// The files in the state directory.
const (
	tokenFile = "api.token"
	certFile  = "tls.crt"
	keyFile   = "tls.key"
)

// certLife is how long the certificate is valid. Clients pin its fingerprint,
// so that the date matters to nobody but a client that checks it.
const certLife = 10 // years

// tokenForm is what a token looks like: 32 random bytes in lowercase hex.
var tokenForm = regexp.MustCompile(`^[0-9a-f]{64}$`)

// LoadOrCreateToken returns the API token in dir/api.token. When the file is
// missing it makes a token of 32 random bytes, as 64 lowercase hex characters,
// and writes it (mode 0600, in dir, which is made with mode 0700 if it is
// missing). A file that holds anything else is an error: it is never replaced
// with another token, which would lock out every client that has the old one.
// A newline at the end of the file is no part of the token.
func LoadOrCreateToken(dir string) (string, error) {
	path := filepath.Join(dir, tokenFile)
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		tok := strings.TrimSpace(string(b))
		if !tokenForm.MatchString(tok) {
			// The error names the file and not its content.
			return "", fmt.Errorf("api: %s does not hold a token of 64 lowercase hex characters", path)
		}
		return tok, nil
	case !errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("api: reading the token: %w", err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("api: %w", err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("api: making a token: %w", err)
	}
	tok := hex.EncodeToString(raw)
	if err := atomicfile.WriteFile(path, []byte(tok), 0o600); err != nil {
		return "", fmt.Errorf("api: writing the token: %w", err)
	}
	return tok, nil
}

// LoadOrCreateCert returns the TLS certificate in dir/tls.crt and dir/tls.key
// and the SHA-256 fingerprint of its DER, as lowercase hex, which a client
// pins. When both files are missing it makes a self-signed ECDSA P-256
// certificate, valid for 10 years, with the common name tikray and the names
// tikray and localhost, and the addresses ips and 127.0.0.1 (an address that
// is nil or unspecified is left out), and writes the certificate (mode 0644)
// and the key (mode 0600), in dir, which is made with mode 0700 if it is
// missing.
//
// Files that exist are used as they are, with the addresses they have: ips
// counts only for a new certificate. A certificate without its key, or a key
// that is not the certificate's, is an error and never a new certificate: a
// client may have pinned the old one, and would not connect, and the person
// should know why. A key without a certificate is not: the certificate is
// written after the key, so that it is what a crash on the first start leaves,
// and nothing was ever served with that key; a new pair replaces it.
func LoadOrCreateCert(dir string, ips []net.IP) (tls.Certificate, string, error) {
	crtPath, keyPath := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
	crtPEM, crtErr := os.ReadFile(crtPath)
	switch {
	case errors.Is(crtErr, fs.ErrNotExist):
		return createCert(dir, ips)
	case crtErr != nil:
		return tls.Certificate{}, "", fmt.Errorf("api: reading the certificate: %w", crtErr)
	}
	keyPEM, keyErr := os.ReadFile(keyPath)
	switch {
	case errors.Is(keyErr, fs.ErrNotExist):
		return tls.Certificate{}, "", fmt.Errorf("api: %s has no %s beside it in %s; restore the key, or remove the certificate to make a new pair (clients that pinned this one must pin the new one)", certFile, keyFile, dir)
	case keyErr != nil:
		return tls.Certificate{}, "", fmt.Errorf("api: reading the key: %w", keyErr)
	}
	cert, err := tls.X509KeyPair(crtPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("api: %s and %s in %s are not a certificate and its key: %w", certFile, keyFile, dir, err)
	}
	return cert, fingerprint(cert), nil
}

// createCert makes the certificate and writes it and its key.
func createCert(dir string, ips []net.IP) (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("api: making a key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("api: making a serial number: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "tikray"},
		// An hour back, so that a client whose clock is a little behind
		// still takes it.
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(certLife, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"tikray", "localhost"},
		IPAddresses:           certIPs(ips),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("api: making a certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("api: encoding the key: %w", err)
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(crtPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("api: %w", err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("api: %w", err)
	}
	crtPath, keyPath := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
	if err := atomicfile.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("api: writing the key: %w", err)
	}
	// The key goes first: a crash between the two leaves a key and no
	// certificate, which LoadOrCreateCert makes a new pair of.
	if err := atomicfile.WriteFile(crtPath, crtPEM, 0o644); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("api: writing the certificate: %w", err)
	}
	return cert, fingerprint(cert), nil
}

// certIPs is ips and 127.0.0.1, each once, without an address that is no
// address to connect to.
func certIPs(ips []net.IP) []net.IP {
	var out []net.IP
	seen := map[string]bool{}
	for _, ip := range append(append([]net.IP(nil), ips...), net.IPv4(127, 0, 0, 1)) {
		if ip.To16() == nil || ip.IsUnspecified() || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip)
	}
	return out
}

// fingerprint is the SHA-256 of the certificate's DER, as lowercase hex.
func fingerprint(c tls.Certificate) string {
	sum := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(sum[:])
}
