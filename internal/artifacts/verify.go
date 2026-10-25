package artifacts

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Arman2122/tikray/internal/xrayver"
)

const (
	// dgstMaxBytes caps a .dgst, which is a few hundred bytes upstream.
	dgstMaxBytes = 64 << 10
	// indexMaxBytes caps the hash index and its signature, each.
	indexMaxBytes = 8 << 20
	// indexTimeout bounds one request when Verifier.HTTP is nil.
	indexTimeout = 30 * time.Second
)

// ErrNoHash means no source of trust knows the SHA-256 of the file.
var ErrNoHash = errors.New("no known SHA-256 for the file")

// ParseDgst returns the lowercase hex SHA-256 from a .dgst file, which holds a
// "SHA2-256= <hex>" or "SHA256= <hex>" line among the other digests.
func ParseDgst(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch strings.ToUpper(strings.TrimSpace(key)) {
		case "SHA2-256", "SHA256":
		default:
			continue
		}
		val = strings.ToLower(strings.TrimSpace(val))
		if !isSHA256Hex(val) {
			return "", fmt.Errorf("dgst: SHA-256 value %.70q is not 64 hex characters", val)
		}
		return val, nil
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("dgst: %w", err)
	}
	return "", errors.New("dgst: no SHA2-256 or SHA256 line")
}

// isSHA256Hex reports whether s is 64 lowercase hex characters.
func isSHA256Hex(s string) bool {
	if len(s) != 2*sha256.Size || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// FileSHA256 returns the lowercase hex SHA-256 of the file at path.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Index is the signed hash index tikray's CI publishes.
type Index struct {
	Version int                          `json:"version"`
	Files   map[string]map[string]string `json:"files"` // tag -> file -> sha256
}

// VerifyIndex checks sigB64, the base64 of an ASN.1 ECDSA signature over the
// SHA-256 of data, against pubPEM, a PKIX ECDSA P-256 public key. Only a
// correctly signed index of version 1 is returned.
func VerifyIndex(data, sigB64 []byte, pubPEM []byte) (*Index, error) {
	block, _ := pem.Decode(pubPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("hash index key: want a PEM block of type PUBLIC KEY")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("hash index key: %w", err)
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("hash index key: want an ECDSA P-256 key")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil {
		return nil, fmt.Errorf("hash index signature: %w", err)
	}
	sum := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return nil, errors.New("hash index signature does not match")
	}
	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("hash index: %w", err)
	}
	if idx.Version != 1 {
		return nil, fmt.Errorf("hash index: unsupported version %d", idx.Version)
	}
	return &idx, nil
}

// Lookup returns the lowercase hex SHA-256 the index lists for file in release
// v. An entry that is not a SHA-256 counts as absent.
func (x *Index) Lookup(v xrayver.Version, file string) (string, bool) {
	if x == nil {
		return "", false
	}
	h := strings.ToLower(x.Files[v.Tag()][file])
	if !isSHA256Hex(h) {
		return "", false
	}
	return h, true
}

// Verifier finds the SHA-256 a release file must have.
type Verifier struct {
	Upstream  Chain        // direct and proxy only: where upstream's .dgst files come from
	IndexURLs []string     // hash index locations, tried in order; each has a ".sig" beside it
	IndexPub  []byte       // PKIX PEM ECDSA P-256 key the index is signed with
	HTTP      *http.Client // for the index; nil means a client with a 30 s timeout
}

// Verified is a known hash and where it came from.
type Verified struct {
	SHA256 string
	Method string // "dgst", "index", or "unverified" when SHA256 is empty
}

// Expected returns the SHA-256 for r.File. It takes upstream's .dgst through
// Upstream, wherever the file itself came from; a .dgst that does not parse
// counts as a failed attempt. Only when every upstream attempt fails does it
// ask the signed index. When neither knows the file it returns
// Verified{Method: "unverified"} and an error wrapping ErrNoHash, and the
// caller decides whether the file may be used unverified. A canceled ctx gives
// ctx's error instead.
func (v Verifier) Expected(ctx context.Context, r Request) (Verified, error) {
	var why []string
	if len(v.Upstream.Sources) > 0 {
		h, err := v.fromDgst(ctx, r)
		if err == nil {
			return Verified{SHA256: h, Method: "dgst"}, nil
		}
		why = append(why, err.Error())
	}
	if err := ctx.Err(); err != nil {
		return Verified{}, fmt.Errorf("verify %s: %w", r.File, err)
	}
	if len(v.IndexURLs) > 0 && len(v.IndexPub) > 0 {
		h, err := v.fromIndex(ctx, r)
		if err == nil {
			return Verified{SHA256: h, Method: "index"}, nil
		}
		why = append(why, err.Error())
	}
	if err := ctx.Err(); err != nil {
		return Verified{}, fmt.Errorf("verify %s: %w", r.File, err)
	}
	if len(why) == 0 {
		why = append(why, "no upstream source or hash index configured")
	}
	return Verified{Method: "unverified"}, fmt.Errorf("%w %s: %s", ErrNoHash, r.File, strings.Join(why, "; "))
}

// fromDgst fetches and parses <file>.dgst through the upstream chain, in a
// private directory that is removed afterwards.
func (v Verifier) fromDgst(ctx context.Context, r Request) (string, error) {
	dir, err := os.MkdirTemp("", "tikray-dgst-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	chain := v.Upstream // a copy; the cap changes only here
	if chain.MaxBytes <= 0 || chain.MaxBytes > dgstMaxBytes {
		chain.MaxBytes = dgstMaxBytes
	}
	dgst := r
	dgst.File = r.File + ".dgst"
	var hash string
	_, err = chain.Fetch(ctx, dgst, filepath.Join(dir, "file.dgst"), func(path string) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		h, err := ParseDgst(f)
		if err != nil {
			return err
		}
		hash = h
		return nil
	})
	if err != nil {
		return "", err
	}
	return hash, nil
}

// fromIndex asks each index URL in turn; the first signed index that lists the
// file wins.
func (v Verifier) fromIndex(ctx context.Context, r Request) (string, error) {
	hc := v.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: indexTimeout}
	}
	var failed []string
	for _, u := range v.IndexURLs {
		h, err := lookupIndex(ctx, hc, u, v.IndexPub, r)
		if err == nil {
			return h, nil
		}
		failed = append(failed, "hash index "+u+": "+err.Error())
		if ctx.Err() != nil {
			break
		}
	}
	return "", errors.New(strings.Join(failed, "; "))
}

func lookupIndex(ctx context.Context, hc *http.Client, rawURL string, pub []byte, r Request) (string, error) {
	data, err := getBytes(ctx, hc, rawURL, indexMaxBytes)
	if err != nil {
		return "", err
	}
	sig, err := getBytes(ctx, hc, rawURL+".sig", indexMaxBytes)
	if err != nil {
		return "", err
	}
	idx, err := VerifyIndex(data, sig, pub)
	if err != nil {
		return "", err
	}
	h, ok := idx.Lookup(r.Version, r.File)
	if !ok {
		return "", fmt.Errorf("lists no SHA-256 for %s %s", r.Version.Tag(), r.File)
	}
	return h, nil
}

// getBytes returns the body of a 2xx answer of at most max bytes.
func getBytes(ctx context.Context, hc *http.Client, rawURL string, max int64) ([]byte, error) {
	var buf bytes.Buffer
	cw := &capWriter{w: &buf, left: max}
	err := get(ctx, hc, rawURL, cw)
	if cw.over {
		return nil, fmt.Errorf("answer is larger than %d bytes", max)
	}
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
