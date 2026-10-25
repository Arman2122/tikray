package artifacts

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Arman2122/tikray/internal/xrayver"
)

var (
	hashA = strings.Repeat("a1", 32) // what upstream's .dgst says
	hashB = strings.Repeat("b2", 32) // what the hash index says
)

const htmlPage = "<html><body>This site is blocked.</body></html>"

// dgstBody is a .dgst as XTLS publishes it: four lines, SHA2-256 third.
func dgstBody(sha256hex string) string {
	return "MD5= " + strings.Repeat("0f", 16) + "\n" +
		"SHA1= " + strings.Repeat("1e", 20) + "\n" +
		"SHA2-256= " + sha256hex + "\n" +
		"SHA2-512= " + strings.Repeat("2d", 64) + "\n"
}

func TestParseDgst(t *testing.T) {
	good := []struct {
		name, in, want string
	}{
		{"SHA2-256 form", dgstBody(hashA), hashA},
		{"SHA256 form", "MD5= " + strings.Repeat("0f", 16) + "\nSHA256= " + hashA + "\nSHA2-512= " + strings.Repeat("2d", 64) + "\n", hashA},
		{"no space after =", "SHA256=" + hashA, hashA},
		{"tabs and spaces after =", "SHA2-256=\t  " + hashA + "  \n", hashA},
		{"CRLF", "MD5= " + strings.Repeat("0f", 16) + "\r\nSHA2-256= " + hashA + "\r\n", hashA},
		{"uppercase hex", "SHA2-256= " + strings.ToUpper(hashA) + "\n", hashA},
		{"SHA2-512 first", "SHA2-512= " + strings.Repeat("2d", 64) + "\nSHA2-256= " + hashA + "\n", hashA},
	}
	for _, tc := range good {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDgst(strings.NewReader(tc.in))
			if err != nil {
				t.Fatalf("ParseDgst: %v", err)
			}
			if got != tc.want {
				t.Errorf("ParseDgst = %q, want %q", got, tc.want)
			}
		})
	}

	bad := []struct {
		name, in string
	}{
		{"empty", ""},
		{"HTML page", htmlPage},
		{"garbage", "\x00\x01 not a digest file at all"},
		{"only other hashes", "MD5= " + strings.Repeat("0f", 16) + "\nSHA2-512= " + strings.Repeat("2d", 64) + "\n"},
		{"SHA2-512 is not SHA2-256", "SHA2-512= " + hashA + "\n"},
		{"no equals sign", "SHA2-256 " + hashA + "\n"},
		{"too short", "SHA2-256= " + hashA[:63] + "\n"},
		{"too long", "SHA2-256= " + hashA + "0\n"},
		{"not hex", "SHA2-256= " + strings.Repeat("g", 64) + "\n"},
		{"empty value", "SHA2-256=\n"},
	}
	for _, tc := range bad {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			if got, err := ParseDgst(strings.NewReader(tc.in)); err == nil {
				t.Errorf("ParseDgst = %q, want an error", got)
			}
		})
	}
}

func TestFileSHA256(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := FileSHA256(p)
	if err != nil {
		t.Fatal(err)
	}
	if want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Errorf("FileSHA256 = %q, want %q", got, want)
	}
	if _, err := FileSHA256(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("FileSHA256 of a missing file succeeded")
	}
}

func newKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pubPEM(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// sign returns the base64 ASN.1 ECDSA signature over SHA-256 of data.
func sign(t *testing.T, k *ecdsa.PrivateKey, data []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return []byte(base64.StdEncoding.EncodeToString(sig))
}

func ed25519Pub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func indexData(t *testing.T, version int, files map[string]map[string]string) []byte {
	t.Helper()
	b, err := json.Marshal(Index{Version: version, Files: files})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// testIndex maps testReq to hash.
func testIndex(t *testing.T, hash string) []byte {
	t.Helper()
	return indexData(t, 1, map[string]map[string]string{
		testReq.Version.Tag(): {testReq.File: hash},
	})
}

func TestVerifyIndex(t *testing.T) {
	key := newKey(t, elliptic.P256())
	pub := pubPEM(t, key)
	data := testIndex(t, hashB)
	sig := sign(t, key, data)

	t.Run("good signature", func(t *testing.T) {
		idx, err := VerifyIndex(data, sig, pub)
		if err != nil {
			t.Fatalf("VerifyIndex: %v", err)
		}
		if h, ok := idx.Lookup(testReq.Version, testReq.File); !ok || h != hashB {
			t.Errorf("Lookup = %q, %v; want %q, true", h, ok, hashB)
		}
	})
	t.Run("surrounding whitespace around the signature", func(t *testing.T) {
		if _, err := VerifyIndex(data, append(append([]byte("\n "), sig...), " \r\n"...), pub); err != nil {
			t.Errorf("VerifyIndex: %v", err)
		}
	})
	t.Run("one flipped byte in data", func(t *testing.T) {
		bad := append([]byte(nil), data...)
		bad[len(bad)/2] ^= 0x01
		if idx, err := VerifyIndex(bad, sig, pub); err == nil {
			t.Errorf("VerifyIndex accepted tampered data: %+v", idx)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		other := pubPEM(t, newKey(t, elliptic.P256()))
		if _, err := VerifyIndex(data, sig, other); err == nil {
			t.Error("VerifyIndex accepted a signature from another key")
		}
	})
	t.Run("signature of other data", func(t *testing.T) {
		if _, err := VerifyIndex(data, sign(t, key, []byte("other")), pub); err == nil {
			t.Error("VerifyIndex accepted a signature over other data")
		}
	})
	t.Run("signature is not base64", func(t *testing.T) {
		if _, err := VerifyIndex(data, []byte("!!! not base64 !!!"), pub); err == nil {
			t.Error("VerifyIndex accepted a signature that is not base64")
		}
	})
	t.Run("signature is not ASN.1", func(t *testing.T) {
		raw := base64.StdEncoding.EncodeToString([]byte("not an asn.1 signature"))
		if _, err := VerifyIndex(data, []byte(raw), pub); err == nil {
			t.Error("VerifyIndex accepted a malformed signature")
		}
	})
	t.Run("empty signature", func(t *testing.T) {
		if _, err := VerifyIndex(data, nil, pub); err == nil {
			t.Error("VerifyIndex accepted an empty signature")
		}
	})
	t.Run("no PEM block", func(t *testing.T) {
		if _, err := VerifyIndex(data, sig, []byte("not pem")); err == nil {
			t.Error("VerifyIndex accepted a key that is not PEM")
		}
	})
	t.Run("wrong PEM type", func(t *testing.T) {
		wrong := strings.NewReplacer("PUBLIC KEY", "CERTIFICATE").Replace(string(pub))
		if _, err := VerifyIndex(data, sig, []byte(wrong)); err == nil {
			t.Error("VerifyIndex accepted a PEM block of the wrong type")
		}
	})
	t.Run("not an ECDSA key", func(t *testing.T) {
		// A valid PKIX block, but of an Ed25519 key.
		der, err := x509.MarshalPKIXPublicKey(ed25519Pub(t))
		if err != nil {
			t.Fatal(err)
		}
		p := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		if _, err := VerifyIndex(data, sig, p); err == nil {
			t.Error("VerifyIndex accepted an Ed25519 key")
		}
	})
	t.Run("ECDSA on another curve", func(t *testing.T) {
		k384 := newKey(t, elliptic.P384())
		if _, err := VerifyIndex(data, sign(t, k384, data), pubPEM(t, k384)); err == nil {
			t.Error("VerifyIndex accepted a P-384 key")
		}
	})
	t.Run("unsupported index version", func(t *testing.T) {
		v2 := indexData(t, 2, map[string]map[string]string{"v26.10.21": {testReq.File: hashB}})
		if _, err := VerifyIndex(v2, sign(t, key, v2), pub); err == nil {
			t.Error("VerifyIndex accepted index version 2")
		}
		v0 := []byte(`{"files":{}}`)
		if _, err := VerifyIndex(v0, sign(t, key, v0), pub); err == nil {
			t.Error("VerifyIndex accepted an index without a version")
		}
	})
	t.Run("signed but not JSON", func(t *testing.T) {
		junk := []byte("<html>signed junk</html>")
		if _, err := VerifyIndex(junk, sign(t, key, junk), pub); err == nil {
			t.Error("VerifyIndex accepted data that is not JSON")
		}
	})
}

func TestIndexLookup(t *testing.T) {
	idx := &Index{Version: 1, Files: map[string]map[string]string{
		"v26.10.21": {
			"Xray-linux-64.zip":         hashB,
			"Xray-linux-arm64-v8a.zip":  strings.ToUpper(hashA),
			"Xray-linux-32.zip":         "not a hash",
			"Xray-linux-riscv64.zip":    hashA[:63],
			"Xray-linux-mips64.zip":     "",
			"Xray-linux-mips64le.zip":   strings.Repeat("zz", 32),
			"Xray-linux-loong64.zip.x":  hashA,
			"Xray-linux-s390x.zip.dgst": hashA,
		},
	}}
	v := xrayver.Version{Major: 26, Minor: 10, Patch: 21}
	if h, ok := idx.Lookup(v, "Xray-linux-64.zip"); !ok || h != hashB {
		t.Errorf("Lookup = %q, %v; want %q, true", h, ok, hashB)
	}
	if h, ok := idx.Lookup(v, "Xray-linux-arm64-v8a.zip"); !ok || h != hashA {
		t.Errorf("Lookup of an uppercase hash = %q, %v; want %q, true", h, ok, hashA)
	}
	for _, file := range []string{"Xray-linux-32.zip", "Xray-linux-riscv64.zip", "Xray-linux-mips64.zip", "Xray-linux-mips64le.zip", "missing.zip"} {
		if h, ok := idx.Lookup(v, file); ok {
			t.Errorf("Lookup(%q) = %q, true; want a miss", file, h)
		}
	}
	if h, ok := idx.Lookup(xrayver.Version{Major: 26, Minor: 10, Patch: 22}, "Xray-linux-64.zip"); ok {
		t.Errorf("Lookup of another release = %q, true; want a miss", h)
	}
	var nilIdx *Index
	if _, ok := nilIdx.Lookup(v, "Xray-linux-64.zip"); ok {
		t.Error("Lookup on a nil Index hit")
	}
}

// indexServer serves data at /index.json and sig at /index.json.sig and counts requests.
func indexServer(t *testing.T, data, sig []byte) (srv *httptest.Server, hits *atomic.Int32) {
	t.Helper()
	hits = new(atomic.Int32)
	srv = serve(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/index.json":
			w.Write(data)
		case "/index.json.sig":
			w.Write(sig)
		default:
			http.NotFound(w, r)
		}
	})
	return srv, hits
}

// dgstServer serves body for the .dgst of testReq; any other path fails the test.
func dgstServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return serve(t, func(w http.ResponseWriter, r *http.Request) {
		if want := "/releases/download/v26.10.21/Xray-linux-64.zip.dgst"; r.URL.Path != want {
			t.Errorf("upstream path %q, want %q", r.URL.Path, want)
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, body)
	})
}

func upstreamOf(srvs ...*httptest.Server) Chain {
	var c Chain
	for _, s := range srvs {
		c.Sources = append(c.Sources, Direct(s.URL, s.Client()))
	}
	return c
}

func wantVerified(t *testing.T, got Verified, err error, sha, method string) {
	t.Helper()
	if err != nil {
		t.Fatalf("Expected: %v", err)
	}
	if got.SHA256 != sha || got.Method != method {
		t.Errorf("Expected = %+v, want SHA256 %q Method %q", got, sha, method)
	}
}

func wantNoHash(t *testing.T, got Verified, err error) {
	t.Helper()
	if !errors.Is(err, ErrNoHash) {
		t.Fatalf("Expected error = %v, want ErrNoHash", err)
	}
	if got.Method != "unverified" || got.SHA256 != "" {
		t.Errorf("Expected = %+v, want Method unverified and no hash", got)
	}
}

func TestExpectedPrefersDgst(t *testing.T) {
	key := newKey(t, elliptic.P256())
	idxSrv, idxHits := indexServer(t, testIndex(t, hashB), sign(t, key, testIndex(t, hashB)))
	v := Verifier{
		Upstream:  upstreamOf(dgstServer(t, dgstBody(hashA))),
		IndexURLs: []string{idxSrv.URL + "/index.json"},
		IndexPub:  pubPEM(t, key),
	}
	got, err := v.Expected(context.Background(), testReq)
	wantVerified(t, got, err, hashA, "dgst")
	if n := idxHits.Load(); n != 0 {
		t.Errorf("the index was fetched %d times although the .dgst worked", n)
	}
}

func TestExpectedFallsBackToIndex(t *testing.T) {
	key := newKey(t, elliptic.P256())
	data := testIndex(t, hashB)
	idxSrv, _ := indexServer(t, data, sign(t, key, data))
	down := serve(t, status(http.StatusServiceUnavailable))
	v := Verifier{
		Upstream:  upstreamOf(down, down),
		IndexURLs: []string{idxSrv.URL + "/index.json"},
		IndexPub:  pubPEM(t, key),
	}
	got, err := v.Expected(context.Background(), testReq)
	wantVerified(t, got, err, hashB, "index")
}

func TestExpectedNoHash(t *testing.T) {
	t.Run("nothing configured", func(t *testing.T) {
		got, err := Verifier{}.Expected(context.Background(), testReq)
		wantNoHash(t, got, err)
	})

	key := newKey(t, elliptic.P256())
	pub := pubPEM(t, key)
	down := serve(t, status(http.StatusServiceUnavailable))

	t.Run("upstream down, no index", func(t *testing.T) {
		got, err := Verifier{Upstream: upstreamOf(down)}.Expected(context.Background(), testReq)
		wantNoHash(t, got, err)
	})
	t.Run("index without a public key", func(t *testing.T) {
		data := testIndex(t, hashB)
		srv, hits := indexServer(t, data, sign(t, key, data))
		got, err := Verifier{Upstream: upstreamOf(down), IndexURLs: []string{srv.URL + "/index.json"}}.Expected(context.Background(), testReq)
		wantNoHash(t, got, err)
		if n := hits.Load(); n != 0 {
			t.Errorf("the index was fetched %d times without a key to check it", n)
		}
	})
	t.Run("index lacks the file", func(t *testing.T) {
		data := indexData(t, 1, map[string]map[string]string{"v26.10.21": {"Other.zip": hashB}})
		srv, _ := indexServer(t, data, sign(t, key, data))
		got, err := Verifier{Upstream: upstreamOf(down), IndexURLs: []string{srv.URL + "/index.json"}, IndexPub: pub}.Expected(context.Background(), testReq)
		wantNoHash(t, got, err)
	})
	t.Run("index signed by another key", func(t *testing.T) {
		data := testIndex(t, hashB)
		srv, _ := indexServer(t, data, sign(t, newKey(t, elliptic.P256()), data))
		got, err := Verifier{Upstream: upstreamOf(down), IndexURLs: []string{srv.URL + "/index.json"}, IndexPub: pub}.Expected(context.Background(), testReq)
		wantNoHash(t, got, err)
	})
	t.Run("index tampered with", func(t *testing.T) {
		data := testIndex(t, hashB)
		sig := sign(t, key, data)
		forged := testIndex(t, hashA)
		srv, _ := indexServer(t, forged, sig)
		got, err := Verifier{Upstream: upstreamOf(down), IndexURLs: []string{srv.URL + "/index.json"}, IndexPub: pub}.Expected(context.Background(), testReq)
		wantNoHash(t, got, err)
	})
	t.Run("signature missing", func(t *testing.T) {
		srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/index.json" {
				w.Write(testIndex(t, hashB))
				return
			}
			http.NotFound(w, r)
		})
		got, err := Verifier{Upstream: upstreamOf(down), IndexURLs: []string{srv.URL + "/index.json"}, IndexPub: pub}.Expected(context.Background(), testReq)
		wantNoHash(t, got, err)
	})
	t.Run("index larger than the cap", func(t *testing.T) {
		big := serve(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write(make([]byte, indexMaxBytes+1))
		})
		got, err := Verifier{Upstream: upstreamOf(down), IndexURLs: []string{big.URL + "/index.json"}, IndexPub: pub}.Expected(context.Background(), testReq)
		wantNoHash(t, got, err)
	})
}

func TestExpectedIndexURLsInOrder(t *testing.T) {
	key := newKey(t, elliptic.P256())
	pub := pubPEM(t, key)
	down := serve(t, status(http.StatusServiceUnavailable))
	badSig, _ := indexServer(t, testIndex(t, hashA), sign(t, newKey(t, elliptic.P256()), testIndex(t, hashA)))
	noEntry := indexData(t, 1, map[string]map[string]string{"v26.10.21": {"Other.zip": hashA}})
	lacking, _ := indexServer(t, noEntry, sign(t, key, noEntry))
	good, goodHits := indexServer(t, testIndex(t, hashB), sign(t, key, testIndex(t, hashB)))
	spare, spareHits := indexServer(t, testIndex(t, hashA), sign(t, key, testIndex(t, hashA)))

	v := Verifier{
		Upstream: upstreamOf(down),
		IndexURLs: []string{
			down.URL + "/index.json",
			badSig.URL + "/index.json",
			lacking.URL + "/index.json",
			good.URL + "/index.json",
			spare.URL + "/index.json",
		},
		IndexPub: pub,
	}
	got, err := v.Expected(context.Background(), testReq)
	wantVerified(t, got, err, hashB, "index")
	if goodHits.Load() == 0 {
		t.Error("the working index was never fetched")
	}
	if n := spareHits.Load(); n != 0 {
		t.Errorf("a later index was fetched %d times after one had already answered", n)
	}
}

func TestExpectedSignatureUrlIsIndexUrlPlusSig(t *testing.T) {
	key := newKey(t, elliptic.P256())
	data := testIndex(t, hashB)
	var paths []string
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		switch r.URL.RequestURI() {
		case "/dir/hashes.json?v=1":
			w.Write(data)
		case "/dir/hashes.json?v=1.sig":
			w.Write(sign(t, key, data))
		default:
			http.NotFound(w, r)
		}
	})
	v := Verifier{IndexURLs: []string{srv.URL + "/dir/hashes.json?v=1"}, IndexPub: pubPEM(t, key), HTTP: srv.Client()}
	got, err := v.Expected(context.Background(), testReq)
	wantVerified(t, got, err, hashB, "index")
	if len(paths) != 2 {
		t.Errorf("requests = %v, want the index and its .sig", paths)
	}
}

// A .dgst that downloads but does not parse is a failed attempt: the chain goes
// on to the next upstream source, and only when all fail does the index count.
func TestExpectedUnparseableDgstMovesOn(t *testing.T) {
	html := dgstServer(t, htmlPage)
	real := dgstServer(t, dgstBody(hashA))

	key := newKey(t, elliptic.P256())
	data := testIndex(t, hashB)
	idxSrv, _ := indexServer(t, data, sign(t, key, data))
	idxURLs, idxPub := []string{idxSrv.URL + "/index.json"}, pubPEM(t, key)

	t.Run("second upstream source has the real .dgst", func(t *testing.T) {
		v := Verifier{Upstream: upstreamOf(html, real), IndexURLs: idxURLs, IndexPub: idxPub}
		got, err := v.Expected(context.Background(), testReq)
		wantVerified(t, got, err, hashA, "dgst")
	})
	t.Run("every upstream source serves HTML", func(t *testing.T) {
		v := Verifier{Upstream: upstreamOf(html, html), IndexURLs: idxURLs, IndexPub: idxPub}
		got, err := v.Expected(context.Background(), testReq)
		wantVerified(t, got, err, hashB, "index")
	})
	t.Run("every upstream source serves HTML and no index", func(t *testing.T) {
		got, err := Verifier{Upstream: upstreamOf(html, html)}.Expected(context.Background(), testReq)
		wantNoHash(t, got, err)
	})
}

func TestExpectedDgstSizeCapAndCleanup(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	// A .dgst past 64 KiB is refused even though a larger MaxBytes is allowed.
	huge := dgstServer(t, dgstBody(hashA)+strings.Repeat("# padding\n", 7000))
	real := dgstServer(t, dgstBody(hashB))
	up := upstreamOf(huge, real)
	up.MaxBytes = 1 << 30
	got, err := Verifier{Upstream: up}.Expected(context.Background(), testReq)
	wantVerified(t, got, err, hashB, "dgst")

	// The caller's chain is not changed by the lowered cap.
	if up.MaxBytes != 1<<30 {
		t.Errorf("Upstream.MaxBytes = %d after Expected, want it untouched", up.MaxBytes)
	}

	// With the default MaxBytes a small .dgst still works.
	got, err = Verifier{Upstream: upstreamOf(real)}.Expected(context.Background(), testReq)
	wantVerified(t, got, err, hashB, "dgst")

	// Failure leaves nothing behind either.
	_, err = Verifier{Upstream: upstreamOf(huge)}.Expected(context.Background(), testReq)
	wantNoHash(t, Verified{Method: "unverified"}, err)

	if left := dirNames(t, tmp); len(left) != 0 {
		t.Errorf("temp directory still holds %v", left)
	}
}

func TestExpectedCanceledContext(t *testing.T) {
	key := newKey(t, elliptic.P256())
	data := testIndex(t, hashB)
	idxSrv, idxHits := indexServer(t, data, sign(t, key, data))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v := Verifier{
		Upstream:  upstreamOf(dgstServer(t, dgstBody(hashA))),
		IndexURLs: []string{idxSrv.URL + "/index.json"},
		IndexPub:  pubPEM(t, key),
	}
	got, err := v.Expected(ctx, testReq)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Expected error = %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrNoHash) {
		t.Error("a canceled lookup must not look like a file without a known hash")
	}
	if got.SHA256 != "" {
		t.Errorf("Expected returned hash %q on cancellation", got.SHA256)
	}
	if n := idxHits.Load(); n != 0 {
		t.Errorf("the index was fetched %d times after cancellation", n)
	}
}
