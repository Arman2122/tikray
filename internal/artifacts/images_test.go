package artifacts

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testImage(t *testing.T, component, arch, version string) []byte {
	t.Helper()
	name := "tikray"
	entry := "/usr/local/bin/tikray"
	var cmd []string
	if component == "runner" {
		name, entry = "tikray-runner", "/tikray-runner"
	} else {
		cmd = []string{"serve"}
	}
	conf, _ := json.Marshal(map[string]any{"os": "linux", "architecture": arch, "config": map[string]any{"Entrypoint": []string{entry}, "Cmd": cmd, "Labels": map[string]string{"org.opencontainers.image.version": version}}})
	configPath := fmt.Sprintf("blobs/sha256/%x", sha256.Sum256(conf))
	layer := bytes.Repeat([]byte{0x00, 0xff, 0x41}, 20000)
	layerPath := fmt.Sprintf("blobs/sha256/%x", sha256.Sum256(layer))
	manifest, _ := json.Marshal([]map[string]any{{"Config": configPath, "RepoTags": []string{"tikray/" + name + ":" + arch}, "Layers": []string{layerPath}}})
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, f := range []struct {
		name string
		b    []byte
	}{{"manifest.json", manifest}, {configPath, conf}, {layerPath, layer}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(f.b))}); err != nil {
			t.Fatal("archive fixture")
		}
		if _, err := tw.Write(f.b); err != nil {
			t.Fatal("archive fixture")
		}
	}
	if tw.Close() != nil {
		t.Fatal("archive fixture")
	}
	return b.Bytes()
}

func signImageFixture(t *testing.T, key *ecdsa.PrivateKey, b []byte) string {
	t.Helper()
	h := sha256.Sum256(b)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal("cannot sign fixture")
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func seedImageTrust(t *testing.T) (*CoreUpdater, *ecdsa.PrivateKey) {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if os.Mkdir(state, 0700) != nil {
		t.Fatal("stage trust")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("key fixture")
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	ref := ImageRef{Component: "tikray", Digest: strings.Repeat("1", 64), Chain: strings.Repeat("2", 128), ImageID: strings.Repeat("3", 64), Size: 8192}
	boot := ImageBootstrap{Version: 1, Arch: "amd64", Publisher: base64.StdEncoding.EncodeToString(der), Tikray: ref, Runner: ref}
	boot.Runner.Component = "runner"
	b, _ := json.Marshal(boot)
	if os.WriteFile(filepath.Join(state, "image-bootstrap.json"), b, 0600) != nil {
		t.Fatal("cannot write bootstrap")
	}
	return &CoreUpdater{Data: root, Arch: "amd64"}, key
}

func putInboxImage(t *testing.T, u *CoreUpdater, component, version string, b []byte, sig string) string {
	t.Helper()
	dir := filepath.Join(u.Data, "inbox", "images", version)
	name := "tikray"
	if component == "runner" {
		name = "tikray-runner"
	}
	p := filepath.Join(dir, name+"-"+u.Arch+".tar")
	if os.MkdirAll(dir, 0700) != nil || os.WriteFile(p, b, 0600) != nil || os.WriteFile(p+".sig", []byte(sig), 0600) != nil {
		t.Fatal("cannot stage inbox fixture")
	}
	return p
}

func TestImageRejectsWrongSignatureArchAndPath(t *testing.T) {
	for _, tc := range []string{"valid", "wrong key", "wrong architecture", "wrong role", "wrong signed version", "altered signed bytes", "unsafe selector", "symlink parent", "symlink archive", "corrupt immutable file", "symlink CAS", "malformed signature"} {
		t.Run(tc, func(t *testing.T) {
			u, key := seedImageTrust(t)
			const version = "v1.2.3"
			const marker = "private-fixture-witness"
			arch, comp, label := "amd64", "runner", version
			if tc == "wrong architecture" {
				arch = "arm64"
			}
			if tc == "wrong role" {
				comp = "tikray"
			}
			if tc == "wrong signed version" {
				label = "v1.1"
			}
			raw := testImage(t, comp, arch, label)
			if tc == "wrong key" {
				key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			}
			sig := signImageFixture(t, key, raw)
			if tc == "altered signed bytes" {
				raw[len(raw)/2] ^= 3
			}
			if tc == "malformed signature" {
				sig = marker
			}
			in := putInboxImage(t, u, "runner", version, raw, sig)
			request := version
			switch tc {
			case "unsafe selector":
				request = "../" + marker
			case "symlink parent", "symlink archive":
				path := in
				if tc == "symlink parent" {
					path = filepath.Dir(in)
				}
				tmp := filepath.Join(u.Data, marker)
				if os.Rename(path, tmp) != nil || os.Symlink(tmp, path) != nil {
					t.Fatal("link fixture")
				}
			case "symlink CAS":
				if os.Symlink(t.TempDir(), filepath.Join(u.Data, "images")) != nil {
					t.Fatal("link fixture")
				}
			case "corrupt immutable file":
				if os.Mkdir(filepath.Join(u.Data, "images"), 0700) != nil || os.WriteFile(filepath.Join(u.Data, "images", fmt.Sprintf("runner-%x.tar", sha256.Sum256(raw))), []byte(marker), 0600) != nil {
					t.Fatal("corrupt CAS fixture")
				}
			}
			got, err := u.StageImage(t.Context(), "runner", request)
			if tc != "valid" {
				if err == nil || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), u.Data) {
					t.Fatal("invalid image accepted or untrusted input echoed")
				}
				return
			}
			if err != nil {
				t.Fatal("valid signed image refused", err)
			}
			ref := got.Ref()
			if !ref.Valid() || ref.Digest != fmt.Sprintf("%x", sha256.Sum256(raw)) || ref.Size != int64(len(raw)) || ref.Component != "runner" {
				t.Fatal("staged identity mismatch")
			}
			var chain string
			for i := 0; i < len(raw); i += 16384 {
				block := sha512.Sum512(raw[i:min(i+16384, len(raw))])
				h := sha512.Sum512([]byte(chain + hex.EncodeToString(block[:])))
				chain = hex.EncodeToString(h[:])
			}
			if ref.Chain != chain || VerifyImageRef(t.Context(), u.Data, ref, u.Arch) != nil {
				t.Fatal("native-compatible readback failed")
			}
			if next, err := u.StageImage(t.Context(), "runner", request); err != nil || next.Ref() != ref {
				t.Fatal("repeat did not reuse sealed archive")
			}
			putInboxImage(t, u, "runner", "sha256-"+ref.Digest, raw, sig)
			if next, err := u.StageImage(t.Context(), "runner", "sha256-"+ref.Digest); err != nil || next.Ref() != ref {
				t.Fatal("digest selector did not bind exact bytes")
			}
		})
	}
}

func TestImageFallbackAndRetention(t *testing.T) {
	u, key := seedImageTrust(t)
	raw := testImage(t, "tikray", "amd64", "v10")
	sig := signImageFixture(t, key, raw)
	var attempts []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts = append(attempts, r.URL.Path)
		switch r.URL.Path {
		case "/pub/v10/tikray-amd64.tar.sig":
			fmt.Fprint(w, sig)
		case "/pub/v10/tikray-amd64.tar":
			fmt.Fprint(w, "corrupt")
		case "/mirror/v10/tikray-amd64.tar":
			w.Write(raw)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	u.ImageSource = ImageSourceConfig{Upstream: srv.URL + "/pub", Direct: srv.Client(), Mirrors: []string{srv.URL + "/mirror/{version}/{file}"}}
	img, e := u.StageImage(t.Context(), "tikray", "v10")
	if e != nil || len(attempts) == 0 || attempts[len(attempts)-1] != "/mirror/v10/tikray-amd64.tar" {
		t.Fatal("did not reach verified mirror")
	}
	u.ImageSource = ImageSourceConfig{}
	old := testImage(t, "tikray", "amd64", "v9")
	putInboxImage(t, u, "tikray", "v9", old, signImageFixture(t, key, old))
	oldRef, e := u.StageImage(t.Context(), "tikray", "v9")
	if e != nil {
		t.Fatal("prior unavailable")
	}
	foreign := filepath.Join(u.Data, "images", "owner.tar")
	if os.WriteFile(foreign, []byte("owner"), 0600) != nil {
		t.Fatal("owner fixture")
	}
	if e := PruneImages(context.Background(), u.Data, u.Arch, []ImageRef{img.Ref()}); e != nil {
		t.Fatal("retirement failed", e)
	}
	if VerifyImageRef(t.Context(), u.Data, img.Ref(), u.Arch) != nil || VerifyImageRef(t.Context(), u.Data, oldRef.Ref(), u.Arch) == nil {
		t.Fatal("wrong slot survived")
	}
	if b, _ := os.ReadFile(foreign); string(b) != "owner" {
		t.Fatal("owner file changed")
	}
}
