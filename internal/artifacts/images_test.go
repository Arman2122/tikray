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
	"syscall"
	"testing"
)

func testImage(t *testing.T, component, arch, version string) []byte {
	t.Helper()
	return imageWithStateLabel(t, component, arch, version, "")
}
func imageWithStateLabel(t *testing.T, component, arch, version, schema string) []byte {
	t.Helper()
	name := "tikray"
	entry := "/usr/local/bin/tikray"
	var cmd []string
	if component == "runner" {
		name, entry = "tikray-runner", "/tikray-runner"
	} else {
		cmd = []string{"serve"}
	}
	conf, _ := json.Marshal(map[string]any{"os": "linux", "architecture": arch, "config": map[string]any{"Entrypoint": []string{entry}, "Cmd": cmd, "Labels": map[string]string{"org.opencontainers.image.version": version, "io.tikray.state-version": schema}}})
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
	if os.WriteFile(filepath.Join(state, "image-bootstrap.receipt"), b, 0600) != nil {
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
	u, key := seedInstalledImages(t)
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

func TestImageRetirementPreservesForeignSignaturesAndResumes(t *testing.T) {
	u, k := seedInstalledImages(t)
	type slot struct {
		ref      ImageRef
		tar, sig string
	}
	stage := func(v string, preexistingSig bool) slot {
		raw := testImage(t, "runner", "amd64", v)
		sig := signImageFixture(t, k, raw)
		path := filepath.Join(u.Data, "images", fmt.Sprintf("runner-%x.tar", sha256.Sum256(raw)))
		if preexistingSig {
			if os.MkdirAll(filepath.Dir(path), 0700) != nil || os.WriteFile(path+".sig", []byte(sig), 0600) != nil {
				t.Fatal("could not create unrelated signature")
			}
		}
		putInboxImage(t, u, "runner", v, raw, sig)
		got, err := u.StageImage(t.Context(), "runner", v)
		if err != nil {
			t.Fatal("signed slot fixture failed", err)
		}
		return slot{got.Ref(), path, path + ".sig"}
	}
	active := stage("r1", false)
	interrupted := stage("r2", false)
	foreign := stage("r3", true)
	if err := os.Remove(interrupted.tar); err != nil {
		t.Fatal("could not simulate interrupted retirement")
	}
	if e := PruneImages(t.Context(), u.Data, u.Arch, []ImageRef{active.ref}); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Lstat(foreign.sig); e != nil {
		t.Fatal("unrelated valid signature was removed")
	}
	for _, p := range []string{interrupted.sig, interrupted.tar + ".owned", foreign.tar, foreign.tar + ".owned"} {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			t.Fatal("interrupted retirement did not converge")
		}
	}
	if VerifyImageRef(t.Context(), u.Data, active.ref, u.Arch) != nil {
		t.Fatal("active data lost")
	}
	stage("r2", false)
}

func TestImageTrustRequiresPrivateHandoff(t *testing.T) {
	u, _ := seedImageTrust(t)
	if err := os.Chmod(filepath.Join(u.Data, "state"), 0777); err != nil {
		t.Fatal("permission fixture")
	}
	if _, e := ReadImageBootstrap(u.Data); e == nil {
		t.Fatal("trust in a writable shared directory was accepted")
	}
}

func TestImageSelectorLimitsAndPinnedNotify(t *testing.T) {
	u, k := seedImageTrust(t)
	for _, invalid := range []string{"", "latest", "../private-marker", "two..dots", "bad name", "sha256-abc", strings.Repeat("a", 65)} {
		if ValidImageVersion(invalid) {
			t.Fatal("unsafe selector accepted")
		}
	}
	raw := testImage(t, "tikray", "amd64", "v1")
	putInboxImage(t, u, "tikray", "v1", raw, signImageFixture(t, k, raw))
	img, err := u.StageImage(t.Context(), "tikray", "v1")
	if err != nil {
		t.Fatal(err)
	}
	tag := "v1"
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/latest" {
			t.Error("notify fetched an archive")
		}
		hits++
		fmt.Fprint(w, tag)
	}))
	defer srv.Close()
	u.ImageSource = ImageSourceConfig{Upstream: srv.URL, Direct: srv.Client()}
	for _, want := range []bool{false, true} {
		if want {
			tag = "v2"
		}
		got, e := u.ImageReleaseAvailable(t.Context(), "tikray", img.Ref())
		if e != nil || got != want {
			t.Fatal("notify release identity mismatch")
		}
	}
	if hits != 2 {
		t.Fatal("notify did not read trusted latest twice")
	}
}

func TestStageImageOnlyReclaimsProvenInterruptedWork(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		u, key := seedImageTrust(t)
		dir := filepath.Join(u.Data, "images")
		work := filepath.Join(dir, ".image-stage-interrupted")
		if os.MkdirAll(work, 0700) != nil {
			t.Fatal("work dir fixture")
		}
		st, e := os.Stat(work)
		if e != nil {
			t.Fatal("stat fixture")
		}
		sys := st.Sys().(*syscall.Stat_t)
		marker, _ := json.Marshal(geoWork{Name: filepath.Base(work), Device: uint64(sys.Dev), Inode: sys.Ino})
		if os.WriteFile(filepath.Join(dir, ".tikray-image-work.json"), marker, 0600) != nil || os.WriteFile(filepath.Join(work, "archive.part"), []byte("unfinished"), 0600) != nil {
			t.Fatal("stage crash fixture")
		}
		if foreign {
			if os.WriteFile(filepath.Join(work, "owner-file"), []byte("keep"), 0600) != nil {
				t.Fatal("mixed fixture")
			}
		}
		raw := testImage(t, "runner", "amd64", "v1")
		putInboxImage(t, u, "runner", "v1", raw, signImageFixture(t, key, raw))
		_, e = u.StageImage(t.Context(), "runner", "v1")
		if foreign {
			if e == nil {
				t.Fatal("accepted a mixed working directory")
			}
			if b, e := os.ReadFile(filepath.Join(work, "owner-file")); e != nil || string(b) != "keep" {
				t.Fatal("unrelated work lost")
			}
		} else if e != nil {
			t.Fatal("proven interrupted stage could not resume", e)
		} else if _, e := os.Stat(work); !os.IsNotExist(e) {
			t.Fatal("known incomplete archive survived successful restaging")
		}
	}
}

func TestImageRetentionKeepsDigestOnDisputedReceipt(t *testing.T) {
	u, k := seedInstalledImages(t)
	raw := testImage(t, "runner", u.Arch, "a")
	putInboxImage(t, u, "runner", "a", raw, signImageFixture(t, k, raw))
	img, e := u.StageImage(t.Context(), "runner", "a")
	if e != nil {
		t.Fatal(e)
	}
	keep := img.Ref()
	keep.Chain = strings.Repeat("f", 128)
	_ = PruneImages(t.Context(), u.Data, u.Arch, []ImageRef{keep})
	if VerifyImageRef(t.Context(), u.Data, img.Ref(), u.Arch) != nil {
		t.Fatal("disputed receipt permitted deletion of active archive")
	}
}

func TestImageRejectsContradictoryArchiveEnd(t *testing.T) {
	u, k := seedImageTrust(t)
	a := testImage(t, "tikray", "amd64", "r4")
	joined := append(a, testImage(t, "runner", "amd64", "r4")...)
	putInboxImage(t, u, "tikray", "r4", joined, signImageFixture(t, k, joined))
	if _, e := u.StageImage(t.Context(), "tikray", "r4"); e == nil {
		t.Fatal("multiple tar archive bodies accepted as one image")
	}
}

func TestImageOnlyUsesHealthyProxyAndRechecksSealedSignature(t *testing.T) {
	u, k := seedImageTrust(t)
	raw := testImage(t, "runner", "amd64", "r5")
	sig := signImageFixture(t, k, raw)
	proxyReads := 0
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyReads++
		switch r.URL.Path {
		case "/r5/tikray-runner-amd64.tar.sig":
			fmt.Fprint(w, sig)
		case "/r5/tikray-runner-amd64.tar":
			w.Write(raw)
		default:
			http.NotFound(w, r)
		}
	}))
	defer proxy.Close()
	const marker = "private-configured-source"
	bad := &http.Client{Transport: geoTransportFunc(func(*http.Request) (*http.Response, error) { return nil, fmt.Errorf("offline %s", marker) })}
	healthy := false
	u.ImageSource = ImageSourceConfig{Upstream: proxy.URL, Direct: bad, Proxy: proxy.Client(), ProxyHealthy: func(context.Context) bool { return healthy }}
	if _, err := u.StageImage(t.Context(), "runner", "r5"); err == nil || strings.Contains(err.Error(), marker) || proxyReads != 0 {
		t.Fatal("unhealthy proxy used or remote diagnostic disclosed")
	}
	healthy = true
	img, err := u.StageImage(t.Context(), "runner", "r5")
	if err != nil || proxyReads != 2 {
		t.Fatal("verified healthy proxy did not supply archive and signature")
	}
	if os.WriteFile(filepath.Join(u.Data, "images", imageFilename(img.Ref())+".sig"), []byte(marker), 0600) != nil {
		t.Fatal("could not alter local signature")
	}
	if _, err = u.StageImage(t.Context(), "runner", "r5"); err == nil || strings.Contains(err.Error(), marker) {
		t.Fatal("published altered local signature accepted or disclosed")
	}
}
