package adapters

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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func fixtureImage(t *testing.T, name, arch string) []byte {
	t.Helper()
	config := []byte(fmt.Sprintf(`{"os":"linux","architecture":%q,"config":{"Entrypoint":["/%s"]}}`, arch, name))
	key := fmt.Sprintf("blobs/sha256/%x", sha256.Sum256(config))
	manifest, _ := json.Marshal([]map[string]any{{"Config": key, "RepoTags": []string{"tikray/" + name + ":" + arch}, "Layers": []string{"layer.tar"}}})
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, f := range []struct {
		name string
		data []byte
	}{{key, config}, {"layer.tar", bytes.Repeat([]byte{0, 0xff, 1, 0x80, 4}, 8700)}, {"manifest.json", manifest}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0600, Size: int64(len(f.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestInstallerVerifiesSignedBytes(t *testing.T) {
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign integration runs with the installer lab")
	}
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "publisher.pub")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0600); err != nil {
		t.Fatal(err)
	}
	b := fixtureImage(t, "tikray", "amd64")
	sum := sha256.Sum256(b)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "tikray-amd64.tar")
	if os.WriteFile(file, b, 0600) != nil || os.WriteFile(file+".sig", []byte(base64.StdEncoding.EncodeToString(sig)), 0600) != nil {
		t.Fatal("write fixtures")
	}
	p, _ := Installed("7.25", "x86_64", "CHR")
	verify := func() error { _, e := VerifyArchive(context.Background(), p, "tikray", dir, keyFile, ""); return e }
	if err := verify(); err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0xff
	if os.WriteFile(file, b, 0600) != nil {
		t.Fatal("write corrupt fixture")
	}
	if err := verify(); err == nil {
		t.Fatal("accepted altered signed archive")
	}
}

func TestReleaseImageIdentityAndChunkOrder(t *testing.T) {
	p, _ := Installed("7.25", "x86_64", "CHR")
	b := fixtureImage(t, "tikray", "amd64")
	a, err := describeArchive(p, "tikray", b, "https://releases.example/tikray")
	if err != nil {
		t.Fatal(err)
	}
	var chunks [][sha512.Size]byte
	for off := 0; off < len(b); off += installerChunkSize {
		chunks = append(chunks, sha512.Sum512(b[off:min(off+installerChunkSize, len(b))]))
	}
	if a.size != len(b) || !slices.Equal(chunks, a.digests) {
		t.Fatal("length or chunk sequence changed")
	}
	for _, tc := range [][2]string{{"tikray-runner", "amd64"}, {"tikray", "arm64"}} {
		if _, err := describeArchive(p, "tikray", fixtureImage(t, tc[0], tc[1]), ""); err == nil {
			t.Fatal("wrong signed release component or architecture accepted")
		}
	}
	for _, u := range []string{"http://releases.example", "https://user@releases.example", `https://host/$exec`, "https://host/b?credential=fixture"} {
		if _, err := describeArchive(p, "tikray", b, u); err == nil {
			t.Fatal("invalid release origin accepted")
		}
	}
	for _, u := range []string{"https://github.com/owner/project/releases/download/v1", "https://www.GITHUB.com:443/owner/project/releases/latest/download", "https://github.com/owner/project/tmp/../releases/latest/download/"} {
		if _, err := describeArchive(p, "tikray", b, u); err == nil {
			t.Fatal("accepted a release endpoint known to return a signed redirect")
		}
	}
	if _, err := describeArchive(p, "tikray", b, "https://owner.github.io/project/releases/download/v1"); err != nil {
		t.Fatal("refused a static release path")
	}
}
