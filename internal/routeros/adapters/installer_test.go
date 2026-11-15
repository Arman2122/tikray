package adapters

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"io/fs"
	"strings"
	"testing"

	routerosfiles "github.com/Arman2122/tikray/routeros"
)

func TestInstallerBindsComponentArchitectureAndChunks(t *testing.T) {
	p, _ := Installed("7.25", "x86_64", "CHR")
	b := fixtureImage(t, "tikray", "amd64")
	a, err := describeArchive(p, "tikray", b, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct{ component, arch string }{{"tikray-runner", "amd64"}, {"tikray", "arm64"}} {
		if _, err := describeArchive(p, "tikray", fixtureImage(t, bad.component, bad.arch), ""); err == nil {
			t.Fatal("accepted substituted image")
		}
	}
	r, err := describeArchive(p, "tikray-runner", fixtureImage(t, "tikray-runner", "amd64"), "")
	if err != nil {
		t.Fatal(err)
	}
	signFixturePair(t, &a, &r)
	for _, bad := range [][]VerifiedArchive{{a}, {r, a}, {a, a}, {a, {}}} {
		var out bytes.Buffer
		if err := BuildInstaller(p, bad, &out); err == nil || out.Len() != 0 {
			t.Fatal("invalid release pair emitted script")
		}
	}
	var out bytes.Buffer
	// Vary a single required input to distinguish release assembly from the
	// transport decision. The public packager always uses embedded sources.
	const health = "watchdog-health.rsc"
	missing := func(name string) ([]byte, error) {
		if name == health {
			return nil, fs.ErrNotExist
		}
		return routerosfiles.Sources.ReadFile(name)
	}
	if err := buildInstaller(p, []VerifiedArchive{a, r}, &out, missing); err == nil || out.Len() != 0 {
		t.Fatal("incomplete installer emitted output")
	}
	const witness = "test-only health body"
	source := func(name string) ([]byte, error) {
		if name == health {
			return []byte("# " + witness), nil
		}
		return routerosfiles.Sources.ReadFile(name)
	}
	if err := buildInstaller(p, []VerifiedArchive{a, r}, &out, source); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	if !strings.Contains(body, witness) {
		t.Fatal("health body missing from assembled installer")
	}
	var off int
	for pos := 0; pos < len(b); pos += installerChunkSize {
		h := sha512.Sum512(b[pos:min(pos+installerChunkSize, len(b))])
		at := strings.Index(body[off:], hex.EncodeToString(h[:]))
		if at < 0 {
			t.Fatal("ordered chunk digest absent")
		}
		off += at + 128
	}
	if strings.Contains(body, "# @TIKRAY_") || !strings.Contains(body, "tikray-emergency-off") || !strings.Contains(body, "tikray-watchdog") {
		t.Fatal("installer was not self-contained")
	}
}

func TestOnlineArchivesAuthenticateBeforePublication(t *testing.T) {
	a := VerifiedArchive{component: "tikray", arch: "amd64", releaseBase: "https://downloads.example/release"}
	src := archiveChecks([]VerifiedArchive{a})
	steps := []string{"$lease", "dst-path=$incoming", `[$verifyStaged "tikray" $incoming]`, "/file/set $transferID name=$path", `[$verifyStaged "tikray" $path]`}
	for _, step := range steps {
		start := strings.Index(src, step)
		if start < 0 {
			t.Fatalf("missing ordered online installation step %q", step)
		}
		src = src[start+len(step):]
	}
	if strings.Contains(archiveChecks([]VerifiedArchive{{component: "tikray", arch: "amd64"}}), "/tool/fetch") {
		t.Fatal("offline installer issued an outbound request")
	}
}

func TestUpdateBootstrapBindsVerifiedPublisherAndLiveImages(t *testing.T) {
	p, _ := Installed("7.25", "x86_64", "CHR")
	var images []VerifiedArchive
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, name := range []string{"tikray", "tikray-runner"} {
		b := fixtureImage(t, name, "amd64")
		a, e := describeArchive(p, name, b, "")
		if e != nil {
			t.Fatal(e)
		}
		if e := signFixture(t, &a, key); e != nil {
			t.Fatal("signed fixture failed")
		}
		images = append(images, a)
	}
	var out bytes.Buffer
	if e := BuildInstaller(p, images, &out); e != nil {
		t.Fatal("signed pair refused", e)
	}
	for _, visible := range []string{"image-bootstrap.json", images[0].publisher, images[1].ref.Chain, images[1].ref.Digest, images[1].ref.ImageID, "live image differs from verified archive", "/file/copy"} {
		if !strings.Contains(out.String(), visible) {
			t.Fatal("bootstrap is missing a trust or initial image witness")
		}
	}
	if pos, ack := strings.Index(out.String(), "# PUBLISH VERIFIED IMAGE BASELINE"), strings.Index(out.String(), "live control, runner and router verification failed"); pos < ack || ack < 0 {
		t.Fatal("bootstrap published before proof")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if signFixture(t, &images[1], other) != nil {
		t.Fatal("signed fixture failed")
	}
	if BuildInstaller(p, images, &bytes.Buffer{}) == nil {
		t.Fatal("per-component mismatched signer accepted")
	}
}
