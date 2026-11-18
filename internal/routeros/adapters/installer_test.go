package adapters

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	routerosfiles "github.com/Arman2122/tikray/routeros"
)

// Source readback may carry one extra native line ending. A compiled helper
// must always fit both the installer and its restricted caller's exact bound.
func TestWatchdogHelperBindsActualSourceLength(t *testing.T) {
	body, helper, err := WatchdogScripts()
	if err != nil {
		t.Fatal(err)
	}
	canonical := strings.ReplaceAll(strings.TrimRight(helper, "\r\n"), "\n", "\r\n")
	if !strings.Contains(body, fmt.Sprintf("($n>%d)", len(canonical)+4)) {
		t.Fatal("native source bound differs from the installed helper")
	}
}

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
			return []byte(`:local proof "` + witness + `"`), nil
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
	if !strings.Contains(body, "tikray:watchdog-traffic") || !strings.Contains(body, "image: traffic helper content changed") {
		t.Fatal("installer omitted the independently pinned traffic helper")
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
	for _, visible := range []string{"image-bootstrap.receipt", images[0].publisher, images[1].ref.Chain, images[1].ref.Digest, images[1].ref.ImageID, "live image differs from verified archive", "/file/copy"} {
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

func TestInstallerSupportsLatestRouterOSReleases(t *testing.T) {
	for _, tt := range []struct {
		version, arch, wantRegex string
		accept, reject           []string
	}{
		{
			version:   "7.25.1",
			arch:      "arm64",
			wantRegex: `^7\.25(\.[1-9][0-9]*)?$`,
			accept:    []string{"7.25", "7.25.1", "7.25.2", "7.25.10"},
			reject:    []string{"7.25.0", "7.24.6", "7.23.8", "7.26", "7.25beta1"},
		},
		{
			version:   "7.24.6",
			arch:      "x86_64",
			wantRegex: `^7\.24\.([6-9]|[1-9][0-9]+)$`,
			accept:    []string{"7.24.6", "7.24.7", "7.24.10"},
			reject:    []string{"7.24", "7.24.0", "7.24.5", "7.25.1", "7.23.8"},
		},
		{
			version:   "7.23.8",
			arch:      "x86_64",
			wantRegex: `^7\.23\.([8-9]|[1-9][0-9]+)$`,
			accept:    []string{"7.23.8", "7.23.9", "7.23.12"},
			reject:    []string{"7.23", "7.23.7", "7.24.6", "7.25"},
		},
	} {
		t.Run(tt.version+"-"+tt.arch, func(t *testing.T) {
			p, err := Installed(tt.version, tt.arch, "CHR")
			if err != nil {
				t.Fatalf("Installed(%q, %q): %v", tt.version, tt.arch, err)
			}
			a, err := describeArchive(p, "tikray", fixtureImage(t, "tikray", p.GOARCH()), "")
			if err != nil {
				t.Fatal(err)
			}
			r, err := describeArchive(p, "tikray-runner", fixtureImage(t, "tikray-runner", p.GOARCH()), "")
			if err != nil {
				t.Fatal(err)
			}
			signFixturePair(t, &a, &r)
			var out bytes.Buffer
			if err := BuildInstaller(p, []VerifiedArchive{a, r}, &out); err != nil {
				t.Fatal(err)
			}
			re := p.InstallerVersionPattern()
			if re != tt.wantRegex {
				t.Fatalf("pattern = %q, want %q", re, tt.wantRegex)
			}
			compiled := regexp.MustCompile(re)
			for _, v := range tt.accept {
				if !compiled.MatchString(v) {
					t.Errorf("pattern %q rejected supported version %q", re, v)
				}
			}
			for _, v := range tt.reject {
				if compiled.MatchString(v) {
					t.Errorf("pattern %q accepted unsupported version %q", re, v)
				}
			}
			// RouterOS escapes \ and $ inside double-quoted strings.
			escaped := strings.NewReplacer(`\`, `\\`, `$`, `\$`).Replace(re)
			if !strings.Contains(out.String(), `~ "`+escaped+`"`) {
				t.Fatalf("installer script missing release-line regex guard %q", escaped)
			}
		})
	}
}
