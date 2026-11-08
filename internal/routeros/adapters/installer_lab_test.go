//go:build lab

package adapters

import (
	"bytes"
	"strings"
	"testing"
)

// The CHR gate and the real packaging command must use the complete reviewed
// embedded sources. An unfinished transport decision cannot produce a release.
func TestCompleteReleaseInstaller(t *testing.T) {
	p, _ := Installed("7.25", "x86_64", "CHR")
	var images []VerifiedArchive
	for _, name := range []string{"tikray", "tikray-runner"} {
		a, err := describeArchive(p, name, fixtureImage(t, name, "amd64"), "")
		if err != nil {
			t.Fatal(err)
		}
		images = append(images, a)
	}
	var out bytes.Buffer
	if err := BuildInstaller(p, images, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "# @TIKRAY_") || !strings.Contains(out.String(), "/healthz") {
		t.Fatal("real release lacks a complete watchdog probe")
	}
}
