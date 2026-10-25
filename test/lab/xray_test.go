package lab

import (
	"slices"
	"testing"
)

func TestXrayCoreVersion(t *testing.T) {
	for in, want := range map[string]string{
		"v1.260327.0": "26.3.27",
		"v1.260118.0": "26.1.18",
		"v1.251208.0": "25.12.8",
		"v26.10.21":   "26.10.21",
		"v26.9.9":     "26.9.9",
	} {
		got, err := XrayCoreVersion(in)
		if err != nil || got != want {
			t.Errorf("XrayCoreVersion(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"latest", "26.3.27", "v1.26032.0", "v2.0.0"} {
		if got, err := XrayCoreVersion(bad); err == nil {
			t.Errorf("XrayCoreVersion(%q) = %q, want an error", bad, got)
		}
	}
}

func TestLabXrayVersion(t *testing.T) {
	t.Setenv("TIKRAY_LAB_XRAY", "")
	if got := LabXrayVersion(); got != "latest" {
		t.Errorf("default %q, want latest", got)
	}
	t.Setenv("TIKRAY_LAB_XRAY", "v26.10.21")
	if got := LabXrayVersion(); got != "v26.10.21" {
		t.Errorf("override %q, want v26.10.21", got)
	}
}

func TestReleaseTags(t *testing.T) {
	// Release tags out of order, a module version, a pre-release and a
	// branch, as `git ls-remote --tags` prints them.
	refs := []string{
		"abc\trefs/tags/v1.260327.0",
		"abc\trefs/tags/v26.9.30",
		"abc\trefs/tags/v26.10.21",
		"abc\trefs/tags/v26.10.3",
		"abc\trefs/tags/v26.2.6",
		"abc\trefs/tags/v25.12.8",
		"abc\trefs/tags/v26.11.1-beta",
		"abc\trefs/heads/main",
	}
	want := []string{"v26.10.21", "v26.10.3", "v26.9.30", "v26.2.6", "v25.12.8"}
	if got := releaseTags(refs); !slices.Equal(got, want) {
		t.Errorf("releaseTags = %q, want %q", got, want)
	}
	if got := releaseTags(nil); len(got) != 0 {
		t.Errorf("releaseTags(nil) = %q, want none", got)
	}
}
