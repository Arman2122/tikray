//go:build lab

package e2e

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrebuiltImages(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TIKRAY_LAB_IMAGES", dir)
	t.Setenv("PATH", dir) // image preparation is complete and dockerd is stopped
	runner := filepath.Join(dir, "tikray-runner-arm64.tar")
	control := filepath.Join(dir, "tikray-arm64.tar")
	for _, path := range []string{runner, control} {
		if err := os.WriteFile(path, []byte("prepared"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gotRunner, gotControl, err := buildImages(t.Context(), "arm64")
	if err != nil || gotRunner != runner || gotControl != control {
		t.Fatalf("prebuilt image paths = %q, %q, %v", gotRunner, gotControl, err)
	}
	if _, _, err := buildImages(t.Context(), "amd64"); err == nil {
		t.Error("missing architecture should fail before boot")
	}
}
