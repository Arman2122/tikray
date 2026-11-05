package lab

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The legacy Docker builder can return success for linux/arm64 while keeping
// the host's amd64 base. An archive named arm64 must not reach the router then.
func TestBuildImagesRefusesWrongPlatform(t *testing.T) {
	bin := t.TempDir()
	for name, script := range map[string]string{
		"go": "#!/bin/sh\nexit 0\n",
		"docker": `#!/bin/sh
case "$1" in
	info) echo 'Storage Driver: overlay2' ;;
	build|buildx) ;;
	image)
		case "$*" in
			*tikray-runner:arm64) echo linux/arm64 ;;
			*) echo linux/amd64 ;;
		esac ;;
	save) touch "$3" ;;
	*) exit 1 ;;
esac
`,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	out := t.TempDir()
	cmd := exec.Command("bash", "../../scripts/build-images.sh", "arm64", out)
	log, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(log), "linux/amd64") || !strings.Contains(string(log), "linux/arm64") {
		t.Fatalf("expected a platform mismatch before export, got %v: %s", err, log)
	}
	if _, err := os.Stat(filepath.Join(out, "tikray-runner-arm64.tar")); err != nil {
		t.Fatalf("the arm64 runner should have been exported: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "tikray-arm64.tar")); !os.IsNotExist(err) {
		t.Fatal("saved the control image after building the wrong platform")
	}
}
