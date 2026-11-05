//go:build lab

package m3

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

// containerFixture builds a Docker-save archive for importing a stopped
// container. A comment probe does not need an image download or executable.
func containerFixture(dir string) (string, error) {
	entry := func(w *tar.Writer, name string, data []byte) error {
		if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}); err != nil {
			return err
		}
		_, err := w.Write(data)
		return err
	}
	var layer bytes.Buffer
	lw := tar.NewWriter(&layer)
	if err := entry(lw, "fixture", []byte("ownership probe\n")); err != nil {
		return "", err
	}
	if err := lw.Close(); err != nil {
		return "", err
	}
	layerHash := fmt.Sprintf("%x", sha256.Sum256(layer.Bytes()))
	cfg := []byte(fmt.Sprintf(`{"architecture":"amd64","os":"linux","config":{"Cmd":["/fixture"]},"rootfs":{"type":"layers","diff_ids":["sha256:%s"]},"history":[{"created_by":"fixture"}]}`, layerHash))
	cfgName := fmt.Sprintf("%x.json", sha256.Sum256(cfg))
	layerName := layerHash + "/layer.tar"
	manifest := []byte(fmt.Sprintf(`[{"Config":%q,"RepoTags":["spike/m3:probe"],"Layers":[%q]}]`, cfgName, layerName))
	var archive bytes.Buffer
	w := tar.NewWriter(&archive)
	for _, f := range []struct {
		name string
		data []byte
	}{{"manifest.json", manifest}, {cfgName, cfg}, {layerName, layer.Bytes()}} {
		if err := entry(w, f.name, f.data); err != nil {
			return "", err
		}
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "m3-fixture.tar")
	return path, os.WriteFile(path, archive.Bytes(), 0600)
}
