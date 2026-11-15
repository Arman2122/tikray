// Package imagearchive reads the classic Docker-save format used by RouterOS.
// No archive entry is extracted into the control container's filesystem.
package imagearchive

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
)

const MaxSize = 128 << 20
const ChunkSize = 16 << 10
const versionLabel = "org.opencontainers.image.version"

var errInvalid = errors.New("image: invalid release archive")
var versionName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type Ref struct {
	Component string `json:"component"`
	Digest    string `json:"digest"`
	Chain     string `json:"chain"`
	Size      int64  `json:"size"`
	ImageID   string `json:"image_id"`
}

func Component(s string) bool { return s == "tikray" || s == "runner" }
func hexValue(s string, size int) bool {
	if len(s) != size || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func (r Ref) Valid() bool {
	return Component(r.Component) && hexValue(r.Digest, 64) && hexValue(r.Chain, 128) && hexValue(r.ImageID, 64) && r.Size > 0 && r.Size <= MaxSize
}
func Version(s string) bool {
	if strings.HasPrefix(s, "sha256-") {
		return hexValue(s[len("sha256-"):], 64)
	}
	return s != "latest" && versionName.MatchString(s) && !strings.Contains(s, "..")
}

func ReleaseName(component string) string {
	if component == "runner" {
		return "tikray-runner"
	}
	return "tikray"
}

type archiveManifest struct {
	Config           string
	RepoTags, Layers []string
}
type config struct {
	Architecture, OS string
	Config           struct {
		Labels          map[string]string
		Entrypoint, Cmd []string
	}
}

// Inspect binds the full file, ordered binary chunks and Docker config ID to
// the same opened archive. Version is empty only for authenticated originals.
func Inspect(ctx context.Context, r io.ReaderAt, size int64, component, arch, version string) (Ref, string, error) {
	if !Component(component) || (arch != "amd64" && arch != "arm64") || (version != "" && !Version(version)) || size <= 0 || size > MaxSize {
		return Ref{}, "", errInvalid
	}
	ref := Ref{Component: component, Size: size}
	raw := io.NewSectionReader(r, 0, size)
	sum := sha256.New()
	var block [ChunkSize]byte
	for offset := int64(0); offset < size; offset += ChunkSize {
		if err := ctx.Err(); err != nil {
			return Ref{}, "", err
		}
		part := block[:min(int64(len(block)), size-offset)]
		if _, err := io.ReadFull(raw, part); err != nil {
			return Ref{}, "", errInvalid
		}
		sum.Write(part)
		h := sha512.Sum512(part)
		mixed := sha512.Sum512([]byte(ref.Chain + hex.EncodeToString(h[:])))
		ref.Chain = hex.EncodeToString(mixed[:])
	}
	ref.Digest = hex.EncodeToString(sum.Sum(nil))
	type entry struct{ offset, size int64 }
	files := map[string]entry{}
	view := io.NewSectionReader(r, 0, size)
	reader := tar.NewReader(view)
	for {
		if err := ctx.Err(); err != nil {
			return Ref{}, "", err
		}
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Ref{}, "", errInvalid
		}
		name := strings.TrimSuffix(h.Name, "/")
		if !safePath(name) || (h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeReg) || len(files) >= 4096 {
			return Ref{}, "", errInvalid
		}
		if _, duplicate := files[name]; duplicate {
			return Ref{}, "", errInvalid
		}
		at, err := view.Seek(0, io.SeekCurrent)
		if err != nil || h.Size < 0 || h.Size > size-at {
			return Ref{}, "", errInvalid
		}
		if h.Typeflag == tar.TypeDir {
			files[name] = entry{size: -1}
		} else {
			files[name] = entry{at, h.Size}
		}
	}
	readJSON := func(name string, dst any) ([]byte, error) {
		f, ok := files[name]
		if !ok || f.size < 1 || f.size > 1<<20 {
			return nil, errInvalid
		}
		data := make([]byte, f.size)
		if _, err := r.ReadAt(data, f.offset); err != nil || json.Unmarshal(data, dst) != nil {
			return nil, errInvalid
		}
		return data, nil
	}
	var list []archiveManifest
	if _, err := readJSON("manifest.json", &list); err != nil || len(list) != 1 {
		return Ref{}, "", errInvalid
	}
	m := list[0]
	if !slices.Equal(m.RepoTags, []string{"tikray/" + ReleaseName(component) + ":" + arch}) || len(m.Layers) == 0 {
		return Ref{}, "", errInvalid
	}
	for _, l := range m.Layers {
		if f, ok := files[l]; !ok || f.size <= 0 || l == m.Config || l == "manifest.json" {
			return Ref{}, "", errInvalid
		}
	}
	var c config
	data, err := readJSON(m.Config, &c)
	if err != nil || c.OS != "linux" || c.Architecture != arch {
		return Ref{}, "", errInvalid
	}
	cfgHash := sha256.Sum256(data)
	ref.ImageID = hex.EncodeToString(cfgHash[:])
	if m.Config != "blobs/sha256/"+ref.ImageID && m.Config != ref.ImageID+".json" {
		return Ref{}, "", errInvalid
	}
	if component == "tikray" {
		if !slices.Equal(c.Config.Entrypoint, []string{"/usr/local/bin/tikray"}) || !slices.Equal(c.Config.Cmd, []string{"serve"}) {
			return Ref{}, "", errInvalid
		}
	} else if !slices.Equal(c.Config.Entrypoint, []string{"/tikray-runner"}) || len(c.Config.Cmd) != 0 {
		return Ref{}, "", errInvalid
	}
	label := c.Config.Labels[versionLabel]
	if version != "" && version != "sha256-"+ref.Digest && (version != label || strings.HasPrefix(version, "sha256-")) {
		return Ref{}, "", errInvalid
	}
	return ref, label, nil
}

func safePath(s string) bool {
	return len(s) > 0 && len(s) <= 256 && path.Clean(s) == s && s != "." && s != ".." && !strings.HasPrefix(s, "../") && !strings.HasPrefix(s, "/") && !strings.ContainsAny(s, "\\:\r\n\x00")
}
