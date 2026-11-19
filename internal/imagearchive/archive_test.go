package imagearchive

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestInspectChunkedChainMatchesReference(t *testing.T) {
	cfgRaw := []byte(`{"architecture":"amd64","os":"linux","config":{"Labels":{"org.opencontainers.image.version":"v1.0.0"},"Entrypoint":["/tikray-runner"]}}`)
	cfgSum := sha256.Sum256(cfgRaw)
	cfgName := hex.EncodeToString(cfgSum[:]) + ".json"

	manifestRaw, err := json.Marshal([]map[string]any{{
		"Config":   cfgName,
		"RepoTags": []string{"tikray/tikray-runner:amd64"},
		"Layers":   []string{"layer.tar"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	// Build a multi-chunk payload (> 3 * ChunkSize) so chunk 0 and subsequent
	// chunks are all exercised against the reference SHA-512 chain formula.
	layer := make([]byte, ChunkSize*3+1024)
	for i := range layer {
		layer[i] = byte((i*31 + 7) & 0xff)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range []struct {
		name string
		data []byte
	}{
		{cfgName, cfgRaw},
		{"layer.tar", layer},
		{"manifest.json", manifestRaw},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0644, Size: int64(len(f.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	archive := buf.Bytes()
	wantChain := ""
	for off := 0; off < len(archive); off += ChunkSize {
		end := min(off+ChunkSize, len(archive))
		h := sha512.Sum512(archive[off:end])
		mixed := sha512.Sum512([]byte(wantChain + hex.EncodeToString(h[:])))
		wantChain = hex.EncodeToString(mixed[:])
	}
	wantDigest := sha256.Sum256(archive)

	got, meta, err := Inspect(t.Context(), bytes.NewReader(archive), int64(len(archive)), "runner", "amd64", "v1.0.0")
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if got.Chain != wantChain {
		t.Fatalf("chain mismatch:\n got: %s\nwant: %s", got.Chain, wantChain)
	}
	if got.Digest != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("digest mismatch: got %s, want %x", got.Digest, wantDigest)
	}
	if meta.Version != "v1.0.0" {
		t.Fatalf("version = %q, want v1.0.0", meta.Version)
	}
}
