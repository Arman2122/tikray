//go:build lab

package e2e

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The SSH helper normalizes line endings. Read the body in hex so the
// comparison measures exactly the bytes kept by RouterOS; only a known
// formatting variant can be reported.
func checkEmergencySource(ctx context.Context, t *testing.T, f *installLab) {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("..", "..", "routeros", "emergency-off.rsc"))
	if err != nil {
		t.Fatal("missing reviewed emergency source")
	}
	_, tail, ok := strings.Cut(string(source), " policy=read,write,test source={")
	body, okEnd := strings.CutSuffix(tail, "}\n    }\n}\n")
	if !ok || !okEnd {
		t.Fatal("invalid source fixture")
	}
	wire, err := f.CHR.RunPrivate(ctx, `:put [:convert [/system/script/get [find where name=tikray-emergency-off and comment="tikray:emergency-off"] source] to=hex]`)
	if err != nil {
		t.Fatal("could not inspect emergency script body")
	}
	observed, err := hex.DecodeString(strings.TrimSpace(wire))
	if err != nil {
		t.Fatal("invalid script source encoding")
	}
	for _, tc := range []struct{ name, text string }{
		{"literal", body}, {"terminal-line", body + "\n"},
	} {
		for _, pair := range []struct{ kind, text string }{
			{"LF", tc.text}, {"CRLF", strings.ReplaceAll(tc.text, "\n", "\r\n")},
		} {
			if string(observed) == pair.text {
				t.Logf("verified emergency body representation %s/%s", tc.name, pair.kind)
				return
			}
		}
	}
	t.Fatal("emergency script body differs from reviewed source")
}
