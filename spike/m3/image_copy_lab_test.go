//go:build lab

package m3

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verify that an owner can copy an archive by its checked ID and compute
// the entire chained SHA512 used by the independent router recovery script.
func TestImageNativeCopyAndProof(t *testing.T) {
	r := newRig(t)
	b := bytes.Repeat([]byte{0, 13, 10, 0xc2, 0xff}, 19001)
	src := filepath.Join(t.TempDir(), "source.tar")
	if os.WriteFile(src, b, 0600) != nil || r.chr.Push(r.ctx, src, "disk1/tkr-copy-origin.tar") != nil {
		t.Fatal("could not transfer public binary fixture")
	}
	var chain string
	for i := 0; i < len(b); i += 16384 {
		h := sha512.Sum512(b[i:min(i+16384, len(b))])
		mix := sha512.Sum512([]byte(chain + hex.EncodeToString(h[:])))
		chain = hex.EncodeToString(mix[:])
	}
	cmd := `{ :local origin [/file/find where name="disk1/tkr-copy-origin.tar"]; :if ([:len $origin]!=1) do={:error "source absent"}; /file/copy [:pick $origin 0] name="disk1/tkr-copy-slot.tar"; :local n [/file/get [find where name="disk1/tkr-copy-slot.tar"] size]; :local pos 0; :local chain ""; :while ($pos<$n) do={:local k 16384; :if (($pos+$k)>$n) do={:set k ($n-$pos)}; :local b ([/file/read file="disk1/tkr-copy-slot.tar" offset=$pos chunk-size=$k as-value]->"data"); :if ([:len $b]!=$k) do={:error "length"}; :local part [:convert [:convert $b from=raw transform=sha512 to=hex] transform=lc]; :set chain [:convert [:convert ($chain . $part) from=raw transform=sha512 to=hex] transform=lc]; :set pos ($pos+$k)}; :if ($chain="` + chain + `") do={:put "copy-proof-complete"} }`
	reply, e := r.chr.RunPrivate(r.ctx, cmd)
	if e != nil || !strings.Contains(reply, "copy-proof-complete") {
		t.Fatal("owner archive copy or native digest chain failed")
	}
}
