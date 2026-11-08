//go:build lab

package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/test/lab"
)

func TestEvidenceRejectsPrivateOrMissingResults(t *testing.T) {
	dir := t.TempDir()
	const suite = "m3-routing"
	write := func(observations []m3Observation, partial bool) error {
		return writeM3Evidence(dir, "7.25", lab.ArchX86, suite, observations, partial)
	}
	var full []m3Observation
	for _, id := range strings.Fields("policy_paths source_and_fasttrack policy_mid_connection failover dns_paths ipv6_guard quic_sniff drift_repair emergency_off") {
		full = append(full, m3Observation{id, true, time.Second})
	}
	if err := write(full, false); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "7.25-x86_64-m3-routing.json")
	baseline, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const private = "private-fixture-value"
	tests := [][]m3Observation{nil, full[:8], append(append([]m3Observation(nil), full...), full[0]), {{private, true, time.Second}}}
	bad := append([]m3Observation(nil), full...)
	bad[0].passed = false
	tests = append(tests, bad)
	for _, rows := range tests {
		if err := write(rows, false); err == nil || strings.Contains(err.Error(), private) {
			t.Fatal("invalid or private full evidence was accepted or echoed")
		}
	}
	if err := write(bad[:1], true); err != nil {
		t.Fatal(err)
	}
	if err := write([]m3Observation{{private, true, time.Second}}, true); err == nil {
		t.Fatal("private partial evidence accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(baseline, after) {
		t.Fatal("bad or partial evidence replaced complete results")
	}
	partial, err := os.ReadFile(filepath.Join(dir, "7.25-x86_64-m3-routing-partial.json"))
	if err != nil || !bytes.Contains(partial, []byte(`"pass": false`)) || bytes.Contains(partial, []byte(private)) {
		t.Fatal("filtered failure was not safely recorded")
	}
}
