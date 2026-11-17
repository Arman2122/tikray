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
	for _, id := range strings.Fields("policy_paths source_and_fasttrack policy_mid_connection failover dns_paths ipv6_guard quic_sniff drift_repair emergency_off geo_diff_and_rollback") {
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

func TestSkippedRegressionIsUnsuccessfulEvidence(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TIKRAY_LAB_RESULTS", dir)
	t.Run("suite", func(st *testing.T) {
		rec := (&Lab{Version: "7.25", Arch: lab.ArchX86}).recordChecks(st, "m2b")
		rec("fixture", func(c *testing.T, note func(string, ...any)) {
			note("temporary-fixture-note")
			c.SkipNow()
		})
	})
	reports, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(reports) != 1 {
		t.Fatal("missing lab report")
	}
	data, err := os.ReadFile(reports[0])
	if err != nil || !bytes.Contains(data, []byte(`"pass": false`)) || bytes.Contains(data, []byte("temporary-fixture-note")) {
		t.Fatal("skipped regression published successful or unfinished observations")
	}
}

func TestMalformedCLIResultOmitsContents(t *testing.T) {
	const private = "private-result-fixture"
	if _, err := decodeCLIResult(private); err == nil || strings.Contains(err.Error(), private) {
		t.Fatal("malformed CLI result exposed its contents or passed")
	}
	if r, err := decodeCLIResult(`{"outcome":"committed"}`); err != nil || r.Outcome != "committed" {
		t.Fatal("lost valid CLI outcome")
	}
}

// A complete watchdog run must exercise both independent restarts, both
// image transactions, and loss of power during an active replacement.
func TestWatchdogEvidenceCoversRebootAndBothComponents(t *testing.T) {
	dir := t.TempDir()
	ids := []string{"control_restart", "runner_restart", "control_update_and_revert", "runner_update_and_revert", "reboot_mid_update"}
	var reports []m3Observation
	for _, id := range ids {
		reports = append(reports, m3Observation{id: id, passed: true, elapsed: time.Second})
	}
	if err := writeM3Evidence(dir, "7.25", lab.ArchX86, "m3-watchdog", reports, false); err != nil {
		t.Fatal("complete watchdog checks could not be recorded")
	}
	if err := writeM3Evidence(dir, "7.25", lab.ArchX86, "m3-watchdog", reports[:4], false); err == nil {
		t.Fatal("missing reboot proof published as complete")
	}
}

func TestOutageEvidenceRequiresEveryFailureMode(t *testing.T) {
	ids := []string{"all_servers_down", "runner_stopped", "xray_dead_runner_up", "control_stopped", "early_reboot", "recovery"}
	reports := make([]m3Observation, len(ids))
	for i, id := range ids {
		reports[i] = m3Observation{id: id, passed: true, elapsed: time.Second}
	}
	dir := t.TempDir()
	if err := writeM3Evidence(dir, "7.25", lab.ArchX86, "m3-outage", reports, false); err != nil {
		t.Fatal("complete outage catalogue unavailable")
	}
	if err := writeM3Evidence(dir, "7.25", lab.ArchX86, "m3-outage", reports[:5], false); err == nil {
		t.Fatal("missing recovery counted as complete")
	}
}
