//go:build lab

package e2e

import (
	"encoding/json"
	"errors"
	"flag"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/atomicfile"
	"github.com/Arman2122/tikray/test/lab"
)

type evidenceCase struct{ id, detail string }

// Only these public descriptions, a verdict and an elapsed time can be
// serialized. Router replies and client-supplied values never enter a report.
var m3Cases = map[string][]evidenceCase{
	"m3-install": {
		{"preflight", "DNS, overlap, ownership and archive-integrity preflights refused unsafe installation."},
		{"clean_install", "The signed core booted, the public ID matched the receipt and the source-restricted account passed its permission controls."},
		{"bridge_acl", "LAN HTTPS access, private service isolation and owner forwarding were checked with live traffic."},
		{"second_import", "Healthy reimport preserved owner access, installation identity and running processes. The stopped control command was repaired."},
		{"interrupted_install", "Management remained available and admission stayed gated until signed bootstrap recovered."},
		{"basic_watchdog", "Real scheduled recovery, wrong-service refusal, component isolation, backoff and emergency suppression passed."},
	},
	"m3-routing": {
		{"policy_paths", "Direct, smart and full policy paths were distinguished by actual LAN egress and proxy observations."},
		{"source_and_fasttrack", "Original source, owned marks, MSS and the FastTrack exception were verified with an unaffected peer."},
		{"policy_mid_connection", "The affected connection changed path and the independent connection survived."},
		{"failover", "After the selected server stopped, the LAN client reached the other proxy egress."},
		{"dns_paths", "Native and steered DNS traffic reached the expected resolvers over TCP and UDP."},
		{"ipv6_guard", "The proxied client encountered the IPv6 guard and the direct client retained external IPv6 connectivity."},
		{"quic_sniff", "Real QUIC Initial packets distinguished name-based routing at the same destination address."},
		{"drift_repair", "The service repaired owned drift. The WAN-side witness saw no closed-client leak during route loss."},
		{"emergency_off", "Two owner commands restored ordinary routing with both containers stopped. Service recovery restored steering and protection."},
	},
	"m3-uninstall": {
		{"keep_data", "Default keep restored routing and API access. Reinstall preserved the claimed admin, settings, UI identity and core."},
		{"purge_owned_data", "Explicit purge removed the verified data root and owned bindings, and preserved the external owner data."},
		{"shared_reference_refuses", "Foreign references, missing service proof and certificate substitution refused teardown."},
		{"interrupted_and_repeat", "Removal resumed after a real interruption, restored ordinary traffic and repeated without owner changes."},
	},
}

type m3Observation struct {
	id      string
	passed  bool
	elapsed time.Duration
}

func (l *Lab) recordM3Checks(t *testing.T, suite string) func(string, func(*testing.T)) {
	t.Helper()
	var observations []m3Observation
	t.Cleanup(func() {
		filtered := strings.Contains(flag.Lookup("test.run").Value.String(), "/")
		partial := filtered || t.Failed()
		err := writeM3Evidence(resultDirectory(), l.Version, l.Arch, suite, observations, partial)
		if err != nil {
			t.Error(err)
		}
	})
	return func(id string, check func(*testing.T)) {
		t.Helper()
		t.Run(id, func(st *testing.T) {
			start := time.Now()
			completed := false
			defer func() {
				observations = append(observations, m3Observation{id, completed && !st.Failed() && !st.Skipped(), time.Since(start)})
			}()
			check(st)
			completed = true
		})
	}
}

func writeM3Evidence(dir, version string, arch lab.Arch, suite string, obs []m3Observation, partial bool) error {
	cases := m3Cases[suite]
	invalid := errors.New("e2e: incomplete or invalid M3 evidence")
	if len(cases) == 0 || len(obs) == 0 || (version != "7.25" && version != "7.23.8") || (arch != lab.ArchX86 && arch != lab.ArchARM64) {
		return invalid
	}
	byID := make(map[string]m3Observation, len(obs))
	for _, o := range obs {
		_, duplicate := byID[o.id]
		if duplicate || o.elapsed < 0 || (!partial && (!o.passed || o.elapsed == 0)) {
			return invalid
		}
		byID[o.id] = o
	}
	var rows []result
	for _, c := range cases {
		o, ok := byID[c.id]
		if !ok {
			if partial {
				continue
			}
			return invalid
		}
		delete(byID, c.id)
		detail := c.detail
		if !o.passed {
			detail = "Check did not complete successfully."
		}
		rows = append(rows, result{ID: c.id, Pass: o.passed, Detail: detail, Seconds: math.Round(o.elapsed.Seconds()*1000) / 1000})
	}
	if len(byID) != 0 {
		return invalid
	}
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return invalid
	}
	base := version + "-" + string(arch) + "-" + suite
	if partial {
		base += "-partial"
	}
	if os.MkdirAll(dir, 0755) != nil || atomicfile.WriteFile(filepath.Join(dir, base+".json"), append(b, '\n'), 0644) != nil {
		return errors.New("e2e: could not store M3 evidence")
	}
	return nil
}
