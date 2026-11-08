//go:build lab

package m3

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The long-term release predates the stable adapter evidence. Probe the actual
// CLI schema before permitting these properties on an owner's containers.
func TestM3InstallSchema(t *testing.T) {
	r := newRig(t)
	for _, field := range []string{"memory-high", "memory-max", "restart-policy"} {
		q, err := r.admin.RunContext(r.ctx, "/console/inspect", "=request=completion", "=input=/container/add "+field, "=.proplist=completion")
		found := false
		if err == nil {
			for _, s := range q.Re {
				if strings.TrimSuffix(s.Map["completion"], "=") == field {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("container field not demonstrated: %s", field)
		}
	}
	fp, err := r.chr.RunPrivate(r.ctx, `:put [:len [/certificate/get [find name=m3-cap-api] fingerprint]]`)
	if err != nil || strings.TrimSpace(fp) != "64" {
		t.Error("certificate lacks native SHA256 fingerprint")
	}
	archive, err := containerFixture(t.TempDir())
	if err != nil || r.chr.Push(r.ctx, archive, "disk1/install-schema.tar") != nil {
		t.Fatal("could not stage schema fixture")
	}
	if _, err = r.admin.RunContext(r.ctx, "/interface/veth/add", "=name=install-schema", "=address=172.29.246.2/29", "=gateway=172.29.246.1", "=comment=tikray:schema-veth"); err != nil {
		t.Fatal("schema veth rejected")
	}
	const tag = "tikray:schema-image"
	if _, err = r.admin.RunContext(r.ctx, "/container/add", "=name=install-schema", "=comment="+tag, "=file=disk1/install-schema.tar", "=interface=install-schema", "=dns=172.29.246.1", "=root-dir=disk1/install-schema", "=start-on-boot=no", "=memory-high=67108864", "=memory-max=134217728", "=restart-policy=on-failure"); err != nil {
		t.Fatal("schema verification rejected a supported container argument")
	}
	ready := ownerWait(r.ctx, time.Minute, func(ctx context.Context) (bool, error) {
		rows, e := r.admin.RunContext(ctx, "/container/print", "?name=install-schema", "?comment="+tag, "=.proplist=stopped,memory-high,memory-max,restart-policy")
		if e != nil || len(rows.Re) != 1 {
			return false, e
		}
		m := rows.Re[0].Map
		return m["stopped"] == "true" && m["memory-high"] == "67108864" && m["memory-max"] == "134217728" && m["restart-policy"] == "on-failure", nil
	})
	if ready != nil {
		t.Fatal("installed container limits or restart policy did not match")
	}
}

func TestCertificateReceiptSurvivesReimport(t *testing.T) {
	t4CertTest(t, false)
}
func TestReusedCertificateHasNoOwnershipReceipt(t *testing.T) {
	t4CertTest(t, true)
}
