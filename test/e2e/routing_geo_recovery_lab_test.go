//go:build lab

package e2e

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

// TestM3GeoRecovery interrupts control after the independent runner reports
// that the new xray is actually on trial. Only the service writes the journal.
func TestM3GeoRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Minute)
	defer cancel()
	f := deployRouting(ctx, t, t)
	const oldTag, newTag = "geo-recovery-a", "geo-recovery-b"
	const journal = dataRoot + "/state/geo-pending.json"
	f.stageGeoFixture(ctx, t, oldTag, routingRemote, true, false)
	f.stageGeoFixture(ctx, t, newTag, routingDomestic, true, false)
	route := f.route
	route.Domestic.IPs = nil
	if _, err := f.api.SetRouting(ctx, route); err != nil {
		t.Fatal("could not prepare recovery policy")
	}
	f.setClientPolicy(ctx, t, store.Policy{Mode: store.ModeSmart, KillSwitch: true})
	update := func(tag string) string {
		t.Helper()
		resp, err := f.api.GeoUpdate(ctx, "custom", tag)
		var res artifacts.Result
		if err != nil || resp.Decode(&res) != nil || res.Kind != artifacts.KindGeo || res.Outcome != runnerapi.OutcomeCommitted || !runnerapi.ValidGeoName(res.To) {
			t.Fatal("could not commit recovery fixture release", apiEvidence(err))
		}
		return res.To
	}
	current := func() runnerapi.Selection {
		t.Helper()
		var s runnerapi.Selection
		if json.Unmarshal(f.exactFile(ctx, t, dataRoot+"/run/active.json"), &s) != nil || s.Validate() != nil {
			t.Fatal("committed recovery selection unreadable")
		}
		return s
	}
	aSlot := update(oldTag)
	before := current()
	if before.Geo != aSlot {
		t.Fatal("old runner selection unverified")
	}
	const list = "/ip/firewall/address-list"
	id := func(cidr string) string { return f.taggedID(ctx, t, list, "tikray:domestic:"+cidr) }
	const shared = "93.184.215.0/30"
	aRange, bRange := routingRemote+"/32", routingDomestic+"/32"
	retained := id(shared)
	if retained == "" || id(aRange) == "" || id(bRange) != "" {
		t.Fatal("old geo list not established")
	}
	f.expectPath(ctx, t, routingRemote, false)
	f.expectPath(ctx, t, routingDomestic, true)
	ownerGeneration := f.ros.Generation()
	ssh := f.ownerLANSSH(ctx, t)
	peer := f.tcpFlow(ctx, t, true, 31375).directWitness(ctx, t)
	ownerLive := func() {
		t.Helper()
		ssh()
		rows, err := f.ros.CommandAt(ctx, ownerGeneration, []string{"/system/resource/print", "?version", "=.proplist=version"})
		if err != nil || len(rows) != 1 {
			t.Fatal("owner API session lost during geo recovery")
		}
		peer.requireLive(ctx, t)
		f.checkOwnerRules(ctx, t)
	}
	ownerLive()
	// Preserve the independent runner through its genuine trial deadline.
	// The owner disables only the installed control port to prevent a graceful
	// HTTP abort or commit from racing the subsequent control process stop.
	port := f.taggedID(ctx, t, "/interface/bridge/port", "tikray:port-ctl")
	control := f.taggedID(ctx, t, "/container", "tikray:tikray")
	runner := f.taggedID(ctx, t, "/container", "tikray:runner")
	sched := f.taggedID(ctx, t, "/system/scheduler", "tikray:watchdog-scheduler")
	if port == "" || control == "" || runner == "" || sched == "" {
		t.Fatal("owned outage fixture unavailable")
	}
	f.routingWrite(ctx, t, "/system/scheduler/disable", "=.id="+sched)
	defer func() {
		sub, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if _, err := f.ros.CommandAt(sub, ownerGeneration, []string{"/system/scheduler/enable", "=.id=" + sched}); err != nil {
			t.Error("could not restore owned watchdog")
		}
	}()

	req, stopRequest := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _, _ = f.api.GeoUpdate(req, "custom", newTag) }()
	defer func() {
		stopRequest()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("interrupted update request did not finish")
		}
	}()
	// Check the authenticated runner state, rather than treating mere
	// existence of candidate.json (written before xray -test) as a trial.
	inspect := `{:local b [/file/get [find where name="disk1/tikray/data/run/runner.token"] contents]; :set b [:pick $b 0 [:find ($b . "\n") "\n"]]; ` +
		`:local reply [/tool/fetch url="http://172.30.252.3:8080/v1/status" duration=3s http-header-field=("Authorization: Bearer " . $b) output=user as-value]; ` +
		`:local s [:deserialize from=json options=json.no-string-conversion value=($reply->"data")]; ` +
		`:if ((($s->"state")="trial") and (($s->"active"->"geo")="` + aSlot + `") and ([:len ($s->"candidate"->"geo")]>0) and (($s->"candidate"->"geo")!="` + aSlot + `") and (($s->"xray_pid")>0)) do={ :put "m3-live-geo-trial|yes|end" }}`
	observe, stopObserve := context.WithTimeout(ctx, 90*time.Second)
	_, live := poll(observe, 90*time.Second, 200*time.Millisecond, func() bool {
		v, e := f.CHR.RunPrivate(observe, inspect)
		return e == nil && strings.Contains(v, "m3-live-geo-trial|yes|end")
	})
	stopObserve()
	if !live {
		t.Fatal("did not observe a real running candidate before interruption")
	}
	f.routingWrite(ctx, t, "/interface/bridge/port/disable", "=.id="+port)
	stopRequest()
	f.routingWrite(ctx, t, "/container/stop", "=.id="+control)
	if f.waitForContainer(ctx, "tikray", "stopped") != nil {
		t.Fatal("control did not stop inside the real trial")
	}

	var pending struct {
		From, To runnerapi.Selection
		Deadline time.Time `json:"trial_deadline"`
	}
	if json.Unmarshal(f.exactFile(ctx, t, journal), &pending) != nil || pending.From != before || pending.To.Validate() != nil || pending.To.Geo == before.Geo || pending.To.Geo == "" || pending.Deadline.IsZero() {
		t.Fatal("stopped daemon left no verifiable pending transaction")
	}
	if id(shared) != retained || id(aRange) != "" || id(bRange) != "" {
		t.Fatal("interruption lost a retained range or prematurely admitted an exemption")
	}
	ownerLive()
	// A receipt from a previously completed trial is insufficient. Require the
	// exact selection + deadline of this request and autonomous runner expiry.
	expiry, stopExpiry := context.WithTimeout(ctx, 4*time.Minute)
	defer stopExpiry()
	_, expired := poll(expiry, 4*time.Minute, time.Second, func() bool {
		raw, e := f.CHR.RunPrivate(expiry, `{:local p [/file/find where name="disk1/tikray/data/run/last-trial.json"]; :if ([:len $p]=1) do={:local r [:deserialize from=json value=[/file/get $p contents]]; :put ("m3-geo-result|" . ($r->"outcome") . "|end")}}`)
		return e == nil && strings.Contains(raw, "m3-geo-result|deadline|end")
	})
	if !expired {
		t.Fatal("runner did not autonomously roll back the orphaned trial")
	}
	var last runnerapi.TrialResult
	if json.Unmarshal(f.exactFile(ctx, t, dataRoot+"/run/last-trial.json"), &last) != nil || last.Outcome != runnerapi.OutcomeDeadline || last.Candidate.Selection != pending.To || !last.Candidate.Deadline.Equal(pending.Deadline) || current() != before {
		t.Fatal("expired runner trial did not restore the exact previous selection")
	}
	if len(f.readROS(ctx, t, "/container", ".id", "?.id="+control, "?stopped=true")) != 1 || len(f.readROS(ctx, t, "/container", ".id", "?.id="+runner, "?running=true")) != 1 {
		t.Fatal("control did not stay stopped with independent runner alive")
	}
	if yes, e := f.exists(ctx, journal); e != nil || !yes {
		t.Fatal("unverified outage retired the geo journal")
	}
	f.routingWrite(ctx, t, "/interface/bridge/port/enable", "=.id="+port)
	f.routingWrite(ctx, t, "/container/start", "=.id="+control)
	f.checkReady(ctx, t)
	if yes, e := f.exists(ctx, journal); e != nil || yes || current() != before || id(shared) != retained || id(aRange) == "" || id(bRange) != "" {
		t.Fatal("restarted service did not settle the previous runner and router policy")
	}
	f.expectPath(ctx, t, routingRemote, false)
	f.expectPath(ctx, t, routingDomestic, true)
	ownerLive()
	bSlot := update(newTag)
	if active := current(); active != pending.To || active.Geo != bSlot || id(shared) != retained || id(aRange) != "" || id(bRange) == "" {
		t.Fatal("owner could not make a fresh update after recovery")
	}
	f.expectPath(ctx, t, routingRemote, true)
	f.expectPath(ctx, t, routingDomestic, false)
	ownerLive()
	t.Logf("CHR %s %s: the runner reverted the orphaned trial. The restarted service restored both LAN paths, preserved the owner session and committed a subsequent update", f.Version, f.Arch)
}
