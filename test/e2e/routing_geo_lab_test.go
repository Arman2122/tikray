//go:build lab

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
	"google.golang.org/protobuf/encoding/protowire"
)

// Real GeoIPList and GeoSiteList records, as in test/compat/geodat.go. An
// optional OWNER list is an independent user rule, outside the publisher's
// domestic IR rules. Removing it makes real xray reject the candidate trial.
func (f *routingLab) stageGeoFixture(ctx context.Context, t *testing.T, tag, public string, ownerSite, damage bool) {
	t.Helper()
	field := func(num protowire.Number, payload []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(nil, num, protowire.BytesType), payload)
	}
	entry := func(code string, records ...[]byte) []byte {
		b := field(1, []byte(code))
		for _, r := range records {
			b = append(b, field(2, r)...)
		}
		return field(1, b)
	}
	cidr := func(prefix netip.Prefix) []byte {
		b := field(1, prefix.Addr().AsSlice())
		return protowire.AppendVarint(protowire.AppendTag(b, 2, protowire.VarintType), uint64(prefix.Bits()))
	}
	domain := func(name string) []byte {
		return append([]byte{8, 2}, field(2, []byte(name))...) // Domain type root.
	}
	const shared = "93.184.215.0/30"
	one := netip.PrefixFrom(netip.MustParseAddr(public), 32)
	sites := entry("IR", domain("fixture-geo.ir"))
	if ownerSite {
		sites = append(sites, entry("OWNER", domain("owner-geo.test"))...)
	}
	payloads := map[string][]byte{"geoip.dat": entry("IR", cidr(netip.MustParsePrefix(shared)), cidr(one)), "geosite.dat": sites,
		"domestic-v4.txt": []byte(shared + "\n" + one.String() + "\n")}
	sums := map[string]string{}
	for k, b := range payloads {
		sum := sha256.Sum256(b)
		sums[k] = hex.EncodeToString(sum[:])
	}
	if damage {
		payloads["domestic-v4.txt"] = []byte("corrupted fixture")
	}
	manifest, e := json.Marshal(map[string]any{"version": tag, "site": []string{"geosite:ir"}, "ip": []string{"geoip:ir"}, "sha256": sums})
	if e != nil {
		t.Fatal("could not encode the lab publisher proof")
	}
	// An expected checksum in the payload inbox must never authenticate the
	// same payload. Install the owner's expected manifest on the private
	// control volume independently of the untrusted upload directory.
	put := func(path, file string, b []byte) {
		t.Helper()
		dir := dataRoot
		for _, part := range strings.Split(path, "/") {
			dir += "/" + part
			f.mustRun(ctx, t, `:if ([:len [/file/find where name="`+dir+`"]] = 0) do={ /file/add type=directory name="`+dir+`" }`)
		}
		local := filepath.Join(t.TempDir(), file)
		if os.WriteFile(local, b, 0600) != nil || f.CHR.Push(ctx, local, dir+"/"+file) != nil {
			t.Fatal("could not stage public lab geo fixture")
		}
	}
	put("state/geo-trust/custom/"+tag, "meta.json", manifest)
	for path, b := range payloads {
		put("inbox/geo/custom/"+tag, path, b)
	}
}

func (f *routingLab) geoDiffAndRollback(ctx context.Context, t *testing.T) {
	t.Helper()
	const a, b, shared = "geo-fixture-a", "geo-fixture-b", "93.184.215.0/30"
	f.stageGeoFixture(ctx, t, a, routingRemote, true, false)
	f.stageGeoFixture(ctx, t, b, routingDomestic, true, false)
	f.stageGeoFixture(ctx, t, "geo-fixture-bad-checksum", routingRemote, true, true)
	f.stageGeoFixture(ctx, t, "geo-fixture-rejected", routingRemote, false, false)
	route := f.route
	route.Domestic.IPs = nil
	if _, err := f.api.SetRouting(ctx, route); err != nil {
		t.Fatal("could not prepare domestic geo paths")
	}
	f.setClientPolicy(ctx, t, store.Policy{Mode: store.ModeSmart, KillSwitch: true})
	f.expectPath(ctx, t, routingRemote, true)
	f.expectPath(ctx, t, routingDomestic, true)
	// Distinguish RouterOS's direct exemption from xray independently making
	// the same direct decision using geoip.dat. Only a fresh LAN SYN leaving
	// ether1 with its original .10 source can hit these observations.
	const mangle = "/ip/firewall/mangle"
	for _, dst := range []string{routingRemote, routingDomestic} {
		f.routingWrite(ctx, t, mangle+"/add", "=chain=postrouting", "=action=passthrough", "=out-interface=ether1", "=src-address="+lanClient.Addr().String(), "=dst-address="+dst, "=protocol=tcp", "=dst-port=80", "=tcp-flags=syn", "=comment=lab:geo-bypass-"+dst)
	}
	checkPaths := func(remoteProxy bool) {
		t.Helper()
		for _, dst := range []string{routingRemote, routingDomestic} {
			tag := "lab:geo-bypass-" + dst
			proxied := (dst == routingRemote) == remoteProxy
			before := f.packets(ctx, t, mangle, tag)
			f.expectPath(ctx, t, dst, proxied)
			after := f.packets(ctx, t, mangle, tag)
			if (proxied && after != before) || (!proxied && after <= before) {
				t.Fatal("actual RouterOS domestic bypass disagrees with egress")
			}
		}
		if f.peerEgress(ctx, routingRemote) != egressDirect || f.peerEgress(ctx, routingDomestic) != egressDirect {
			t.Fatal("geo change disrupted the ordinary peer")
		}
		f.checkOwnerRules(ctx, t)
	}
	update := func(tag, want string) string {
		t.Helper()
		resp, err := f.api.GeoUpdate(ctx, "custom", tag)
		var res artifacts.Result
		if err != nil || resp.Decode(&res) != nil || res.Kind != artifacts.KindGeo || res.Outcome != want || !runnerapi.ValidGeoName(res.To) {
			t.Fatal("geo service did not return the required outcome", tag, want, apiEvidence(err))
		}
		return res.To
	}
	active := func() runnerapi.Selection {
		t.Helper()
		var s runnerapi.Selection
		if json.Unmarshal(f.exactFile(ctx, t, dataRoot+"/run/active.json"), &s) != nil || s.Validate() != nil {
			t.Fatal("could not verify committed runner selection")
		}
		return s
	}
	failed := func(tag, outcome string) {
		t.Helper()
		_, err := f.api.GeoUpdate(ctx, "custom", tag)
		var ae *apiclient.Error
		if !errors.As(err, &ae) || ae.Result == nil || ae.Result.Kind != artifacts.KindGeo || ae.Result.Outcome != outcome {
			t.Fatal("geo operation did not produce the expected rejection", tag, outcome, apiEvidence(err))
		}
	}
	aSlot := update(a, runnerapi.OutcomeCommitted)
	if active().Geo != aSlot {
		t.Fatal("first geo release was not the committed runner selection")
	}
	checkPaths(false)
	// This rule survives separately from the publisher's metadata. A third
	// correctly checksummed bundle that lacks OWNER must fail in xray -test.
	route.Domestic.Domains = append(append([]string{}, route.Domestic.Domains...), "geosite:owner")
	if _, err := f.api.SetRouting(ctx, route); err != nil {
		t.Fatal("could not add independent geosite rule")
	}
	f.checkReady(ctx, t)
	const menu = "/ip/firewall/address-list"
	id := func(cidr string) string { return f.taggedID(ctx, t, menu, "tikray:domestic:"+cidr) }
	aRange, bRange := routingRemote+"/32", routingDomestic+"/32"
	retained, old := id(shared), id(aRange)
	if retained == "" || old == "" || id(bRange) != "" {
		t.Fatal("candidate A did not produce the expected domestic membership")
	}
	// A named foreign member cannot be overwritten by a transaction.
	const ownerTag = "lab:geo-owned-elsewhere"
	f.routingWrite(ctx, t, menu+"/add", "=list=tikray-domestic", "=address="+bRange, "=comment="+ownerTag)
	ownerID := f.taggedID(ctx, t, menu, ownerTag)
	if ownerID == "" {
		t.Fatal("missing positive owner membership witness")
	}
	before := active()
	_, err := f.api.GeoUpdate(ctx, "custom", b)
	if err == nil || active() != before || id(shared) != retained || id(aRange) != old || id(bRange) != "" || f.taggedID(ctx, t, menu, ownerTag) != ownerID {
		t.Fatal("foreign membership was lost or shared policy mutated")
	}
	f.routingWrite(ctx, t, menu+"/remove", "=.id="+ownerID)
	f.checkReady(ctx, t)
	previousRows := f.policyInventory(ctx, t)
	bSlot := update(b, runnerapi.OutcomeCommitted)
	next := active()
	if next.Geo != bSlot || next.Geo == aSlot || next.Core != before.Core || id(shared) != retained || id(aRange) != "" || id(bRange) == "" {
		t.Fatal("second release replaced a retained row or failed to switch its own range")
	}
	checkPaths(true)
	inventory := f.policyInventory(ctx, t)
	wantRows := maps.Clone(previousRows)
	delete(wantRows, menu+"|tikray:domestic:"+aRange)
	wantRows[menu+"|tikray:domestic:"+bRange] = id(bRange)
	if !maps.Equal(inventory, wantRows) {
		t.Fatal("changing one geo exemption rewrote other RouterOS rows")
	}
	process := f.probe(ctx, t, "runner")
	if update(b, artifacts.OutcomeNoop) != bSlot || active() != next || f.probe(ctx, t, "runner") != process || !maps.Equal(inventory, f.policyInventory(ctx, t)) {
		t.Fatal("identical geo release disturbed runner or RouterOS")
	}
	failed("geo-fixture-bad-checksum", artifacts.OutcomeRefused)
	if active() != next || !maps.Equal(inventory, f.policyInventory(ctx, t)) {
		t.Fatal("bad checksum changed the verified policy")
	}
	failed("geo-fixture-rejected", runnerapi.OutcomeRejected)
	f.checkReady(ctx, t)
	if active() != next || id(shared) != retained || id(bRange) == "" || id(aRange) != "" {
		t.Fatal("rejected real runner trial did not restore candidate B")
	}
	checkPaths(true)
	resp, err := f.api.GeoRollback(ctx)
	var res artifacts.Result
	if err != nil || resp.Decode(&res) != nil || res.Kind != artifacts.KindGeo || res.Outcome != runnerapi.OutcomeCommitted || res.From != bSlot || res.To != aSlot || active() != before || id(shared) != retained || id(aRange) == "" || id(bRange) != "" {
		t.Fatal("geo rollback did not restore prior selection and domestic ranges")
	}
	checkPaths(false)
}
