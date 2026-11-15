//go:build lab

package m3

import (
	"context"
	"maps"
	"strings"
	"testing"
	"time"
)

type stoppedRunnerCase struct {
	f           *nativeImageCase
	old, active map[string]any
	id          string
	state       func(any)
	check       func(string, map[string]any) bool
	marker      func(string, map[string]any, map[string]any, any)
}

func newStoppedRunnerCase(t *testing.T) *stoppedRunnerCase {
	t.Helper()
	f := newNativeImageCase(t)
	runnerRef := func(ref map[string]any) map[string]any {
		out := maps.Clone(ref)
		out["component"] = "runner"
		h := out["digest"].(string)
		f.pub(f.data+"/images/runner-"+h+".tar", f.archiveBytes[h])
		return out
	}
	old, active := runnerRef(f.first), runnerRef(f.second)
	state := func(previous any) {
		f.write("image-runner.receipt", map[string]any{"version": 1, "installation_id": nativeImageIdentity, "active": active, "previous": previous})
	}
	f.write("image-bootstrap.receipt", map[string]any{"version": 1, "arch": "amd64", "publisher": "fixture", "tikray": f.first, "runner": old})
	f.write("install.request", map[string]any{"scope": map[string]string{"lan_list": "m3-images-lan"}})
	state(old)
	f.run(`/interface/veth/add name=tikray-runner comment="tikray:veth-runner" address=172.27.248.3/29 gateway=172.27.248.1`)
	root := strings.TrimSuffix(f.data, "/data") + "/containers/runner"
	f.run(`/container/add name=tikray-runner comment="tikray:runner" interface=tikray-runner file="` + f.data + "/images/runner-" + active["digest"].(string) + `.tar" root-dir="` + root + `" envlists=tikray-runner mountlists=tikray-runner dns=172.27.248.1 memory-high=201326592 memory-max=268435456 restart-policy=on-failure start-on-boot=yes logging=no`)
	check := func(condition string, ref map[string]any) bool {
		t.Helper()
		return ownerWait(f.r.ctx, 20*time.Second, func(ctx context.Context) (bool, error) {
			v, e := f.r.chr.RunPrivate(ctx, `{:local id [/container/find where name=tikray-runner and comment="tikray:runner" and `+condition+`]; :if ([:len $id]=1) do={:local v [:tostr [/container/get $id image-id]]; :put (($v="`+ref["image_id"].(string)+`") or ($v="sha256:`+ref["image_id"].(string)+`"))}}`)
			return strings.TrimSpace(v) == "true", e
		}) == nil
	}
	if !check("stopped", active) {
		t.Fatal("stopped runner fixture unavailable")
	}
	id := f.run(`:put [:tostr [/container/find where name=tikray-runner and stopped]]`)
	marker := func(target string, from, to map[string]any, flag any) {
		m := map[string]any{"version": 1, "installation_id": nativeImageIdentity, "phase": "requested", "component": target, "previous": from, "candidate": to, "selection_digest": strings.Repeat("e", 64), "started": 1000, "deadline": 1300, "nonce": strings.Repeat("f", 32)}
		if flag != nil {
			m["offline_rollback"] = flag
		}
		f.write("image-update.request", m)
	}
	return &stoppedRunnerCase{f, old, active, id, state, check, marker}
}

// An authenticated offline rollback targets only the exact committed previous
// runner. Native ownership and actual stopped state must both still agree.
func TestNativeStoppedRunnerReturnsCommittedImage(t *testing.T) {
	c := newStoppedRunnerCase(t)
	f, old, active, id, state, check, marker := c.f, c.old, c.active, c.id, c.state, c.check, c.marker
	// An explicitly false field is not a new authorization, and the stopped
	// runner capability cannot be extended to the control image.
	for _, bad := range []any{false, "true", 1} {
		marker("runner", active, old, bad)
		if got := f.tick(); got != "image: invalid request" {
			t.Fatalf("invalid offline capability was accepted (%s)", got)
		}
	}
	marker("tikray", f.first, f.second, true)
	if got := f.tick(); got != "image: invalid request" {
		t.Fatal("cross-role offline authorization", got)
	}
	// A previous ref with the same role and image ID but altered archive
	// evidence still cannot authorize removing the existing stopped row.
	wrong := maps.Clone(old)
	wrong["chain"] = strings.Repeat("c", 128)
	state(wrong)
	marker("runner", active, old, true)
	if got := f.tick(); got != "image: unverified offline rollback" {
		t.Fatalf("ambiguous previous archive changed the stopped row (%s)", got)
	}
	if f.run(`:put [:tostr [/container/find where name=tikray-runner and stopped]]`) != id {
		t.Fatal("refusal changed the original native ID")
	}
	state(old)
	marker("runner", active, old, true)
	if got := f.tick(); got != "" || !check("running", old) {
		t.Fatalf("stopped runner did not return to the exact committed previous image (%s)", got)
	}
	if f.run(`:put [:len [/file/find where name="disk1/tikray-phases/data/state/image-update.request"]]`) != "1" {
		t.Fatal("offline rollback cleared without verified service proof")
	}
}

// A running owner process can be stopped for maintenance after an offline
// API observation. Conversely an already stopped process can be started by
// the owner during preparation. Neither event transfers the earlier consent.
func TestNativeStoppedRunnerConsentDoesNotFollowLaterState(t *testing.T) {
	for _, originally := range []string{"running", "stopped"} {
		t.Run(originally, func(t *testing.T) {
			c := newStoppedRunnerCase(t)
			f := c.f
			setupRunnerImageRouting(t, f.r, f.run, "172.27.248.3")
			f.run(`:for i from=61 to=96 do={:local a ("192.168.88." . $i); /ip/firewall/address-list/add list=tikray-src-full-open address=$a comment=("tikray:src-full-open:" . $a . "/32")}`)
			if originally == "running" {
				f.run(`/container/start [find where name=tikray-runner and stopped]`)
				if !c.check("running", c.active) {
					t.Fatal("original runner did not start")
				}
			}
			c.marker("runner", c.active, c.old, true)
			if got := f.tick(); got != "" || !c.check(originally, c.active) {
				t.Fatalf("original state changed before preparation completed (%s)", got)
			}
			next := "running"
			if originally == "running" {
				next = "stopped"
				f.run(`/container/stop [find where name=tikray-runner and running]`)
			} else {
				f.run(`/container/start [find where name=tikray-runner and stopped]`)
			}
			if !c.check(next, c.active) {
				t.Fatal("owner lifecycle change failed")
			}
			got := f.tick()
			if originally == "stopped" && got != "image: offline rollback baseline changed" {
				t.Fatalf("later maintenance start was not positively refused (%s)", got)
			}
			if f.run(`:put [:tostr [/container/find where name=tikray-runner and comment="tikray:runner"]]`) != c.id || !c.check(next, c.active) {
				t.Fatal("offline permission followed a later owner lifecycle change")
			}
		})
	}
}
