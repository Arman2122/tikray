//go:build lab

package m3

import (
	"context"
	"encoding/json"
	"maps"
	"strings"
	"testing"
	"time"
)

func TestNativeLargeRunnerPreparationPreservesTrialWindow(t *testing.T) {
	f := newNativeImageCase(t)
	setupRunnerImageRouting(t, f.r, f.run, "172.27.248.3")
	stage := func(ref map[string]any) map[string]any {
		t.Helper()
		out := maps.Clone(ref)
		out["component"] = "runner"
		hash := out["digest"].(string)
		f.pub(f.data+"/images/runner-"+hash+".tar", f.archiveBytes[hash])
		return out
	}
	old, next := stage(f.first), stage(f.second)
	f.write("image-bootstrap.receipt", map[string]any{"version": 1, "arch": "amd64", "publisher": "fixture", "tikray": f.first, "runner": old})
	f.write("image-runner.receipt", map[string]any{"version": 1, "installation_id": nativeImageIdentity, "active": old, "previous": nil})
	f.write("install.request", map[string]any{"scope": map[string]string{"lan_list": "m3-images-lan"}})
	f.run(`/interface/veth/add name=tikray-runner comment="tikray:veth-runner" address=172.27.248.3/29 gateway=172.27.248.1`)
	root := strings.TrimSuffix(f.data, "/data") + "/containers/runner"
	f.run(`/container/add name=tikray-runner comment="tikray:runner" interface=tikray-runner file="` + f.data + "/images/runner-" + old["digest"].(string) + `.tar" root-dir="` + root + `" envlists=tikray-runner mountlists=tikray-runner dns=172.27.248.1 memory-high=201326592 memory-max=268435456 restart-policy=on-failure start-on-boot=yes logging=no`)
	wait := func(check string) bool {
		t.Helper()
		return ownerWait(f.r.ctx, 65*time.Second, func(c context.Context) (bool, error) {
			s, e := f.r.chr.RunPrivate(c, check)
			return strings.TrimSpace(s) == "true", e
		}) == nil
	}
	if !wait(`:put ([:len [/container/find where comment="tikray:runner" and stopped]]=1)`) {
		t.Fatal("runner baseline import failed")
	}
	f.run(`/container/start [find where name=tikray-runner and comment="tikray:runner"]`)
	installed := func(ref map[string]any) bool {
		t.Helper()
		return f.run(`{:local c [/container/find where name=tikray-runner and comment="tikray:runner" and running];:if ([:len $c]=1) do={:local code [:tostr [/container/get [:pick $c 0] image-id]];:put ($code~"`+ref["image_id"].(string)+`")}}`) == "true"
	}
	if !wait(`:put ([:len [/container/find where comment="tikray:runner" and running]]=1)`) || !installed(old) {
		t.Fatal("runner baseline not running")
	}
	// Six batches of 24 still leave two prefixes: the fixture's initial open
	// client and 145 more static assignments. No live clients are needed.
	f.run(`:for n from=1 to=145 do={:local ip ("192.0.2." . $n); /ip/firewall/address-list/add list=tikray-src-full-open address=$ip comment=("tikray:src-full-open:" . $ip . "/32")}`)
	if !wait(`:put (([:tonsec [/system/resource/get uptime]]/1000000000)>65)`) {
		t.Fatal("fixture minute clock unavailable")
	}
	f.write("image-update.request", map[string]any{"version": 1, "installation_id": nativeImageIdentity, "component": "runner", "previous": old, "candidate": next, "selection_digest": strings.Repeat("a", 64), "phase": "requested", "nonce": nativeImageNonce, "started": 1000, "deadline": 1300})
	const pre = `:local id [:pick [/system/script/find where name=tikray-image-transition] 0]; :local prefix "tikray:image-transition "; :local j [:deserialize from=json options=json.no-string-conversion value=[:pick [/system/script/get $id comment] [:len $prefix] 4096]];`
	minute := func() {
		t.Helper()
		f.run("{" + pre + `:set ($j->"seen") (([:tonsec [/system/resource/get uptime]]/1000000000)-60); /system/script/set $id comment=($prefix . [:serialize to=json options=json.no-string-conversion value=$j])}`)
	}
	state := func() (string, int, int) {
		t.Helper()
		var j struct {
			Phase string
			Age   int
			Flow  struct{ Next int }
		}
		if json.Unmarshal([]byte(f.run("{"+pre+`:put [:serialize to=json options=json.no-string-conversion value=$j]}`)), &j) != nil {
			t.Fatal("missing native preparation journal")
		}
		return j.Phase, j.Age, j.Flow.Next
	}
	for tick := 0; tick < 6; tick++ {
		if tick != 0 {
			minute()
		}
		if e := f.tick(); e != "" {
			t.Fatal("runner preflight failed", e)
		}
		phase, age, consumed := state()
		if !installed(old) || (phase != "prepare" && phase != "replace") || age != 0 || consumed < 1 || consumed > 24*(tick+1) {
			t.Fatalf("old runner or trial clock changed during bounded preflight (batch %d, age %d, verified prefixes %d)", tick+1, age, consumed)
		}
	}
	// The work budget is a maximum. A busy CHR may complete fewer than
	// 24 prefixes per tick and expose the running flag after /container/start.
	awaitRunning := func(ref map[string]any) bool {
		t.Helper()
		id := ref["image_id"].(string)
		return wait(`{:local c [/container/find where name=tikray-runner and comment="tikray:runner" and running];:local ok false;:if ([:len $c]=1) do={:set ok ([:tostr [/container/get [:pick $c 0] image-id]]~"` + id + `")}; :put $ok}`)
	}
	phase, age, verified := state()
	for remaining := 0; phase != "verify" && remaining < 24; remaining++ {
		if phase == "prepare" {
			if age != 0 || !installed(old) {
				t.Fatalf("preparation disturbed running old image (age %d, prefixes %d)", age, verified)
			}
			minute()
		}
		if e := f.tick(); e != "" {
			t.Fatal("runner cutover failed", e)
		}
		phase, age, verified = state()
	}
	if phase != "verify" || age > 8 || !awaitRunning(next) {
		t.Fatalf("candidate did not receive a fresh trial after preflight (verify %t, age %d, prefixes %d)", phase == "verify", age, verified)
	}

	for i := 0; i < 4; i++ {
		minute()
		if e := f.tick(); e != "" {
			t.Fatal("unhealthy trial tick failed", e)
		}
		phase, age, _ = state()
		if !installed(next) || phase != "verify" || age < 60*(i+1) || age >= 300 {
			t.Fatal("earlier preparation consumed time from the active trial")
		}
	}
	minute()
	if e := f.tick(); e != "" || !awaitRunning(old) {
		t.Fatal("original runner did not return after actual trial expiry", e)
	}
}
