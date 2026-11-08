//go:build lab

package m3

import (
	"strconv"
	"strings"
	"testing"
	"time"

	routerosfiles "github.com/Arman2122/tikray/routeros"
)

// Match the production scheduler's policy and invocation. A manual test alone
// cannot prove that a scheduled tick is visible to the job guard or that
// successive jobs can access the persisted failure receipt.
func TestWatchdogSchedulerIdentity(t *testing.T) {
	r := newRig(t)
	const name = "m3-wd-identity"
	run := func(args ...string) {
		t.Helper()
		if _, err := r.admin.RunArgsContext(r.ctx, args); err != nil {
			t.Fatal("watchdog scheduler identity fixture command refused")
		}
	}
	run("/system/script/add", "=name=m3-wd-receipt", "=policy=read,write,test", "=source=")
	stateSource, e := routerosfiles.Sources.ReadFile("watchdog-state.rsc")
	if e != nil {
		t.Fatal(e)
	}
	step, e := routerosfiles.Sources.ReadFile("watchdog-step.rsc")
	if e != nil {
		t.Fatal(e)
	}
	source := "{\n" + string(stateSource) + "\n" + string(step) + `
        :local receipt [$wdState "init"]
        :local prior ($receipt->"tikray")
        :if ([:typeof $prior] != "array") do={ :set prior [:toarray ""] }
        :local now ([:tonsec [/system/resource/get uptime]]/1000000000)
        :local state [$wdStep $prior false $now]
        :if ([$wdState "save" "tikray" $state $now] != true) do={ :error "bad save" }
        :local named [:len [/system/script/job/find where script="m3-wd-identity"]]
        :local actual [:jobname]
        /system/script/set [find name="m3-wd-receipt"] comment=(($state->"miss") . "|" . $named . "|" . ($actual="m3-wd-identity"))
    }`
	run("/system/script/add", "=name="+name, "=policy=read,write,test", "=source="+source)
	for range 2 {
		run("/system/script/run", "=number="+name)
	}
	read := func() (int, int, bool) {
		v, e := r.chr.RunPrivate(r.ctx, `:put [/system/script/get [find name="m3-wd-receipt"] comment]`)
		if e != nil {
			t.Fatal("receipt unreadable")
		}
		parts := strings.Split(strings.TrimSpace(v), "|")
		if len(parts) != 3 {
			t.Fatal("missing tick receipt")
		}
		n, _ := strconv.Atoi(parts[0])
		jobs, _ := strconv.Atoi(parts[1])
		return n, jobs, parts[2] == "true"
	}
	if n, j, _ := read(); n != 2 || j != 1 {
		t.Fatalf("manual witnesses ticks=%d jobs=%d", n, j)
	}
	run("/system/scheduler/add", "=name="+name, "=interval=2s", "=start-time=startup", "=on-event="+name, "=policy=read,write,test")
	deadline := time.Now().Add(18 * time.Second)
	for time.Now().Before(deadline) {
		q, e := r.admin.RunContext(r.ctx, "/system/scheduler/print", "?name="+name, "=.proplist=run-count")
		if e == nil && len(q.Re) == 1 && q.Re[0].Map["run-count"] != "" && q.Re[0].Map["run-count"] != "0" {
			time.Sleep(250 * time.Millisecond)
			n, j, own := read()
			if j != 1 || !own {
				t.Fatalf("scheduled witnesses ticks=%d jobs=%d matching-jobname=%t", n, j, own)
			}
			if n == 3 {
				t.Log("a native scheduled tick advanced the same receipt from two misses to three")
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("native scheduled tick did not advance the protected receipt")
}
