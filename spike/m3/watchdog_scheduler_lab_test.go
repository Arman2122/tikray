//go:build lab

package m3

import (
	"encoding/base64"
	"regexp"
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

func TestWatchdogInactiveExitsCleanly(t *testing.T) {
	r := newRig(t)
	body, e := routerosfiles.Sources.ReadFile("watchdog.rsc")
	if e != nil {
		t.Fatal(e)
	}
	source := string(body)
	for _, part := range []struct{ key, file string }{{"STEP", "watchdog-step.rsc"}, {"STATE", "watchdog-state.rsc"}} {
		b, e := routerosfiles.Sources.ReadFile(part.file)
		if e != nil {
			t.Fatal(e)
		}
		source = strings.ReplaceAll(source, "# @TIKRAY_WATCHDOG_"+part.key+"@", string(b))
	}
	source = strings.ReplaceAll(source, "# @TIKRAY_WATCHDOG_HEALTH@", `:error "unexpected health probe"`)
	add, e := r.admin.RunContext(r.ctx, "/system/script/add", "=name=tikray-watchdog", "=policy=read,write,test", "=source="+source)
	if e != nil || add.Done == nil {
		t.Fatal("fixture script add")
	}
	run := func() {
		t.Helper()
		if _, e := r.admin.RunContext(r.ctx, "/system/script/run", "=.id="+add.Done.Map["ret"]); e != nil {
			out, _ := r.chr.RunPrivate(r.ctx, `:onerror reason in={ /system/script/run tikray-watchdog } do={ :put ("wd-reason=" . [:convert $reason to=base64]) }`)
			_, raw, _ := strings.Cut(out, "wd-reason=")
			msg, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
			text := strings.ToLower(e.Error() + " " + string(msg))
			pos := regexp.MustCompile(`line [0-9]+ column [0-9]+`).FindString(text)
			for _, s := range []string{"expected end of command", "expected command name", "syntax error", "not enough permissions", "invalid internal item number", "no such item", "script is too large", "script error", "unable to", "invalid value", "no such command", "executing script", "not enough", "not found", "argument"} {
				if strings.Contains(text, s) {
					t.Fatal("inactive watchdog", s, pos)
				}
			}
			t.Fatal("inactive watchdog rejected", pos)
		}
	}
	run()
	if _, e := r.admin.RunContext(r.ctx, "/system/script/add", "=name=tikray-emergency-state", "=source=", "=comment=tikray:emergency-state"); e != nil {
		t.Fatal("fixture emergency marker")
	}
	run()
}
