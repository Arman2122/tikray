//go:build lab

package m3

import (
	"regexp"
	"strings"
	"testing"

	routerosfiles "github.com/Arman2122/tikray/routeros"
)

// Exercise the exact transition used in the scheduler, with deterministic
// uptime samples. Router downtime cannot turn a later deadline into a storm.
func TestBasicWatchdogBackoffAndRecovery(t *testing.T) {
	step, e := routerosfiles.Sources.ReadFile("watchdog-step.rsc")
	if e != nil {
		t.Fatal("watchdog transition missing")
	}
	r := newRig(t)
	src := `{ ` + string(step) + `
	:local state [:toarray ""]
	:local restarts [:toarray ""]
	:for minute from=1 to=39 do={
		:set state [$wdStep $state false (60 * $minute)]
		:if ($state->"restart") do={ :set restarts ($restarts,$minute) }
	}
	:if ([:tostr $restarts] != "3;4;6;10;18;33") do={ :error "restart intervals" }
	:set state [$wdStep $state true 2400]
	:if ((($state->"miss") != 0) or (($state->"delay") != 1) or ($state->"restart")) do={ :error "recovery" }
	:local peer [$wdStep [:toarray ""] false 2460]
	:if ((($peer->"miss") != 1) or (($state->"miss") != 0)) do={ :error "component isolation" }
	:put "verified" }`
	add, e := r.admin.RunContext(r.ctx, "/system/script/add", "=name=watchdog-state-probe", "=source="+src)
	if e != nil || add.Done == nil {
		t.Fatal("watchdog fixture not installed")
	}
	if _, e = r.admin.RunContext(r.ctx, "/system/script/run", "=.id="+add.Done.Map["ret"]); e != nil {
		for _, marker := range []string{"restart intervals", "recovery", "component isolation", "syntax error", "expected", "operation", "not a valid"} {
			if strings.Contains(e.Error(), marker) {
				t.Fatal("watchdog fixture", marker, regexp.MustCompile(`line [0-9]+ column [0-9]+`).FindString(e.Error()))
			}
		}
		t.Fatal("watchdog state machine failed")
	}
}
