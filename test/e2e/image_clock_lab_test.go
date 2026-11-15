//go:build lab

package e2e

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The journal comes from RouterOS. Bracket that read with its independent
// system uptime and scheduler count, discarding a read across a tick.
type imageClockReading struct {
	phase                              string
	age, seen, upBefore, upAfter, runs int
}

type imageClockEdge struct {
	imageClockReading
	earliest int // Uptime last observed before this scheduler invocation began.
}

var imageClockFrame = regexp.MustCompile(`m3-clock[|]([0-9]{1,19})[|](absent|verify|replace|prepare|restore|recover|commit|committed|reverted|unverified)[|]([0-9]+)[|]([0-9]+)[|]([0-9]+)[|]([0-9]+)[|]([0-9]+)[|]([0-9]+)[|]end`)

// Each value that reaches the host is a fixed phase, a public sequence, or
// a nonnegative counter. Leave the receipt's contents on the router.
const readImageClock = `{
    :local tick [/system/scheduler/find where name="tikray-watchdog" and comment="tikray:watchdog-scheduler"];
    :if ([:len $tick]!=1) do={ :error "clock unavailable" };
    :local before ([:tonsec [/system/resource/get uptime]]/1000000000);
    :local r1 [/system/scheduler/get [:pick $tick 0] run-count];
    :local age 0; :local seen 0; :local phase "absent";
    :local rows [/system/script/find where name="tikray-image-transition"];
    :if ([:len $rows]=1) do={
        :set phase "unverified";
        :local id [:pick $rows 0]; :local prefix "tikray:image-transition ";
        :local txt [/system/script/get $id comment];
        :if (([/system/script/get $id source]="") and ([:pick $txt 0 [:len $prefix]]=$prefix) and ([:len $txt]<=4096)) do={
            :local j [:deserialize from=json options=json.no-string-conversion value=[:pick $txt [:len $prefix] [:len $txt]]];
            :if ((($j->"nonce")="@nonce@") and ([:typeof ($j->"age")]="num") and ([:typeof ($j->"seen")]="num")) do={
                :foreach allowed in={"verify";"prepare";"replace";"restore";"recover";"commit";"committed";"reverted"} do={
                    :if (($j->"phase")=$allowed) do={ :set phase $allowed }
                };
                :set age ($j->"age"); :set seen ($j->"seen")
            }
        }
    };
    :local after ([:tonsec [/system/resource/get uptime]]/1000000000);
    :local r2 [/system/scheduler/get [:pick $tick 0] run-count];
    :put ("m3-clock|@sample@|" . $phase . "|" . $age . "|" . $seen . "|" . $before . "|" . $after . "|" . $r1 . "|" . $r2 . "|end")
}`

func (f *routingLab) imageClock(ctx context.Context, nonce string) (imageClockReading, bool) {
	if !imageNonce.MatchString(nonce) {
		return imageClockReading{}, false
	}
	ref := strconv.FormatInt(time.Now().UnixNano(), 10)
	command := strings.NewReplacer("\n", " ", "@nonce@", nonce, "@sample@", ref).Replace(readImageClock)
	wire, e := f.CHR.RunPrivate(ctx, command)
	m := imageClockFrame.FindStringSubmatch(wire)
	if e != nil || len(m) != 9 || m[1] != ref {
		return imageClockReading{}, false
	}
	var fields [6]int
	for i, v := range m[3:] {
		var err error
		fields[i], err = strconv.Atoi(v)
		if err != nil {
			return imageClockReading{}, false
		}
	}
	if fields[4] != fields[5] || fields[3] < fields[2] || fields[0] > 300 {
		return imageClockReading{}, false
	}
	return imageClockReading{m[2], fields[0], fields[1], fields[2], fields[3], fields[4]}, true
}

func (s imageClockEdge) accountsForUptime(p imageClockEdge) bool {
	delta := s.age - p.age
	// Each actual evaluation is between the last observation of the prior
	// scheduler count and the first observation of this journal update.
	return s.phase == "verify" && p.phase == "verify" && s.age < 300 && s.runs == p.runs+1 && delta > 0 &&
		s.seen >= s.earliest-1 && s.seen <= s.upAfter+1 && p.seen >= p.earliest-1 && p.seen <= p.upAfter+1 &&
		s.seen-p.seen == delta && delta >= s.earliest-p.upAfter-1 && delta <= s.upAfter-p.earliest+1
}

func (f *routingLab) imageTick(ctx context.Context, t *testing.T, nonce string, anchor *imageClockEdge) imageClockEdge {
	t.Helper()
	var prev imageClockReading
	var havePrev bool
	lower := -1
	limit := 3 * time.Minute
	if anchor != nil {
		prev = anchor.imageClockReading
		havePrev = true
		limit = 85 * time.Second
	}
	var got imageClockEdge
	_, ok := poll(ctx, limit, 400*time.Millisecond, func() bool {
		cur, visible := f.imageClock(ctx, nonce)
		if !visible {
			return false
		}
		if havePrev && cur.runs != prev.runs {
			lower = prev.upBefore
		}
		prev, havePrev = cur, true
		if anchor != nil && (cur.phase == "restore" || cur.phase == "recover" || cur.phase == "reverted") {
			t.Fatal("clock jump prematurely retired the signed image trial")
		}
		if cur.phase != "verify" || lower < 0 {
			return false
		}
		if anchor == nil {
			if cur.age < 50 || cur.age >= 180 || cur.seen < lower-1 || cur.seen > cur.upAfter+1 {
				return false
			}
		} else {
			if cur.runs <= anchor.runs || cur.age <= anchor.age {
				return false
			}
		}
		got = imageClockEdge{cur, lower}
		return true
	})
	if !ok {
		t.Fatalf("missing timed native verification tick: phase=%s age=%d seen=%d uptime=%d count=%d", prev.phase, prev.age, prev.seen, prev.upAfter, prev.runs)
	}
	if anchor != nil && !got.accountsForUptime(*anchor) {
		t.Fatalf("trial did not use its measured uptime: age=%d->%d seen=%d->%d windows=%d..%d/%d..%d count=%d->%d", anchor.age, got.age, anchor.seen, got.seen, anchor.earliest, anchor.upAfter, got.earliest, got.upAfter, anchor.runs, got.runs)
	}
	return got
}

func TestImageTrialClockUsesActualTickInterval(t *testing.T) {
	a := imageClockEdge{imageClockReading{"verify", 58, 280, 280, 281, 4}, 279}
	b := imageClockEdge{imageClockReading{"verify", 119, 341, 341, 342, 5}, 340}
	if !b.accountsForUptime(a) {
		t.Fatal("real 61-second tick refused")
	}
	for _, bad := range []imageClockEdge{
		{imageClockReading{"verify", 120, 341, 341, 342, 5}, 340},
		{imageClockReading{"verify", 119, 341, 270, 271, 5}, 270},
		{imageClockReading{"verify", 119, 341, 341, 342, 6}, 340},
		{imageClockReading{"restore", 300, 341, 341, 342, 5}, 340},
	} {
		if bad.accountsForUptime(a) {
			t.Fatal("unproved timer jump or different native tick accepted")
		}
	}
}
