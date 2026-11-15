//go:build lab

package m3

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A command that succeeds in the owner terminal may fail in the scheduler
// with the same source. Publish an inert receipt from the real restricted tick.
func TestImageSchedulerCanPublishPhase(t *testing.T) {
	r := newRig(t)
	run := func(s string) string {
		t.Helper()
		v, err := r.chr.RunPrivate(r.ctx, s)
		if err != nil {
			t.Fatal("private scheduler fixture command refused")
		}
		return strings.TrimSpace(v)
	}
	run(`/system/script/add name=m3-place-result source="" policy=read comment=waiting`)
	run(`/system/script/add name=m3-place-script policy=read,write,test,ftp source={ :local res [/system/script/find where name="m3-place-result"]; /system/scheduler/disable [find where name="m3-place-scheduler"]; :onerror e in={ /system/script/add name=m3-native-inert source="" dont-require-permissions=no policy=read comment="m3:receipt"; /system/script/set $res comment=published } do={ :local code "other"; :if ([:typeof [:find [:tostr $e] "permission"]]="num") do={:set code "permission"}; /system/script/set $res comment=$code } }`)
	run(`/system/scheduler/add name=m3-place-scheduler start-time=00:00:00 interval=2s policy=read,write,test,ftp on-event=m3-place-script`)
	var result string
	if err := ownerWait(r.ctx, 50*time.Second, func(ctx context.Context) (bool, error) {
		v, e := r.chr.RunPrivate(ctx, `:put [/system/script/get [find where name="m3-place-result"] comment]`)
		result = strings.TrimSpace(v)
		return result == "published" || result == "permission" || result == "other", e
	}); err != nil {
		t.Fatal("actual scheduler did not publish a completion receipt")
	}
	if result != "published" {
		t.Fatalf("native inert publication refused (permission=%t)", result == "permission")
	}
	if run(`:put [:len [/system/script/find where name="m3-native-inert" and comment="m3:receipt" and source="" and !dont-require-permissions]]`) != "1" {
		t.Fatal("missing tagged final native receipt")
	}
}
