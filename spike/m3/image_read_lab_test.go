//go:build lab

package m3

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Probe only synthetic public bytes. The owner can read the same payload
// under any name, but the scheduled process has a different native policy.
func TestImageSchedulerReadsPublicHandoffs(t *testing.T) {
	r := newRig(t)
	run := func(cmd string) string {
		t.Helper()
		s, err := r.chr.RunPrivate(r.ctx, cmd)
		if err != nil {
			t.Fatal("private handoff fixture failed")
		}
		return strings.TrimSpace(s)
	}
	for _, ext := range []string{"json", "request", "receipt", "tar"} {
		run(`/file/add name="disk1/m3-public.` + ext + `" type=file contents="mode-proof"`)
	}
	run(`/system/script/add name=m3-handoff-verdict source="" policy=read comment=waiting`)
	const program = `/system/script/add name=m3-handoff-reader policy=read,write,test,ftp source={
	    :local verdict ""
	    :foreach ext in={"json";"request";"receipt";"tar"} do={
	        :local path ("disk1/m3-public." . $ext); :local id [/file/find where name=$path]
	        :if (([:len $id]!=1) or ([/file/get $id size]!=10)) do={:error "fixture: missing public input"}
	        :local whole false; :local chunk false
	        :do {:set whole ([/file/get $id contents]="mode-proof")} on-error={}
	        :do {:set chunk (([/file/read file=$path offset=0 chunk-size=10 as-value]->"data")="mode-proof")} on-error={}
	        :foreach bit in=({$whole;$chunk}) do={:if ($bit) do={:set verdict ($verdict . "1")} else={:set verdict ($verdict . "0")}}
	    }
	    /system/script/set [find where name=m3-handoff-verdict] comment=$verdict
	}
`
	path := filepath.Join(t.TempDir(), "m3-public-read.rsc")
	if os.WriteFile(path, []byte(program), 0600) != nil || r.chr.Push(r.ctx, path, "m3-public-read.rsc") != nil {
		t.Fatal("cannot stage native reader")
	}
	run("/import file-name=m3-public-read.rsc")
	const read = `:put [/system/script/get [find where name=m3-handoff-verdict] comment]`
	run("/system/script/run m3-handoff-reader")
	if run(read) != "11111111" {
		t.Fatal("owner could not read all public positive controls")
	}
	run(`/system/script/set [find where name=m3-handoff-verdict] comment=waiting`)
	run(`/system/scheduler/add name=m3-handoff-test on-event=m3-handoff-reader interval=2s start-time=00:00:00 policy=read,write,test,ftp`)
	var got string
	if err := ownerWait(r.ctx, 40*time.Second, func(ctx context.Context) (bool, error) {
		s, e := r.chr.RunPrivate(ctx, read)
		got = strings.TrimSpace(s)
		return got != "waiting" && got != "", e
	}); err != nil || got != "00111111" {
		t.Fatal("scheduled public handoff capabilities differed")
	}
}
