//go:build lab

package m3

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/routeros/adapters"
)

// The retained-flow classifier may not change the meaning of a rule the owner
// adds after approval, even when the native runner cut has already begun.
func TestRunnerImagePreservesNewOwnerMarkUsers(t *testing.T) {
	r := newRig(t)
	run := func(command string) string {
		t.Helper()
		s, e := r.chr.RunPrivate(r.ctx, command)
		if e != nil {
			t.Fatal("native mark-ownership fixture refused")
		}
		return strings.TrimSpace(s)
	}
	setupRunnerImageRouting(t, r, run, "172.31.255.3")
	watch, helper, e := adapters.WatchdogScripts()
	a, b := strings.Index(watch, ":local imageTraffic do={"), strings.Index(watch, ":if ($7=\"transit\")")
	if e != nil || a < 0 || b <= a {
		t.Fatal("missing released native helper")
	}
	if _, e = r.admin.RunContext(r.ctx, "/system/script/add", "=name=tikray-watchdog-traffic", "=comment=tikray:watchdog-traffic", "=policy=read", "=source="+strings.ReplaceAll(helper, "\n", "\r\n")); e != nil {
		t.Fatal("native helper provisioning refused")
	}
	const nonce = "dddddddddddddddddddddddddddddddd"
	const temp = "tikray-i-" + nonce
	program := "{\n" + watch[a:b] + `
	:local lease do={:return true}; :local quota {"staging"={"nonce"="` + nonce + `"}}
	:local prior [/system/script/find where name=m3-mark-start]; :local action [/system/script/get [find where name=m3-mark-op] comment]
	:if ($action="read") do={:local rows [$imageTraffic "read" [:toarray ""] 172.31.255.3 m3-images-lan $lease $quota false]; /system/script/set $prior comment=[:serialize to=json options=json.no-string-conversion value=$rows]; :put "accepted"} else={
		:local data [:deserialize from=json options=json.no-string-conversion value=[/system/script/get $prior comment]]
		:onerror why in={:local result [$imageTraffic $action $data 172.31.255.3 m3-images-lan $lease $quota false]; :if (($result->"done")=true) do={:put "accepted"} } do={
			:if ([:typeof [:find [:tostr $why] "image: owner consumes normal open mark"]]="num") do={:put "normal-consumer"}
			:if ([:typeof [:find [:tostr $why] "image: shared transient connection mark"]]="num") do={:put "temporary-consumer"}
			:if ([:typeof [:find [:tostr $why] "image: shared connection mark writer"]]="num") do={:put "shared-writer"}
		}
	}
}`
	p := filepath.Join(t.TempDir(), "mark.rsc")
	if os.WriteFile(p, []byte(program), 0600) != nil || r.chr.Push(r.ctx, p, "m3-image-mark.rsc") != nil {
		t.Fatal("could not stage native operation")
	}
	run(`/system/script/add name=m3-mark-start source="" policy=read; /system/script/add name=m3-mark-op source="" policy=read comment=read`)
	tick := func(op, want string) {
		t.Helper()
		run(`/system/script/set [find where name=m3-mark-op] comment=` + op)
		if out := run(`/import file-name=m3-image-mark.rsc`); !strings.Contains(out, want) {
			t.Fatalf("mark ownership %s returned the wrong verdict (wanted %s)", op, want)
		}
	}
	tick("read", "accepted")
	tick("hold", "accepted")
	caseRule := func(menu, field, value, action, reason string) {
		t.Helper()
		q, e := r.admin.RunContext(r.ctx, menu+"/add", "=chain=owner-img-case", "=action="+action, "="+field+"="+value, "=comment=owner:img-case")
		if e != nil || q.Done == nil {
			t.Fatalf("%s %s fixture was rejected", menu, field)
		}
		id := q.Done.Map["ret"]
		if id == "" {
			t.Fatal("owner test ID absent")
		}
		for _, boundary := range []string{"hold", "release"} {
			tick(boundary, reason)
			if run(fmt.Sprintf(`:put [:len [%s/find where comment="owner:img-case" and .id=[:toid "%s"]]]`, menu, id)) != "1" || run(`:put [:len [/ip/firewall/mangle/find where comment="tikray:conn-full-open" and new-connection-mark="`+temp+`"]]`) != "1" {
				t.Fatalf("image %s changed an owner mark input or classifier", boundary)
			}
		}
		if _, e = r.admin.RunContext(r.ctx, menu+"/remove", "=.id="+id); e != nil {
			t.Fatal("cannot remove private test row")
		}
	}
	for _, menu := range []string{"/ip/firewall/filter", "/ip/firewall/nat", "/ip/firewall/mangle"} {
		for _, prefix := range []string{"", "!"} {
			caseRule(menu, "connection-mark", prefix+"tikray-open", "accept", "normal-consumer")
			caseRule(menu, "connection-mark", prefix+temp, "accept", "temporary-consumer")
		}
	}
	caseRule("/ip/firewall/mangle", "new-connection-mark", "tikray-open", "mark-connection", "shared-writer")
	caseRule("/ip/firewall/mangle", "new-connection-mark", temp, "mark-connection", "shared-writer")
	tick("release", "accepted")
}
