//go:build lab

package m3

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	routerosfiles "github.com/Arman2122/tikray/routeros"
)

// Run the actual read-only retained-directory gate before any infrastructure
// is created. Empty/new installations still use the ordinary empty-tree gate.
func TestRetainedDataRequiresOwnerSelection(t *testing.T) {
	r := newRig(t)
	b, e := routerosfiles.Sources.ReadFile("install.rsc")
	if e != nil {
		t.Fatal(e)
	}
	_, part, ok := strings.Cut(string(b), "    :local retainedPath ")
	gate, _, end := strings.Cut(part, "    :if ([:len $seedFiles] = 0) do={\n        # An upload")
	if !ok || !end {
		t.Fatal("installer reuse gate missing")
	}
	const path = "disk1/tikray-reuse/data"
	const id = "123456789abcdef0123456789abcdef0"
	check := func(cmd string) string {
		t.Helper()
		out, e := r.chr.RunPrivate(r.ctx, cmd)
		if e != nil {
			t.Fatal("fixture operation failed")
		}
		return strings.TrimSpace(out)
	}
	check(`/file/add name=disk1/tikray-reuse type=directory; /file/add name=disk1/tikray-reuse/data type=directory; /file/add name=disk1/tikray-reuse/data/state type=directory`)
	for _, rel := range []string{"state/state.v1.json", "state/tls.crt", "state/tls.key", "owner-file"} {
		check("/file/add name=" + path + "/" + rel + " type=file contents=preserve")
	}
	script := "{ :global reuseTestID; :global reuseTestSubnet; :local data \"" + path + "\"; :local subnet $reuseTestSubnet; :local requestedReuse $reuseTestID; :local seedFiles [:toarray \"\"]; :local retainedPath " + gate + "\n:put (\"ACCEPT-\" . $reuse)\n}"
	file := filepath.Join(t.TempDir(), "read-retained.rsc")
	if os.WriteFile(file, []byte(script), 0600) != nil || r.chr.Push(r.ctx, file, "read-retained.rsc") != nil {
		t.Fatal("stage retained gate")
	}
	run := func(which, subnet string) string {
		return check(`:global reuseTestID "` + which + `"; :global reuseTestSubnet "` + subnet + `"; :onerror e in={ /import read-retained.rsc } do={ :put "REFUSED" }`)
	}
	if got := run("", "172.31.255.0/29"); !strings.Contains(got, "ACCEPT-false") {
		t.Fatal("fresh upload no longer passes empty retained gate")
	}
	check(`/file/add name=disk1/tikray-reuse/data/install.retained type=file contents=[:serialize to=json options=json.no-string-conversion value={"version"=1;"installation_id"="` + id + `";"data"="` + path + `";"subnet"="172.31.255.0/29"}]`)
	for _, arg := range [][]string{{"", "172.31.255.0/29"}, {strings.Repeat("a", 32), "172.31.255.0/29"}, {id, "172.30.0.0/29"}} {
		if run(arg[0], arg[1]) != "REFUSED" {
			t.Fatal("unexpected retained data silently adopted")
		}
	}
	if got := run(id, "172.31.255.0/29"); !strings.Contains(got, "ACCEPT-true") {
		t.Fatal("owner-selected retained volume refused")
	}
	check("/file/add name=" + path + "/state/install.ready type=file contents=stale")
	if run(id, "172.31.255.0/29") != "REFUSED" {
		t.Fatal("unretired previous installation accepted")
	}
	if check(":put [/file/get [find name="+path+"/owner-file] contents]") != "preserve" {
		t.Fatal("retention preflight modified owner data")
	}
}
