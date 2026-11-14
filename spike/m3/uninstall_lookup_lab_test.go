//go:build lab

package m3

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	routerosfiles "github.com/Arman2122/tikray/routeros"
)

// A next hop can reference a VRF from another routing table. Both pinned
// versions accept that syntax for VRFs and reject it for a plain FIB table.
func TestUninstallLookupTableMatchesGatewayVRF(t *testing.T) {
	r := newRig(t)
	run := func(cmd string) string {
		t.Helper()
		body, err := r.chr.RunPrivate(r.ctx, cmd)
		if err != nil {
			t.Fatal("private lookup table fixture failed")
		}
		return strings.TrimSpace(body)
	}
	run(`/routing/table/add name=tikray-closed fib; /interface/bridge/add name=owner-empty disabled=yes; /ip/vrf/add name=tikray-open interfaces=owner-empty; :delay 2s`)
	if run(`{:onerror problem in={ /ip/route/add dst-address=198.18.8.1/32 gateway=198.51.100.254@tikray-closed; :put "accepted" } do={ :put "absent" }}`) != "absent" {
		t.Fatal("lookup table support on this version changed")
	}
	run(`/ip/route/add dst-address=198.18.8.1/32 gateway=198.51.100.254@tikray-open disabled=yes comment=owner-dependent`)
	b, err := routerosfiles.Sources.ReadFile("uninstall-references.rsc")
	if err != nil {
		t.Fatal(err)
	}
	helper, _, found := strings.Cut(string(b), ":local references do={")
	if !found {
		t.Fatal("no table reference check")
	}
	file := filepath.Join(t.TempDir(), "lookup.rsc")
	src := "{\n" + helper + `
	:local refusal false
	:onerror reason in={ :local unused [$checkTable "tikray-open" [:toarray ""]] } do={
		:set refusal ([:typeof [:find [:tostr $reason] "owner next hop uses private lookup table"]]="num")
	}
	:if (!$refusal) do={ :error "exact lookup dependency was missed" }
	:local near [$checkTable "tikray-closed" [:toarray ""]]
	:put "verified"
}
`
	if os.WriteFile(file, []byte(src), 0600) != nil || r.chr.Push(r.ctx, file, "lookup.rsc") != nil {
		t.Fatal("lookup fixture transfer failed")
	}
	if out := run(`:onerror ignored in={ /import lookup.rsc } do={:put "incomplete"}`); !strings.Contains(out, "verified") {
		t.Fatal("owner recursive gateway did not match exactly")
	}
}
