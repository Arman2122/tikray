//go:build lab

package m3

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RouterOS adds a read-only .nextid to ordered whole-row reads. A healthy
// row followed by an owner row must still pass the full selector check. An
// additional real matcher changes its scope and must be refused.
func TestInstallFirewallReadback(t *testing.T) {
	r := newRig(t)
	src, e := os.ReadFile("../../routeros/install.rsc")
	if e != nil {
		t.Fatal("missing installer")
	}
	const begin = "    :local ensure do={"
	_, rest, ok := strings.Cut(string(src), begin)
	body, _, end := strings.Cut(rest, "\n    :local dir do={")
	if !ok || !end {
		t.Fatal("missing installer ownership check")
	}
	const menu = "/ip/firewall/nat"
	add := func(words ...string) string {
		t.Helper()
		a, e := r.admin.RunArgsContext(r.ctx, append([]string{menu + "/add"}, words...))
		if e != nil || a.Done == nil || a.Done.Map["ret"] == "" {
			t.Fatal("NAT fixture rejected")
		}
		return a.Done.Map["ret"]
	}
	if _, e := r.admin.RunContext(r.ctx, "/interface/list/add", "=name=fixture-egress"); e != nil {
		t.Fatal("egress list fixture rejected")
	}
	if _, e := r.admin.RunContext(r.ctx, "/interface/list/member/add", "=list=fixture-egress", "=interface=ether1"); e != nil {
		t.Fatal("egress member fixture rejected")
	}
	const tag = "tikray:nat-containers"
	id := add("=chain=srcnat", "=src-address=172.29.246.0/29", "=out-interface-list=fixture-egress", "=action=masquerade", "=comment="+tag)
	add("=chain=srcnat", "=src-address=198.18.23.1", "=action=accept", "=comment=owner:order-witness")
	check := func(helper string) string {
		t.Helper()
		prog := "{\n" + begin + helper + `
   :local preflight false; :local empty [:toarray ""]; :local noop do={:return true}
   :local props {"chain"="srcnat";"src-address"="172.29.246.0/29";"out-interface-list"="fixture-egress";"action"="masquerade"}
   :local read [/ip/firewall/nat/get [:pick [/ip/firewall/nat/find where comment="tikray:nat-containers"] 0]]
   :if ([:typeof ($read->".nextid")] != "id") do={ :put "ordering-metadata-absent" } else={
       :onerror problem in={:local found [$ensure "/ip/firewall/nat" "tikray:nat-containers" $empty $props $preflight "" $noop $empty]; :put "accepted"} do={
           :if ([:typeof [:find [:tostr $problem] "object conflict in firewall selectors"]] = "num") do={:put "extra-selector"} else={:put "unrelated-failure"}
       }
   }
}
`
		p := filepath.Join(t.TempDir(), "row.rsc")
		if os.WriteFile(p, []byte(prog), 0600) != nil || r.chr.Push(r.ctx, p, "row.rsc") != nil {
			t.Fatal("row fixture upload failed")
		}
		out, e := r.chr.RunPrivate(r.ctx, "/import file-name=row.rsc")
		if e != nil {
			t.Fatal("row fixture failed")
		}
		return strings.TrimSpace(out)
	}
	// Retain the actual failure as a positive control. The sole difference
	// between these reads is whether native ordering metadata is recognized.
	previous := strings.Replace(body, `;".nextid"`, "", 1)
	if previous == body || !strings.Contains(check(previous), "extra-selector") {
		t.Fatal("missing historical refusal of the healthy row")
	}
	if o := check(body); !strings.Contains(o, "accepted") {
		for _, category := range []string{"ordering-metadata-absent", "extra-selector", "unrelated-failure"} {
			if strings.Contains(o, category) {
				t.Fatal("healthy NAT row failed", category)
			}
		}
		t.Fatal("healthy NAT row did not return a known verdict")
	}
	if _, e := r.admin.RunContext(r.ctx, menu+"/set", "=.id="+id, "=protocol=tcp"); e != nil {
		t.Fatal("could not configure real additional matcher")
	}
	if o := check(body); !strings.Contains(o, "extra-selector") {
		t.Fatal("unmanaged protocol matcher was accepted or unproven")
	}
}
