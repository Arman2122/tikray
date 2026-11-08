//go:build lab

package m3

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A background repair may already have closed DNS under a temporary
// forward drop when the owner imports again. Use the release observation
// against live ordered IDs; moving the bridge accept hook to first would
// let an existing translated binding through before that drop.
func TestInstallBridgeGuardPlacement(t *testing.T) {
	r := newRig(t)
	const menu = "/ip/firewall/filter"
	run := func(args ...string) string {
		t.Helper()
		v, e := r.admin.RunArgsContext(r.ctx, args)
		if e != nil || v.Done == nil {
			t.Fatal("order fixture rejected")
		}
		return v.Done.Map["ret"]
	}
	before := r.chr
	get := func(s string) string {
		t.Helper()
		o, e := before.RunPrivate(r.ctx, s)
		if e != nil {
			t.Fatal("order verification failed")
		}
		return strings.TrimSpace(o)
	}
	first := get(`:put [:pick [/ip/firewall/filter/find where chain="forward" and !dynamic] 0]`)
	add := func(tag, action, anchor string, extra ...string) string {
		t.Helper()
		q := []string{menu + "/add", "=chain=forward", "=action=" + action, "=comment=" + tag}
		if anchor != "" {
			q = append(q, "=place-before="+anchor)
		}
		return run(append(q, extra...)...)
	}
	owner := add("owner:order-probe", "accept", first, "=src-address=198.18.1.6")
	run(menu+"/add", "=chain=tikray-egress", "=action=return", "=comment=tikray:egress-skip-local")
	guard := add("tikray:egress-guard", "jump", owner, "=jump-target=tikray-egress")
	held := add("tikray:hold:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "drop", guard, "=src-address=198.18.1.6", "=protocol=tcp", "=dst-port=53")
	if got := get(`:put [:pick [/ip/firewall/filter/find where chain="forward" and !dynamic] 0]`); got != held {
		t.Fatal("missing live negative control for an unconditional first placement")
	}
	data, e := os.ReadFile("../../routeros/install.rsc")
	if e != nil {
		t.Fatal("installer missing")
	}
	_, txt, ok := strings.Cut(string(data), "        # Bridge admission can accept")
	if !ok {
		t.Fatal("release observation missing")
	}
	_, txt, ok = strings.Cut(txt, "\n")
	if !ok {
		t.Fatal("invalid release observation")
	}
	code, _, ok := strings.Cut(txt, "        # End guard order observation.")
	if !ok {
		t.Fatal("invalid release observation")
	}
	src := "{\n" + code + `    :put ([:tostr $first] . "|" . [:tostr $moveBelowGuard])
}
`
	p := filepath.Join(t.TempDir(), "order.rsc")
	if os.WriteFile(p, []byte(src), 0600) != nil || r.chr.Push(r.ctx, p, "order.rsc") != nil {
		t.Fatal("order script staging failed")
	}
	witness := func(v string) {
		t.Helper()
		o := get("/import file-name=order.rsc")
		if !strings.Contains(o, owner+"|"+v) {
			t.Fatal("bridge admission placed ahead of a closed hold, or behind an owner accept")
		}
	}
	witness("false")
	run(menu+"/add", "=chain=tikray-bridge-fw", "=action=return", "=comment=tikray:acl-probe")
	add("tikray:acl-hook", "jump", held, "=jump-target=tikray-bridge-fw", "=dst-address=172.31.255.0/29")
	witness("true")
}
