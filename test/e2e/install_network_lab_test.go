//go:build lab

package e2e

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"maps"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/store"
)

var countLine = regexp.MustCompile(`(?m)^m3-count=([0-9]+)[[:space:]]*$`)

func (f *installLab) checkBridge(ctx context.Context, t *testing.T) {
	t.Helper()
	f.ownerPortForward(ctx, t)
	tcp := func(wan bool, host string, port int) bool {
		dial := f.Net.Client
		if wan {
			dial = f.Net.Inet
		}
		// A new socket every time prevents an established conntrack binding
		// from concealing the effect of a rule on incoming connections.
		return dial(ctx, "python3", "-c", `import socket,sys
s=socket.create_connection((sys.argv[1],int(sys.argv[2])),2);s.close()`, host, strconv.Itoa(port)).Run() == nil
	}
	for _, wan := range []bool{false, true} {
		if !tcp(wan, "198.51.100.2", 22) {
			t.Fatal("owner management lost reachability")
		}
		for _, port := range []int{53, 1080, 8080, 10085} {
			if tcp(wan, installRunner, port) {
				t.Fatal("fresh untrusted connection reached a private runner listener")
			}
		}
	}
	if !tcp(false, installControl, 443) || tcp(true, installControl, 443) {
		t.Fatal("LAN management or WAN isolation failed")
	}
	if f.probe(ctx, t, "ports") != "verified" {
		t.Fatal("control cannot reach a running private service")
	}
	f.mustRun(ctx, t, `:if ([/ping 172.30.252.3 count=3 interval=500ms] = 0) do={:error "router cannot reach runner"}`)
	routerRunner := f.mustRun(ctx, t, `{:local b [/file/get [find name="disk1/tikray/data/run/runner.token"] contents]; :set b [:pick $b 0 [:find ($b . "\n") "\n"]]; :local r [/tool/fetch url="http://172.30.252.3:8080/v1/status" http-header-field=("Authorization: Bearer " . $b) output=user as-value]; :local s [:deserialize from=json value=($r->"data")]; :put ((($s->"state")="running") and (($s->"gateway_up")=true))}`)
	if routerRunner != "true" {
		t.Fatal("router could not authenticate to the running runner")
	}

	// UDP reachability needs a positive drop witness: a DNS timeout alone
	// could also result from an unavailable upstream. Probe from both sides.
	drops := func() int64 {
		var n int64
		_, good := poll(ctx, 3*time.Second, 200*time.Millisecond, func() bool {
			out, e := f.CHR.RunPrivate(ctx, `{:local n 0; :foreach i in=[/ip/firewall/filter/find where comment~"^tikray:" and action=drop] do={:set n ($n + [/ip/firewall/filter/get $i packets])}; :foreach i in=[/ip/firewall/raw/find where comment~"^tikray:" and action=drop] do={:set n ($n + [/ip/firewall/raw/get $i packets])}; :put ("m3-count=" . [:tostr $n])}`)
			if e != nil {
				return false
			}
			found := countLine.FindStringSubmatch(out)
			if len(found) != 2 {
				return false
			}
			n, e = strconv.ParseInt(found[1], 10, 64)
			return e == nil
		})
		if !good {
			t.Fatal("missing firewall counters")
		}
		return n
	}
	for i, dial := range []func(context.Context, string, ...string) *exec.Cmd{f.Net.Client, f.Net.Inet} {
		base := drops()
		resp, err := dial(ctx, "dig", "+short", "+time=2", "+tries=1", "@"+installRunner, "domestic.test", "A").Output()
		origin := []string{"LAN", "WAN"}[i]
		if err == nil {
			t.Fatalf("private UDP DNS answered from %s (IPv4 answer %t)", origin, hasIPv4Answer(resp))
		}
		_, hit := poll(ctx, 4*time.Second, 200*time.Millisecond, func() bool { return drops() > base })
		if !hit {
			t.Fatalf("private UDP DNS from %s lacked its firewall drop witness", origin)
		}
	}
	// Exercise traffic that the control account has admitted. Netwatch alone
	// controls the open DNS rules; both transports must survive bridge ACLs.
	api := f.pinned(ctx, t)
	state, err := api.State(ctx)
	if err != nil {
		t.Fatal("could not read default routing")
	}
	var s struct {
		Routing store.Routing
		DNS     store.DNS
	}
	if json.Unmarshal(state.Body, &s) != nil {
		t.Fatal("could not decode baseline settings")
	}
	dns := store.DNS{Domestic: netip.MustParseAddr("203.0.113.54"), Remote: "203.0.113.53"}
	routing := s.Routing
	routing.Domestic.Domains = append(routing.Domestic.Domains, "domain:domestic.test")
	if _, err = api.SetDNS(ctx, dns); err != nil {
		t.Fatal("could not set test resolvers")
	}
	if _, err = api.SetRouting(ctx, routing); err != nil {
		t.Fatal("could not set test DNS routing")
	}
	mac, err := f.Net.Client(ctx, "cat", "/sys/class/net/eth0/address").Output()
	if err != nil {
		t.Fatal("could not identify LAN client")
	}
	if _, err := api.SetDevice(ctx, store.Device{Address: lanClient, MAC: strings.TrimSpace(string(mac)), Policy: store.Policy{Mode: store.ModeFull}}); err != nil {
		t.Fatal("could not admit test LAN client")
	}
	f.checkReady(ctx, t)
	q := `comment="tikray:dns-full-open-udp"`
	_, ok := poll(ctx, time.Minute, time.Second, func() bool {
		out, e := f.CHR.RunPrivate(ctx, `:put [:len [/ip/firewall/nat/find where `+q+` and disabled=no]]`)
		return e == nil && strings.TrimSpace(out) == "1"
	})
	if !ok {
		t.Fatal("production account or netwatch could not arm open DNS")
	}
	for _, opts := range [][]string{{}, {"+tcp"}} {
		before := f.mustRun(ctx, t, `:put [/ip/firewall/nat/get [find where comment="tikray:dns-full-open-`+map[bool]string{false: "udp", true: "tcp"}[len(opts) > 0]+`"] packets]`)
		args := append([]string{"+short", "+time=5", "+tries=2", "@93.184.216.25", "domestic.test", "A"}, opts...)
		out, err := f.Net.Client(ctx, "dig", args...).Output()
		after := f.mustRun(ctx, t, `:put [/ip/firewall/nat/get [find where comment="tikray:dns-full-open-`+map[bool]string{false: "udp", true: "tcp"}[len(opts) > 0]+`"] packets]`)
		if err != nil || !hasIPv4Answer(out) || after == before {
			t.Fatal("authorized translated DNS lacked a response and primary NAT witness")
		}
	}
	// Require both a closed policy row and an unrelated owner NAT row:
	// matching a broad substring would otherwise pass with only open rules.
	closed := store.Device{Address: netip.MustParsePrefix("192.168.88.111/32"), MAC: "02:00:00:00:00:6f", Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}}
	if _, e := api.SetDevice(ctx, closed); e != nil {
		t.Fatal("could not admit closed netwatch witness")
	}
	f.checkReady(ctx, t)
	f.mustRun(ctx, t, `/ip/firewall/nat/add chain=lab-private action=accept comment="lab:tikray:dns-full-open-tcp"`)
	f.netwatchCycle(ctx, t)
	if _, e := api.RemoveDevice(ctx, closed.Address); e != nil {
		t.Fatal("could not remove closed witness")
	}
	if _, e := api.RemoveDevice(ctx, lanClient); e != nil {
		t.Fatal("could not restore direct LAN policy")
	}
	if _, e := api.SetDNS(ctx, s.DNS); e != nil {
		t.Fatal("could not restore initial DNS settings")
	}
	if _, e := api.SetRouting(ctx, s.Routing); e != nil {
		t.Fatal("could not restore initial routing")
	}
	f.checkReady(ctx, t)
}

// Check the effect from RouterOS while the control daemon is waiting on
// an unreachable runner. The exact open primary rows must be the only flips.
func (f *installLab) netwatchCycle(ctx context.Context, t *testing.T) {
	t.Helper()
	snapshot := func() map[string]string {
		rows := f.mustRun(ctx, t, `:foreach id in=[/ip/firewall/nat/find] do={:put ([/ip/firewall/nat/get $id comment] . "|" . [:tostr [/ip/firewall/nat/get $id disabled]])}`)
		out := map[string]string{}
		for _, r := range strings.Split(rows, "\n") {
			c, state, ok := strings.Cut(r, "|")
			if !ok {
				t.Fatal("NAT state witness unreadable")
			}
			out[c] = state
		}
		return out
	}
	up := snapshot()
	down := maps.Clone(up)
	for _, proto := range []string{"tcp", "udp"} {
		name := "tikray:dns-full-open-" + proto
		if up[name] != "false" || up["tikray:dns-full-closed-"+proto] != "false" {
			t.Fatal("positive open/closed DNS control unavailable")
		}
		down[name] = "true"
	}
	if up["lab:tikray:dns-full-open-tcp"] != "false" {
		t.Fatal("missing owner DNS control")
	}
	f.mustRun(ctx, t, "/container/stop [find name=tikray-runner]")
	check := func(want map[string]string) {
		t.Helper()
		_, ok := poll(ctx, time.Minute, time.Second, func() bool { return maps.Equal(snapshot(), want) })
		if !ok {
			t.Fatal("netwatch did not toggle exactly the open primary rules")
		}
	}
	check(down)
	f.mustRun(ctx, t, "/container/start [find name=tikray-runner]")
	check(up)
	f.checkReady(ctx, t)
}

// Dig may print other lines before the answer; require an actual IPv4 RR.
func hasIPv4Answer(b []byte) bool {
	for _, line := range strings.Fields(string(b)) {
		if a, e := netip.ParseAddr(line); e == nil && a.Is4() {
			return true
		}
	}
	return false
}

func (f *installLab) checkWatchdog(ctx context.Context, t *testing.T) {
	t.Helper()
	tick := func() {
		t.Helper()
		wire := f.mustRun(ctx, t, `:onerror why in={ /system/script/run tikray-watchdog; :put "m3-import-ok" } do={ :put ("m3-import-error=" . [:convert [:tostr $why] to=base64]) }`)
		if _, err := installOutput(wire); err != nil {
			t.Fatalf("native watchdog tick failed: %v", err)
		}
	}
	f.mustRun(ctx, t, `/system/scheduler/disable [find name=tikray-watchdog]`)
	defer func() { f.mustRun(ctx, t, `/system/scheduler/enable [find name=tikray-watchdog]`) }()
	stop := func(name string) {
		t.Helper()
		f.mustRun(ctx, t, `/container/stop [find name=`+name+`]`)
		if f.waitForContainer(ctx, name, "stopped") != nil {
			t.Fatal("could not stop target container")
		}
	}
	stillStopped := func(name string) {
		t.Helper()
		if st, e := containerStatus(ctx, f.CHR, name); e != nil || st != "stopped" {
			t.Fatal("container restarted before failure threshold")
		}
	}
	waitUp := func(name string) {
		t.Helper()
		if f.waitForContainer(ctx, name, "running") != nil {
			t.Fatal("watchdog failed to restart the failing component")
		}
	}
	ctlStart := func() string {
		t.Helper()
		s := f.probe(ctx, t, "control-start")
		if _, e := strconv.ParseUint(s, 10, 64); e != nil {
			t.Fatal("control process start unavailable")
		}
		return s
	}
	tick()
	trace := f.mustRun(ctx, t, `{:local rows [/container/find where name="tikray-runner" and comment="tikray:runner"]; :local rid [:pick $rows 0]; :put ("m3-peer=" . [:len $rows] . "|" . [:convert [:tostr $rid] to=hex] . "|end")}`)
	match := regexp.MustCompile(`m3-peer=([0-9]+)\|([0-9a-fA-F]*)\|end`).FindStringSubmatch(trace)
	if len(match) != 3 || match[1] != "1" {
		t.Fatalf("runner fixture lookup did not return exactly one tagged row (structured acknowledgement %t)", len(match) == 3)
	}
	raw, err := hex.DecodeString(match[2])
	id := string(raw)
	if err != nil || !regexp.MustCompile(`^\*[A-Fa-f0-9]+$`).MatchString(id) {
		t.Fatalf("invalid native runner ID (encoded length %d)", len(match[2]))
	}

	// One malformed/unowned component cannot suppress a verified sibling.
	// Preserve the exact runtime identity and restore only the row we tagged.
	f.mustRun(ctx, t, `/container/set `+id+` comment=lab:watchdog-peer`)
	restorePeer := func() {
		t.Helper()
		f.mustRun(ctx, t, `{:local c [/container/get `+id+`]; :if ((($c->"name")="tikray-runner") and (($c->"comment")="lab:watchdog-peer")) do={ /container/set `+id+` comment="tikray:runner" }; :if ([/container/get `+id+` comment]!="tikray:runner") do={:error "fixture peer identity changed"} }`)
	}
	defer restorePeer()
	// The verified interval starts after the owner-side fixture rename and
	// finishes before restoring the tag. Metadata edits are outside it.
	instance := func() string {
		t.Helper()
		v := f.probe(ctx, t, "runner")
		m := regexp.MustCompile(`(?m)^([0-9]+\.[0-9]+\.[0-9]+)\|([A-Za-z2-7]{20,64})[[:space:]]*$`).FindStringSubmatch(v)
		if len(m) != 3 || m[1] != f.Newest {
			t.Fatal("runner instance witness unavailable inside the ownership window")
		}
		return m[2]
	}
	// RouterOS can recycle a running container as it applies a comment
	// edit. Let that operation settle before attributing any later change
	// to a watchdog invocation.
	if sleep(ctx, 8*time.Second) != nil {
		t.Fatal("fixture settling interrupted")
	}
	f.checkReady(ctx, t)
	oldRunner := instance()
	_, stable := poll(ctx, 25*time.Second, 2*time.Second, func() bool {
		if sleep(ctx, 2*time.Second) != nil {
			return false
		}
		next := instance()
		unchanged := next == oldRunner
		oldRunner = next
		return unchanged
	})
	if !stable {
		t.Fatal("retagged runner did not settle")
	}
	stop("tikray")
	// An intentional stop must stay down without a scheduler. The three
	// misses below must all be produced by actual native minute executions.
	if sleep(ctx, 8*time.Second) != nil {
		t.Fatal("native restart control interrupted")
	}
	stillStopped("tikray")
	count := func() int64 {
		raw := f.mustRun(ctx, t, `:put [/system/scheduler/get [find name=tikray-watchdog] run-count]`)
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			t.Fatal("unreadable scheduler counter")
		}
		return n
	}
	before := count()
	f.mustRun(ctx, t, `/system/scheduler/enable [find name=tikray-watchdog]`)
	// Observe run-count for each execution. Re-enabling a scheduler can
	// reset a native counter, which does not constitute a health check.
	for minute := 1; minute <= 3; minute++ {
		_, observed := poll(ctx, 85*time.Second, 300*time.Millisecond, func() bool {
			n := count()
			if n < before {
				before = n
				return false
			}
			if n == before {
				return false
			}
			if n-before != 1 {
				t.Fatal("could not distinguish consecutive scheduled ticks")
			}
			before = n
			return true
		})
		if !observed {
			t.Fatal("missing real minute scheduler tick")
		}
		if minute < 3 {
			// run-count advances at dispatch. Give the native job time to
			// run before asserting the failed component remains stopped.
			if sleep(ctx, 2*time.Second) != nil {
				t.Fatal("scheduled check interrupted")
			}
			_, idle := poll(ctx, 12*time.Second, 200*time.Millisecond, func() bool {
				return f.mustRun(ctx, t, `:put [:len [/system/script/job/find where script="tikray-watchdog"]]`) == "0"
			})
			if !idle {
				t.Fatal("scheduled probe did not finish")
			}
			stillStopped("tikray")
		}
	}
	waitUp("tikray")
	f.mustRun(ctx, t, `/system/scheduler/disable [find name=tikray-watchdog]`)
	f.checkReady(ctx, t)
	if instance() != oldRunner {
		t.Fatal("a runner instance changed during the foreign-ownership observation window")
	}
	restorePeer()
	// Recovery after the physical owner turns steering off must stay under
	// owner control even when the containers cannot communicate.
	stop("tikray")
	f.mustRun(ctx, t, "/system/script/run tikray-emergency-off")
	for range 5 {
		tick()
		stillStopped("tikray")
	}
	f.mustRun(ctx, t, "/container/start [find name=tikray]")
	f.checkReady(ctx, t)
	// A successful health probe resets previous misses. Leave the control
	// healthy throughout an independent runner failure/recovery.
	tick()
	oldControl := ctlStart()
	stop("tikray-runner")
	tick()
	stillStopped("tikray-runner")
	tick()
	stillStopped("tikray-runner")
	tick()
	waitUp("tikray-runner")
	f.checkReady(ctx, t)
	if ctlStart() != oldControl {
		t.Fatal("runner failure restarted the healthy control plane")
	}
	tick()
	// With a persistent control-only health failure the restart interval
	// grows. Observe real process start times instead of a synthetic counter.
	f.mustRun(ctx, t, `/ip/firewall/filter/add chain=output dst-address=172.30.252.2 protocol=tcp dst-port=443 action=drop comment="lab:watchdog-outage"`)
	var starts []time.Time
	firstTick := 0
	prev := ctlStart()
	for n, deadline := 1, time.Now().Add(6*time.Minute); time.Now().Before(deadline) && len(starts) < 3; n++ {
		tick()
		waitUp("tikray")
		next := ctlStart()
		if next != prev {
			if len(starts) == 0 {
				firstTick = n
			}
			starts = append(starts, time.Now())
			prev = next
		}
		if len(starts) < 3 {
			if err := sleep(ctx, 3*time.Second); err != nil {
				t.Fatal("watchdog observation canceled")
			}
		}
	}
	f.mustRun(ctx, t, `/ip/firewall/filter/remove [find where comment="lab:watchdog-outage"]`)
	if len(starts) != 3 || firstTick != 3 || starts[1].Sub(starts[0]) < 55*time.Second || starts[2].Sub(starts[1]) < 110*time.Second || starts[2].Sub(starts[1]) < starts[1].Sub(starts[0])+30*time.Second {
		t.Fatal("repeated control failures did not use increasing restart backoff")
	}
	f.checkReady(ctx, t)
	tick()

}
