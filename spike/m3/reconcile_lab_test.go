//go:build lab

package m3

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

type countedNative struct {
	*routeros.Client
	writes   int
	lastMenu string
}

func (c *countedNative) CommandAt(ctx context.Context, g uint64, words []string) ([]routeros.Row, error) {
	c.lastMenu = words[0]
	if !strings.HasSuffix(c.lastMenu, "/print") {
		c.writes++
	}
	return c.Client.CommandAt(ctx, g, words)
}

func TestM3ReconcilePolicy(t *testing.T) {
	r := newRig(t)
	c := &countedNative{Client: newNativeClient(t, r)}
	add := func(label string, words ...string) string {
		t.Helper()
		reply, e := r.admin.RunArgsContext(r.ctx, words)
		if e != nil || reply.Done == nil || reply.Done.Map["ret"] == "" {
			t.Fatalf("fixture add rejected: %s", label)
		}
		return reply.Done.Map["ret"]
	}
	add("bridge", "/interface/bridge/add", "=name=tikray", "=protocol-mode=none", "=comment=tikray:bridge")
	add("bridge address", "/ip/address/add", "=interface=tikray", "=address=172.30.252.1/29", "=comment=tikray:addr")
	add("LAN list", "/interface/list/add", "=name=inside")
	add("LAN member", "/interface/list/member/add", "=list=inside", "=interface=ether2")
	const filter = "/ip/firewall/filter"
	deny := add("owner deny", filter+"/add", "=chain=forward", "=action=drop", "=src-address=198.18.0.19", "=comment=owner:deny")
	ft := add("owner FastTrack", filter+"/add", "=chain=forward", "=action=fasttrack-connection", "=connection-state=established,related", "=comment=owner:ft")
	accept := add("owner accept", filter+"/add", "=chain=forward", "=action=accept", "=connection-state=established,related", "=comment=owner:after")
	lan := routeros.LAN{Interface: "ether2", Prefix: netip.MustParsePrefix("192.168.88.0/24")}
	scope := routeros.InstallScope{LANList: "inside", Subnet: netip.MustParsePrefix("172.30.252.0/29"), LANs: []routeros.LAN{lan}, WAN: routeros.WANPath{Interface: "ether1", Gateway: netip.MustParseAddr("198.51.100.254")}}
	s := store.Default()
	s.Network.Subnet = scope.Subnet
	s.Devices = []store.Device{
		{Address: netip.MustParsePrefix("192.168.88.21/32"), MAC: "02:00:00:00:00:21", Policy: store.Policy{Mode: store.ModeSmart}},
		{Address: netip.MustParsePrefix("192.168.88.22/32"), MAC: "02:00:00:00:00:22", Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}},
	}
	in, err := routeros.Project(s)
	if err != nil {
		t.Fatal(err)
	}
	observe := func() routeros.Actual {
		t.Helper()
		a, e := routeros.Observe(r.ctx, c, scope)
		if e != nil {
			t.Fatalf("scoped observation at %s: %v", c.lastMenu, e)
		}
		if len(a.Topology.ForeignRefs) != 0 {
			t.Fatal("fixture or readback has conflicting foreign references")
		}
		return a
	}
	apply := func(a routeros.Actual, target []routeros.Object) []routeros.Op {
		t.Helper()
		ops, e := routeros.Plan(a, target)
		if e != nil {
			t.Fatalf("policy plan: %v", e)
		}
		before := c.writes
		if e = routeros.Execute(r.ctx, c, a, ops); e != nil {
			n := c.writes - before
			// Op comments come from this test's compiled target; raw router
			// replies and executable script text never reach diagnostics.
			last := "none"
			if n > 0 && n <= len(ops) {
				last = ops[n-1].Comment
			}
			t.Fatalf("policy apply at %s after %d writes (%s): %v", c.lastMenu, n, last, e)
		}
		if c.writes-before != len(ops) {
			t.Fatal("unexpected mutation count")
		}
		return ops
	}
	var a routeros.Actual
	for end := time.Now().Add(12 * time.Second); ; {
		a, err = routeros.Observe(r.ctx, c, scope)
		if err == nil && len(a.Topology.FastTrack) == 1 && a.Topology.FastTrack[0].Next != nil {
			break
		}
		if time.Now().After(end) {
			t.Fatal("owner FastTrack fixture not yet effective")
		}
		time.Sleep(150 * time.Millisecond)
	}
	target, err := routeros.Desired(in, a.Topology, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(apply(a, target)) == 0 {
		t.Fatal("empty install")
	}
	a = observe()
	if len(apply(a, target)) != 0 {
		t.Fatal("stable policy was rewritten")
	}
	for _, fixture := range [][]string{
		{"/ip/route", "=dst-address=198.18.240.7/32", "=gateway=198.51.100.254", "=routing-table=tikray-open", "=comment=owner:foreign-route"},
		{filter, "=chain=owner-private", "=action=drop", "=src-address-list=!tikray-domestic", "=comment=owner:foreign-use"},
	} {
		words := append([]string{fixture[0] + "/add"}, fixture[1:]...)
		id := add("foreign reference", words...)
		start := c.writes
		conflicted, e := routeros.Observe(r.ctx, c, scope)
		if e != nil || len(conflicted.Topology.ForeignRefs) == 0 {
			t.Fatal("foreign resource reference not identified", e)
		}
		_, e = routeros.Plan(conflicted, target)
		if e == nil || c.writes != start {
			t.Fatal("unverified shared resource accepted")
		}
		if _, e = r.admin.RunContext(r.ctx, fixture[0]+"/remove", "=.id="+id); e != nil {
			t.Fatal("foreign fixture cleanup failed")
		}
	}
	ownerID := func(menu, tag string) string {
		t.Helper()
		rr, e := r.admin.RunContext(r.ctx, menu+"/print", "?comment="+tag, "=.proplist=.id")
		if e != nil || len(rr.Re) != 1 || rr.Re[0].Map[".id"] == "" {
			t.Fatal("owner fixture identity missing")
		}
		return rr.Re[0].Map[".id"]
	}
	exception := ownerID(filter, "tikray:no-fasttrack")
	ownerOrder, e := r.admin.RunContext(r.ctx, filter+"/print", "?chain=forward", "=.proplist=.id")
	if e != nil {
		t.Fatal("owner order unavailable")
	}
	var order []string
	for _, r := range ownerOrder.Re {
		order = append(order, r.Map[".id"])
	}
	if slices.Index(order, deny) < 0 || slices.Index(order, deny) >= slices.Index(order, exception) || slices.Index(order, exception)+1 != slices.Index(order, ft) || slices.Index(order, accept) <= slices.Index(order, ft) {
		t.Fatal("owner forward order changed")
	}
	const dns = "tikray:dns-router-smart-open-tcp"
	i := slices.IndexFunc(a.Rows, func(row routeros.Observed) bool { return row.Comment == dns })
	if i < 0 {
		t.Fatal("missing DNS control")
	}
	if _, err = r.admin.RunContext(r.ctx, a.Rows[i].Menu+"/remove", "=.id="+ownerID(a.Rows[i].Menu, dns)); err != nil {
		t.Fatal("owner removal failed")
	}
	if ops := apply(observe(), target); len(ops) != 1 || ops[0].Kind != "add" || ops[0].Comment != dns {
		t.Fatal("singleton repair rewrote unrelated policy")
	}
	if len(apply(observe(), target)) != 0 {
		t.Fatal("DNS siblings lost order after repair")
	}
	if _, err = r.admin.RunContext(r.ctx, filter+"/move", "=numbers="+exception, "=destination="+deny); err != nil {
		t.Fatal("owner move fixture failed")
	}
	if ops := apply(observe(), target); len(ops) != 1 || ops[0].Kind != "move" {
		t.Fatal("anchor repair rewrote unrelated policy")
	}
	apply(observe(), nil)
	if len(apply(observe(), nil)) != 0 {
		t.Fatal("detachment did not converge")
	}
	t.Log("restricted diff: install, zero-write readback, single DNS restoration, FastTrack order repair and complete traffic-policy detachment passed")
	checkJournalRestart(t, r, c, scope)
}

func checkJournalRestart(t *testing.T, r *rig, c *countedNative, scope routeros.InstallScope) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("private test state unavailable")
	}
	engine := routeros.NewEngine(c, scope, dir)
	reconcile := func(label string, target routeros.Target) (routeros.Report, error) {
		t.Helper()
		start := time.Now()
		report, err := engine.Reconcile(r.ctx, target)
		t.Logf("one-host engine %s: %.2fs", label, time.Since(start).Seconds())
		return report, err
	}
	selection := runnerapi.Selection{Core: "26.10.31", Config: "config/" + strings.Repeat("a", 64) + ".json"}
	state := store.Default()
	state.Network.Subnet = scope.Subnet
	p, err := routeros.Project(state)
	if err != nil {
		t.Fatal(err)
	}
	baseline := routeros.Target{Revision: 1, Selection: selection, Policy: p, Verify: func(context.Context) error { return nil }}
	if _, err = reconcile("direct baseline", baseline); err != nil {
		t.Fatal("direct baseline", err)
	}
	// The binding and its independent witness are both observed on the
	// router before enabling a closed policy on the first address.
	witness := startTransitionFlows(t, r)
	flow := witness.flow
	peer := flow("192.168.88.110")
	mac, e := r.net.Client(r.ctx, "cat", "/sys/class/net/eth0/address").Output()
	if e != nil {
		t.Fatal("LAN MAC unavailable")
	}
	state.Devices = []store.Device{{Address: netip.MustParsePrefix("192.168.88.10/32"), MAC: strings.TrimSpace(string(mac)), Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}}}
	closed := baseline
	closed.Revision = 2
	closed.Policy, err = routeros.Project(state)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = engine.Prepare(r.ctx, closed)
	t.Logf("one-host engine guard preparation and purge: %.2fs", time.Since(start).Seconds())
	if err != nil {
		if errors.Is(err, routeros.ErrIPv6FlowScope) {
			p, e := r.admin.RunContext(r.ctx, "/ipv6/settings/print", "?forward", "=.proplist=forward,disable-ipv6,ipv6-fasttrack-active,ipv6-fasttrack-packets")
			if e == nil && len(p.Re) == 1 {
				row := p.Re[0].Map
				t.Logf("IPv6 scope: forwarding=%t acceleration enabled=%t acceleration previously used=%t", row["forward"] == "true", row["ipv6-fasttrack-active"] == "true", row["ipv6-fasttrack-packets"] != "" && row["ipv6-fasttrack-packets"] != "0")
			}
		}
		t.Fatalf("stage closed policy at %s: %v", c.lastMenu, err)
	}
	if st, e := os.Stat(filepath.Join(dir, "router-policy.json")); e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("private restart journal missing")
	}
	holds := func() map[string]string {
		t.Helper()
		actual, e := engine.Snapshot(r.ctx)
		if e != nil {
			t.Fatal("guard readback unavailable", e)
		}
		out := map[string]string{}
		for _, r := range actual.Rows {
			if strings.HasPrefix(r.Comment, "tikray:hold:") {
				out[r.Comment] = r.ID
			}
		}
		return out
	}
	installed := holds()
	if len(installed) == 0 || flow("192.168.88.10") != "" || flow("192.168.88.110") != peer {
		t.Fatal("guard or targeted conntrack invalidation failed")
	}
	engine = routeros.NewEngine(c, scope, dir)
	closed.Verify = func(context.Context) error { return errors.New("runner selection pending") }
	if _, err = reconcile("restart with unverified runner", closed); err == nil || !maps.Equal(holds(), installed) {
		t.Fatal("unverified selection released protection after restart")
	}
	closed.Verify = baseline.Verify
	if _, err = reconcile("complete transition", closed); err != nil {
		t.Fatalf("finish closed policy at %s: %v", c.lastMenu, err)
	}
	if len(holds()) != 0 {
		t.Fatal("verified transition retained temporary guards")
	}
	writes := c.writes
	report, err := reconcile("verified no-op", closed)
	if err != nil || c.writes != writes || report.Invalidated != 0 {
		t.Fatal("verified closed policy did not converge", err)
	}
	checkClosedRoutePolling(t, r, c, engine, closed, witness, peer)
	file := "emergency-off.rsc"
	if r.chr.Push(r.ctx, filepath.Join("..", "..", "routeros", file), file) != nil {
		t.Fatal("emergency script upload failed")
	}
	verdict, e := r.chr.RunPrivate(r.ctx, `:do {/import file-name=emergency-off.rsc; /system/script/run tikray-emergency-off; :put "armed-off"} on-error={:put "failed"}`)
	if e != nil || !strings.HasSuffix(strings.TrimSpace(verdict), "armed-off") {
		t.Fatal("emergency command failed")
	}
	marker, busy, e := routeros.EmergencyState(r.ctx, c, c.Generation())
	if e != nil || marker == "" || busy {
		t.Fatal("emergency suspension was not observable")
	}
	proof, e := c.CommandAt(r.ctx, c.Generation(), []string{"/system/script/print", "?.id=" + marker, "?comment=tikray:emergency-state", "=.proplist=policy,dont-require-permissions"})
	if e != nil || len(proof) != 1 {
		t.Fatal("restricted marker permissions were unreadable")
	}
	perms := strings.FieldsFunc(proof[0]["policy"], func(r rune) bool { return r == ',' || r == ';' || r == ' ' })
	allowed := slices.DeleteFunc(slices.Clone(perms), func(s string) bool { return strings.HasPrefix(s, "!") })
	slices.Sort(allowed)
	t.Logf("restricted marker: policy exactly read,write=%t stored literal read,write=%t explicit negatives=%t dont-require-permissions=false=%t", slices.Equal(allowed, []string{"read", "write"}), proof[0]["policy"] == "read,write", len(perms) != len(allowed), proof[0]["dont-require-permissions"] == "false")
	if _, err = reconcile("emergency re-arm", closed); err != nil {
		t.Fatalf("re-arm at %s: %v", c.lastMenu, err)
	}
	marker, busy, e = routeros.EmergencyState(r.ctx, c, c.Generation())
	if e != nil || marker != "" || busy || len(holds()) != 0 {
		t.Fatal("re-arm did not verify and remove emergency marker")
	}
	baseline.Revision = 3
	if _, err = reconcile("restore direct", baseline); err != nil {
		t.Fatalf("restore direct policy at %s: %v", c.lastMenu, err)
	}
	if flow("192.168.88.110") != peer {
		t.Fatal("unaffected peer binding changed")
	}
	t.Log("journal: guarded transition, selective purge, restart with rejected runner proof, successful re-arm and verified direct restoration")
}

type trafficWitness struct {
	flow   func(string) string
	counts func() (int, int)
	sender func(bool) *exec.Cmd
}

func startTransitionFlows(t *testing.T, r *rig) trafficWitness {
	t.Helper()
	if _, e := r.chr.RunPrivate(r.ctx, "/ip/firewall/connection/tracking/set enabled=yes udp-timeout=8m udp-stream-timeout=8m"); e != nil {
		t.Fatal("tracking fixture failed")
	}
	if r.net.Client(r.ctx, "ip", "addr", "add", "192.168.88.110/32", "dev", "eth0").Run() != nil {
		t.Fatal("peer alias failed")
	}
	if r.net.Inet(r.ctx, "ip", "addr", "add", "93.184.216.248/32", "dev", "lo").Run() != nil {
		t.Fatal("WAN target failed")
	}
	// The WAN namespace needs a return route for reverse-path validation
	// of an original LAN source, including a packet sent without masquerade.
	if r.net.Inet(r.ctx, "ip", "route", "add", "192.168.88.0/24", "via", "198.51.100.2").Run() != nil {
		t.Fatal("WAN witness return route failed")
	}
	trace := filepath.Join(t.TempDir(), "wan-packets")
	receiver := r.net.Inet(r.ctx, "python3", "-c", `import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("93.184.216.248",31947))
with open(sys.argv[1],"wb",buffering=0) as log:
 while True:
  data,_=s.recvfrom(64)
  if data in (b"C",b"D"):log.write(data)`, trace)
	if receiver.Start() != nil {
		t.Fatal("WAN witness failed")
	}
	t.Cleanup(func() { receiver.Process.Kill(); receiver.Wait() })
	counts := func() (int, int) {
		t.Helper()
		b, e := os.ReadFile(trace)
		if errors.Is(e, os.ErrNotExist) {
			return 0, 0
		}
		if e != nil {
			t.Fatal("WAN observation unavailable")
		}
		return bytes.Count(b, []byte("C")), bytes.Count(b, []byte("D"))
	}
	sender := func(stream bool) *exec.Cmd {
		return r.net.Client(r.ctx, "python3", "-c", `import socket,sys,time
sockets=[]
for ip,data in (("192.168.88.10",b"C"),("192.168.88.110",b"D")):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((ip,31946));sockets.append((s,data))
while True:
 for s,data in sockets:s.sendto(data,("93.184.216.248",31947))
 if sys.argv[1]!="true":break
 time.sleep(.1)`, strconv.FormatBool(stream))
	}
	flow := func(src string) string {
		t.Helper()
		rw, e := r.admin.RunContext(r.ctx, "/ip/firewall/connection/print", "?src-address="+src, "?dst-address=93.184.216.248", "?src-port=31946", "?dst-port=31947", "=.proplist=.id")
		if e != nil || len(rw.Re) > 1 {
			t.Fatal("flow witness unavailable")
		}
		if len(rw.Re) == 0 {
			return ""
		}
		return rw.Re[0].Map[".id"]
	}
	for end := time.Now().Add(12 * time.Second); ; {
		if sender(false).Run() != nil {
			t.Fatal("LAN flow fixture failed")
		}
		c, d := counts()
		if c > 0 && d > 0 && flow("192.168.88.10") != "" && flow("192.168.88.110") != "" {
			return trafficWitness{flow, counts, sender}
		}
		if time.Now().After(end) {
			t.Fatal("both source payloads must reach the WAN in the direct positive control")
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func checkClosedRoutePolling(t *testing.T, r *rig, c *countedNative, engine *routeros.Engine, closed routeros.Target, w trafficWitness, peer string) {
	t.Helper()
	const routes = "/ip/route"
	tags := []string{"tikray:route-closed-runner", "tikray:route-closed-fallback"}
	match := func(tag string) []string {
		return []string{routes + "/print", "?comment=" + tag, "?routing-table=tikray-closed", "?dst-address=0.0.0.0/0", "=.proplist=.id"}
	}
	drops := func() uint64 {
		t.Helper()
		var total uint64
		for _, tag := range []string{"tikray:egress-drop-full", "tikray:egress-drop-marked"} {
			rw, e := r.admin.RunContext(r.ctx, "/ip/firewall/filter/print", "?comment="+tag, "=.proplist=packets")
			if e != nil || len(rw.Re) != 1 {
				t.Fatal("closed egress counter unavailable")
			}
			count, e := strconv.ParseUint(rw.Re[0].Map["packets"], 10, 64)
			if e != nil {
				t.Fatal("invalid egress counter")
			}
			total += count
		}
		return total
	}
	blocked, control := w.counts()
	sender := w.sender(true)
	if sender.Start() != nil {
		t.Fatal("continuous route-drift traffic failed")
	}
	defer func() { sender.Process.Kill(); sender.Wait() }()
	for _, tag := range tags {
		rw, e := r.admin.RunArgsContext(r.ctx, match(tag))
		if e != nil || len(rw.Re) != 1 {
			t.Fatal("scoped route identity missing before drift")
		}
		if _, e = r.admin.RunContext(r.ctx, routes+"/remove", "=.id="+rw.Re[0].Map[".id"]); e != nil {
			t.Fatal("fixture route removal failed")
		}
	}
	for _, tag := range tags {
		rw, e := r.admin.RunArgsContext(r.ctx, match(tag))
		if e != nil || len(rw.Re) != 0 {
			t.Fatal("closed routes still present in drift interval")
		}
	}
	before := drops()
	// A quiet receiver cannot certify isolation. Require a fresh witness
	// in every second of the 30-second route poll with both routes gone.
	last := control
	for range 30 {
		select {
		case <-r.ctx.Done():
			t.Fatal("route observation cancelled")
		case <-time.After(time.Second):
		}
		closedCount, directCount := w.counts()
		if closedCount != blocked || directCount <= last {
			t.Fatal("WAN leak or missing direct control during route drift")
		}
		last = directCount
	}
	if drops() <= before {
		t.Fatal("closed egress guard did not observe the test traffic")
	}
	writes := c.writes
	report, e := engine.Reconcile(r.ctx, closed)
	if e != nil || report.Added != 2 || report.Set+report.Removed+report.Moved+report.Invalidated != 0 || c.writes-writes != 2 {
		t.Fatal("route drift repair changed unrelated state", e)
	}
	for _, tag := range tags {
		rw, e := r.admin.RunArgsContext(r.ctx, match(tag))
		if e != nil || len(rw.Re) != 1 {
			t.Fatal("exact closed route was not restored")
		}
	}
	closedCount, directCount := w.counts()
	if closedCount != blocked || directCount <= last || w.flow("192.168.88.110") != peer {
		t.Fatal("WAN leak or interrupted peer during route repair")
	}
	t.Logf("30-second route drift: zero closed WAN packets, %d direct WAN packets and advancing closed guard counters; two owned routes restored, peer binding preserved", directCount-control)
}
