//go:build lab

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/test/lab"
	"golang.org/x/crypto/ssh"
)

// Fixed payload and source port distinguish a fresh policy-client flow from
// the continuous direct peer on the same real WAN destination. Its source as
// received on the fake internet distinguishes both VLESS egresses from WAN.
type routingWAN struct {
	trace string
}

func newRoutingWAN(ctx context.Context, t *testing.T, f *routingLab) *routingWAN {
	t.Helper()
	w := &routingWAN{filepath.Join(t.TempDir(), "wan-observations")}
	// Capture on the wire before reverse-path filtering or UDP delivery. A
	// leaking packet with an untranslated private source still counts. Local
	// VLESS egresses terminate in this namespace, so a second UDP socket
	// certifies the closed client's positive proxied control separately.
	serve := f.Net.Inet(ctx, "python3", "-c", `import select,socket,struct,sys
target=socket.inet_aton(sys.argv[1])
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.bind((sys.argv[1],31947))
wire=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800)); wire.bind(("wan0",0))
with open(sys.argv[2],"wb",buffering=0) as log:
 while True:
  ready,_,_=select.select([udp,wire],[],[])
  for s in ready:
   if s is udp:
    p,addr=udp.recvfrom(32)
    if p==b"C" and addr[0] in sys.argv[4:6]:log.write(b"P")
    continue
   frame=wire.recv(65535)
   if len(frame)<43 or frame[12:14]!=b"\x08\x00" or frame[23]!=17 or frame[30:34]!=target:continue
   start=14+4*(frame[14]&15)
   if len(frame)<start+9:continue
   _,port,size,_=struct.unpack_from("!4H",frame,start)
   p=frame[start+8:start+size]
   if port!=31947 or p not in (b"C",b"D"):continue
   if p==b"D" and frame[26:30]!=socket.inet_aton(sys.argv[3]):p=b"?"
   log.write(p)`, routingRemote, w.trace, egressDirect, serverEgress["a"], serverEgress["b"])
	startRoutingProcess(t, serve)
	return w
}

func startRoutingProcess(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Start(); err != nil {
		t.Fatal("traffic witness did not start")
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
}

func (w *routingWAN) sample(t *testing.T) wanSample {
	t.Helper()
	b, err := os.ReadFile(w.trace)
	if errors.Is(err, os.ErrNotExist) {
		return wanSample{}
	}
	if err != nil {
		t.Fatal("WAN trace unavailable")
	}
	return wanSample{
		closedDirect: bytes.Count(b, []byte{'C'}), closedProxy: bytes.Count(b, []byte{'P'}),
		peerDirect: bytes.Count(b, []byte{'D'}), unknown: bytes.Count(b, []byte{'?'}),
	}
}

const routingEmitter = `import socket,sys,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],31946))
while True:
 s.sendto(sys.argv[2].encode(),(sys.argv[3],31947))
 if sys.argv[4]=="once": break
 time.sleep(.1)`

func (f *routingLab) taggedID(ctx context.Context, t *testing.T, menu, tag string) string {
	t.Helper()
	rows := f.readROS(ctx, t, menu, ".id,comment", "?comment="+tag)
	if len(rows) == 0 {
		return ""
	}
	if len(rows) != 1 || rows[0]["comment"] != tag || rows[0][".id"] == "" {
		t.Fatal("router row identity is ambiguous")
	}
	return rows[0][".id"]
}

func (f *routingLab) routingWrite(ctx context.Context, t *testing.T, words ...string) {
	t.Helper()
	if _, err := f.ros.CommandAt(ctx, f.ros.Generation(), words); err != nil {
		t.Fatalf("owner fixture operation failed at %s", words[0])
	}
}

// Compare the whole managed traffic inventory (including exact row IDs)
// around repairs. RouterOS can reorder its route print as activity changes.
func (f *routingLab) policyInventory(ctx context.Context, t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, menu := range []string{"/ip/firewall/filter", "/ip/firewall/mangle", "/ip/firewall/nat", "/ip/firewall/address-list", "/ipv6/firewall/filter", "/ip/route", "/routing/table", "/tool/netwatch"} {
		rows := f.readROS(ctx, t, menu, ".id,comment", "?>comment=tikray:", "?<comment=tikray;", "?#&")
		for _, row := range rows {
			key := menu + "|" + row["comment"]
			if row[".id"] == "" || !strings.HasPrefix(row["comment"], "tikray:") || out[key] != "" {
				t.Fatal("unverified policy inventory")
			}
			out[key] = row[".id"]
		}
	}
	return out
}

func (f *routingLab) eventCursor(ctx context.Context, t *testing.T) uint64 {
	t.Helper()
	reply, err := f.api.Events(ctx, 0)
	var events []service.Event
	if err != nil || json.Unmarshal(reply.Body, &events) != nil {
		t.Fatal("router event inventory unavailable")
	}
	var seq uint64
	for _, e := range events {
		seq = max(seq, e.Seq)
	}
	return seq
}

func (f *routingLab) waitForDriftEvent(ctx context.Context, t *testing.T, after uint64) {
	t.Helper()
	_, ok := poll(ctx, 95*time.Second, 750*time.Millisecond, func() bool {
		reply, err := f.api.Events(ctx, after)
		var events []service.Event
		return err == nil && json.Unmarshal(reply.Body, &events) == nil && slices.ContainsFunc(events, func(e service.Event) bool {
			return e.Seq > after && e.Kind == service.KindRouter && e.Message == "drift corrected"
		})
	})
	if !ok {
		t.Fatal("verified drift repair did not produce a new service event")
	}
}

func (f *routingLab) checkDriftRepair(ctx context.Context, t *testing.T) {
	t.Helper()
	f.setClientPolicy(ctx, t, store.Policy{Mode: store.ModeDirect})
	w := newRoutingWAN(ctx, t, f)
	startRoutingProcess(t, f.peer(ctx, "python3", "-c", routingEmitter, "192.168.88.110", "D", routingRemote, "stream"))
	peer := f.tcpFlow(ctx, t, true, 31369)
	if peer.echo(t) != egressDirect {
		t.Fatal("direct peer did not receive its own WAN echo")
	}
	id := peer.id(ctx, t)
	if id == "" {
		t.Fatal("direct peer has no live two-way WAN flow")
	}
	_, ok := poll(ctx, 12*time.Second, 250*time.Millisecond, func() bool {
		if f.Net.Client(ctx, "python3", "-c", routingEmitter, "192.168.88.10", "C", routingRemote, "once").Run() != nil {
			t.Fatal("LAN emitter unavailable")
		}
		s := w.sample(t)
		return s.closedDirect > 0 && s.peerDirect > 0 && s.unknown == 0
	})
	if !ok {
		t.Fatal("WAN receiver could not see both client addresses directly")
	}
	f.setClientPolicy(ctx, t, store.Policy{Mode: store.ModeFull, KillSwitch: true})
	startRoutingProcess(t, f.Net.Client(ctx, "python3", "-c", routingEmitter, "192.168.88.10", "C", routingRemote, "stream"))
	_, ok = poll(ctx, f.proxiedWithin(), time.Second, func() bool { return w.sample(t).closedProxy > 0 })
	if !ok {
		t.Fatal("closed-client traffic never reached the WAN witness through xray")
	}

	const nat = "/ip/firewall/nat"
	const dns = "tikray:dns-full-closed-tcp"
	prev := f.policyInventory(ctx, t)
	configuration := func(menu, tag, fields string) map[string]string {
		t.Helper()
		rr := f.readROS(ctx, t, menu, fields, "?comment="+tag)
		if len(rr) != 1 {
			t.Fatal("missing configuration witness", tag)
		}
		return rr[0]
	}
	const dnsFields = "chain,action,src-address-list,in-interface-list,protocol,dst-port,to-addresses,to-ports,disabled"
	wantDNS := configuration(nat, dns, dnsFields)
	dnsID := f.taggedID(ctx, t, nat, dns)
	if dnsID == "" || prev[nat+"|"+dns] != dnsID {
		t.Fatal("initial tagged DNS rule missing")
	}
	seq := f.eventCursor(ctx, t)
	f.routingWrite(ctx, t, nat+"/remove", "=.id="+dnsID)
	f.waitForDriftEvent(ctx, t, seq)
	repaired := f.policyInventory(ctx, t)
	newID := f.taggedID(ctx, t, nat, dns)
	if newID == "" || !maps.Equal(configuration(nat, dns, dnsFields), wantDNS) {
		t.Fatal("tagged TCP DNS rule was not recreated")
	}
	prev[nat+"|"+dns] = newID
	if !maps.Equal(prev, repaired) {
		t.Fatal("recreating a single tagged rule changed unrelated row IDs")
	}

	// Hold only the control process's native API connection while withdrawing
	// the routes. This puts a genuine sweep-sized interval between the loss
	// and the service's next successful observation; xray, LAN and the owner
	// all remain up. Dropping in raw precedes an established input accept.
	const raw = "/ip/firewall/raw"
	const gate = "lab:delay-routing-observation"
	words := []string{raw + "/add", "=chain=prerouting", "=action=drop", "=in-interface=tikray", "=src-address=" + installControl, "=dst-address=172.30.252.1", "=protocol=tcp", "=dst-port=9879", "=comment=" + gate}
	bounds := f.readROS(ctx, t, raw, ".id", "?chain=prerouting", "?dynamic=false")
	if len(bounds) > 0 {
		words = append(words, "=place-before="+bounds[0][".id"])
	}
	f.routingWrite(ctx, t, words...)
	gateID := f.taggedID(ctx, t, raw, gate)
	if gateID == "" {
		t.Fatal("control-transport fixture missing")
	}
	release := func() {
		if gateID == "" {
			return
		}
		if got := f.taggedID(ctx, t, raw, gate); got != gateID {
			t.Fatal("control-transport fixture changed ownership")
		}
		f.routingWrite(ctx, t, raw+"/remove", "=.id="+gateID)
		gateID = ""
	}
	defer release()
	const routes = "/ip/route"
	tags := []string{"tikray:route-closed-runner", "tikray:route-closed-fallback"}
	const routeFields = "dst-address,routing-table,gateway,distance,check-gateway,blackhole,disabled"
	wantRoutes := map[string]map[string]string{}
	seq = f.eventCursor(ctx, t)
	leakBase := w.sample(t).closedDirect
	for _, tag := range tags {
		wantRoutes[tag] = configuration(routes, tag, routeFields)
		was := prev[routes+"|"+tag]
		if was == "" {
			t.Fatal("closed route fixture missing")
		}
		f.routingWrite(ctx, t, routes+"/remove", "=.id="+was)
		if f.taggedID(ctx, t, routes, tag) != "" {
			t.Fatal("closed route remained before the polling window")
		}
	}
	drops := func() uint64 {
		var n uint64
		for _, tag := range []string{"tikray:egress-drop-full", "tikray:egress-drop-marked"} {
			rows := f.readROS(ctx, t, "/ip/firewall/filter", "packets", "?comment="+tag)
			if len(rows) != 1 {
				t.Fatal("closed guard missing")
			}
			k, e := strconv.ParseUint(rows[0]["packets"], 10, 64)
			if e != nil {
				t.Fatal("guard counter unavailable")
			}
			n += k
		}
		return n
	}
	d0 := drops()
	s := w.sample(t)
	peerBase := s.peerDirect
	if s.closedDirect != leakBase || s.unknown != 0 {
		t.Fatal("closed WAN leak at route removal")
	}
	for range 30 {
		if sleep(ctx, time.Second) != nil {
			t.Fatal("closed route observation cancelled")
		}
		next := w.sample(t)
		if !next.isolatedSince(s) {
			t.Fatal("closed WAN leak or missing same-second direct witness")
		}
		s = next
	}
	if d := drops(); d <= d0 {
		t.Fatalf("closed guard did not account for probes during route absence (%d -> %d)", d0, d)
	}
	if peer.echo(t) != egressDirect || peer.id(ctx, t) != id {
		t.Fatal("unrelated TCP connection was interrupted during route absence")
	}
	for _, tag := range tags {
		if f.taggedID(ctx, t, routes, tag) != "" {
			t.Fatal("closed route returned before the end of the polling window")
		}
	}
	release()
	f.waitForDriftEvent(ctx, t, seq)
	final := f.policyInventory(ctx, t)
	for _, tag := range tags {
		key := routes + "|" + tag
		if final[key] == "" || !maps.Equal(configuration(routes, tag, routeFields), wantRoutes[tag]) {
			t.Fatal("withdrawn route was not restored")
		}
		prev[key] = final[key]
	}
	if !maps.Equal(prev, final) {
		t.Fatal("route repair rewrote unrelated policy rows")
	}
	_, ok = poll(ctx, 25*time.Second, 250*time.Millisecond, func() bool { return w.sample(t).closedProxy > s.closedProxy })
	if !ok || w.sample(t).closedDirect != leakBase || peer.echo(t) != egressDirect || peer.id(ctx, t) != id {
		t.Fatal("closed route repair leaked or failed to restore the proxy without interrupting its peer")
	}
	f.checkOwnerRules(ctx, t)
	t.Logf("zero direct closed packets with both routes absent for 30 seconds; %d direct peer packets received by the same WAN service; closed filter counters increased; same peer connection survived", s.peerDirect-peerBase)
}

// Keep an authenticated connection from the independent owner's LAN address
// open throughout the outage. Each round trip opens a new command channel,
// so the test also exercises the router's SSH service after steering changes.
func (f *routingLab) ownerLANSSH(ctx context.Context, t *testing.T) func() {
	t.Helper()
	pw, err := os.ReadFile(filepath.Join(lab.CacheDir(), "ready", f.Version, string(f.Arch), "password"))
	if err != nil {
		t.Fatal("owner SSH fixture unavailable")
	}
	d := net.Dialer{Timeout: 10 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("192.168.88.201")}}
	const target = "192.168.88.1:22"
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatal("independent owner LAN could not reach SSH")
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(12 * time.Second))
	// The VM is freshly cloned on the private lab LAN, as in lab.CHR.
	cc, chans, reqs, err := ssh.NewClientConn(conn, target, &ssh.ClientConfig{
		User: "admin+ct", Auth: []ssh.AuthMethod{ssh.Password(string(pw))}, HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal("independent owner LAN SSH login failed")
	}
	c := ssh.NewClient(cc, chans, reqs)
	t.Cleanup(func() { c.Close() })
	conn.SetDeadline(time.Time{})
	return func() {
		t.Helper()
		conn.SetDeadline(time.Now().Add(12 * time.Second))
		defer conn.SetDeadline(time.Time{})
		s, err := c.NewSession()
		if err != nil {
			t.Fatal("original owner LAN SSH transport was lost")
		}
		defer s.Close()
		out, err := s.Output(`:put "owner-lan-ok"`)
		if err != nil || strings.TrimSpace(string(out)) != "owner-lan-ok" {
			t.Fatal("owner LAN SSH command failed")
		}
	}
}

func (f *routingLab) checkEmergencyOff(ctx context.Context, t *testing.T) {
	t.Helper()
	f.setClientPolicy(ctx, t, store.Policy{Mode: store.ModeFull, KillSwitch: true})
	peer := f.tcpFlow(ctx, t, true, 31370)
	if peer.echo(t) != egressDirect {
		t.Fatal("unaffected peer did not receive its own WAN echo")
	}
	id := peer.id(ctx, t)
	ownerGeneration := f.ros.Generation()
	lanSSH := f.ownerLANSSH(ctx, t)
	ownerLive := func() {
		t.Helper()
		lanSSH()
		rows, e := f.ros.CommandAt(ctx, ownerGeneration, []string{"/system/resource/print", "?version", "=.proplist=version"})
		if e != nil || len(rows) != 1 {
			t.Fatal("original owner's API-SSL session did not survive")
		}
		if peer.echo(t) != egressDirect || peer.id(ctx, t) != id || id == "" {
			t.Fatal("unrelated client connection lost continuity")
		}
		f.checkOwnerRules(ctx, t)
	}
	paths := func(suspended bool) {
		t.Helper()
		via := f.egress(ctx, routingRemote)
		if (suspended && via != egressDirect) || (!suspended && via != serverEgress["a"] && via != serverEgress["b"]) {
			t.Fatal("unexpected emergency IPv4 path")
		}
		for _, transport := range []string{"tcp", "udp"} {
			q := strconv.FormatInt(time.Now().UnixNano(), 10) + ".foreign.routing-probe.test"
			want := "198.18.53.2"
			if suspended {
				want = "198.18.53.1"
			}
			if !slices.Equal(f.protocolDNS(ctx, t, false, q, "A", transport, "203.0.113.53"), []string{want}) {
				t.Fatal("unexpected emergency DNS path", transport)
			}
		}
		if f.ipv6Reachable(ctx, t, false) != suspended || !f.ipv6Reachable(ctx, t, true) {
			t.Fatal("unexpected emergency IPv6 forwarding")
		}
		ownerLive()
	}
	paths(false)
	owned := f.policyInventory(ctx, t)
	setContainer := func(name, tag, action, state string) {
		t.Helper()
		rows := f.readROS(ctx, t, "/container", ".id", "?name="+name, "?comment="+tag)
		if len(rows) != 1 || rows[0][".id"] == "" {
			t.Fatal("owned container identity conflict", name)
		}
		f.routingWrite(ctx, t, "/container/"+action, "=.id="+rows[0][".id"])
		if f.waitForContainer(ctx, name, state) != nil {
			t.Fatal("container did not enter expected state", name, state)
		}
	}
	// Stop control first so no ordinary apply can re-arm during the outage.
	setContainer("tikray", "tikray:tikray", "stop", "stopped")
	setContainer("tikray-runner", "tikray:runner", "stop", "stopped")
	runs := func() int {
		t.Helper()
		rows := f.readROS(ctx, t, "/system/script", ".id,run-count", "?name=tikray-emergency-off", "?comment=tikray:emergency-off")
		if len(rows) != 1 {
			t.Fatal("off command missing")
		}
		n, err := strconv.Atoi(rows[0]["run-count"])
		if err != nil {
			t.Fatal("off command counter unavailable")
		}
		return n
	}
	tick := f.watchdogTicker(ctx, t)
	var ordinary *routingFlow
	var ordinaryID string
	for attempt := 1; attempt <= 2; attempt++ {
		previous := runs()
		f.mustRun(ctx, t, "/system/script/run tikray-emergency-off")
		if runs() != previous+1 || f.taggedID(ctx, t, "/system/script", "tikray:emergency-state") == "" {
			t.Fatal("a real emergency invocation and its marker were not both observed")
		}
		if attempt == 1 {
			// Cross the ordinary three-failure restart threshold while
			// the emergency marker remains armed and both are down.
			for range 3 {
				tick()
			}
		}
		for _, component := range []string{"tikray", "tikray-runner"} {
			if n := f.readROS(ctx, t, "/container", ".id", "?name="+component, "?stopped=true"); len(n) != 1 {
				t.Fatal("emergency proof requires both containers down")
			}
		}
		if !maps.Equal(owned, f.policyInventory(ctx, t)) {
			t.Fatal("emergency command removed or recreated traffic-policy rows")
		}
		paths(true)
		if attempt == 1 {
			ordinary = f.tcpFlow(ctx, t, false, 31371)
		}
		if ordinary.echo(t) != egressDirect {
			t.Fatal("normal LAN flow was interrupted while suspended")
		}
		got := ordinary.id(ctx, t)
		if got == "" || attempt == 2 && got != ordinaryID {
			t.Fatal("repeating emergency off replaced a restored direct binding")
		}
		ordinaryID = got
	}
	setContainer("tikray-runner", "tikray:runner", "start", "running")
	setContainer("tikray", "tikray:tikray", "start", "running")
	f.checkReady(ctx, t)
	if f.taggedID(ctx, t, "/system/script", "tikray:emergency-state") != "" {
		t.Fatal("successful reconcile retained the suspension marker")
	}
	_, ok := poll(ctx, f.proxiedWithin(), time.Second, func() bool {
		ip := f.egress(ctx, routingRemote)
		return ip == serverEgress["a"] || ip == serverEgress["b"]
	})
	if !ok {
		t.Fatal("emergency recovery did not re-arm the proxy")
	}
	paths(false)
	for menu, tag := range map[string]string{"/ip/firewall/filter": "tikray:egress-guard", "/ip/firewall/mangle": "tikray:jump-pre", "/ipv6/firewall/filter": "tikray:ipv6:jump"} {
		if len(f.readROS(ctx, t, menu, ".id", "?comment="+tag, "?disabled=false")) != 1 {
			t.Fatal("verified rearm did not restore a protection hook")
		}
	}
}
