//go:build lab

package m3

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/store"
)

// Exercise the actual compiler output. The existing rig represents control
// and runner endpoints on the isolated LAN and boots a fresh writable overlay.
func TestM3CompiledIPv4(t *testing.T) {
	r := newRig(t)
	const lan = "m3-probe-lan"
	ownerAdd := func(label string, words ...string) string {
		t.Helper()
		reply, err := r.admin.RunArgsContext(r.ctx, words)
		if err != nil || reply.Done == nil || reply.Done.Map["ret"] == "" {
			t.Fatalf("fixture add failed: %s", label)
		}
		return reply.Done.Map["ret"]
	}
	ownerAdd("container bridge", "/interface/bridge/add", "=name=tikray", "=protocol-mode=none")
	ownerAdd("LAN list", "/interface/list/add", "=name="+lan)
	ownerAdd("LAN membership", "/interface/list/member/add", "=list="+lan, "=interface=ether2")
	deny := ownerAdd("prior owner deny", "/ip/firewall/filter/add", "=chain=forward", "=action=drop", "=src-address=198.18.222.101", "=comment=owner:policy-prior")
	v6Anchor := ownerAdd("IPv6 forward anchor", "/ipv6/firewall/filter/add", "=chain=forward", "=action=drop", "=src-address=2001:db8:207::7/128", "=comment=owner:policy-v6")
	ft := ownerAdd("owner FastTrack", "/ip/firewall/filter/add", "=chain=forward", "=action=fasttrack-connection", "=connection-state=established,related", "=comment=owner:policy-fasttrack")
	after := ownerAdd("owner slow-path accept", "/ip/firewall/filter/add", "=chain=forward", "=action=accept", "=connection-state=established,related", "=comment=owner:policy-after")
	const ownerTable = "owner-policy"
	ownerAdd("foreign FIB", "/routing/table/add", "=fib=yes", "=name="+ownerTable)
	ownerAdd("foreign default", "/ip/route/add", "=dst-address=0.0.0.0/0", "=gateway=198.51.100.254", "=routing-table="+ownerTable)
	ownerAdd("foreign passthrough route mark", "/ip/firewall/mangle/add", "=chain=prerouting", "=in-interface=ether2", "=protocol=udp", "=src-port=31579", "=action=mark-routing", "=new-routing-mark="+ownerTable, "=passthrough=yes")
	mac, err := r.net.Client(r.ctx, "cat", "/sys/class/net/eth0/address").Output()
	if err != nil {
		t.Fatal("client identity unavailable")
	}
	st := store.Default()
	st.Devices = []store.Device{
		{Address: netip.MustParsePrefix("192.168.88.10/32"), MAC: strings.TrimSpace(string(mac)), Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}},
		{Address: netip.MustParsePrefix("192.168.88.21/32"), MAC: "02:00:00:00:00:21", Policy: store.Policy{Mode: store.ModeSmart}},
	}
	in, err := routeros.Project(st)
	if err != nil {
		t.Fatal("policy projection failed")
	}
	obs := routeros.Topology{
		Subnet: st.Network.Subnet, LANList: lan, LANMembers: []string{"ether2"},
		ForeignRoutingMarks: []string{ownerTable},
		LANs:                []routeros.LAN{{Interface: "ether2", Prefix: netip.MustParsePrefix("192.168.88.0/24")}},
		RouterIPs:           []netip.Addr{netip.MustParseAddr("192.168.88.1")},
		WAN:                 []routeros.WANPath{{Interface: "ether1", Gateway: netip.MustParseAddr("198.51.100.254"), Network: netip.MustParsePrefix("198.51.100.0/24")}},
		FastTrack:           []routeros.FastTrackRule{{ID: ft, Match: map[string]string{"connection-state": "established,related"}, Next: &routeros.ForwardRule{ID: after, Action: "accept", Match: map[string]string{"connection-state": "established,related"}}}},
	}
	rows, err := routeros.Desired(in, obs, nil)
	if err != nil {
		t.Fatal("compiler refused isolated topology")
	}

	// The target is globally routable in the policy classifier but exists
	// only in the lab WAN. A direct positive control proves the listener.
	const target = "93.184.216.248"
	ownerAdd("owner prerouting control", "/ip/firewall/mangle/add", "=chain=prerouting", "=action=passthrough", "=src-address=192.168.88.10", "=dst-address="+target, "=comment=owner:policy-unmarked")
	ownerAdd("explicit main matcher", "/ip/firewall/mangle/add", "=chain=prerouting", "=action=passthrough", "=src-address=192.168.88.10", "=dst-address="+target, "=routing-mark=main", "=comment=owner:policy-main")
	_, noMarkErr := r.admin.RunContext(r.ctx, "/ip/firewall/mangle/add", "=chain=prerouting", "=action=passthrough", "=src-address=192.168.88.10", "=dst-address="+target, "=routing-mark=no-mark", "=comment=owner:policy-no-mark")
	if r.net.Inet(r.ctx, "ip", "addr", "add", target+"/32", "dev", "lo").Run() != nil {
		t.Fatal("WAN witness address failed")
	}
	// Reverse-path filtering on wan0 needs a route back to the LAN client.
	if r.net.Inet(r.ctx, "ip", "route", "add", "192.168.88.0/24", "via", "198.51.100.2", "dev", "wan0").Run() != nil {
		t.Fatal("WAN witness return path failed")
	}
	trace := filepath.Join(t.TempDir(), "wan-witness")
	witness := r.net.Inet(r.ctx, "python3", "-u", "-c", `import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind((sys.argv[1],31578))
with open(sys.argv[2],"wb",buffering=0) as f:
 f.write(b"ready")
 while True:
  data,addr=s.recvfrom(64)
  f.write(b"+" if data==b"control" else b"!")
`, target, trace)
	if witness.Start() != nil {
		t.Fatal("WAN witness failed")
	}
	defer func() { _ = witness.Process.Kill(); _ = witness.Wait() }()
	await := func(label string, limit time.Duration, ok func() bool) {
		t.Helper()
		for end := time.Now().Add(limit); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
			if ok() {
				return
			}
		}
		t.Fatalf("observation timed out: %s", label)
	}
	traceIs := func(want string) bool { b, e := os.ReadFile(trace); return e == nil && string(b) == want }
	await("WAN readiness", 4*time.Second, func() bool { return traceIs("ready") })
	send := func(payload string) {
		t.Helper()
		if r.net.Client(r.ctx, "python3", "-c", `import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
if sys.argv[2]=="foreign": s.bind(("192.168.88.10",31579))
s.sendto(sys.argv[2].encode(),(sys.argv[1],31578))`, target, payload).Run() != nil {
			t.Fatal("LAN datagram failed")
		}
	}
	send("control")
	await("WAN positive control", 5*time.Second, func() bool { return traceIs("ready+") })

	ids := map[string]string{}
	openDNS, closedDNS := "", ""
	var openRow routeros.Object
	create := func(o routeros.Object) string {
		t.Helper()
		words := []string{o.Menu + "/add", "=comment=" + o.Comment}
		var fields []string
		for k, v := range o.Props {
			fields = append(fields, "="+k+"="+v)
		}
		sort.Strings(fields)
		words = append(words, fields...)
		if o.InitialDisabled {
			words = append(words, "=disabled=yes")
		}
		switch {
		case o.Before == "first:forward" && o.Menu == "/ip/firewall/filter":
			words = append(words, "=place-before="+deny)
		case o.Before == "first:forward" && o.Menu == "/ipv6/firewall/filter":
			words = append(words, "=place-before="+v6Anchor)
		case o.Before == ft:
			words = append(words, "=place-before="+ft)
		case strings.HasPrefix(o.Before, "tikray:") && ids[o.Before] != "":
			words = append(words, "=place-before="+ids[o.Before])
		case o.Before == "first:dstnat":
			// A repaired primary precedes its already-installed fallback.
			after := false
			for _, other := range rows {
				if after && other.Menu == o.Menu && other.Props["chain"] == o.Props["chain"] && ids[other.Comment] != "" {
					words = append(words, "=place-before="+ids[other.Comment])
					break
				}
				if o.Comment == other.Comment {
					after = true
				}
			}
		}
		reply, err := r.api.RunArgsContext(r.ctx, words)
		if err != nil || reply.Done == nil || reply.Done.Map["ret"] == "" {
			t.Fatalf("compiler row rejected: %s", o.Comment)
		}
		return reply.Done.Map["ret"]
	}
	for _, o := range rows {
		ids[o.Comment] = create(o)
		if o.Menu == "/ip/firewall/nat" && o.Props["action"] == "dst-nat" && o.Props["protocol"] == "udp" {
			if o.InitialDisabled {
				openDNS = o.Comment
				openRow = o
			} else {
				closedDNS = o.Comment
			}
		}
	}
	read := func(menu, tag, field string) string {
		t.Helper()
		reply, e := r.api.RunContext(r.ctx, menu+"/print", "?comment="+tag, "=.proplist="+field)
		if e != nil || len(reply.Re) != 1 {
			t.Fatal("scoped compiler observation failed")
		}
		return reply.Re[0].Map[field]
	}
	mutate := func(menu, op, tag string) {
		t.Helper()
		if ids[tag] == "" {
			t.Fatal("missing fixture identity")
		}
		if _, err := r.api.RunContext(r.ctx, menu+"/"+op, "=.id="+ids[tag]); err != nil {
			t.Fatalf("fixture change failed: %s", tag)
		}
	}
	// With neither closed route installed, the main default is reachable.
	// Observe both the classifier and the independent early guard, and
	// witness that no packet arrived on the WAN after the positive control.
	await("installed prerouting hook becomes valid", 15*time.Second, func() bool { return read("/ip/firewall/mangle", "tikray:jump-pre", "invalid") == "false" })
	for _, tag := range []string{"tikray:route-closed-runner", "tikray:route-closed-fallback"} {
		mutate("/ip/route", "remove", tag)
	}
	for range 3 {
		send("closed")
	}
	count := func(menu, tag string) int { n, _ := strconv.Atoi(read(menu, tag, "packets")); return n }
	classified := count("/ip/firewall/mangle", "tikray:conn-full-closed")
	routed := count("/ip/firewall/mangle", "tikray:route-closed")
	guarded := count("/ip/firewall/filter", "tikray:egress-drop-marked")
	packetMarks := count("/ip/firewall/mangle", "tikray:packet-closed")
	noMark := -1
	if noMarkErr == nil {
		noMark = count("/ip/firewall/mangle", "owner:policy-no-mark")
	}
	t.Logf("matcher controls: ordinary=%d explicitMain=%d noMarkAccepted=%t noMarkPackets=%d", count("/ip/firewall/mangle", "owner:policy-unmarked"), count("/ip/firewall/mangle", "owner:policy-main"), noMarkErr == nil, noMark)
	if classified < 1 || routed < 1 || guarded < 1 || packetMarks < 1 || !traceIs("ready+") {
		for _, o := range rows {
			if o.Menu == "/ip/firewall/mangle" {
				t.Logf("compiled mangle %s hits=%d invalid=%s", o.Comment, count(o.Menu, o.Comment), read(o.Menu, o.Comment, "invalid"))
			}
		}
		t.Fatalf("closed drift: classified=%d routed=%d guarded=%d packetMarks=%d isolated=%t prerouting=%d mainMatcher=%d sourceGuard=%d", classified, routed, guarded, packetMarks, traceIs("ready+"), count("/ip/firewall/mangle", "owner:policy-unmarked"), count("/ip/firewall/mangle", "owner:policy-main"), count("/ip/firewall/filter", "tikray:egress-drop-full"))
	}
	sourceDrops := count("/ip/firewall/filter", "tikray:egress-drop-full")
	send("foreign")
	await("closed source guard with owner routing mark", 4*time.Second, func() bool { return count("/ip/firewall/filter", "tikray:egress-drop-full") > sourceDrops })
	skippedOwner := false
	for _, o := range rows {
		if o.Menu == "/ip/firewall/mangle" && o.Props["routing-mark"] == ownerTable && o.Props["action"] == "return" {
			skippedOwner = count(o.Menu, o.Comment) > 0
		}
	}
	if !skippedOwner || count("/ip/firewall/mangle", "tikray:conn-full-closed") != classified || !traceIs("ready+") {
		t.Fatal("foreign mark was captured or leaked closed traffic")
	}
	// The owner's routing table contains only a WAN default. Even after
	// dstnat has made the query look local, it may not exit towards WAN.
	const leakDNS = "tikray:egress-dns-full-closed-udp"
	beforeDNS := count("/ip/firewall/filter", leakDNS)
	if r.net.Client(r.ctx, "python3", "-c", `import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("192.168.88.10",31579))
s.sendto(b"misrouted",(sys.argv[1],53))`, target).Run() != nil {
		t.Fatal("foreign-table DNS fixture failed")
	}
	await("translated runner DNS over foreign route", 4*time.Second, func() bool { return count("/ip/firewall/filter", leakDNS) > beforeDNS })
	reply, e := r.admin.RunContext(r.ctx, "/ip/firewall/filter/print", "?chain=forward", "=.proplist=.id")
	if e != nil {
		t.Fatal("owner order check failed")
	}
	var order []string
	for _, row := range reply.Re {
		order = append(order, row.Map[".id"])
	}
	exception := slices.Index(order, ids["tikray:no-fasttrack"])
	if exception < 1 || slices.Index(order, deny) >= exception || slices.Index(order, ft) != exception+1 {
		t.Fatal("FastTrack exception bypassed owner filter order")
	}

	if openDNS == "" || closedDNS == "" {
		t.Fatal("missing DNS classes")
	}
	last := [3]string{}
	dnsState := func(status, open string) bool {
		current := [3]string{read("/tool/netwatch", "tikray:runner-watch", "status"), read("/ip/firewall/nat", openDNS, "disabled"), read("/ip/firewall/nat", closedDNS, "disabled")}
		// Native print omits the never-written disabled bit on enabled rows.
		for i := 1; i < len(current); i++ {
			if current[i] == "" {
				current[i] = "false"
			}
		}
		if current != last {
			// These fields contain a fixed probe status and two booleans.
			t.Logf("watch=%q open-disabled=%q closed-disabled=%q", current[0], current[1], current[2])
			last = current
		}
		return current == [3]string{status, open, "false"}
	}
	// The test endpoint answers only on the disposable bridge. A repaired
	// row starts disabled even if netwatch already observed the runner up.
	await("initial down", 18*time.Second, func() bool { return dnsState("down", "true") })
	runner := st.Network.Runner().String() + "/32"
	if exec.CommandContext(r.ctx, "ip", "addr", "add", runner, "dev", "tklab-lan").Run() != nil {
		t.Fatal("isolated runner peer failed")
	}
	await("runner up", 18*time.Second, func() bool { return dnsState("up", "false") })
	mutate("/ip/firewall/nat", "remove", openDNS)
	ids[openDNS] = create(openRow)
	await("repaired row while already up", 18*time.Second, func() bool { return dnsState("up", "false") })
	if r.net.Client(r.ctx, "ip", "addr", "add", "192.168.88.21/32", "dev", "eth0").Run() != nil {
		t.Fatal("open DNS client unavailable")
	}
	sourcePort := 31600
	query := func(tag string) {
		t.Helper()
		before := count("/ip/firewall/nat", tag)
		// The native disabled bit can change before the firewall addresses
		// new connections with the recompiled rules. Each attempt uses a
		// fresh five-tuple, without expiring a previous DNS binding.
		await("new DNS transaction via "+tag, 8*time.Second, func() bool {
			sourcePort++
			if r.net.Client(r.ctx, "python3", "-c", `import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("192.168.88.21",int(sys.argv[2])))
s.sendto(b"query",(sys.argv[1],53))`, target, strconv.Itoa(sourcePort)).Run() != nil {
				t.Fatal("open DNS transaction failed")
			}
			return count("/ip/firewall/nat", tag) > before
		})
	}
	query(openDNS)
	// Filter only the monitored endpoint. Withdrawing a host address while
	// its ARP entry is warm lets the lab host forward the probes via its
	// existing route to the same subnet on the other side of CHR.
	ownerAdd("runner ICMP loss", "/ip/firewall/filter/add", "=chain=output", "=protocol=icmp", "=dst-address="+st.Network.Runner().String(), "=action=drop", "=comment=owner:policy-icmp-loss")
	await("runner down", 25*time.Second, func() bool { return dnsState("down", "true") })
	if count("/ip/firewall/filter", "owner:policy-icmp-loss") == 0 {
		t.Fatal("loss fixture did not stop runner probes")
	}
	query("tikray:dns-router-smart-open-udp")
	if !traceIs("ready+") {
		t.Fatal("late WAN leak")
	}
	t.Log("compiled IPv4: real LAN marks, closed guard with both routes missing, WAN witness, FastTrack order and autonomous DNS repair passed")
}
