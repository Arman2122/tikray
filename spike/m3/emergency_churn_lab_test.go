//go:build lab

package m3

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	routerfiles "github.com/Arman2122/tikray/routeros"
)

// Expiring LAN flows exercise native menu races during both owner operations.
// A second address keeps one ordinary binding and receives fresh echoed data.
func TestEmergencyConntrackChurn(t *testing.T) {
	r, _, uninstall := uninstallFixture(t)
	ctx, cancel := context.WithTimeout(r.ctx, 8*time.Minute)
	defer cancel()
	cmd := func(s string) string {
		t.Helper()
		v, e := r.chr.RunPrivate(ctx, s)
		if e != nil {
			t.Fatal("private router fixture refused")
		}
		return strings.TrimSpace(v)
	}
	body, e := routerfiles.Sources.ReadFile("emergency-off.rsc")
	if e != nil {
		t.Fatal("missing emergency body")
	}
	path := filepath.Join(t.TempDir(), "off.rsc")
	if os.WriteFile(path, body, 0600) != nil || r.chr.Push(ctx, path, "off.rsc") != nil {
		t.Fatal("stage owner script")
	}
	cmd("/import file-name=off.rsc")
	cmd(`/interface/bridge/add name=tikray protocol-mode=none arp=reply-only comment="tikray:bridge"; /ip/address/add interface=tikray address=10.225.247.1/29 comment="tikray:addr"`)
	cmd(`/interface/list/add name=emergency-clients; /interface/list/member/add list=emergency-clients interface=ether2; /ip/firewall/address-list/add list=tikray-src-full-closed address=192.168.88.10 comment="tikray:src-full-closed:192.168.88.10/32"`)
	cmd(`/ip/firewall/mangle/add chain=tikray-pre action=mark-connection protocol=udp dst-port=31987 connection-state=new connection-mark=no-mark new-connection-mark=tikray-closed src-address-list=tikray-src-full-closed comment="tikray:conn-full-closed"; /ip/firewall/mangle/add chain=prerouting in-interface-list=emergency-clients action=jump jump-target=tikray-pre comment="tikray:jump-pre"`)
	cmd(`/ip/firewall/nat/add chain=dstnat src-address-list=tikray-src-full-closed protocol=udp dst-port=53 action=dst-nat to-addresses=10.225.247.3 to-ports=53 comment="tikray:dns-full-closed-udp"; /ip/firewall/connection/tracking/set enabled=yes udp-timeout=2s udp-stream-timeout=30s`)
	if r.net.Client(ctx, "ip", "addr", "add", "192.168.88.110/32", "dev", "eth0").Run() != nil {
		t.Fatal("add separate client")
	}
	if r.net.Inet(ctx, "ip", "route", "add", "192.168.88.0/24", "via", "198.51.100.2").Run() != nil {
		t.Fatal("return route unavailable")
	}
	server := r.net.Inet(ctx, "python3", "-c", `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("198.51.100.254",31987))
while True:
 data,peer=s.recvfrom(100)
 if data==b"owner":s.sendto(data,peer)`)
	if server.Start() != nil {
		t.Fatal("receiver did not start")
	}
	defer func() { server.Process.Kill(); server.Wait() }()
	// Install the independent owner's rule before the socket is created.
	markPeer := `/ip/firewall/mangle/find where comment="owner:emergency-peer" and chain=prerouting and action=mark-connection and new-connection-mark="owner-emergency-peer"`
	cmd(`/ip/firewall/mangle/add chain=prerouting src-address=192.168.88.110 dst-address=198.51.100.254 protocol=udp src-port=31979 dst-port=31987 connection-mark=no-mark action=mark-connection new-connection-mark=owner-emergency-peer comment="owner:emergency-peer"`)
	markerID := cmd(":put [:tostr [" + markPeer + "]]")
	if markerID == "" {
		t.Fatal("could not establish the independent owner marker")
	}
	countFile := filepath.Join(t.TempDir(), "echo-count")
	proc := r.net.Client(ctx, "python3", "-c", `import socket,time,sys,pathlib
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("192.168.88.110",31979));s.setblocking(False)
seq=0;received=0;counter=pathlib.Path(sys.argv[1])
while True:
 if seq%10==0:s.sendto(b"owner",("198.51.100.254",31987))
 try:
  if s.recv(40)==b"owner":received+=1;counter.write_text(str(received))
 except BlockingIOError:pass
 t=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);t.bind(("192.168.88.10",20000+seq%20000))
 t.sendto(b"churn",("198.51.100.254",31987));t.sendto(b"dns",("203.0.113.30",53));t.close()
 seq+=1;time.sleep(.013)`, countFile)
	if proc.Start() != nil {
		t.Fatal("private flow generator did not start")
	}
	defer func() { proc.Process.Kill(); proc.Wait() }()
	peerCount := func() int { b, _ := os.ReadFile(countFile); n, _ := strconv.Atoi(string(b)); return n }
	// RouterOS may publish a new menu ID for the very same binding.
	// The owner mark is written before the writer is disabled. A UDP
	// row recreated for the same socket cannot regain that mark.
	type counts struct{ sent, received uint64 }
	peerCounts := func() (counts, bool) {
		out, err := r.chr.RunPrivate(ctx, `{:local rows [/ip/firewall/connection/print detail as-value where src-address=192.168.88.110 and dst-address=198.51.100.254 and src-port=31979 and dst-port=31987 and protocol=udp and connection-mark="owner-emergency-peer"]; :if ([:len $rows]=1) do={:local row [:pick $rows 0]; :put ([:tostr ($row->"orig-packets")] . "," . [:tostr ($row->"repl-packets")])}}`)
		if err != nil {
			return counts{}, false
		}
		out = strings.TrimSpace(out)
		requests, replies, ok := strings.Cut(out, ",")
		sent, e1 := strconv.ParseUint(requests, 10, 64)
		received, e2 := strconv.ParseUint(replies, 10, 64)
		return counts{sent, received}, ok && e1 == nil && e2 == nil && sent > 0 && received > 0
	}
	for end := time.Now().Add(12 * time.Second); ; {
		if _, ok := peerCounts(); ok && peerCount() > 0 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("independent marked echo did not establish")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if cmd(":put [:tostr ["+markPeer+"]]") != markerID {
		t.Fatal("independent owner marker changed")
	}
	cmd("/ip/firewall/mangle/disable [" + markPeer + "]")
	if cmd(":put [/ip/firewall/mangle/get ["+markPeer+"] disabled]") != "true" {
		t.Fatal("independent owner marker could rematch a new flow")
	}
	// A single menu read can trap when another source's UDP entries age
	// out underneath it. Only a positive read of the original marked peer
	// can satisfy this witness.
	waitPeer := func() counts {
		t.Helper()
		for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
			if current, ok := peerCounts(); ok {
				return current
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("independent marked UDP binding unavailable")
		return counts{}
	}
	// Require on-router evidence that candidate IDs naturally expire before
	// exercising one command against both a live mark and a DNS translation.
	q := `/ip/firewall/connection/find where src-address=192.168.88.10 and protocol=udp and dst-port=31987 and connection-mark=tikray-closed`

	var port int
	for end := time.Now().Add(30 * time.Second); port < 20000 || port > 39999; {
		if time.Now().After(end) {
			t.Fatal("no positive marked UDP candidate")
		}
		out := cmd(`{:local list [` + q + `];:if ([:len $list]>0) do={ :do {:put [/ip/firewall/connection/get [:pick $list 0] src-port]} on-error={} }}`)
		port, _ = strconv.Atoi(out)
		time.Sleep(150 * time.Millisecond)
	}
	for end := time.Now().Add(40 * time.Second); ; {
		if cmd(":put [:len ["+q+" and src-port="+strconv.Itoa(port)+"]]") == "0" {
			break
		}
		if time.Now().After(end) {
			t.Fatal("failed to observe actual expiry")
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Log("verified natural expiry and independent ordinary echo")
	for round := 0; round < 3; round++ {
		cmd(`/ip/firewall/mangle/enable [find comment="tikray:jump-pre"]; /ip/firewall/nat/enable [find comment="tikray:dns-full-closed-udp"]`)
		for end := time.Now().Add(10 * time.Second); ; {
			n, _ := strconv.Atoi(cmd(":put [:len [" + q + "]]"))
			if n >= 24 {
				break
			}
			if time.Now().After(end) {
				t.Fatal("insufficient live marked tuples during churn")
			}
			time.Sleep(150 * time.Millisecond)
		}
		baseline := peerCount()
		previous := waitPeer()
		if round == 2 {
			if got := uninstall(); got != "" {
				t.Fatal("packaged uninstall failed during verified expiry", got)
			}
		} else {
			out, err := r.chr.RunPrivate(ctx, `:onerror reason in={ /system/script/run tikray-emergency-off; :put "command-completed" } do={ :put "command-refused" }`)
			if err != nil || !strings.HasSuffix(strings.TrimSpace(out), "command-completed") {
				t.Fatalf("owner command failed during verified expiry, round %d", round+1)
			}
		}
		current := waitPeer()
		if current.sent <= previous.sent || current.received <= previous.received || peerCount() <= baseline {
			t.Fatal("independent marked UDP binding or round-trip progress was lost")
		}
		if round == 2 {
			if cmd(`:put [:len [/ip/firewall/mangle/find where comment="tikray:jump-pre"]]`) != "0" {
				t.Fatal("uninstall left the policy hook")
			}
			break
		}

		if cmd(`:put [/ip/firewall/mangle/get [find comment="tikray:jump-pre"] disabled]`) != "true" || cmd(`:put [/ip/firewall/nat/get [find comment="tikray:dns-full-closed-udp"] disabled]`) != "true" {
			t.Fatal("off reported success with enabled hook")
		}
	}
}

// The CLI can publish a new ID for a connection that still owns the same
// live socket. Such a handle cannot authorize another removal or certify
// that an old marked path disappeared.
func TestEmergencyRotatedHandle(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithTimeout(r.ctx, 4*time.Minute)
	defer cancel()
	run := func(command string) string {
		t.Helper()
		reply, err := r.chr.RunPrivate(ctx, command)
		if err != nil {
			t.Fatal("alias fixture command failed")
		}
		return strings.TrimSpace(reply)
	}
	run(`/ip/firewall/mangle/add chain=prerouting protocol=tcp dst-port=31835 tcp-flags=syn connection-state=new action=mark-connection new-connection-mark=tikray-closed passthrough=yes comment=churn-syn`)
	for end := time.Now().Add(15 * time.Second); run(`:put [/ip/firewall/mangle/get [find where comment=churn-syn] invalid]`) != "false"; {
		if time.Now().After(end) {
			t.Fatal("alias SYN classifier never became valid")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if r.net.Inet(ctx, "ip", "route", "add", "192.168.88.0/24", "via", "198.51.100.2").Run() != nil {
		t.Fatal("alias fixture return route")
	}
	server := r.net.Inet(ctx, "python3", "-c", `import socket
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("198.51.100.254",31835));s.listen(1);c,_=s.accept()
while True:
 b=c.recv(64)
 if not b:break
 c.sendall(b)`)
	if server.Start() != nil {
		t.Fatal("alias echo server did not start")
	}
	defer func() { server.Process.Kill(); server.Wait() }()
	countFile := filepath.Join(t.TempDir(), "echo")
	client := r.net.Client(ctx, "python3", "-c", `import socket,time,pathlib,sys
s=socket.socket();s.settimeout(2);s.bind(("192.168.88.10",31794));s.connect(("198.51.100.254",31835))
i=0;p=pathlib.Path(sys.argv[1])
while True:
 s.sendall(b"x")
 if s.recv(1)!=b"x":break
 i+=1;p.write_text(str(i));time.sleep(.1)`, countFile)
	if client.Start() != nil {
		t.Fatal("alias echo client did not start")
	}
	defer func() { client.Process.Kill(); client.Wait() }()
	count := func() int { b, _ := os.ReadFile(countFile); n, _ := strconv.Atoi(string(b)); return n }
	for end := time.Now().Add(10 * time.Second); count() < 3; {
		if time.Now().After(end) {
			t.Fatal("no positive established echo")
		}
		time.Sleep(time.Second)
	}
	body, err := routerfiles.Sources.ReadFile("emergency-off.rsc")
	if err != nil {
		t.Fatal(err)
	}
	begin := strings.Index(string(body), "            :local readFlows do=")
	end := strings.Index(string(body), "            :local frozen ")
	if begin < 0 || end <= begin {
		t.Fatal("emergency conntrack helpers not found")
	}
	helpers := string(body[begin:end])
	// This uses the exact production read and verdict functions. No other
	// conntrack reads refresh the original CLI handle while the echo runs.
	source := "{" + helpers + `
	:local query {"src"=192.168.88.10;"dst"=198.51.100.254;"protocol"="tcp";"sport"=31794;"port"=31835}
	:local rows [$readFlows "exact" 192.168.88.10 $query]
	:if ([:len $rows]!=1) do={ :error "missing-tuple" }
	:local first [:pick $rows 0]; :local old [$capture $first]
	:if (($first->"connection-mark")!="tikray-closed") do={ :error "missing-mark" }
	:if (![$checkFlow "remove" $old $readFlows $capture $ownerDNS 10.225.247.3]) do={ :error "first-handle" }
	:local packets ($first->"orig-packets"); :local replies ($first->"repl-packets")
	:delay 80s
	:set rows [$readFlows "exact" 192.168.88.10 $old]
	:if ([:len $rows]!=1) do={ :error "lost-tuple" }
	:local now [:pick $rows 0]
	:if (([:tostr ($now->".id")]=($old->"flow")) or (($now->"connection-mark")!="tikray-closed") or (($now->"orig-packets")<=$packets) or (($now->"repl-packets")<=$replies)) do={ :error "rotation-unverified" }
	:if ([$checkFlow "remove" $old $readFlows $capture $ownerDNS 10.225.247.3]) do={ :error "unsafe-remove" }
	:if (![$checkFlow "verify" $old $readFlows $capture $ownerDNS 10.225.247.3]) do={ :error "unsafe-verdict" }
	:put "rotated-mark-remains"
}`
	path := filepath.Join(t.TempDir(), "alias.rsc")
	if os.WriteFile(path, []byte(source), 0600) != nil || r.chr.Push(ctx, path, "alias.rsc") != nil {
		t.Fatal("could not stage alias witness")
	}
	before := count()
	verdict := run(`:onerror reason in={ /import file-name=alias.rsc } do={ :put "alias-incomplete" }`)
	if !strings.Contains(verdict, "rotated-mark-remains") {
		t.Fatal("the running original socket did not demonstrate safe removal refusal after native ID rotation")
	}
	if count() <= before+20 {
		t.Fatal("original TCP socket did not keep echoing")
	}
}
