//go:build lab

package m3

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/routeros/adapters"
	routerfiles "github.com/Arman2122/tikray/routeros"
)

// The fixture is an ordinary IP router with a single interface and a main
// default via CHR. Both endpoints send genuine datagrams from their own IPs.
func TestNativeGuardStopsRunnerReturnTowardWAN(t *testing.T) {
	r := newRig(t)
	run := func(cmd string) string {
		t.Helper()
		v, e := r.chr.RunPrivate(r.ctx, cmd)
		if e != nil {
			t.Fatal("private transit fixture command refused")
		}
		return strings.TrimSpace(v)
	}
	until := func(label string, condition func() bool) {
		t.Helper()
		if ownerWait(r.ctx, 65*time.Second, func(context.Context) (bool, error) { return condition(), nil }) != nil {
			t.Fatal(label)
		}
	}
	start := func(cmd *exec.Cmd) {
		t.Helper()
		if cmd.Start() != nil {
			t.Fatal("cannot start transit endpoint")
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	}
	run(`/interface/list/add name=transit-lan; /interface/list/member/add list=transit-lan interface=ether2; /interface/bridge/add name=tikray protocol-mode=none comment="tikray:bridge"; /ip/address/add address=172.27.248.1/29 interface=tikray comment="tikray:addr"; /interface/veth/add name=tikray-runner address=172.27.248.3/29 gateway=172.27.248.1 comment="tikray:veth-runner"; /interface/bridge/port/add interface=tikray-runner bridge=tikray comment="tikray:port-runner"`)
	run(`/routing/table/add name=m3-transit fib; /ip/route/add routing-table=m3-transit dst-address=198.51.100.254/32 gateway=172.27.248.3; /ip/route/add routing-table=m3-transit dst-address=192.168.88.10/32 gateway=172.27.248.3`)
	run(`/ip/firewall/mangle/add chain=prerouting in-interface=ether2 src-address=192.168.88.10 dst-address=198.51.100.254 protocol=udp dst-port=31795 action=mark-routing new-routing-mark=m3-transit passthrough=no; /ip/firewall/mangle/add chain=prerouting in-interface=ether1 src-address=198.51.100.254 dst-address=192.168.88.10 protocol=udp dst-port=31797 action=mark-routing new-routing-mark=m3-transit passthrough=no`)
	run(`/ip/firewall/nat/add chain=srcnat out-interface=tikray protocol=udp dst-port=31795,31797 action=accept; /ip/firewall/nat/add chain=srcnat src-address=172.27.248.0/29 out-interface=ether1 action=masquerade; /ip/firewall/nat/add chain=srcnat src-address=192.168.88.110 out-interface=ether1 action=masquerade; /ip/firewall/filter/add chain=forward action=accept comment="owner:transit-control"`)
	ownerID := run(`:put [:tostr [/ip/firewall/filter/find where comment="owner:transit-control"]]`)
	if r.net.Client(r.ctx, "ip", "addr", "add", "192.168.88.110/32", "dev", "eth0").Run() != nil || r.net.Inet(r.ctx, "ip", "route", "replace", "192.168.88.10/32", "via", "198.51.100.2").Run() != nil {
		t.Fatal("independent endpoint routing unavailable")
	}
	dir := t.TempDir()
	wan, lan := filepath.Join(dir, "wan"), filepath.Join(dir, "lan")
	const observe = `import re,select,socket,sys
w=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800));w.bind(("wan0",0))
h=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);h.bind(("198.51.100.254",31798))
with open(sys.argv[1],"wb",buffering=0) as out:
 while True:
  for s in select.select([w,h],[],[])[0]:
   if s is h:
    b,a=s.recvfrom(64)
    if a[0]=="198.51.100.2" and re.fullmatch(rb"(init|round-trip) true [01] [01] [01]",b):out.write(b"I"+b[-5:].replace(b" ",b"")+b";");out.write(b"K" if b.startswith(b"round-trip") else b"")
    if b==b"runner-origin" and a[0]=="198.51.100.2":s.sendto(b"confirmed",a);out.write(b"H")
    continue
   f,sa=w.recvfrom(65535)
   if sa[2]==socket.PACKET_OUTGOING or len(f)<43 or f[12:14]!=b"\x08\x00" or f[23]!=17 or f[30:34]!=socket.inet_aton("198.51.100.254"):continue
   k=14+4*(f[14]&15)
   if int.from_bytes(f[k+2:k+4],"big")!=31795:continue
   size=int.from_bytes(f[k+4:k+6],"big"); b=f[k+8:k+size];src=socket.inet_ntoa(f[26:30])
   if b in (b"B",b"A",b"C"):out.write(b if src=="192.168.88.10" and f[22]==61 else b"X")
   if b in (b"b",b"a",b"c") and src=="198.51.100.2" and f[22]==63:out.write(b)`
	start(r.net.Inet(r.ctx, "python3", "-c", observe, wan))
	start(r.net.Client(r.ctx, "python3", "-c", `import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("192.168.88.10",31797))
with open(sys.argv[1],"wb",buffering=0) as out:
 while True:
  p,peer=s.recvfrom(32)
  if peer[0]=="198.51.100.254" and p in (b"B",b"A",b"C",b"L"):out.write(p)`, lan))
	program, e := os.ReadFile("testdata/transit/main.go")
	if e != nil {
		t.Fatal("missing benign native router fixture")
	}
	raw, _ := nativeProbeProgram(t, "private-transit", 0, program)
	p := filepath.Join(dir, "relay.tar")
	if os.WriteFile(p, raw, 0600) != nil || r.chr.Push(r.ctx, p, "disk1/transit-fixture.tar") != nil {
		t.Fatal("cannot stage benign router")
	}
	run(`/container/add name=transit-fixture interface=tikray-runner file=disk1/transit-fixture.tar root-dir=disk1/transit-root cmd=/pause dns=172.27.248.1 restart-policy=on-failure start-on-boot=no logging=no memory-high=134217728 memory-max=201326592`)
	until("native container never extracted", func() bool { return run(`:put [:len [/container/find where name=transit-fixture and stopped]]`) == "1" })
	run(`/container/start [find where name=transit-fixture]`)
	read := func(path string) string { v, _ := os.ReadFile(path); return string(v) }
	rx := regexp.MustCompile(`I([01])([01])([01]);`)
	until("no untouched PID1 observation", func() bool { return rx.MatchString(read(wan)) })
	bits := rx.FindStringSubmatch(read(wan))
	t.Log("PID1 inherited forwarding", bits[1], bits[2], "echo-ignore", bits[3])
	const send = `import socket,sys,time
for i in range(14):
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
  s.bind((sys.argv[1],int(sys.argv[4])+i));s.setsockopt(socket.IPPROTO_IP,socket.IP_TTL,64);s.sendto(sys.argv[5].encode(),(sys.argv[2],int(sys.argv[3])))
 time.sleep(.04)`
	emit := func(phase string, from int) {
		t.Helper()
		if r.net.Client(r.ctx, "python3", "-c", send, "192.168.88.10", "198.51.100.254", "31795", strconv.Itoa(from), phase).Run() != nil || r.net.Client(r.ctx, "python3", "-c", send, "192.168.88.110", "198.51.100.254", "31795", strconv.Itoa(from+30), strings.ToLower(phase)).Run() != nil || r.net.Inet(r.ctx, "python3", "-c", send, "198.51.100.254", "192.168.88.10", "31797", strconv.Itoa(from+60), phase).Run() != nil {
			t.Fatal("cannot send independent native traffic")
		}
	}
	emit("B", 33800)
	until("no verified ordinary runner return on wire", func() bool { return strings.Contains(read(wan), "B") })
	until("initial unrelated WAN/normal LAN reply missing", func() bool {
		return strings.Contains(read(wan), "b") && strings.Contains(read(lan), "B") && strings.Contains(read(wan), "K")
	})
	t.Logf("ordinary runner transit reached real WAN from original LAN source at TTL 61 (%d packets)", strings.Count(read(wan), "B"))
	body, e := routerfiles.Sources.ReadFile("transit-guard.rsc")
	if e != nil {
		t.Fatal("native installer lacks the verified bridge-return guard")
	}
	enrolled := []string{"192.168.88.0/24"}
	guard := func(op string) string {
		t.Helper()
		var scope strings.Builder
		scope.WriteString(":local enrolled [:toarray \"\"];\n")
		for _, cidr := range enrolled {
			fmt.Fprintf(&scope, ":set ($enrolled->[:len $enrolled]) {\"prefix\"=\"%s\"}\n", cidr)
		}
		src := "{\n" + string(body) + "\n" + scope.String() + ":local permit do={:return true}; :local v [$transitGuard \"" + op + "\" \"172.27.248.0/29\" \"transit-lan\" $permit 1 $enrolled]; :put \"verified\"\n}"

		if os.WriteFile(p, []byte(src), 0600) != nil || r.chr.Push(r.ctx, p, "transit-check.rsc") != nil {
			t.Fatal("cannot stage native guard check")
		}
		out := run(`:onerror why in={/import file-name=transit-check.rsc} do={:put ("fixed-error=" . [:convert [:tostr $why] to=base64])}`)
		if _, enc, ok := strings.Cut(out, "fixed-error="); ok {
			enc = strings.TrimSpace(enc)
			raw, _ := base64.StdEncoding.DecodeString(strings.Fields(enc + " .")[0])
			for _, m := range regexp.MustCompile(`:error "([^"]+)"`).FindAllStringSubmatch(string(body), -1) {
				if strings.Contains(string(raw), m[1]) {
					return m[1]
				}
			}
			for _, x := range []string{"syntax", "expected", "no such", "invalid", "not enough", "failure", "bad command", "cannot", "input does not", "missing", "script error", "already", "could not", "permission", "argument", "not allowed", "impossible", "too many"} {
				if strings.Contains(strings.ToLower(string(raw)), x) {
					subject := ""
					for _, prop := range []string{"of value-name", "of list", "of interface", "of number", "of address", "of comment", "of timeout", "of proplist", "of id"} {
						if strings.Contains(string(raw), prop) {
							subject = prop
						}
					}
					t.Log("guard category", x, subject, regexp.MustCompile(`line [0-9]+ column [0-9]+`).FindString(string(raw)))
					return "refused"
				}
			}
			words := strings.ToLower(string(raw))
			var safe []string
			for _, word := range strings.Fields("address filter referenced list cannot compare shift operation values numeric range property item string array invalid unable to convert must be number command input in error script kernel dynamic native add remove type set expected matching name match topic syntax") {
				if strings.Contains(words, word) {
					safe = append(safe, word)
				}
			}
			t.Log("guard unclassified", len(raw), strings.Join(safe, "/"), regexp.MustCompile(`line [0-9]+ column [0-9]+`).FindString(words))
			return "refused"
		}
		return out
	}
	if !strings.Contains(guard("place"), "verified") {
		t.Fatal("guard could not be installed")
	}
	id := run(`:put [:tostr [/ip/firewall/filter/find where comment="tikray:acl-runner-transit"]]`)
	if _, e := net.ParseMAC(run(`:put [/interface/veth/get [find where name=tikray-runner] container-mac-address]`)); e != nil || !regexp.MustCompile(`^\*[0-9a-fA-F]+$`).MatchString(id) {
		t.Fatal("missing tagged guard or verified runner MAC")
	}
	heart := strings.Count(read(wan), "H")
	emit("A", 34100)
	until("owner traffic, normal runner WAN or WAN-origin LAN reply lost", func() bool {
		return strings.Contains(read(wan), "a") && strings.Contains(read(lan), "A") && strings.Count(read(wan), "H") > heart
	})
	if strings.ContainsAny(read(wan), "AX") {
		t.Fatal("WAN accepted prohibited or unclassified runner-return packet")
	}
	n, e := strconv.Atoi(run(`:put [/ip/firewall/filter/get [find where comment="tikray:acl-runner-transit"] packets]`))
	if e != nil || n < 1 {
		t.Fatal("protected traffic did not hit exact owned drop")
	}
	// Later owner list edits must not turn the WAN into an enrolled LAN prefix.
	run(`/interface/list/member/add list=transit-lan interface=ether1 comment="owner:wan-added"`)
	emit("C", 34500)
	until("WAN-list drift broke owned or unrelated positive controls", func() bool { return strings.Contains(read(wan), "c") && strings.Contains(read(lan), "C") })
	if strings.Contains(read(wan), "C") {
		t.Fatal("private outside-source transit escaped after WAN joined the LAN interface list")
	}
	run(`/interface/list/member/remove [find where comment="owner:wan-added"]`)
	member := run(`:put [:tostr [/ip/firewall/filter/find where chain="tikray-transit" and comment="tikray:acl-transit-lan:192.168.88.0/24"]]`)
	if member == "" {
		t.Fatal("durable enrolled LAN return absent")
	}
	for _, rule := range []string{
		`/ip/firewall/filter/add chain=transit-owner action=jump jump-target=tikray-transit comment="owner:transit-ref"`,
		`/ip/firewall/filter/add chain=tikray-transit action=accept comment="owner:transit-ref"`,
	} {
		run(rule)
		foreign := run(`:put [:tostr [/ip/firewall/filter/find where comment="owner:transit-ref"]]`)
		if !strings.Contains(guard("repair"), "owner uses private runner transit chain") || run(`:put [:tostr [/ip/firewall/filter/find where comment="owner:transit-ref"]]`) != foreign {
			t.Fatal("native repair accepted or removed a foreign chain member or caller")
		}
		run(`/ip/firewall/filter/remove [find where comment="owner:transit-ref"]`)
	}
	// Losing either terminal keeps the other in force. An unrelated global
	// address list with the obsolete experimental name is not an input.
	backupBefore := run(`:put [/ip/firewall/filter/get [find where comment="tikray:acl-transit-deny-backup"] packets]`)
	run(`/ip/firewall/filter/remove [find where comment="tikray:acl-transit-deny"]; /ip/firewall/address-list/add list=tikray-transit-lans address=0.0.0.0/0 comment="owner:independent-list"; /interface/list/member/add list=transit-lan interface=ether1 comment="owner:wan-added"`)
	emit("C", 34800)
	until("surviving terminal never positively caught the new fixtures", func() bool {
		return run(`:put [/ip/firewall/filter/get [find where comment="tikray:acl-transit-deny-backup"] packets]`) != backupBefore
	})
	if strings.Contains(read(wan), "C") {
		t.Fatal("outside-source WAN packet escaped after one terminal was removed")
	}
	if got := guard("repair"); !strings.Contains(got, "verified") {
		t.Fatal("surviving terminal did not permit owned repair", got)
	}
	if run(`:put [:len [/ip/firewall/filter/find where comment="tikray:acl-transit-deny" and !disabled]]`) != "1" || run(`:put [:len [/ip/firewall/address-list/find where comment="owner:independent-list"]]`) != "1" {
		t.Fatal("terminal was not restored or independent owner list changed")
	}

	run(`/interface/list/member/remove [find where comment="owner:wan-added"]`)
	run(`/ip/firewall/filter/disable [find where comment="tikray:acl-runner-transit"]`)
	run(`/ip/firewall/filter/move [find where comment="owner:transit-control"] destination=[find where comment="tikray:acl-runner-transit"]`)
	if !strings.Contains(guard("repair"), "verified") || run(`:put [:len [/ip/firewall/filter/find where comment="tikray:acl-runner-transit" and !disabled]]`) != "1" || run(`:put [:tostr [:pick [/ip/firewall/filter/find where chain=forward and !dynamic] 0]]`) != id || run(`:put [:tostr [/ip/firewall/filter/find where comment="owner:transit-control"]]`) != ownerID {
		t.Fatal("reimport did not repair order by preserving native identities")
	}
	// An already disabled terminal above still-working LAN returns may need
	// several bounded ticks to restore. Do not activate it mid-repair.
	for i := 50; i < 73; i++ {
		enrolled = append(enrolled, fmt.Sprintf("192.168.%d.0/24", i))
	}
	if !strings.Contains(guard("place"), "verified") {
		t.Fatal("cannot admit all fixture returns")
	}
	run(`/ip/firewall/filter/disable [find where comment="tikray:acl-transit-deny"]; /ip/firewall/filter/move [find where comment="tikray:acl-transit-deny"] destination=[:pick [find where chain=tikray-transit] 0]`)
	if !strings.Contains(guard("repair"), "runner return LAN repair pending") || run(`:put [/ip/firewall/filter/get [find where comment="tikray:acl-transit-deny"] disabled]`) != "true" {
		t.Fatal("disabled terminal cut off an existing LAN return during a bounded repair")
	}
	emit("L", 35100)
	until("enrolled LAN reply lost in partial terminal repair", func() bool { return strings.Contains(read(lan), "L") })
	complete := false
	for range 8 {
		result := guard("repair")
		if strings.Contains(result, "verified") {
			complete = true
			break
		}
		if !strings.Contains(result, "runner return LAN repair pending") {
			t.Fatal("unexpected partial return repair", result)
		}
	}
	if !complete || run(`:put [/ip/firewall/filter/get [find where comment="tikray:acl-transit-deny"] disabled]`) != "false" {
		t.Fatal("both terminal drops did not recover after LAN returns")
	}

	run(`/ip/firewall/filter/set [find where comment="tikray:acl-runner-transit"] protocol=tcp`)
	if !strings.Contains(guard("check"), "extra runner transit condition") || run(fmt.Sprintf(`:put [:tostr [/ip/firewall/filter/get [:toid "%s"] protocol]]`, id)) == "" {
		t.Fatal("changed guard was silently adopted")
	}
	t.Logf("protected native runner-return packets dropped=%d, closed WAN=0, owner WAN and replies to LAN present", n)
}

// The restricted scheduler may heal a missing guard from the private handoff
// only if it was actually published for the current installation.
func TestNativeRunnerGuardRejectsStaleInstallScope(t *testing.T) {
	f := newNativeImageCase(t)
	setupRunnerGuardScope(t, f.run, "172.27.248.1")
	watch, _, err := adapters.WatchdogScripts()
	start, end := strings.Index(watch, ":local imageTraffic do={"), strings.Index(watch, ":if ($7=\"transit\")")
	if err != nil || start < 0 || end <= start {
		t.Fatal("native guard binding unavailable")
	}
	src := "{\n" + watch[start:end] + `
	:local permit do={:return true}
	:onerror why in={ :local id [$imageTraffic "transit" "disk1/tikray-phases/data" "` + nativeImageIdentity + `" $permit true]; :if ([:typeof $id]="id") do={:put "protected"} } do={
	    :if ([:typeof [:find [:tostr $why] "runner return scope identity differs"]]="num") do={:put "scope-refused"}
	}
}`
	f.pub("m3-runner-scope.rsc", []byte(src))
	for _, tc := range []struct {
		version  int
		id       string
		expected string
	}{{1, strings.Repeat("f", 32), "scope-refused"}, {2, nativeImageIdentity, "scope-refused"}, {1, nativeImageIdentity, "protected"}} {
		f.write("install.request", map[string]any{"version": tc.version, "installation_id": tc.id, "scope": map[string]any{"subnet": "172.27.248.0/29", "lan_list": "m3-images-lan", "lans": []map[string]string{{"prefix": "192.168.88.0/24"}}}})
		if got := f.run(`/import file-name=m3-runner-scope.rsc`); !strings.Contains(got, tc.expected) {
			t.Fatal("native scope not bound to its independently installed identity", tc.expected)
		}
		if tc.expected == "scope-refused" && f.run(`:put [:len [/ip/firewall/filter/find where comment~"^tikray:acl-(runner-transit|transit-)"]]`) != "0" {
			t.Fatal("stale scope changed router filters")
		}
	}
}
