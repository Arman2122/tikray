//go:build lab

package m3

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/routeros/adapters"
	routerfiles "github.com/Arman2122/tikray/routeros"
)

// Use the real scheduler and the actual extracted native rows. Neither fixture
// image contains the control service, and the control row is stopped throughout.
func TestOfflineWatchdogProtectsRunnerTransit(t *testing.T) {
	c := newStoppedRunnerCase(t)
	f, r := c.f, c.f.r
	const (
		primary = "tikray:acl-runner-transit"
		owner   = "owner:offline-transit"
		allow   = "m3-images-lan"
		net     = "172.27.248.0/29"
	)
	wait := func(label string, cond func() bool) {
		t.Helper()
		if ownerWait(r.ctx, 70*time.Second, func(context.Context) (bool, error) { return cond(), nil }) != nil {
			t.Fatal(label)
		}
	}
	f.run(`/container/stop [find where name="tikray" and running]`)
	f.run(`/interface/bridge/port/add bridge=tikray interface=tikray-ctl comment="tikray:port-ctl"; /interface/bridge/port/add bridge=tikray interface=tikray-runner comment="tikray:port-runner"`)
	f.run(`:if ([:len [/ip/address/find where interface=ether2 and address="192.168.88.1/24"]]=0) do={/ip/address/add interface=ether2 address=192.168.88.1/24 comment="owner:offline-lan"}`)
	f.run(`/ip/firewall/filter/add chain=forward action=accept comment="owner:offline-transit"; /ip/firewall/nat/add chain=srcnat out-interface=ether1 src-address=192.168.88.0/24 action=masquerade comment="owner:offline-masq"`)
	ownerID := f.run(`:put [:tostr [/ip/firewall/filter/find where comment="owner:offline-transit"]]`)
	if ownerID == "" {
		t.Fatal("owner rule absent")
	}
	ownerFlow := func() {
		t.Helper()
		if r.net.Client(r.ctx, "ping", "-c", "1", "-W", "3", "198.51.100.254").Run() != nil ||
			f.run(`:put [:tostr [/ip/firewall/filter/find where comment="owner:offline-transit" and chain=forward and action=accept and !disabled]]`) != ownerID {
			t.Fatal("unrelated owner LAN path or native rule changed")
		}
	}
	// A real installed router already owns the static ARP and FDB rows.
	// Prime them before emitting any traffic that could create a dynamic ARP.
	bindings, err := routerfiles.Sources.ReadFile("bindings.rsc")
	if err != nil {
		t.Fatal("missing private-peer provisioning")
	}
	f.pub("m3-offline-bind.rsc", []byte("{\n"+string(bindings)+"\n:local repaired [$bindPeers \"repair\" \"172.27.248.0/29\"]; :if ($repaired!=true) do={:error \"fixture: peer bindings\"}\n}"))
	f.run("/import file-name=m3-offline-bind.rsc")
	if f.run(`:put [:len [/ip/arp/find where interface=tikray and !dynamic and comment~"^tikray:arp-"]]`) != "2" {
		t.Fatal("native static binding fixture unavailable")
	}
	// Route only this synthetic sample through the inert runner. Its
	// untouched native Linux namespace really forwards during startup.
	// An independent WAN socket confirms its absence; positive rule counters
	// prove the traffic actually returned through the RouterOS filter.
	f.run(`/routing/table/add name=m3-offline-path fib; /ip/route/add routing-table=m3-offline-path dst-address=198.51.100.254/32 gateway=172.27.248.3; /ip/route/add routing-table=m3-offline-path dst-address=198.51.100.254/32 blackhole distance=2; /ip/firewall/mangle/add chain=prerouting in-interface=ether2 src-address=192.168.88.10 dst-address=198.51.100.254 protocol=udp dst-port=31795 action=mark-routing new-routing-mark=m3-offline-path passthrough=no`)
	work := t.TempDir()
	flag, trace := filepath.Join(work, "send"), filepath.Join(work, "wan")
	start := func(cmd *exec.Cmd) {
		t.Helper()
		if cmd.Start() != nil {
			t.Fatal("cannot start independent wire witness")
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	}
	start(r.net.Inet(r.ctx, "python3", "-c", `import socket,struct,sys
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800));s.bind(("wan0",0))
target=socket.inet_aton("198.51.100.254")
with open(sys.argv[1],"wb",buffering=0) as f:
 while True:
  b=s.recv(65535)
  if len(b)<43 or b[12:14]!=b"\x08\x00" or b[23]!=17 or b[30:34]!=target:continue
  i=14+(b[14]&15)*4
  if len(b)<i+8:continue
  source,port,size,_=struct.unpack_from("!4H",b,i)
  payload=b[i+8:i+size]
  if port==31795 and payload==b"offline-runner-probe":
   f.write(b"R" if b[26:30]==socket.inet_aton("192.168.88.10") and b[22]==61 else b"D" if b[22]==63 else b"E")
  if port==31796 and payload==b"offline-owner-control":f.write(b"P")
`, trace))
	start(r.net.Client(r.ctx, "python3", "-c", `import os,socket,sys,time
while True:
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
  s.bind(("192.168.88.10",0))
  s.sendto(b"offline-owner-control",("198.51.100.254",31796))
  if os.path.exists(sys.argv[1]):s.sendto(b"offline-runner-probe",("198.51.100.254",31795))
 time.sleep(.045)`, flag))
	wire := func() string { b, _ := os.ReadFile(trace); return string(b) }
	wait("owner WAN receiver has no positive physical-wire control", func() bool { return strings.Contains(wire(), "P") })
	emitting := func(on bool) {
		t.Helper()
		if on {
			if err := os.WriteFile(flag, []byte("1"), 0600); err != nil {
				t.Fatal("cannot enable runner probe")
			}
		} else {
			if err := os.Remove(flag); err != nil && !os.IsNotExist(err) {
				t.Fatal("cannot quiesce runner probe")
			}
		}
	}
	packets := func() int {
		v := f.run(`{:local sum 0; :foreach g in=[/ip/firewall/filter/find where comment="tikray:acl-runner-transit" or comment="tikray:acl-transit-deny" or comment="tikray:acl-transit-deny-backup"] do={:set sum ($sum + [/ip/firewall/filter/get $g packets])}; :put $sum}`)
		n, _ := strconv.Atoi(v)
		return n
	}
	checkWire := func(prior int) {
		t.Helper()
		wait("no positive router drop for returned managed packets", func() bool { return packets() > prior })
		emitting(false)
		if v := wire(); strings.ContainsAny(v, "RDE") {
			t.Fatalf("managed probes reached the physical WAN: original-return=%d direct-hop=%d other=%d", strings.Count(v, "R"), strings.Count(v, "D"), strings.Count(v, "E"))
		}
	}
	ownerFlow()
	f.write("install.request", map[string]any{"version": 1, "installation_id": nativeImageIdentity, "scope": map[string]any{
		"subnet": net, "lan_list": allow, "lans": []map[string]any{{"interface": "ether2", "prefix": "192.168.88.0/24", "dedicated": true}},
		"wan": map[string]string{"interface": "ether1"},
	}})
	f.pub(f.data+"/state/install.ready", []byte(strings.Repeat("a", 64)))
	body, _, err := adapters.WatchdogScripts()
	if err != nil {
		t.Fatal("production watchdog unavailable")
	}
	if _, err = r.admin.RunContext(r.ctx, "/system/script/add", "=name=tikray-watchdog", "=policy=read,write,test,ftp", "=source="+strings.ReplaceAll(body, "\n", "\r\n"), "=comment=tikray:watchdog-script"); err != nil {
		t.Fatal("cannot install production watchdog")
	}
	// Seed a legitimate existing long control backoff while the runner
	// starts at zero. Every subsequent miss/attempt comes from a real tick.
	f.run(`/system/script/add name=tikray-watchdog-state source="" policy=read comment="tikray:watchdog-state initial"`)
	reset := `{ :local stamp ([:tonsec [/system/resource/get uptime]] / 1000000000); :local saved {"version"=1;"installation_id"="` + nativeImageIdentity + `";"tikray"={"miss"=3;"delay"=15;"due"=($stamp + 890);"at"=$stamp}}; /system/script/set [find where name="tikray-watchdog-state"] comment=("tikray:watchdog-state " . [:serialize to=json options=json.no-string-conversion value=$saved]) }`
	f.run(`/system/scheduler/add name=tikray-watchdog disabled=yes interval=2s start-time=00:00:00 policy=read,write,test,ftp on-event=tikray-watchdog comment="tikray:watchdog-scheduler"`)
	disable := func() {
		t.Helper()
		f.run(`/system/scheduler/disable [find where name="tikray-watchdog"]`)
		wait("prior native job still active", func() bool {
			return f.run(`:put [:len [/system/script/job/find where script="tikray-watchdog"]]`) == "0"
		})
	}
	enable := func() {
		t.Helper()
		f.run(reset)
		f.run(`/system/scheduler/enable [find where name="tikray-watchdog"]`)
	}
	bothStopped := func() {
		t.Helper()
		wait("both native components are not stopped", func() bool {
			return f.run(`:put [:len [/container/find where (name="tikray-runner" or name="tikray") and stopped]]`) == "2"
		})
	}
	checkOrder := func() string {
		const menu = "/ip/firewall/filter"
		rows, err := r.admin.RunContext(r.ctx, menu+"/print", "?chain=forward", "=.proplist=comment")
		if err != nil {
			return ""
		}
		seen := make(map[string]bool)
		for _, row := range rows.Re {
			tag := row.Map["comment"]
			if tag == owner {
				break
			}
			seen[tag] = true
		}
		for _, tag := range []string{primary, "tikray:acl-runner-transit-dst"} {
			if !seen[tag] {
				return "false"
			}
			actual, err := r.admin.RunContext(r.ctx, menu+"/print", "?comment="+tag, "=.proplist=.id,action,chain,in-interface,src-address,out-interface-list,jump-target,disabled,invalid,dynamic")
			if err != nil {
				return ""
			}
			if len(actual.Re) != 1 {
				return "false"
			}
			row := actual.Re[0].Map
			if row["chain"] != "forward" || row["in-interface"] != "tikray" || row["src-address"] != "!172.27.248.0/29" || row["disabled"] == "true" || row["invalid"] == "true" || row["dynamic"] == "true" {
				return "false"
			}
			if tag == primary && (row["action"] != "drop" || row["out-interface-list"] != "!m3-images-lan") {
				return "false"
			}
			if tag == "tikray:acl-runner-transit-dst" && (row["action"] != "jump" || row["jump-target"] != "tikray-transit") {
				return "false"
			}
		}
		return "true"
	}
	positive := func(previousID string, priorPackets int) {
		t.Helper()
		wait("restricted watchdog did not restart the runner", func() bool { return f.run(`:put [:len [/container/find where name=tikray-runner and running]]`) == "1" })
		disable()
		var placed, control string
		wait("missing scoped guard observation", func() bool {
			placed = checkOrder()
			control = f.run(`:put [:len [/container/find where name=tikray and stopped]]`)
			return (placed == "true" || placed == "false") && (control == "1" || control == "0")
		})
		if placed != "true" || control != "1" {
			t.Fatalf("runner started before protected readback: guard_order=%t control_stopped=%t", placed == "true", control == "1")
		}
		if previousID != "" && f.run(`:put [:tostr [/ip/firewall/filter/find where comment="tikray:acl-runner-transit"]]`) != previousID {
			t.Fatal("native repair replaced the owned rule")
		}
		checkWire(priorPackets)
		ownerFlow()
	}
	bothStopped()
	emitting(true)
	enable()
	positive("", 0)
	// The owner can edit a live LAN list while the controller is offline.
	// The second filter still proves the packet's enrolled destination.
	ownerBefore := packets()
	f.run(`/interface/list/member/add list=m3-images-lan interface=ether1 comment="owner:offline-reclass"`)
	emitting(true)
	checkWire(ownerBefore)
	ownerFlow()
	f.run(`/interface/list/member/remove [find where list=m3-images-lan and interface=ether1 and comment="owner:offline-reclass"]`)
	ownedID := f.run(`:put [:tostr [/ip/firewall/filter/find where comment="tikray:acl-runner-transit"]]`)
	f.run(`/container/stop [find where name=tikray-runner and running]`)
	bothStopped()
	f.run(`/ip/firewall/filter/move [find where comment="owner:offline-transit"] destination=[find where comment="tikray:acl-runner-transit"]`)
	if checkOrder() == "true" {
		t.Fatal("failed to displace the owned rule")
	}
	prior := packets()
	emitting(true)
	enable()
	positive(ownedID, prior)
	f.run(`/container/stop [find where name=tikray-runner and running]`)
	bothStopped()
	f.run(`/ip/firewall/filter/add chain=input action=accept comment="tikray:acl-runner-transit"`)
	duplicate := f.run(`:put [:tostr [/ip/firewall/filter/find where comment="tikray:acl-runner-transit" and chain=input]]`)
	if duplicate == "" {
		t.Fatal("failed to establish ambiguous ownership")
	}
	enable()
	wait("three real failures did not reach the watchdog restart decision", func() bool {
		v := f.run(`{:local s [/system/script/get [find where name="tikray-watchdog-state"] comment]; :local p [:deserialize from=json options=json.no-string-conversion value=[:pick $s [:len "tikray:watchdog-state "] [:len $s]]]; :put ($p->"tikray-runner"->"miss")}`)
		n, _ := strconv.Atoi(v)
		return n == 3
	})
	disable()
	bothStopped()
	if f.run(`:put [:tostr [/ip/firewall/filter/find where comment="tikray:acl-runner-transit" and chain=input]]`) != duplicate || f.run(`:put [:len [/ip/firewall/filter/find where comment="tikray:acl-runner-transit"]]`) != "2" {
		t.Fatal("ambiguous transit guard was modified")
	}
	ownerFlow()
	// A pending, explicit offline rollback cannot start the old archive until
	// the very same native pre-start check succeeds, even without control.
	c.marker("runner", c.active, c.old, true)
	count := func() int {
		n, e := strconv.Atoi(f.run(`:put [/system/scheduler/get [find where name="tikray-watchdog"] run-count]`))
		if e != nil {
			return -1
		}
		return n
	}
	oldCount := count()
	if oldCount < 0 {
		t.Fatal("no positive scheduler count")
	}
	enable()
	wait("native scheduler did not process the pending rollback", func() bool { return count() >= oldCount+3 })
	disable()
	if f.run(`:put [:len [/container/find where interface=tikray-runner and running]]`) != "0" || f.run(`:put [:tostr [/ip/firewall/filter/find where comment="tikray:acl-runner-transit" and chain=input]]`) != duplicate {
		t.Fatal("ambiguous guard admitted offline image recovery")
	}
	f.run(`/ip/firewall/filter/remove [find where comment="tikray:acl-runner-transit" and chain=input]; /ip/firewall/filter/remove [find where comment="tikray:acl-runner-transit" and chain=forward]; /ip/firewall/filter/remove [find where comment="tikray:acl-runner-transit-dst" and chain=forward]`)
	emitting(true)
	enable()
	wait("previous verified runner did not start during native recovery", func() bool {
		v := f.run(`{:local row [/container/find where name=tikray-runner and running]; :if ([:len $row]=1) do={:local code [:tostr [/container/get $row image-id]]; :put (($code="` + c.old["image_id"].(string) + `") or ($code="sha256:` + c.old["image_id"].(string) + `"))}}`)
		return v == "true"
	})
	positive("", 0)
}
