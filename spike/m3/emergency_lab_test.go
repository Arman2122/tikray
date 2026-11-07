//go:build lab

package m3

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run the distributed script with neither tikray container present. A second
// LAN address keeps a real UDP binding while the first one's mark is cleared.
func TestM3EmergencyOffline(t *testing.T) {
	path := filepath.Join("..", "..", "routeros", "emergency-off.rsc")
	if _, err := os.Stat(path); err != nil {
		t.Fatal("missing emergency script")
	}
	r := newRig(t)
	run := func(label, commands string) string {
		t.Helper()
		s, err := r.chr.RunPrivate(r.ctx, commands)
		if err != nil {
			t.Fatalf("router refused %s", label)
		}
		return strings.TrimSpace(s)
	}
	const file = "emergency-off.rsc"
	if r.chr.Push(r.ctx, path, file) != nil {
		t.Fatal("upload failed")
	}
	verdict := func(label, commands, event string) {
		t.Helper()
		s := run(label, commands)
		if !strings.HasSuffix(s, event) {
			t.Fatalf("%s: unexpected fixed verdict", label)
		}
	}
	run("foreign script", "/system/script/add name=tikray-emergency-off comment=owner source={}")
	verdict("installer name collision", `:do {/import file-name=emergency-off.rsc; :put "accepted"} on-error={:put "refused"}`, "refused")
	run("remove fixture", "/system/script/remove [find where name=tikray-emergency-off and comment=owner]")
	for range 2 {
		verdict("install", `/import file-name=emergency-off.rsc; :put [:len [/system/script/find where name="tikray-emergency-off" and comment="tikray:emergency-off"]]`, "1")
	}
	run("bridge", `/interface/bridge/add name=tikray protocol-mode=none comment="tikray:bridge"; /ip/address/add interface=tikray address=10.225.247.1/29 comment="tikray:addr"`)
	run("LAN", `/interface/list/add name=emergency-clients; /interface/list/member/add list=emergency-clients interface=ether2`)
	run("source membership", `/ip/firewall/address-list/add list=tikray-src-full-closed address=192.168.88.10 comment="tikray:src-full-closed:192.168.88.10/32"`)
	run("classifier", `/ip/firewall/mangle/add chain=tikray-pre action=mark-connection protocol=udp dst-port=31987 connection-state=new connection-mark=no-mark new-connection-mark=tikray-closed src-address-list=tikray-src-full-closed comment="tikray:conn-full-closed"; /ip/firewall/mangle/add chain=prerouting in-interface-list=emergency-clients action=jump jump-target=tikray-pre comment="tikray:jump-pre"`)
	run("DNS", `/ip/firewall/nat/add chain=dstnat in-interface-list=emergency-clients src-address-list=tikray-src-full-closed protocol=udp dst-port=53 action=dst-nat to-addresses=10.225.247.3 to-ports=53 comment="tikray:dns-full-closed-udp"`)
	run("equivalent runner translation", `/ip/firewall/address-list/add list=tikray-src-full-closed address=192.168.88.113 comment="tikray:src-full-closed:192.168.88.113/32"; /ip/firewall/nat/add chain=dstnat action=dst-nat src-address=192.168.88.113 protocol=udp dst-port=53 to-addresses=10.225.247.3 to-ports=53 comment="owner:runner-equivalent"`)
	run("open DNS source", `/ip/firewall/address-list/add list=tikray-src-full-open address=192.168.88.111 comment="tikray:src-full-open:192.168.88.111/32"`)
	run("owner-equivalent source", `/ip/firewall/address-list/add list=tikray-src-full-open address=192.168.88.112 comment="tikray:src-full-open:192.168.88.112/32"; /ip/firewall/nat/add chain=dstnat action=redirect src-address=192.168.88.112 protocol=udp dst-port=53 to-ports=53 comment="owner:equivalent"`)
	run("open DNS router fallback", `/ip/firewall/nat/add chain=dstnat in-interface-list=emergency-clients src-address-list=tikray-src-full-open protocol=udp dst-port=53 action=redirect to-ports=53 comment="tikray:dns-router-full-open-udp"`)
	run("IPv6", `/ipv6/firewall/filter/add chain=tikray-ipv6 in-interface=ether2 action=reject comment="tikray:ipv6:ingress:00000000000000000000000000000000"; /ipv6/firewall/filter/add chain=forward in-interface-list=emergency-clients action=jump jump-target=tikray-ipv6 comment="tikray:ipv6:jump"`)
	run("foreign ACL", `/ip/firewall/filter/add chain=forward action=drop src-address=192.0.2.77 comment="tikray:install-bridge-isolation"`)
	run("watch", `/tool/netwatch/add type=simple host=10.225.247.3 interval=5s comment="tikray:runner-watch"`)
	run("foreign marker", `/system/script/add name=tikray-emergency-state comment=owner source={}`)
	verdict("marker collision", `:do {/system/script/run tikray-emergency-off; :put "accepted"} on-error={:put "refused"}`, "refused")
	verdict("zero writes on refusal", `:put [/ip/firewall/mangle/get [find where comment="tikray:jump-pre"] disabled]`, "false")
	run("remove marker fixture", `/system/script/remove [find where name="tikray-emergency-state" and comment="owner"]`)
	for _, alias := range []string{"192.168.88.110/32", "192.168.88.111/32", "192.168.88.112/32", "192.168.88.113/32"} {
		if r.net.Client(r.ctx, "ip", "addr", "add", alias, "dev", "eth0").Run() != nil {
			t.Fatal("witness alias")
		}
	}
	run("old decoy writer", `/ip/firewall/mangle/add chain=prerouting action=mark-connection connection-state=new src-address=192.168.88.110 protocol=udp dst-port=31987 new-connection-mark=tikray-closed comment="owner:old-decoy-writer"`)
	run("conntrack lifetime", "/ip/firewall/connection/tracking/set enabled=yes udp-timeout=2m")
	receiver := r.net.Inet(r.ctx, "python3", "-c", `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("198.51.100.254",31987))
while True:s.recvfrom(64)`)
	if receiver.Start() != nil {
		t.Fatal("WAN witness unavailable")
	}
	defer func() { receiver.Process.Kill(); receiver.Wait() }()
	send := func() {
		t.Helper()
		if r.net.Client(r.ctx, "python3", "-c", `import socket
for ip in ("192.168.88.10","192.168.88.110","192.168.88.111","192.168.88.112"):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((ip,31979));s.sendto(b"probe",("198.51.100.254",31987));s.sendto(b"dns",("203.0.113.30",53));s.close()`).Run() != nil {
			t.Fatal("send failed")
		}
	}
	count := func(source string) string {
		return run("conntrack witness", ":put [:len [/ip/firewall/connection/find where src-address="+source+" and src-port=31979 and dst-port=31987]]")
	}
	dns := func(source string) string {
		return run("DNS binding witness", ":put [:len [/ip/firewall/connection/find where src-address="+source+" and src-port=31979 and dst-port=53]]")
	}
	for _, tag := range []string{"tikray:conn-full-closed", "tikray:jump-pre", "owner:old-decoy-writer"} {
		for end := time.Now().Add(10 * time.Second); ; {
			if run("effective writer", ":put [/ip/firewall/mangle/get [find where comment=\""+tag+"\"] invalid]") == "false" {
				break
			}
			if time.Now().After(end) {
				t.Fatal("owner fixture never became valid")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	for _, tag := range []string{"tikray:dns-full-closed-udp", "tikray:dns-router-full-open-udp"} {
		for end := time.Now().Add(10 * time.Second); ; {
			if run("effective translation", ":put [/ip/firewall/nat/get [find where comment=\""+tag+"\"] invalid]") == "false" {
				break
			}
			if time.Now().After(end) {
				t.Fatal("fixture translation never became valid")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	for end := time.Now().Add(10 * time.Second); ; {
		send()
		if count("192.168.88.10") == "1" && count("192.168.88.110") == "1" && dns("192.168.88.10") == "1" && dns("192.168.88.110") == "1" && dns("192.168.88.111") == "1" {
			break
		}
		if time.Now().After(end) {
			t.Fatal("independent UDP witnesses missing")
		}
		time.Sleep(150 * time.Millisecond)
	}
	for _, src := range []string{"192.168.88.10", "192.168.88.110"} {
		value := run("mark read", ":put [:tostr [/ip/firewall/connection/get [find where src-address="+src+" and dst-port=31987] connection-mark]]")
		if value != "tikray-closed" {
			t.Fatal("mark missing on a positive-control tuple")
		}
	}
	run("remove decoy writer", `/ip/firewall/mangle/remove [find where comment="owner:old-decoy-writer"]`)
	run("duplicate owned tag", `/ip/firewall/mangle/add chain=output action=mark-connection new-connection-mark=tikray-closed comment="tikray:conn-full-closed"`)
	verdict("duplicate writer refuses", `:do {/system/script/run tikray-emergency-off; :put "accepted"} on-error={:put "refused"}`, "refused")
	verdict("inert on writer refusal", `:put [:len [/system/script/find where name="tikray-emergency-state"]]`, "0")
	run("remove duplicate", `/ip/firewall/mangle/remove [find where chain=output and comment="tikray:conn-full-closed"]`)
	verdict("owned DNS translation proof", `:put [:len [/ip/firewall/connection/find where src-address=192.168.88.10 and dst-port=53 and dstnat and reply-src-address=10.225.247.3 and reply-src-port=53]]`, "1")
	verdict("open DNS translation proof", `:put [:len [/ip/firewall/connection/find where src-address=192.168.88.111 and dst-port=53 and dstnat and reply-src-port=53]]`, "1")
	verdict("equivalent owner translation proof", `:put [:len [/ip/firewall/connection/find where src-address=192.168.88.112 and dst-port=53 and dstnat and reply-src-port=53]]`, "1")
	for pass := range 2 {
		if pass == 1 {
			run("new owner redirect", `/ip/firewall/nat/add chain=dstnat action=redirect src-address=192.168.88.111 protocol=udp dst-port=53 to-ports=53 comment="owner:new"`)
			for end := time.Now().Add(10 * time.Second); ; {
				if run("owner rule valid", `:put [/ip/firewall/nat/get [find where comment="owner:new"] invalid]`) == "false" {
					break
				}
				if time.Now().After(end) {
					t.Fatal("new owner rule not valid")
				}
				time.Sleep(100 * time.Millisecond)
			}
			for end := time.Now().Add(10 * time.Second); ; {
				if r.net.Client(r.ctx, "python3", "-c", `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("192.168.88.111",31979));s.sendto(b"new",("203.0.113.30",53))`).Run() != nil {
					t.Fatal("new owner DNS witness")
				}
				if run("new owner translation proof", `:put [:len [/ip/firewall/connection/find where src-address=192.168.88.111 and src-port=31979 and dst-port=53 and dstnat and reply-src-port=53]]`) == "1" {
					break
				}
				if time.Now().After(end) {
					t.Fatal("new owner redirect did not establish a binding")
				}
				time.Sleep(150 * time.Millisecond)
			}
		}
		if pass == 0 {
			emergencyDuringWatchdog(t, r)
		} else {
			verifyRecovery := interruptedEmergencyDNS(t, r)
			verdict("owner command", `/system/script/run tikray-emergency-off; :put "completed"`, "completed")
			verifyRecovery()
		}
		for _, check := range []struct{ menu, tag string }{{"/ip/firewall/mangle", "tikray:jump-pre"}, {"/ipv6/firewall/filter", "tikray:ipv6:jump"}, {"/ip/firewall/nat", "tikray:dns-full-closed-udp"}, {"/tool/netwatch", "tikray:runner-watch"}} {
			verdict("policy entry disabled", ":put ["+check.menu+"/get [find where comment=\""+check.tag+"\"] disabled]", "true")
		}
		verdict("owner ACL preserved", `:put [/ip/firewall/filter/get [find where comment="tikray:install-bridge-isolation"] disabled]`, "false")
		verdict("marker", `:put [:len [/system/script/find where name="tikray-emergency-state" and comment="tikray:emergency-state"]]`, "1")
		if (dns("192.168.88.111") == "1") != (pass == 1) || dns("192.168.88.112") != "1" {
			t.Fatalf("pass=%d closed=%t marked=%t open=%t equivalent=%t", pass, dns("192.168.88.10") == "1", count("192.168.88.10") == "1", dns("192.168.88.111") == "1", dns("192.168.88.112") == "1")
		}
		if count("192.168.88.10") != "0" || count("192.168.88.110") != "1" || dns("192.168.88.10") != "0" || dns("192.168.88.110") != "1" {
			t.Fatalf("binding presence marked target=%t marked witness=%t DNS target=%t DNS witness=%t", count("192.168.88.10") == "1", count("192.168.88.110") == "1", dns("192.168.88.10") == "1", dns("192.168.88.110") == "1")
		}
	}
}

// The running watchdog holds the real script between its first capture
// and detachment. Introduce new marked and translated tuples only after
// the marker appears and prove they exist before releasing that watchdog.
func emergencyDuringWatchdog(t *testing.T, r *rig) {
	t.Helper()
	run := func(cmd string) string {
		t.Helper()
		v, e := r.chr.RunPrivate(r.ctx, cmd)
		if e != nil {
			t.Fatal("watchdog race fixture command refused")
		}
		return strings.TrimSpace(v)
	}
	until := func(label, cmd string) {
		t.Helper()
		end := time.Now().Add(4 * time.Second)
		for run(cmd) != "1" {
			if time.Now().After(end) {
				t.Fatalf("missing %s", label)
			}
			time.Sleep(30 * time.Millisecond)
		}
	}
	async := func(cmd string) <-chan error {
		done := make(chan error, 1)
		go func() { _, e := r.chr.RunPrivate(r.ctx, cmd); done <- e }()
		return done
	}
	run(`/system/script/add name=tikray-watchdog source={:local ticks 0; :while (([:len [/system/script/find where name="m3-release-watchdog"]] = 0) and ($ticks < 160)) do={:delay 50ms; :set ticks ($ticks+1)}}`)
	watchdog := async(`/system/script/run tikray-watchdog`)
	until("running watchdog", `:put [:len [/system/script/job/find where script="tikray-watchdog"]]`)
	off := async(`/system/script/run tikray-emergency-off`)
	until("pre-detach marker", `:put [:len [/system/script/find where name="tikray-emergency-state"]]`)
	send := func() {
		t.Helper()
		if r.net.Client(r.ctx, "python3", "-c", `import socket
for ip in ("192.168.88.10","192.168.88.113"):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((ip,32019));s.sendto(b"late",("198.51.100.254",31987));s.sendto(b"late-dns",("203.0.113.30",53));s.close()`).Run() != nil {
			t.Fatal("late flows unavailable")
		}
	}
	send()
	mark := `:put [:len [/ip/firewall/connection/find where src-address=192.168.88.10 and src-port=32019 and dst-port=31987 and connection-mark=tikray-closed]]`
	dns := `:put [:len [/ip/firewall/connection/find where src-address=192.168.88.10 and src-port=32019 and dst-port=53 and dstnat and reply-src-address=10.225.247.3]]`
	owner := `:put [:len [/ip/firewall/connection/find where src-address=192.168.88.113 and src-port=32019 and dst-port=53 and dstnat and reply-src-address=10.225.247.3]]`
	until("new marked tuple", mark)
	until("new DNS tuple", dns)
	until("owner-equivalent new DNS tuple", owner)
	run(`/system/script/add name=m3-release-watchdog source={}`)
	if <-watchdog != nil || <-off != nil {
		t.Fatal("emergency command did not complete across watchdog exit")
	}
	if run(mark) != "0" || run(dns) != "0" || run(owner) != "1" {
		t.Fatal("late tracked binding survived or equivalent owner binding was removed")
	}
}

// Recreate the boundary after suspension disabled DNS but before it removed
// the old bindings. Only one of the two clients would still get the same
// translation through the owner's rules after the interruption.
func interruptedEmergencyDNS(t *testing.T, r *rig) func() {
	t.Helper()
	run := func(q string) string {
		t.Helper()
		s, err := r.chr.RunPrivate(r.ctx, q)
		if err != nil {
			t.Fatal("interrupted emergency fixture command refused")
		}
		return strings.TrimSpace(s)
	}
	const primary = `[find where comment="tikray:dns-full-closed-udp"]`
	run("/ip/firewall/nat/enable " + primary)
	binding := func(addr string) string {
		t.Helper()
		return run(":put [:len [/ip/firewall/connection/find where src-address=" + addr + " and src-port=32029 and dst-port=53 and dstnat and reply-src-address=10.225.247.3 and reply-src-port=53]]")
	}
	for end := time.Now().Add(10 * time.Second); ; {
		if run(":put [/ip/firewall/nat/get "+primary+" invalid]") == "false" {
			break
		}
		if time.Now().After(end) {
			t.Fatal("interrupted emergency fixture primary did not activate")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := r.net.Client(r.ctx, "python3", "-c", `import socket
for ip in ("192.168.88.10", "192.168.88.113"):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((ip,32029));s.sendto(b"dns",("203.0.113.30",53));s.close()`).Run(); err != nil {
		t.Fatal("interrupted emergency fixture flows unavailable")
	}
	for end := time.Now().Add(10 * time.Second); binding("192.168.88.10") != "1" || binding("192.168.88.113") != "1"; {
		if time.Now().After(end) {
			t.Fatal("interrupted emergency fixture lacked both initial runner bindings")
		}
		time.Sleep(100 * time.Millisecond)
	}
	run("/ip/firewall/nat/disable " + primary)
	if binding("192.168.88.10") != "1" || binding("192.168.88.113") != "1" {
		t.Fatal("initial runner translations did not survive detachment")
	}
	return func() {
		t.Helper()
		if binding("192.168.88.10") != "0" || binding("192.168.88.113") != "1" {
			t.Fatal("interrupted emergency rerun retained stale runner DNS or removed owner DNS")
		}
	}
}
