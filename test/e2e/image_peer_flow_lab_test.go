//go:build lab

package e2e

import (
	"bytes"
	"context"
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Fresh tuples do not exercise the cached NAT decision of an already
// proxied connection. Keep a single UDP socket bound during the transition.
type imagePeerFlow struct{ wire, replies, dns string }

//go:embed testdata/kept_dns.py
var keptImageDNS string

func (f *routingLab) keepImagePeerFlow(ctx context.Context, t *testing.T) *imagePeerFlow {
	t.Helper()
	dir := t.TempDir()
	flow := &imagePeerFlow{filepath.Join(dir, "wire"), filepath.Join(dir, "replies"), filepath.Join(dir, "dns")}
	server := f.Net.Inet(ctx, "python3", "-c", `import select,socket,struct,sys
target=socket.inet_aton(sys.argv[1])
wire=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800));wire.bind(("wan0",0))
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind((sys.argv[1],31948))
with open(sys.argv[2],"wb",buffering=0) as log:
 while True:
  ready,_,_=select.select([udp,wire],[],[])
  for sock in ready:
   if sock is udp:
    data,peer=udp.recvfrom(32)
    if data!=b"wd-kept":continue
    if peer[0]==sys.argv[3]:udp.sendto(b"direct",peer)
    elif peer[0] in sys.argv[4:6]:udp.sendto(b"proxy",peer)
    continue
   b=wire.recv(65535)
   if len(b)<43 or b[12:14]!=b"\x08\x00" or b[23]!=17 or b[30:34]!=target:continue
   start=14+4*(b[14]&15)
   if len(b)<start+15:continue
   _,port,size,_=struct.unpack_from("!4H",b,start)
   if port==31948 and b[start+8:start+size]==b"wd-kept":
    log.write(b"N" if socket.inet_ntoa(b[26:30])==sys.argv[3] else b"?")`, routingRemote, flow.wire, egressDirect, serverEgress["a"], serverEgress["b"])
	startRoutingProcess(t, server)
	client := f.peer(ctx, "python3", "-c", `import socket,sys,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],32242));s.settimeout(.35)
with open(sys.argv[3],"wb",buffering=0) as log:
 while True:
  try:
   s.sendto(b"wd-kept",(sys.argv[2],31948))
   data,peer=s.recvfrom(16)
   if peer==(sys.argv[2],31948) and data in (b"direct",b"proxy"):log.write(b"D" if data==b"direct" else b"P")
  except OSError:pass
  time.sleep(.1)`, routingPeer, routingRemote, flow.replies)
	startRoutingProcess(t, client)
	startRoutingProcess(t, f.peer(ctx, "python3", "-c", keptImageDNS, routingPeer, flow.dns))
	flow.requireProxy(ctx, t)
	return flow
}

type nativeFlowCounters struct {
	id     string
	values [4]uint64
}

func flowCounters(id string, fields []string) (nativeFlowCounters, bool) {
	r := nativeFlowCounters{id: id}
	if r.id == "" || len(fields) != len(r.values) {
		return r, false
	}
	for i, field := range fields {
		v, e := strconv.ParseUint(field, 10, 64)
		if e != nil {
			return r, false
		}
		r.values[i] = v
	}
	return r, true
}

func (r nativeFlowCounters) continued(prev nativeFlowCounters) bool {
	if r.id != prev.id {
		return false
	}
	for i, v := range r.values {
		if v < prev.values[i] {
			return false
		}
	}
	return true
}

func TestForeignFlowWitnessRejectsReusedID(t *testing.T) {
	before := nativeFlowCounters{"*1", [4]uint64{900, 900, 27790, 27790}}
	if !before.continued(before) {
		t.Fatal("steady unrelated connection refused")
	}
	for i := range before.values {
		removed := before
		removed.values[i] = 4
		if removed.continued(before) {
			t.Fatal("a reset counter on the same native ID passed")
		}
	}
	changed := before
	changed.id = "*2"
	if changed.continued(before) {
		t.Fatal("a different native ID passed without an identity proof")
	}
}

var ownerFlowFrame = regexp.MustCompile(`m3-owner-row[|]([*][0-9A-Fa-f]+)[|]([0-9]+)[|]([0-9]+)[|]([0-9]+)[|]([0-9]+)[|]end`)

// The API and owner SSH sessions read the same unmarked tuple independently.
// RouterOS can reuse its displayed ID even when a connection is erased.
func (f *routingLab) monitorForeignFlow(ctx context.Context, t *testing.T, address string, echoes func() int) func() {
	t.Helper()
	// A timed-out per-flow read may cancel its native observer. Keep the
	// independently monitored owner's management session out of that path.
	observer := f.ownerSession(ctx, t)
	t.Cleanup(func() { observer.Close() })
	type pair [2]nativeFlowCounters
	cmd := []string{"/ip/firewall/connection/print", "=.proplist=.id,orig-packets,repl-packets,orig-bytes,repl-bytes,connection-mark,reply-src-address,reply-src-port", "?protocol=udp", "?src-address=" + address, "?src-port=31932", "?dst-address=198.51.100.254", "?dst-port=31931"}
	sshQuery := `{:local rows [/ip/firewall/connection/find where src-address=[:toip "` + rosEscape(address) + `"] and protocol=udp and src-port=31932 and dst-address=198.51.100.254 and dst-port=31931 and connection-mark!="tikray-open" and connection-mark!="tikray-closed" and connection-mark!="tikray-open-udp" and connection-mark!="tikray-open-runner" and connection-mark!="tikray-open-wan"];:if ([:len $rows]=1) do={:local id [:pick $rows 0];:put ("m3-owner-row|" . [:tostr $id] . "|" . [/ip/firewall/connection/get $id orig-packets] . "|" . [/ip/firewall/connection/get $id repl-packets] . "|" . [/ip/firewall/connection/get $id orig-bytes] . "|" . [/ip/firewall/connection/get $id repl-bytes] . "|end")}}`
	read := func(c context.Context) (pair, bool) {
		var current pair
		bound, end := context.WithTimeout(c, 7*time.Second)
		defer end()
		_, got := poll(bound, 7*time.Second, 200*time.Millisecond, func() bool {
			rows, err := observer.CommandAt(bound, observer.Generation(), cmd)
			if err != nil || len(rows) != 1 {
				return false
			}
			r := rows[0]
			mark := r["connection-mark"]
			if (mark != "" && mark != "no-mark") || r["reply-src-address"] != "198.51.100.254" || r["reply-src-port"] != "31931" {
				return false
			}
			var apiOK bool
			current[0], apiOK = flowCounters(r[".id"], []string{r["orig-packets"], r["repl-packets"], r["orig-bytes"], r["repl-bytes"]})
			if !apiOK {
				return false
			}
			wire, err := f.CHR.RunPrivate(bound, sshQuery)
			parts := ownerFlowFrame.FindStringSubmatch(wire)
			if err != nil || len(parts) != 6 {
				return false
			}
			var sshOK bool
			current[1], sshOK = flowCounters(parts[1], parts[2:])
			return sshOK
		})
		return current, got
	}
	first, ok := read(ctx)
	if !ok {
		t.Fatal("two independent owner sessions could not verify the unrelated flow")
	}
	monitor, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	var failed atomic.Bool
	go func() {
		defer close(done)
		prev := first
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-monitor.Done():
				return
			case <-tick.C:
				now, ok := read(monitor)
				if !ok || !now[0].continued(prev[0]) || !now[1].continued(prev[1]) {
					if monitor.Err() == nil {
						failed.Store(true)
					}
					return
				}
				prev = now
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
	return func() {
		t.Helper()
		start := echoes()
		if _, ok := poll(ctx, 10*time.Second, 200*time.Millisecond, func() bool { return echoes() >= start+2 }); !ok {
			t.Fatal("the unrelated stream did not receive two fresh UDP replies")
		}
		now, ok := read(ctx)
		if failed.Load() || !ok || !now[0].continued(first[0]) || !now[1].continued(first[1]) || now[0].values[1] <= first[0].values[1] || now[1].values[1] <= first[1].values[1] {
			t.Fatalf("unrelated connection continuity failed: monitor=%t read=%t api_id=%t ssh_id=%t api_counts=%v->%v ssh_counts=%v->%v", !failed.Load(), ok, now[0].id == first[0].id, now[1].id == first[1].id, first[0].values, now[0].values, first[1].values, now[1].values)
		}
	}
}

func (s *imagePeerFlow) count(path string, marker byte) int {
	b, _ := os.ReadFile(path)
	return bytes.Count(b, []byte{marker})
}

func (s *imagePeerFlow) requireDirect(ctx context.Context, t *testing.T) {
	t.Helper()
	start := s.count(s.replies, 'D')
	dns := s.count(s.dns, 'D')
	_, ok := poll(ctx, 18*time.Second, 200*time.Millisecond, func() bool {
		return s.count(s.replies, 'D') >= start+2 && s.count(s.wire, 'N') >= 2 && s.count(s.dns, 'D') >= dns+2
	})
	if !ok || s.count(s.wire, '?') > 0 {
		t.Fatalf("retained open sockets failed fallback: data_replies=%d dns_replies=%d masqueraded=%d unexpected_source=%d", s.count(s.replies, 'D')-start, s.count(s.dns, 'D')-dns, s.count(s.wire, 'N'), s.count(s.wire, '?'))
	}
}

func (s *imagePeerFlow) requireProxy(ctx context.Context, t *testing.T) {
	t.Helper()
	udp, dns := s.count(s.replies, 'P'), s.count(s.dns, 'P')
	_, ok := poll(ctx, 25*time.Second, 200*time.Millisecond, func() bool {
		return s.count(s.replies, 'P') >= udp+2 && s.count(s.dns, 'P') >= dns+2
	})
	if !ok {
		t.Fatal("retained open data or DNS socket did not receive fresh proxied answers")
	}
}

// A late reply or delayed ICMP error must not make the original socket
// fall one query behind for the remainder of a routing transition.
func TestKeptDNSProbeSurvivesLateReply(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the CHR probe fixture")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "probe.py")
	output := filepath.Join(dir, "verdict")
	if os.WriteFile(source, []byte(keptImageDNS), 0600) != nil {
		t.Fatal("cannot stage probe")
	}
	const driver = `import errno, runpy, socket, struct, sys, time
path, output = sys.argv[1:]
class Socket:
 def __init__(self): self.sent=0; self.received=0; self.query=None
 def bind(self, addr): pass
 def settimeout(self, t): pass
 def sendto(self, query, dest):
  self.sent += 1
  if self.sent == 1: raise OSError(errno.ECONNREFUSED, "fixture error")
  self.query = query
 def recvfrom(self, bound):
  ident=struct.unpack_from("!H",self.query)[0]
  self.received += 1
  if self.received == 1: ident ^= 1
  header=struct.pack("!6H",ident,0x8180,1,1,0,0)
  answer=b"\xc0\x0c"+struct.pack("!HHIH",1,1,0,4)+bytes([198,18,54,1])
  return header+self.query[12:]+answer,("203.0.113.53",53)
client=Socket()
socket.socket=lambda *a,**kw: client
def delay(_):
 if client.sent >= 2: raise SystemExit(0)
time.sleep=delay
sys.argv=[path,"192.168.88.110",output]
runpy.run_path(path,run_name="__main__")
`
	cmd := exec.CommandContext(t.Context(), python, "-c", driver, source, output)
	if cmd.Run() != nil {
		t.Fatal("kept DNS probe exited on a transient send error")
	}
	b, e := os.ReadFile(output)
	if e != nil || string(b) != "D" {
		t.Fatal("same DNS socket did not wait for the current reply after an earlier one arrived")
	}
}
