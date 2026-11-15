//go:build lab

package e2e

import (
	"bytes"
	"context"
	_ "embed"
	"os"
	"path/filepath"
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
  s.sendto(b"wd-kept",(sys.argv[2],31948))
  try:
   data,peer=s.recvfrom(16)
   if peer==(sys.argv[2],31948) and data in (b"direct",b"proxy"):log.write(b"D" if data==b"direct" else b"P")
  except socket.timeout:pass
  time.sleep(.1)`, routingPeer, routingRemote, flow.replies)
	startRoutingProcess(t, client)
	startRoutingProcess(t, f.peer(ctx, "python3", "-c", keptImageDNS, routingPeer, flow.dns))
	flow.requireProxy(ctx, t)
	return flow
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
