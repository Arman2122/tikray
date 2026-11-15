//go:build lab

package e2e

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The two gateways share a lab subnet, but have different Ethernet MACs.
// Receiving the marked open client's UDP on the second MAC distinguishes
// following the owner's new main default from using a stale tikray table.
func (f *routingLab) imageAlternateGateway(ctx context.Context, t *testing.T) {
	t.Helper()
	const link = "wd-gateway6b"
	const address = "198.51.100.253"
	const mac = "02:00:00:6b:00:fd"
	run := func(args ...string) {
		t.Helper()
		if f.Net.Inet(ctx, "ip", args...).Run() != nil {
			t.Fatal("could not configure independent WAN next hop")
		}
	}
	run("link", "add", "link", "wan0", "name", link, "address", mac, "type", "macvlan", "mode", "bridge")
	defer run("link", "del", link)
	run("addr", "add", address+"/32", "dev", link)
	run("link", "set", link, "up")
	f.mustRun(ctx, t, `/ip/arp/add interface=ether1 address=`+address+` mac-address=`+mac+` comment="lab:image-alt-wan"`)
	defer f.mustRun(ctx, t, `/ip/arp/remove [find where interface=ether1 and address=`+address+` and comment="lab:image-alt-wan"]`)

	capture := filepath.Join(t.TempDir(), "gateway-count")
	cmd := f.Net.Inet(ctx, "python3", "-c", `import socket,sys,struct
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800));s.bind((sys.argv[1],0))
addr=socket.inet_aton(sys.argv[3]);mac=bytes.fromhex(sys.argv[4].replace(":",""))
with open(sys.argv[2],"wb",buffering=0) as log:
 while True:
  b=s.recv(65535)
  if len(b)<43 or b[:6]!=mac or b[12:14]!=b"\x08\x00" or b[23]!=17 or b[30:34]!=addr:continue
  start=14+4*(b[14]&15)
  if len(b)<start+9:continue
  _,port,size,_=struct.unpack_from("!4H",b,start)
  p=b[start+8:start+size]
  if port==31947 and p in (b"C",b"D"):log.write(p)`, link, capture, routingRemote, mac)
	startRoutingProcess(t, cmd)
	if _, ok := poll(ctx, 3*time.Second, 100*time.Millisecond, func() bool { _, e := os.Stat(capture); return e == nil }); !ok {
		t.Fatal("second WAN wire capture unavailable")
	}
	id := f.taggedID(ctx, t, "/ip/route", "lab:default")
	if id == "" {
		t.Fatal("owner's primary route missing")
	}
	read := func(gw string) bool {
		rows := f.readROS(ctx, t, "/ip/route", ".id", "?.id="+id, "?dst-address=0.0.0.0/0", "?routing-table=main", "?active=true", "?gateway="+gw)
		return len(rows) == 1 && rows[0][".id"] == id
	}
	const first = "198.51.100.254"
	if !read(first) {
		t.Fatal("main default before WAN change could not be identified")
	}
	f.routingWrite(ctx, t, "/ip/route/set", "=.id="+id, "=gateway="+address)
	defer func() {
		f.routingWrite(ctx, t, "/ip/route/set", "=.id="+id, "=gateway="+first)
		if _, ok := poll(ctx, 5*time.Second, 200*time.Millisecond, func() bool { return read(first) }); !ok {
			t.Fatal("owner's original WAN gateway did not return")
		}
	}()
	if _, ok := poll(ctx, 5*time.Second, 200*time.Millisecond, func() bool { return read(address) }); !ok {
		t.Fatal("owner's alternate WAN gateway never became active")
	}
	_, reached := poll(ctx, 10*time.Second, 200*time.Millisecond, func() bool {
		b, _ := os.ReadFile(capture)
		return bytes.Count(b, []byte{'D'}) >= 2
	})
	b, e := os.ReadFile(capture)
	if e != nil || !reached || bytes.Contains(b, []byte{'C'}) {
		t.Fatal("changed main gateway lacked open traffic or received a closed packet while runner was unverified")
	}
}
