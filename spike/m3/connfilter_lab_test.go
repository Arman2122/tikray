//go:build lab

package m3

import (
	"strings"
	"testing"
	"time"
)

func TestM3SourceFilter(t *testing.T) {
	r := newRig(t)
	if _, e := r.chr.RunPrivate(r.ctx, "/ip/firewall/connection/tracking/set enabled=yes"); e != nil {
		t.Fatal("tracking setup")
	}
	if r.net.Client(r.ctx, "ip", "addr", "add", "192.168.88.110/32", "dev", "eth0").Run() != nil {
		t.Fatal("control alias")
	}
	srv := r.net.Inet(r.ctx, "python3", "-c", `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("198.51.100.254",31987))
while True:s.recvfrom(32)`)
	if srv.Start() != nil {
		t.Fatal("receiver")
	}
	defer func() { srv.Process.Kill(); srv.Wait() }()
	send := func() {
		if r.net.Client(r.ctx, "python3", "-c", `import socket
for ip in ("192.168.88.10","192.168.88.110"):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((ip,31979));s.sendto(b"probe",("198.51.100.254",31987));s.close()`).Run() != nil {
			t.Fatal("send")
		}
	}
	query := func(q ...string) (a, b, unexpected int) {
		args := append([]string{"/ip/firewall/connection/print", "=.proplist=.id,src-address,src-port,dst-port"}, q...)
		rw, e := r.api.RunArgsContext(r.ctx, args)
		if e != nil {
			return -1, -1, -1
		}
		for _, v := range rw.Re {
			switch strings.Split(v.Map["src-address"], ":")[0] {
			case "192.168.88.10":
				a++
			case "192.168.88.110":
				b++
			default:
				unexpected++
			}
		}
		return
	}
	for end := time.Now().Add(12 * time.Second); ; {
		send()
		a, b, _ := query("?dst-port=31987")
		if a > 0 && b > 0 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("independent two-flow control missing")
		}
		time.Sleep(200 * time.Millisecond)
	}
	for _, q := range [][]string{{"?src-address=192.168.88.10"}, {"?src-address", "?<src-address=192.168.88.8", "?#!", "?>src-address=192.168.88.15", "?#!"}} {
		a, b, extra := query(q...)
		if a != 1 || b != 0 || extra != 0 {
			t.Errorf("source filter: positive=%d decoy=%d unrelated=%d", a, b, extra)
		}
	}
}
