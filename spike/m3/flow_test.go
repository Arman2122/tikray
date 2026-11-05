//go:build lab

package m3

import (
	"context"
	"errors"
	"fmt"

	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	ros "github.com/go-routeros/routeros/v3"
)

// Use two persistent UDP sockets to an isolated echo server across CHR. A second successful
// echo on the witness socket proves the surviving flow did useful work.
func probeConntrack(t *testing.T, r *rig) {
	removal, observedListen := false, false
	defer func() {
		if !removal {
			r.mark(t, "B.conntrack.remove", "INCONCLUSIVE", "fixture did not reach verified removal")
		}
		if !observedListen {
			r.mark(t, "B.conntrack.listen", "INCONCLUSIVE", "fixture did not reach listener comparison")
		}
	}()

	const menu = "/ip/firewall/connection"
	const peer = "203.0.113.30"
	const peerPort = 31453
	if _, err := r.chr.RunPrivate(r.ctx, "/ip/firewall/connection/tracking/set enabled=yes"); err != nil {
		r.mark(t, "B.conntrack.fixture", "INCONCLUSIVE", "could not enable disposable connection tracking")
		return
	}
	// Keep the synthetic clients in the fake LAN and the echo peer in the
	// fake WAN; the return route makes the two original LAN tuples visible.
	if r.net.Inet(r.ctx, "ip", "route", "add", "192.168.88.10/32", "via", "198.51.100.2", "dev", "wan0").Run() != nil {
		t.Fatal("conntrack: return route unavailable")
	}
	defer r.net.Inet(r.ctx, "ip", "route", "del", "192.168.88.10/32", "dev", "wan0").Run()
	serve := r.net.Inet(r.ctx, "python3", "-u", "-c", `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("203.0.113.30",31453))
while True:
 b,addr=s.recvfrom(64)
 s.sendto(b,addr)`)
	if serve.Start() != nil {
		t.Fatal("conntrack: echo peer unavailable")
	}
	defer func() { _ = serve.Process.Kill(); _ = serve.Wait() }()
	client := r.net.Client(r.ctx, "python3", "-u", "-c", `import socket,sys
socks={}
for p in (31461,31462):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("192.168.88.10",p));s.settimeout(2)
 socks[str(p)]=s
for line in sys.stdin:
 port,serial=line.split();s=socks[port];payload=serial.encode()
 try:
  s.sendto(payload,("203.0.113.30",31453));b,peer=s.recvfrom(64)
  print("echo "+port+" "+serial if peer==("203.0.113.30",31453) and b==payload else "mismatch")
 except OSError:
  print("unavailable")`)
	input, err := client.StdinPipe()
	if err != nil {
		t.Fatal("conntrack: client input unavailable")
	}
	out, w, err := os.Pipe()
	if err != nil {
		t.Fatal("conntrack: client output unavailable")
	}
	defer out.Close()
	defer w.Close()
	client.Stdout = w
	if err = client.Start(); err != nil {
		t.Fatal("conntrack: LAN client unavailable")
	}
	defer func() { input.Close(); client.Process.Kill(); client.Wait() }()
	reader := bufio.NewReader(out)
	seq := 0
	exchange := func(port int) bool {
		for range 3 {
			seq++
			if _, err := io.WriteString(input, fmt.Sprintf("%d %d\n", port, seq)); err != nil {
				return false
			}
			_ = out.SetReadDeadline(time.Now().Add(3 * time.Second))
			reply, err := reader.ReadString('\n')
			if err == nil && reply == fmt.Sprintf("echo %d %d\n", port, seq) {
				return true
			}
		}
		return false
	}
	rowID := func(cl *ros.Client, s int) (string, bool) {
		ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
		defer cancel()
		rows, err := cl.RunContext(ctx, menu+"/print", "=.proplist=.id,protocol,src-address,src-port,dst-address,dst-port", "?protocol=udp")
		if err != nil {
			return "", false
		}
		sport := strconv.Itoa(s)
		id := ""
		for _, row := range rows.Re {
			m := row.Map
			srcOK := m["src-address"] == "192.168.88.10:"+sport || (m["src-address"] == "192.168.88.10" && m["src-port"] == sport)
			dstOK := m["dst-address"] == peer+":"+strconv.Itoa(peerPort) || (m["dst-address"] == peer && m["dst-port"] == strconv.Itoa(peerPort))
			if m["protocol"] == "udp" && srcOK && dstOK {
				if id != "" || m[".id"] == "" {
					return "", false
				}
				id = m[".id"]
			}
		}
		return id, true
	}
	const target, witness = 31461, 31462
	first, read1 := rowID(r.admin, target)
	other, read2 := rowID(r.admin, witness)
	if !read1 || !read2 || first != "" || other != "" {
		r.mark(t, "B.conntrack.fixture", "INCONCLUSIVE", "baseline five-tuples already present or unreadable")
		return
	}
	// Subscribe on both identities before creating either flow. An initial dump of the
	// target cannot be in an initial dump. A newly allocated ID is a real event.
	listeners := make([]*ros.ListenReply, 2)
	for i, cl := range []*ros.Client{r.api, r.admin} {
		listeners[i], _ = cl.ListenArgsQueueContext(r.ctx, []string{menu + "/listen", "=.proplist=.id,.dead"}, 256)
		_, _ = cl.RunContext(r.ctx, menu+"/print", "=.proplist=.id", "?protocol=udp")
	}
	defer func() {
		for _, l := range listeners {
			if l != nil {
				ctx, cancel := context.WithTimeout(r.ctx, 4*time.Second)
				_, _ = l.CancelContext(ctx)
				cancel()
			}
		}
	}()
	if !exchange(target) || !exchange(witness) {
		r.mark(t, "B.conntrack.fixture", "INCONCLUSIVE", "could not establish both round-trip forwarded flows")
		return
	}
	// The RouterOS connection menu may refresh after traffic has arrived.
	// A long-lived socket and an exact tuple are required before identifying
	// a row; never infer a removal from an empty initial snapshot.
	var tid, wid, ownerTid, ownerWid string
	for end := time.Now().Add(8 * time.Second); time.Now().Before(end); time.Sleep(250 * time.Millisecond) {
		tid, _ = rowID(r.api, target)
		wid, _ = rowID(r.api, witness)
		ownerWid, _ = rowID(r.admin, witness)
		ownerTid, _ = rowID(r.admin, target)
		if tid != "" && wid != "" && tid != wid && ownerWid != "" && ownerTid != "" && ownerWid != ownerTid {
			break
		}
		exchange(target)
		exchange(witness)
	}
	if tid == "" || wid == "" || tid == wid || ownerWid == "" || ownerTid == "" || ownerTid == ownerWid {
		r.mark(t, "B.conntrack.fixture", "INCONCLUSIVE", fmt.Sprintf("tuple discovery target=%t witness=%t ownerWitness=%t", tid != "", wid != "", ownerWid != ""))
		return
	}
	removal = true
	rm := []string{menu + "/remove", "=.id=" + tid}
	_, err = r.api.RunArgsContext(r.ctx, rm)
	if err != nil {
		var de *ros.DeviceError
		if errors.As(err, &de) && strings.Contains(strings.ToLower(de.Error()), "permission") {
			ownerNow, ok := rowID(r.admin, target)
			if !ok || ownerNow == "" || ownerNow != ownerTid {
				r.mark(t, "B.conntrack.remove", "INCONCLUSIVE", "owner could not reidentify the exact target before control deletion")
				return
			}
			_, e := r.admin.RunContext(r.ctx, menu+"/remove", "=.id="+ownerNow)
			if id, ok := rowID(r.admin, target); e == nil && ok && id == "" {
				r.mark(t, "B.conntrack.remove", "FAIL", "restricted deletion denied; identical owner deletion removed the exact target")
			} else {
				r.mark(t, "B.conntrack.remove", "INCONCLUSIVE", "could not verify owner control after denial")
			}
		} else {
			r.mark(t, "B.conntrack.remove", "INCONCLUSIVE", "native removal failed without a confirmed permission control")
		}
	} else {
		var targetGone, witnessContinues, roundTrip, readable bool
		for started := time.Now(); time.Since(started) < 4*time.Second; time.Sleep(150 * time.Millisecond) {
			after, ok := rowID(r.admin, target)
			wid2, ok2 := rowID(r.admin, witness)
			alive := exchange(witness)
			wid3, ok3 := rowID(r.api, witness)
			readable = ok && ok2 && ok3
			targetGone = ok && after == ""
			witnessContinues = wid2 == ownerWid && wid3 == wid
			roundTrip = alive
			if targetGone && witnessContinues && roundTrip && readable {
				break
			}
		}
		if targetGone && witnessContinues && roundTrip && readable {
			r.mark(t, "B.conntrack.remove", "PASS", "exact target ID gone, same witness ID and socket completed a fresh echo round trip")
		} else {
			r.mark(t, "B.conntrack.remove", "INCONCLUSIVE", fmt.Sprintf("targetGone=%t sameWitness=%t freshEcho=%t readOK=%t", targetGone, witnessContinues, roundTrip, readable))
		}

	}
	type seen struct {
		matched, unsupported, valid bool
		events                      int
	}
	observed := func(l *ros.ListenReply, localID string) seen {
		if l == nil {
			return seen{}
		}
		timer := time.NewTimer(6 * time.Second)
		defer timer.Stop()
		events := 0
		for {
			select {
			case row, ok := <-l.Chan():
				if !ok {
					var trap *ros.DeviceError
					if errors.As(l.Err(), &trap) {
						msg := strings.ToLower(trap.Error())
						return seen{unsupported: strings.Contains(msg, "no such command") || strings.Contains(msg, "permission"), valid: true}
					}
					return seen{valid: l.Err() == nil, events: events}
				}
				events++
				if row.Map[".id"] == localID {
					return seen{matched: true, valid: true, events: events}
				}
			case <-timer.C:
				return seen{valid: true, events: events}
			}
		}
	}
	observedListen = true
	u := observed(listeners[0], tid)
	a := observed(listeners[1], ownerTid)
	switch {
	case u.matched:
		r.mark(t, "B.conntrack.listen", "PASS", "subscribed before proof of traffic, received event for the newly allocated target connection ID")
	case u.unsupported && a.unsupported:
		r.mark(t, "B.conntrack.listen", "FAIL", "restricted and owner sessions both received an explicit unsupported or denied listener trap")
	case u.valid && a.matched:
		r.mark(t, "B.conntrack.listen", "INCONCLUSIVE", "owner observed the target event, restricted listener did not; no permission denial proven")
	default:
		r.mark(t, "B.conntrack.listen", "INCONCLUSIVE", fmt.Sprintf("new connection notification not proven; bounded listeners restricted=%t/%d owner=%t/%d events", u.valid, u.events, a.valid, a.events))
	}
}
