//go:build linux

package netsetup

import (
	"bytes"
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// A veth peer owns its socket in a distinct namespace. The test thread
// returns to the runner's namespace before it exercises the production code.
func forwardingPeer(t *testing.T, wire netlink.Link, name, routerCIDR, peerCIDR, localIP string) *net.UDPConn {
	t.Helper()
	runner, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatal(err)
	}
	peer, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	switchTo := func(f *os.File) {
		t.Helper()
		if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
			t.Fatal(err)
		}
	}
	addIP := func(link netlink.Link, cidr string) {
		t.Helper()
		a, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(link, a); err != nil {
			t.Fatal(err)
		}
	}
	link := func(n string) netlink.Link {
		t.Helper()
		l, e := netlink.LinkByName(n)
		if e != nil {
			t.Fatal(e)
		}
		if e = netlink.LinkSetUp(l); e != nil {
			t.Fatal(e)
		}
		return l
	}
	switchTo(runner)
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: "peer0", PeerNamespace: netlink.NsFd(int(peer.Fd()))}); err != nil {
		t.Fatal(err)
	}
	port := link(name)
	if err := netlink.LinkSetMaster(port, wire); err != nil {
		t.Fatal(err)
	}
	addIP(wire, routerCIDR)
	switchTo(peer)
	defer switchTo(runner)
	nic := link("peer0")
	addIP(nic, peerCIDR)
	if localIP != strings.Split(peerCIDR, "/")[0] {
		addIP(nic, localIP+"/32")
	}
	gw, _, _ := net.ParseCIDR(routerCIDR)
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: nic.Attrs().Index, Gw: gw}); err != nil {
		t.Fatal(err)
	}
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(localIP)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRunnerForwardingStartup(t *testing.T) {
	inNewNetns(t)
	// The main route exits the same logical interface as the selected
	// LAN packets enter, just as it does on the RouterOS runner veth.
	wire := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "wire"}}
	if err := netlink.LinkAdd(wire); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(wire); err != nil {
		t.Fatal(err)
	}
	client := forwardingPeer(t, wire, "ing0", "192.0.2.1/30", "192.0.2.2/30", "192.0.2.2")
	wan := forwardingPeer(t, wire, "wan0", "198.51.100.1/30", "198.51.100.2/30", "203.0.113.7")
	dst := wan.LocalAddr().(*net.UDPAddr)
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: wire.Attrs().Index, Gw: net.ParseIP("198.51.100.2")}); err != nil {
		t.Fatal(err)
	}
	ing, err := Ingress()
	if err != nil || ing.Attrs().Name != "wire" {
		t.Fatal("runner did not discover the single ingress/main-route interface")
	}
	control, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	send := func(to *net.UDPAddr, body string) {
		t.Helper()
		if _, e := client.WriteToUDP([]byte(body), to); e != nil {
			t.Fatal(e)
		}
	}
	reaches := func(socket *net.UDPConn, body string, wait time.Duration) bool {
		t.Helper()
		socket.SetReadDeadline(time.Now().Add(wait))
		var b [256]byte
		for {
			n, _, e := socket.ReadFromUDP(b[:])
			if e != nil {
				if ne, ok := e.(net.Error); ok && ne.Timeout() {
					return false
				}
				t.Fatal(e)
			}
			if string(b[:n]) == body {
				return true
			}
		}
	}
	if err := setValue(forwardingFile, "1"); err != nil {
		t.Fatal(err)
	}
	if err := setValue(gatewayFile, "0"); err != nil {
		t.Fatal(err)
	}
	send(dst, "positive default route")
	if !reaches(wan, "positive default route", time.Second) {
		t.Fatal("no real forwarded positive control through main")
	}
	if err := StartClosed(); err != nil {
		t.Fatal(err)
	}
	send(dst, "startup")
	if reaches(wan, "startup", 200*time.Millisecond) {
		t.Error("runner startup forwarded through the unguarded main default")
	}
	localProbe := func() {
		t.Helper()
		send(control.LocalAddr().(*net.UDPAddr), "control")
		if !reaches(control, "control", time.Second) {
			t.Fatal("local repair path unavailable")
		}
	}
	localProbe()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	healthy := false
	var tun *netlink.Tuntap
	conflict := netlink.NewRule()
	conflict.Priority = rulePriority - 1
	conflict.IifName = ing.Attrs().Name
	conflict.Table = unix.RT_TABLE_MAIN
	extraDefault := &netlink.Route{LinkIndex: ing.Attrs().Index, Dst: defaultDst, Gw: net.ParseIP("198.51.100.2"), Table: TunTable, Priority: UnreachablePriority - 1}
	step := 0
	Keep(ctx, ing, func() bool { return healthy }, func(routes, up bool) {
		step++
		fwd, e := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if e != nil {
			t.Fatal(e)
		}
		echo, e := os.ReadFile(gatewayFile)
		if e != nil {
			t.Fatal(e)
		}
		switch step {
		case 1, 2, 3, 5:
			if routes || up || strings.TrimSpace(string(fwd)) != "0" || strings.TrimSpace(string(echo)) != "1" {
				t.Errorf("step %d: forwarding or ping open without a usable protected TUN", step)
			}
			send(dst, "blocked")
			if reaches(wan, "blocked", 200*time.Millisecond) {
				t.Errorf("step %d: unguarded WAN packet", step)
			}
			localProbe()
		case 4:
			if !routes || !up || strings.TrimSpace(string(fwd)) != "1" || strings.TrimSpace(string(echo)) != "0" {
				t.Fatal("protected forwarding failed to reopen")
			}
			const payload = "healthy data path"
			send(dst, payload)
			var packet [2048]byte
			fd := int(tun.Fds[0].Fd())
			deadline := time.Now().Add(time.Second)
			for {
				if time.Now().After(deadline) {
					t.Fatal("TUN never received healthy flow")
				}
				p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				n, e := unix.Poll(p, 50)
				if e != nil {
					t.Fatal(e)
				}
				if n == 0 {
					continue
				}
				n, e = unix.Read(fd, packet[:])
				if e != nil {
					t.Fatal(e)
				}
				if bytes.Contains(packet[:n], []byte(payload)) {
					break
				}
			}
		}
		switch step {
		case 1:
			tun = addTestTun(t)
			if e := netlink.RuleAdd(conflict); e != nil {
				t.Fatal(e)
			}
			healthy = true
		case 2:
			if e := netlink.RuleDel(conflict); e != nil {
				t.Fatal(e)
			}
			if e := netlink.RouteAdd(extraDefault); e != nil {
				t.Fatal(e)
			}
		case 3:
			if e := tun.Fds[0].Close(); e != nil {
				t.Fatal(e)
			}
			send(dst, "competing fallback")
			if reaches(wan, "competing fallback", 200*time.Millisecond) {
				t.Error("extra default forwarded after TUN loss")
			}
			if e := netlink.RouteDel(extraDefault); e != nil {
				t.Fatal(e)
			}
			tun = addTestTun(t)
		case 4:
			if e := tun.Fds[0].Close(); e != nil {
				t.Fatal(e)
			}
			// The unreachable route must protect the period before the
			// next tick notices that xray has closed its TUN.
			send(dst, "lost TUN")
			if reaches(wan, "lost TUN", 200*time.Millisecond) {
				t.Error("main took over after the TUN disappeared")
			}
		case 5:
			cancel()
		}
	})
	if step != 5 {
		t.Fatal("retry sequence incomplete")
	}
}

// Losing CAP_NET_ADMIN causes the real kernel to deny RouteReplace. The
// already-closed namespace can continue serving until the next successful tick.
func TestRunnerRetriesUnreachableGuard(t *testing.T) {
	inNewNetns(t)
	ing := addLink(t, "ing0")
	addTestTun(t)
	if err := StartClosed(); err != nil {
		t.Fatal(err)
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var original [2]unix.CapUserData
	if err := unix.Capget(&header, &original[0]); err != nil {
		t.Fatal(err)
	}
	held := original
	held[0].Effective &^= 1 << unix.CAP_NET_ADMIN
	if err := unix.Capset(&header, &held[0]); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := unix.Capset(&header, &original[0]); e != nil {
			t.Error(e)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	steps := 0
	Keep(ctx, ing, func() bool { return true }, func(routes, up bool) {
		steps++
		forward, e := os.ReadFile(forwardingFile)
		if e != nil {
			t.Fatal(e)
		}
		echo, e := os.ReadFile(gatewayFile)
		if e != nil {
			t.Fatal(e)
		}
		switch steps {
		case 1:
			if up || routes || strings.TrimSpace(string(forward)) != "0" || strings.TrimSpace(string(echo)) != "1" {
				t.Fatal("failed guard write activated the gateway")
			}
			if err := unix.Capset(&header, &original[0]); err != nil {
				t.Fatal(err)
			}
		case 2:
			if !up || !routes || strings.TrimSpace(string(forward)) != "1" || strings.TrimSpace(string(echo)) != "0" {
				t.Fatal("retry did not reopen the protected path")
			}
			cancel()
		}
	})
	if steps != 2 {
		t.Fatal("retry did not finish")
	}
}
