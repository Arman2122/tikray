//go:build lab

package e2e

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/store"
)

const (
	v6Primary = "2001:db8:88::10"
	v6Peer    = "2001:db8:88::110"
	v6Target  = "2001:db8:4:1::2"
)

func (f *routingLab) setupProtocols(ctx context.Context, t *testing.T) {
	t.Helper()
	f.mustRun(ctx, t, `/ipv6/address/add interface=ether2 address=2001:db8:88::1/64 advertise=no comment="lab:routing-v6-lan"`)
	for _, c := range []struct {
		addr string
		run  func(context.Context, string, ...string) *exec.Cmd
	}{
		{v6Primary, f.Net.Client}, {v6Peer, f.peer},
	} {
		if c.run(ctx, "ip", "-6", "addr", "add", c.addr+"/64", "dev", "eth0", "nodad").Run() != nil ||
			c.run(ctx, "ip", "-6", "route", "replace", v6Target+"/128", "via", "2001:db8:88::1", "dev", "eth0").Run() != nil {
			t.Fatal("could not attach client IPv6 route")
		}
	}
	if f.Net.Inet(ctx, "ip", "-6", "route", "replace", "2001:db8:88::/64", "via", "2001:db8:4:1::1", "dev", "wan0").Run() != nil {
		t.Fatal("could not attach external IPv6 return route")
	}
}

// Require a real DNS reply even for an empty answer. A resolver failure or
// timeout cannot stand in for the IPv4-only policy returning no AAAA records.
func (f *routingLab) protocolDNS(ctx context.Context, t *testing.T, peer bool, name, typ, network, resolver string) []string {
	t.Helper()
	run := f.Net.Client
	if peer {
		run = f.peer
	}
	args := []string{"-4", "+noall", "+comments", "+answer", "+time=4", "+tries=2", "@" + resolver, name, typ}
	if network == "tcp" {
		args = append(args, "+tcp")
	}
	out, err := run(ctx, "dig", args...).Output()
	if err != nil || !strings.Contains(string(out), "status: NOERROR,") {
		t.Fatalf("%s %s reply missing or unsuccessful", network, typ)
	}
	var answers []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, ";") || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 5 || !strings.EqualFold(fields[0], strings.TrimSuffix(name, ".")+".") || fields[2] != "IN" || fields[3] != typ {
			t.Fatal("unexpected DNS answer record")
		}
		ip, e := netip.ParseAddr(fields[4])
		if e != nil {
			t.Fatal("invalid DNS address")
		}
		answers = append(answers, ip.String())
	}
	return answers
}

func (f *routingLab) dnsPaths(ctx context.Context, t *testing.T) {
	t.Helper()
	routing := f.route
	routing.Domestic.Domains = append(slices.Clone(f.route.Domestic.Domains), "domain:domestic.routing-probe.test")
	if _, e := f.api.SetRouting(ctx, routing); e != nil {
		t.Fatal("could not admit DNS witness domain")
	}
	defer func() {
		if _, e := f.api.SetRouting(ctx, f.route); e != nil {
			t.Fatal("could not restore fixture routing")
		}
		f.checkReady(ctx, t)
	}()
	f.checkReady(ctx, t)
	for _, transport := range []string{"tcp", "udp"} {
		tag := "tikray:dns-full-open-" + transport
		_, up := poll(ctx, time.Minute, time.Second, func() bool {
			rows := f.readROS(ctx, t, "/ip/firewall/nat", "disabled", "?comment="+tag)
			return len(rows) == 1 && rows[0]["disabled"] != "true"
		})
		if !up {
			t.Fatal("open DNS primary did not arm")
		}
		name := transport + ".foreign.routing-probe.test."
		before := f.packets(ctx, t, "/ip/firewall/nat", tag)
		if !slices.Equal(f.protocolDNS(ctx, t, true, name, "A", transport, "203.0.113.53"), []string{"198.18.53.1"}) ||
			f.packets(ctx, t, "/ip/firewall/nat", tag) != before {
			t.Fatal("direct peer's resolver or NAT path changed")
		}
		for _, q := range []struct{ name, answer string }{
			{transport + ".domestic.routing-probe.test.", "198.18.54.1"},
			{name, "198.18.53.2"},
		} {
			n := f.packets(ctx, t, "/ip/firewall/nat", tag)
			// No resolver runs at this numeric address. Both the reply and a
			// fresh hit on the production primary are required.
			if !slices.Equal(f.protocolDNS(ctx, t, false, q.name, "A", transport, routingRemote), []string{q.answer}) || f.packets(ctx, t, "/ip/firewall/nat", tag) <= n {
				t.Fatalf("%s resolver or egress did not match policy", transport)
			}
		}
	}
}

// Match the returned ICMPv6 echo or the exact quoted echo in an
// administratively-prohibited error. An arbitrary timeout is inconclusive.
const v6Probe = `import ipaddress, os, socket, struct, sys, time
src,dst=sys.argv[1:]
nonce=os.urandom(12); ident=os.getpid()&65535
echo=struct.pack("!BBHHH",128,0,0,ident,1)+nonce
ip=lambda a:ipaddress.IPv6Address(a).packed
s=socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.IPPROTO_ICMPV6)
s.bind((src,0));s.sendto(echo,(dst,0))
end=time.monotonic()+4
while time.monotonic()<end:
 s.settimeout(max(0.01,end-time.monotonic()))
 try: p,peer=s.recvfrom(2048)
 except socket.timeout:break
 if len(p)>=20 and p[:2]==bytes([129,0]) and ip(peer[0])==ip(dst) and p[4:]==echo[4:]:
  print("echo");sys.exit()
 if len(p)>=68 and p[:2]==bytes([1,1]) and ip(peer[0])==ip("2001:db8:88::1") and p[14]==58 and p[16:32]==ip(src) and p[32:48]==ip(dst) and p[48:50]==bytes([128,0]) and p[52:68]==echo[4:]:
  print("prohibited");sys.exit()
sys.exit(1)`

func (f *routingLab) ipv6Reachable(ctx context.Context, t *testing.T, peer bool) bool {
	t.Helper()
	run, addr := f.Net.Client, v6Primary
	if peer {
		run, addr = f.peer, v6Peer
	}
	out, err := run(ctx, "python3", "-c", v6Probe, addr, v6Target).Output()
	if err != nil {
		t.Fatal("no matched IPv6 echo reply or administrative rejection")
	}
	switch strings.TrimSpace(string(out)) {
	case "echo":
		return true
	case "prohibited":
		return false
	default:
		t.Fatal("malformed IPv6 witness")
		return false
	}
}

func (f *routingLab) ipv6Guard(ctx context.Context, t *testing.T) {
	t.Helper()
	f.setClientPolicy(ctx, t, store.Policy{Mode: store.ModeDirect})
	if !f.ipv6Reachable(ctx, t, false) || !f.ipv6Reachable(ctx, t, true) {
		t.Fatal("unrestricted clients failed IPv6 reachability control")
	}
	f.setClientPolicy(ctx, t, fullOpen)
	const tag = "tikray:ipv6:host:192.168.88.10"
	before := f.packets(ctx, t, "/ipv6/firewall/filter", tag)
	if f.ipv6Reachable(ctx, t, false) || f.packets(ctx, t, "/ipv6/firewall/filter", tag) <= before || !f.ipv6Reachable(ctx, t, true) {
		t.Fatal("guard did not reject precisely the selected MAC")
	}
	if a := f.protocolDNS(ctx, t, true, "dual.foreign.routing-probe.test.", "AAAA", "udp", "203.0.113.53"); !slices.Equal(a, []string{v6Target}) {
		t.Fatal("direct resolver failed positive AAAA control")
	}
	if a := f.protocolDNS(ctx, t, false, "dual.foreign.routing-probe.test.", "AAAA", "udp", routingRemote); len(a) != 0 {
		t.Fatal("proxied DNS exposed an IPv6 destination")
	}
	if a := f.protocolDNS(ctx, t, false, "dual.foreign.routing-probe.test.", "A", "udp", routingRemote); !slices.Equal(a, []string{"198.18.53.2"}) {
		t.Fatal("proxied resolver failed IPv4 fallback")
	}
}

func (f *routingLab) quicSniff(ctx context.Context, t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	bin, cert := filepath.Join(dir, "routequic"), filepath.Join(dir, "cert.pem")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./test/lab/fixtures/labinet/cmd/routequic")
	build.Dir = repoRoot()
	if err := build.Run(); err != nil {
		t.Fatal("could not build QUIC fixture")
	}
	server := f.Net.Inet(ctx, bin, "serve", routingRemote+":443", cert)
	if server.Start() != nil {
		t.Fatal("QUIC fixture start")
	}
	defer func() { server.Process.Kill(); server.Wait() }()
	if _, ok := poll(ctx, 8*time.Second, 100*time.Millisecond, func() bool { _, e := os.Stat(cert); return e == nil }); !ok {
		t.Fatal("QUIC fixture did not publish its public certificate")
	}
	const tag = "lab:quic-to-runner"
	f.mustRun(ctx, t, fmt.Sprintf(`/interface/bridge/filter/add chain=output out-interface=tikray-runner mac-protocol=ip ip-protocol=udp src-address=192.168.88.10/32 dst-address=%s/32 dst-port=443 action=passthrough comment=%s`, routingRemote, tag))
	defer f.mustRun(ctx, t, `/interface/bridge/filter/remove [find where comment="lab:quic-to-runner"]`)
	probe := func(peer bool, name string) (string, bool) {
		run, addr := f.Net.Client, "192.168.88.10"
		if peer {
			run, addr = f.peer, routingPeer
		}
		out, e := run(ctx, bin, "probe", addr+":0", routingRemote+":443", name, cert).Output()
		fields := strings.Fields(string(out))
		if e != nil || len(fields) != 3 || fields[1] != routingRemote || fields[2] != name {
			return "", false
		}
		return fields[0], true
	}
	if e, ok := probe(true, "domestic.test"); !ok || e != egressDirect {
		t.Fatal("direct peer failed full QUIC handshake control")
	}
	f.setClientPolicy(ctx, t, store.Policy{Mode: store.ModeSmart})
	for _, name := range []string{"domestic.test", "foreign.test"} {
		before := f.packets(ctx, t, "/interface/bridge/filter", tag)
		egress, ok := probe(false, name)
		if !ok || name == "domestic.test" && egress != egressDirect || name == "foreign.test" && !isRoutingProxy(egress) {
			t.Fatal("QUIC source, destination or observed SNI did not match", name)
		}
		if f.packets(ctx, t, "/interface/bridge/filter", tag) <= before {
			t.Fatal("QUIC spoke to the WAN without first reaching the real runner", name)
		}
	}
}
