//go:build lab

package e2e

import (
	"bufio"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
)

const (
	routingRemote   = "93.184.216.248"
	routingDomestic = "93.184.216.249"
	routingPeer     = "192.168.88.110"
	routingPeerNS   = "tkrouting-peer"
)

var fullOpen = store.Policy{Mode: store.ModeFull}

type routingLab struct {
	*installLab
	api          *apiclient.Client
	ros          *routeros.Client
	mac, peerMAC string
	route        store.Routing
	serverIDs    map[string]string
}

func deployRouting(ctx context.Context, t, owner *testing.T) *routingLab {
	t.Helper()
	f := &routingLab{installLab: deployM3(ctx, t, owner), serverIDs: map[string]string{}}
	f.clients(ctx, t, owner)
	f.targets(ctx, t, owner)
	f.mustRun(ctx, t, `/ip/firewall/filter/add chain=forward action=drop src-address=198.18.23.17 comment="lab:tikray:no-fasttrack"`)
	f.ownerRules = f.readOwnerRules(ctx, t)
	f.stage(ctx, t, true)
	f.requireSuccess(ctx, t)
	f.checkReady(ctx, t)
	f.api = f.pinned(ctx, t)
	f.ros = f.ownerSession(ctx, t)
	owner.Cleanup(func() { f.ros.Close() })
	f.route = store.Default().Routing
	f.route.Domestic = store.Domestic{Domains: []string{"domain:domestic.test"}, IPs: []string{routingDomestic + "/32"}}
	if _, err := f.api.SetRouting(ctx, f.route); err != nil {
		t.Fatal("routing fixture rejected domestic prefix")
	}
	if _, err := f.api.SetDNS(ctx, store.DNS{Remote: "203.0.113.53", Domestic: netip.MustParseAddr("203.0.113.54")}); err != nil {
		t.Fatal("routing fixture rejected resolvers")
	}
	if _, err := f.api.SetHealth(ctx, store.Health{ProbeURL: labProbeURL}); err != nil {
		t.Fatal("routing fixture rejected health probe")
	}
	for _, s := range []struct{ name, link string }{{"a", linkA}, {"b", linkB}} {
		resp, err := f.api.AddServer(ctx, apiclient.NewServer{Link: s.link})
		var server store.Server
		if err != nil || resp.Decode(&server) != nil || server.ID == "" {
			t.Fatal("could not add fixture server", s.name)
		}
		f.serverIDs[s.name] = server.ID
	}
	f.checkReady(ctx, t)
	f.waitAlive(ctx, t)
	f.setupProtocols(ctx, t)
	return f
}

func (f *routingLab) waitAlive(ctx context.Context, t *testing.T) {
	t.Helper()
	_, ok := poll(ctx, 2*time.Minute, time.Second, func() bool {
		resp, e := f.api.Status(ctx)
		var s service.Status
		return e == nil && resp.Decode(&s) == nil && s.Applied && !s.Pending && aliveIn(s.Health, f.serverIDs["a"]) && aliveIn(s.Health, f.serverIDs["b"])
	})
	if !ok {
		t.Fatal("both distinct VLESS exits did not pass their independent health probes")
	}
}

func (f *routingLab) readROS(ctx context.Context, t *testing.T, menu, fields string, query ...string) []routeros.Row {
	t.Helper()
	if len(query) == 0 {
		t.Fatal("native fixture read needs a router-side predicate")
	}
	rows, e := f.ros.CommandAt(ctx, f.ros.Generation(), append([]string{menu + "/print", "=.proplist=" + fields}, query...))
	if e != nil {
		t.Fatal("native fixture read failed", menu)
	}
	return rows
}

func (f *routingLab) peer(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", routingPeerNS, name}, args...)...)
}

// Obtain actual DHCP ACKs in the two separate L2 namespaces. A configured
// reservation in waiting state cannot establish the observed MAC of a client.
//
//go:embed testdata/routing_dhcp.py
var routingDHCP string

func (f *routingLab) clients(ctx context.Context, t, owner *testing.T) {
	t.Helper()
	if exec.CommandContext(ctx, "ip", "netns", "add", routingPeerNS).Run() != nil {
		t.Fatal("dedicated peer namespace unavailable")
	}
	owner.Cleanup(func() {
		if exec.Command("ip", "netns", "del", routingPeerNS).Run() != nil {
			owner.Error("peer namespace cleanup failed")
		}
	})
	for _, args := range [][]string{
		{"link", "add", "tklab-peer-h", "type", "veth", "peer", "name", "eth0", "netns", routingPeerNS},
		{"link", "set", "tklab-peer-h", "master", "tklab-lan", "up"},
		{"-n", routingPeerNS, "link", "set", "lo", "up"}, {"-n", routingPeerNS, "link", "set", "eth0", "up"},
		{"-n", routingPeerNS, "addr", "add", routingPeer + "/24", "dev", "eth0"},
		{"-n", routingPeerNS, "route", "add", "default", "via", "192.168.88.1"},
	} {
		if exec.CommandContext(ctx, "ip", args...).Run() != nil {
			t.Fatal("dedicated peer link unavailable")
		}
	}
	f.mustRun(ctx, t, `/ip/dhcp-server/network/add address=192.168.88.0/24 gateway=192.168.88.1 dns-server=192.168.88.1 comment="lab:routing-network"`)
	f.mustRun(ctx, t, `/ip/dhcp-server/add interface=ether2 name=m3-routing-dhcp address-pool=static-only conflict-detection=no disabled=no lease-time=1d comment="lab:routing-dhcp"`)
	for _, c := range []struct {
		addr string
		cmd  func(context.Context, string, ...string) *exec.Cmd
		dest *string
	}{{lanClient.Addr().String(), f.Net.Client, &f.mac}, {routingPeer, f.peer, &f.peerMAC}} {
		raw, e := c.cmd(ctx, "cat", "/sys/class/net/eth0/address").Output()
		m, e2 := net.ParseMAC(strings.TrimSpace(string(raw)))
		if e != nil || e2 != nil || len(m) != 6 {
			t.Fatal("client hardware address unavailable")
		}
		*c.dest = m.String()
		f.mustRun(ctx, t, fmt.Sprintf(`/ip/dhcp-server/lease/add server=m3-routing-dhcp address=%s mac-address=%s comment="lab:routing-client"`, c.addr, m))
		if err := c.cmd(ctx, "python3", "-c", routingDHCP, c.addr).Run(); err != nil {
			t.Fatal("LAN client did not receive a DHCP acknowledgement", c.addr, err)
		}
		// The RouterOS lease menu may refresh after the wire ACK.
		query := fmt.Sprintf(`:put [:len [/ip/dhcp-server/lease/find where status=bound and active-address=%s and active-mac-address=%s]]`, c.addr, strings.ToUpper(m.String()))
		_, bound := poll(ctx, 12*time.Second, 500*time.Millisecond, func() bool {
			return f.mustRun(ctx, t, query) == "1"
		})
		if !bound {
			state := f.mustRun(ctx, t, fmt.Sprintf(`:put [:len [/ip/dhcp-server/lease/find where address=%s and status=bound]]`, c.addr))
			address := f.mustRun(ctx, t, fmt.Sprintf(`:put [:len [/ip/dhcp-server/lease/find where active-address=%s]]`, c.addr))
			t.Fatalf("DHCP ACK lacks bound lease for %s (bound %t, active address %t)", c.addr, state == "1", address == "1")
		}
	}
	if f.mac == f.peerMAC {
		t.Fatal("LAN clients share a link identity")
	}
}

// The .248/.249 addresses exist only in the fake internet, outside every
// reserved bypass. The TCP echo reports what the remote end actually sees.
const routingTargets = `import socketserver,http.server,threading,sys
class HTTP(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  if self.path!="/whoami":self.send_error(404);return
  b=self.client_address[0].encode();self.send_response(200);self.send_header("Content-Length",str(len(b)));self.end_headers();self.wfile.write(b)
class Echo(socketserver.StreamRequestHandler):
 def handle(self):
  while self.rfile.readline(32):self.wfile.write(self.client_address[0].encode()+b"\n")
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
servers=[http.server.ThreadingHTTPServer((a,80),HTTP) for a in sys.argv[1:]]+[Server((sys.argv[1],31945),Echo)]
for s in servers:threading.Thread(target=s.serve_forever,daemon=True).start()
print("ready",flush=True);threading.Event().wait()`

func (f *routingLab) targets(ctx context.Context, t, owner *testing.T) {
	t.Helper()
	for _, ip := range []string{routingRemote, routingDomestic} {
		if f.Net.Inet(ctx, "ip", "addr", "add", ip+"/32", "dev", "lo").Run() != nil {
			t.Fatal("isolated remote address setup failed")
		}
	}
	cmd := f.Net.Inet(ctx, "python3", "-c", routingTargets, routingRemote, routingDomestic)
	out, e := cmd.StdoutPipe()
	if e != nil || cmd.Start() != nil {
		t.Fatal("isolated target startup failed")
	}
	owner.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	var ready string
	timer := time.AfterFunc(8*time.Second, func() { cmd.Process.Kill() })
	_, e = fmt.Fscanln(out, &ready)
	timer.Stop()
	if e != nil || ready != "ready" {
		t.Fatal("isolated targets unavailable")
	}
	if f.egress(ctx, routingRemote) != egressDirect || f.peerEgress(ctx, routingDomestic) != egressDirect {
		t.Fatal("pre-install direct/peer positive controls failed")
	}
}

func (f *routingLab) setClientPolicy(ctx context.Context, t *testing.T, p store.Policy) {
	t.Helper()
	if _, err := f.api.SetDevice(ctx, store.Device{Address: lanClient, MAC: f.mac, Name: "routing-client", Policy: p}); err != nil {
		var ae *apiclient.Error
		routerUnavailable, routerConflict := false, false
		if errors.As(err, &ae) {
			routerUnavailable = ae.Detail == service.ErrRouterUnavailable.Error()
			routerConflict = ae.Detail == service.ErrRouterConflict.Error()
		}
		t.Fatalf("LAN policy mutation failed (%s, unavailable=%t conflict=%t deadline=%t), mode=%s closed=%t", apiEvidence(err), routerUnavailable, routerConflict, errors.Is(err, context.DeadlineExceeded), p.Mode, p.KillSwitch)
	}
	f.checkReady(ctx, t)
}

func (f *routingLab) egress(ctx context.Context, addr string) string {
	return f.curl(ctx, "http://"+addr+"/whoami")
}
func (f *routingLab) peerEgress(ctx context.Context, addr string) string {
	out, _ := f.peer(ctx, "curl", "--noproxy", "*", "-fsS", "--max-time", "4", "http://"+addr+"/whoami").Output()
	return strings.TrimSpace(string(out))
}
func isRoutingProxy(ip string) bool { return ip == serverEgress["a"] || ip == serverEgress["b"] }

type routingFlow struct {
	f      *routingLab
	stdin  io.WriteCloser
	out    *bufio.Reader
	cmd    *exec.Cmd
	source string
	port   int
}

func (f *routingLab) tcpFlow(ctx context.Context, t *testing.T, peer bool, port int) *routingFlow {
	t.Helper()
	src, command := lanClient.Addr().String(), f.Net.Client
	if peer {
		src, command = routingPeer, f.peer
	}
	const client = `import socket,sys
s=socket.socket();s.settimeout(8);s.bind((sys.argv[1],int(sys.argv[2])));s.connect((sys.argv[3],31945))
f=s.makefile("rb")
for _ in sys.stdin:
 s.sendall(b"probe\n");line=f.readline(64)
 if not line:break
 sys.stdout.buffer.write(line);sys.stdout.flush()`
	cmd := command(ctx, "python3", "-u", "-c", client, src, strconv.Itoa(port), routingRemote)
	in, e1 := cmd.StdinPipe()
	out, e2 := cmd.StdoutPipe()
	if e1 != nil || e2 != nil || cmd.Start() != nil {
		t.Fatal("persistent LAN stream startup failed")
	}
	t.Cleanup(func() { in.Close(); cmd.Process.Kill(); cmd.Wait() })
	flow := &routingFlow{f: f, stdin: in, out: bufio.NewReader(out), cmd: cmd, source: src, port: port}
	// The connection menu on CHR refreshes asynchronously. Establish the
	// exact tuple while its socket is exchanging data before testing either
	// continuity or removal. An empty initial read proves neither.
	_, ok := poll(ctx, 12*time.Second, 250*time.Millisecond, func() bool {
		flow.echo(t)
		return flow.id(ctx, t) != ""
	})
	if !ok {
		t.Fatal("live TCP tuple did not appear in RouterOS", src, port)
	}
	return flow
}

func (s *routingFlow) echo(t *testing.T) string {
	t.Helper()
	addr := s.exchange()
	if addr == "" {
		t.Fatal("persistent remote witness disappeared")
	}
	return addr
}

func (s *routingFlow) exchange() string {
	timer := time.AfterFunc(10*time.Second, func() { s.cmd.Process.Kill() })
	defer timer.Stop()
	if _, e := io.WriteString(s.stdin, "probe\n"); e != nil {
		return ""
	}
	line, err := s.out.ReadString('\n')
	addr, parse := netip.ParseAddr(strings.TrimSpace(line))
	if err != nil || parse != nil || !addr.Is4() {
		return ""
	}
	return addr.String()
}
func (s *routingFlow) row(ctx context.Context, t *testing.T) routeros.Row {
	t.Helper()
	r := s.f.readROS(ctx, t, "/ip/firewall/connection", ".id,src-address,src-port,dst-address,dst-port,protocol,connection-mark,fasttrack",
		"?protocol=tcp", "?src-address="+s.source, "?src-port="+strconv.Itoa(s.port), "?dst-address="+routingRemote, "?dst-port=31945")
	if len(r) > 1 {
		t.Fatal("ambiguous connection witness")
	}
	if len(r) == 0 {
		return nil
	}
	return r[0]
}
func (s *routingFlow) id(ctx context.Context, t *testing.T) string { return s.row(ctx, t)[".id"] }
