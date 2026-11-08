//go:build lab

package e2e

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/apiclient"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
)

func (f *routingLab) expectPath(ctx context.Context, t *testing.T, destination string, proxied bool) {
	t.Helper()
	_, ok := poll(ctx, f.proxiedWithin(), time.Second, func() bool {
		got := f.egress(ctx, destination)
		return (proxied && isRoutingProxy(got)) || (!proxied && got == egressDirect)
	})
	if !ok {
		t.Fatal("unexpected remote egress for policy and destination", destination, proxied)
	}
}

func (f *routingLab) policyPaths(ctx context.Context, t *testing.T) {
	t.Helper()
	for _, tc := range []struct {
		mode             store.Mode
		remote, domestic bool
	}{
		{store.ModeDirect, false, false}, {store.ModeSmart, true, false}, {store.ModeFull, true, true},
	} {
		f.setClientPolicy(ctx, t, store.Policy{Mode: tc.mode})
		f.expectPath(ctx, t, routingRemote, tc.remote)
		f.expectPath(ctx, t, routingDomestic, tc.domestic)
		// A private WAN destination and a router-local SSH endpoint must work
		// even when the client's public traffic uses a VLESS egress.
		if f.whoami(ctx) != egressDirect || f.peerEgress(ctx, routingRemote) != egressDirect {
			t.Fatal("local bypass or direct peer lost its path", tc.mode)
		}
		if f.Net.Client(ctx, "python3", "-c", `import socket
s=socket.create_connection(("192.168.88.1",22),4)
if not s.recv(64).startswith(b"SSH-"):raise SystemExit(1)`).Run() != nil {
			t.Fatal("policy interrupted router-local management", tc.mode)
		}
	}
}

func (f *routingLab) packets(ctx context.Context, t *testing.T, menu, tag string) uint64 {
	t.Helper()
	rows := f.readROS(ctx, t, menu, "packets,comment", "?comment="+tag)
	if len(rows) != 1 {
		t.Fatal("counter lacks one exact tagged row", tag)
	}
	n, e := strconv.ParseUint(rows[0]["packets"], 10, 64)
	if e != nil {
		t.Fatal("invalid counter for", tag)
	}
	return n
}

func (f *routingLab) sourceAndFastTrack(ctx context.Context, t *testing.T) {
	t.Helper()
	// A previous owner masquerade could erase the policy client's source at
	// the runner. Refuse activation, and allow exactly the WAN-scoped rule.
	f.setClientPolicy(ctx, t, store.Policy{Mode: store.ModeDirect})
	const owner = "witness:source-masquerade"
	f.mustRun(ctx, t, `/ip/firewall/nat/add chain=srcnat src-address=192.168.88.10 action=masquerade comment="witness:source-masquerade"`)
	t.Cleanup(func() {
		f.mustRun(ctx, t, `/ip/firewall/nat/remove [find where chain=srcnat and action=masquerade and comment="witness:source-masquerade"]`)
	})
	identity := f.taggedID(ctx, t, "/ip/firewall/nat", owner)
	_, err := f.api.SetDevice(ctx, store.Device{Address: lanClient, MAC: f.mac, Name: "routing-client", Policy: store.Policy{Mode: store.ModeFull, KillSwitch: true}})
	var refusal *apiclient.Error
	if identity == "" || !errors.As(err, &refusal) || refusal.Status != http.StatusConflict || f.egress(ctx, routingRemote) != egressDirect {
		t.Fatal("unsafe source NAT was not refused with ordinary forwarding intact")
	}
	f.routingWrite(ctx, t, "/ip/firewall/nat/set", "=.id="+identity, "=out-interface=ether1")
	f.setClientPolicy(ctx, t, fullOpen)
	// A broad rule left below the verified exemptions must stay untouched.
	f.mustRun(ctx, t, `/ip/firewall/nat/unset [find where chain=srcnat and action=masquerade and comment="witness:source-masquerade"] out-interface`)
	const br = "/interface/bridge/filter"
	const packet = "lab:private-runner-ingress"
	// Observe the actual frame routed to the runner, after the srcnat hook.
	// Original tuples from connection tracking alone cannot detect an SNAT.
	f.mustRun(ctx, t, `/interface/bridge/filter/add chain=output out-interface=tikray-runner mac-protocol=ip ip-protocol=tcp src-address=192.168.88.10/32 dst-address=93.184.216.248/32 src-port=31823 dst-port=31945 action=passthrough comment="lab:private-runner-ingress"`)
	t.Cleanup(func() {
		f.mustRun(ctx, t, `/interface/bridge/filter/remove [find where comment="lab:private-runner-ingress" and action=passthrough]`)
	})
	// Numeric comparisons must use a control observed on this same run.
	mss := f.packets(ctx, t, "/ip/firewall/mangle", "tikray:mss-open")
	slow := f.packets(ctx, t, "/ip/firewall/filter", "tikray:no-fasttrack")
	brCount := f.packets(ctx, t, br, packet)
	proxy := f.tcpFlow(ctx, t, false, 31823)
	peer := f.tcpFlow(ctx, t, true, 31824)
	for range 4 {
		if !isRoutingProxy(proxy.echo(t)) || peer.echo(t) != egressDirect {
			t.Fatal("remote stream source did not identify both paths")
		}
	}
	pr, dr := proxy.row(ctx, t), peer.row(ctx, t)
	if pr == nil || pr["src-address"] != "192.168.88.10" || pr["connection-mark"] != "tikray-open" || pr["fasttrack"] == "true" || dr == nil || dr["fasttrack"] != "true" {
		t.Fatalf("unexpected FastTrack paths: policy row=%t source=%t mark=%t accelerated=%t; peer row=%t accelerated=%t",
			pr != nil, pr["src-address"] == "192.168.88.10", pr["connection-mark"] == "tikray-open", pr["fasttrack"] == "true", dr != nil, dr["fasttrack"] == "true")
	}
	rows := f.readROS(ctx, t, "/ip/firewall/filter", "comment,action,packet-mark,disabled,dynamic", "?chain=forward")
	var previous string
	anchors, exempt := 0, 0
	for _, r := range rows {
		if r["disabled"] == "true" || r["dynamic"] == "true" {
			continue
		}
		if r["comment"] == "tikray:no-fasttrack" {
			exempt++
			if r["action"] != "accept" || r["packet-mark"] != "tikray-proxied" {
				t.Fatal("invalid FastTrack exception")
			}
		}
		if r["action"] == "fasttrack-connection" {
			anchors++
			if previous != "tikray:no-fasttrack" || r["comment"] != "lab:fasttrack" {
				t.Fatal("FastTrack exception is not directly before the owner's rule")
			}
		}
		previous = r["comment"]
	}
	if anchors != 1 || exempt != 1 {
		t.Fatal("missing or duplicate FastTrack anchor/exception")
	}
	if f.packets(ctx, t, br, packet) <= brCount || f.packets(ctx, t, "/ip/firewall/mangle", "tikray:mss-open") <= mss || f.packets(ctx, t, "/ip/firewall/filter", "tikray:no-fasttrack") <= slow {
		t.Fatal("live runner-ingress, MSS or FastTrack exception evidence did not advance")
	}
	if f.taggedID(ctx, t, "/ip/firewall/nat", owner) != identity || f.packets(ctx, t, "/ip/firewall/nat", "tikray:preserve-open") == 0 {
		t.Fatal("source preservation or owner NAT identity was lost")
	}
	f.setClientPolicy(ctx, t, store.Policy{Mode: store.ModeFull, KillSwitch: true})
	closed := f.tcpFlow(ctx, t, false, 31825)
	if !isRoutingProxy(closed.echo(t)) || f.packets(ctx, t, "/ip/firewall/nat", "tikray:preserve-closed") == 0 {
		t.Fatal("closed stream lost its original source to masquerade")
	}
	f.checkOwnerRules(ctx, t)
}

func (f *routingLab) policyMidConnection(ctx context.Context, t *testing.T) {
	t.Helper()
	f.setClientPolicy(ctx, t, store.Policy{Mode: store.ModeDirect})
	current := f.tcpFlow(ctx, t, false, 31827)
	peer := f.tcpFlow(ctx, t, true, 31828)
	for range 3 {
		if current.echo(t) != egressDirect || peer.echo(t) != egressDirect {
			t.Fatal("direct baseline streams unavailable")
		}
	}
	old, keep := current.row(ctx, t), peer.id(ctx, t)
	if old == nil || old[".id"] == "" || old["fasttrack"] != "true" || keep == "" {
		t.Fatalf("missing accelerated baseline or peer witness: policy row=%t ID=%t accelerated=%t peer ID=%t", old != nil, old[".id"] != "", old["fasttrack"] == "true", keep != "")
	}
	f.setClientPolicy(ctx, t, store.Policy{Mode: store.ModeFull, KillSwitch: true})
	if current.id(ctx, t) == old[".id"] || current.exchange() == egressDirect {
		t.Fatal("old direct stream survived closed admission")
	}
	if peer.echo(t) != egressDirect || peer.id(ctx, t) != keep {
		t.Fatal("independent live peer was reset")
	}
	replacement := f.tcpFlow(ctx, t, false, 31829)
	if !isRoutingProxy(replacement.echo(t)) {
		t.Fatal("replacement TCP stream did not use a real proxy")
	}
	r := replacement.row(ctx, t)
	if r == nil || r["connection-mark"] != "tikray-closed" || r["fasttrack"] == "true" {
		t.Fatal("replacement TCP binding is not on the closed path")
	}
}

func (f *routingLab) failover(ctx context.Context, t *testing.T) {
	t.Helper()
	f.waitAlive(ctx, t)
	got := f.egress(ctx, routingRemote)
	var down, up string
	switch got {
	case serverEgress["a"]:
		down, up = "a", "b"
	case serverEgress["b"]:
		down, up = "b", "a"
	default:
		t.Fatal("no healthy initial proxy egress")
	}
	if e := f.Inet.SetServer(down, false); e != nil {
		t.Fatal("could not stop selected remote server")
	}
	t.Cleanup(func() {
		if e := f.Inet.SetServer(down, true); e != nil {
			t.Error("could not restore remote server")
		}
	})
	_, ok := poll(ctx, f.proxiedWithin(), time.Second, func() bool {
		resp, e := f.api.Status(ctx)
		var state service.Status
		return e == nil && resp.Decode(&state) == nil && !aliveIn(state.Health, f.serverIDs[down]) && aliveIn(state.Health, f.serverIDs[up]) && f.egress(ctx, routingRemote) == serverEgress[up]
	})
	if !ok || f.peerEgress(ctx, routingRemote) != egressDirect {
		t.Fatal("failover did not switch egress with peer intact")
	}
	if e := f.Inet.SetServer(down, true); e != nil {
		t.Fatal("could not restore remote server")
	}
	f.waitAlive(ctx, t)
}
