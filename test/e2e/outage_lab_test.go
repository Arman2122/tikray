//go:build lab

package e2e

import (
	"context"
	"os"
	"testing"
	"time"
)

// Every outage has simultaneous closed/open clients and the independent
// owner channel. Evidence is emitted only by the fixed public catalogue.
func TestM3Outage(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Minute)
	defer cancel()
	l := &Lab{Version: env("TIKRAY_LAB_CHANNEL", "stable"), Arch: labArch()}
	check := l.recordM3Checks(t, "m3-outage")
	check("runner_stopped", func(t *testing.T) {
		f := deployRouting(ctx, t, t)
		l.Version = f.Version
		wan := f.imageWAN(ctx, t)
		socket := f.keepImagePeerFlow(ctx, t)
		ssh := f.ownerLANSSH(ctx, t)
		f.scheduler(ctx, t, false)
		f.containerAction(ctx, t, "tikray", "stop", "stopped")
		f.containerAction(ctx, t, "runner", "stop", "stopped")
		_, ok := poll(ctx, 80*time.Second, time.Second, func() bool { return f.peerEgress(ctx, routingRemote) == egressDirect })
		if !ok {
			t.Fatal("fresh open flow did not reach WAN after route convergence")
		}
		start := socket.count(socket.replies, 'D')
		_, ok = poll(ctx, 35*time.Second, 200*time.Millisecond, func() bool { return socket.count(socket.replies, 'D') >= start+2 })
		data, _ := os.ReadFile(socket.wire)
		if !ok || socket.count(socket.wire, '?') > 0 {
			t.Fatalf("original open UDP socket did not acquire WAN NAT: replies=%d wire=%d invalid=%d", socket.count(socket.replies, 'D')-start, len(data), socket.count(socket.wire, '?'))
		}
		if s := wan.sample(t); s.closedDirect != 0 || s.unknown != 0 {
			t.Fatal("WAN observed a closed or untranslated new flow")
		}
		ssh()
		f.containerAction(ctx, t, "runner", "start", "running")
		_, ok = poll(ctx, f.proxiedWithin(), time.Second, func() bool { return isRoutingProxy(f.peerEgress(ctx, routingRemote)) })
		if !ok {
			t.Fatal("fresh open path did not recover automatically")
		}
		start = socket.count(socket.replies, 'P')
		_, ok = poll(ctx, 35*time.Second, 200*time.Millisecond, func() bool { return socket.count(socket.replies, 'P') >= start+2 })
		if !ok {
			t.Fatal("original UDP socket did not resume proxy after recovery")
		}
		if wan.sample(t).closedDirect != 0 {
			t.Fatal("closed UDP escaped during recovery")
		}
		ssh()
		f.containerAction(ctx, t, "tikray", "start", "running")
		f.checkReady(ctx, t)
	})
}
