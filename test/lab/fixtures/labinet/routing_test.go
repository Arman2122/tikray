package labinet

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestRoutingResolverIdentifiesListenerAndEgress(t *testing.T) {
	addr := netip.MustParseAddr
	for _, tc := range []struct{ resolver, source, expect string }{
		{"203.0.113.53", "198.51.100.2", "198.18.53.1"},
		{"203.0.113.53", "203.0.113.10", "198.18.53.2"},
		{"203.0.113.54", "198.51.100.2", "198.18.54.1"},
		{"203.0.113.54", "203.0.113.11", "198.18.54.2"},
	} {
		got, ok := routingDNSAnswer("query.domestic.routing-probe.test.", addr(tc.resolver), addr(tc.source))
		if !ok || got.String() != tc.expect {
			t.Fatalf("incorrect path witness for %s/%s", tc.resolver, tc.source)
		}
	}
	if _, ok := routingDNSAnswer("bad.example.", addr("203.0.113.53"), addr("198.51.100.2")); ok {
		t.Fatal("unrelated name acquired an answer")
	}
	if _, ok := routingDNSAnswer("query.foreign.routing-probe.test.", addr("203.0.113.53"), addr("198.51.100.99")); ok {
		t.Fatal("unknown source counted as the direct WAN path")
	}
}

func TestQUICHandshakeReportsObservedRoute(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ready := filepath.Join(t.TempDir(), "public.pem")
	server, err := StartQUICWitness("127.0.0.1:0", ready)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(ctx)
	go ServeQUICWitness(ctx, server)
	for _, name := range []string{"domestic.test", "foreign.test"} {
		src, dst, sni, err := ProbeQUIC(ctx, "127.0.0.1:0", server.LocalAddr().String(), name, ready)
		if err != nil {
			t.Fatal(err)
		}
		if src != net.IPv4(127, 0, 0, 1).String() || dst != "127.0.0.1" || sni != name {
			t.Fatal("missing independent QUIC source, destination or SNI witness")
		}
	}
}
