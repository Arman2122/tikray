package service

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/render"
)

func TestPingServerMeasuresTCPAndCachesInStatus(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	e := newEnv(t)
	e.s = e.newService(Config{})

	outbound, _ := json.Marshal(map[string]any{
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": host,
				"port":    port,
				"users":   []any{map[string]any{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}},
			}},
		},
		"streamSettings": map[string]any{"network": "tcp", "security": "none"},
	})
	srv, _, err := e.s.AddServer(t.Context(), 0, NewServer{Name: "local-ping", Outbound: outbound})
	if err != nil {
		t.Fatalf("AddServer: %v", err)
	}

	res, err := e.s.PingServer(t.Context(), srv.ID)
	if err != nil {
		t.Fatalf("PingServer: %v", err)
	}
	if !res.Alive || res.TCPMs <= 0 || res.ID != srv.ID {
		t.Fatalf("unexpected ping result: %+v", res)
	}

	all := e.s.PingAllServers(t.Context())
	if len(all) != 1 || !all[0].Alive || all[0].TCPMs <= 0 {
		t.Fatalf("unexpected PingAllServers: %+v", all)
	}

	st := e.s.Status(t.Context())
	if got, ok := st.Pings[srv.ID]; !ok || !got.Alive || got.TCPMs <= 0 {
		t.Fatalf("Status.Pings missing cached result: %+v", st.Pings)
	}

	if _, err := e.s.PingServer(t.Context(), "missing"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestCoreReleasesIncludesTestedFallbackOffline(t *testing.T) {
	e := newEnv(t)
	e.s = e.newService(Config{})

	// Cancel context immediately so network fetch falls back offline cleanly.
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()

	info := e.s.CoreReleases(ctx)
	if len(info.Releases) < 2 {
		t.Fatalf("expected fallback core releases, got %+v", info)
	}
	wantLatest := render.Tested[1].String()
	if info.Latest != wantLatest {
		t.Fatalf("Latest = %q, want %q", info.Latest, wantLatest)
	}
	foundTested := false
	for _, r := range info.Releases {
		if r.Version == wantLatest && r.Tested {
			foundTested = true
		}
	}
	if !foundTested {
		t.Fatalf("tested release %s not found in %+v", wantLatest, info.Releases)
	}
}
