package service

import (
	"context"
	"errors"
	"testing"

	"github.com/Arman2122/tikray/internal/xray"
)

type fakeXrayStats struct {
	sys   xray.SysStats
	stats []xray.Stat
	err   error
}

func (f *fakeXrayStats) SysStats(context.Context) (xray.SysStats, error) {
	if f.err != nil {
		return xray.SysStats{}, f.err
	}
	return f.sys, nil
}

func (f *fakeXrayStats) QueryStats(context.Context, string, bool) ([]xray.Stat, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.stats, nil
}

func TestStatsFiltersKnownTagsAndHandlesUnavailable(t *testing.T) {
	e := newEnv(t)
	fx := &fakeXrayStats{
		sys: xray.SysStats{Uptime: 3600, NumGoroutine: 42, Alloc: 12 << 20},
	}
	e.s = e.newService(Config{Xray: fx, Version: "v1.0.0"})

	srv, _, err := e.s.AddServer(t.Context(), 0, NewServer{Link: sampleVLESSLink})
	if err != nil {
		t.Fatalf("AddServer: %v", err)
	}
	fx.stats = []xray.Stat{
		{Name: "outbound>>>srv-" + srv.ID + ">>>traffic>>>uplink", Value: 1024},
		{Name: "outbound>>>srv-" + srv.ID + ">>>traffic>>>downlink", Value: 8192},
		{Name: "outbound>>>direct>>>traffic>>>downlink", Value: 500},
		{Name: "inbound>>>tun-in>>>traffic>>>uplink", Value: 2048},
		{Name: "outbound>>>secret-leak-tag>>>traffic>>>uplink", Value: 999},
		{Name: "user>>>alice@secret>>>traffic>>>uplink", Value: 777},
		{Name: "outbound>>>direct>>>traffic>>>uplink", Value: -5},
	}

	got := e.s.Stats(t.Context())
	if !got.Available || got.Sys == nil || got.Sys.Uptime != 3600 || got.Sys.Alloc != 12<<20 {
		t.Fatalf("unexpected stats sys: %+v", got)
	}
	if len(got.Outbounds) != 4 {
		t.Fatalf("outbounds len = %d, want 4: %+v", len(got.Outbounds), got.Outbounds)
	}
	if got.Outbounds[0].ServerID != srv.ID || got.Outbounds[0].Uplink != 1024 || got.Outbounds[0].Downlink != 8192 {
		t.Fatalf("server counter = %+v", got.Outbounds[0])
	}
	if got.Outbounds[1].Tag != "direct" || got.Outbounds[1].Downlink != 500 || got.Outbounds[1].Uplink != 0 {
		t.Fatalf("direct counter = %+v", got.Outbounds[1])
	}
	if got.Inbounds[0].Tag != "tun-in" || got.Inbounds[0].Uplink != 2048 {
		t.Fatalf("tun-in counter = %+v", got.Inbounds[0])
	}

	// Status also exposes BootID and Version.
	st := e.s.Status(t.Context())
	if st.BootID == "" || st.BootID != e.s.BootID() || st.Version != "v1.0.0" {
		t.Fatalf("status boot_id/version = %q / %q", st.BootID, st.Version)
	}

	// When xray is unreachable, Stats reports Available: false cleanly.
	fx.err = errors.New("connection refused")
	down := e.s.Stats(t.Context())
	if down.Available || down.Sys != nil || len(down.Outbounds) != 0 || len(down.Inbounds) != 0 {
		t.Fatalf("down stats = %+v", down)
	}
}
