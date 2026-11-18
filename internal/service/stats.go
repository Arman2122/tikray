package service

import (
	"context"
	"strings"

	"github.com/Arman2122/tikray/internal/xray"
)

// XrayStats is the subset of xray's gRPC API that Service.Stats reads.
// *xray.Client implements it.
type XrayStats interface {
	QueryStats(ctx context.Context, pattern string, reset bool) ([]xray.Stat, error)
	SysStats(ctx context.Context) (xray.SysStats, error)
}

// TrafficCounter holds byte counters for one rendered inbound or outbound tag.
type TrafficCounter struct {
	Tag      string `json:"tag"`
	ServerID string `json:"server_id,omitempty"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

// SysMetrics holds xray's process uptime, goroutine count, and heap allocation.
type SysMetrics struct {
	Uptime       uint32 `json:"uptime"`
	NumGoroutine uint32 `json:"num_goroutine"`
	Alloc        uint64 `json:"alloc"`
}

// Stats is the live runtime telemetry reported by GET /v1/stats.
type Stats struct {
	Available bool             `json:"available"`
	Sys       *SysMetrics      `json:"sys,omitempty"`
	Outbounds []TrafficCounter `json:"outbounds"`
	Inbounds  []TrafficCounter `json:"inbounds"`
}

var (
	staticOutboundTags = []string{"direct", "block", "dns-out"}
	staticInboundTags  = []string{"tun-in", "socks-in", "dns-in", "api-in"}
)

// Stats reads live traffic counters and process metrics from xray's gRPC API.
// Only known rendered tags (active servers plus static inbounds/outbounds) are
// returned so unexpected xray output can never surface. When xray is unreachable
// or starting up, Available is false with empty slices.
func (s *Service) Stats(ctx context.Context) Stats {
	empty := Stats{
		Available: false,
		Outbounds: []TrafficCounter{},
		Inbounds:  []TrafficCounter{},
	}
	if s.xray == nil || s.repairBridge || s.bootPending.Load() {
		return empty
	}
	rctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()

	sys, err := s.xray.SysStats(rctx)
	if err != nil {
		return empty
	}
	raw, _ := s.xray.QueryStats(rctx, "", false)

	st, _ := s.store.State()
	outOrder := make([]TrafficCounter, 0, len(st.Servers)+len(staticOutboundTags))
	outIdx := make(map[string]int, len(st.Servers)+len(staticOutboundTags))
	for _, srv := range st.Servers {
		tag := "srv-" + srv.ID
		outIdx[tag] = len(outOrder)
		outOrder = append(outOrder, TrafficCounter{Tag: tag, ServerID: srv.ID})
	}
	for _, tag := range staticOutboundTags {
		outIdx[tag] = len(outOrder)
		outOrder = append(outOrder, TrafficCounter{Tag: tag})
	}

	inOrder := make([]TrafficCounter, 0, len(staticInboundTags))
	inIdx := make(map[string]int, len(staticInboundTags))
	for _, tag := range staticInboundTags {
		inIdx[tag] = len(inOrder)
		inOrder = append(inOrder, TrafficCounter{Tag: tag})
	}

	for _, item := range raw {
		if item.Value < 0 {
			continue
		}
		parts := strings.Split(item.Name, ">>>")
		if len(parts) != 4 || parts[2] != "traffic" {
			continue
		}
		kind, tag, dir := parts[0], parts[1], parts[3]
		var dst *TrafficCounter
		switch kind {
		case "outbound":
			if idx, ok := outIdx[tag]; ok {
				dst = &outOrder[idx]
			}
		case "inbound":
			if idx, ok := inIdx[tag]; ok {
				dst = &inOrder[idx]
			}
		}
		if dst == nil {
			continue
		}
		switch dir {
		case "uplink":
			dst.Uplink = item.Value
		case "downlink":
			dst.Downlink = item.Value
		}
	}

	return Stats{
		Available: true,
		Sys: &SysMetrics{
			Uptime:       sys.Uptime,
			NumGoroutine: sys.NumGoroutine,
			Alloc:        sys.Alloc,
		},
		Outbounds: outOrder,
		Inbounds:  inOrder,
	}
}
