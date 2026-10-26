// Package xray is a small client for xray's gRPC API: the stats, observatory
// and routing services the health monitor reads. It speaks gRPC itself, over
// HTTP/2 without TLS and with hand-encoded protobuf, to keep
// google.golang.org/grpc and generated code out of the binary.
package xray

import (
	"context"
	"fmt"
	"time"
)

// Client calls xray's API, which the render's api-in inbound exposes. The
// zero value, with an Addr, is ready to use.
type Client struct {
	Addr    string        // host:port of xray's api-in inbound
	Timeout time.Duration // for one call; zero means 5 s
}

// QueryStats returns the counters whose name contains pattern; an empty
// pattern matches them all. With reset, xray also sets each counter it
// returns back to 0.
func (c *Client) QueryStats(ctx context.Context, pattern string, reset bool) ([]Stat, error) {
	b, err := c.call(ctx, statsService+"/"+methodQueryStats, encodeQueryStats(pattern, reset))
	if err != nil {
		return nil, err
	}
	stats, err := decodeQueryStats(b)
	if err != nil {
		return nil, fmt.Errorf("xray: %s: decoding the answer: %w", methodQueryStats, err)
	}
	return stats, nil
}

// SysStats returns xray's uptime and memory use.
func (c *Client) SysStats(ctx context.Context) (SysStats, error) {
	b, err := c.call(ctx, statsService+"/"+methodGetSysStats, nil)
	if err != nil {
		return SysStats{}, err
	}
	st, err := decodeSysStats(b)
	if err != nil {
		return SysStats{}, fmt.Errorf("xray: %s: decoding the answer: %w", methodGetSysStats, err)
	}
	return st, nil
}

// OutboundStatus returns what the observatory knows of each outbound it
// probes. It has an entry for an outbound only once the first probe has
// finished. xray answers with status 12 (UNIMPLEMENTED) while its config has
// no ObservatoryService.
func (c *Client) OutboundStatus(ctx context.Context) ([]OutboundStatus, error) {
	b, err := c.call(ctx, observatoryService+"/"+methodGetOutboundStatus, nil)
	if err != nil {
		return nil, err
	}
	st, err := decodeOutboundStatus(b)
	if err != nil {
		return nil, fmt.Errorf("xray: %s: decoding the answer: %w", methodGetOutboundStatus, err)
	}
	return st, nil
}

// BalancerTargets returns, for the balancer tag, the outbound that an
// override pins it to ("" when there is none) and the outbounds that the
// balancer's strategy picks now: for leastPing, the alive one with the least
// delay. targets is empty while the strategy picks none.
func (c *Client) BalancerTargets(ctx context.Context, tag string) (override string, targets []string, err error) {
	b, err := c.call(ctx, routingService+"/"+methodGetBalancerInfo, encodeBalancerInfo(tag))
	if err != nil {
		return "", nil, err
	}
	override, targets, err = decodeBalancerInfo(b)
	if err != nil {
		return "", nil, fmt.Errorf("xray: %s: decoding the answer: %w", methodGetBalancerInfo, err)
	}
	return override, targets, nil
}
